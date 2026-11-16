package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// ctrlCExitWindow: two Ctrl+C presses closer than this apart exit tp.
// (ISIG is off on the local tty, so a lone Ctrl+C is forwarded to the
// remote; only a quick second press is reserved for quitting tp.)
const ctrlCExitWindow = 1500 * time.Millisecond

// ensureCRLF makes sure every \n in b is preceded by a \r. Remote ptys with
// OPOST/ONLCR disabled emit bare \n; without the \r the local terminal
// can't start a new line and everything smears onto one row.
// Strategy: \n -> \r\n, then fix the double-\r that results from
// already-correct \r\n pairs.
func ensureCRLF(b []byte) []byte {
	b = bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n"))
	return bytes.ReplaceAll(b, []byte("\r\r\n"), []byte("\r\n"))
}

// tpDebug turns on protocol tracing. Set TP_DEBUG to any non-empty value.
// A CLI flag would be ambiguous here: everything after `tp ssh` is passed
// through to ssh verbatim, so `tp ssh host -d` cannot tell tp's flag from
// ssh's. An environment variable sidesteps that entirely.
var tpDebug = os.Getenv("TP_DEBUG") != ""

// dbgOut is the lazily opened debug sink. Output goes to TP_DEBUG_FILE when it
// names a writable file, otherwise to stderr. A file is what you actually want
// during a transfer: the progress bar repaints a single line with \r, so debug
// lines written to the same terminal smear it into noise.
var dbgOut struct {
	sync.Mutex
	w     io.Writer
	color bool
}

// dbg writes one timestamped trace line. Timestamps matter: most protocol
// bugs here are ordering/timing bugs between the two reader goroutines.
func dbg(format string, args ...any) {
	if !tpDebug {
		return
	}
	dbgOut.Lock()
	defer dbgOut.Unlock()
	if dbgOut.w == nil {
		if p := os.Getenv("TP_DEBUG_FILE"); p != "" {
			f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
			if err == nil {
				dbgOut.w = f // a file: no ANSI colours, just plain text
			} else {
				fmt.Fprintf(os.Stderr, "tp: debug log %s: %v (logging to stderr instead)\n", p, err)
				dbgOut.w, dbgOut.color = os.Stderr, true
			}
		} else {
			dbgOut.w, dbgOut.color = os.Stderr, true
		}
	}
	prefix := "[tp:dbg] "
	if dbgOut.color {
		prefix = "\033[1;35m[tp:dbg]\033[0m "
	}
	fmt.Fprintf(dbgOut.w, "%s%s "+format+"\n",
		append([]any{prefix, time.Now().Format("15:04:05.000")}, args...)...)
}

// linkDead flips to 1 when writing to the ssh pty fails (ssh exited, the pipe
// went away). A transfer that keeps feeding bytes into a dead link would run to
// completion, then report a misleading "verification timed out" half a minute
// later, so readers poll this and give up at once.
var linkDead int32

// Injection accounting. Handing bytes to the injection queue is NOT the same as
// the remote having them: a bastion that rate-limits input leaves a backlog
// sitting in tp's own buffers, and every timeout tp arms too early gets blamed
// on the remote. So the queue counts bytes in and bytes out, and anything that
// waits for an answer waits for the backlog to drain first.
//
// injectSeq counts completed pty writes and injectWritten the bytes behind them;
// the writer chunks its writes so both keep ticking even when one huge line takes
// a long time to push through a slow link. injectStallLimit is how long no
// progress at all is tolerated before the link is called dead — a dead-but-open
// pty blocks in f.Write rather than returning an error, which would otherwise
// wedge a transfer behind a frozen progress bar. Tunable via TP_LINK_STALL
// (seconds) and a variable so tests can shrink it.
var (
	injectSeq        int64
	injectQueued     int64
	injectWritten    int64
	injectStallLimit = 60 * time.Second
)

// injectChunk caps how much goes into a single pty write. Small enough that the
// stall watchdog sees progress often on a slow link; the byte stream the remote
// receives is identical.
const injectChunk = 1024

func init() {
	if v := os.Getenv("TP_LINK_STALL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			injectStallLimit = time.Duration(n) * time.Second
		}
	}
}

// injectBacklog is how many bytes tp still holds that the remote has not been
// given yet.
func injectBacklog() int64 {
	return atomic.LoadInt64(&injectQueued) - atomic.LoadInt64(&injectWritten)
}

// resetInject zeroes the injection counters. Only tests need it: the counters are
// process-wide, and a test that stops its injector early would otherwise leave a
// phantom backlog for the next one to wait out.
func resetInject() {
	atomic.StoreInt64(&injectQueued, 0)
	atomic.StoreInt64(&injectWritten, 0)
	atomic.StoreInt64(&injectSeq, 0)
	atomic.StoreInt32(&linkDead, 0)
}

// startInjector drains injectCh into w, in chunks, and keeps the byte accounting
// that injectBacklog reads. There is exactly one implementation on purpose: the
// tests share it, so the backlog can never disagree with what was really written
// (a test-local writer used to leave the counters claiming megabytes still
// undelivered, and every wait then burned the whole stall timeout).
//
// A failed write means the link is gone: flag linkDead and keep draining so
// senders never block forever on a full channel — they notice and abort.
func startInjector(w io.Writer, injectCh chan []byte) {
	go func() {
		for data := range injectCh {
			total := len(data)
			for off := 0; off < total; off += injectChunk {
				n := min(total-off, injectChunk)
				if _, err := w.Write(data[off : off+n]); err != nil {
					dbg("inject write failed: %v", err)
					atomic.StoreInt32(&linkDead, 1)
					for range injectCh {
					}
					return
				}
				atomic.AddInt64(&injectWritten, int64(n))
				atomic.AddInt64(&injectSeq, 1)
			}
			dbg("inject %d bytes: %s", total, dbgQuote(data))
		}
	}()
}

// stallWatch expires only while nothing at all is moving, so a throttled link
// that is slow but alive never trips it.
type stallWatch struct {
	last  int64
	since time.Time
	limit time.Duration
}

func newStallWatch() *stallWatch {
	return &stallWatch{last: atomic.LoadInt64(&injectWritten), since: time.Now(), limit: injectStallLimit}
}

// stalled reports true once the written-byte counter has sat still for the whole
// limit; any movement resets the clock.
func (w *stallWatch) stalled() bool {
	if now := atomic.LoadInt64(&injectWritten); now != w.last {
		w.last = now
		w.since = time.Now()
		return false
	}
	return time.Since(w.since) > w.limit
}

// waitInjectDrained blocks until every byte tp queued has reached the pty, and
// reports whether it drained. It gives up only when the backlog stops shrinking
// for injectStallLimit, so a slow bastion takes longer instead of being declared
// dead. progress, when non-nil, is called about once a second with the bytes
// still queued, so a long wait does not read as a hang.
func waitInjectDrained(progress func(int64)) bool {
	w := newStallWatch()
	var lastReport time.Time
	for injectBacklog() > 0 {
		if w.stalled() || atomic.LoadInt32(&linkDead) == 1 {
			return false
		}
		if progress != nil && time.Since(lastReport) >= time.Second {
			progress(injectBacklog())
			lastReport = time.Now()
		}
		time.Sleep(20 * time.Millisecond)
	}
	if progress != nil {
		progress(0)
	}
	return true
}

// injectWait hands data to the injection writer, reporting false when the link
// is dead or has made no write at all for injectStallLimit. Slow is fine — the
// writer keeps bumping injectSeq, so we keep waiting; no progress at all is what
// means the link is gone.
func injectWait(injectCh chan<- []byte, data []byte) bool {
	for {
		timer := time.NewTimer(injectStallLimit)
		before := atomic.LoadInt64(&injectSeq)
		select {
		case injectCh <- data:
			timer.Stop()
			atomic.AddInt64(&injectQueued, int64(len(data)))
			return true
		case <-timer.C:
			timer.Stop()
			if atomic.LoadInt32(&linkDead) == 1 || atomic.LoadInt64(&injectSeq) == before {
				dbg("injectWait: no write progress for %v, calling the link dead", injectStallLimit)
				return false
			}
			// Still draining, just slowly: keep waiting.
		}
	}
}

// dbgQuote renders b for debug logging, truncating large payloads (e.g. the
// base64 stream during a !get/!put transfer) so a download doesn't flood the
// screen with data that looks like a leak. The remaining byte count is always
// shown so you can tell how much was elided.
func dbgQuote(b []byte) string {
	const max = 120
	if len(b) > max {
		return fmt.Sprintf("%q... [+%d more bytes]", string(b[:max]), len(b)-max)
	}
	return fmt.Sprintf("%q", b)
}

type localCmd struct {
	action  string
	arg1    string
	arg2    string
	logMode int    // -l 0|1 (for !get): 0 = no log, 1 = resumable
	logFile string // -f <file> (for !get): override the resume log name
}

// pendingPut carries the expected sha256 of an in-flight !put so the
// output reader can verify the remote's checksum when it reports back.
var pendingPut struct {
	mu     sync.Mutex
	result chan string // receives remote sha ("" if none)
}

// lastPtyOut is the unix-nano time of the most recent pty output byte, updated
// by the output reader. Local messages use it to wait for the remote to go quiet
// (its PS1 flushed) before printing, so they land on a clean line instead of
// interleaving with the remote shell's prompt.
var lastPtyOut int64

// putGuard coordinates the "target already exists?" guard for !put. Before
// overwriting a remote file we (1) ask the remote whether the target exists and
// (2) if it does, prompt the user locally and capture their y/N answer. Both
// channels are nil except while a guard is in flight.
var putGuard struct {
	mu        sync.Mutex
	existsCh  chan bool     // receives the remote existence-check result
	tmpSizeCh chan int64    // receives the remote temp-file size (resume probe)
	cksumCh   chan []string // receives the remote's last-N block checksums (resume probe)
	answerCh  chan string   // receives the user's answer to the overwrite prompt
}

// getLog carries the per-block logging/resume configuration from doNoRemoteGet
// (stdin reader goroutine) to the __TP_BEGIN__ handler (output reader
// goroutine). Set before the command is injected; read once when the download
// starts. enabled=false means plain (non-resumable) download.
var getLog struct {
	mu         sync.Mutex
	enabled    bool   // -l 1: record a resume log
	logName    string // resume log path ("" = auto: <target>.tprlog)
	resumeFrom int    // block to resume from (0 = fresh start)
	resumeSize int64  // bytes already in the partial temp file
}

func cmdSSH(args []string) int {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "usage: tp ssh <host> [ssh_args...]\n")
		fmt.Fprintf(os.Stderr, "  In-session: !get <remote_path> [local_name]\n")
		fmt.Fprintf(os.Stderr, "              !put <local_path> [remote_path]\n")
		return 1
	}

	host := args[0]
	sshArgs := args[1:]

	cmd := exec.Command("ssh", append([]string{host}, sshArgs...)...)
	f, err := pty.Start(cmd)
	if err != nil {
		fatalf("start ssh: %v", err)
	}
	defer f.Close()
	dbg("session start: ssh %s", strings.Join(args, " "))

	// Set local PTY (tp ↔ ssh) to raw mode:
	// - ECHO off: we do our own local echo (echoInput) as the single source and
	//   suppress the remote's duplicate via echoSuppressor. Relying on either the
	//   PTY or the remote alone is unreliable across nested/multi-hop links.
	// - No ICANON (no 4096-byte line limit, needed for long base64 lines)
	// - No ICRNL (ssh handles line endings)
	if termios, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS); err == nil {
		termios.Lflag &^= unix.ICANON | unix.ISIG | unix.ECHO
		termios.Iflag &^= unix.ICRNL | unix.IXON
		termios.Oflag &^= unix.OPOST
		termios.Cc[unix.VMIN] = 1
		termios.Cc[unix.VTIME] = 0
		unix.IoctlSetTermios(int(f.Fd()), unix.TCSETS, termios)
	}

	// Put the user's terminal into raw mode (like ssh does) so every keystroke —
	// including Ctrl+C — is delivered to us immediately instead of being
	// line-buffered by the local tty. With ISIG off, a lone Ctrl+C is forwarded
	// to the remote; a second press within ctrlCExitWindow quits tp (handled in
	// the stdin reader below). Local ECHO is off (see echoInput/echoSuppressor).
	//
	// We keep the ORIGINAL termios and always restore it — on normal exit (defer),
	// on SIGTERM/SIGINT (handler below), and on double Ctrl+C — so a killed tp
	// never leaves the user's shell with Ctrl+C disabled.
	var localTermios *unix.Termios
	if orig, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS); err == nil {
		localTermios = orig
		raw := *orig
		raw.Lflag &^= unix.ISIG | unix.ICANON | unix.ECHO
		raw.Iflag &^= unix.IXON
		raw.Cc[unix.VMIN] = 1
		raw.Cc[unix.VTIME] = 0
		unix.IoctlSetTermios(int(os.Stdin.Fd()), unix.TCSETS, &raw)
	}
	restoreLocalTermios := func() {
		if localTermios != nil {
			unix.IoctlSetTermios(int(os.Stdin.Fd()), unix.TCSETS, localTermios)
		}
	}
	defer restoreLocalTermios()

	// Match local terminal size
	if w, h, err := term.GetSize(int(os.Stdin.Fd())); err == nil {
		pty.Setsize(f, &pty.Winsize{Rows: uint16(h), Cols: uint16(w)})
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGWINCH:
				if w, h, err := term.GetSize(int(os.Stdin.Fd())); err == nil {
					pty.Setsize(f, &pty.Winsize{Rows: uint16(h), Cols: uint16(w)})
				}
			default: // SIGTERM/SIGINT: restore the terminal, then exit
				restoreLocalTermios()
				os.Exit(130)
			}
		}
	}()

	injectCh := make(chan []byte, 50)
	cmdCh := make(chan localCmd, 1)
	var suppress int32
	var echoSup echoSuppressor

	// === PTY output → local stdout (fix \r\n double translation) ===
	go func() {
		var (
			lineBuf []byte
			cap     captureState
		)

		buf := make([]byte, 8192)
		for {
			n, rerr := f.Read(buf)
			if n > 0 {
				atomic.StoreInt64(&lastPtyOut, time.Now().UnixNano())
				dbg("pty out %d bytes: %s", n, dbgQuote(buf[:n]))
				incoming := buf[:n]
				// Drop the remote's duplicate of our local echo (see echoSuppressor),
				// but only for normal interactive output — NEVER during a !get/!put
				// transfer, where the stream is base64/markers and any filtering would
				// corrupt it (a single eaten byte breaks base64 decode and leaks the
				// whole line to the screen).
				if !cap.capturing && atomic.LoadInt32(&suppress) == 0 {
					var kept []byte
					consumed := 0
					for _, b := range incoming {
						if echoSup.tryConsume(b) {
							consumed++
						} else {
							kept = append(kept, b)
						}
					}
					if consumed > 0 {
						dbg("echoSup swallowed %d/%d remote echo bytes", consumed, n)
					}
					incoming = kept
				}
				lineBuf = append(lineBuf, incoming...)

				for {
					idx := bytes.IndexByte(lineBuf, '\n')
					if idx < 0 {
						break
					}
					line := lineBuf[:idx+1]
					lineBuf = lineBuf[idx+1:]

					// While a !put is streaming, discard the echoed base64 — but let
					// protocol markers through so the __TP_DONE__ that ends the upload
					// is still captured even while output is suppressed.
					if atomic.LoadInt32(&suppress) == 1 && !mightBeMarker(line) {
						continue
					}

					// Normalise to \r\n for local display (remote may emit bare \n).
					line = ensureCRLF(line)

					handleLine(line, &cap)
				}

				// Incomplete line: forward immediately unless it might be a TP marker.
				// No minimum-length gate: the remote shell echoes each keystroke
				// as 1-2 bytes, so gating on length would make typing invisible.
				if len(lineBuf) > 0 && !cap.capturing && atomic.LoadInt32(&suppress) == 0 {
					if !mightBeMarker(lineBuf) {
						os.Stdout.Write(ensureCRLF(lineBuf))
						lineBuf = nil
					}
				}
			}
			if rerr != nil {
				if len(lineBuf) > 0 && atomic.LoadInt32(&suppress) == 0 {
					os.Stdout.Write(ensureCRLF(lineBuf))
				}
				if cap.file != nil {
					// The link died (e.g. ssh disconnected) mid-download. Remove
					// the partial temp file so the original target — if any — is
					// left untouched, and tell the user it didn't complete.
					cap.file.Close()
					cap.file = nil
					if cap.capturing {
						if cap.tmpName != "" {
							os.Remove(cap.tmpName)
						}
						errf("download interrupted (%s received); ./%s not written",
							humanSize(cap.size), cap.name)
					}
				}
				return
			}
		}
	}()

	// === Dedicated injection writer (prevents deadlock with stdin reader) ===
	startInjector(f, injectCh)

	// === Local stdin → PTY (byte-by-byte for real-time key forwarding) ===
	go func() {
		buf := make([]byte, 4096)
		var pendingLine []byte
		// atLineStart is true when the next byte typed begins a new line (right
		// after a submitted Enter, or at session start). Only at line start do we
		// allow leading whitespace before a `!` command.
		atLineStart := true

		// echoedCols tracks how many visible columns we've echoed on the current
		// input line (normal-branch commands). It lets us stop echoing backspaces
		// once the cursor reaches the start of the line, so backspacing into the
		// prompt doesn't smear it (the remote's own line discipline already refuses
		// to delete the prompt; we just mirror that in our local echo).
		echoedCols := 0

		// ISIG is off and the tty is raw, so Ctrl+C shows up here as a literal
		// 0x03 byte rather than raising SIGINT. Forward a lone press to the
		// remote (interrupt its foreground job); a second press within
		// ctrlCExitWindow quits tp — the only keyboard way to kill it, since
		// Ctrl+C no longer arrives as a signal.
		var lastCtrlC time.Time
		// confirmBuf accumulates the user's answer while a !put overwrite
		// confirmation is pending (see captureConfirm).
		var confirmBuf []byte

		for {
			n, rerr := os.Stdin.Read(buf)
			if n > 0 {
				data := buf[:n]
				dbg("stdin read %d bytes: %s", n, dbgQuote(data))

				// Two Ctrl+C within the window (or both in a single read) → quit tp.
				if c := bytes.Count(data, []byte{0x03}); c > 0 {
					now := time.Now()
					if c >= 2 || now.Sub(lastCtrlC) < ctrlCExitWindow {
						restoreLocalTermios()
						fmt.Fprintln(os.Stderr, "\ntp: exiting (double Ctrl+C)")
						os.Exit(130)
					}
					lastCtrlC = now
				}

				// If a !put overwrite confirmation is pending, capture this input as
				// the answer instead of forwarding it to the remote. The double-Ctrl+C
				// quit above still takes priority, so the user can always break out.
				putGuard.mu.Lock()
				answerCh := putGuard.answerCh
				putGuard.mu.Unlock()
				if answerCh != nil {
					dbg("stdin: capturing confirm input %q", dbgQuote(data))
					captureConfirm(data, &confirmBuf, answerCh)
					continue
				}

				// Decide whether this read is (the start of) a local `!` command.
				// Buffer it if: we're already mid-command, the first real byte is
				// `!` (skipping leading escapes/whitespace and bracketed-paste
				// markers), or — only at line start — the read so far is nothing but
				// whitespace (a `!` command may follow).
				if len(pendingLine) > 0 || isBangStart(data) || bytes.HasPrefix(data, []byte("\x1b[200~")) || (atLineStart && isLeadingSpace(data)) {
					// A `!` command — typed directly, indented, or wrapped in
					// bracketed-paste markers. It never reaches the remote, so we echo it
					// ourselves AND buffer it with basic line editing (backspace, Ctrl+U
					// kill-line, Ctrl+W delete-word) so the user can modify or CANCEL it
					// before Enter, like a normal shell line. Without this, editing or
					// canceling left mangled control bytes in the buffer that got executed
					// as a garbage command on Enter.
					i := 0
					for i < len(data) {
						b := data[i]
						switch {
						case b == 0x1b: // escape seq (arrows, paste markers): skip
							if j := skipEscapeSeq(data, i); j > i {
								i = j
								continue
							}
							i++
						case b == '\n': // Enter: commit the line
							os.Stdout.Write([]byte{'\n'})
							pendingLine = append(pendingLine, '\n')
							i++
						case b == 0x7f || b == 0x08: // backspace / DEL: pop last rune
							if len(pendingLine) > 0 {
								pendingLine = chopLastRune(pendingLine)
								os.Stdout.Write([]byte("\b \b"))
							}
							i++
						case b == 0x15: // Ctrl+U: kill the whole line
							for len(pendingLine) > 0 {
								pendingLine = chopLastRune(pendingLine)
								os.Stdout.Write([]byte("\b \b"))
							}
							i++
						case b == 0x17: // Ctrl+W: delete the last word
							j := len(pendingLine)
							for j > 0 && pendingLine[j-1] == ' ' {
								j--
							}
							for j > 0 && pendingLine[j-1] != ' ' {
								j--
							}
							for k := j; k < len(pendingLine); k++ {
								os.Stdout.Write([]byte("\b \b"))
							}
							pendingLine = pendingLine[:j]
							i++
						case b >= 0x20: // printable (ASCII + UTF-8): echo + buffer
							os.Stdout.Write([]byte{b})
							pendingLine = append(pendingLine, b)
							i++
						default: // other control chars: not part of the command
							i++
						}
					}
				} else {
					// Normal input: local echo (always on) + forward. The remote may
					// also echo; echoSup drops the duplicate in the output reader.
					// We don't echo the Enter key — the remote supplies its own break.
					//
					// Ctrl+U (kill line): erase our OWN local echo of the current line
					// so the screen clears even when the remote never sends a clear
					// sequence back (e.g. its ECHO is off, so nothing comes down the
					// pty to erase what we painted). We still forward Ctrl+U so the
					// remote's readline clears its buffer too. Any duplicate clear the
					// remote does send is harmless — extra backspaces just clamp at the
					// prompt.
					if bytes.IndexByte(data, 0x15) >= 0 {
						echoedCols = killLocalLine(os.Stdout, echoedCols)
					}
					// Clear pending echo bytes when sending input that will make the
					// remote readline generate new screen content (TAB completion,
					// arrow-key history, etc.). Without this, readline's output can be
					// mistaken for a still-pending remote echo and silently suppressed —
					// making completions and history recall invisible in nested or
					// high-latency setups where echoes haven't round-tripped yet.
					if bytes.IndexByte(data, 0x09) >= 0 || bytes.IndexByte(data, 0x1b) >= 0 {
						echoSup.clear()
					}
					echoInput(data, true, &echoedCols)
					echoSup.push(data)
					f.Write(data)
					atLineStart = data[len(data)-1] == '\n'
					continue
				}

				for {
					idx := bytes.IndexByte(pendingLine, '\n')
					if idx < 0 {
						break
					}
					line := pendingLine[:idx+1]
					pendingLine = pendingLine[idx+1:]
					dbg("pendingLine flush: %q", line)

					// Strip ANSI escape sequences (incl. bracketed-paste markers
					// \x1b[200~ / \x1b[201~) to get the real command text.
					clean := strings.TrimSpace(string(stripANSI(line)))
					// "!!get" / "!!put" is the escape hatch: the user means the literal
					// shell word (a remote alias of that name, a line inside a heredoc),
					// not tp's command. Drop one "!" and let the remote have it. A bare
					// "!!" or "!!vim" still falls through untouched as bash history
					// expansion.
					if strings.HasPrefix(clean, "!!get") || strings.HasPrefix(clean, "!!put") {
						if i := bytes.Index(line, []byte("!!")); i >= 0 {
							line = append(append([]byte{}, line[:i+1]...), line[i+2:]...)
						}
						echoSup.push(stripANSI(line))
						f.Write(line)
						continue
					}
					if strings.HasPrefix(clean, "!get") || strings.HasPrefix(clean, "!put") {
						parts := strings.Fields(clean)
						// logMode -1 = "-l not given"; resolved per-action below where the default is
						// logging-on so an interrupted transfer can resume.
						lc := localCmd{action: parts[0][1:], logMode: -1}
						if len(parts) >= 2 {
							lc.arg1 = parts[1]
						}
						// Remaining args: [local_name] plus optional !get flags
						// (-l 0|1, -f <log_file>) in any order.
						for i := 2; i < len(parts); i++ {
							switch parts[i] {
							case "-l":
								if i+1 < len(parts) {
									fmt.Sscanf(parts[i+1], "%d", &lc.logMode)
									i++
								}
							case "-f":
								if i+1 < len(parts) {
									lc.logFile = parts[i+1]
									i++
								}
							default:
								if lc.arg2 == "" {
									lc.arg2 = parts[i]
								}
							}
						}
						cmdCh <- lc
					} else {
						// Not a tp command (e.g. !!, or a pasted normal command).
						// Forward the ORIGINAL line — markers intact — so the remote
						// shell sees a proper bracketed paste.
						echoSup.push(stripANSI(line))
						f.Write(line)
					}
				}
				atLineStart = len(pendingLine) == 0
			}
			if rerr != nil {
				return
			}
		}
	}()

	// === Command handler ===
	go func() {
		for lc := range cmdCh {
			switch lc.action {
			case "get":
				if lc.arg1 == "" {
					fmt.Fprintln(os.Stderr, "\ntp: usage: !get <remote_path> [local_name] [-l 0|1] [-f <log_file>]  (resume on by default; -l 0 disables)")
					continue
				}
				echoSup.clear() // don't let stale echo entries corrupt the marker/base64
				if lc.logMode == -1 {
					lc.logMode = 1 // resume by default; opt out with -l 0
				}
				doNoRemoteGet(injectCh, lc.arg1, lc.arg2, lc.logMode, lc.logFile)
			case "put":
				if lc.arg1 == "" {
					fmt.Fprintln(os.Stderr, "\ntp: usage: !put <local_path> [remote_path] [-l 0|1] [-f <log_file>]  (resume on by default; -l 0 disables)")
					continue
				}
				remotePath := lc.arg2
				if remotePath == "" {
					remotePath = "." + "/" + filepath.Base(lc.arg1)
				}
				echoSup.clear() // don't let stale echo entries corrupt the transfer
				if lc.logMode == -1 {
					lc.logMode = 1 // resume by default; opt out with -l 0
				}
				doNoRemotePut(injectCh, &suppress, lc.arg1, remotePath, lc.logMode, lc.logFile)
			}
		}
	}()

	// Propagate ssh's own exit status so tp is usable in scripts (it previously
	// always exited 0, even when ssh itself failed).
	code := 0
	if werr := cmd.Wait(); werr != nil {
		var ee *exec.ExitError
		if errors.As(werr, &ee) {
			code = ee.ExitCode()
		} else {
			code = 1
		}
	}
	dbg("session end: ssh exit code %d", code)
	return code
}
