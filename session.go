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

// ctrlCExitWindow and ctrlCExitCount: three Ctrl+C presses within 1.5s exit tp.
// (ISIG is off on the local tty, so a single Ctrl+C aborts an active transfer
// or forwards to the remote; only three rapid presses quit tp.)
const (
	ctrlCExitWindow = 1500 * time.Millisecond
	ctrlCExitCount  = 3
)

// ctrlCTracker tracks recent Ctrl+C timestamps within ctrlCExitWindow and
// reports when the threshold (ctrlCExitCount) is reached.
type ctrlCTracker struct {
	times []time.Time
}

func (t *ctrlCTracker) record(now time.Time, count int) bool {
	if count <= 0 {
		return false
	}
	kept := t.times[:0]
	for _, ts := range t.times {
		if now.Sub(ts) < ctrlCExitWindow {
			kept = append(kept, ts)
		}
	}
	t.times = kept
	for i := 0; i < count; i++ {
		t.times = append(t.times, now)
	}
	return len(t.times) >= ctrlCExitCount
}

// putCancel coordinates single-Ctrl+C cancellation of an active !put upload.
var putCancel struct {
	mu     sync.Mutex
	active bool
	ch     chan struct{}
}

func startPutCancel() chan struct{} {
	putCancel.mu.Lock()
	defer putCancel.mu.Unlock()
	ch := make(chan struct{})
	putCancel.active = true
	putCancel.ch = ch
	return ch
}

func stopPutCancel() {
	putCancel.mu.Lock()
	defer putCancel.mu.Unlock()
	putCancel.active = false
	putCancel.ch = nil
}

// cancelActivePut signals the active !put upload (if any) to abort and reports
// whether a put was active.
func cancelActivePut() bool {
	putCancel.mu.Lock()
	defer putCancel.mu.Unlock()
	if !putCancel.active {
		return false
	}
	if putCancel.ch != nil {
		select {
		case <-putCancel.ch:
		default:
			close(putCancel.ch)
		}
	}
	return true
}

func isCancelled(ch <-chan struct{}) bool {
	if ch == nil {
		return false
	}
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

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
	return waitInjectDrainedCancel(nil, progress)
}

func waitInjectDrainedCancel(cancelCh <-chan struct{}, progress func(int64)) bool {
	w := newStallWatch()
	var lastReport time.Time
	for injectBacklog() > 0 {
		if w.stalled() || atomic.LoadInt32(&linkDead) == 1 || isCancelled(cancelCh) {
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
	action    string
	arg1      string
	arg2      string
	logMode   int    // -d 0|1: 0 = no log, 1 = resumable
	logFile   string // -f <file>: override the resume log name
	rateLimit int64  // -l <rate> (e.g. 20K) or -r <rate>: bytes/sec limit (0 = unlimited)
	parseErr  error  // non-nil when flag parsing failed
}

// parseLocalCmd parses an in-session command line (get@! / put@! / !get / !put)
// allowing flags in any position (before, between, or after positional args).
// `-d 0` / `-d 1` controls resume logging; `-l <rate>` (e.g. `-l 20K`) or
// `-r <rate>` sets the transfer rate limit in bytes/sec.
func parseLocalCmd(parts []string) localCmd {
	lc := localCmd{
		action:  tpAction(parts[0]),
		logMode: -1,
	}
	for i := 1; i < len(parts); i++ {
		switch parts[i] {
		case "-d":
			if i+1 >= len(parts) {
				lc.parseErr = fmt.Errorf("-d requires an argument (0 or 1)")
				return lc
			}
			val := parts[i+1]
			i++
			if val != "0" && val != "1" {
				lc.parseErr = fmt.Errorf("invalid -d value %q (expected 0 or 1)", val)
				return lc
			}
			fmt.Sscanf(val, "%d", &lc.logMode)
		case "-l", "-r", "--limit":
			if i+1 >= len(parts) {
				lc.parseErr = fmt.Errorf("%s requires a rate argument (e.g. 20K, 1M)", parts[i])
				return lc
			}
			r, err := parseRateLimit(parts[i+1])
			if err != nil {
				lc.parseErr = err
				return lc
			}
			lc.rateLimit = r
			i++
		case "-f":
			if i+1 >= len(parts) {
				lc.parseErr = fmt.Errorf("-f requires a log file path")
				return lc
			}
			lc.logFile = parts[i+1]
			i++
		default:
			if lc.arg1 == "" {
				lc.arg1 = parts[i]
			} else if lc.arg2 == "" {
				lc.arg2 = parts[i]
			}
		}
	}
	return lc
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
	enabled    bool   // -d 1: record a resume log
	logName    string // resume log path ("" = auto: <target>.tprlog)
	resumeFrom int    // block to resume from (0 = fresh start)
	resumeSize int64  // bytes already in the partial temp file
	blockSize  int    // bytes per block (tpBlockSize default; smaller when rate-limited)
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

	// Open the pty by hand rather than with pty.Start, so that the terminal modes
	// and the window size below are already in place when ssh starts: ssh reads
	// the termios of its own stdin and hands them to the server in the pty-req, so
	// whatever the pty says at that instant becomes the REMOTE shell's terminal.
	f, tty, err := pty.Open()
	if err != nil {
		fatalf("open pty: %v", err)
	}
	defer f.Close()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}

	// Set the local PTY (tp ↔ ssh) to raw mode:
	// - No ICANON (no 4096-byte line limit, needed for long base64 lines)
	// - No ICRNL / IXON (ssh handles line endings; XON/XOFF would eat ^Q and ^S)
	// - No OPOST (tp does its own \n -> \r\n with ensureCRLF)
	//
	// ECHO stays ON, and that is the whole reason line editing works. ssh copies
	// this ECHO bit into the pty-req, so it decides whether the REMOTE pty echoes
	// — and bash's readline decides once, at startup, whether it draws anything:
	// with ECHO off it concludes it is wired to a silent device and from then on
	// ↑ history recall, Tab completion and Ctrl+R all happen with nothing on the
	// screen. The command still runs, so it looks like tp swallowed the redraw.
	// (tp used to clear ECHO here because it echoed every keystroke itself; that
	// turned a local-echo shortcut into permanently invisible line editing.)
	//
	// Keeping it on costs nothing on this side: ssh puts the pty into raw mode
	// itself as soon as its loop starts, so the line discipline never echoes tp's
	// own writes back into the output reader.
	if termios, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS); err == nil {
		ptyRaw(termios)
		unix.IoctlSetTermios(int(f.Fd()), unix.TCSETS, termios)
	}

	// Match local terminal size, before ssh reads it for the pty-req.
	if w, h, err := term.GetSize(int(os.Stdin.Fd())); err == nil {
		pty.Setsize(f, &pty.Winsize{Rows: uint16(h), Cols: uint16(w)})
	}

	if err := cmd.Start(); err != nil {
		tty.Close()
		fatalf("start ssh: %v", err)
	}
	// ssh has its own copy of the slave now; ours has to go, or the pty would
	// still have a writer after ssh dies and the output reader would never see EOF.
	tty.Close()
	dbg("session start: ssh %s", strings.Join(args, " "))

	// Put the user's terminal into raw mode (like ssh does) so every keystroke —
	// including Ctrl+C — is delivered to us immediately instead of being
	// line-buffered by the local tty. With ISIG off, a lone Ctrl+C is forwarded
	// to the remote; a second press within ctrlCExitWindow quits tp (handled in
	// the stdin reader below). Local ECHO is off because the remote echoes — the
	// same split ssh uses; two programs painting the same keystroke is how you
	// get doubled characters and doubled erases.
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
	var capMu sync.Mutex
	var cap captureState

	// === PTY output → local stdout (fix \r\n double translation) ===
	go func() {
		var lineBuf []byte

		buf := make([]byte, 8192)
		for {
			n, rerr := f.Read(buf)
			if n > 0 {
				atomic.StoreInt64(&lastPtyOut, time.Now().UnixNano())
				dbg("pty out %d bytes: %s", n, dbgQuote(buf[:n]))
				incoming := buf[:n]
				capMu.Lock()
				capturing := cap.capturing
				capMu.Unlock()
				// Drop the remote's duplicate of our local echo (see echoSuppressor),
				// but only for normal interactive output — NEVER during a !get/!put
				// transfer, where the stream is base64/markers and any filtering would
				// corrupt it (a single eaten byte breaks base64 decode and leaks the
				// whole line to the screen).
				if !capturing && atomic.LoadInt32(&suppress) == 0 {
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

					capMu.Lock()
					handleLine(line, &cap)
					capMu.Unlock()
				}

				// Incomplete line: forward immediately unless it might be a TP marker.
				// No minimum-length gate: the remote shell echoes each keystroke
				// as 1-2 bytes, so gating on length would make typing invisible.
				capMu.Lock()
				capturing = cap.capturing
				capMu.Unlock()
				if len(lineBuf) > 0 && !capturing && atomic.LoadInt32(&suppress) == 0 {
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
				dlWatchStop() // the link is gone; a note about waiting would be a lie
				capMu.Lock()
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
				capMu.Unlock()
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

		// ISIG is off and the tty is raw, so Ctrl+C shows up here as a literal
		// 0x03 byte rather than raising SIGINT.
		// - 1st Ctrl+C during an active transfer aborts that transfer cleanly;
		//   outside a transfer it is forwarded to the remote.
		// - 3 Ctrl+C presses within ctrlCExitWindow quit tp.
		var ctrlC ctrlCTracker
		// confirmBuf accumulates the user's answer while a !put overwrite
		// confirmation is pending (see captureConfirm).
		var confirmBuf []byte

		for {
			n, rerr := os.Stdin.Read(buf)
			if n > 0 {
				data := buf[:n]
				dbg("stdin read %d bytes: %s", n, dbgQuote(data))

				// Three Ctrl+C within the window → quit tp.
				if c := bytes.Count(data, []byte{0x03}); c > 0 {
					if ctrlC.record(time.Now(), c) {
						restoreLocalTermios()
						fmt.Fprintln(os.Stderr, "\ntp: exiting (triple Ctrl+C)")
						os.Exit(130)
					}
				}

				// If a !put overwrite confirmation is pending, capture this input as
				// the answer instead of forwarding it to the remote. The triple-Ctrl+C
				// quit above still takes priority, so the user can always break out.
				putGuard.mu.Lock()
				answerCh := putGuard.answerCh
				putGuard.mu.Unlock()
				if answerCh != nil {
					dbg("stdin: capturing confirm input %q", dbgQuote(data))
					captureConfirm(data, &confirmBuf, answerCh)
					continue
				}

				// Single Ctrl+C during an active transfer aborts the transfer cleanly
				// instead of leaving tp stuck in capture/suppress mode.
				if bytes.IndexByte(data, 0x03) >= 0 {
					if cancelActivePut() {
						pendingLine = nil
						continue
					}
					if abortActiveGet(&capMu, &cap) {
						pendingLine = nil
						f.Write([]byte{0x03})
						continue
					}
				}

				// Decide whether this read is (the start of) a local transfer command.
				// Buffer it if: we're already mid-command, the first real byte is `!`, the
				// read is wrapped in bracketed-paste markers, or the text could still grow
				// into a tp command ("get@! …" starts with an ordinary letter, so it needs
				// this gate rather than a first-byte test).
				// Keys with no glyph of their own (arrow keys, Ctrl+R, Tab, an empty Enter)
				// are immediate actions for the remote's readline and can never start a tp
				// command. Buffering one loses it — the buffer only keeps printable bytes —
				// which is how Tab completion never reached the shell at all.
				if len(pendingLine) > 0 || isBangStart(data) ||
					bytes.HasPrefix(data, []byte("\x1b[200~")) ||
					(hasGlyph(data) && couldBeTpCommand(string(data))) {
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

					// The line may have diverged ("git status"): it was ordinary typing
					// after all. Those bytes are already on screen from the echo above, so
					// hand them to the remote without echoing twice, and register them as
					// expected echo so the remote's copy is not printed a second time.
					if len(pendingLine) > 0 && bytes.IndexByte(pendingLine, '\n') < 0 &&
						!couldBeTpCommand(string(pendingLine)) {
						dbg("pendingLine released: %q", pendingLine)
						echoSup.push(pendingLine)
						f.Write(pendingLine)
						pendingLine = nil
						continue
					}
				} else {
					// Normal input: forward it and show whatever comes back. The remote
					// shell is the single source of truth for the screen, exactly as
					// under plain ssh — it echoes what you type and redraws the line
					// whenever readline edits it. tp must not paint its own copy on top:
					// two painters, one screen, is how you get doubled characters and
					// doubled erases (tp's "\b \b" plus readline's "\b\e[K" wipes one
					// column too many and eats into the prompt).
					//
					// Drop any echo still owed from a released command line (see
					// pendingLine above) before keys that make readline redraw the whole
					// line (Tab completion, arrows, Ctrl+R): that redraw must never be
					// mistaken for the echo tp is waiting for and silently swallowed.
					if bytes.IndexByte(data, 0x09) >= 0 || bytes.IndexByte(data, 0x1b) >= 0 {
						echoSup.clear()
					}
					f.Write(data)
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
					// Recognised by its first word, so `get@! f` is a download while
					// `get@!x` or a heredoc line that merely starts with `get` is not.
					action := ""
					if parts := strings.Fields(clean); len(parts) > 0 {
						action = tpAction(parts[0])
					}
					if action != "" {
						parts := strings.Fields(clean)
						cmdCh <- parseLocalCmd(parts)
					} else {
						// Not a tp command (e.g. !!, or a pasted normal command).
						// Forward the ORIGINAL line — markers intact — so the remote
						// shell sees a proper bracketed paste.
						echoSup.push(stripANSI(line))
						f.Write(line)
					}
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	// === Command handler ===
	go func() {
		for lc := range cmdCh {
			if lc.parseErr != nil {
				errf("%v", lc.parseErr)
				continue
			}
			switch lc.action {
			case "get":
				if lc.arg1 == "" {
					fmt.Fprintln(os.Stderr, "\ntp: usage: get@! [-l <rate>] [-d 0|1] [-f <log_file>] <remote_path> [local_name]  (e.g. get@! -l 20K /tmp/f ~/Downloads/f)")
					continue
				}
				echoSup.clear() // don't let stale echo entries corrupt the marker/base64
				if lc.logMode == -1 {
					lc.logMode = 1 // resume by default; opt out with -d 0
				}
				doNoRemoteGet(injectCh, lc.arg1, lc.arg2, lc.logMode, lc.logFile, lc.rateLimit)
			case "put":
				if lc.arg1 == "" {
					fmt.Fprintln(os.Stderr, "\ntp: usage: put@! [-l <rate>] [-d 0|1] [-f <log_file>] <local_path> [remote_path]  (e.g. put@! -l 20K ~/f /tmp/f)")
					continue
				}
				localPath := expandLocalPath(lc.arg1)
				remotePath := lc.arg2
				if remotePath == "" {
					remotePath = "." + "/" + filepath.Base(localPath)
				}
				echoSup.clear() // don't let stale echo entries corrupt the transfer
				if lc.logMode == -1 {
					lc.logMode = 1 // resume by default; opt out with -d 0
				}
				doNoRemotePut(injectCh, &suppress, localPath, remotePath, lc.logMode, lc.logFile, lc.rateLimit)
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
