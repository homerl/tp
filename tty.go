package main

import (
	"bytes"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// ptyRaw turns the tp↔ssh pty into a byte pipe: no line discipline sitting
// between tp's injected base64 and ssh (ICANON would cap a write at 4096 bytes
// and buffer partial lines), no signal keys, no output translation.
//
// ECHO is deliberately left exactly as it was found. ssh reads the termios of
// its own stdin and copies them — ECHO included — into the SSH pty-req, so this
// bit decides whether the REMOTE pty echoes. And bash's readline decides once,
// at each prompt, whether it draws anything at all: with ECHO off it assumes a
// silent device and never redraws the input line, which makes ↑ history recall,
// Tab completion and Ctrl+R run with nothing on the screen. tp no longer echoes
// keystrokes itself (the remote's echo is the copy the user sees), so there is
// nothing left for clearing ECHO to buy.
func ptyRaw(t *unix.Termios) {
	t.Lflag &^= unix.ICANON | unix.ISIG
	t.Iflag &^= unix.ICRNL | unix.IXON
	t.Oflag &^= unix.OPOST
	t.Cc[unix.VMIN] = 1
	t.Cc[unix.VTIME] = 0
}

// hasGlyph reports whether a read carries at least one character with a visible
// glyph once the ANSI escape sequences are stripped. A read without any — a lone
// Tab, a lone Enter, an arrow key, Ctrl+R — is a readline action, never the start
// of a tp command, and must go straight to the remote: the command buffer keeps
// printable bytes only, so holding such a read simply loses the key.
func hasGlyph(b []byte) bool {
	return len(bytes.TrimFunc(stripANSI(b), func(r rune) bool {
		return r < 0x20 || r == 0x7f
	})) > 0
}

// echoSuppressor makes the local echo of a released command line the single
// source of truth for the characters it already painted. tp echoes those bytes
// itself while it is deciding whether the line is a transfer command; the remote
// shell echoes them back once they are handed over, which would be a duplicate.
// push() records the printable characters handed over; tryConsume() lets the
// output reader drop the remote's copy of each one. As soon as an incoming byte
// doesn't match the next expected echo, the queue is cleared (the echo is
// finished, or never coming on this link), so real command output is never
// swallowed. Ordinary typing is not pushed at all: the remote's echo is the only
// copy the user sees, exactly as under plain ssh.
type echoSuppressor struct {
	mu sync.Mutex
	q  []byte
}

// push records the echoable bytes in data (printable ASCII + UTF-8, excluding DEL
// and skipping ANSI escape sequences). Control characters (Enter, tab, arrows,
// backspace) are not recorded: the remote does not echo them as plain bytes.
func (e *echoSuppressor) push(data []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	i := 0
	for i < len(data) {
		b := data[i]
		if b == 0x1b {
			if j := skipEscapeSeq(data, i); j > i {
				i = j
				continue
			}
			i++
			continue
		}
		if (b >= 0x20 && b != 0x7f) || b == '\r' || b == '\n' {
			e.q = append(e.q, b)
		}
		i++
	}
}

// tryConsume reports whether b is the next expected remote echo (and thus should
// be suppressed). It consumes it if so. If the queue is non-empty but b doesn't
// match, the queue is cleared and b is treated as real output.
func (e *echoSuppressor) tryConsume(b byte) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.q) > 0 {
		if e.q[0] == b {
			e.q = e.q[1:]
			return true
		}
		e.q = nil
	}
	return false
}

// clear discards any pending echo bytes. Called before a !get/!put transfer so
// stale entries can't corrupt the __TP_BEGIN__ marker or the base64 stream.
func (e *echoSuppressor) clear() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.q = nil
}

// skipEscapeSeq returns the index just past the single ANSI escape sequence
// starting at data[start] (data[start] must be 0x1b). It returns start if the
// sequence can't be fully parsed (e.g. truncated at the end of the buffer).
func skipEscapeSeq(data []byte, start int) int {
	i := start + 1
	if i >= len(data) {
		return start
	}
	switch data[i] {
	case '[': // CSI: ESC [ params final(0x40-0x7e)
		i++
		for i < len(data) && (data[i] < 0x40 || data[i] > 0x7e) {
			i++
		}
		if i >= len(data) {
			return start // truncated
		}
		return i + 1 // skip the final byte
	case 'O': // SS3: ESC O final (application-mode arrows, F1-F4)
		if i+1 >= len(data) {
			return start // truncated
		}
		return i + 2
	case ']': // OSC: ESC ] ... (BEL or ST)
		i++
		for i < len(data) && data[i] != 0x07 {
			if data[i] == 0x1b && i+1 < len(data) && data[i+1] == '\\' {
				return i + 2
			}
			i++
		}
		if i < len(data) && data[i] == 0x07 {
			return i + 1
		}
		return start // truncated
	default: // Fe: ESC + one char
		return start + 2
	}
}

// captureConfirm consumes input bytes while an overwrite confirmation is
// pending, echoing them locally and buffering the answer until Enter. On Enter
// the buffered answer is delivered to answerCh; on Ctrl+C the confirmation is
// cancelled (answered "n"). It then clears putGuard.answerCh so the stdin
// reader resumes normal forwarding. It never forwards to the remote.
func captureConfirm(data []byte, confirmBuf *[]byte, answerCh chan<- string) {
	for _, b := range data {
		switch {
		case b == '\n' || b == '\r' || b == 0x03: // Enter commits, Ctrl+C cancels
			ans := "n"
			if b != 0x03 {
				ans = string(*confirmBuf)
				os.Stdout.Write([]byte{'\n'})
			} else {
				os.Stdout.Write([]byte("\r\n"))
			}
			select {
			case answerCh <- ans:
			default:
			}
			dbg("captureConfirm: delivering answer %q", ans)
			*confirmBuf = nil
			pendingAnswerClear()
			return
		case b == 0x7f || b == 0x08: // backspace / DEL
			if len(*confirmBuf) > 0 {
				*confirmBuf = (*confirmBuf)[:len(*confirmBuf)-1]
				os.Stdout.Write([]byte("\b \b"))
			}
		case b >= 0x20: // printable: echo + buffer
			os.Stdout.Write([]byte{b})
			*confirmBuf = append(*confirmBuf, b)
		default: // other control chars: ignore
		}
	}
}

// pendingAnswerClear resets putGuard.answerCh so the stdin reader stops
// capturing confirmation input.
func pendingAnswerClear() {
	putGuard.mu.Lock()
	putGuard.answerCh = nil
	putGuard.mu.Unlock()
}

// chopLastRune removes the last UTF-8 rune from b and returns the shortened
// slice. Used for backspace handling while editing a buffered `!` command.
func chopLastRune(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	i := len(b) - 1
	for i > 0 && b[i]&0xC0 == 0x80 { // walk back over UTF-8 continuation bytes
		i--
	}
	return b[:i]
}

// skipJunk returns the offset of the first "content" byte in b, skipping leading
// ANSI escape sequences and horizontal whitespace (space, tab). This is what we
// look past to find a `!` command that may be indented or wrapped in
// bracketed-paste markers (\x1b[200~).
func skipJunk(b []byte) int {
	i := 0
	for i < len(b) {
		switch {
		case b[i] == 0x1b:
			j := skipEscapeSeq(b, i)
			if j <= i {
				return i // truncated escape; stop here
			}
			i = j
		case b[i] == ' ' || b[i] == '\t':
			i++
		default:
			return i
		}
	}
	return i
}

// isBangStart reports whether the first content byte of data is '!' (after
// skipping leading escapes and whitespace). Detects a `!` command even when the
// terminal indents it or wraps it in bracketed-paste markers.
func isBangStart(data []byte) bool {
	i := skipJunk(data)
	return i < len(data) && data[i] == '!'
}

// stripANSI removes all ANSI escape sequences (CSI/OSC/Fe) from b, returning the
// clean content. Used to parse a `!` command that a terminal wrapped in
// bracketed-paste markers (\x1b[200~...\x1b[201~).
func stripANSI(b []byte) []byte {
	out := make([]byte, 0, len(b))
	i := 0
	for i < len(b) {
		if b[i] == 0x1b {
			if j := skipEscapeSeq(b, i); j > i {
				i = j
				continue
			}
		}
		out = append(out, b[i])
		i++
	}
	return out
}

// waitForQuiet waits until the remote pty has been silent for `quiet` (no output
// bytes), so a local message prints on a clean line instead of interleaving with
// the remote shell's PS1. It returns as soon as the quiet period is reached, or
// gives up after `maxWait` (the remote may be slow; we print anyway). This adds
// only a one-time delay at message boundaries, never during the data stream.
func waitForQuiet(quiet, maxWait time.Duration) {
	deadline := time.Now().Add(maxWait)
	last := atomic.LoadInt64(&lastPtyOut)
	for {
		if time.Now().After(deadline) {
			return // give up; print anyway
		}
		if cur := atomic.LoadInt64(&lastPtyOut); cur != last {
			last = cur // new output arrived; restart the quiet timer
			continue
		}
		// No new output since `last`; return once it's been quiet long enough.
		if time.Since(time.Unix(0, last)) >= quiet {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}
