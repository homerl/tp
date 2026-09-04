package main

import (
	"bytes"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// killLocalLine erases cols columns of the local echo on w (the characters the
// user has typed on the current line) and returns the new column count (0). It
// is a no-op when cols is 0. Used for Ctrl+U on normal input so the screen
// clears even when the remote never sends its own clear sequence down the pty.
func killLocalLine(w io.Writer, cols int) int {
	if cols > 0 {
		w.Write(bytes.Repeat([]byte("\b \b"), cols))
	}
	return 0
}

// echoInput writes a local echo of data to stdout. It is the single source of
// what the user sees as they type (the PTY and remote echoes are off/suppressed).
// ANSI escape sequences (arrows, bracketed-paste markers, ...) are skipped — they
// have no visible glyph. Backspace erases the previous character. The newline is
// echoed only when echoNL is true: for normal input the remote supplies its own
// line break (echoing it too would double the newline); `!` commands never reach
// the remote, so we echo their newline ourselves.
func echoInput(data []byte, echoNL bool, cols *int) {
	var out []byte
	i := 0
	for i < len(data) {
		b := data[i]
		switch {
		case b == 0x1b: // skip ANSI escape sequences (arrows, bracketed paste, ...)
			if j := skipEscapeSeq(data, i); j > i {
				i = j
				continue
			}
			i++ // lone/truncated ESC
		case b == 0x08 || b == 0x7f: // backspace / DEL: erase previous char
			if cols != nil && *cols > 0 {
				out = append(out, '\b', ' ', '\b')
				*cols--
			}
			// If nothing is left to erase (cursor at line start), swallow the
			// backspace so it can't smear the prompt. The remote still receives it
			// and its own line discipline ignores it there as well.
			i++
		case b == '\n':
			if echoNL {
				out = append(out, '\r', '\n')
			}
			if cols != nil {
				*cols = 0
			}
			i++
		case b >= 0x20: // printable (ASCII + UTF-8)
			out = append(out, b)
			if cols != nil {
				*cols++
			}
			i++
		default: // other control chars: no visible glyph
			i++
		}
	}
	if len(out) > 0 {
		os.Stdout.Write(out)
	}
}

// echoSuppressor makes local echo the single source of truth for what the user
// types. We always echo keystrokes locally (echoInput); the remote shell often
// echoes them back too, which would be a duplicate. push() records the printable
// characters we sent; tryConsume() lets the output reader drop the remote's copy
// of each one. As soon as an incoming byte doesn't match the next expected echo,
// the queue is cleared (the echo is finished, or never coming on this link), so
// real command output is never swallowed. This works whether or not the remote
// echoes at all.
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

// isLeadingSpace reports whether b is entirely horizontal whitespace (space /
// tab). Used at line start to hold a possibly-indented `!` command until its
// first real byte arrives. Deliberately EXCLUDES escape sequences: those (arrow
// keys, cursor moves, ...) are immediate actions that must be forwarded at once,
// not held. Bracketed-paste markers are handled separately via an explicit prefix
// check, since they are the only escapes that legitimately precede a `!` command.
func isLeadingSpace(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c != ' ' && c != '\t' {
			return false
		}
	}
	return true
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
