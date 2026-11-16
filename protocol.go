package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cespare/xxhash/v2"
)

const (
	TPBegin   = "__TP_BEGIN__"
	TPDone    = "__TP_DONE__"
	TPError   = "__TP_ERROR__"
	TPExists  = "__TP_EXISTS__"
	TPBlock   = "__TP_BLOCK__"
	TPTmpSize = "__TP_TMP_SIZE__"
	TPCksum   = "__TP_CKSUM__"
)

// tpMarkers lists every marker the output reader recognises.
var tpMarkers = []string{TPBegin, TPDone, TPError, TPExists, TPBlock, TPTmpSize, TPCksum}

// hasFullMarker reports whether s contains a marker in the form it takes in
// REMOTE OUTPUT. Injected commands carry split markers (__TP_""DONE__), so their
// own echo never matches here — which is exactly what lets the nonce filter tell
// "the shell echoing my command back" apart from "the answer to my command".
func hasFullMarker(s string) bool {
	for _, m := range tpMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// splitNonceTag pulls the "#<nonce>" tag out of a marker response's fields. The
// probes echo that tag (double-quoted, so the shell keeps it instead of treating
// it as a comment) which lets the reader tell a reply to the command still in
// flight from a late reply to one that already gave up. Returns the remaining
// fields and the tag ("" when the response carries none).
func splitNonceTag(fields []string) ([]string, string) {
	out := make([]string, 0, len(fields))
	nonce := ""
	for _, f := range fields {
		if nonce == "" && len(f) > 1 && strings.HasPrefix(f, "#") {
			nonce = f[1:]
			continue
		}
		out = append(out, f)
	}
	return out, nonce
}

// responseIsStale reports whether a tagged response belongs to an earlier
// command whose probe already timed out. Delivering it to whoever is waiting now
// would hand them an answer to a different question.
func responseIsStale(nonce string) bool {
	if nonce == "" {
		return false
	}
	cur := currentEchoNonce()
	return cur != "" && nonce != cur
}

func handleLine(line []byte, cap *captureState) {
	trimmed := strings.TrimRight(string(line), "\r\n")

	// Capturing mode (!get download in progress). We keep only base64 alphabet
	// characters, discarding newlines/whitespace, and stream-decode them as they
	// arrive: feedB64 buffers the 0-3 char partial group across lines, so the
	// multi-hop link can split or re-wrap the base64 stream at arbitrary points
	// without corrupting it (and memory stays O(1), not the whole file). The file
	// is written to a temp path; finish() runs once at __TP_DONE__ to check the
	// tail and checksum, then renames it into place.
	if cap.capturing {
		// __TP_BLOCK__ <num> <sha256> — a new block begins. Close out the previous
		// block (verify + log) and start the new one. The base64 for the new block
		// follows on subsequent lines (or after the marker on this line).
		if bi := strings.Index(trimmed, TPBlock); bi >= 0 {
			cap.finalizeBlock()
			// The marker line is "__TP_BLOCK__ <num> <checksum>" — the text after the
			// marker is the block number + checksum (NOT base64), so we must NOT feed
			// it to the block. The block's base64 arrives on subsequent lines. The
			// checksum length selects the algorithm: 8 = crc32 (cksum fallback),
			// 16 = xxh64 (fast), 64 = sha256.
			rest := trimmed[bi+len(TPBlock):]
			parts := strings.Fields(rest)
			if len(parts) >= 2 {
				fmt.Sscanf(parts[0], "%d", &cap.curBlockNum)
				cap.curBlockSha = parts[1]
				switch len(parts[1]) {
				case 16:
					cap.curBlockAlgo = "xxh64"
					cap.curBlockHash = xxhash.New()
				case 8:
					cap.curBlockAlgo = "crc32"
					cap.curBlockHash = crc32.NewIEEE()
				default:
					cap.curBlockAlgo = "sha256"
					cap.curBlockHash = sha256.New()
				}
			}
			cap.b64.reset() // each block is a fresh base64 stream
			dbg("%s: block %d algo %s", TPBlock, cap.curBlockNum, cap.curBlockAlgo)
			return
		}
		if di := strings.Index(trimmed, TPDone); di >= 0 {
			var chars []byte
			for i := 0; i < di; i++ { // base64 before the marker, if any
				if isB64Char(trimmed[i]) {
					chars = append(chars, trimmed[i])
				}
			}
			if len(chars) > 0 {
				cap.feedB64(chars)
			}
			cap.finalizeBlock() // close out the last block
			cap.finish()
			cap.capturing = false
			return
		}
		var chars []byte
		for i := 0; i < len(trimmed); i++ {
			if isB64Char(trimmed[i]) {
				chars = append(chars, trimmed[i])
			}
		}
		if len(chars) > 0 {
			cap.feedB64(chars)
		}
		cap.tickProgress()
		return
	}

	// Drop the remote's echo of the command we just injected. It carries our
	// per-command nonce and would otherwise print the raw (long) command to the
	// screen. Only checked when not capturing: the echo always arrives before
	// __TP_BEGIN__ starts a download. A line that also holds a complete marker is
	// the RESPONSE to that command (which echoes the same nonce), so it must not
	// be swallowed here.
	if n := currentEchoNonce(); n != "" && strings.Contains(trimmed, n) && !hasFullMarker(trimmed) {
		dbg("drop echo of injected command (nonce %s)", n)
		return
	}

	// __TP_EXISTS__ yes|no — the remote's answer to the !put existence check.
	// Deliver it to doNoRemotePut; it owns the rest of the guard logic.
	if idx := strings.Index(trimmed, TPExists); idx >= 0 {
		parts, tag := splitNonceTag(strings.Fields(trimmed[idx+len(TPExists):]))
		if responseIsStale(tag) {
			dbg("drop stale %s response (tag %s)", TPExists, tag)
			return
		}
		exists := len(parts) > 0 && parts[0] == "yes"
		dbg("%s response: exists=%v", TPExists, exists)
		putGuard.mu.Lock()
		ch := putGuard.existsCh
		putGuard.mu.Unlock()
		if ch != nil {
			select {
			case ch <- exists:
			default:
			}
			return
		}
		os.Stdout.Write(line)
		return
	}

	// __TP_TMP_SIZE__ <n> — the remote's answer to the !put resume probe (the
	// size of the partial temp file). Deliver it to doNoRemotePut; it decides
	// whether to append the remaining blocks or re-send from scratch.
	if idx := strings.Index(trimmed, TPTmpSize); idx >= 0 {
		parts, tag := splitNonceTag(strings.Fields(trimmed[idx+len(TPTmpSize):]))
		if responseIsStale(tag) {
			dbg("drop stale %s response (tag %s)", TPTmpSize, tag)
			return
		}
		var n int64
		if len(parts) > 0 {
			fmt.Sscanf(parts[0], "%d", &n)
		}
		dbg("%s response: size=%d", TPTmpSize, n)
		putGuard.mu.Lock()
		ch := putGuard.tmpSizeCh
		putGuard.mu.Unlock()
		if ch != nil {
			select {
			case ch <- n:
			default:
			}
			return
		}
		os.Stdout.Write(line)
		return
	}

	// __TP_CKSUM__ <c1> <c2> ... — the remote's answer to the !put resume
	// checksum probe: the checksums of the last few complete blocks of the
	// partial temp file, in order. Deliver them to doNoRemotePut; it matches
	// them against the local log to find the newest intact block to resume from.
	if idx := strings.Index(trimmed, TPCksum); idx >= 0 {
		raw := strings.Fields(trimmed[idx+len(TPCksum):])
		// Split off the trailing #nonce tag; the rest are the checksum fields.
		parts, tag := splitNonceTag(raw)
		if responseIsStale(tag) {
			dbg("drop stale %s response (tag %s)", TPCksum, tag)
			return
		}
		dbg("%s response: %d checksums", TPCksum, len(parts))
		putGuard.mu.Lock()
		ch := putGuard.cksumCh
		putGuard.mu.Unlock()
		if ch != nil {
			select {
			case ch <- parts:
			default:
			}
			return
		}
		os.Stdout.Write(line)
		return
	}

	// __TP_ERROR__ <message> — the remote reported a !get failure (e.g. the file
	// doesn't exist). Report it and don't create a file.
	if idx := strings.Index(trimmed, TPError); idx >= 0 {
		msg := strings.TrimSpace(trimmed[idx+len(TPError):])
		dbg("%s from remote: %s", TPError, msg)
		errf("%s", msg)
		return
	}

	// __TP_BEGIN__|filename|size|totalBlocks
	// The marker is searched anywhere in the line: shells (e.g. bash 5.1+
	// with bracketed paste) may prepend escape sequences like "\x1b[?2004l\r"
	// before command output. Base64 data lines can never contain "_" or "|",
	// so this is unambiguous. The 4th field is totalBlocks (per-block mode);
	// the whole-file sha256 is no longer sent (each block is verified on its own).
	if idx := strings.Index(trimmed, TPBegin); idx >= 0 {
		rest := trimmed[idx+len(TPBegin):]
		parts := strings.SplitN(rest, "|", 4)
		cap.reset()
		cap.capturing = true
		name := "downloaded_file"
		if len(parts) >= 2 && parts[1] != "" {
			name = parts[1]
		}
		if len(parts) >= 3 {
			fmt.Sscanf(parts[2], "%d", &cap.totalSize)
		}
		if len(parts) >= 4 {
			fmt.Sscanf(parts[3], "%d", &cap.totalBlocks)
		}
		cap.name = name
		cap.blocksize = tpBlockSize
		cap.tmpName = name + ".tptmp"
		dbg("%s: name=%q size=%d blocks=%d", TPBegin, name, cap.totalSize, cap.totalBlocks)

		// Read the logging/resume config (set by doNoRemoteGet before inject).
		getLog.mu.Lock()
		logEnabled := getLog.enabled
		logName := getLog.logName
		resumeFrom := getLog.resumeFrom
		resumeSize := getLog.resumeSize
		getLog.mu.Unlock()

		if logEnabled {
			if logName == "" {
				logName = name + ".tprlog"
			}
			cap.logName = logName
			if resumeFrom > 0 {
				// Resume: open the existing partial temp in append mode and the log
				// in append mode (keep the entries already recorded).
				file, err := os.OpenFile(cap.tmpName, os.O_APPEND|os.O_WRONLY, 0644)
				if err != nil {
					errf("open ./%s for resume: %v", cap.tmpName, err)
					return
				}
				cap.file = file
				cap.size = resumeSize
				lf, err := os.OpenFile(logName, os.O_APPEND|os.O_WRONLY, 0644)
				if err != nil {
					cap.file.Close()
					errf("open log %s: %v", logName, err)
					return
				}
				cap.logFile = lf
				fmt.Fprintf(os.Stderr, "\n\033[1;36m[tp] ↻ resuming ./%s from block %d/%d\033[0m\n", name, resumeFrom, cap.totalBlocks)
			} else {
				// Fresh start: create the temp file and the log (with a header line).
				os.Remove(cap.tmpName)
				file, err := os.Create(cap.tmpName)
				if err != nil {
					errf("create ./%s: %v", cap.tmpName, err)
					return
				}
				cap.file = file
				lf, err := os.Create(logName)
				if err != nil {
					cap.file.Close()
					errf("create log %s: %v", logName, err)
					return
				}
				cap.logFile = lf
				fmt.Fprintf(lf, "%s %d\n", name, cap.totalBlocks)
				lf.Sync()
				fmt.Fprintf(os.Stderr, "\n\033[1;36m[tp] ↓ %s → ./%s (resumable)\033[0m\n", humanSize(cap.totalSize), name)
			}
		} else {
			// Plain (non-resumable) download: temp file only, no log.
			os.Remove(cap.tmpName)
			file, err := os.Create(cap.tmpName)
			if err != nil {
				errf("create ./%s: %v", cap.tmpName, err)
				return
			}
			cap.file = file
			fmt.Fprintf(os.Stderr, "\n\033[1;36m[tp] ↓ %s → ./%s\033[0m\n", humanSize(cap.totalSize), name)
		}
		cap.capturing = true
		return
	}

	// __TP_DONE__ [remote_sha] - !put verification result (marker anywhere).
	// Just deliver the remote sha to doNoRemotePut; it owns all reporting.
	if idx := strings.Index(trimmed, TPDone); idx >= 0 {
		pendingPut.mu.Lock()
		ch := pendingPut.result
		pendingPut.mu.Unlock()

		if ch != nil {
			parts, tag := splitNonceTag(strings.Fields(trimmed[idx+len(TPDone):]))
			if responseIsStale(tag) {
				dbg("drop stale %s response (tag %s)", TPDone, tag)
				return
			}
			remoteSha := ""
			if len(parts) > 0 {
				remoteSha = parts[0]
			}
			dbg("%s response: remote sha %q", TPDone, remoteSha)
			// Non-blocking: never stall the output-reader goroutine (which drives
			// all terminal I/O) on a full channel.
			select {
			case ch <- remoteSha:
			default:
			}
			return
		}
		os.Stdout.Write(line)
		return
	}

	os.Stdout.Write(line)
}

// maxMarkerLen is one longer than the longest marker ("__TP_TMP_SIZE__"). A
// partial line only needs holding while a "__TP_" near its end could still grow
// into a marker; past that the bytes following it have already ruled every
// marker out.
const maxMarkerLen = 16

// mightBeMarker reports whether a partial line (no newline yet) still has to be
// held back from the screen because it could be a protocol marker. Two cases
// need holding: it already contains a complete marker (a response line that
// arrived cut in half — flushing it would both print raw protocol and lose the
// answer), or its tail holds a "__TP_" close enough to the end to still become
// one (a marker split across two reads).
//
// It deliberately does NOT hold any line that merely contains "__TP_" somewhere
// in the middle. The shell echoing one of our injected commands, or readline
// redrawing such a line out of history, contains plenty of __TP_ prefixes (the
// split form, __TP_""DONE__, which is never a real marker) and readline redraws
// carry no newline at all — holding those meant the recalled line sat in the
// buffer invisible until the next newline arrived, which is exactly what made
// arrow-key history recall look dead and buried the overwrite prompt under it.
func mightBeMarker(lineBuf []byte) bool {
	if hasFullMarker(string(lineBuf)) {
		return true
	}
	i := bytes.LastIndex(lineBuf, []byte("__TP_"))
	return i >= 0 && len(lineBuf)-i < maxMarkerLen
}

// dq double-quotes a path for safe use inside a remote shell command.
// It rejects paths containing characters that could break out of the quotes
// or otherwise alter the command line.
func dq(s string) (string, bool) {
	if s == "" || strings.ContainsAny(s, "'\"$`\\\t\n\r!") {
		return "", false
	}
	return `"` + s + `"`, true
}

// splitMarker inserts an empty-string concatenation right after the "__TP_"
// prefix, e.g. "__TP_DONE__" -> `__TP_""DONE__`. When the remote shell runs
// `echo __TP_""DONE__` it still prints "__TP_DONE__", but the command text
// itself (which the interactive shell echoes straight back to us) no longer
// contains the full marker, so handleLine can't misfire on the command's own
// echo.
func splitMarker(m string) string {
	const p = "__TP_"
	if strings.HasPrefix(m, p) {
		return p + `""` + m[len(p):]
	}
	return m
}

// leadSpace is prefixed to every command tp injects into the remote shell. On
// the many systems whose bash sets HISTCONTROL=ignorespace or ignoreboth
// (Debian and Ubuntu do it in /etc/bash.bashrc), a leading space keeps the line
// out of the history. Without it, pressing ↑ after a transfer recalls tp's
// 1200-character one-liner instead of the user's own commands — and running it
// re-downloads the file. Where HISTCONTROL is unset this is just a harmless
// leading space. It must NOT be used on !put base64 data lines: those are read
// by `head`/`base64 -d`, not by the shell.
// onlyEscapes reports whether b is nothing but escape sequences (and other
// non-printing bytes) with at least one escape in it: an arrow key, a Ctrl+R, a
// function key. Those are readline actions for the remote and must be forwarded
// the instant they arrive.
func onlyEscapes(b []byte) bool {
	return bytes.Contains(b, []byte{0x1b}) && len(bytes.TrimSpace(stripANSI(b))) == 0
}

const leadSpace = " "

// tpCommands are the in-session transfer commands.
//
// The bang trails the word ("get@! /path") on purpose. bash only performs
// history expansion on a "!" followed by something other than a space, tab or
// newline, so a trailing bang is inert: the line can never be swallowed by
// history expansion, which is what made the leading-bang spellings awkward to
// type on a live shell (a forwarded "!get" comes back as "bash: !get: event not
// found"). "!get"/"!put" are still accepted for muscle memory and existing docs.
var tpCommands = []string{"get@!", "put@!", "!get", "!put"}

// tpAction maps a typed first word to the transfer to run, or "" when the word
// is not a tp command. The legacy "!get"/"!put" match as prefixes, as they
// always have; the trailing-bang spellings must match exactly, so a word like
// "get@1x" stays an ordinary argument.
func tpAction(word string) string {
	switch word {
	case "get@!", "put@!":
		return word[:3]
	}
	switch {
	case strings.HasPrefix(word, "!get"):
		return "get"
	case strings.HasPrefix(word, "!put"):
		return "put"
	}
	return ""
}

// couldBeTpCommand reports whether text typed so far could still grow into a tp
// command. It gates buffering: "g" is ambiguous ("get@! /f" versus "git status"),
// so the line is held only until it diverges — "git" is released to the remote on
// the third keystroke, and ordinary typing keeps its readline, Tab completion and
// Ctrl+R. Without this gate, catching "get@!" would mean holding every line that
// starts with g or p for its whole length.
func couldBeTpCommand(text string) bool {
	text = strings.TrimLeft(string(stripANSI([]byte(text))), " \t")
	for _, c := range tpCommands {
		if len(text) <= len(c) {
			if strings.HasPrefix(c, text) {
				return true
			}
			continue
		}
		if strings.HasPrefix(text, c) {
			return true
		}
	}
	return false
}

// echoNonce tags each injected remote command with a random token (appended as
// a shell comment) so the output reader can recognize and drop the remote's
// echo of that command — otherwise the raw (long, ugly) command would print to
// the screen. The token is random so it can never collide with real output.
var echoNonce struct {
	mu  sync.Mutex
	val string
}

// setEchoNonce generates a fresh nonce and returns it. Call it before injecting
// a command and append the returned value to that command.
func setEchoNonce() string {
	var b [8]byte
	var s string
	if _, err := rand.Read(b[:]); err == nil {
		s = hex.EncodeToString(b[:])
	} else {
		s = fmt.Sprintf("tpn%d", time.Now().UnixNano()) // urandom unavailable: fall back to time-based
	}
	echoNonce.mu.Lock()
	echoNonce.val = s
	echoNonce.mu.Unlock()
	return s
}

// currentEchoNonce returns the active nonce ("" if none is set).
func currentEchoNonce() string {
	echoNonce.mu.Lock()
	defer echoNonce.mu.Unlock()
	return echoNonce.val
}

// existsProbe reports whether the (dq-quoted) target exists, as
// "__TP_EXISTS__ #<nonce> yes|no". The quoted nonce tag rides back in the answer
// so a reply to an already-abandoned probe is recognisable and dropped.
func existsProbe(qTarget, nonce string) string {
	return leadSpace + fmt.Sprintf("[ -e %s ] && echo %s \"#%s\" yes || echo %s \"#%s\" no\n",
		qTarget, splitMarker(TPExists), nonce, splitMarker(TPExists), nonce)
}

// tmpSizeProbe reports the size (in bytes) of the upload's partial temp file,
// as "__TP_TMP_SIZE__ #<nonce> <n>" (0 if missing). !put resume uses it to check
// the remote's partial file matches the blocks already sent.
func tmpSizeProbe(qTmp, nonce string) string {
	return leadSpace + fmt.Sprintf("echo %s \"#%s\" $(wc -c < %s 2>/dev/null || echo 0)\n",
		splitMarker(TPTmpSize), nonce, qTmp)
}

// cksumProbe reports the xxh64 checksums of the given 0-based block indices of
// the upload's partial temp file, as "__TP_CKSUM__ #<nonce> <c1> <c2> ...". Each
// block is a 4MiB slice hashed with xxh64 (matching the local log); if the remote
// lacks xxh64sum the fields come back empty and the caller re-uploads.
func cksumProbe(qTmp string, blocks []int, nonce string) string {
	list := make([]string, len(blocks))
	for i, b := range blocks {
		list[i] = strconv.Itoa(b)
	}
	return leadSpace + fmt.Sprintf(
		"echo %s \"#%s\" $(for i in %s; do dd if=%s bs=4M skip=$i count=1 2>/dev/null | xxh64sum 2>/dev/null | awk '{print $1}'; done | tr '\\n' ' ')\n",
		splitMarker(TPCksum), nonce, strings.Join(list, " "), qTmp)
}

// truncateCmd truncates the partial temp file to exactly nBlocks complete 4MiB
// blocks, dropping any corrupt trailing blocks. It prefers the (cheap,
// metadata-only) `truncate` and falls back to a copy on BSD/macOS.
func truncateCmd(qTmp string, nBlocks int64, nonce string) string {
	size := nBlocks * int64(tpBlockSize)
	return leadSpace + fmt.Sprintf("truncate -s %d %s 2>/dev/null || { head -c %d %s > %s.trunc && mv -f %s.trunc %s; } #%s\n",
		size, qTmp, size, qTmp, qTmp, qTmp, qTmp, nonce)
}

// waitOneShot waits for a value on ch or a timeout, returning (value, ok). ok is
// false (and value is the zero value) on timeout.
func waitOneShot[T any](ch chan T, timeout time.Duration) (T, bool) {
	var zero T
	select {
	case v := <-ch:
		return v, true
	case <-time.After(timeout):
		return zero, false
	}
}

// probeRemote injects a nonce-tagged probe into the remote and waits (up to
// timeout) for its result. The output reader delivers the result through a
// one-shot channel registered in putGuard via register; register(nil) clears it
// before returning. ok is false on timeout; callers fall back to a safe
// default. The caller generates the nonce and embeds it in probeCmd so the
// probe's own echo can be dropped.
func probeRemote[T any](injectCh chan<- []byte, probeCmd string, timeout time.Duration, register func(ch chan T)) (T, bool) {
	var zero T
	ch := make(chan T, 1)
	putGuard.mu.Lock()
	register(ch)
	putGuard.mu.Unlock()
	defer func() {
		putGuard.mu.Lock()
		register(nil)
		putGuard.mu.Unlock()
	}()
	// The timeout is meant to measure how long the REMOTE takes to answer. On a
	// link that rate-limits input the command itself can take minutes to arrive,
	// so the clock only starts once tp has actually handed every byte over.
	if !injectWait(injectCh, []byte(probeCmd)) {
		return zero, false
	}
	if !waitInjectDrained(nil) {
		dbg("probe: link died before the command was fully delivered: %s", dbgQuote([]byte(probeCmd)))
		return zero, false
	}
	v, ok := waitOneShot(ch, timeout)
	if !ok {
		dbg("probe timed out after %v: %s", timeout, dbgQuote([]byte(probeCmd)))
	} else {
		dbg("probe answered: %v", v)
	}
	return v, ok
}

// probeRemoteTmpSize asks the remote how big the upload's partial temp file is
// (for !put resume). ok is false on timeout (the caller then falls back to a
// full re-upload, which is always safe).
func probeRemoteTmpSize(injectCh chan<- []byte, qTmp string) (int64, bool) {
	nonce := setEchoNonce()
	return probeRemote(injectCh, tmpSizeProbe(qTmp, nonce), 10*time.Second, func(ch chan int64) { putGuard.tmpSizeCh = ch })
}

// probeRemoteCksums asks the remote for the xxh64 checksums of the given block
// indices of the upload's partial temp file (for !put resume). ok is false on
// timeout (the caller then falls back to a full re-upload, which is always
// safe). The returned slice has one entry per requested block, in order; an
// entry is empty if that block couldn't be read/hashed.
func probeRemoteCksums(injectCh chan<- []byte, qTmp string, blocks []int) ([]string, bool) {
	nonce := setEchoNonce()
	return probeRemote(injectCh, cksumProbe(qTmp, blocks, nonce), 15*time.Second, func(ch chan []string) { putGuard.cksumCh = ch })
}
