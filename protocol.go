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
	// __TP_BEGIN__ starts a download.
	if n := currentEchoNonce(); n != "" && strings.Contains(trimmed, n) {
		return
	}

	// __TP_EXISTS__ yes|no — the remote's answer to the !put existence check.
	// Deliver it to doNoRemotePut; it owns the rest of the guard logic.
	if idx := strings.Index(trimmed, TPExists); idx >= 0 {
		parts := strings.Fields(trimmed[idx+len(TPExists):])
		exists := len(parts) > 0 && parts[0] == "yes"
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
		parts := strings.Fields(trimmed[idx+len(TPTmpSize):])
		var n int64
		if len(parts) > 0 {
			fmt.Sscanf(parts[0], "%d", &n)
		}
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
		// Drop the trailing #nonce tag (and any stray # field); keep only the
		// checksum fields.
		var parts []string
		for _, f := range raw {
			if strings.HasPrefix(f, "#") {
				continue
			}
			parts = append(parts, f)
		}
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
			parts := strings.Fields(trimmed[idx+len(TPDone):])
			remoteSha := ""
			if len(parts) > 0 {
				remoteSha = parts[0]
			}
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

// mightBeMarker reports whether a partial line (no newline yet) could
// contain a TP marker. Any line containing "__TP_" is held until its
// newline arrives, so a marker split across two reads can never be
// forwarded early and destroyed. Base64 data lines can never contain
// underscores, and normal shell output essentially never contains our
// private marker prefix, so holding such lines briefly is harmless.
func mightBeMarker(lineBuf []byte) bool {
	return bytes.Contains(lineBuf, []byte("__TP_"))
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
// "__TP_EXISTS__ yes|no".
func existsProbe(qTarget, nonce string) string {
	return fmt.Sprintf("[ -e %s ] && echo %s yes || echo %s no #%s\n",
		qTarget, splitMarker(TPExists), splitMarker(TPExists), nonce)
}

// tmpSizeProbe reports the size (in bytes) of the upload's partial temp file,
// as "__TP_TMP_SIZE__ <n>" (0 if missing). !put resume uses it to check the
// remote's partial file matches the blocks already sent.
func tmpSizeProbe(qTmp, nonce string) string {
	return fmt.Sprintf("echo %s $(wc -c < %s 2>/dev/null || echo 0) #%s\n",
		splitMarker(TPTmpSize), qTmp, nonce)
}

// cksumProbe reports the xxh64 checksums of the given 0-based block indices of
// the upload's partial temp file, as "__TP_CKSUM__ <c1> <c2> ...". Each block
// is a 4MiB slice hashed with xxh64 (matching the local log); if the remote
// lacks xxh64sum the fields come back empty and the caller re-uploads.
func cksumProbe(qTmp string, blocks []int, nonce string) string {
	list := make([]string, len(blocks))
	for i, b := range blocks {
		list[i] = strconv.Itoa(b)
	}
	return fmt.Sprintf(
		"echo %s $(for i in %s; do dd if=%s bs=4M skip=$i count=1 2>/dev/null | xxh64sum 2>/dev/null | awk '{print $1}'; done | tr '\\n' ' ') #%s\n",
		splitMarker(TPCksum), strings.Join(list, " "), qTmp, nonce)
}

// truncateCmd truncates the partial temp file to exactly nBlocks complete 4MiB
// blocks, dropping any corrupt trailing blocks. It prefers the (cheap,
// metadata-only) `truncate` and falls back to a copy on BSD/macOS.
func truncateCmd(qTmp string, nBlocks int64, nonce string) string {
	size := nBlocks * int64(tpBlockSize)
	return fmt.Sprintf("truncate -s %d %s 2>/dev/null || { head -c %d %s > %s.trunc && mv -f %s.trunc %s; } #%s\n",
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
	ch := make(chan T, 1)
	putGuard.mu.Lock()
	register(ch)
	putGuard.mu.Unlock()
	defer func() {
		putGuard.mu.Lock()
		register(nil)
		putGuard.mu.Unlock()
	}()
	injectCh <- []byte(probeCmd)
	return waitOneShot(ch, timeout)
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
