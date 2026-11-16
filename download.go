package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cespare/xxhash/v2"
)

// b64stream is an incremental standard-base64 decoder. Feed it base64 alphabet
// characters (whitespace already stripped) and it emits the decoded bytes as
// soon as each 4-character quantum is complete, so a download streams to disk
// in O(1) memory instead of buffering the whole file. It tolerates the stream
// being re-wrapped or split at arbitrary points because it only ever groups the
// continuous alphabet in 4s from the start — the original line wrapping is
// irrelevant.
type b64stream struct {
	pending []byte // 0-3 alphabet chars waiting to complete a 4-char group
}

// feed decodes complete 4-char base64 groups from chars and writes the bytes to
// w, returning the count or an error on a corrupt group.
func (s *b64stream) feed(chars []byte, w io.Writer) (int64, error) {
	buf := append(s.pending, chars...)
	n := len(buf) / 4 * 4 // chars forming complete groups
	var written int64
	if n > 0 {
		dec := make([]byte, base64.StdEncoding.DecodedLen(n))
		dlen, err := base64.StdEncoding.Decode(dec, buf[:n])
		if err != nil {
			s.pending = nil
			return written, err
		}
		if _, err := w.Write(dec[:dlen]); err != nil {
			s.pending = nil
			return written, err
		}
		written = int64(dlen)
	}
	s.pending = buf[n:]
	return written, nil
}

// finish reports any trailing residue. A well-formed stream ends on a group
// boundary (pending empty); a non-empty remainder means the transfer was cut
// short.
func (s *b64stream) finish() error {
	if len(s.pending) == 0 {
		return nil
	}
	return fmt.Errorf("truncated base64 stream (%d trailing chars)", len(s.pending))
}

// reset clears the residue buffer. Used between blocks in a per-block
// download: each block is a fresh base64 stream, so the decoder must not carry
// residue from the previous block into the next.
func (s *b64stream) reset() {
	s.pending = nil
}

// tpBlockSize is the per-block download chunk size (4 MiB). A file is split
// into ceil(size/tpBlockSize) blocks; each block is checksummed and logged
// independently so an interrupted transfer can resume from the last good block.
const tpBlockSize = 4 * 1024 * 1024

// captureState tracks an in-progress !get download. Decoded bytes stream
// straight to a temp file (O(1) memory); on success it's renamed over the
// target, so a failed/interrupted transfer never clobbers an existing file.
type captureState struct {
	capturing bool
	file      *os.File
	tmpName   string // temp file being written; renamed to name on success
	name      string
	hash      hash.Hash // whole-file sha256 (legacy; unused when per-block)
	b64       b64stream // incremental base64 decoder (holds <4 residue chars)
	b64err    error     // first decode/write error, if any
	size      int64     // decoded bytes written so far (exact)
	totalSize int64     // expected size (0 = unknown)
	sha       string    // expected sha256 ("" = unknown / per-block mode)

	// Per-block resume state (populated when logging is enabled).
	blocksize    int       // bytes per block (tpBlockSize)
	totalBlocks  int       // ceil(totalSize / blocksize)
	curBlockNum  int       // block number currently being received
	curBlockSha  string    // expected checksum of the current block (from remote)
	curBlockHash hash.Hash // running hash of the current block's decoded bytes
	curBlockAlgo string    // "xxh64", "sha256", or "crc32" (detected from the checksum length)
	blocksDone   int       // number of blocks verified + logged so far
	logFile      *os.File  // resume log being appended (nil = no logging)
	logName      string    // resume log path

	started time.Time
	ticker  progressTicker
}

func (c *captureState) reset() {
	if c.file != nil {
		c.file.Close()
	}
	if c.logFile != nil {
		c.logFile.Close()
	}
	*c = captureState{}
	c.hash = sha256.New()
	c.blocksize = tpBlockSize
	c.started = time.Now()
	c.ticker.start(0)
}

// tickProgress prints instantaneous speed (delta since last tick, not overall average)
func (c *captureState) tickProgress() {
	if c.hash == nil {
		return
	}
	due, speed := c.ticker.tick(c.size)
	if !due {
		return
	}
	pct := ""
	if c.totalSize > 0 {
		pct = fmt.Sprintf(" (%.0f%%)", float64(c.size)/float64(c.totalSize)*100)
	}
	fmt.Fprintf(os.Stderr, "\r\033[1;36m[tp] ↓\033[0m %s%s %s   ", humanSize(c.size), pct, speedStr(speed))
}

// feedB64 decodes base64 groups from chars and streams the bytes to the temp
// file and, when per-block logging is active, the current block's hash.
func (c *captureState) feedB64(chars []byte) {
	if c.file == nil || c.b64err != nil {
		return
	}
	var w io.Writer
	if c.curBlockHash != nil {
		w = io.MultiWriter(c.file, c.curBlockHash)
	} else {
		w = c.file
	}
	n, err := c.b64.feed(chars, w)
	if err != nil {
		c.b64err = err
		return
	}
	c.size += n
}

// finalizeBlock verifies the current block's sha256 against the remote's and
// records it in the resume log. It is called when a new block begins (to close
// out the previous one) and once more at __TP_DONE__ (to close out the last).
// On a checksum mismatch it sets b64err so finish() aborts the transfer.
func (c *captureState) finalizeBlock() {
	if c.curBlockHash == nil {
		return
	}
	var actualSha string
	switch c.curBlockAlgo {
	case "xxh64":
		actualSha = fmt.Sprintf("%016x", c.curBlockHash.(hash.Hash64).Sum64())
	case "crc32":
		actualSha = fmt.Sprintf("%08x", c.curBlockHash.(hash.Hash32).Sum32())
	default: // sha256
		actualSha = hex.EncodeToString(c.curBlockHash.Sum(nil))
	}
	if c.curBlockSha != "" && actualSha != c.curBlockSha {
		c.b64err = fmt.Errorf("block %d checksum mismatch (want %s, got %s)",
			c.curBlockNum, shortCksum(c.curBlockSha), shortCksum(actualSha))
	}
	if c.logFile != nil && c.b64err == nil {
		fmt.Fprintf(c.logFile, "%d %s\n", c.curBlockNum, actualSha)
		c.logFile.Sync()
	}
	c.blocksDone = c.curBlockNum + 1
	c.curBlockHash = nil
}

// finish closes the temp file and either renames it over the target (success) or
// removes it (failure), so the original file — if any — is never left
// half-written. In per-block mode the whole-file sha256 is skipped: every block
// was already verified individually. On success the resume log is removed;
// on failure it is kept so the next run can resume.
func (c *captureState) finish() {
	if c.file == nil {
		return
	}
	// Check for a truncated stream (residue that never formed a full group).
	if c.b64err == nil {
		if err := c.b64.finish(); err != nil {
			c.b64err = err
		}
	}
	// Guard against a short transfer. In per-block mode each block's checksum is
	// computed against whatever bytes the remote actually sent, so a truncated
	// file (remote file shrank mid-download) or a full /tmp (dd wrote a partial
	// block) still passes every per-block check. The only backstop is the total
	// byte count the remote announced up front; if we received fewer bytes than
	// that, the file is incomplete — fail and keep the log so it can resume.
	if c.b64err == nil && c.totalSize > 0 && c.size != c.totalSize {
		c.b64err = fmt.Errorf("short download (%s of %s); remote file may have changed or /tmp filled",
			humanSize(c.size), humanSize(c.totalSize))
	}
	c.file.Close()
	c.file = nil
	if c.logFile != nil {
		c.logFile.Close()
		c.logFile = nil
	}

	if c.b64err != nil {
		if c.tmpName != "" {
			os.Remove(c.tmpName)
		}
		// Keep the resume log (if any) so the next run can pick up where this
		// one stopped. Drop it only if nothing was logged yet (nothing to resume).
		if c.logName != "" && c.blocksDone == 0 {
			os.Remove(c.logName)
		}
		errf("%v (original ./%s untouched)", c.b64err, c.name)
		return
	}
	if c.sha != "" {
		actualSha := hex.EncodeToString(c.hash.Sum(nil))
		if actualSha != c.sha {
			if c.tmpName != "" {
				os.Remove(c.tmpName)
			}
			if c.logName != "" && c.blocksDone == 0 {
				os.Remove(c.logName)
			}
			fmt.Fprintf(os.Stderr, "\n\033[1;31m[tp] ✗ SHA256 MISMATCH (original ./%s untouched)\033[0m\n  want: %s\n  got:  %s\n",
				c.name, c.sha, actualSha)
			return
		}
	}
	// Success: move the complete temp file over the target.
	if c.tmpName != "" {
		if err := os.Rename(c.tmpName, c.name); err != nil {
			os.Remove(c.tmpName)
			errf("rename to ./%s failed: %v", c.name, err)
			return
		}
	}
	// Transfer complete: the resume log is no longer needed, remove it.
	if c.logName != "" {
		os.Remove(c.logName)
	}
	elapsed := time.Since(c.started).Seconds()
	var speed float64
	if elapsed > 0 {
		speed = float64(c.size) / elapsed / 1024 / 1024
	}
	fmt.Fprintf(os.Stderr, "\n\033[1;32m[tp] ✓ ./%s (%s) %.1fs %s avg\033[0m\n",
		c.name, humanSize(c.size), elapsed, speedStr(speed))
}

// shortCksum abbreviates a checksum for error messages. The remote may report
// crc32 (8 hex chars), xxh64 (16) or sha256 (64) depending on which hash tool
// it has, so a fixed 12-char slice would run off the end of the shortest one
// and panic exactly when we are trying to report a problem.
func shortCksum(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}

// isB64Char reports whether c is a standard-base64 alphabet character. Used to
// accumulate only base64 data during a !get, tolerating the newlines/whitespace
// that intermediate hops may insert when re-wrapping the stream.
func isB64Char(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '+' || c == '/' || c == '=':
		return true
	}
	return false
}

func doNoRemoteGet(injectCh chan<- []byte, remotePath, localPath string, logMode int, logFile string) {
	if localPath == "" {
		localPath = filepath.Base(remotePath)
	}

	// Quote the remote path exactly like !put does (dq rejects quotes/$/
	// backtick/backslash/!), so a hostile path can't inject shell commands into
	// the remote one-liner. The local name is embedded in the __TP_BEGIN__ marker
	// and the remote echo, so it must not contain the marker's field separator
	// (|) or a double quote (which would break the remote echo's quoting).
	qRemote, ok := dq(remotePath)
	if !ok {
		fmt.Fprintf(os.Stderr, "\n\033[1;31m[tp] unsupported characters in remote path %q (no quotes/$/backtick/backslash/! allowed)\033[0m\n", remotePath)
		return
	}
	// localPath lands inside the double-quoted __TP_BEGIN__ echo on the remote,
	// so it needs the same protection as the remote path (dq) plus the marker's
	// field separator (|). Without this a name like "x$(cmd)y" would run cmd on
	// the remote — command substitution ($ and backtick) works even inside
	// double quotes, which the bare quote-check above would not catch.
	if _, okLP := dq(localPath); !okLP || strings.ContainsAny(localPath, "|") {
		fmt.Fprintf(os.Stderr, "\n\033[1;31m[tp] unsupported characters in local name %q (no quotes/$/backtick/backslash/!/| allowed)\033[0m\n", localPath)
		return
	}

	// Resume log name (only used when logMode == 1).
	if logFile == "" {
		logFile = localPath + ".tprlog"
	}

	// Resume check: if logging is on and a log + partial temp exist, verify the
	// last recorded block and, if it checks out, start the transfer from the next
	// block instead of byte 0. On any mismatch we fall back to a fresh download.
	resumeFrom := 0
	resumeSize := int64(0)
	if logMode == 1 {
		resumeFrom, resumeSize = checkResumeLog(logFile, localPath)
	}

	// Guard: if the local target already exists and we are NOT resuming, confirm
	// before overwriting it. (When resuming the target is the partial temp, not
	// the final file, so no overwrite prompt is needed.)
	if resumeFrom == 0 {
		if _, err := os.Stat(localPath); err == nil {
			// Spell out that this is the LOCAL file, and where. Inside a nested ssh a
			// bare "logs.zip already exists" reads like it is talking about the machine
			// you are typed into, which is the opposite machine.
			shown := localPath
			if abs, aerr := filepath.Abs(localPath); aerr == nil {
				shown = abs
			}
			if !promptOverwrite(shown, "locally (the machine you started tp on)") {
				return
			}
		}
	}

	// Publish the logging/resume config to the __TP_BEGIN__ handler (output
	// reader goroutine) before we inject the command.
	getLog.mu.Lock()
	getLog.enabled = logMode == 1
	getLog.logName = logFile
	getLog.resumeFrom = resumeFrom
	getLog.resumeSize = resumeSize
	getLog.mu.Unlock()

	nonce := setEchoNonce()
	if resumeFrom > 0 {
		fmt.Fprintf(os.Stderr, "\n\033[1;36m[tp] ↻ %s → ./%s (resume from block %d)\033[0m\n", remotePath, localPath, resumeFrom)
	} else {
		fmt.Fprintf(os.Stderr, "\n\033[1;36m[tp] ↓ %s → ./%s\033[0m\n", remotePath, localPath)
	}

	// Per-block one-liner: the remote splits the file into 4 MiB blocks and, for
	// each, emits a __TP_BLOCK__ <n> <checksum> marker followed by that block's
	// base64. The local side verifies each block's checksum as it arrives and
	// logs it, so an interrupted transfer resumes from the last good block. The
	// checksum prefers xxh64 (fast, 16 hex chars) and falls back to sha256 (64
	// hex chars) when the remote lacks xxh64sum; the local detects which by the
	// checksum length. Portable tools: stat/xxh64sum|sha256sum/base64 each have
	// GNU→BSD fallbacks. We start at N=$resumeFrom so a resume skips the blocks
	// already on disk.
	//
	// NOTE on quoting: qRemote uses are standalone command args (double-quoting
	// correct). localPath (in the __TP_BEGIN__ echo) and remotePath (in the
	// "no such file" echo) sit INSIDE a double-quoted echo string, so they stay
	// raw — dq() already rejected quotes/$/backtick/backslash/!.
	// The remote picks ONE hash tool up front (xxh64sum → sha256sum → shasum →
	// sha256 → cksum) and aborts with __TP_ERROR__ if none exist — we never
	// transfer without a checksum, so a corrupt stream can't be silently
	// accepted. The local detects the algorithm by checksum length
	// (8 = crc32/cksum, 16 = xxh64, 64 = sha256). The temp block file is
	// written to /tmp if writable, otherwise to the current directory.
	inject := leadSpace + fmt.Sprintf(
		"if [ -f %s ]; then TPDIR=/tmp;[ -w /tmp ]||TPDIR=.; SZ=$(stat -c%%s %s 2>/dev/null || stat -f%%z %s 2>/dev/null); T=$(( (SZ + %d) / %d )); if command -v xxh64sum >/dev/null 2>&1; then H=xxh64sum;A='{print $1}'; elif command -v sha256sum >/dev/null 2>&1; then H=sha256sum;A='{print $1}'; elif command -v shasum >/dev/null 2>&1; then H=\"shasum -a 256\";A='{print $1}'; elif command -v sha256 >/dev/null 2>&1; then H=sha256;A='{print $1}'; elif command -v cksum >/dev/null 2>&1; then H=cksum;A='{printf \"%%08x\",$1}'; else echo \"%s no hash tool on remote (need xxh64sum/sha256sum/shasum/sha256/cksum)\"; fi; if [ -n \"$H\" ]; then echo \"%s|%s|$SZ|$T\"; N=%d; while [ $N -lt $T ]; do dd if=%s bs=%d skip=$N count=1 2>/dev/null > $TPDIR/.tpblk.$$; [ -s $TPDIR/.tpblk.$$ ] || break; S=$($H $TPDIR/.tpblk.$$ 2>/dev/null | awk \"$A\"); echo \"%s $N $S\"; base64 -w 32000 $TPDIR/.tpblk.$$ 2>/dev/null || base64 $TPDIR/.tpblk.$$; N=$((N+1)); done; rm -f $TPDIR/.tpblk.$$; echo %s; fi; else echo \"%s no such file: %s\"; fi #%s\n",
		qRemote, qRemote, qRemote, tpBlockSize-1, tpBlockSize, splitMarker(TPError), splitMarker(TPBegin), localPath, resumeFrom, qRemote, tpBlockSize, splitMarker(TPBlock), splitMarker(TPDone), splitMarker(TPError), remotePath, nonce)
	if len(inject) > 4095 {
		fmt.Fprintf(os.Stderr, "\n\033[1;31m[tp] remote path too long for line-based download\033[0m\n")
		return
	}
	injectCh <- []byte(inject)
}

// checkResumeLog inspects a resume log and the matching partial temp file. It
// returns (resumeFrom, resumeSize, ok) where resumeFrom is the first block to
// re-transfer (0 = fresh start) and resumeSize is the byte count already on
// disk. It returns (0,0) when there is nothing valid to resume from: no log,
// filename mismatch, missing/partial temp, or a last-block checksum mismatch
// (in which case the stale log + temp are removed so the next run starts clean).
func checkResumeLog(logName, localPath string) (int, int64) {
	rl, stale := readResumeLog(logName, localPath)
	if stale {
		// Log is for a different file: it's stale. Drop it and start fresh.
		os.Remove(logName)
		os.Remove(localPath + ".tptmp")
		return 0, 0
	}
	if rl == nil || len(rl.blocks) < 1 {
		return 0, 0 // no log, or header only, no blocks recorded
	}
	last := rl.blocks[len(rl.blocks)-1]
	// The partial temp must exist and be exactly (last.num+1) full blocks long.
	tmpName := localPath + ".tptmp"
	fi, err := os.Stat(tmpName)
	if err != nil {
		os.Remove(logName)
		return 0, 0
	}
	resumeFrom := last.num + 1
	wantSize := int64(resumeFrom) * int64(tpBlockSize)
	// The temp must hold at least the recorded blocks. A Ctrl+C mid-block leaves
	// a partial trailing block (the temp is between wantSize and wantSize+block),
	// so we truncate it back to the last complete block before resuming. Anything
	// else — too small, or more than one extra block — is corrupt: start fresh.
	if fi.Size() < wantSize || fi.Size() >= wantSize+int64(tpBlockSize) {
		os.Remove(logName)
		os.Remove(tmpName)
		return 0, 0
	}
	if fi.Size() > wantSize {
		// Drop the partial trailing block so we resume on a clean block boundary.
		if err := os.Truncate(tmpName, wantSize); err != nil {
			os.Remove(logName)
			os.Remove(tmpName)
			return 0, 0
		}
	}
	// Verify the last block's checksum by re-reading it from the temp file.
	f, err := os.Open(tmpName)
	if err != nil {
		os.Remove(logName)
		return 0, 0
	}
	defer f.Close()
	if _, err := f.Seek(wantSize-int64(tpBlockSize), 0); err != nil {
		os.Remove(logName)
		return 0, 0
	}
	// Detect the algorithm from the stored checksum's length (8 = crc32/cksum,
	// 16 = xxh64, 64 = sha256) — it must match what the remote used when it
	// recorded the block.
	var h hash.Hash
	switch len(last.cksum) {
	case 16:
		h = xxhash.New()
	case 8:
		h = crc32.NewIEEE()
	default:
		h = sha256.New()
	}
	if _, err := io.CopyN(h, f, int64(tpBlockSize)); err != nil {
		os.Remove(logName)
		return 0, 0
	}
	var actual string
	switch len(last.cksum) {
	case 16:
		actual = fmt.Sprintf("%016x", h.(hash.Hash64).Sum64())
	case 8:
		actual = fmt.Sprintf("%08x", h.(hash.Hash32).Sum32())
	default:
		actual = hex.EncodeToString(h.Sum(nil))
	}
	if actual != last.cksum {
		// Last block doesn't match: the tail is corrupt. Start fresh.
		os.Remove(logName)
		os.Remove(tmpName)
		return 0, 0
	}
	return resumeFrom, wantSize
}
