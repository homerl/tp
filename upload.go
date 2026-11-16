package main

import (
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cespare/xxhash/v2"
)

// putDataLineLen: base64 characters per data line. The remote PTY is in
// canonical mode with a 4096-byte line buffer; input lines longer than that
// get truncated by the tty driver, silently corrupting the transfer. 3765
// keeps a safe margin.
const putDataLineLen = 4000

// putCmdLine builds the single remote command for uploading fileSize bytes
// sent as N base64 data lines, and returns that command plus N.
//
// `head -n N` exits after reading exactly N lines, so the transfer does NOT
// depend on receiving an EOF (^D). That matters a lot: in multi-hop SSH
// chains an intermediate canonical-mode pty consumes ^D as VEOF and it never
// reaches the target machine, which left the old `base64 -d` waiting forever
// and wedged the terminal. Because head exits on its own, nothing is left
// reading the tty afterwards — the terminal is always recovered.
//
// The decoded data goes to a temp file and is moved over the target only if
// its size matches, so a corrupt transfer never clobbers an existing file.
func putCmdLine(qTarget, qTmp string, sendSize, fileSize int64, resume bool, nonce string) (string, int) {
	// sendSize is how many bytes THIS run transmits (the remaining blocks when
	// resuming, the whole file otherwise); it sets N, the number of data lines
	// head will read. fileSize is the final on-disk size the temp must reach
	// before it's moved over the target (always the full file size).
	b64Len := (sendSize + 2) / 3 * 4
	n := (int(b64Len) + putDataLineLen - 1) / putDataLineLen
	redirect := ">"
	if resume {
		redirect = ">>"
	}
	line := leadSpace + fmt.Sprintf(
		"head -n %d | base64 -d %s %s 2>/dev/null; [ \"$(wc -c < %s 2>/dev/null)\" = \"%d\" ] && mv -f %s %s; rm -f %s; echo %s \"#%s\" $(sha256sum %s 2>/dev/null | awk '{print $1}')\n",
		n, redirect, qTmp, qTmp, fileSize, qTmp, qTarget, qTmp, splitMarker(TPDone), nonce, qTarget)
	return line, n
}

// isYesAnswer reports whether a confirmation answer means "yes" (y/yes,
// case-insensitive, surrounding whitespace ignored).
func isYesAnswer(s string) bool {
	a := strings.ToLower(strings.TrimSpace(s))
	return a == "y" || a == "yes"
}

// promptOverwrite asks the user to confirm overwriting an existing target file,
// capturing the answer via the stdin reader (putGuard.answerCh). It returns
// true only if the user explicitly answers y/yes; any other answer, a timeout,
// or a cancel aborts. where is an optional location hint shown in the prompt
// ("on remote" for !put); it's empty for local (!get) targets.
func promptOverwrite(target, where string) bool {
	loc := ""
	if where != "" {
		loc = " " + where
	}
	// Let the remote finish flushing (its PS1) so the prompt lands on a clean
	// line instead of interleaving with the shell's prompt.
	waitForQuiet(30*time.Millisecond, 300*time.Millisecond)
	fmt.Fprintf(os.Stderr, "\n\033[1;33m[tp] ⚠ %s already exists%s. Overwrite? [y/N]\033[0m ", target, loc)
	putGuard.mu.Lock()
	answerCh := make(chan string, 1)
	putGuard.answerCh = answerCh
	putGuard.mu.Unlock()

	answer, ok := waitOneShot(answerCh, 60*time.Second)
	dbg("promptOverwrite: answer=%q ok=%v", answer, ok)
	// Release the capture (captureConfirm already clears it on a normal answer;
	// this covers the timeout path so late input isn't swallowed).
	putGuard.mu.Lock()
	putGuard.answerCh = nil
	putGuard.mu.Unlock()
	if !ok {
		errf("confirmation timed out; aborting, %s not modified", target)
		return false
	}
	if !isYesAnswer(answer) {
		fmt.Fprintf(os.Stderr, "\033[1;33m[tp] ⚠ aborted, %s not modified\033[0m\n", target)
		return false
	}
	return true
}

// confirmOverwrite checks whether the remote target already exists and, if so,
// prompts the user to confirm overwriting it. Returns false if the upload
// should be aborted (the user declined, or the check/confirmation couldn't be
// completed in time). It injects a one-shot existence probe tagged with its own
// nonce (so the probe's command echo is dropped) and waits for the
// __TP_EXISTS__ result before deciding whether to ask.
func confirmOverwrite(injectCh chan<- []byte, remotePath string) bool {
	qTarget, ok := dq(remotePath)
	if !ok {
		return true // caller already validated the path; proceed
	}
	nonce := setEchoNonce()
	exists, ok := probeRemote(injectCh, existsProbe(qTarget, nonce), 10*time.Second, func(ch chan bool) { putGuard.existsCh = ch })
	dbg("confirmOverwrite: exists=%v ok=%v", exists, ok)
	if !ok {
		errf("could not determine if %s exists; aborting for safety", remotePath)
		return false
	}
	if !exists {
		return true // nothing to overwrite
	}
	return promptOverwrite(remotePath, "on remote")
}

// logPutBlock records a completed block's checksum in the !put resume log. The
// local is the source and always hashes with xxh64 (fast); the checksum is only
// for tracking/debugging — the upload's correctness is guaranteed by the final
// whole-file sha256 the remote reports back.
func logPutBlock(f *os.File, blockNum int, h hash.Hash) {
	cksum := fmt.Sprintf("%016x", h.(hash.Hash64).Sum64())
	fmt.Fprintf(f, "%d %s\n", blockNum, cksum)
	f.Sync()
}

// checkPutResumeLog reports how many blocks a previous !put already sent, by
// reading the local resume log. Unlike the get log, there is no local partial
// file to re-verify (the local IS the source and still has the original), so we
// only check the header names this file and that the block numbers are a clean
// 0..N-1 run. It returns the block to resume from (N) and the total block count
// from the header; (0, 0) means "no valid log, start fresh". A stale log (wrong
// filename or a gap in the block numbers) is removed.
func checkPutResumeLog(logName, localPath string) (int, int) {
	rl, stale := readResumeLog(logName, localPath)
	if stale {
		os.Remove(logName) // stale log for a different file
		return 0, 0
	}
	if rl == nil {
		return 0, 0 // no log -> fresh start
	}
	if rl.blockLines == 0 {
		return 0, rl.total // header only, nothing sent yet
	}
	// The block lines must be a clean 0..N-1 run: no malformed lines, no gaps,
	// no out-of-order numbers.
	if len(rl.blocks) != rl.blockLines {
		os.Remove(logName) // a malformed line: corrupt log
		return 0, 0
	}
	for i, b := range rl.blocks {
		if b.num != i {
			os.Remove(logName) // gap or out-of-order: corrupt log
			return 0, 0
		}
	}
	return len(rl.blocks), rl.total // N blocks sent (lines 1..N)
}

// readPutLogChecksums reads the local !put resume log and returns a map of
// block number -> checksum. It is used by the resume path to match the
// remote's reported block checksums against what we recorded when we sent
// them. It returns nil if the log is missing or doesn't name this file.
func readPutLogChecksums(logName, localPath string) map[int]string {
	rl, _ := readResumeLog(logName, localPath)
	if rl == nil || len(rl.blocks) == 0 {
		return nil
	}
	cksums := make(map[int]string, len(rl.blocks))
	for _, b := range rl.blocks {
		cksums[b.num] = b.cksum
	}
	return cksums
}

// injectBestEffort queues a small cleanup command, dropping it if the injection
// queue is full — which only happens when the link is already wedged, in which
// case there is nobody left to run it anyway.
func injectBestEffort(injectCh chan<- []byte, data []byte) {
	select {
	case injectCh <- data:
		atomic.AddInt64(&injectQueued, int64(len(data)))
	default:
	}
}

// putAbort reports a lost link and hands the terminal back.
func putAbort(suppress *int32, remotePath string) {
	atomic.StoreInt32(suppress, 0)
	fmt.Fprintf(os.Stderr, "\n\033[1;31m[tp] ✗ connection lost; %s not uploaded (re-run to resume)\033[0m\n", remotePath)
}

// doNoRemotePut uploads without tp on the remote. The remote runs a single
// `head -n N | base64 -d` (see putCmdLine for why that survives multi-hop
// chains); a corrupt transfer fails the size guard and never clobbers the
// existing target file.
func doNoRemotePut(injectCh chan<- []byte, suppress *int32, localPath, remotePath string, logMode int, logFile string) {
	lf, err := os.Open(localPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n\033[1;31m[tp] open %s: %v\033[0m\n", localPath, err)
		return
	}
	defer lf.Close()

	lstat, _ := lf.Stat()
	fileSize := lstat.Size()
	totalBlocks := (int(fileSize) + tpBlockSize - 1) / tpBlockSize

	qTarget, okT := dq(remotePath)
	tmpOut := remotePath + ".tptmp"
	qTmp, okO := dq(tmpOut)
	if !okT || !okO {
		fmt.Fprintf(os.Stderr, "\n\033[1;31m[tp] unsupported characters in remote path %q (no quotes/$/backtick/backslash/! allowed)\033[0m\n", remotePath)
		return
	}
	// Resume log name (only used when logMode == 1). Stored locally, next to the
	// source file, so a re-run can pick up where an interrupted upload left off.
	if logFile == "" {
		logFile = localPath + ".tprlog"
	}

	// Resume decision. When logging is on and a previous run left a valid log, we
	// know how many blocks we already sent. We probe the remote for the size of
	// its partial temp file (K = size/4MiB complete blocks), then verify the last
	// few complete blocks against the log's checksums. We resume from the newest
	// intact block (truncating any corrupt trailing blocks off the temp first);
	// if none of the recent blocks match we report it and re-upload the whole
	// file. The final whole-file sha256 is the backstop for anything weirder.
	resumeFrom := 0
	if logMode == 1 {
		sent, _ := checkPutResumeLog(logFile, localPath)
		if sent > 0 && sent <= totalBlocks {
			if remoteSize, ok := probeRemoteTmpSize(injectCh, qTmp); ok {
				K := int(remoteSize / int64(tpBlockSize)) // complete blocks on the remote
				if K > 0 && K <= sent {
					// The last up-to-5 complete blocks, oldest -> newest.
					lo := K - 5
					if lo < 0 {
						lo = 0
					}
					blocks := make([]int, K-lo)
					for i := lo; i < K; i++ {
						blocks[i-lo] = i
					}
					remoteCk, ok2 := probeRemoteCksums(injectCh, qTmp, blocks)
					logCk := readPutLogChecksums(logFile, localPath)
					if ok2 && logCk != nil && len(remoteCk) == len(blocks) {
						// Newest block whose checksum matches the log wins.
						match := -1
						for i, num := range blocks {
							if remoteCk[i] != "" && remoteCk[i] == logCk[num] {
								match = num
							}
						}
						if match >= 0 {
							resumeFrom = match + 1
							// Drop any trailing bytes past the last good block — corrupt
							// blocks, or a partial block left by a mid-block Ctrl+C — so
							// the append starts on a clean boundary. Truncating to exactly
							// resumeFrom full blocks is a no-op when the temp already ends
							// there; skip it once everything is sent.
							if resumeFrom < totalBlocks {
								if !injectWait(injectCh, []byte(truncateCmd(qTmp, int64(resumeFrom), setEchoNonce()))) {
									putAbort(suppress, remotePath)
									return
								}
								time.Sleep(200 * time.Millisecond)
							}
							fmt.Fprintf(os.Stderr, "\n\033[1;36m[tp] ↻ %s → %s (resume from block %d/%d)\033[0m\n", localPath, remotePath, resumeFrom, totalBlocks)
						} else {
							errf("remote temp is corrupt (no recent block matches the log); re-uploading whole file")
							os.Remove(logFile)
						}
					} else {
						// Couldn't verify (no xxh64sum, timeout, ...): re-upload.
						os.Remove(logFile)
					}
				} else {
					// Temp size doesn't line up with what we sent: re-upload.
					os.Remove(logFile)
				}
			}
		} else if sent > totalBlocks {
			// Stale log from a larger/different file: discard and start fresh.
			os.Remove(logFile)
		}
	}

	// Guard: if the remote target already exists, confirm before overwriting it.
	// (Skipped when resuming: the target is the partial temp, not the final file.)
	if resumeFrom == 0 && !confirmOverwrite(injectCh, remotePath) {
		return
	}

	// How much this run transmits and whether the remote appends to its existing
	// partial temp (resume) or overwrites it (fresh).
	sendSize := fileSize
	resume := resumeFrom > 0
	if resume {
		sendSize = fileSize - int64(resumeFrom)*int64(tpBlockSize)
		if sendSize < 0 {
			sendSize = 0 // all blocks already present; just finalize (move temp)
		}
	}

	nonce := setEchoNonce()
	cmdLine, numLines := putCmdLine(qTarget, qTmp, sendSize, fileSize, resume, nonce)
	if len(cmdLine) > 4095 {
		fmt.Fprintf(os.Stderr, "\n\033[1;31m[tp] remote path too long for line-based upload\033[0m\n")
		return
	}

	// Hash the local file up front so we can verify after the upload. This
	// deliberately reads the file a second time (the transfer below re-reads it):
	// that snapshot IS the consistency check. If the file is edited mid-upload,
	// the bytes we send no longer hash to this value, and the mismatch is reported
	// instead of a torn file being silently accepted.
	localSha := sha256FileHandle(lf)
	// For a resume, skip the blocks we already sent (the remote has them).
	lf.Seek(int64(resumeFrom)*int64(tpBlockSize), io.SeekStart)

	// Open the resume log. Fresh upload: create it and write the header. Resume:
	// append to it (the header + already-sent blocks are already recorded).
	var logF *os.File
	if logMode == 1 {
		var lerr error
		if resume {
			logF, lerr = os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0644)
		} else {
			logF, lerr = os.Create(logFile)
			if lerr == nil {
				fmt.Fprintf(logF, "%s %d\n", localPath, totalBlocks)
			}
		}
		if lerr != nil {
			fmt.Fprintf(os.Stderr, "\n\033[1;31m[tp] cannot open resume log %s: %v\033[0m\n", logFile, lerr)
			return
		}
		defer logF.Close()
	}

	fmt.Fprintf(os.Stderr, "\n\033[1;33m[tp] ↑ ./%s (%s) → %s\033[0m\n",
		localPath, humanSize(fileSize), remotePath)

	// Register for verification
	resultCh := make(chan string, 1)
	pendingPut.mu.Lock()
	pendingPut.result = resultCh
	pendingPut.mu.Unlock()
	defer func() {
		pendingPut.mu.Lock()
		pendingPut.result = nil
		pendingPut.mu.Unlock()
	}()

	atomic.StoreInt32(suppress, 1)

	// For a fresh upload, remove any stale temp file first. For a resume we must
	// KEEP the remote's partial temp (we're about to append to it). Then start
	// the reader: head -n N | base64 -d [>] tmp; ... (see putCmdLine).
	// NOTE: line terminators are a single \n (not \r\n): in canonical mode
	// ICRNL turns \r into \n, so \r\n would inject a stray empty line that
	// head -n N would count as data.
	if !resume {
		if !injectWait(injectCh, []byte(leadSpace+fmt.Sprintf("rm -f %s 2>/dev/null #%s\n", qTmp, nonce))) {
			putAbort(suppress, remotePath)
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	if !injectWait(injectCh, []byte(cmdLine)) {
		putAbort(suppress, remotePath)
		return
	}
	time.Sleep(300 * time.Millisecond) // let head start reading

	// Per-block logging state (only active when logMode == 1). We hash each 4MiB
	// block as its raw bytes stream out and record the checksum the moment the
	// block completes, so an interrupted run leaves a log that says exactly how
	// many whole blocks the remote has.
	var blockHash hash.Hash
	var blockNum int
	var blockBytes int64
	if logMode == 1 {
		blockNum = resumeFrom
		blockHash = xxhash.New()
	}

	// Stream exactly numLines lines of continuous base64. head exits after
	// reading them, so no EOF/^D is needed (see putCmdLine).
	buf := make([]byte, 24*1024)
	pending := make([]byte, 0, putDataLineLen+8192)
	var sent int64
	linesSent := 0
	start := time.Now()
	var putTicker progressTicker
	putTicker.start(0)

	for {
		n, rerr := io.ReadFull(lf, buf)
		if atomic.LoadInt32(&linkDead) == 1 {
			putAbort(suppress, remotePath)
			return
		}
		if n > 0 {
			if logF != nil {
				// Feed the block hash, splitting at the 4MiB boundary if this read
				// straddles it (a read is <=24KiB, so it can cross at most one
				// boundary). When the boundary is hit, log the just-finished block.
				remaining := int64(tpBlockSize) - blockBytes
				if int64(n) <= remaining {
					blockHash.Write(buf[:n])
					blockBytes += int64(n)
				} else {
					blockHash.Write(buf[:remaining])
					logPutBlock(logF, blockNum, blockHash)
					blockNum++
					blockHash = xxhash.New()
					blockHash.Write(buf[remaining:])
					blockBytes = int64(n) - remaining
				}
			}
			pending = append(pending, base64.StdEncoding.EncodeToString(buf[:n])...)
			sent += int64(n)
			// Emit complete data lines (copy: pending's backing array is reused)
			for len(pending) >= putDataLineLen {
				if !injectWait(injectCh, append(append([]byte{}, pending[:putDataLineLen]...), '\n')) {
					putAbort(suppress, remotePath)
					return
				}
				pending = pending[putDataLineLen:]
				linesSent++

				if due, speed := putTicker.tick(sent); due {
					// Show the total file position (blocks already on the remote +
					// bytes sent this run), not just this run's byte count, so a
					// resume starts at the right percentage instead of 0%.
					pos := int64(resumeFrom)*int64(tpBlockSize) + sent
					pct := 0.0
					if fileSize > 0 {
						pct = float64(pos) / float64(fileSize) * 100
					}
					fmt.Fprintf(os.Stderr, "\r\033[1;33m[tp] ↑\033[0m %s/%s (%.0f%%) %s   ",
						humanSize(pos), humanSize(fileSize), pct, speedStr(speed))
				}
			}
		}
		if rerr != nil {
			break
		}
	}
	// Flush the final partial line
	if len(pending) > 0 {
		if !injectWait(injectCh, append(append([]byte{}, pending...), '\n')) {
			putAbort(suppress, remotePath)
			return
		}
		linesSent++
	}
	// Log the last (possibly partial) block's checksum, if any bytes were left.
	if logF != nil && blockBytes > 0 {
		logPutBlock(logF, blockNum, blockHash)
		blockBytes = 0
	}
	if linesSent != numLines {
		// Should be impossible; kill head so the terminal is not left waiting.
		injectBestEffort(injectCh, []byte{3})
		injectBestEffort(injectCh, []byte("\n"))
		atomic.StoreInt32(suppress, 0)
		fmt.Fprintf(os.Stderr, "\n\033[1;31m[tp] internal error: sent %d lines, expected %d\033[0m\n", linesSent, numLines)
		return
	}

	// NOTE: suppress stays ON through the verification wait below. Turning it
	// off here would let late base64 echoes (still in flight) print to the
	// screen; we only stop suppressing once the select returns.

	fmt.Fprintln(os.Stderr)

	// tp has handed every byte to the pty, but that is not the same as the remote
	// having received them: tp's injection queue plus the pty buffer can hold
	// hundreds of kilobytes, which through a bastion that paces input is minutes
	// of unread data. Saying "sent" and starting the verify clock at that moment
	// turns a perfectly healthy transfer into a spurious "verification timed
	// out", so drain first and say what we are waiting on while we do it.
	if !waitInjectDrained(func(n int64) {
		if n > 0 {
			fmt.Fprintf(os.Stderr, "\r\033[1;33m[tp] ↑\033[0m link is slower than tp can read: %s still queued   ", humanSize(n))
		} else {
			fmt.Fprint(os.Stderr, "\r\033[K")
		}
	}) {
		putAbort(suppress, remotePath)
		return
	}

	elapsed := time.Since(start).Seconds()
	var speed float64
	if elapsed > 0 {
		speed = float64(sent) / elapsed / 1024 / 1024
	}
	fmt.Fprintf(os.Stderr, "\033[1;33m[tp] sent %s (%.1fs, %s avg) → %s, verifying...\033[0m\n",
		humanSize(sent), elapsed, speedStr(speed), remotePath)

	// Wait for the remote's checksum. The clock starts here, with every byte
	// delivered to the link, so it measures what the remote is doing: draining its
	// queue, decoding, hashing. Hashing scales with the file, so the budget does.
	//
	// But tp cannot see past its own end of the link: on a bastion that paces
	// input, the bytes tp already wrote can still be minutes away from the remote,
	// and nothing tp observes says so. The DONE marker is the only real proof. So
	// the first budget expiring does NOT declare failure — it changes the message
	// and keeps waiting. A false "timed out" resets the terminal mid-transfer and
	// leaves a file the user cannot trust, which is worse than waiting; measured
	// behaviour was a perfectly good 12 KB upload reported as failed, with DONE
	// landing one second later.
	verifyBudget := 30*time.Second + time.Duration(fileSize/tpBlockSize)*2*time.Second
	if v := os.Getenv("TP_VERIFY_TIMEOUT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			verifyBudget = time.Duration(n) * time.Second
		}
	}
	// Hard stop, so a remote that really did die does not hang tp forever.
	verifyCap := max(10*time.Minute, 20*verifyBudget)
	if v := os.Getenv("TP_VERIFY_CAP"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			verifyCap = time.Duration(n) * time.Second
		}
	}
	verifyStart := time.Now()
	heartbeat := time.NewTicker(time.Second)
	defer heartbeat.Stop()
	timeout := time.After(verifyBudget)
	slowNotice := false
	var remoteSha string
	gotResult := false
	timedOut := false
	for !gotResult && !timedOut {
		select {
		case remoteSha = <-resultCh:
			gotResult = true
		case <-timeout:
			if slowNotice {
				timedOut = true
				break
			}
			// First expiry: say what is likely going on and keep waiting.
			slowNotice = true
			timeout = time.After(verifyCap - verifyBudget)
			fmt.Fprintf(os.Stderr, "\n\033[1;33m[tp] ⚠ no answer after %.0fs; the remote may still be receiving through a slow link, waiting up to %.0fm (Ctrl+C to give up)\033[0m\n",
				verifyBudget.Seconds(), verifyCap.Minutes())
		case <-heartbeat.C:
			if atomic.LoadInt32(&linkDead) == 1 {
				atomic.StoreInt32(suppress, 0)
				fmt.Fprintf(os.Stderr, "\n\033[1;31m[tp] ✗ connection lost while verifying %s\033[0m\n", remotePath)
				return
			}
			fmt.Fprintf(os.Stderr, "\r\033[1;33m[tp] ↑\033[0m verifying… (%.0fs)   ", time.Since(verifyStart).Seconds())
		}
	}

	switch {
	case gotResult && remoteSha == "":
		fmt.Fprintf(os.Stderr, "\033[1;33m[tp] ⚠ sent %s but could not verify (no sha256 on remote?)\033[0m\n", remotePath)
	case gotResult && localSha != remoteSha:
		fmt.Fprintf(os.Stderr, "\033[1;31m[tp] ✗ upload FAILED: sha256 mismatch (remote file left untouched)\033[0m\n  want: %s\n  got:  %s\n  file: %s on remote\n",
			localSha, remoteSha, remotePath)
	case gotResult:
		fmt.Fprintf(os.Stderr, "\033[1;32m[tp] ✓ %s uploaded OK\033[0m\n", remotePath)
		// Upload verified: the resume log is no longer needed.
		if logMode == 1 {
			os.Remove(logFile)
		}
	default: // timedOut
		// Last resort: interrupt whatever is running and restore the prompt
		// so the user can continue working in this terminal, then clean up
		// the temp files (this line queues behind anything still pending).
		injectBestEffort(injectCh, []byte{3})
		injectBestEffort(injectCh, []byte("\n"))
		injectBestEffort(injectCh, []byte(leadSpace+fmt.Sprintf("rm -f %s 2>/dev/null #%s\n", qTmp, nonce)))
		fmt.Fprintf(os.Stderr, "\033[1;33m[tp] ⚠ verification timed out; terminal reset, check %s manually\033[0m\n", remotePath)
	}

	// Transfer + verification are done (or timed out); no more base64 will
	// arrive, so it's safe to stop suppressing output.
	atomic.StoreInt32(suppress, 0)
}
