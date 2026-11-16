package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/creack/pty"
)

// TestMain shrinks the link-stall window for the whole suite. Production waits a
// full minute of zero write progress before calling a link dead; a test that gets
// its injection accounting wrong would then burn that minute on every wait (and
// the suite would look hung rather than wrong). Five seconds is still longer than
// anything in the suite legitimately stalls, and turns the next such mistake into
// a fast failure.
func TestMain(m *testing.M) {
	restore := injectStallLimit
	injectStallLimit = 5 * time.Second
	code := m.Run()
	injectStallLimit = restore
	os.Exit(code)
}

// putResult captures the outcome of a simulated !put over a pty chain.
type putResult struct {
	completed bool // remote reported the TPDone marker with correct sha
	alive     bool // terminal responsive after the upload
	output    []byte
}

// runPutOverPTY simulates doNoRemotePut's exact command sequence against a
// writer that reaches the target bash (directly or through a nested chain).
func runPutOverPTY(t *testing.T, w ptyWriter, sizeMB int) putResult {
	t.Helper()
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.bin")

	orig := make([]byte, sizeMB*1024*1024)
	if _, err := rand.Read(orig); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(orig)
	wantSha := hex.EncodeToString(sum[:])

	qTarget, okT := dq(outPath)
	tmpOut := outPath + ".tptmp"
	qTmp, okO := dq(tmpOut)
	if !okT || !okO {
		t.Fatal("dq rejected test path")
	}
	cmdLine, numLines := putCmdLine(qTarget, qTmp, int64(len(orig)), int64(len(orig)), false, "testnonce0000000")

	w.write([]byte(fmt.Sprintf("rm -f %s 2>/dev/null\n", qTmp)))
	time.Sleep(300 * time.Millisecond)
	w.write([]byte(cmdLine))
	time.Sleep(300 * time.Millisecond) // let head start reading

	// Stream exactly numLines lines of continuous base64 (no ^D sent!)
	lines := simulatePutStreaming(orig)
	if len(lines) != numLines {
		t.Fatalf("line count mismatch: %d vs %d", len(lines), numLines)
	}
	for _, line := range lines {
		w.write(append(append([]byte{}, line...), '\n'))
	}

	res := putResult{output: w.output()}
	// The remote answers "__TP_DONE__ #<nonce> <sha>" (the tag is what lets tp
	// discard a reply to a probe that already gave up); accept it with or without.
	re := regexp.MustCompile("__TP_DONE__ (?:#\\S+ )?([0-9a-f]{64})")
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		out := w.output()
		if m := re.FindSubmatch(out); m != nil {
			res.completed = string(m[1]) == wantSha
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// The terminal must be usable after the upload (the user's core complaint)
	w.write([]byte("echo __ALIVE__\n"))
	before := len(w.output())
	aliveRe := regexp.MustCompile(`(?m)(^|\r)__ALIVE__\r?$`)
	ad := time.Now().Add(10 * time.Second)
	for time.Now().Before(ad) {
		if aliveRe.Match(w.output()[before:]) {
			res.alive = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	res.output = w.output()
	return res
}

// ptyWriter abstracts "send bytes toward the target bash" + "collect output".
type ptyWriter interface {
	write([]byte)
	output() []byte
	cleanup()
}

// syncBuffer is a mutex-protected bytes.Buffer for safe concurrent
// read/write between the drain goroutine and the test's polling loop.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Bytes()
}

func (s *syncBuffer) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Len()
}

// singleHopWriter: bash directly in a pty (simple ssh session).
type singleHopWriter struct {
	f   *os.File
	out *syncBuffer
}

func (s *singleHopWriter) write(b []byte) { s.f.Write(b) }
func (s *singleHopWriter) output() []byte { return s.out.Bytes() }
func (s *singleHopWriter) cleanup()       { s.f.Close() }

// nestedWriter: ptyA runs a byte-copier ("ssh machineA" on the jump host),
// which forwards to ptyB running bash (the target). ptyA stays canonical —
// the worst case where an intermediate pty eats ^D as VEOF.
type nestedWriter struct {
	pa, pb *os.File
	out    *syncBuffer
}

func (n *nestedWriter) write(b []byte) { n.pa.Write(b) }
func (n *nestedWriter) output() []byte { return n.out.Bytes() }
func (n *nestedWriter) cleanup()       { n.pa.Close(); n.pb.Close() }

// TestPTYUploadRoundTrip: real end-to-end !put through a single pty.
func TestPTYUploadRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	cmd := exec.Command("bash", "--norc", "--noprofile")
	f, err := pty.Start(cmd)
	if err != nil {
		t.Skipf("cannot start pty: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	w := &singleHopWriter{f: f, out: &syncBuffer{}}
	defer w.cleanup()
	go drain(w.f, w.out)

	time.Sleep(300 * time.Millisecond) // let bash start
	res := runPutOverPTY(t, w, 5)
	if !res.completed {
		t.Fatalf("upload failed/corrupted; output tail: %q", tail(res.output, 500))
	}
	if !res.alive {
		t.Fatalf("terminal NOT usable after upload; output tail: %q", tail(res.output, 500))
	}
}

// TestPTYUploadNestedRoundTrip reproduces the user's jump-host scenario:
// data passes through an intermediate canonical-mode pty that eats ^D. The
// old `base64 -d` approach hung forever here; `head -n N` must complete and
// leave the terminal usable.
func TestPTYUploadNestedRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	innerCmd := exec.Command("bash", "--norc", "--noprofile")
	pb, err := pty.Start(innerCmd)
	if err != nil {
		t.Skipf("cannot start inner pty: %v", err)
	}
	copier := exec.Command("sh", "-c", "cat >&3") // "ssh machineA": stdin -> fd3
	copier.ExtraFiles = []*os.File{pb}
	pa, err := pty.Start(copier)
	if err != nil {
		t.Skipf("cannot start outer pty: %v", err)
	}
	defer func() { _ = innerCmd.Process.Kill(); _ = copier.Process.Kill() }()
	w := &nestedWriter{pa: pa, pb: pb, out: &syncBuffer{}}
	defer w.cleanup()
	go drain(pb, w.out)
	go drain(pa, nil) // discard jump-host echo

	time.Sleep(300 * time.Millisecond)
	res := runPutOverPTY(t, w, 4)
	if !res.completed {
		t.Fatalf("nested upload failed/corrupted; output tail: %q", tail(res.output, 500))
	}
	if !res.alive {
		t.Fatalf("nested terminal NOT usable after upload; output tail: %q", tail(res.output, 500))
	}
}

// drain copies a pty's output into buf (or discards it) so the pty never
// blocks on a full output buffer.
func drain(f *os.File, buf io.Writer) {
	b := make([]byte, 64*1024)
	for {
		n, err := f.Read(b)
		if n > 0 && buf != nil {
			buf.Write(b[:n])
		}
		if err != nil {
			return
		}
	}
}

// TestHandleLineGetFlow unit-tests the !get capture path: feed synthetic
// BEGIN/data/DONE lines through handleLine and check the saved file.
func TestHandleLineGetFlow(t *testing.T) {
	dir := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWD)

	orig := make([]byte, 100_000)
	if _, err := rand.Read(orig); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(orig)
	sha := hex.EncodeToString(sum[:])

	var cap captureState
	b64 := base64.StdEncoding.EncodeToString(orig)

	// BEGIN line
	handleLine([]byte(fmt.Sprintf("__TP_BEGIN__|testfile.bin|%d|%s\n", len(orig), sha)), &cap)
	if !cap.capturing {
		t.Fatal("not capturing after BEGIN")
	}

	// Data lines in 32000-char chunks (what `base64 -w 32000` produces)
	for len(b64) > 0 {
		chunk := b64
		if len(chunk) > 32000 {
			chunk = chunk[:32000]
		}
		handleLine([]byte(chunk+"\n"), &cap)
		b64 = b64[len(chunk):]
	}

	// DONE line
	handleLine([]byte("__TP_DONE__\n"), &cap)
	if cap.capturing {
		t.Fatal("still capturing after DONE")
	}

	got, err := os.ReadFile("testfile.bin")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("download mismatch: got %d bytes, want %d", len(got), len(orig))
	}
}

// TestPTYDownloadRoundTrip: real end-to-end !get through a single pty. It
// exercises doNoRemoteGet's injected command against a live bash, the streaming
// base64 decoder (O(1) memory), the temp-file+rename write (no stale temp, no
// clobber), and the command-echo suppression (the remote echoes the injected
// command back; that echo must not leak a false __TP_ERROR__).
func TestPTYDownloadRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWD)

	// The "remote" file lives in the same temp dir (bash runs here).
	remotePath := filepath.Join(dir, "remote.bin")
	orig := make([]byte, 3*1024*1024)
	if _, err := rand.Read(orig); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(remotePath, orig, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", "--norc", "--noprofile")
	f, err := pty.Start(cmd)
	if err != nil {
		t.Skipf("cannot start pty: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	// Capture stderr (via a real pipe, since os.Stderr is *os.File) so we can
	// assert the download printed a success line and NOT a false "no such file"
	// from the command echo.
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = errW

	var capMu sync.Mutex
	var cap captureState
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 8192)
		var lineBuf []byte
		for {
			n, rerr := f.Read(buf)
			if n > 0 {
				lineBuf = append(lineBuf, buf[:n]...)
				for {
					idx := bytes.IndexByte(lineBuf, '\n')
					if idx < 0 {
						break
					}
					line := lineBuf[:idx+1]
					lineBuf = lineBuf[idx+1:]
					capMu.Lock()
					handleLine(line, &cap)
					capMu.Unlock()
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	resetInject()
	injectCh := make(chan []byte, 50)
	startInjector(f, injectCh)

	time.Sleep(300 * time.Millisecond) // let bash start

	localName := "downloaded.bin"
	doNoRemoteGet(injectCh, remotePath, localName, 0, "")

	// Wait for the download to finish: capture ends and the file exists.
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		capMu.Lock()
		capturing := cap.capturing
		capMu.Unlock()
		if !capturing {
			if _, err := os.Stat(localName); err == nil {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	got, err := os.ReadFile(localName)
	if err != nil {
		t.Fatalf("downloaded file missing: %v", err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("download mismatch: got %d bytes, want %d", len(got), len(orig))
	}
	if _, err := os.Stat(localName + ".tptmp"); err == nil {
		t.Fatalf("stale temp file left behind: %s.tptmp", localName)
	}

	// Stop bash so the reader goroutine's pty read returns an error (closing a
	// pty that another goroutine is blocked reading is unsafe in Go). Then drain
	// the captured stderr and assert on it.
	close(injectCh) // no more injections; lets the writer goroutine exit
	_ = cmd.Process.Kill()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reader goroutine did not stop after killing bash")
	}
	errW.Close()
	os.Stderr = oldStderr
	var outBuf bytes.Buffer
	io.Copy(&outBuf, errR)
	errR.Close()
	out := outBuf.String()
	if bytes.Contains([]byte(out), []byte("no such file")) {
		t.Fatalf("false 'no such file' leaked from the command echo:\n%s", out)
	}
	if !bytes.Contains([]byte(out), []byte("✓")) {
		t.Fatalf("no success line printed:\n%s", out)
	}
}

// TestPTYDownloadResumeRoundTrip verifies the per-block resume end-to-end: a
// pre-existing valid log + partial temp (simulating an interrupted download)
// causes a fresh !get to skip the already-downloaded blocks and append the
// rest, producing a complete, correct file. We prove it actually resumed (not a
// silent fresh re-download) by asserting the remote never emitted a
// __TP_BLOCK__ 0 marker (block 0 was already on disk, so the source command
// started at N=1) but did emit __TP_BLOCK__ 1. The logged block uses an xxh64
// checksum (16 hex) so the resume path also exercises algorithm auto-detection.
func TestPTYDownloadResumeRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWD)

	// The "remote" file: 5 MiB = 2 blocks (4 MiB + 1 MiB).
	const size = 5 * 1024 * 1024
	remotePath := filepath.Join(dir, "remote.bin")
	orig := make([]byte, size)
	if _, err := rand.Read(orig); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(remotePath, orig, 0644); err != nil {
		t.Fatal(err)
	}

	const localName = "resumed.bin"
	logName := localName + ".tprlog"
	tmpName := localName + ".tptmp"

	// Simulate an interrupted download: block 0 (4 MiB) is already on disk and
	// logged. checkResumeLog re-verifies block 0's checksum against the partial
	// temp before we start, so it must match.
	firstBlock := orig[:tpBlockSize]
	cksum := fmt.Sprintf("%016x", xxhash.Sum64(firstBlock))
	if err := os.WriteFile(logName, []byte(fmt.Sprintf("%s 2\n0 %s\n", localName, cksum)), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmpName, firstBlock, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", "--norc", "--noprofile")
	cmd.Dir = dir
	f, err := pty.Start(cmd)
	if err != nil {
		t.Skipf("cannot start pty: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	var capMu sync.Mutex
	var cap captureState
	var outMu sync.Mutex
	var outBuf bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 8192)
		var lineBuf []byte
		for {
			n, rerr := f.Read(buf)
			if n > 0 {
				outMu.Lock()
				outBuf.Write(buf[:n])
				outMu.Unlock()
				lineBuf = append(lineBuf, buf[:n]...)
				for {
					idx := bytes.IndexByte(lineBuf, '\n')
					if idx < 0 {
						break
					}
					line := lineBuf[:idx+1]
					lineBuf = lineBuf[idx+1:]
					capMu.Lock()
					handleLine(line, &cap)
					capMu.Unlock()
				}
			}
			if rerr != nil {
				return
			}
		}
	}()
	resetInject()
	injectCh := make(chan []byte, 50)
	startInjector(f, injectCh)
	time.Sleep(300 * time.Millisecond) // let bash start

	// Start the download with logging on. checkResumeLog should detect the
	// partial state and resume from block 1 (skipping block 0).
	doNoRemoteGet(injectCh, remotePath, localName, 1, "")

	// Wait for the download to finish: capture ends and the file is complete.
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		capMu.Lock()
		capturing := cap.capturing
		capMu.Unlock()
		if !capturing {
			if fi, err := os.Stat(localName); err == nil && fi.Size() == int64(size) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	got, err := os.ReadFile(localName)
	if err != nil {
		t.Fatalf("resumed file missing: %v", err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("resumed download mismatch: got %d bytes, want %d", len(got), len(orig))
	}
	if _, err := os.Stat(tmpName); err == nil {
		t.Fatalf("stale temp file left behind: %s", tmpName)
	}
	if _, err := os.Stat(logName); err == nil {
		t.Fatalf("resume log should be removed on success: %s", logName)
	}

	// Prove it actually resumed: the remote must NOT have emitted a
	// __TP_BLOCK__ 0 marker (block 0 was already on disk, so the source command
	// started at N=1). A silent fresh re-download would emit __TP_BLOCK__ 0.
	// (The command echo carries "__TP_BLOCK__ $N $S" with literal $N/$S, so it
	// can't be mistaken for a real "__TP_BLOCK__ 0 " marker.)
	outMu.Lock()
	out := outBuf.String()
	outMu.Unlock()
	if strings.Contains(out, "__TP_BLOCK__ 0 ") {
		t.Fatalf("download did not resume (remote emitted __TP_BLOCK__ 0); tail: %q", tail([]byte(out), 400))
	}
	if !strings.Contains(out, "__TP_BLOCK__ 1 ") {
		t.Fatalf("expected __TP_BLOCK__ 1 in a resume; tail: %q", tail([]byte(out), 400))
	}

	close(injectCh)
	_ = cmd.Process.Kill()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reader goroutine did not stop after killing bash")
	}
}

// TestPTYUploadResumeRoundTrip verifies the per-block resume for !put
// end-to-end. A previous run left a valid local log (block 0 recorded) plus the
// remote's partial temp file (block 0's 4MiB on disk). A fresh !put with -l 1
// must probe the remote, see the temp matches, and APPEND only the remaining
// block — not re-send block 0. Since data flows local→remote there are no block
// markers in the pty output to inspect, so we prove the resume by counting the
// bytes the local injected: a resume of a 5MiB (2-block) file sends only block 1
// (~1.34MiB of base64), whereas a silent fresh re-upload would send all 5MiB
// (~6.7MiB). We assert the injected volume stays well under the full-file size.
func TestPTYUploadResumeRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWD)

	// The local source file: 5 MiB = 2 blocks (4 MiB + 1 MiB).
	const size = 5 * 1024 * 1024
	orig := make([]byte, size)
	if _, err := rand.Read(orig); err != nil {
		t.Fatal(err)
	}
	localPath := "local.bin"
	if err := os.WriteFile(localPath, orig, 0644); err != nil {
		t.Fatal(err)
	}
	remotePath := filepath.Join(dir, "remote.bin")
	tmpName := remotePath + ".tptmp"
	logName := localPath + ".tprlog"

	// Simulate an interrupted upload: block 0 (4 MiB) already reached the
	// remote (in its partial temp) and is recorded in the local log.
	firstBlock := orig[:tpBlockSize]
	cksum := fmt.Sprintf("%016x", xxhash.Sum64(firstBlock))
	if err := os.WriteFile(logName, []byte(fmt.Sprintf("%s 2\n0 %s\n", localPath, cksum)), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmpName, firstBlock, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", "--norc", "--noprofile")
	cmd.Dir = dir
	f, err := pty.Start(cmd)
	if err != nil {
		t.Skipf("cannot start pty: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	var capMu sync.Mutex
	var cap captureState
	var outMu sync.Mutex
	var outBuf bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 8192)
		var lineBuf []byte
		for {
			n, rerr := f.Read(buf)
			if n > 0 {
				outMu.Lock()
				outBuf.Write(buf[:n])
				outMu.Unlock()
				lineBuf = append(lineBuf, buf[:n]...)
				for {
					idx := bytes.IndexByte(lineBuf, '\n')
					if idx < 0 {
						break
					}
					line := lineBuf[:idx+1]
					lineBuf = lineBuf[idx+1:]
					capMu.Lock()
					handleLine(line, &cap)
					capMu.Unlock()
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	// Injector that also counts how many bytes the local pushed toward the
	// remote — the signal that distinguishes a resume from a fresh re-upload.
	// Snapshot the global delivery counter: what this test hands over is the delta,
	// which is how we tell a resume from a full re-send.
	injBase := atomic.LoadInt64(&injectQueued)
	resetInject()
	injectCh := make(chan []byte, 50)
	startInjector(f, injectCh)
	time.Sleep(300 * time.Millisecond) // let bash start

	var suppress int32
	doNoRemotePut(injectCh, &suppress, localPath, remotePath, 1, "")

	// Wait for the upload to finish: the remote target reaches full size.
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if fi, err := os.Stat(remotePath); err == nil && fi.Size() == int64(size) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	got, err := os.ReadFile(remotePath)
	if err != nil {
		t.Fatalf("uploaded file missing: %v", err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("resumed upload mismatch: got %d bytes, want %d", len(got), len(orig))
	}
	if _, err := os.Stat(tmpName); err == nil {
		t.Fatalf("stale remote temp left behind: %s", tmpName)
	}
	if _, err := os.Stat(logName); err == nil {
		t.Fatalf("resume log should be removed on success: %s", logName)
	}

	// Prove it actually resumed: a fresh re-upload would inject ~6.7MiB of
	// base64; a resume injects only block 1 (~1.34MiB) plus a little overhead.
	// 3MiB is a safe threshold between the two.
	if inj := atomic.LoadInt64(&injectQueued) - injBase; inj > 3*1024*1024 {
		t.Fatalf("upload did not resume (injected %d bytes, >3MiB means a full re-send)", inj)
	}

	close(injectCh)
	_ = cmd.Process.Kill()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reader goroutine did not stop after killing bash")
	}
}

// TestPTYUploadResumeCorruptTail verifies the "newest block corrupt" path. The
// remote's partial temp has all 5 blocks present, but the LAST one is corrupted
// (its checksum no longer matches the log) while block 3 is intact. The resume
// logic must detect that, truncate the temp back to block 3, and re-send only
// the tail (block 4) — not the whole file. We prove it by counting injected
// bytes: a tail re-send of a 20MiB (5-block) file is ~5.3MiB of base64, a full
// re-upload is ~27MiB.
func TestPTYUploadResumeCorruptTail(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWD)

	// The local source file: 20 MiB = 5 blocks of 4 MiB.
	const size = 5 * tpBlockSize
	orig := make([]byte, size)
	if _, err := rand.Read(orig); err != nil {
		t.Fatal(err)
	}
	localPath := "local.bin"
	if err := os.WriteFile(localPath, orig, 0644); err != nil {
		t.Fatal(err)
	}
	remotePath := filepath.Join(dir, "remote.bin")
	tmpName := remotePath + ".tptmp"
	logName := localPath + ".tprlog"

	// Build the log with correct checksums for all 5 blocks.
	var logBuf bytes.Buffer
	fmt.Fprintf(&logBuf, "%s 5\n", localPath)
	for b := 0; b < 5; b++ {
		block := orig[b*tpBlockSize : (b+1)*tpBlockSize]
		fmt.Fprintf(&logBuf, "%d %016x\n", b, xxhash.Sum64(block))
	}
	if err := os.WriteFile(logName, logBuf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	// The remote temp has all 5 blocks, but the last (block 4) is corrupted.
	tmpData := make([]byte, size)
	copy(tmpData, orig)
	for i := 4 * tpBlockSize; i < size; i++ {
		tmpData[i] ^= 0xFF // flip every byte of the last block
	}
	if err := os.WriteFile(tmpName, tmpData, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", "--norc", "--noprofile")
	cmd.Dir = dir
	f, err := pty.Start(cmd)
	if err != nil {
		t.Skipf("cannot start pty: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	var capMu sync.Mutex
	var cap captureState
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 8192)
		var lineBuf []byte
		for {
			n, rerr := f.Read(buf)
			if n > 0 {
				lineBuf = append(lineBuf, buf[:n]...)
				for {
					idx := bytes.IndexByte(lineBuf, '\n')
					if idx < 0 {
						break
					}
					line := lineBuf[:idx+1]
					lineBuf = lineBuf[idx+1:]
					capMu.Lock()
					handleLine(line, &cap)
					capMu.Unlock()
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	// Snapshot the global delivery counter: what this test hands over is the delta,
	// which is how we tell a resume from a full re-send.
	injBase := atomic.LoadInt64(&injectQueued)
	resetInject()
	injectCh := make(chan []byte, 50)
	startInjector(f, injectCh)
	time.Sleep(300 * time.Millisecond) // let bash start

	var suppress int32
	doNoRemotePut(injectCh, &suppress, localPath, remotePath, 1, "")

	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if fi, err := os.Stat(remotePath); err == nil && fi.Size() == int64(size) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	got, err := os.ReadFile(remotePath)
	if err != nil {
		t.Fatalf("uploaded file missing: %v", err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("resumed upload mismatch: got %d bytes, want %d", len(got), len(orig))
	}
	if _, err := os.Stat(tmpName); err == nil {
		t.Fatalf("stale remote temp left behind: %s", tmpName)
	}
	if _, err := os.Stat(logName); err == nil {
		t.Fatalf("resume log should be removed on success: %s", logName)
	}

	// A tail re-send (block 4 only) is ~5.3MiB of base64; a full re-upload is
	// ~27MiB. 12MiB sits safely between them.
	if inj := atomic.LoadInt64(&injectQueued) - injBase; inj > 12*1024*1024 {
		t.Fatalf("upload did not resume from the corrupt tail (injected %d bytes, >12MiB means a full re-send)", inj)
	}

	close(injectCh)
	_ = cmd.Process.Kill()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reader goroutine did not stop after killing bash")
	}
}

// TestPTYUploadResumePartialTail verifies the mid-block Ctrl+C case for !put.
// The remote's partial temp ends with a PARTIAL block (the upload was cut off
// inside block 4), so its size is not a multiple of 4MiB. The resume logic must
// truncate that partial tail back to the last complete block and re-send only
// block 4 — not the whole file, and not append on top of the partial bytes.
func TestPTYUploadResumePartialTail(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWD)

	// The local source file: 20 MiB = 5 blocks of 4 MiB.
	const size = 5 * tpBlockSize
	orig := make([]byte, size)
	if _, err := rand.Read(orig); err != nil {
		t.Fatal(err)
	}
	localPath := "local.bin"
	if err := os.WriteFile(localPath, orig, 0644); err != nil {
		t.Fatal(err)
	}
	remotePath := filepath.Join(dir, "remote.bin")
	tmpName := remotePath + ".tptmp"
	logName := localPath + ".tprlog"

	// The log records the first 4 complete blocks (sent = 4); block 4 was still
	// in flight when we were interrupted.
	var logBuf bytes.Buffer
	fmt.Fprintf(&logBuf, "%s 5\n", localPath)
	for b := 0; b < 4; b++ {
		block := orig[b*tpBlockSize : (b+1)*tpBlockSize]
		fmt.Fprintf(&logBuf, "%d %016x\n", b, xxhash.Sum64(block))
	}
	if err := os.WriteFile(logName, logBuf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	// The remote temp holds blocks 0..3 intact plus a partial block 4 (1 MiB of
	// its 4 MiB), so its size is NOT a multiple of 4MiB.
	const partial = tpBlockSize / 4
	tmpData := make([]byte, 4*tpBlockSize+partial)
	copy(tmpData, orig[:len(tmpData)])
	if err := os.WriteFile(tmpName, tmpData, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", "--norc", "--noprofile")
	cmd.Dir = dir
	f, err := pty.Start(cmd)
	if err != nil {
		t.Skipf("cannot start pty: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	var capMu sync.Mutex
	var cap captureState
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 8192)
		var lineBuf []byte
		for {
			n, rerr := f.Read(buf)
			if n > 0 {
				lineBuf = append(lineBuf, buf[:n]...)
				for {
					idx := bytes.IndexByte(lineBuf, '\n')
					if idx < 0 {
						break
					}
					line := lineBuf[:idx+1]
					lineBuf = lineBuf[idx+1:]
					capMu.Lock()
					handleLine(line, &cap)
					capMu.Unlock()
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	// Snapshot the global delivery counter: what this test hands over is the delta,
	// which is how we tell a resume from a full re-send.
	injBase := atomic.LoadInt64(&injectQueued)
	resetInject()
	injectCh := make(chan []byte, 50)
	startInjector(f, injectCh)
	time.Sleep(300 * time.Millisecond) // let bash start

	var suppress int32
	doNoRemotePut(injectCh, &suppress, localPath, remotePath, 1, "")

	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if fi, err := os.Stat(remotePath); err == nil && fi.Size() == int64(size) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	got, err := os.ReadFile(remotePath)
	if err != nil {
		t.Fatalf("uploaded file missing: %v", err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("resumed upload mismatch: got %d bytes, want %d", len(got), len(orig))
	}
	if _, err := os.Stat(tmpName); err == nil {
		t.Fatalf("stale remote temp left behind: %s", tmpName)
	}
	if _, err := os.Stat(logName); err == nil {
		t.Fatalf("resume log should be removed on success: %s", logName)
	}

	// A tail re-send (block 4 only) is ~5.3MiB of base64; a full re-upload is
	// ~27MiB. 12MiB sits safely between them.
	if inj := atomic.LoadInt64(&injectQueued) - injBase; inj > 12*1024*1024 {
		t.Fatalf("upload did not resume from the partial tail (injected %d bytes, >12MiB means a full re-send)", inj)
	}

	close(injectCh)
	_ = cmd.Process.Kill()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reader goroutine did not stop after killing bash")
	}
}

// TestPutExistsProbeOverPTY verifies the !put existence probe over a real bash
// pty: an existing target reports true, a missing one reports false, and the
// probe's own command echo is dropped (no false result, no raw command leak).
func TestPutExistsProbeOverPTY(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	existing := filepath.Join(dir, "exists.bin")
	if err := os.WriteFile(existing, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.bin")

	cmd := exec.Command("bash", "--norc", "--noprofile")
	f, err := pty.Start(cmd)
	if err != nil {
		t.Skipf("cannot start pty: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	var capMu sync.Mutex
	var cap captureState
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 8192)
		var lineBuf []byte
		for {
			n, rerr := f.Read(buf)
			if n > 0 {
				lineBuf = append(lineBuf, buf[:n]...)
				for {
					idx := bytes.IndexByte(lineBuf, '\n')
					if idx < 0 {
						break
					}
					line := lineBuf[:idx+1]
					lineBuf = lineBuf[idx+1:]
					capMu.Lock()
					handleLine(line, &cap)
					capMu.Unlock()
				}
			}
			if rerr != nil {
				return
			}
		}
	}()
	resetInject()
	injectCh := make(chan []byte, 50)
	startInjector(f, injectCh)
	time.Sleep(300 * time.Millisecond) // let bash start

	probe := func(target string) bool {
		q, ok := dq(target)
		if !ok {
			t.Fatalf("dq rejected %q", target)
		}
		nonce := setEchoNonce()
		putGuard.mu.Lock()
		ch := make(chan bool, 1)
		putGuard.existsCh = ch
		putGuard.mu.Unlock()
		defer func() {
			putGuard.mu.Lock()
			putGuard.existsCh = nil
			putGuard.mu.Unlock()
		}()
		injectCh <- []byte(existsProbe(q, nonce))
		select {
		case e := <-ch:
			return e
		case <-time.After(10 * time.Second):
			t.Fatal("probe timed out")
			return false
		}
	}

	if !probe(existing) {
		t.Fatal("existing target should report exists=true")
	}
	if probe(missing) {
		t.Fatal("missing target should report exists=false")
	}

	close(injectCh)
	_ = cmd.Process.Kill()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reader goroutine did not stop")
	}
}

// TestPTYPutConfirmRoundTrip exercises the full !put overwrite guard over a
// real pty: an existing target triggers the prompt, and the answer decides the
// outcome — "y" overwrites, "n" or a bare Enter (default No) leaves the target
// untouched. The answer is pushed to putGuard.answerCh to stand in for the
// stdin reader's captureConfirm.
func TestPTYPutConfirmRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	for _, tc := range []struct {
		ans      string
		wantData string
	}{
		{"y", "NEWDATA"},
		{"yes", "NEWDATA"},
		{"n", "OLDDATA"},
		{"", "OLDDATA"}, // bare Enter -> default No
	} {
		t.Run("ans="+tc.ans, func(t *testing.T) {
			dir := t.TempDir()
			oldWD, _ := os.Getwd()
			if err := os.Chdir(dir); err != nil {
				t.Fatal(err)
			}
			defer os.Chdir(oldWD)

			if err := os.WriteFile("local.bin", []byte("NEWDATA"), 0644); err != nil {
				t.Fatal(err)
			}
			remotePath := filepath.Join(dir, "remote.bin")
			if err := os.WriteFile(remotePath, []byte("OLDDATA"), 0644); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command("bash", "--norc", "--noprofile")
			cmd.Dir = dir
			f, err := pty.Start(cmd)
			if err != nil {
				t.Skipf("cannot start pty: %v", err)
			}
			defer func() { _ = cmd.Process.Kill() }()

			var capMu sync.Mutex
			var cap captureState
			done := make(chan struct{})
			go func() {
				defer close(done)
				buf := make([]byte, 8192)
				var lineBuf []byte
				for {
					n, rerr := f.Read(buf)
					if n > 0 {
						lineBuf = append(lineBuf, buf[:n]...)
						for {
							idx := bytes.IndexByte(lineBuf, '\n')
							if idx < 0 {
								break
							}
							line := lineBuf[:idx+1]
							lineBuf = lineBuf[idx+1:]
							capMu.Lock()
							handleLine(line, &cap)
							capMu.Unlock()
						}
					}
					if rerr != nil {
						return
					}
				}
			}()
			injectCh := make(chan []byte, 100)
			startInjector(f, injectCh)
			time.Sleep(300 * time.Millisecond)

			// Stand in for the stdin reader: answer the prompt when it appears.
			go func() {
				for {
					putGuard.mu.Lock()
					ch := putGuard.answerCh
					putGuard.mu.Unlock()
					if ch != nil {
						ch <- tc.ans
						return
					}
					time.Sleep(5 * time.Millisecond)
				}
			}()

			var suppress int32
			doNoRemotePut(injectCh, &suppress, "local.bin", remotePath, 0, "")

			// Wait for the target to reach the expected content (overwrite or not).
			deadline := time.Now().Add(30 * time.Second)
			for time.Now().Before(deadline) {
				if b, err := os.ReadFile(remotePath); err == nil && string(b) == tc.wantData {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			got, _ := os.ReadFile(remotePath)
			if string(got) != tc.wantData {
				t.Fatalf("target = %q, want %q (ans=%q)", got, tc.wantData, tc.ans)
			}

			close(injectCh)
			_ = cmd.Process.Kill()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("reader goroutine did not stop")
			}
		})
	}
}

// TestPTYGetConfirmRoundTrip verifies !get now confirms before overwriting an
// existing local target (same y/N as !put): "y" downloads over it, "n" or a
// bare Enter (default No) leaves the local file untouched. The answer is pushed
// to putGuard.answerCh to stand in for the stdin reader's captureConfirm.
func TestPTYGetConfirmRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	for _, tc := range []struct {
		ans      string
		wantData string
	}{
		{"y", "REMOTEDATA"},
		{"yes", "REMOTEDATA"},
		{"n", "LOCALOLD"},
		{"", "LOCALOLD"}, // bare Enter -> default No
	} {
		t.Run("ans="+tc.ans, func(t *testing.T) {
			dir := t.TempDir()
			oldWD, _ := os.Getwd()
			if err := os.Chdir(dir); err != nil {
				t.Fatal(err)
			}
			defer os.Chdir(oldWD)

			remotePath := filepath.Join(dir, "remote.bin")
			if err := os.WriteFile(remotePath, []byte("REMOTEDATA"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile("local.bin", []byte("LOCALOLD"), 0644); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command("bash", "--norc", "--noprofile")
			cmd.Dir = dir
			f, err := pty.Start(cmd)
			if err != nil {
				t.Skipf("cannot start pty: %v", err)
			}
			defer func() { _ = cmd.Process.Kill() }()

			var capMu sync.Mutex
			var cap captureState
			done := make(chan struct{})
			go func() {
				defer close(done)
				buf := make([]byte, 8192)
				var lineBuf []byte
				for {
					n, rerr := f.Read(buf)
					if n > 0 {
						lineBuf = append(lineBuf, buf[:n]...)
						for {
							idx := bytes.IndexByte(lineBuf, '\n')
							if idx < 0 {
								break
							}
							line := lineBuf[:idx+1]
							lineBuf = lineBuf[idx+1:]
							capMu.Lock()
							handleLine(line, &cap)
							capMu.Unlock()
						}
					}
					if rerr != nil {
						return
					}
				}
			}()
			injectCh := make(chan []byte, 100)
			startInjector(f, injectCh)
			time.Sleep(300 * time.Millisecond)

			// Stand in for the stdin reader: answer the prompt when it appears.
			go func() {
				for {
					putGuard.mu.Lock()
					ch := putGuard.answerCh
					putGuard.mu.Unlock()
					if ch != nil {
						ch <- tc.ans
						return
					}
					time.Sleep(5 * time.Millisecond)
				}
			}()

			doNoRemoteGet(injectCh, remotePath, "local.bin", 0, "")

			deadline := time.Now().Add(30 * time.Second)
			for time.Now().Before(deadline) {
				if b, err := os.ReadFile("local.bin"); err == nil && string(b) == tc.wantData {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			got, _ := os.ReadFile("local.bin")
			if string(got) != tc.wantData {
				t.Fatalf("local = %q, want %q (ans=%q)", got, tc.wantData, tc.ans)
			}

			close(injectCh)
			_ = cmd.Process.Kill()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("reader goroutine did not stop")
			}
		})
	}
}

func tail(s []byte, n int) string {
	if len(s) <= n {
		return string(s)
	}
	return string(s[len(s)-n:])
}

// TestPutAbortsWhenLinkDies covers the "ssh died mid-upload" path. A pty write
// that fails must end the transfer at once: otherwise tp keeps pushing 20 MB
// into a dead pipe and then reports a misleading "verification timed out".
func TestPutAbortsWhenLinkDies(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	localPath := filepath.Join(dir, "big.bin")
	orig := make([]byte, 20*1024*1024)
	if _, err := rand.Read(orig); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localPath, orig, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", "--norc", "--noprofile")
	cmd.Dir = dir
	// Own process group, so the kill below takes out the `head`/`base64` children
	// too. As long as any of them holds the pty slave open, writes to the master
	// keep succeeding into a full buffer instead of failing the way they do when
	// a real ssh session drops.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	f, err := pty.Start(cmd)
	if err != nil {
		t.Skipf("cannot start pty: %v", err)
	}
	defer func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); f.Close() }()

	// Same contract as the real injection writer in cmdSSH: a failed write means
	// the link is gone; flag it and keep draining so senders never wedge.
	resetInject()
	injectCh := make(chan []byte, 50)
	go func() {
		for data := range injectCh {
			if _, werr := f.Write(data); werr != nil {
				atomic.StoreInt32(&linkDead, 1)
				for range injectCh {
				}
				return
			}
			atomic.AddInt64(&injectSeq, 1)
			atomic.AddInt64(&injectWritten, int64(len(data)))
		}
	}()
	defer atomic.StoreInt32(&linkDead, 0)
	// The abort here comes from the write failing outright, so the suite-wide stall
	// window (shrunk by TestMain) is not what ends this transfer.

	var suppress int32
	// Parse the remote's output the way the real session does, so the existence
	// probe is answered and the upload actually gets under way.
	go func() {
		buf := make([]byte, 8192)
		var lineBuf []byte
		var cap captureState
		for {
			n, rerr := f.Read(buf)
			if n > 0 {
				lineBuf = append(lineBuf, buf[:n]...)
				for {
					idx := bytes.IndexByte(lineBuf, '\n')
					if idx < 0 {
						break
					}
					line := lineBuf[:idx+1]
					lineBuf = lineBuf[idx+1:]
					// Same rule as the real session: while a !put streams, drop the
					// echoed base64 but keep protocol markers.
					if atomic.LoadInt32(&suppress) == 1 && !mightBeMarker(line) {
						continue
					}
					handleLine(line, &cap)
				}
			}
			if rerr != nil {
				return
			}
		}
	}()
	time.Sleep(300 * time.Millisecond) // let bash start

	done := make(chan struct{})
	go func() {
		defer close(done)
		doNoRemotePut(injectCh, &suppress, localPath, filepath.Join(dir, "remote.bin"), 0, "")
	}()

	time.Sleep(1 * time.Second) // mid-transfer
	// Simulate the session dropping. Closing the master is what makes it
	// deterministic: the next write returns EBADF, the same failure a dead ssh
	// leaves behind.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	_ = f.Close()

	select {
	case <-done:
		// Good: it noticed and gave up.
	case <-time.After(15 * time.Second):
		t.Fatal("upload did not abort after the link died (still pushing bytes into a dead pty)")
	}
	if atomic.LoadInt32(&linkDead) != 1 {
		t.Fatal("a failing pty write was not reported as a dead link")
	}
	if atomic.LoadInt32(&suppress) != 0 {
		t.Fatal("output suppression left on after the abort; the terminal would look dead")
	}
}
