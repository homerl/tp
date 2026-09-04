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
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cespare/xxhash/v2"
)

// simulatePutStreaming mirrors doNoRemotePut's line generation: read 24KB
// raw chunks, base64-encode, and emit continuous data lines of
// putDataLineLen chars. Returns the emitted lines (payload only, no newline).
func simulatePutStreaming(orig []byte) [][]byte {
	var lines [][]byte
	pending := make([]byte, 0, putDataLineLen+8192)
	for off := 0; off < len(orig); {
		end := off + 24*1024
		if end > len(orig) {
			end = len(orig)
		}
		pending = append(pending, base64.StdEncoding.EncodeToString(orig[off:end])...)
		for len(pending) >= putDataLineLen {
			lines = append(lines, append([]byte{}, pending[:putDataLineLen]...))
			pending = pending[putDataLineLen:]
		}
		off = end
	}
	if len(pending) > 0 {
		lines = append(lines, append([]byte{}, pending...))
	}
	return lines
}

// TestPutLineGeneration checks the invariants of the !put protocol:
// the number of streamed lines matches N in `head -n N`, every line fits the
// remote PTY's 4096-byte canonical line buffer, and concatenating the lines
// decodes back to the original file.
func TestPutLineGeneration(t *testing.T) {
	for _, tc := range []struct {
		size int
		path string
	}{
		{0, "./a.bin"},
		{1, "./a.bin"},
		{3, "./a.bin"},
		{4095, "./a.bin"},
		{24*1024 + 7, "./a.bin"},
		{putDataLineLen * 3 / 4, "./a.bin"},
		{10 * 1024 * 1024, "/data/home/user/deep/nested/directory/a-very-long-filename.tar.gz"},
	} {
		t.Run(strconv.Itoa(tc.size), func(t *testing.T) {
			orig := make([]byte, tc.size)
			if _, err := rand.Read(orig); err != nil {
				t.Fatal(err)
			}

			qTarget, okT := dq(tc.path)
			tmpOut := tc.path + ".tptmp"
			qTmp, okO := dq(tmpOut)
			if !okT || !okO {
				t.Fatal("dq rejected test path")
			}
			cmdLine, numLines := putCmdLine(qTarget, qTmp, int64(len(orig)), int64(len(orig)), false)
			if len(cmdLine) > 4095 {
				t.Fatalf("command line too long: %d bytes", len(cmdLine))
			}

			lines := simulatePutStreaming(orig)
			if len(lines) != numLines {
				t.Fatalf("line count mismatch: streamed %d, head -n %d", len(lines), numLines)
			}
			var payload bytes.Buffer
			for _, l := range lines {
				// Invariant: every data line (+ newline) fits the PTY buffer
				if len(l)+1 > 4095 {
					t.Fatalf("line too long for remote PTY: %d bytes", len(l)+1)
				}
				payload.Write(l)
			}

			// The concatenated payload must decode back to the original file
			decoded, err := base64.StdEncoding.DecodeString(payload.String())
			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}
			if !bytes.Equal(decoded, orig) {
				t.Fatalf("roundtrip mismatch: got %d bytes, want %d", len(decoded), len(orig))
			}

			// The command line must carry the head count, size guard and marker
			if !strings.Contains(cmdLine, fmt.Sprintf("head -n %d", numLines)) ||
				!strings.Contains(cmdLine, strconv.Itoa(len(orig))) ||
				!strings.Contains(cmdLine, splitMarker(TPDone)) {
				t.Fatalf("command line missing parts: %s", cmdLine)
			}
		})
	}
}

// TestDQ checks path quoting/sanitization
func TestDQ(t *testing.T) {
	ok := []string{"./a.bin", "/tmp/x y.tar.gz", "a-b_c.d"}
	for _, s := range ok {
		if q, okq := dq(s); !okq || q != `"`+s+`"` {
			t.Errorf("dq(%q) = %q, %v; want quoted, true", s, q, okq)
		}
	}
	bad := []string{"", "a'b", `a"b`, "a$b", "a\x60b", "a\\b", "a!b", "a\nb", "a\tb"}
	for _, s := range bad {
		if q, okq := dq(s); okq {
			t.Errorf("dq(%q) = %q; want rejected", s, q)
		}
	}
}

// TestMightBeMarker covers the bug that lost the !put verification line:
// a marker split across two reads (e.g. "__TP_DO" then "NE__ <sha>") must be
// held back, not forwarded early. Also covers markers with shell escape
// sequences prepended (bash 5.1+ bracketed paste).
func TestMightBeMarker(t *testing.T) {
	// Partial prefixes (marker split across reads) must be held
	for _, s := range []string{"__TP_", "__TP_D", "__TP_DO", "__TP_DONE", "__TP_B", "__TP_BEGIN"} {
		if !mightBeMarker([]byte(s)) {
			t.Errorf("mightBeMarker(%q) = false, want true", s)
		}
	}
	// Complete markers (newline not arrived yet) must also be held
	for _, s := range []string{TPBegin, TPDone, TPBegin + "|x|1|y", TPDone + " abc123"} {
		if !mightBeMarker([]byte(s)) {
			t.Errorf("mightBeMarker(%q) = false, want true", s)
		}
	}
	// Markers with escape-sequence junk prepended must be held
	for _, s := range []string{"\x1b[?2004l\r__TP_DO", "\x1b[?2004l\r" + TPDone} {
		if !mightBeMarker([]byte(s)) {
			t.Errorf("mightBeMarker(%q) = false, want true", s)
		}
	}
	// Normal output must NOT be held
	for _, s := range []string{"hello world", "$ ls -la", "MgECgg== base64 data line", "user@host:~$", "\x1b[?2004l\r"} {
		if mightBeMarker([]byte(s)) {
			t.Errorf("mightBeMarker(%q) = true, want false", s)
		}
	}
}

// TestHandleLineGarbagePrefixedMarkers reproduces the user's environment:
// bash 5.1+ (bracketed paste) prepends "\x1b[?2004l\r" before command output,
// so marker lines arrive as "\x1b[?2004l\r__TP_DONE__ <sha>". Both markers
// must still be recognized.
func TestHandleLineGarbagePrefixedMarkers(t *testing.T) {
	dir := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWD)

	// 1) BEGIN with escape junk prepended must start a capture. The 4th field
	// is now totalBlocks (per-block mode), not the whole-file sha.
	var cap captureState
	handleLine([]byte("\x1b[?2004l\r__TP_BEGIN__|junk.bin|5|1\n"), &cap)
	if !cap.capturing {
		t.Fatal("BEGIN with escape prefix not recognized")
	}
	if cap.name != "junk.bin" || cap.totalSize != 5 || cap.totalBlocks != 1 {
		t.Fatalf("bad BEGIN parse: name=%q size=%d totalBlocks=%d", cap.name, cap.totalSize, cap.totalBlocks)
	}
	cap.file.Close()
	cap.capturing = false

	// 2) DONE (put verification) with escape junk prepended must report the sha
	resultCh := make(chan string, 1)
	pendingPut.mu.Lock()
	pendingPut.result = resultCh
	pendingPut.mu.Unlock()
	defer func() {
		pendingPut.mu.Lock()
		pendingPut.result = nil
		pendingPut.mu.Unlock()
	}()

	handleLine([]byte("\x1b[?2004l\r__TP_DONE__ deadbeef\n"), &cap)
	select {
	case gotSha := <-resultCh:
		if gotSha != "deadbeef" {
			t.Fatalf("DONE with escape prefix parsed sha=%q, want deadbeef", gotSha)
		}
	default:
		t.Fatal("DONE with escape prefix not recognized (channel empty)")
	}
}

// TestSha256FileHandle checks hashing + seek-back behavior
func TestSha256FileHandle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.bin")
	data := make([]byte, 700_000)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	got := sha256FileHandle(f)
	sum := sha256.Sum256(data)
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("sha mismatch:\n got %s\n want %s", got, want)
	}

	// After hashing, the handle must be seeked back to the start
	buf := make([]byte, len(data))
	if _, err := io.ReadFull(f, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, data) {
		t.Fatal("file not seeked back to start after sha256FileHandle")
	}
}

// TestEchoSuppressor validates the local-echo de-duplication logic: ordered
// consumption, queue-clear on mismatch, and skipping of escape sequences and
// control characters (which the remote never echoes as plain bytes).
func TestEchoSuppressor(t *testing.T) {
	var e echoSuppressor
	e.push([]byte("ls"))
	if !e.tryConsume('l') {
		t.Fatal("l should be suppressed")
	}
	if !e.tryConsume('s') {
		t.Fatal("s should be suppressed")
	}
	if e.tryConsume('x') {
		t.Fatal("x should NOT be suppressed (queue empty)")
	}

	var e2 echoSuppressor
	e2.push([]byte("ls"))
	if e2.tryConsume('x') {
		t.Fatal("x should not match")
	}
	if e2.tryConsume('l') {
		t.Fatal("after mismatch, l should not be suppressed (queue cleared)")
	}

	var e3 echoSuppressor
	e3.push([]byte("\x1b[A")) // arrow up
	if e3.tryConsume('A') || e3.tryConsume('[') {
		t.Fatal("escape sequence bytes must not be recorded")
	}

	var e4 echoSuppressor
	e4.push([]byte("a\n\t"))
	if !e4.tryConsume('a') {
		t.Fatal("a should be suppressed")
	}
	if !e4.tryConsume('\n') {
		t.Fatal("newline should be suppressed (remote may echo it back)")
	}
	if e4.tryConsume('\t') {
		t.Fatal("tab must not be recorded")
	}

	var e5 echoSuppressor
	e5.push([]byte("中")) // multi-byte UTF-8
	for _, b := range []byte("中") {
		if !e5.tryConsume(b) {
			t.Fatal("utf8 byte should be suppressed")
		}
	}
}

// TestBangDetectionWithBracketedPaste verifies that `!` commands are detected and
// parsed correctly whether typed directly, indented, or wrapped in bracketed-paste
// markers by the terminal.
func TestBangDetectionWithBracketedPaste(t *testing.T) {
	if !isBangStart([]byte("!get x\n")) {
		t.Fatal("typed ! should be detected")
	}
	if !isBangStart([]byte("\x1b[200~!get x\x1b[201~\n")) {
		t.Fatal("pasted ! (bracketed paste) should be detected")
	}
	if isBangStart([]byte("ls\n")) {
		t.Fatal("plain ls must not be detected as bang")
	}
	if isBangStart([]byte("\x1b[200~ls\x1b[201~\n")) {
		t.Fatal("pasted plain ls must not be detected as bang")
	}
	if isBangStart([]byte("\x1b[A")) {
		t.Fatal("arrow key (escape only) must not be detected as bang")
	}
	// leading whitespace / tab before ! is still a bang command
	if !isBangStart([]byte("  !get x")) {
		t.Fatal("indented ! should be detected")
	}
	if !isBangStart([]byte("\t!put x y")) {
		t.Fatal("tab-indented ! should be detected")
	}
	// isLeadingSpace: only horizontal whitespace — NOT escape sequences (those are
	// immediate actions like arrow keys that must be forwarded at once).
	if !isLeadingSpace([]byte("  ")) || !isLeadingSpace([]byte("\t")) {
		t.Fatal("whitespace should be leading-space")
	}
	if isLeadingSpace([]byte("\x1b[A")) { // arrow key must NOT be held
		t.Fatal("escape sequence must not be treated as leading space")
	}
	if isLeadingSpace([]byte("ls")) || isLeadingSpace([]byte(" l")) {
		t.Fatal("content byte must not be leading-space")
	}

	// stripANSI: removes bracketed paste markers, keeps content
	if got := string(stripANSI([]byte("\x1b[200~!get a b\x1b[201~\n"))); got != "!get a b\n" {
		t.Fatalf("stripANSI = %q, want %q", got, "!get a b\n")
	}
	if got := string(stripANSI([]byte("!put x y"))); got != "!put x y" {
		t.Fatalf("stripANSI passthrough = %q", got)
	}
	if got := string(stripANSI([]byte("\x1b[31mred\x1b[0m"))); got != "red" {
		t.Fatalf("stripANSI color = %q, want red", got)
	}
}

// TestGetRobustToLineSplitting verifies that a !get download is reassembled
// correctly even when the multi-hop link re-wraps the base64 stream at
// arbitrary (non-4-char-aligned) boundaries. Per-line decoding would fail and
// leak such lines to the screen; the accumulate-then-decode approach must not.
func TestGetRobustToLineSplitting(t *testing.T) {
	orig := make([]byte, 100000)
	for i := range orig {
		orig[i] = byte(i*7 + 3)
	}
	b64 := base64.StdEncoding.EncodeToString(orig)

	tmp, err := os.CreateTemp(t.TempDir(), "dl*")
	if err != nil {
		t.Fatal(err)
	}
	defer tmp.Close()
	cs := &captureState{
		capturing: true,
		file:      tmp,
		hash:      sha256.New(),
		name:      tmp.Name(),
		totalSize: int64(len(orig)),
	}

	// Feed the base64 in 7-char chunks (NOT a multiple of 4) each terminated by
	// a newline — simulating the stream being re-wrapped at odd points.
	const width = 7
	for i := 0; i < len(b64); i += width {
		end := i + width
		if end > len(b64) {
			end = len(b64)
		}
		handleLine([]byte(b64[i:end]+"\n"), cs)
	}
	// Also feed a chunk with a stray mid-line space + CRLF, then the marker.
	handleLine([]byte("\r  \n"), cs)
	handleLine([]byte(TPDone+"\n"), cs)

	// finish() closed tmp; reopen to verify the written content.
	f, err := os.Open(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("decoded %d bytes, want %d (content mismatch after line splitting)", len(got), len(orig))
	}
}

// TestB64Stream verifies the incremental decoder: it must reassemble the
// original bytes no matter how the alphabet is chunked (any width, including
// 1), handle all three padding residues, and flag a truncated stream.
func TestB64Stream(t *testing.T) {
	for _, size := range []int{0, 1, 2, 3, 4, 5, 1000, 1000000} {
		for _, width := range []int{1, 3, 7, 32000} {
			t.Run(fmt.Sprintf("size=%d,width=%d", size, width), func(t *testing.T) {
				orig := make([]byte, size)
				if _, err := rand.Read(orig); err != nil {
					t.Fatal(err)
				}
				b64 := base64.StdEncoding.EncodeToString(orig)

				var got bytes.Buffer
				var dec b64stream
				for i := 0; i < len(b64); i += width {
					end := i + width
					if end > len(b64) {
						end = len(b64)
					}
					if _, err := dec.feed([]byte(b64[i:end]), &got); err != nil {
						t.Fatalf("feed: %v", err)
					}
				}
				if err := dec.finish(); err != nil {
					t.Fatalf("finish on a complete stream: %v", err)
				}
				if !bytes.Equal(got.Bytes(), orig) {
					t.Fatalf("decoded %d bytes, want %d", got.Len(), size)
				}
			})
		}
	}

	// A truncated stream (drop the last alphabet char) must be flagged.
	orig := make([]byte, 1000)
	if _, err := rand.Read(orig); err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(orig)
	var got bytes.Buffer
	var dec b64stream
	if _, err := dec.feed([]byte(b64[:len(b64)-1]), &got); err != nil {
		t.Fatalf("feed: %v", err)
	}
	if err := dec.finish(); err == nil {
		t.Fatal("finish should report a truncated stream")
	}
}

// TestSplitMarker checks that splitMarker breaks the full marker out of the
// command text (so a shell echo can't be mistaken for a real marker) while the
// shell still concatenates it back to the real marker when executed.
func TestSplitMarker(t *testing.T) {
	for _, m := range []string{TPBegin, TPDone, TPError} {
		s := splitMarker(m)
		if strings.Contains(s, m) {
			t.Errorf("splitMarker(%q)=%q still contains the full marker", m, s)
		}
		if !strings.Contains(s, "__TP_") {
			t.Errorf("splitMarker(%q)=%q lost the __TP_ prefix (mightBeMarker relies on it)", m, s)
		}
		// Simulate the shell concatenating `__TP_""REST__`: drop the empty-string
		// token and rejoin — must equal the original marker.
		rejoined := strings.Replace(s, `""`, "", 1)
		if rejoined != m {
			t.Errorf("splitMarker(%q) rejoins to %q, want %q", m, rejoined, m)
		}
	}
}

// resetGetLog clears the package-level getLog so tests that call handleLine
// directly don't inherit stale resume state from a prior e2e test.
func resetGetLog() {
	getLog.mu.Lock()
	getLog.enabled = false
	getLog.logName = ""
	getLog.resumeFrom = 0
	getLog.resumeSize = 0
	getLog.mu.Unlock()
}

// TestHandleLinePerBlock exercises the per-block download path end to end
// (no pty): BEGIN starts the capture, BLOCK begins a block, base64 feeds it,
// DONE finalizes + renames. Verifies each block's sha256 is checked and the
// temp file is renamed to the target.
func TestHandleLinePerBlock(t *testing.T) {
	resetGetLog()
	dir := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWD)

	data := []byte("hello per-block world")
	b64 := base64.StdEncoding.EncodeToString(data)
	sha := hex.EncodeToString(func() []byte { h := sha256.Sum256(data); return h[:] }())

	var cap captureState
	handleLine([]byte("__TP_BEGIN__|pb.bin|"+strconv.Itoa(len(data))+"|1\n"), &cap)
	if !cap.capturing {
		t.Fatal("BEGIN did not start capture")
	}
	handleLine([]byte("__TP_BLOCK__ 0 "+sha+"\n"), &cap)
	handleLine([]byte(b64+"\n"), &cap)
	handleLine([]byte("__TP_DONE__\n"), &cap)
	if cap.capturing {
		t.Fatal("capture did not finish")
	}
	got, err := os.ReadFile("pb.bin")
	if err != nil {
		t.Fatalf("file missing: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("mismatch: got %q want %q", got, data)
	}
	if _, err := os.Stat("pb.bin.tptmp"); err == nil {
		t.Fatal("stale temp left behind")
	}

	// Bad checksum must abort and NOT rename.
	var cap2 captureState
	handleLine([]byte("__TP_BEGIN__|bad.bin|"+strconv.Itoa(len(data))+"|1\n"), &cap2)
	handleLine([]byte("__TP_BLOCK__ 0 "+strings.Repeat("0", 64)+"\n"), &cap2)
	handleLine([]byte(b64+"\n"), &cap2)
	handleLine([]byte("__TP_DONE__\n"), &cap2)
	if _, err := os.Stat("bad.bin"); err == nil {
		t.Fatal("bad checksum should not produce a file")
	}
}

// TestHandleLineShortDownload guards the !get "false success" hole: the remote
// announces a total size up front, but if fewer bytes actually arrive (the file
// shrank mid-download, or /tmp filled and dd truncated a block) every per-block
// checksum still passes — they were computed against the truncated data. Only
// the total-size backstop in finish() can catch it. A short download must NOT
// be renamed over the target.
func TestHandleLineShortDownload(t *testing.T) {
	resetGetLog()
	dir := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWD)

	data := []byte("only twenty bytes!!!") // 20 bytes actually sent
	sha := hex.EncodeToString(func() []byte { h := sha256.Sum256(data); return h[:] }())
	b64 := base64.StdEncoding.EncodeToString(data)

	var cap captureState
	// Remote claims a 40-byte file (1 block) but only 20 bytes arrive.
	handleLine([]byte("__TP_BEGIN__|short.bin|40|1\n"), &cap)
	handleLine([]byte("__TP_BLOCK__ 0 "+sha+"\n"), &cap)
	handleLine([]byte(b64+"\n"), &cap)
	handleLine([]byte("__TP_DONE__\n"), &cap)
	if cap.capturing {
		t.Fatal("capture did not finish")
	}
	if _, err := os.Stat("short.bin"); err == nil {
		t.Fatal("short download must not be renamed to the target")
	}
	if _, err := os.Stat("short.bin.tptmp"); err == nil {
		t.Fatal("temp file should have been removed on short download")
	}
}

// TestHandleLinePerBlockXXH64 is the xxh64 variant of the per-block test: the
// remote's checksum is 16 hex chars (xxh64sum output), so the local must detect
// the algorithm by length and verify with xxh64, not sha256.
func TestHandleLinePerBlockXXH64(t *testing.T) {
	resetGetLog()
	dir := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWD)

	data := []byte("hello per-block world")
	b64 := base64.StdEncoding.EncodeToString(data)
	sum := xxhash.Sum64(data)
	cksum := fmt.Sprintf("%016x", sum) // 16 hex chars → xxh64 path

	var cap captureState
	handleLine([]byte("__TP_BEGIN__|xx.bin|"+strconv.Itoa(len(data))+"|1\n"), &cap)
	handleLine([]byte("__TP_BLOCK__ 0 "+cksum+"\n"), &cap)
	if cap.curBlockAlgo != "xxh64" {
		t.Fatalf("algo = %q, want xxh64", cap.curBlockAlgo)
	}
	handleLine([]byte(b64+"\n"), &cap)
	handleLine([]byte("__TP_DONE__\n"), &cap)
	if cap.capturing {
		t.Fatal("capture did not finish")
	}
	got, err := os.ReadFile("xx.bin")
	if err != nil {
		t.Fatalf("file missing: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("mismatch: got %q want %q", got, data)
	}

	// A wrong xxh64 checksum must abort (proves it's not silently using sha256).
	var cap2 captureState
	handleLine([]byte("__TP_BEGIN__|xxbad.bin|"+strconv.Itoa(len(data))+"|1\n"), &cap2)
	handleLine([]byte("__TP_BLOCK__ 0 "+strings.Repeat("0", 16)+"\n"), &cap2)
	handleLine([]byte(b64+"\n"), &cap2)
	handleLine([]byte("__TP_DONE__\n"), &cap2)
	if _, err := os.Stat("xxbad.bin"); err == nil {
		t.Fatal("bad xxh64 checksum should not produce a file")
	}
}

// TestCheckResumeLog covers the resume decision: a valid log + matching partial
// temp yields a resume point; any inconsistency (missing log, filename mismatch,
// size mismatch, last-block checksum mismatch) falls back to a fresh start and
// cleans up the stale files.
func TestCheckResumeLog(t *testing.T) {
	dir := t.TempDir()
	oldWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWD)

	const target = "big.bin"
	tmp := target + ".tptmp"
	logName := target + ".tprlog"

	// One full 4MiB block of deterministic data.
	block := make([]byte, tpBlockSize)
	for i := range block {
		block[i] = byte(i % 251)
	}
	blockSha := hex.EncodeToString(func() []byte { h := sha256.Sum256(block); return h[:] }())

	writeLog := func() {
		if err := os.WriteFile(logName, []byte(target+" 3\n0 "+blockSha+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	writeTmp := func() {
		if err := os.WriteFile(tmp, block, 0644); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("valid", func(t *testing.T) {
		writeLog()
		writeTmp()
		from, size := checkResumeLog(logName, target)
		if from != 1 || size != tpBlockSize {
			t.Fatalf("got from=%d size=%d, want 1/%d", from, size, tpBlockSize)
		}
	})

	// Ctrl+C mid-block: the temp holds block 0 plus a partial block 1. We must
	// truncate the partial tail back to the last complete block and resume.
	t.Run("partial trailing block", func(t *testing.T) {
		writeLog()
		partial := make([]byte, tpBlockSize+512*1024)
		copy(partial, block) // block 0 intact
		for i := tpBlockSize; i < len(partial); i++ {
			partial[i] = byte(i % 7) // partial block 1 (garbage tail)
		}
		if err := os.WriteFile(tmp, partial, 0644); err != nil {
			t.Fatal(err)
		}
		from, size := checkResumeLog(logName, target)
		if from != 1 || size != tpBlockSize {
			t.Fatalf("got from=%d size=%d, want 1/%d", from, size, tpBlockSize)
		}
		fi, err := os.Stat(tmp)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Size() != int64(tpBlockSize) {
			t.Fatalf("temp not truncated: %d bytes, want %d", fi.Size(), tpBlockSize)
		}
	})

	t.Run("no log", func(t *testing.T) {
		os.Remove(logName)
		os.Remove(tmp)
		from, size := checkResumeLog(logName, target)
		if from != 0 || size != 0 {
			t.Fatalf("got from=%d size=%d, want 0/0", from, size)
		}
	})

	t.Run("filename mismatch", func(t *testing.T) {
		os.WriteFile(logName, []byte("other.bin 3\n0 "+blockSha+"\n"), 0644)
		writeTmp()
		from, _ := checkResumeLog(logName, target)
		if from != 0 {
			t.Fatalf("got from=%d, want 0", from)
		}
		if _, err := os.Stat(logName); err == nil {
			t.Fatal("stale log should be removed")
		}
		if _, err := os.Stat(tmp); err == nil {
			t.Fatal("stale temp should be removed")
		}
	})

	t.Run("size mismatch", func(t *testing.T) {
		writeLog()
		os.WriteFile(tmp, block[:1024], 0644) // wrong size
		from, _ := checkResumeLog(logName, target)
		if from != 0 {
			t.Fatalf("got from=%d, want 0", from)
		}
	})

	t.Run("checksum mismatch", func(t *testing.T) {
		os.WriteFile(logName, []byte(target+" 3\n0 "+strings.Repeat("f", 64)+"\n"), 0644)
		writeTmp()
		from, _ := checkResumeLog(logName, target)
		if from != 0 {
			t.Fatalf("got from=%d, want 0", from)
		}
		if _, err := os.Stat(tmp); err == nil {
			t.Fatal("corrupt temp should be removed")
		}
	})
}

// TestKillLocalLine checks the Ctrl+U local-erase helper: it writes one
// "\b \b" (backspace-space-backspace) per column so the echoed line is wiped,
// returns 0, and is a no-op at column 0.
func TestKillLocalLine(t *testing.T) {
	var buf bytes.Buffer
	if got := killLocalLine(&buf, 3); got != 0 {
		t.Fatalf("cols = %d, want 0", got)
	}
	if want := "\b \b\b \b\b \b"; buf.String() != want {
		t.Fatalf("erase = %q, want %q", buf.String(), want)
	}

	buf.Reset()
	if got := killLocalLine(&buf, 0); got != 0 {
		t.Fatalf("cols = %d, want 0", got)
	}
	if buf.Len() != 0 {
		t.Fatalf("erase = %q, want empty at col 0", buf.String())
	}
}

// TestIsYesAnswer checks the overwrite-confirmation answer interpretation.
func TestIsYesAnswer(t *testing.T) {
	for _, s := range []string{"y", "Y", "yes", "YES", " Yes ", "y ", "y\n"} {
		if !isYesAnswer(s) {
			t.Errorf("isYesAnswer(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "n", "N", "no", "x", "maybe", "yy"} {
		if isYesAnswer(s) {
			t.Errorf("isYesAnswer(%q) = true, want false", s)
		}
	}
}

// TestExistsProbe checks the probe command is well-formed: it carries the split
// marker (so its own echo can't misfire), the nonce, and a quoted -e test.
func TestExistsProbe(t *testing.T) {
	probe := existsProbe(`"/tmp/x"`, "deadbeef00011122")
	if strings.Contains(probe, TPExists) {
		t.Fatal("probe contains the full marker (its echo would misfire)")
	}
	if !strings.Contains(probe, "__TP_") {
		t.Fatal("probe lost the __TP_ prefix (mightBeMarker relies on it)")
	}
	if !strings.Contains(probe, "deadbeef00011122") {
		t.Fatal("probe missing the nonce")
	}
	if !strings.Contains(probe, `[ -e "/tmp/x" ]`) {
		t.Fatal("probe missing the quoted -e test")
	}
}

// TestHandleLineExists checks handleLine delivers the __TP_EXISTS__ result to
// the guard channel (true for "yes", false for "no").
func TestHandleLineExists(t *testing.T) {
	echoNonce.mu.Lock()
	echoNonce.val = "" // ensure a stale nonce can't swallow the probe line
	echoNonce.mu.Unlock()

	deliver := func(line string) bool {
		ch := make(chan bool, 1)
		putGuard.mu.Lock()
		putGuard.existsCh = ch
		putGuard.mu.Unlock()
		defer func() {
			putGuard.mu.Lock()
			putGuard.existsCh = nil
			putGuard.mu.Unlock()
		}()
		var cap captureState
		handleLine([]byte(line), &cap)
		select {
		case e := <-ch:
			return e
		default:
			t.Fatalf("no result delivered for %q", line)
			return false
		}
	}
	if !deliver("__TP_EXISTS__ yes\n") {
		t.Fatal("'yes' should deliver true")
	}
	if deliver("__TP_EXISTS__ no\n") {
		t.Fatal("'no' should deliver false")
	}
}

// TestCaptureConfirm checks the stdin confirmation capture: printable bytes are
// buffered and echoed, Enter delivers the answer, Ctrl+C cancels ("n"), and the
// guard's answerCh is cleared so normal forwarding resumes.
func TestCaptureConfirm(t *testing.T) {
	// Enter delivers the typed answer.
	ch := make(chan string, 1)
	putGuard.mu.Lock()
	putGuard.answerCh = ch
	putGuard.mu.Unlock()
	var buf []byte
	captureConfirm([]byte("y\n"), &buf, ch)
	select {
	case a := <-ch:
		if a != "y" {
			t.Fatalf("got %q, want y", a)
		}
	default:
		t.Fatal("no answer delivered on Enter")
	}
	putGuard.mu.Lock()
	cleared := putGuard.answerCh == nil
	putGuard.mu.Unlock()
	if !cleared {
		t.Fatal("answerCh not cleared after Enter")
	}

	// Nothing is delivered until Enter; Ctrl+C then cancels with "n".
	ch2 := make(chan string, 1)
	putGuard.mu.Lock()
	putGuard.answerCh = ch2
	putGuard.mu.Unlock()
	var buf2 []byte
	captureConfirm([]byte("n"), &buf2, ch2) // partial, no Enter yet
	select {
	case <-ch2:
		t.Fatal("should not deliver before Enter")
	default:
	}
	captureConfirm([]byte{0x03}, &buf2, ch2) // Ctrl+C cancels
	select {
	case a := <-ch2:
		if a != "n" {
			t.Fatalf("got %q, want n (cancel)", a)
		}
	default:
		t.Fatal("no answer on Ctrl+C")
	}
}

func TestWaitForQuiet(t *testing.T) {
	// Recent pty output (just now) -> must wait until the quiet period elapses.
	atomic.StoreInt64(&lastPtyOut, time.Now().UnixNano())
	start := time.Now()
	waitForQuiet(50*time.Millisecond, 500*time.Millisecond)
	elapsed := time.Since(start)
	if elapsed < 45*time.Millisecond {
		t.Fatalf("returned too early: %v (want >= ~50ms quiet period)", elapsed)
	}
	if elapsed > 300*time.Millisecond {
		t.Fatalf("returned too late: %v (want << 500ms max wait)", elapsed)
	}

	// Continuous pty output -> the quiet timer keeps restarting, so it only
	// returns once the max wait is hit.
	done := make(chan struct{})
	go func() {
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				atomic.StoreInt64(&lastPtyOut, time.Now().UnixNano())
			}
		}
	}()
	// Mark output as "just now" so the quiet timer starts fresh; the goroutine
	// keeps refreshing it so the quiet period never completes.
	atomic.StoreInt64(&lastPtyOut, time.Now().UnixNano())
	start = time.Now()
	waitForQuiet(50*time.Millisecond, 200*time.Millisecond)
	elapsed = time.Since(start)
	close(done)
	if elapsed < 180*time.Millisecond {
		t.Fatalf("returned too early under continuous output: %v (want ~200ms max wait)", elapsed)
	}
	if elapsed > 600*time.Millisecond {
		t.Fatalf("returned too late: %v", elapsed)
	}
}
