package main

import (
	"bytes"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

func TestParseRateLimit(t *testing.T) {
	valid := map[string]int64{
		"20K":    20 * 1024,
		"20k":    20 * 1024,
		"20KB":   20 * 1024,
		"20K/s":  20 * 1024,
		"2M":     2 * 1024 * 1024,
		"50000":  50000,
		"10000B": 10000,
	}
	for in, want := range valid {
		got, err := parseRateLimit(in)
		if err != nil {
			t.Errorf("parseRateLimit(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parseRateLimit(%q) = %d, want %d", in, got, want)
		}
	}
	for _, bad := range []string{"", "0", "-5K", "abc", "K"} {
		if _, err := parseRateLimit(bad); err == nil {
			t.Errorf("parseRateLimit(%q) expected error, got nil", bad)
		}
	}
}

func TestBlockSizeForRate(t *testing.T) {
	cases := []struct {
		rate int64
		want int
	}{
		{0, tpBlockSize},
		{5 * 1024, 16 * 1024},
		{10 * 1024, 16 * 1024},
		{20 * 1024, 16 * 1024},
		{50 * 1024, 16 * 1024},
		{500 * 1024, 16 * 1024},
	}
	for _, tc := range cases {
		if got := blockSizeForRate(tc.rate); got != tc.want {
			t.Errorf("blockSizeForRate(%d) = %d, want %d", tc.rate, got, tc.want)
		}
	}
}

func TestParseLocalCmdFlexibleFlags(t *testing.T) {
	cases := []struct {
		line    string
		action  string
		arg1    string
		arg2    string
		logMode int
		rate    int64
		wantErr bool
	}{
		{
			line:    "get@! -l 20K /tmp/getfile ~/Downloads/getfile",
			action:  "get",
			arg1:    "/tmp/getfile",
			arg2:    "~/Downloads/getfile",
			logMode: -1,
			rate:    20 * 1024,
		},
		{
			line:    "put@! -l 20K /tmp/getfile ~/Downloads/getfile",
			action:  "put",
			arg1:    "/tmp/getfile",
			arg2:    "~/Downloads/getfile",
			logMode: -1,
			rate:    20 * 1024,
		},
		{
			line:    "get@! /tmp/f local.bin -l 0 -r 50K",
			action:  "get",
			arg1:    "/tmp/f",
			arg2:    "local.bin",
			logMode: 0,
			rate:    50 * 1024,
		},
		{
			line:    "get@! /tmp/f -l 1",
			action:  "get",
			arg1:    "/tmp/f",
			logMode: 1,
			rate:    0,
		},
		{
			line:    "put@! -l badrate /tmp/f",
			action:  "put",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		lc := parseLocalCmd(strings.Fields(tc.line))
		if tc.wantErr {
			if lc.parseErr == nil {
				t.Errorf("%q: expected parseErr, got nil", tc.line)
			}
			continue
		}
		if lc.parseErr != nil {
			t.Errorf("%q: unexpected error: %v", tc.line, lc.parseErr)
			continue
		}
		if lc.action != tc.action || lc.arg1 != tc.arg1 || lc.arg2 != tc.arg2 || lc.logMode != tc.logMode || lc.rateLimit != tc.rate {
			t.Errorf("%q: got %+v, want action=%q arg1=%q arg2=%q logMode=%d rate=%d",
				tc.line, lc, tc.action, tc.arg1, tc.arg2, tc.logMode, tc.rate)
		}
	}
}

func TestDownloadInjectAccountingNonNegative(t *testing.T) {
	resetInject()
	defer resetInject()

	injectCh := make(chan []byte, 4)
	var sink bytes.Buffer
	startInjector(&sink, injectCh)

	doNoRemoteGet(injectCh, "/tmp/nonexistent_tp_test", "local.bin", 0, "", 0)
	dlWatchStop()

	if !waitInjectDrained(nil) {
		t.Fatal("waitInjectDrained returned false")
	}
	if b := injectBacklog(); b != 0 {
		t.Fatalf("injectBacklog() = %d, want 0", b)
	}
	close(injectCh)
}

func TestPTYUploadRateLimitedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	// 12 KiB raw -> ~16 KiB base64; at 20 KiB/s should take >= ~0.7s.
	orig := make([]byte, 12*1024)
	if _, err := rand.Read(orig); err != nil {
		t.Fatal(err)
	}
	localPath := filepath.Join(dir, "src.bin")
	remotePath := filepath.Join(dir, "dst.bin")
	if err := os.WriteFile(localPath, orig, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", "--norc", "--noprofile")
	f, err := pty.Start(cmd)
	if err != nil {
		t.Fatalf("pty.Start: %v", err)
	}
	defer func() {
		f.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	if termios, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS); err == nil {
		ptyRaw(termios)
		unix.IoctlSetTermios(int(f.Fd()), unix.TCSETS, termios)
	}

	var suppress int32
	go func() {
		var lineBuf []byte
		var cap captureState
		buf := make([]byte, 8192)
		for {
			n, rerr := f.Read(buf)
			if n > 0 {
				atomic.StoreInt64(&lastPtyOut, time.Now().UnixNano())
				lineBuf = append(lineBuf, buf[:n]...)
				for {
					idx := bytes.IndexByte(lineBuf, '\n')
					if idx < 0 {
						break
					}
					line := lineBuf[:idx+1]
					lineBuf = lineBuf[idx+1:]
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

	resetInject()
	defer resetInject()
	injectCh := make(chan []byte, 50)
	startInjector(f, injectCh)
	defer close(injectCh)

	time.Sleep(300 * time.Millisecond)

	start := time.Now()
	doNoRemotePut(injectCh, &suppress, localPath, remotePath, 0, "", 20*1024)
	elapsed := time.Since(start)

	got, err := os.ReadFile(remotePath)
	if err != nil {
		t.Fatalf("uploaded file missing: %v", err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("uploaded content mismatch")
	}
	if elapsed < 500*time.Millisecond {
		t.Fatalf("upload finished too fast (%v); rate limit 20K was not applied", elapsed)
	}
	t.Logf("rate-limited upload (12 KiB @ 20K/s) succeeded in %v", elapsed.Round(time.Millisecond))
}

func TestPTYDownloadRateLimitedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	// 12 KiB raw -> ~16 KiB base64; at 20 KiB/s should take >= ~0.6s.
	orig := make([]byte, 12*1024)
	if _, err := rand.Read(orig); err != nil {
		t.Fatal(err)
	}
	remotePath := filepath.Join(dir, "remote.bin")
	if err := os.WriteFile(remotePath, orig, 0644); err != nil {
		t.Fatal(err)
	}

	origWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origWD)

	cmd := exec.Command("bash", "--norc", "--noprofile")
	f, err := pty.Start(cmd)
	if err != nil {
		t.Fatalf("pty.Start: %v", err)
	}
	defer func() {
		f.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	if termios, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS); err == nil {
		ptyRaw(termios)
		unix.IoctlSetTermios(int(f.Fd()), unix.TCSETS, termios)
	}

	var capMu sync.Mutex
	var cap captureState
	go func() {
		var lineBuf []byte
		buf := make([]byte, 8192)
		for {
			n, rerr := f.Read(buf)
			if n > 0 {
				atomic.StoreInt64(&lastPtyOut, time.Now().UnixNano())
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
	defer resetInject()
	injectCh := make(chan []byte, 50)
	startInjector(f, injectCh)
	defer close(injectCh)

	time.Sleep(300 * time.Millisecond)

	localName := "downloaded_limited.bin"
	start := time.Now()
	doNoRemoteGet(injectCh, remotePath, localName, 0, "", 20*1024)

	deadline := time.Now().Add(30 * time.Second)
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
	elapsed := time.Since(start)

	got, err := os.ReadFile(localName)
	if err != nil {
		t.Fatalf("downloaded file missing: %v", err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("downloaded content mismatch")
	}
	if elapsed < 500*time.Millisecond {
		t.Fatalf("download finished too fast (%v); rate limit 20K was not applied", elapsed)
	}
	t.Logf("rate-limited download (12 KiB @ 20K/s) succeeded in %v", elapsed.Round(time.Millisecond))
}
