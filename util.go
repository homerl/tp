package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// parseRateLimit parses a human-readable byte rate such as "20K", "500k",
// "2M", "10000", or "20KB" into bytes per second.
func parseRateLimit(s string) (int64, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return 0, fmt.Errorf("empty rate limit")
	}
	u := strings.ToUpper(raw)
	u = strings.TrimSuffix(u, "/S")
	u = strings.TrimSuffix(u, "B")
	mult := int64(1)
	switch {
	case strings.HasSuffix(u, "K"):
		mult = 1024
		u = strings.TrimSuffix(u, "K")
	case strings.HasSuffix(u, "M"):
		mult = 1024 * 1024
		u = strings.TrimSuffix(u, "M")
	case strings.HasSuffix(u, "G"):
		mult = 1024 * 1024 * 1024
		u = strings.TrimSuffix(u, "G")
	}
	n, err := strconv.ParseInt(u, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid rate limit %q (expected e.g. 20K, 500K, 2M)", s)
	}
	return n * mult, nil
}

// expandLocalPath expands a leading "~/" to the local user's home directory.
func expandLocalPath(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			if p == "~" {
				return home
			}
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

func humanSize(n int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)
	switch {
	case n >= TB:
		return fmt.Sprintf("%.2f TB", float64(n)/float64(TB))
	case n >= GB:
		return fmt.Sprintf("%.2f GB", float64(n)/float64(GB))
	case n >= MB:
		return fmt.Sprintf("%.2f MB", float64(n)/float64(MB))
	case n >= KB:
		return fmt.Sprintf("%.2f KB", float64(n)/float64(KB))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// screenf writes a message to the controlling terminal, falling back to stderr.
// tp's own output is routinely redirected ("tp ssh host 2>tp.log"), and a message
// that lands only in a log file is indistinguishable from a hang: the screen sits
// there while tp waits — for an overwrite answer, or simply for bytes that are
// crossing a slow bastion. Anything the user needs to see belongs on the screen
// whatever the redirections.
func screenf(format string, args ...any) {
	if tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0); err == nil {
		fmt.Fprintf(tty, format, args...)
		tty.Close()
		return
	}
	fmt.Fprintf(os.Stderr, format, args...)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "tp: "+format+"\n", args...)
	os.Exit(1)
}

// errf prints a red [tp] ✗ error to stderr on its own line (leading newline so
// it doesn't smear onto the remote prompt). Use it for single-line errors; the
// couple of multi-line diagnostics keep their own Fprintf so the continuation
// lines stay uncolored.
func errf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\n\033[1;31m[tp] ✗ "+format+"\033[0m\n", args...)
}

// sha256FileHandle hashes the file and seeks it back to the start
func sha256FileHandle(f *os.File) string {
	h := sha256.New()
	buf := make([]byte, 512*1024)
	for {
		n, err := io.ReadFull(f, buf)
		h.Write(buf[:n])
		if err != nil {
			break
		}
	}
	f.Seek(0, io.SeekStart)
	return hex.EncodeToString(h.Sum(nil))
}

func speedStr(mbs float64) string {
	return fmt.Sprintf("%.2f MB/s", mbs)
}

// progressTicker computes instantaneous transfer speed with a ~100ms throttle,
// shared by the !get (download) and !put (upload) progress displays. start
// primes the baseline at the given byte position; tick(pos) reports whether a
// progress line is due (>=100ms since the last tick) and the speed since then.
type progressTicker struct {
	lastPos  int64
	lastTick time.Time
}

func (p *progressTicker) start(pos int64) {
	p.lastPos = pos
	p.lastTick = time.Now()
}

// tick returns (due, speedMbps). due is true once at least 100ms have elapsed
// since the last tick (and it then updates the baseline); speedMbps is the
// instantaneous speed since the last tick.
func (p *progressTicker) tick(pos int64) (bool, float64) {
	now := time.Now()
	if now.Sub(p.lastTick) < 100*time.Millisecond {
		return false, 0
	}
	dt := now.Sub(p.lastTick)
	var speed float64
	if dt > 0 {
		speed = float64(pos-p.lastPos) / dt.Seconds() / 1024 / 1024
	}
	p.lastPos = pos
	p.lastTick = now
	return true, speed
}
