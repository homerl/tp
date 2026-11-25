package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// logBlock is one recorded block in a .tprlog resume log.
type logBlock struct {
	num   int
	cksum string
}

// resumeLog is the parsed contents of a .tprlog file: the header (the local
// filename it was created for, total block count, and optional block size) plus
// every recorded block in file order. !get and !put both write this same format.
type resumeLog struct {
	name       string     // filename from the header
	total      int        // total block count from the header
	blockSize  int        // bytes per block (defaults to tpBlockSize if omitted in legacy logs)
	blocks     []logBlock // successfully parsed blocks, in file order
	blockLines int        // total block lines in the file (incl. malformed)
}

// readResumeLog reads and parses a .tprlog file. It returns the parsed log, or
// nil when the file is missing/empty/malformed. The stale flag is true when the
// file exists but its header names a different local path (a log left over from
// another file); callers decide whether to delete it. Malformed block lines are
// skipped but counted in blockLines so callers can detect a corrupt log.
func readResumeLog(logName, localPath string) (rl *resumeLog, stale bool) {
	data, err := os.ReadFile(logName)
	if err != nil {
		return nil, false // no log
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 1 {
		return nil, false
	}
	hdr := strings.Fields(lines[0])
	if len(hdr) < 2 {
		return nil, false // malformed header
	}
	if hdr[0] != localPath {
		return nil, true // stale: log belongs to a different file
	}
	var total int
	fmt.Sscanf(hdr[1], "%d", &total)
	blockSize := tpBlockSize
	if len(hdr) >= 3 {
		if bs, err := strconv.Atoi(hdr[2]); err == nil && bs > 0 {
			blockSize = bs
		}
	}
	rl = &resumeLog{name: hdr[0], total: total, blockSize: blockSize, blockLines: len(lines) - 1}
	for _, ln := range lines[1:] {
		f := strings.Fields(ln)
		if len(f) < 2 {
			continue
		}
		num, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		rl.blocks = append(rl.blocks, logBlock{num: num, cksum: f[1]})
	}
	return rl, false
}
