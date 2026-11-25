package main

import (
	"fmt"
	"os"
)

const version = "0.5.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "ssh":
		os.Exit(cmdSSH(os.Args[2:]))
	case "version", "--version":
		fmt.Printf("tp %s\n", version)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "tp: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `tp %s - transfer files over SSH terminal (nothing to install on remote)

Usage:
  tp ssh <host> [ssh_args]       Local: wrap ssh (use this instead of 'ssh')
  tp version

In-session commands (type these in the tp ssh terminal):
  @tp_get@ [-l <rate>] [-d 0|1] [-f <log>] <remote_path> [local_name]   Download a remote file
  @tp_put@ [-l <rate>] [-d 0|1] [-f <log>] <local_path> [remote_path]   Upload a local file
  (-l 20K / -r 20K limits transfer rate to 20 KiB/s; default unlimited)

Workflow:
  $ tp ssh jump1              # instead of 'ssh jump1'
  # ... manually navigate to the target machine however you normally do ...
  # Now on the target machine:

  @tp_get@ /tmp/bigfile.bin             # download
  @tp_put@ ./local.txt /tmp/remote.txt  # upload

Both directions verify checksums automatically.
The local 'tp ssh' silently intercepts data - you only see progress bars.

Slow links (some bastions pace pasted input): tp reports how much is still
queued and waits for the remote instead of failing early. Tunables:
  TP_LINK_STALL, TP_VERIFY_TIMEOUT, TP_VERIFY_CAP  (seconds)

Debugging:
  TP_DEBUG=1 tp ssh ...                     trace the protocol to stderr
  TP_DEBUG=1 TP_DEBUG_FILE=/tmp/tp.log ...  trace to a file (keeps the screen clean)
`, version)
}
