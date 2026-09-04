package main

import (
	"fmt"
	"os"
)

const version = "0.4.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "ssh":
		cmdSSH(os.Args[2:])
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
  !get <remote_path> [local_name]    Download a remote file
  !put <local_path> [remote_path]    Upload a local file

Workflow:
  $ tp ssh jump1              # instead of 'ssh jump1'
  # ... manually navigate to the target machine however you normally do ...
  # Now on the target machine:

  !get /tmp/bigfile.bin              # download
  !put ./local.txt /tmp/remote.txt   # upload

Both directions verify sha256 automatically.
The local 'tp ssh' silently intercepts data - you only see progress bars.
`, version)
}
