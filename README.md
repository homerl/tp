# tp (town portal) — Transfer files over an SSH terminal, nothing to install on the remote end

> Bouncing through multiple jump hosts to move a pile of logs back and forth is maddening.

> 中文版 / Chinese version: [README_CN.md](README_CN.md)

Wrap `ssh`, and inside the session use `!get` / `!put` to transfer files, with automatic checksums and resumable transfers.

### The best thing about this project

In one sentence: **as long as you can type characters into that terminal and see the echo back, you can transfer files.**
tp only ever moves "the characters you can see" — anywhere you can type and see output is a channel for it.
Think of tp as opening a little "backdoor window" on your already-open SSH session — data doesn't open a new channel, it hides inside the same character stream you use for typing commands and watching the screen scroll, piggybacking on the existing ssh connection. So it doesn't care much about the environment.

## Why this exists

You SSH into a machine and want to transfer a file in or out, but:
- The jump host auto-forwarding again, and you have no idea what intermediate nodes you went through
- Multi-layer jumps + multiple OTPs (jump hosts) make scp a pain
- Some environments only hand you an interactive terminal, with no other channel to transfer through
- Custom / minimal ssh servers, bastion hosts: ops has locked down everything they could
- Your terminal doesn't support OSC 52

tp's approach: **if you already have an SSH session, just use it to transfer.** Data goes base64-encoded into the existing SSH channel; the remote only needs `base64` + `dd` + a hash tool, which basically every Linux has.

## Core features

- **Zero installation on the remote**: no need to install tp or any agent on the far end
- **Automatic checksums**: downloads are verified block by block in 4 MiB chunks
- **Resumable transfers**: on by default. Re-run the same command after an interruption and it resumes from the block where it stopped

## Build

```
go build -o tp .
```

Dependencies: Go 1.26+, just three libraries (`creack/pty`, `xxhash`, `x/sys` + `x/term`).

## Usage

```
tp ssh <host> [ssh_args]       # replaces 'ssh', passes the following args straight to ssh
tp version
```

### In-session commands

Type directly in the `tp ssh` terminal:

```
!get <remote_path> [local_name] [-l 0|1] [-f <log_file>]
!put <local_path> [remote_path] [-l 0|1] [-f <log_file>]
```

| Parameter | Description |
|------|------|
| `-l 1` | Enable logging / resumption (**default is 1**) |
| `-l 0` | Disable, transfer without recording |
| `-f <file>` | Custom log file path (by default it auto-detects the resume log `<target filename>.tprlog`) |

### Typical workflow

```bash
$ tp ssh jump1 -p 2222          # replaces 'ssh jump1 -p 2222'
# ... manually jump to the target machine ...

# Download
!get /tmp/bigfile.bin
[tp] ↓ 1.2 GB → ./bigfile.bin (resumable)
[tp] ✓ ./bigfile.bin (1.2 GB) 42.3s 29.15 MB/s avg

# Upload
!put ./local.txt /tmp/remote.txt
[tp] ↑ ./local.txt (3.4 MB) → /tmp/remote.txt
[tp] ✓ /tmp/remote.txt uploaded OK

```

After an interruption (Ctrl+C or network drop), re-run the same `!get` / `!put` and it resumes from where it stopped:

```
[tp] ↻ /tmp/bigfile.bin → ./bigfile.bin (resume from block 87)
```

### Exiting

- Double-tap Ctrl+C (twice within 1.5s) to exit tp; the terminal restores automatically
- A single Ctrl+C is forwarded to the remote end (interrupts the remote foreground process)
- The remote `exit` also exits

## Debugging

tp traces its own protocol through two environment variables — there is no
`--debug` flag on purpose, because everything after `tp ssh` is passed verbatim
 to ssh, so a flag there could not be told apart from one meant for ssh.

```
TP_DEBUG=1 tp ssh host                     # trace to stderr
TP_DEBUG=1 TP_DEBUG_FILE=/tmp/tp.log tp ssh host   # trace to a file
```

Prefer `TP_DEBUG_FILE` while a transfer is running: the progress bar repaints a
single line with `\r`, so debug lines written to the same terminal smear it.

The log is timestamped and shows both directions of the conversation — what tp
injected, what came back, which lines it recognised as protocol markers, and
which it dropped as the shell echoing a command back at it:

```
11:46:52.656 drop echo of injected command (nonce 286ff10b9b170f89)
11:46:52.659 __TP_TMP_SIZE__ response: size=4194304
11:46:52.659 probe answered: 4194304
11:46:53.379 __TP_DONE__ response: remote sha "be27c93d..."
```

Large payloads are truncated to 120 bytes with the elided count shown, so a
20 MB download does not bury the interesting lines.

## How it works

### Overall architecture

```
Your keyboard
    │
    ▼
┌──────────────────────────────────────────────┐
│  tp (local process)                          │
│                                              │
│  stdin reader ──→ local echo + forward        │
│       │                                       │
│       ├── recognizes !get / !put commands     │
│       │                                       │
│       ▼                                       │
│  PTY (tp ↔ ssh)                               │
│       │                                       │
│  output reader ──→ parse __TP_*__ tags        │
│       │         filter remote duplicate echo  │
│       │         base64 stream-decode → write  │
│       ▼                                       │
│  stdout → your screen                         │
└──────────────────────────────────────────────┘
    │
    ▼ SSH tunnel
┌──────────────────────────────────────────────┐
│  Remote shell (no tp)                         │
│  Executes injected shell commands:            │
│    Download: dd + base64 output in chunks     │
│    Upload: head -n N | base64 -d → temp file  │
└──────────────────────────────────────────────┘
```

### Download (!get) flow

1. tp injects a shell command into the SSH channel; the remote reads the file in 4 MiB chunks with `dd`
2. Each chunk first sends a `__TP_BLOCK__ <n> <cksum>` tag, then the base64 of that chunk
3. The local output reader parses the tags, stream-decodes the base64 (O(1) memory), and verifies chunk by chunk
4. Checksum passes → appended to the temp file + written to `.tprlog`
5. On completion, `__TP_DONE__` triggers: rename the temp file to the target, delete the log
6. On any failure: delete the temp file, keep the log (for resuming), leave the original file untouched

### Upload (!put) flow

1. tp first probes whether the remote target exists (`__TP_EXISTS__`); if it does, it prompts y/N
2. Inject `head -n N | base64 -d > tmp`
3. Feed the base64 data into the PTY in rows of 3765 chars (to avoid the 4096 line-buffer limit)
4. `head` exits automatically once N lines are read (no reliance on ^D, safe across multi-layer jumps)
5. The remote verifies the temp file size → renames it to the target → reports sha256 (`__TP_DONE__ <sha>`)
6. The local side compares sha256; only a match counts as success

### Why duplicate characters aren't shown

tp sets the local terminal to raw mode and does its own echo (`echoInput`), while a queue called `echoSuppressor` matches and swallows the duplicate characters from the remote echo. Whether the remote has ECHO or OPOST on or off, only one copy is displayed.

### Resumption mechanism

- Log file `.tprlog`: first line is `<filename> <total blocks>`, then each subsequent line is `<block number> <checksum>`
- Download resume: check the log + the last chunk's checksum in the local temp file; if it passes, continue from the next chunk
- Upload resume: probe the remote temp file size + the xxh64 of the last few chunks, compare against the local log to find the newest intact chunk
- The log file is deleted automatically on successful transfer

## Protocol tags

| Tag | Direction | Purpose |
|------|------|------|
| `__TP_BEGIN__\|name\|size\|blocks` | remote→local | download start |
| `__TP_BLOCK__ <n> <cksum>` | remote→local | new chunk start |
| `__TP_DONE__ [sha]` | remote→local | transfer end (includes sha256 for uploads) |
| `__TP_ERROR__ <msg>` | remote→local | error |
| `__TP_EXISTS__ yes\|no` | remote→local | target file existence probe |
| `__TP_TMP_SIZE__ <n>` | remote→local | upload resume: remote temp file size |
| `__TP_CKSUM__ <c1> <c2>...` | remote→local | upload resume: remote temp file chunk checksums |

In the injected command, the tag is split into `__TP_""DONE__` form (empty-string concatenation), so that when the shell echoes the command itself it won't accidentally trigger local parsing. Each injected command also carries a random nonce (in a shell comment), used to identify and discard the remote's echo of the command.

## Project structure

```
main.go         entrypoint, command dispatch
session.go      tp ssh main session: PTY management, goroutine orchestration, !command parsing
tty.go          local terminal handling: echo, echoSuppressor, ANSI parsing
protocol.go     protocol tag parsing, remote probing, nonce
download.go     !get implementation: chunked download, stream base64 decode, resumption
upload.go       !put implementation: chunked upload, progress, checksums
resume.go       .tprlog log parsing
util.go          utility functions (humanSize, progressTicker, etc.)
e2e_test.go     end-to-end tests (simulates full PTY link)
sshwrap_test.go protocol/PTY unit tests
```

## Testing

```
go test ./...
```

Test coverage:
- Full `!get` / `!put` flow (simulated PTY + base64 stream)
- Resumption (recovery after interruption)
- Checksum failure handling
- Overlap confirmation
- echoSuppressor in various combinations
- Path injection protection

## Compatibility

**Remote requirements** (basically always present):
- `base64` (GNU or BSD)
- `dd`
- `xxh64sum` (preferred) or `sha256sum` / `shasum` / `sha256` (at least one)
- `stat` (GNU or BSD), `wc`, `head`, `mv`, `rm`

**Local requirements**:
- Linux only (uses unix ioctl)
- Go 1.26+ to build

**Known limitations**:
- Requires an interactive SSH session (not the `ssh host command` mode)
- Paths can't contain quotes, `$`, backticks, backslashes, or `!` (anti-injection)
- A single injected command can't exceed 4095 bytes (PTY canonical mode line-buffer limit); very long paths may trigger truncation
- Many bash shortcuts (line editing, history, etc.) don't work properly, and the echo occasionally misbehaves. Its positioning is "open a bash terminal to frequently upload/download small files," so it hasn't been improved in more complex directions
- Only bash has been tested so far; it hasn't been broadly tested against other shells / terminals
