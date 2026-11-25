# tp (town portal) — Transfer files over an SSH terminal, nothing to install on the remote end

> Bouncing through multiple jump hosts to move a pile of logs back and forth is maddening.

> 中文版 / Chinese version: [README_CN.md](README_CN.md)

Wrap `ssh`, and inside the session use `get@!` / `put@!` to transfer files, with automatic checksums and resumable transfers.

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
get@! [-l <rate>] [-d 0|1] [-f <log_file>] <remote_path> [local_name]
put@! [-l <rate>] [-d 0|1] [-f <log_file>] <local_path> [remote_path]
```

| Parameter | Description |
|------|------|
| `-l <rate>` / `-r <rate>` | Rate limit (**unlimited by default**), e.g. `-l 20K`, `-l 500K`, `-l 2M`, to prevent bastion buffer overflows (uses 16 KiB blocks when rate-limited; flags may appear before or after paths; local paths expand `~/`) |
| `-d 1` | Enable logging / resumption (**default is 1**) |
| `-d 0` | Disable, transfer without recording |
| `-f <file>` | Custom log file path (by default it auto-detects the resume log `<target filename>.tprlog`) |

`!get` / `!put` work as well, for muscle memory. The bang trails the word in the
primary spelling because bash performs history expansion on a `!` followed by
anything but a space, tab or newline — a leading `!get` could come back as
`bash: !get: event not found`, while a trailing bang is inert and always reaches
tp. Commands are matched as whole words, so `get@!x` or a line that merely starts
with `get` goes to the shell.

### Slow links and bastions

Some bastion hosts pace pasted input, delivering it a few characters at a time.
tp reads a file far faster than such a link can carry it, so it now says so
instead of failing: while its own queue is still backing up you will see
`link is slower than tp can read: 17 KB still queued`, and if the remote has not
answered after the first budget it waits longer rather than declaring a transfer
failed (a false timeout resets the terminal mid-transfer and leaves a file you
cannot trust — tp has then simply not seen the confirmation yet).

| Variable | Default | Meaning |
|------|------|------|
| `TP_LINK_STALL` | `60` | seconds with zero write progress before the link is called dead |
| `TP_QUIET_NOTE` | `10` | seconds of silence before tp says it is still waiting (`0` = never) |
| `TP_VERIFY_TIMEOUT` | `30` + 2s per 4 MiB | first wait for the remote's checksum |
| `TP_VERIFY_CAP` | `600` | absolute limit on that wait |
| `TP_DEBUG` | off | trace the protocol to stderr |
| `TP_DEBUG_FILE` | off | trace to a file instead (keeps the progress bar clean) |

### Fast network, glacial screen: the link is metered by lines

A symptom worth recognising before you blame tp: inside the bastion session,
scrolling back in `screen` crawls — 100 lines can take five minutes, and pasting
refreshes visibly line by line — yet `scp` a big log to another machine and it
flies. The bandwidth is there; the *screen path* is not.

This is a well-populated corner of the internet, and the intermediaries all make
the same trade: they meter by **lines or screenfuls**, not by bytes, because they
want to stay interactive. The tmux author on why tmux crawls where ssh flies:
"ssh is happy to fill the TCP buffers and let the terminal chew through it, the
only thing it cares about responding to is ^C", so tmux slows down once it has
about eight screenfuls outstanding (`TTY_BLOCK_START` = cols × rows × 8) and
redraws instead — bigger window, bigger tax. EternalTerminal's flow control is
literally 1024 lines/second, which is why `cat`-ing a file with no newlines in it
is suddenly fast. Browser terminals (xterm.js and friends) add their own frame
rate on top, and lose the backpressure a native terminal gets free from the
kernel. Bastion vendors hit it themselves: JumpServer shipped a bug where `sz`
stalled at 99% above ~100 KB.

What it costs tp:

- **Upload — barely affected.** That direction is input, and tp already assumes
  some bastions drip characters (see `link is slower than tp can read` above).
  The upload command also runs `stty -echo` on the remote, which matters a lot
  here: with echo on, the kernel would echo the whole base64 body back and every
  byte would be rendered twice.
- **Download — this is the one at risk.** A 4 MiB block leaves the remote as
  5.6 MB of base64 in 175 long lines (`base64 -w 32000`), so 100 MB is ~4,400
  newlines: cheap if the meter counts newlines in the stream. But if that shell
  is inside an *attached* `screen`/`tmux` window, the multiplexer has to draw the
  stream into its window, and it wraps at the window width: 5.6 MB over 80
  columns is ~70,000 lines per block, ~1.7 million per 100 MB. That is the
  difference between a minute and an afternoon.

Measure it before optimising. Run this in the bastion session, once inside
`screen` and once outside — the difference is what the multiplexer charges:

```bash
dd if=/dev/zero of=/tmp/50m.bin bs=1M count=50

# 1 pure throughput, nothing ever drawn
time dd if=/dev/zero bs=1M count=50 2>/dev/null | base64 | wc -c

# 2 the same bytes, but they have to reach the screen
time base64 -w 0 /tmp/50m.bin > /dev/tty

# 3 what a line costs: 2000 lines vs the same bytes with no newlines
time seq 1 2000 > /dev/tty
time seq 1 2000 | tr '\n' ' ' > /dev/tty

# 4 what one round trip costs
time (for i in $(seq 30); do echo x > /dev/tty; done)
```

How to read it: 1 fast and 2 slow means the money is charged for *drawing*, and
tp's downloads pay it. 3's first line far slower than its second means newlines
are the unit. If 1, 2 and 3 are all fine and only `screen` scrolling is painful,
your terminal is ugly and tp is fine. Test 4 × the number of lines is your floor.

What you can do about it, biggest lever first:

1. Do big transfers in a shell that is not an attached `screen`/`tmux` window —
   otherwise every base64 byte is parsed, drawn and re-emitted on its way to you.
2. Make the window wide (smaller font, 300–400 columns). The multiplexer wraps at
   the window width, so 4× the columns is 4× fewer lines to draw. tp passes your
   real window size to the remote, so this reaches all the way through.
3. Keep bulk output out of the tty: `cmd > /tmp/x 2>&1` then `less /tmp/x`.
   Bytes that never enter the pty are never metered.
4. In `screen`, `defbce on` shrinks redraws. Do not reach for `defflow`: XON/XOFF
   through a chain of proxies tends to lock the session instead.

### Downloading never goes silent

Nothing times out on the download path — a get ends when `__TP_DONE__` arrives,
and its progress bar only moves when bytes arrive. On a link that drips, the
screen therefore just stops moving while everything is fine, which looks exactly
like a crashed program (and was reported as one). So while a get is in flight a
watchdog keeps saying what tp is waiting for, after 10s of silence and then at
25s, 1m, 2m and 5m:

```
[tp] … still waiting for the remote to answer: 12s of silence, nothing received yet
[tp] … still waiting for ./big.bin: 25s of silence, 4.20 MB/100.00 MB received
[tp] … still waiting for ./big.bin: 25s of silence, 4.20 MB/100.00 MB received, tp is still pushing 1.2 KB
```

The last line is the useful one: bytes still queued on tp's side mean the link is
pacing *input*, while silence with an empty queue means the remote (or something
rendering for it) is the one holding the data. Bytes moving resets the ladder, so
a transfer that is merely slow stays quiet; one that is truly stuck gets the last
note, which names the two explanations that look identical from the chair and then
stops talking. `TP_QUIET_NOTE=30` moves the whole ladder; `0` silences it.

### Typical workflow

```bash
$ tp ssh jump1 -p 2222          # replaces 'ssh jump1 -p 2222'
# ... manually jump to the target machine ...

# Download
get@! /tmp/bigfile.bin
[tp] ↓ 1.2 GB → ./bigfile.bin (resumable)
[tp] ✓ ./bigfile.bin (1.2 GB) 42.3s 29.15 MB/s avg

# Upload
put@! ./local.txt /tmp/remote.txt
[tp] ↑ ./local.txt (3.4 MB) → /tmp/remote.txt
[tp] ✓ /tmp/remote.txt uploaded OK

```

After an interruption (Ctrl+C or network drop), re-run the same `get@!` / `put@!` and it resumes from where it stopped:

```
[tp] ↻ /tmp/bigfile.bin → ./bigfile.bin (resume from block 87)
```

### Exiting and cancelling

- Single Ctrl+C: cleanly aborts an active `get@!` / `put@!` transfer and restores the terminal (keeping resume state); when idle, forwards to the remote foreground process
- Triple-tap Ctrl+C (3 times within 1.5s): exits tp and restores the terminal automatically
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
│  stdin reader ──→ forward keystrokes          │
│       │                                       │
│       ├── recognizes get@! / put@! commands     │
│       │                                       │
│       ▼                                       │
│  PTY (tp ↔ ssh)                               │
│       │                                       │
│  output reader ──→ parse __TP_*__ tags        │
│       │         drop echo of a released line  │
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

### Download (get@!) flow

1. tp injects a shell command into the SSH channel; the remote reads the file in 4 MiB chunks with `dd`
2. Each chunk first sends a `__TP_BLOCK__ <n> <cksum>` tag, then the base64 of that chunk
3. The local output reader parses the tags, stream-decodes the base64 (O(1) memory), and verifies chunk by chunk
4. Checksum passes → appended to the temp file + written to `.tprlog`
5. On completion, `__TP_DONE__` triggers: rename the temp file to the target, delete the log
6. On any failure: delete the temp file, keep the log (for resuming), leave the original file untouched

### Upload (put@!) flow

1. tp first probes whether the remote target exists (`__TP_EXISTS__`); if it does, it prompts y/N
2. Inject `head -n N | base64 -d > tmp`
3. Feed the base64 data into the PTY in rows of 4000 chars (to avoid the 4096 line-buffer limit; with `-l <rate>`, automatically uses shorter lines and paces writes smoothly)
4. `head` exits automatically once N lines are read (no reliance on ^D, safe across multi-layer jumps)
5. The remote verifies the temp file size → renames it to the target → reports sha256 (`__TP_DONE__ <sha>`)
6. The local side compares sha256; only a match counts as success

### Who echoes what

One screen, one painter: **the remote shell echoes, tp forwards.** That is the
same split plain `ssh` uses, and it is the only one that survives line editing.
tp puts its own terminal in raw mode (so it sees every keystroke) and puts the
pty it shares with ssh in raw mode too — *except* `ECHO`, which it deliberately
leaves alone. ssh copies the termios of its own stdin into the SSH `pty-req`, so
that bit decides whether the **remote** pty echoes, and bash's readline decides
once per prompt whether it draws anything at all: on a no-echo terminal it
concludes it is wired to a silent device, and ↑ history recall, Tab completion
and Ctrl+R then all happen with nothing on the screen — the command still runs,
so the terminal just looks like it never refreshed.

tp used to clear `ECHO` and echo every keystroke itself. Then the remote had
nothing to draw, and the two painters never met — until someone pressed ↑, where
readline had something to show that tp had no way to know about. Local echo also
double-erased (tp's `\b \b` plus readline's `\b\e[K` wipes one column too many)
and printed your password in clear text.

Local echo survives in exactly two places, where the bytes genuinely never reach
the remote: the `get@!` / `put@!` line you are typing, and the y/N overwrite
answer. A released command line (typed `git status`, held as a possible `get@!`)
is the one case where tp has already painted bytes the remote is about to echo,
so it hands them to `echoSuppressor` to swallow that copy.

### Why uploads say `stty -echo`

Now that the remote pty echoes, the kernel would echo every byte of an upload
back down the link — a 3 MB upload coming back as 4 MB of base64, on the slowest
link in the path. So the upload command runs `stty -echo` before `head` starts
reading and `stty echo` before it reports the checksum. Downloads are unaffected
(tp sends one line, the rest flows the other way).

### Why tp's commands stay out of your shell history

tp runs a transfer by injecting one long shell command into your session. Every
injected command starts with a space, so a remote whose bash sets
`HISTCONTROL=ignorespace` or `ignoreboth` (Debian and Ubuntu ship that) never
records it — ↑ keeps recalling your own commands instead of a 1200-character
one-liner that would re-transfer the file if you ran it. On a remote without
that setting the space is simply ignored and tp's command does land in the
history; nothing breaks, it is just noisier to scroll back through.

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
tty.go          local terminal handling: pty modes, echoSuppressor, ANSI parsing
protocol.go     protocol tag parsing, remote probing, nonce
download.go     get@! implementation: chunked download, stream base64 decode, resumption
upload.go       put@! implementation: chunked upload, progress, checksums
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
- Full `get@!` / `put@!` flow (simulated PTY + base64 stream)
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
- ↑ history recall, Tab completion and Ctrl+R work, because the remote is the one
  echoing. If a bastion forces its pty to no-echo, typing is invisible — exactly
  as it would be under plain `ssh`
- Its positioning is "open a bash terminal to frequently upload/download small
  files", so it hasn't been improved in more complex directions (no terminal
  emulator, no screen model behind what it forwards)
- Only bash has been tested so far; it hasn't been broadly tested against other shells / terminals
