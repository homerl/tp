# tp（town portal / 传送门）— 在 SSH 终端里传文件，远端不用装任何东西

> 多跳板机反复传输多份日志实在让人崩溃

在 `ssh` 包一层，在会话里用 `!get` / `!put` 传文件，自动校验、断点续传。

### 这个项目最大的特点

简单说一句话：**只要你能在那个终端里敲进字符、也能看到回显，你就能传文件。**
因为 tp 传的只是「你能看到的那些字符」，任何能打字、能看回显的地方，就是它的通道。
打个比方，tp 就像给你已经开着的 SSH 会话开了个「后门小窗」——数据不另开通道，就藏在平时你敲命令、屏幕刷字的那些字符流里，借道现有这条 ssh 连接捎过去。所以它根本不挑环境


## 为什么做这个

你 SSH 到一台机器，想传个文件过来或过去，但：
- 跳板机再次自动跳转,你根本不清楚经过了哪些中间节点
- 多层跳转 + 多个OTP（jump host）时 scp 很麻烦
- 有些环境你只能拿到一个交互式终端，没有别的通道进行传输
- 定制版 / 精简版的 ssh server、堡垒机：运维把该关的都关了
- Terminal 不支持OSC 52

tp 的思路是：**只要有一个 SSH 会话了，那就直接用它传。** 数据走 base64 塞进现有 SSH 通道，远端只需要 `base64` + `dd` + 一个 hash 工具，这些基本每个 Linux 都有。

## 核心特性

- **远端零安装**：不需要在远端装 tp 或任何 agent
- **自动校验**：下载按 4 MiB 分块逐块校验
- **断点续传**：默认开启。中断后重新执行同一条命令，自动从上次断掉的块继续

## 构建

```
go build -o tp .
```

依赖：Go 1.26+，就三个库（`creack/pty`、`xxhash`、`x/sys` + `x/term`）。

## 使用

```
tp ssh <host> [ssh_args]       # 代替 'ssh'，后面参数原样传给 ssh
tp version
```

### 会话内命令

在 `tp ssh` 的终端里直接输入：

```
!get <remote_path> [local_name] [-l 0|1] [-f <log_file>]
!put <local_path> [remote_path] [-l 0|1] [-f <log_file>]
```

| 参数 | 说明 |
|------|------|
| `-l 1` | 开启日志/断点续传（**默认就是 1**） |
| `-l 0` | 关闭，纯传不记录 |
| `-f <file>` | 自定义日志文件路径（默认会自动获取断点日志 `<目标文件名>.tprlog`） |

### 典型工作流

```bash
$ tp ssh jump1 -p 2222          # 代替 ssh jump1 -p 2222
# ... 手动跳转到目标机器 ...

# 下载
!get /tmp/bigfile.bin
[tp] ↓ 1.2 GB → ./bigfile.bin (resumable)
[tp] ✓ ./bigfile.bin (1.2 GB) 42.3s 29.15 MB/s avg

# 上传
!put ./local.txt /tmp/remote.txt
[tp] ↑ ./local.txt (3.4 MB) → /tmp/remote.txt
[tp] ✓ /tmp/remote.txt uploaded OK

```

中断（Ctrl+C 或网络断了）后重新执行同一条 `!get` / `!put`，会从断点继续：

```
[tp] ↻ /tmp/bigfile.bin → ./bigfile.bin (resume from block 87)
```

### 退出

- 双击 Ctrl+C（1.5 秒内按两次）退出 tp，终端自动恢复
- 单次 Ctrl+C 转发给远端（中断远端前台进程）
- 远端 `exit` 也会退出

## 调试

tp 靠两个环境变量输出自己的协议轨迹——故意没做 `--debug` 参数，因为 `tp ssh` 后面的东西是原样透传给 ssh 的，放个 flag 在那儿分不清是给你的还是给 ssh 的。

```
TP_DEBUG=1 tp ssh host                     # 输出到 stderr
TP_DEBUG=1 TP_DEBUG_FILE=/tmp/tp.log tp ssh host   # 输出到文件
```

传文件的时候建议用 `TP_DEBUG_FILE`：进度条是用 `\r` 在同一行反复刷的，debug 打到同一个终端会把它花掉。

日志带时间戳，两个方向都记：tp 注入了什么、远端答了什么、哪些行被认成协议标记、哪些被当成 shell 回显的命令丢掉了：

```
11:46:52.656 drop echo of injected command (nonce 286ff10b9b170f89)
11:46:52.659 __TP_TMP_SIZE__ response: size=4194304
11:46:52.659 probe answered: 4194304
11:46:53.379 __TP_DONE__ response: remote sha "be27c93d..."
```

大段数据只留前 120 字节，并告诉你隐掉了多少，所以传 20 MB 不会把有用的几行埋掉。

## 工作原理

### 整体架构

```
你的键盘
    │
    ▼
┌──────────────────────────────────────────────┐
│  tp (本地进程)                                │
│                                              │
│  stdin reader ──→ 本地 echo + 转发           │
│       │                                      │
│       ├── 识别 !get / !put 命令              │
│       │                                      │
│       ▼                                      │
│  PTY (tp ↔ ssh)                              │
│       │                                      │
│  output reader ──→ 解析 __TP_*__ 标记        │
│       │         过滤远端重复 echo             │
│       │         base64 流式解码 → 写文件      │
│       ▼                                      │
│  stdout → 你的屏幕                           │
└──────────────────────────────────────────────┘
    │
    ▼ SSH 隧道
┌──────────────────────────────────────────────┐
│  远端 shell（无 tp）                          │
│  执行注入的 shell 命令：                      │
│    下载: dd + base64 分块输出                 │
│    上传: head -n N | base64 -d → 写临时文件   │
└──────────────────────────────────────────────┘
```

### 下载 (!get) 流程

1. tp 往 SSH 通道注入一条 shell 命令，远端用 `dd` 按 4 MiB 分块读文件
2. 每块先发一个 `__TP_BLOCK__ <序号> <校验和>` 标记，再发该块的 base64
3. 本地 output reader 解析标记、流式解码 base64（O(1) 内存）、逐块校验
4. 校验和通过 → 追加到临时文件 + 写入 `.tprlog`
5. 全部完成后 `__TP_DONE__` 触发：rename 临时文件到目标，删除日志
6. 任何一步失败：删除临时文件，保留日志（供续传），原文件不受影响

### 上传 (!put) 流程

1. tp 先探测远端目标是否存在（`__TP_EXISTS__`），存在则弹 y/N
2. 注入 `head -n N | base64 -d > tmp` 命令
3. 本地按 3765 字符/行把 base64 数据喂进 PTY（避开 4096 行缓冲限制）
4. `head` 读满 N 行自动退出（不依赖 ^D，多层跳转安全）
5. 远端校验临时文件大小 → rename 到目标 → 回报 sha256（`__TP_DONE__ <sha>`）
6. 本地比对 sha256，通过才算成功

### 为什么不会显示重复字符

tp 把本地终端设为 raw mode，自己做 echo（`echoInput`），同时用一个 `echoSuppressor` 队列匹配并吞掉远端回显的重复字符。不管远端 ECHO 开没开、OPOST 开没开，显示都只有一份。

### 断点续传机制

- 日志文件 `.tprlog`：首行是 `<文件名> <总块数>`，之后每行 `<块号> <校验和>`
- 下载续传：检查日志 + 本地临时文件的最后一个块校验和，通过则从下一块继续
- 上传续传：探测远端临时文件大小 + 最后几块的 xxh64，和本地日志比对，找到最新完好块
- 日志文件在传输成功时自动删除

## 协议标记

| 标记 | 方向 | 用途 |
|------|------|------|
| `__TP_BEGIN__\|name\|size\|blocks` | 远端→本地 | 下载开始 |
| `__TP_BLOCK__ <n> <cksum>` | 远端→本地 | 新块开始 |
| `__TP_DONE__ [sha]` | 远端→本地 | 传输结束（上传时带 sha256） |
| `__TP_ERROR__ <msg>` | 远端→本地 | 错误 |
| `__TP_EXISTS__ yes\|no` | 远端→本地 | 目标文件存在探测 |
| `__TP_TMP_SIZE__ <n>` | 远端→本地 | 上传续传：远端临时文件大小 |
| `__TP_CKSUM__ <c1> <c2>...` | 远端→本地 | 上传续传：远端临时文件块校验和 |

注入的命令里标记被拆成 `__TP_""DONE__` 的形式（空字符串拼接），这样 shell 回显命令本身时不会误触发本地解析。每条注入命令还带一个随机 nonce（shell 注释），用来识别并丢弃远端对命令的回显。

## 项目结构

```
main.go        入口，命令分发
session.go     tp ssh 主会话：PTY 管理、goroutine 编排、!命令解析
tty.go         本地终端处理：echo、echoSuppressor、ANSI 解析
protocol.go    协议标记解析、远端探测、nonce
download.go    !get 实现：分块下载、流式 base64 解码、续传
upload.go      !put 实现：分块上传、进度、校验
resume.go      .tprlog 日志解析
util.go        工具函数（humanSize、progressTicker 等）
e2e_test.go    端到端测试（模拟完整 PTY 链路）
sshwrap_test.go 协议/PTY 层单元测试
```

## 测试

```
go test ./...
```

测试覆盖：
- 完整 `!get` / `!put` 流程（模拟 PTY + base64 流）
- 断点续传（中断后恢复）
- 校验和失败处理
- 覆盖确认
- echoSuppressor 各种组合
- 路径注入防护

## 兼容性

**远端要求**（基本都有）：
- `base64`（GNU 或 BSD）
- `dd`
- `xxh64sum`（优先）或 `sha256sum` / `shasum` / `sha256`（至少一个）
- `stat`（GNU 或 BSD）、`wc`、`head`、`mv`、`rm`

**本地要求**：
- 仅 Linux（用了 unix ioctl）
- Go 1.26+ 构建

**已知限制**：
- 需要交互式 SSH 会话（非 `ssh host command` 模式）
- 路径中不能包含引号、`$`、反引号、反斜杠、`!`（防注入）
- 单条注入命令不能超过 4095 字节（PTY canonical mode 行缓冲限制），极长路径可能触发截断
- 很多 bash 快捷键（行编辑、历史等）没法正常用，回显偶尔也会抽风。定位就是开一个 bash 终端频繁上传下载小块文件，所以没往更复杂的方向改进
- 目前只测了 bash，没大范围测过其他 shell / 终端
