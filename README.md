# Tendriq 卷须

[![ci](https://github.com/tokced/tendriq/actions/workflows/ci.yml/badge.svg)](https://github.com/tokced/tendriq/actions/workflows/ci.yml)

[一句话部署](#一句话交给-agent-部署) · [中文介绍](#中文介绍) · [English introduction](#english-introduction) · [架构](#架构) · [快速开始](#快速开始) · [安全默认值](#安全默认值)

**Tendriq 卷须**是一个自托管的 AI agent 跨设备执行项目，官方仓库为 **`tokced/tendriq`**，原名 Tendril。**一个大脑，多台执行器。**

**Tendriq** is a self-hosted cross-device execution system for AI agents, formerly named Tendril. The official repository is **`tokced/tendriq`**. **One brain. Many executors.**

## 一句话交给 agent 部署

不方便分享链接？把下面这句话复制给具备联网搜索与终端操作能力的 agent：

```text
帮我找到开源项目 Tendriq 卷须，阅读官方文档，在我的设备上完成部署并验证可用，必要的设备授权由我确认。
```

这是给 agent 的任务提示词，不是安装命令，也不代表零授权部署。需要使用者确认目标设备、授权目录与必要权限。供 agent 阅读的部署流程见 [Agent 部署指引](docs/agent-deploy.md)。

For an agent with web search and terminal access:

```text
Find the open-source project Tendriq, read its official documentation, deploy it on my devices, and verify that it works; ask me to confirm the required device authorizations.
```

This is a task prompt, not a shell command or an unattended installer. Follow the [agent deployment guide](docs/agent-deploy.md) and obtain the user's authorization before connecting devices or expanding access.

> **兼容性 / Compatibility:** 本次更新品牌和仓库名；可执行文件 `tendril-agent`、`TENDRIL_*` 环境变量、`TENDRIL1:` 邀请格式、现有默认状态目录及 `tendril` MCP/skill 标识保持不变。The rebrand does not rename existing runtime identifiers or state directories; use the documented identifiers rather than mechanically replacing them with `tendriq`.

## 中文介绍

### 让 AI 的行动，不再止于一台电脑。

**一个大脑，多台设备。让你的 AI 从“告诉你怎么做”，走向“在你的机器上真正完成”。**

你的设备分散在不同地方，运行着不同系统。但完成一件事，不应该要求你在它们之间来回切换、复制命令，再把结果搬回聊天窗口。

Tendriq 把这些设备接到同一个 agent 的行动范围内：**思考留在母端，执行延伸到各处。**

模型、上下文与记忆集中在一处；设备上的轻量子端只负责接受指令、执行任务、回传结果。不需要在每台机器上再部署一套模型，也不需要让多个独立 agent 反复同步任务背景。

像植物伸出的卷须——**大脑不必搬过去，行动可以延伸过去。**

### 不只是看见设备，而是能在设备上做事

通过 Tendriq，agent 可以在获授权的设备上执行命令、浏览目录、读写和传输文件，并查询任务状态与结果。

这意味着，你可以让同一个 agent 到另一台机器上检查运行环境、读取日志、修改文件，再根据实际返回继续处理，而不必由你充当两台机器之间的“复制粘贴接口”。

**设备不再只是聊天中被提到的名字，而是可以实际调用的执行端。**

### 设备可以增加，工具列表不必跟着复制

Tendriq 通过 MCP 提供一套统一工具，目标设备作为参数传入。

接入另一台设备，不必再给模型重复挂上一整套同名工具。相同的调用方式，面向不同的机器。

**扩展的是行动范围，不是重复的工具清单。**

### 把执行交出去，把授权留在自己手里

能够远程执行，不代表应该默认放开一切。

Tendriq 支持按设备批准、暂停和吊销接入；文件操作限定在授权目录内；命令执行需要母端与子端双方显式开启。设备通过有期限的一次性邀请接入，连接使用 TLS，并固定母端证书指纹。关键操作留下审计记录。

**让 agent 能做事，也让你能决定：在哪台设备上，允许它做哪些事。**

### 不把愿景冒充已经交付的能力

Tendriq 已提供母端服务、Go 子端和 MCP 桥。Windows 与 Linux 子端已有实机使用；macOS 子端已通过交叉编译，仍待实机验收。

它不是远程桌面，不提供屏幕流；也不是安全沙箱——命令以子端运行账户的权限执行，文件访问的目录限制不等于命令执行隔离。请只在你拥有或明确获授权的设备上部署。

**不必给每台机器一个大脑。<br>给同一个大脑，伸向多台机器的卷须。**

**Tendriq · 一个大脑，多台执行器。**

---

## English introduction

### Give your AI reach beyond a single computer.

**One brain. Many machines. Take your AI from telling you how to do something to getting it done on your own devices.**

Your devices live in different places and run different operating systems. Getting something done should not mean switching between them, copying commands, and carrying the results back to a chat window.

Tendriq brings those devices within reach of a single agent: **reasoning stays on the mother host; execution reaches out to your machines.**

The model, context, and memory stay in one place. A lightweight executor on each device accepts instructions, runs tasks, and returns results. There is no need to deploy a model on every machine or keep separate agents synchronized on the same task.

Like the tendrils of a climbing plant—**the brain stays put. Its reach keeps growing.**

### Not just seeing your devices. Getting things done on them.

Through Tendriq, an agent can execute commands on authorized devices, browse directories, read, write, and transfer files, and retrieve task status and results.

The same agent can inspect the environment on another machine, read its logs, edit files, and continue working from the results it actually receives—without making you the copy-and-paste interface between computers.

**A device is no longer just a name in a conversation. It becomes an executor the agent can actually use.**

### Add devices, not duplicate tool lists.

Tendriq exposes one shared set of tools through MCP, with the target device passed as a parameter.

Connecting another device does not require registering another copy of the same tools with the model. The same interface works across different machines.

**Grow the agent's reach, not a list of duplicate tools.**

### Delegate execution. Keep control of authorization.

Remote execution should not mean unrestricted access by default.

Tendriq supports per-device approval, suspension, and revocation. File operations stay within authorized directories. Command execution must be explicitly enabled on both the mother host and the device. Devices join through expiring, single-use invitations, connect over TLS with the mother host's certificate fingerprint pinned, and leave audit records for key operations.

**Give your agent the ability to act—and keep the decision about where it may act and what you enable.**

### A clear line between what works and what comes next.

Tendriq already provides the mother service, Go executors, and an MCP bridge. Windows and Linux executors have been used on real machines. The macOS executor has been cross-compiled successfully but still awaits real-device validation.

Tendriq is not a remote desktop and does not provide screen streaming. It is not a security sandbox: commands run with the executor account's privileges, and file-access directory restrictions do not isolate command execution. Deploy it only on devices you own or are explicitly authorized to manage.

**You do not need a brain on every machine.<br>Give one brain tendrils that reach them all.**

**Tendriq · One brain. Many executors.**

---

> ⚠️ **这是远程执行软件，不是沙箱 / Remote execution software, not a sandbox.** 子端以运行它的用户身份（Windows 服务模式下是 `LocalSystem`）执行命令、读写授权目录。The executor runs commands with its account's privileges (`LocalSystem` in Windows service mode). 安装前请先读 / Read the [威胁模型 / threat model](docs/threat-model.md) before installing.

## 架构

```
        ┌──────────── 母端（唯一大脑）────────────┐
        │ agent（Hermes / Codex / Claude …）      │
        │        │ MCP stdio                    │
        │ tendril-mcp（翻译层，不执行、不缓存）  │
        │        │ HTTP + Bearer 控制令牌        │
        │ 母端服务：设备台账 · 授权 · 任务 · 审计 │
        └───────────────┬────────────────────────┘
                        │ 子端主动建立加密长连接（TLS 证书固定）
        ┌───────────────┼────────────────┐
      Windows          Linux            macOS
    tendril-agent  tendril-agent   tendril-agent
     只执行、只回传事实；不调用模型
```

- 母端默认只监听 `127.0.0.1:8911`，控制接口用控制令牌鉴权（POSIX `0600`；Windows 靠用户目录 ACL）。
- 子端用一次性邀请接入：邀请里带地址、设备 id、密钥、母端证书与指纹，有有效期。
- 每台设备独立状态：`approved`、`enabled`（暂停）、`allow_exec`、`roots`（允许访问的目录）。
- 所有动作写 `audit.jsonl`：谁、何时、对哪台设备、提交了什么。

## 状态

| 部分 | 状态 |
|---|---|
| 母端 | ✅ Linux / macOS / Windows 可运行：设备台账、邀请、授权、暂停、任务、审计、TLS（自签证书需要 openssl；`--tls system` 走公网证书） |
| Go 子端 | ✅ Windows 用户级/服务、Linux 已实机使用；macOS 仅交叉编译通过，未实机验收 |
| Python 参考子端 | ✅ 可用于开发与联调（同样默认关闭命令执行） |
| MCP stdio 桥（11 个工具，设备作为参数） | ✅ 可用 |
| 46 条端到端 + 5 条平台适配 + 5 条部署/投递脚本检查 + Go 单测 | ✅ 通过（CI 在 Linux/macOS/Windows 上跑平台测试与三平台编译） |
| 母端常驻 | ✅ Linux systemd / macOS launchd / Windows 计划任务（`deploy/install-mother-*`） |
| 图形界面 / Hub 扩展面板 | ❌ 不在本仓库；母端已有 HTTP 接口，界面是可选的 |
| 屏幕流、ConPTY、开机自启策略下发 | ❌ 未做 |

## 平台支持

母端和子端都不绑定 Linux：

| | Linux | macOS | Windows |
|---|---|---|---|
| 母端 | ✅ | ✅（CI 平台矩阵） | ✅（CI 平台矩阵；PowerShell 里 `python mother\server.py …`） |
| Go 子端 | ✅ 实机使用 | ✅ 交叉编译 + CI 构建；未实机验收，服务宿主需自行用 launchd | ✅ 作者现网在用用户级/服务安装；公开树构建经 CI |
| 状态目录 | `~/.local/state/tendril`（跟随 `XDG_STATE_HOME`） | `~/Library/Application Support/Tendril` | `%LOCALAPPDATA%\Tendril` |
| 自签证书 | `openssl` | 系统 LibreSSL 或 `brew install openssl@3` | Git for Windows 自带，或安装 OpenSSL |

`TENDRIL_STATE` 可以覆盖状态目录（三平台一致）。macOS 的子端服务化（开机自启）目前需要自己写 launchd plist；Windows 有内置的 `--install-user` / `--install-service`。

## 快速开始

完整步骤（含 Windows 服务、TLS、MCP 配置）见 [docs/quickstart.md](docs/quickstart.md)。

```bash
# 母端（Python 3.12+；自签证书需要 openssl）
# Linux/macOS 用 python3；Windows 在 PowerShell 里用 python
git clone https://github.com/tokced/tendriq.git && cd tendriq
python3 mother/server.py --state ~/.local/state/tendril init-tls \
    --san mother.example --san 192.168.1.10
python3 mother/server.py add-device zen-pc --root /home/me --exec
python3 mother/server.py serve --host 0.0.0.0 --port 8911

# 邀请（一次性、默认 15 分钟）
python3 mother/server.py invite zen-pc --url https://mother.example:8911

# 子端（在目标机器上）
cd agent/go && go build -trimpath -o tendril-agent .
./tendril-agent --invite 'TENDRIL1:…' --root /home/me --allow-exec
```

接进 agent（MCP）：

```json
{
  "mcpServers": {
    "tendril": {
      "command": "python3",
      "args": ["/path/to/tendril/mcp/tendril_mcp.py"],
      "env": {
        "TENDRIL_MOTHER_URL": "https://mother.example:8911",
        "TENDRIL_TOKEN_FILE": "~/.local/state/tendril/control.token",
        "TENDRIL_CA": "~/.config/tendril/mother-cert.pem"
      }
    }
  }
}
```

密钥/证书配置按客户端格式放（Hermes：`config.yaml` 的 `mcp_servers`；Claude/Cursor：各自的 MCP 配置）。

## 安全默认值

- **命令执行默认关闭**：母端每台设备一个 `allow_exec`；子端自己也默认拒绝，需启动时显式 `--allow-exec`。两层都开才执行。
- **文件访问限定在 `roots`**：子端解析真实路径后判定，越界直接拒绝并说明原因。
- **设备状态显式**：`approved` / `enabled` 都必须是显式值；停用和吊销立即影响下一次请求，不靠缓存。
- **邀请一次性、有期限**，内含设备密钥与母端证书指纹；泄露后可在母端 `remove-device` 让旧密钥立即 401。
- **控制令牌 = 母端全部权限**：`0600` 保存，不要放进配置仓库；MCP 桥只从文件读取，不下发给模型。
- **审计**：`state/audit.jsonl` 记录提交、批准、暂停、取消、任务结束；命令文本只留前 200 字符。

## 仓库结构

```
mother/server.py          # 母端：HTTP 控制面 + 子端通道 + 台账 + 审计
agent/go/                 # Go 子端（Windows/Linux/macOS）
agent/tendril_agent.py   # Python 参考子端（开发/联调）
mcp/tendril_mcp.py       # MCP stdio 桥（devices/exec/task/ls/read/write/…）
skill/tendril/SKILL.md   # 给支持 skill 的客户端用的操作手册
deploy/                   # 母端常驻安装脚本 + 子端投递构建（publish-agents.sh）
tests/test_mother.py      # 46 条端到端测试（真进程 + 真 HTTP）
tests/test_platform.py    # 5 条平台适配（状态目录/openssl/IP/证书）
tests/test_deploy_assets.py  # 5 条部署与投递脚本检查
docs/threat-model.md      # 先读这个
docs/quickstart.md
docs/protocol.md
```

## 开发

```bash
python3 -m unittest tests.test_mother -v     # 母端 + 子端端到端
cd agent/go && go test ./...                  # 子端单测
cd agent/go && go build -trimpath -o tendril-agent .
```

## License

[MIT](LICENSE)。子端会在你的设备上执行命令，请先读 [SECURITY.md](SECURITY.md) 与 [威胁模型](docs/threat-model.md)。
