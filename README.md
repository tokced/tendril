# Tendril

**给 agent 装上的手和眼睛。** 一个大脑在母端（模型、上下文、记忆），多台异构设备只负责执行并回传事实——子端不思考、不保存上下文、不自主规划。

Tendril gives one agent hands on many machines. The brain (model, context, memory) stays on the mother host; each paired device runs a small executor that only does what it is told and reports facts back.

> ⚠️ **这是远程执行软件，不是沙箱。** 子端以运行它的用户身份（Windows 服务模式下是 `LocalSystem`）执行命令、读写授权目录。安装前请先读 [威胁模型](docs/threat-model.md)。只在你拥有或明确获授权的设备上部署。

## 它解决什么

- 一个 agent 需要摸到多台机器：家里的 Windows、NAS、Linux 小主机。
- 不想给每台机器各配一个 MCP server（3 台 × 40 工具 = 工具列表和 token 成本都会失控）。
- 需要「按设备授权 / 撤销 / 暂停 / 审计」，而不是把设备写死在配置里。

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
| 母端 | ✅ | ✅ | ✅（PowerShell 里 `python mother\server.py …`） |
| Go 子端 | ✅ 实机使用 | ✅ 交叉编译；服务宿主需自行用 launchd/launchctl | ✅ 用户级 / 服务两种安装 |
| 状态目录 | `~/.local/state/tendril`（跟随 `XDG_STATE_HOME`） | `~/Library/Application Support/Tendril` | `%LOCALAPPDATA%\Tendril` |
| 自签证书 | `openssl` | 系统 LibreSSL 或 `brew install openssl@3` | Git for Windows 自带，或安装 OpenSSL |

`TENDRIL_STATE` 可以覆盖状态目录（三平台一致）。macOS 的子端服务化（开机自启）目前需要自己写 launchd plist；Windows 有内置的 `--install-user` / `--install-service`。

## 快速开始

完整步骤（含 Windows 服务、TLS、MCP 配置）见 [docs/quickstart.md](docs/quickstart.md)。

```bash
# 母端（Python 3.12+；自签证书需要 openssl）
# Linux/macOS 用 python3；Windows 在 PowerShell 里用 python
git clone <repo> && cd tendril
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
