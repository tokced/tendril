# 快速开始

## 0. 前提

母端三平台都能跑；子端按目标机平台构建。

| 角色 | Linux | macOS | Windows |
|---|---|---|---|
| 母端 | Python 3.12+ | Python 3.12+ | Python 3.12+（PowerShell 里 `python mother\server.py`） |
| 自签证书 | 系统 `openssl` | LibreSSL 或 `brew install openssl@3` | Git for Windows 自带，或 `winget install ShiningLight.OpenSSL` |
| 状态目录 | `~/.local/state/tendril` | `~/Library/Application Support/Tendril` | `%LOCALAPPDATA%\Tendril` |
| Go 子端 | 实机可用 | 交叉编译后可用 | 用户级 / 服务安装 |
| Go 子端 | 目标机无需运行时；构建需要 Go 1.26+（交叉编译 Windows/Linux/macOS） |
| Python 子端（可选） | 目标机有 Python 3.10+，用于开发和联调 |
| MCP 客户端 | Hermes / Claude Code / Codex / Cursor 等任意支持 stdio MCP 的客户端 |

状态目录按平台取默认值（见上表），三平台都可用 `TENDRIL_STATE` 覆盖。

## 1. 母端：证书 → 设备 → 启动

```bash
REPO=/path/to/tendril
STATE=~/.local/state/tendril

# 自签证书；SAN 写子端将要连接的地址（DNS 名或 IP），不写则自动带 localhost + 本机 IPv4
python3 "$REPO/mother/server.py" --state "$STATE" init-tls \
  --san mother.example --san 192.168.1.10

# 登记设备：授权目录可重复，--exec 才允许命令执行
python3 "$REPO/mother/server.py" --state "$STATE" add-device zen-pc \
  --root /home/me --root /data --exec

# 启动（有证书就自动走 TLS；默认只监听 127.0.0.1）
python3 "$REPO/mother/server.py" --state "$STATE" serve --host 0.0.0.0 --port 8911
```

- `--host 0.0.0.0` 才会对局域网开放。暴露前先看 [威胁模型](threat-model.md)。
- 控制令牌在 `$STATE/control.token`（0600）；MCP 桥通过它访问母端，**不要**把它发给模型或提交进仓库。
- `add-device` 输出设备密钥；邀请会自动带上，无需手抄。

## 2. 生成邀请（母端运行时）

```bash
python3 "$REPO/mother/server.py" --state "$STATE" invite zen-pc \
  --url https://mother.example:8911
```

输出一条短链接命令（Windows PowerShell / Linux/macOS），有效期默认 900 秒：

```
Windows:  curl.exe -kfsSL https://mother.example:8911/j/xxxxxxxx | Out-String | iex
Linux:    curl -fsSL "https://mother.example:8911/j/xxxxxxxx?os=linux"  | bash -s -- --daemon
macOS:    curl -fsSL "https://mother.example:8911/j/xxxxxxxx?os=macos"  | bash -s -- --daemon
```

短链接由**正在运行的母端**提供，所以先 `serve` 再 `invite`。`-k` 只用于取安装脚本这一步；后续子端连接固定邀请里的证书。

## 3. 子端

### 构建

```bash
cd agent/go
go build -trimpath -o tendril-agent .                                        # 本机（Linux/macOS）
GOOS=windows GOARCH=amd64 go build -trimpath -o tendril-agent.exe .          # Windows
GOOS=darwin  GOARCH=arm64 go build -trimpath -o tendril-agent-darwin .       # macOS (Apple Silicon)
```

内网邀请的三条安装命令分别下载 `agent.exe` / `agent-linux` / `agent-darwin`（放在母端状态目录的 `deliver/`，并附 `.sha256`）。

### 直接运行（Linux/macOS/Windows 命令行）

```bash
./tendril-agent --invite 'TENDRIL1:…' --root /home/me --allow-exec
```

- `--root` 是**本机允许访问的目录**，可重复；越界请求会被拒绝。
- `--allow-exec` 是**本机**授权；母端还必须有 `allow_exec`，两层都开才执行。
- 不加 `--allow-exec` 也能用文件读写，命令执行会返回「本机未授权」。

### Windows 用户级安装（免管理员，登录后在线）

```powershell
.\tendril-agent.exe --install-user --invite 'TENDRIL1:…' --root "$env:USERPROFILE" --allow-exec
.\tendril-agent.exe --service-status
.\tendril-agent.exe --uninstall-user
```

### Windows 服务（开机即在线，需管理员）

```powershell
.\tendril-agent.exe --install-service --invite 'TENDRIL1:…' --root "D:\work" --allow-exec
.\tendril-agent.exe --service-status
.\tendril-agent.exe --uninstall-service
```

服务模式以 `LocalSystem` 运行，看不到映射盘符；路径请用本地绝对路径或 UNC。

## 4. 接进 agent（MCP）

把桥接进程配置给客户端。桥只做 HTTP ⇄ MCP 翻译，不执行、不缓存。

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

- Hermes：写进 `~/.hermes/config.yaml` 的 `mcp_servers`（字段名按当前版本）。
- Claude Code / Cursor：各自的 MCP 配置文件。
- 直连本机母端（`http://127.0.0.1:8911`）时不需要 `TENDRIL_CA`。

配置里**不要**写控制令牌本身；桥从 `TENDRIL_TOKEN_FILE` 读取。

## 5. 验证

```bash
# 母端侧：看设备是否在线、授权状态
curl -s -H "Authorization: Bearer $(cat $STATE/control.token)" \
  http://127.0.0.1:8911/v1/devices | python3 -m json.tool

# 通过 MCP 工具：先 devices，再 exec/task
```

期望结果：设备 `online: true`、`approved: true`、`host_mode`（console/service）、`can_exec` 与你的授权一致。

## 6. 日常操作

| 动作 | 命令 |
|---|---|
| 暂停一台设备（保留台账与授权） | `curl -X POST …/v1/devices/<id>/enable -d '{"enabled": false}'`（带 Bearer） |
| 批准 / 停止 | `…/v1/devices/<id>/approve`、`…/deny` |
| 吊销并删除设备 | `python3 mother/server.py remove-device <id>`（旧密钥立即 401） |
| 看审计 | `tail -f $STATE/audit.jsonl` |
| 取消任务 | `POST /v1/tasks/<task_id>/cancel` |

## 7. 从旧版本升级

0.1 起设备状态是显式的：`approved` 必须是 `true` 才允许连接；旧台账里没有这个字段的设备会被当作**未批准**。

```bash
# 逐台确认后批准（母端 CLI）
python3 mother/server.py --state ~/.local/state/tendril approve <device-id>
```

另外 console 直接运行子端现在也必须加 `--allow-exec` 才允许命令执行；安装成服务/用户级时以安装时写入的配置为准（安装默认关闭）。

## 8. 排错

| 现象 | 先查 |
|---|---|
| 子端启动即退出 | 母端 https 是否给了 `--ca` 或邀请里的证书；`--root` 是否存在 |
| 设备一直 offline | 母端 `ONLINE_WINDOW`（默认 15s）与子端轮询；防火墙/证书 SAN 是否覆盖实际地址 |
| `exec` 返回「未授权」 | 母端 `allow_exec` 与子端 `--allow-exec` 是否**都**开 |
| 读写被拒「不在授权目录内」 | `--root` 是子端本机路径；服务模式看不到映射盘符 |
| 取不到安装脚本 | 短链接只在母端运行时可用；邀请过期需重新 `invite` |
