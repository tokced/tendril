# 协议

母端提供两个面：**控制面**（人/agent 用）和**设备通道**（子端用）。所有请求与响应都是 JSON。

## 1. 控制面

鉴权：`Authorization: Bearer <control.token>`。默认只监听 `127.0.0.1`。

| 方法 | 路径 | 作用 |
|---|---|---|
| GET | `/v1/health` | 健康检查（无鉴权） |
| GET | `/v1/devices` | 设备列表：id、name、os、identity、host_mode、online、last_seen、roots、allow_exec、approved、enabled |
| GET | `/v1/tasks` | 任务列表（可按设备过滤） |
| GET | `/v1/tasks/{id}` | 任务状态与结果 |
| POST | `/v1/tasks/{id}/cancel` | 取消任务（子端执行期间轮询到 `__cancel__` 会终止进程组） |
| GET | `/v1/audit` | 审计事件（jsonl 的读接口） |
| POST | `/v1/devices/{id}/exec` | 提交命令：`{command, shell?: bash\|powershell\|cmd, cwd?, timeout_s?}` → `202 {task_id}` |
| POST | `/v1/devices/{id}/fs/list` | 列目录 |
| POST | `/v1/devices/{id}/fs/read` | 读文件（分块 + 游标） |
| POST | `/v1/devices/{id}/fs/write` | 写文件（分块） |
| POST | `/v1/devices/{id}/fs/mkdir` / `rename` / `remove` | 目录与文件操作 |
| POST | `/v1/devices/{id}/approve` / `deny` | 设备批准状态 |
| POST | `/v1/devices/{id}/enable` | 暂停/恢复：`{enabled: bool}`；暂停后子端拿不到任务，台账保留 |

公共约束：

- 设备不存在 → `404`；未批准 → `403`；已暂停 → `409`；离线（超出在线窗口）→ `409` 且**不下发**。
- `exec` 要求母端台账 `allow_exec=true`，否则 `403`；命令长度上限 `TENDRIL_MAX_COMMAND`（默认 64 KiB），超时 1–3600 秒。
- 输出有上限：`EXEC_CAP`（默认 256 KiB）、文件读分块（`cap` + `offset`/`next_offset`，`truncated` 标明还有后续）。
- 所有提交、批准、暂停、取消、执行结束都写 `audit.jsonl`；命令文本只记录前 200 字符。

## 2. 设备通道（子端 → 母端）

子端主动连接，不需要入站端口。HTTP + TLS（固定证书或系统根）。

| 方法 | 路径 | 作用 |
|---|---|---|
| POST | `/agent/poll` | 长轮询取任务；请求体可带 `{os, identity, roots, host_mode, can_exec}` 作为心跳信息；无任务时按 `POLL_WAIT` 挂起 |
| POST | `/agent/ack` | 确认收到任务（母端据此区分「没送到」与「在跑」） |
| POST | `/agent/result` | 回传任务结果：`{task_id, ok, ...}`；执行期间可回传进度 |
| GET | `/j/{sid}?os=windows\|linux\|macos` | 一次性安装脚本（短邀请；缺省 windows） |
| GET | `/files/{name}` | 固定文件投递（子端二进制等） |

鉴权：`X-Tendril-Device-Id` + 设备密钥（`Authorization: Bearer <secret>`）。设备未批准 `403`，已暂停 `403`，未知设备 `401`。

任务载荷：

```json
{"kind": "exec", "payload": {"command": "...", "shell": "bash|powershell|cmd|", "timeout_s": 120, "cwd": null, "cap": 262144}}
{"kind": "fs.read", "payload": {"path": "...", "offset": 0, "limit": 262144}}
{"kind": "fs.write", "payload": {"path": "...", "content_base64": "...", "offset": 0}}
```

任务状态：`queued → running → succeeded | failed | cancelled`。`state=succeeded` 只表示子端执行完了；`command_ok` 才表示命令退出码为 0。

## 3. 邀请

`TENDRIL1:<base64url(json)>`，JSON 字段：

| 字段 | 说明 |
|---|---|
| `v` | 版本，当前 1 |
| `url` | 子端要连的母端地址（https） |
| `device` / `secret` | 设备 id 与密钥 |
| `exp` | 到期时间（unix 秒），默认 900 秒 |
| `cert` / `fp` | 自签证书 PEM 与 DER sha256 指纹；子端固定校验 |
| `tls: "system"` | 公网 CA 模式（Tailscale Funnel / 反向代理），不用自签证书 |
| `addrs` | 可选：明确入口 IP 列表，绕过 DNS 多节点里不可达的地址 |

邀请一次性使用：短链 sid 由母端内存 + `pending-invites.json` 管理，重复取脚本不会延长期限。

## 4. MCP 桥

`mcp/tendril_mcp.py` 把控制面暴露成 11 个工具，**设备作为参数**（不按设备拆多个 server）：

| 工具 | 说明 |
|---|---|
| `devices` | 列设备与授权状态；做任何事之前先调它 |
| `exec` | 提交命令，立即返回 `task_id` |
| `task` | 读任务状态/结果：`exit_code`、`command_ok`、stdout/stderr、截断标记 |
| `ls` / `read` | 目录与文件读取（分块 + 游标） |
| `write` / `mkdir` / `rename` / `remove` | 文件写与目录操作 |
| `pull` / `push` | 与大文件传输相关的分块读取/写入封装 |

桥是无状态翻译：不缓存、不执行、不保存设备列表；控制令牌只从 `TENDRIL_TOKEN_FILE` 读。
