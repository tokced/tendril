---
name: tendril
description: Use when operating paired devices via Tendril.
version: 1.0.0
author: Tendril contributors
license: MIT
metadata:
  hermes:
    tags: [remote-exec, devices, mcp]
---

# 用 Tendril 操作远端设备

## When to Use

需要通过 MCP 工具 `tendril_*` 在**已配对设备**上读文件、写文件或执行命令时。操作本机请用内置的
`terminal` / `read_file` / `write_file`，不要绕到 Tendril。

## 第一步永远是 devices

调用 `devices`，逐台确认：

| 字段 | 含义 |
|---|---|
| `online` | 最近一次通信在在线窗口内；`false` 时提交会被拒（409），不要重试到死 |
| `approved` | 未批准的设备连不上；需要人在母端批准 |
| `enabled` | `false` 表示被母端暂停；先启用再操作 |
| `allow_exec` | 母端是否允许命令；子端还要本机 `--allow-exec`，两层都开才会执行 |
| `roots` | 子端允许访问的目录；越界会被拒，不是权限不足 |
| `host_mode` | `console` / `user` / `service`；决定它能看到哪些路径（服务模式看不到映射盘符） |

**没有设备 id 就不要动作。** 不要猜设备名、不要把 `localhost` 当远端。

## 工具与用法

| 工具 | 用法要点 |
|---|---|
| `devices` | 先调；结果里带 `device` 字段，确认操作对象 |
| `exec` | 提交后立即返回 `task_id`，用 `task` 轮询。`state=succeeded` 只代表跑完了，`command_ok` 才是退出码 0 |
| `task` | 看 `stdout`/`stderr`/`exit_code`/`truncated`；被截断就去设备侧过滤，不要把整份日志拉回来 |
| `ls` / `read` | `read` 有 `offset`/`limit`，返回 `next_offset` 与 `truncated`；大文件循环读，每次只取需要的窗口 |
| `write` | 分块写；覆盖前先 `read` 确认目标，改代码先 `ls` 看目录 |
| `mkdir` / `rename` / `remove` | 破坏性操作；`remove` 前必须确认路径与设备 |
| `pull` / `push` | 大文件用它们，不要用 `read` 循环拉整文件 |

## 红线

1. **写文件、删除、执行命令前，先说清「哪台设备 + 哪个路径 + 做什么」，等用户确认。** 只读操作可以连续做。
2. `allow_exec=false` 的设备不要尝试绕过（不要改用写脚本再 `exec`、不要通过计划任务间接执行）。
3. 不把控制令牌、设备密钥、邀请串放进命令、文件或回复里。
4. 不在远端跑交互式/常驻命令（`vim`、`top`、`npm run dev`）；需要长任务是提交一次命令并轮询，或用设备侧的后台机制。
5. 命令里不拼接未转义的用户输入；不要把整段 shell 交给远端拼。
6. 设备侧的输出可能含敏感信息；只回传必要片段，不整份贴进对话。

## 失败语义（按这个区分，不要一律报「权限不足」）

| 返回 | 含义 | 怎么办 |
|---|---|---|
| `403 设备尚未被母端批准` | 母端未批准 | 让用户在母端批准；不要重试 |
| `403 设备已被母端暂停` | `enabled=false` | 让用户启用 |
| `403 此设备未授权命令执行` | 母端 `allow_exec` 关闭 | 说明只做文件操作，或让用户授权 |
| `409 设备离线` | 超出在线窗口 | 检查设备是否开机/在线；不要立刻重发 |
| `本机未授权命令执行` | 子端没有 `--allow-exec` | 只能做文件操作；需要用户在设备本机授权 |
| `路径不在授权目录内` | `roots` 限制 | 换路径或让用户调整 `--root`；不是「文件不存在」 |
| `超时` / `cancelled` | 任务被取消或超时 | 报告已发生的部分结果；重发前确认副作用 |

## 示例

```
devices → 选 zen-pc（online, approved, allow_exec, roots=[/home/me]）
exec(device="zen-pc", command="grep -n 'ERROR' /home/me/app.log | tail -20")
task(task_id=…) → command_ok=true, stdout=…
read(device="zen-pc", path="/home/me/app.conf", offset=0, limit=4096)
```

修改文件：

```
read → 确认原内容与路径
write(device="zen-pc", path="/home/me/app.conf", content=…)
exec(device="zen-pc", command="python3 -m json.tool /home/me/app.conf")
```

删除/覆盖类操作必须先让用户确认设备与路径。
