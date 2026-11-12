#!/usr/bin/env python3
"""Tendril MCP stdio 适配器：把 Tendril 母端的 v1 接口暴露成母端 Hermes 的工具。

母端才是唯一大脑：这个进程只做翻译（MCP ⇄ HTTP），不执行任何东西、不缓存状态。

环境变量：
    TENDRIL_MOTHER_URL   默认 http://127.0.0.1:8911
    TENDRIL_TOKEN_FILE   默认 ~/.local/state/tendril/control.token
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

SERVER = {"name": "tendril", "version": "0.2.0-m1"}
PROTOCOL = "2024-11-05"
MOTHER = os.environ.get("TENDRIL_MOTHER_URL", "http://127.0.0.1:8911").rstrip("/")
TOKEN_FILE = Path(os.environ.get("TENDRIL_TOKEN_FILE",
                                 "~/.local/state/tendril/control.token")).expanduser()
CA_FILE = os.environ.get("TENDRIL_CA", str(Path("~/.config/tendril/mother-ca.pem").expanduser()))

REMOTE_NOTE = (
    "此工具操作的是**远端设备**，不是母端本机。"
    "改母端本机请用内置 read_file / write_file / terminal。"
    "返回里一定有 device 字段，用来确认你操作的是哪台机器。"
)

TOOLS = [
    {
        "name": "devices",
        "description": (
            "列出 Tendril 管理的远端设备：设备 id、系统、执行身份、是否在线、最后通信时间、"
            "授权目录、是否允许命令。" + REMOTE_NOTE + " 操作任何设备前先调用它。"
        ),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "exec",
        "description": (
            "在远端设备上提交一条非交互命令，立即返回 task_id（不等待）。"
            "用 task 工具取结果。command_ok 表示命令退出码为 0；state=succeeded 只表示任务被执行了。"
            + REMOTE_NOTE
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "device": {"type": "string"},
                "command": {"type": "string", "description": "命令文本"},
                "shell": {"type": "string", "enum": ["bash", "powershell", "cmd"], "default": "bash"},
                "cwd": {"type": "string", "description": "工作目录（可选）"},
                "timeout_s": {"type": "integer", "minimum": 1, "maximum": 3600, "default": 120},
            },
            "required": ["device", "command"],
            "additionalProperties": False,
        },
    },
    {
        "name": "task",
        "description": (
            "读取命令任务的当前状态与结果：state(queued/running/succeeded/failed)、exit_code、"
            "command_ok、stdout、stderr、是否被截断、耗时。"
            "输出可能被截断（stdout_truncated/stdout_bytes），需要更多内容时改用设备侧过滤（grep）而不是整份拉回。"
            + REMOTE_NOTE
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"task_id": {"type": "string"}},
            "required": ["task_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "write",
        "description": (
            "写入远端设备上的文件（覆盖式，先写临时文件再原子替换）。"
            "可选 expect_size 防止覆盖你读完之后别人改过的文件；不匹配会被拒绝。"
            "适合文本/小文件；大文件请分块走 HTTP，不要把整份内容塞进对话。" + REMOTE_NOTE
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "device": {"type": "string"},
                "path": {"type": "string"},
                "content": {"type": "string", "description": "文件内容（UTF-8 文本）；传空串可清空文件"},
                "expect_size": {"type": "integer", "description": "可选：期望的当前文件字节数"},
            },
            "required": ["device", "path", "content"],
            "additionalProperties": False,
        },
    },
    {
        "name": "mkdir",
        "description": "在远端设备上新建目录（父目录必须已存在）。" + REMOTE_NOTE,
        "inputSchema": {"type": "object",
                        "properties": {"device": {"type": "string"}, "path": {"type": "string"}},
                        "required": ["device", "path"], "additionalProperties": False},
    },
    {
        "name": "rename",
        "description": "重命名/移动远端设备上的文件或目录（同一授权目录内；目标已存在会被拒绝，不覆盖）。" + REMOTE_NOTE,
        "inputSchema": {"type": "object",
                        "properties": {"device": {"type": "string"},
                                       "from": {"type": "string"}, "to": {"type": "string"}},
                        "required": ["device", "from", "to"], "additionalProperties": False},
    },
    {
        "name": "remove",
        "description": (
            "删除远端设备上的文件或空目录。目录非空时必须显式 recursive=true（会连同内容一起删除）。"
            "不能删除授权根目录本身。" + REMOTE_NOTE
        ),
        "inputSchema": {"type": "object",
                        "properties": {"device": {"type": "string"}, "path": {"type": "string"},
                                       "recursive": {"type": "boolean", "default": False}},
                        "required": ["device", "path"], "additionalProperties": False},
    },
    {
        "name": "pull",
        "description": (
            "把远端设备上的文件拉到母端本机（分块、字节精确、结束时校验大小）。"
            "适合大文件；目标是本机路径，来源受设备授权目录限制。" + REMOTE_NOTE
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "device": {"type": "string"},
                "path": {"type": "string", "description": "远端文件路径"},
                "local_path": {"type": "string", "description": "母端本机保存路径"},
                "overwrite": {"type": "boolean", "default": False},
            },
            "required": ["device", "path", "local_path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "push",
        "description": (
            "把母端本机文件推到远端设备（分块写入、临时文件→原子替换、返回 sha256 校验）。"
            "可选 expect_size 防止覆盖设备上已被改动的同名文件。" + REMOTE_NOTE
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "device": {"type": "string"},
                "local_path": {"type": "string"},
                "path": {"type": "string", "description": "远端目标路径"},
                "expect_size": {"type": "integer", "description": "可选：期望的远端当前大小"},
            },
            "required": ["device", "local_path", "path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "ls",
        "description": "列出远端设备某个目录（仅限已授权目录）。" + REMOTE_NOTE,
        "inputSchema": {
            "type": "object",
            "properties": {"device": {"type": "string"}, "path": {"type": "string"}},
            "required": ["device", "path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "read",
        "description": (
            "分页读取远端设备上的文件。返回 content、size、offset、next_offset、truncated、binary。"
            "默认只读 64 KiB；大文件用 offset 续读，或在设备侧用 exec+grep 过滤，不要逐块拉整份文件。" + REMOTE_NOTE
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "device": {"type": "string"},
                "path": {"type": "string"},
                "offset": {"type": "integer", "minimum": 0, "default": 0},
                "limit": {"type": "integer", "minimum": 1, "maximum": 1048576, "default": 65536},
            },
            "required": ["device", "path"],
            "additionalProperties": False,
        },
    },
]


def log(msg: str) -> None:
    sys.stderr.write(f"[tendril-mcp] {msg}\n")
    sys.stderr.flush()


def token() -> str:
    try:
        text = TOKEN_FILE.read_text().strip()
    except OSError as e:
        raise RuntimeError(f"读不到控制令牌 {TOKEN_FILE}: {e}") from e
    if not text:
        raise RuntimeError(f"控制令牌文件为空：{TOKEN_FILE}")
    return text


_OPENER = None


def opener():
    """https 必须固定母端证书；不提供「跳过校验」的开关。"""
    global _OPENER
    if _OPENER is None:
        if MOTHER.startswith("https://"):
            if not CA_FILE:
                raise RuntimeError("母端是 https，需要设置 TENDRIL_CA 指向母端证书")
            ctx = ssl.create_default_context(cafile=os.path.expanduser(CA_FILE))
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            _OPENER = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        else:
            _OPENER = urllib.request.build_opener()
    return _OPENER


def http(method: str, path: str, body: dict | None = None, timeout: float = 30) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{MOTHER}{path}", data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {token()}")
    try:
        with opener().open(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw) if raw else {}
        except ValueError:
            return e.code, {"error": f"HTTP {e.code}"}
    except urllib.error.URLError as e:
        return 0, {"error": f"母端不可达（{MOTHER}）：{e.reason}"}


TASK_FIELDS = ("state", "exit_code", "command_ok", "timed_out", "cancelled", "stdout", "stderr",
               "stdout_truncated", "stderr_truncated", "stdout_bytes", "stderr_bytes",
               "elapsed_s", "error", "warning")
TERMINAL = ("succeeded", "failed", "cancelled", "interrupted")


def slim(task: dict) -> dict:
    """只留模型需要的字段：任务表里的 payload 回显和时间戳没有意义，还占上下文。"""
    if not isinstance(task, dict):
        return task
    if "result" in task and isinstance(task["result"], dict):
        out = {"state": task.get("state")}
        out.update({k: task["result"][k] for k in TASK_FIELDS if k in task["result"]})
        for k in ("error",):
            if k in task and task[k] and not out.get(k):
                out[k] = task[k]
        return out
    return {k: task[k] for k in ("state", "error", "http_status") if k in task}


def text(payload, is_error: bool = False) -> dict:
    body = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, indent=1)
    return {"content": [{"type": "text", "text": body}], "isError": is_error}


def guard(device: str) -> dict | None:
    code, body = http("GET", "/v1/devices")
    if code != 200:
        return text({"error": body.get("error", "无法读取设备列表"), "http_status": code}, True)
    rows = {d["device"]: d for d in body.get("devices", [])}
    if device not in rows:
        return text({"error": f"未知设备 {device!r}", "available": sorted(rows)}, True)
    return None


def wait_task(task_id: str, timeout_s: float) -> dict:
    """短轮询到终态；超时就把当前状态原样返回，不猜结果。"""
    end = time.time() + timeout_s
    last: dict = {}
    while time.time() < end:
        code, body = http("GET", f"/v1/tasks/{task_id}")
        if code != 200:
            return {"error": body.get("error", "读取任务失败"), "http_status": code}
        last = body
        if body.get("state") in TERMINAL:
            return body
        time.sleep(0.25)
    return last or {"error": "任务未返回"}


def with_retry(fn, attempts: int = 2):
    """只对「设备未在 Ns 内回执」这类瞬时错误重试一次；真实错误立刻返回。"""
    last = None
    for i in range(attempts):
        last = fn()
        blob = json.dumps(last, ensure_ascii=False)
        if "未在" not in blob or "回执" not in blob:
            return last
        time.sleep(0.6 * (i + 1))
    return last


def call(name: str, args: dict) -> dict:
    if name == "devices":
        code, body = http("GET", "/v1/devices")
        if code != 200:
            return text(body, True)
        if not body.get("devices"):
            return text("当前没有已登记的设备（Tendril 母端在线，但设备台账为空）。")
        return text({"devices": body["devices"]})

    device = str(args.get("device") or "")
    bad = guard(device)
    if bad:
        return bad

    if name == "exec":
        payload = {"command": args.get("command"),
                   "timeout_s": int(args.get("timeout_s") or 120)}
        if args.get("shell"):                      # 不指定就交给子端：Windows 默认 powershell，Linux 默认 bash
            payload["shell"] = args["shell"]
        if args.get("cwd"):
            payload["cwd"] = args["cwd"]
        code, body = http("POST", f"/v1/devices/{device}/exec", payload)
        if code != 202:
            return text({"device": device, **body}, True)
        # 短任务直接帮模型等到结果，长任务留 task_id
        task = wait_task(body["task_id"], 20)
        return text({"device": device, "task_id": body["task_id"], **slim(task)})

    if name == "task":
        code, body = http("GET", f"/v1/tasks/{args.get('task_id')}")
        return text(slim(body) if code == 200 else body, code != 200)

    if name == "mkdir":
        code, body = http("POST", f"/v1/devices/{device}/fs/mkdir", {"path": args.get("path")})
        return text({"device": device, **body}, code != 200)

    if name == "rename":
        code, body = http("POST", f"/v1/devices/{device}/fs/rename",
                          {"from": args.get("from"), "to": args.get("to")})
        return text({"device": device, **body}, code != 200)

    if name == "remove":
        code, body = http("POST", f"/v1/devices/{device}/fs/remove",
                          {"path": args.get("path"), "recursive": bool(args.get("recursive"))})
        return text({"device": device, **body}, code != 200)

    if name == "write":
        payload = {"path": args.get("path"), "offset": 0, "final": True,
                   "data_b64": base64.b64encode(str(args.get("content", "")).encode()).decode()}
        if args.get("expect_size") is not None:
            payload["expect_size"] = int(args["expect_size"])
        code, body = http("POST", f"/v1/devices/{device}/fs/write", payload)
        return text({"device": device, **body}, code != 200)

    if name == "pull":
        remote = args.get("path")
        local = args.get("local_path")
        if not remote or not local:
            return text({"error": "path 与 local_path 都必须给出"}, True)
        dest = Path(local).expanduser()
        if dest.exists() and not args.get("overwrite"):
            return text({"error": f"本机已存在 {dest}；要覆盖请传 overwrite=true"}, True)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".tendril-part")
        sha = hashlib.sha256()
        offset = 0
        total = None
        with open(tmp, "wb") as out:
            while True:
                code, body = with_retry(lambda: http("POST", f"/v1/devices/{device}/fs/read",
                                  {"path": remote, "offset": offset, "limit": 1048576, "raw": True}))
                if code != 200:
                    tmp.unlink(missing_ok=True)
                    return text({"error": f"第 {offset} 字节处读取失败：{body.get('error') or code}"}, True)
                total = body.get("size", total)
                if body.get("binary"):
                    blob = base64.b64decode(body.get("content_base64") or "")
                else:
                    # 老版本子端不支持 raw：文本模式退回解码后的内容（UTF-8 往返不改字节）
                    blob = (body.get("content") or "").encode()
                if not blob:
                    break
                out.write(blob)
                sha.update(blob)
                offset += len(blob)
                nxt = body.get("next_offset", offset)
                if nxt <= offset - len(blob) or not body.get("truncated"):
                    break
        if total is not None and offset != total:
            tmp.unlink(missing_ok=True)
            return text({"error": f"长度不符：收到 {offset}，远端声称 {total}"}, True)
        if dest.exists():
            dest.unlink()
        tmp.replace(dest)
        return text({"ok": True, "local_path": str(dest), "size": offset,
                     "sha256": sha.hexdigest(), "remote_path": remote})

    if name == "push":
        remote = args.get("path")
        local = args.get("local_path")
        if not remote or not local:
            return text({"error": "local_path 与 path 都必须给出"}, True)
        src = Path(local).expanduser()
        if not src.is_file():
            return text({"error": f"本机没有这个文件：{src}"}, True)
        data = src.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        chunk = 768 * 1024
        offset = 0
        while offset < len(data) or (not data and offset == 0):
            piece = data[offset:offset + chunk]
            final = offset + len(piece) >= len(data)
            payload = {"path": remote, "offset": offset, "final": final,
                       "data_b64": base64.b64encode(piece).decode()}
            if final:
                payload["hash"] = True
                if args.get("expect_size") is not None:
                    payload["expect_size"] = int(args["expect_size"])
            code, body = with_retry(lambda: http("POST", f"/v1/devices/{device}/fs/write", payload))
            if code != 200:
                return text({"error": f"第 {offset} 字节处写入失败：{body.get('error') or code}"}, True)
            if final:
                if body.get("sha256") and body["sha256"] != sha:
                    return text({"error": "设备侧 sha256 与本机不一致，未完成写入",
                                 "local_sha256": sha, "device_sha256": body.get("sha256")}, True)
                return text({"ok": True, "path": remote, "size": len(data),
                             "sha256": sha, "local_path": str(src)})
            offset += len(piece)
        return text({"error": "写入未完成"}, True)

    if name == "ls":
        code, body = http("POST", f"/v1/devices/{device}/fs/list", {"path": args.get("path")})
        return text({"device": device, **body}, code != 200)

    if name == "read":
        payload = {"path": args.get("path"), "offset": int(args.get("offset") or 0),
                   "limit": int(args.get("limit") or 65536)}
        code, body = http("POST", f"/v1/devices/{device}/fs/read", payload)
        return text({"device": device, **body}, code != 200)

    return text({"error": f"未知工具 {name}"}, True)


def handle(msg: dict):
    method, mid = msg.get("method"), msg.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": PROTOCOL, "capabilities": {"tools": {}}, "serverInfo": SERVER}}
    if method in ("notifications/initialized", "initialized"):
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        if name not in {t["name"] for t in TOOLS}:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": f"unknown tool: {name}"}}
        try:
            result = call(name, params.get("arguments") or {})
        except Exception as e:  # 任何异常都要变成工具结果，不能让适配器崩掉
            result = text({"error": f"{type(e).__name__}: {e}"}, True)
        return {"jsonrpc": "2.0", "id": mid, "result": result}
    if method in ("resources/list", "prompts/list"):
        key = "resources" if method.startswith("resources") else "prompts"
        return {"jsonrpc": "2.0", "id": mid, "result": {key: []}}
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}


def main() -> int:
    log(f"start pid={os.getpid()} mother={MOTHER} token_file={TOKEN_FILE} ca={CA_FILE or '-'}")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            log("ignored non-JSON line")
            continue
        if not isinstance(msg, dict):
            continue
        reply = handle(msg)
        if reply is not None:
            sys.stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    log("stdin closed, exit")
    return 0


if __name__ == "__main__":
    sys.exit(main())
