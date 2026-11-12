"""Tendril 子端（Python 参考实现）。

职责只有三件：连母端、执行、回传事实。不调用模型、不保存上下文、不自主规划。

M2 增补：
- TLS：母端用自签证书时，子端必须用 `--ca mother-cert.pem` 固定这张证书并做主机名校验，
  不接受「跳过校验」。母端是 https 而没给 --ca 就直接拒绝启动。
- 取消：执行期间主循环继续短轮询，收到 `__cancel__` 就终止整棵进程组，并把取消回执发回去。

用法：
    python3 agent/tendril_agent.py --mother https://mother.example:8911 \
        --device zen-pc --secret <secret> --ca run/state/mother-cert.pem --root /data
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import shutil
import platform
import signal
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

POLL_IDLE = 25.0      # 空闲时的长轮询窗口
POLL_BUSY = 1.0       # 执行中要频繁回来收取消
MAX_LIST = 500


def log(msg: str) -> None:
    sys.stderr.write(f"[tendril-agent] {msg}\n")
    sys.stderr.flush()


class Confined:
    """把路径限制在允许目录内。

    realpath + commonpath 是字符串级判断，不是句柄级；Windows 上真正的抗穿越要靠
    重解析点/句柄 API（Go 版用 os.Root）。这里明说不等价。
    """

    def __init__(self, roots: list[str]):
        self.roots = [Path(r).resolve() for r in roots]

    def resolve(self, raw: str) -> Path:
        if not raw or "\x00" in raw:
            raise ValueError("路径为空或含空字符")
        if not self.roots:
            raise PermissionError("此设备未授权任何目录")
        p = Path(raw).expanduser()
        if not p.is_absolute():
            raise ValueError("只接受绝对路径")
        target = p.resolve(strict=False)
        for root in self.roots:
            if target == root or root in target.parents:
                return target
        raise PermissionError(f"路径不在授权目录内：{raw}（授权：{self.roots}）")


def run_command(payload: dict, cancel: threading.Event) -> dict:
    """执行一条非交互命令。整棵进程树一起结束，避免只杀掉外壳。"""
    command = payload["command"]
    shell = payload.get("shell") or "bash"      # 空 = 平台默认（POSIX 就是 bash）
    timeout = float(payload.get("timeout_s", 120))
    cap = int(payload.get("cap", 256 * 1024))
    cwd = payload.get("cwd") or None
    if shell not in ("bash", ""):
        return {"ok": False, "error": f"POSIX 子端只支持 bash，收到 {shell}"}

    started = time.time()
    proc = subprocess.Popen(
        ["bash", "-c", command],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL, cwd=cwd, start_new_session=True,
    )
    timed_out = cancelled = False
    deadline = started + timeout
    while True:
        if cancel.is_set():
            cancelled = True
            break
        if time.time() >= deadline:
            timed_out = True
            break
        try:
            proc.wait(timeout=0.2)
            break
        except subprocess.TimeoutExpired:
            continue
    if cancelled or timed_out:
        try:
            if hasattr(os, "killpg"):
                os.killpg(proc.pid, signal.SIGKILL)
            else:  # Windows 上没有进程组：只能杀直接子进程
                proc.kill()
        except (ProcessLookupError, OSError):
            pass
    out, err = proc.communicate()
    out, err = out or b"", err or b""

    def decode(data: bytes) -> tuple[str, bool]:
        return data[:cap].decode("utf-8", "replace"), len(data) > cap

    text_out, cut_out = decode(out)
    text_err, cut_err = decode(err)
    return {
        # ok 表示「这次任务是否被真实执行」，不表示命令本身成功；
        # 命令成败在 exit_code / command_ok 里，两者不能混成一个字段。
        "ok": not timed_out and not cancelled,
        "command_ok": proc.returncode == 0 and not timed_out and not cancelled,
        "exit_code": proc.returncode,
        "timed_out": timed_out,
        "cancelled": cancelled,
        "stdout": text_out,
        "stderr": text_err,
        "stdout_truncated": cut_out,
        "stderr_truncated": cut_err,
        "stdout_bytes": len(out),
        "stderr_bytes": len(err),
        "elapsed_s": round(time.time() - started, 3),
        "error": "已按取消请求终止进程组" if cancelled else (
            f"超时 {timeout}s，已终止进程组" if timed_out else None),
    }


_write_locks: dict[str, threading.Lock] = {}
_write_locks_guard = threading.Lock()


def _lock_for(path: str) -> threading.Lock:
    with _write_locks_guard:
        return _write_locks.setdefault(path, threading.Lock())


def fs_mkdir(confined: Confined, payload: dict) -> dict:
    target = confined.resolve(payload["path"])
    if target == target.anchor:
        return {"ok": False, "error": "目标是盘符根目录，不允许创建"}
    try:
        target.mkdir(parents=False, exist_ok=False)
    except FileExistsError:
        return {"ok": False, "error": f"已存在：{target}"}
    except OSError as e:
        return {"ok": False, "error": f"创建目录失败：{e}"}
    return {"ok": True, "path": str(target), "type": "dir"}


def fs_rename(confined: Confined, payload: dict) -> dict:
    src = confined.resolve(payload["from"])
    dst = confined.resolve(payload["to"])
    # resolve() 已经保证两端都在授权目录内
    if dst.exists() or dst.is_symlink():
        return {"ok": False, "error": f"目标已存在，拒绝覆盖：{dst}"}
    try:
        os.rename(src, dst)
    except OSError as e:
        return {"ok": False, "error": f"重命名失败：{e}"}
    return {"ok": True, "path": str(dst), "from": str(src)}


def fs_remove(confined: Confined, payload: dict) -> dict:
    target = confined.resolve(payload["path"])
    if not target.exists() and not target.is_symlink():
        return {"ok": False, "error": f"不存在：{target}"}
    recursive = bool(payload.get("recursive"))
    try:
        if target.is_dir() and not target.is_symlink():
            if recursive:
                shutil.rmtree(target)
            else:
                target.rmdir()   # 非空会失败，符合「必须显式递归」
        else:
            target.unlink()
    except OSError as e:
        return {"ok": False, "error": f"删除失败（非空目录需显式 recursive）：{e}"}
    return {"ok": True, "path": str(target), "type": "dir" if target.is_dir() else "file"}


def fs_write(confined: Confined, payload: dict) -> dict:
    """分块写入：临时文件 → 校验 → 原子替换；版本不符就拒绝覆盖。"""
    target = confined.resolve(payload["path"])
    offset = int(payload.get("offset", 0))
    if offset < 0:
        return {"ok": False, "error": "offset 不能为负"}
    try:
        raw = base64.b64decode(payload.get("data_b64") or "", validate=True)
    except Exception:
        return {"ok": False, "error": "data_b64 不是合法 base64"}
    final = bool(payload.get("final"))
    tmp = target.with_name(target.name + ".tendril-part")

    with _lock_for(str(target)):
        mode = "wb" if offset == 0 else "r+b"
        if offset > 0 and not tmp.exists():
            return {"ok": False, "error": "缺少前置分块（临时文件不存在）"}
        try:
            with open(tmp, mode) as f:
                f.seek(offset)
                f.write(raw)
                if not final:
                    return {"ok": True, "path": str(target), "offset": offset,
                            "next_offset": offset + len(raw)}
                f.flush()
                os.fsync(f.fileno())
                size = os.fstat(f.fileno()).st_size
        except OSError as e:
            tmp.unlink(missing_ok=True)
            return {"ok": False, "error": f"写入失败：{e}"}

        want = offset + len(raw)
        if size != want:
            tmp.unlink(missing_ok=True)
            return {"ok": False, "error": f"收到 {size} 字节，期望 {want}：分块缺失或乱序"}

        expect_size = payload.get("expect_size")
        expect_mtime = payload.get("expect_mtime")
        if (expect_size is not None or expect_mtime is not None) and target.exists():
            st = target.stat()
            if expect_size is not None and st.st_size != expect_size:
                tmp.unlink(missing_ok=True)
                return {"ok": False, "error": f"目标文件已变化（大小 {st.st_size}，期望 {expect_size}），拒绝覆盖"}
            if expect_mtime is not None and int(st.st_mtime) != expect_mtime:
                tmp.unlink(missing_ok=True)
                return {"ok": False, "error": "目标文件修改时间已变化，拒绝覆盖"}

        digest = None
        if payload.get("hash"):
            h = hashlib.sha256()
            with open(tmp, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            digest = h.hexdigest()
        try:
            os.replace(tmp, target)
        except OSError as e:
            tmp.unlink(missing_ok=True)
            return {"ok": False, "error": f"替换目标文件失败：{e}"}
        out = {"ok": True, "path": str(target), "size": want, "offset": offset, "next_offset": want}
        if digest:
            out["sha256"] = digest
        return out


def fs_list(confined: Confined, payload: dict) -> dict:
    target = confined.resolve(payload["path"])
    if not target.exists():
        return {"ok": False, "error": "路径不存在"}
    if not target.is_dir():
        return {"ok": False, "error": "不是目录"}
    entries = []
    with os.scandir(target) as it:
        for entry in it:
            if len(entries) >= MAX_LIST:
                break
            try:
                st = entry.stat(follow_symlinks=False)
                entries.append({
                    "name": entry.name,
                    "type": "dir" if entry.is_dir(follow_symlinks=False) else "file",
                    "size": st.st_size,
                    "mtime": int(st.st_mtime),
                    "symlink": entry.is_symlink(),
                })
            except OSError:
                continue
    entries.sort(key=lambda e: (e["type"] != "dir", e["name"].lower()))
    return {"ok": True, "path": str(target), "entries": entries, "truncated": len(entries) >= MAX_LIST}


def fs_read(confined: Confined, payload: dict) -> dict:
    target = confined.resolve(payload["path"])
    offset = int(payload.get("offset", 0))
    limit = int(payload.get("limit", 65536))
    if not target.is_file():
        return {"ok": False, "error": "不是文件或不存在"}
    size = target.stat().st_size
    with target.open("rb") as f:
        f.seek(min(offset, size))
        chunk = f.read(limit)
    next_offset = min(offset, size) + len(chunk)
    bom = chunk[:3] == b"\xef\xbb\xbf"
    if bom:
        chunk = chunk[3:]
    # raw=true 时强制 base64：文件搬运需要字节精确，不能被文本解码改写
    raw_mode = bool(payload.get("raw"))
    # 同理：按文件头判定，否则小块读取会把二进制当文本返回。
    # UTF-16 文本天然含 NUL，有 BOM 就按文本处理（Windows 的 ini/reg/日志常见）。
    probe = b""
    try:
        with target.open("rb") as pf:
            probe = pf.read(8192)
    except OSError:
        probe = chunk[:8192]
    utf16 = probe[:2] in (b"\xff\xfe", b"\xfe\xff")
    binary = raw_mode or (not utf16 and b"\x00" in probe)
    body: dict = {
        "ok": True, "path": str(target), "size": size, "offset": offset,
        "next_offset": next_offset, "truncated": next_offset < size, "binary": binary,
        "encoding": None if binary else ("utf-8-sig" if bom else ("utf-16" if utf16 else "utf-8")),
    }
    if binary:
        body["content_base64"] = base64.b64encode(chunk).decode()
    elif utf16:
        raw = chunk[2:] if (offset == 0 and chunk[:2] in (b"\xff\xfe", b"\xfe\xff")) else chunk
        codec = "utf-16-le" if probe[:2] == b"\xff\xfe" else "utf-16-be"
        body["content"] = raw.decode(codec, "replace")
    else:
        body["content"] = chunk.decode("utf-8", "replace")
    return body


def handle(confined: Confined, item: dict, cancel: threading.Event, allow_exec: bool = False) -> dict:
    kind = item.get("kind")
    payload = item.get("payload") or {}
    try:
        if kind == "exec":
            if not allow_exec:
                return {"ok": False, "error": "本机未授权命令执行（启动时未加 --allow-exec）"}
            return run_command(payload, cancel)
        if kind == "fs.list":
            return fs_list(confined, payload)
        if kind == "fs.mkdir":
            return fs_mkdir(confined, payload)
        if kind == "fs.rename":
            return fs_rename(confined, payload)
        if kind == "fs.remove":
            return fs_remove(confined, payload)
        if kind == "fs.write":
            return fs_write(confined, payload)
        if kind == "fs.read":
            return fs_read(confined, payload)
        return {"ok": False, "error": f"未知任务类型 {kind}"}
    except (ValueError, PermissionError, OSError) as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


class Client:
    """所有 HTTP 出口集中在这里：TLS 固定校验 + 网络层兜底捕获。"""

    def __init__(self, mother: str, device: str, secret: str, ca: str | None):
        self.mother = mother.rstrip("/")
        self.headers = {"X-Tendril-Device-Id": device, "X-Tendril-Device-Key": secret}
        self.opener = urllib.request.build_opener()
        if self.mother.startswith("https://"):
            if not ca:
                raise SystemExit("母端是 https，必须用 --ca 指定母端证书（固定校验，不允许跳过）")
            if "BEGIN CERTIFICATE" in ca:      # 邀请里直接带的 PEM，不落盘
                ctx = ssl.create_default_context()
                ctx.load_verify_locations(cadata=ca)
            else:
                ctx = ssl.create_default_context(cafile=os.path.expanduser(ca))
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

    def post(self, path: str, body: dict | None, timeout: float) -> tuple[int, dict]:
        raw = json.dumps(body or {}).encode()
        req = urllib.request.Request(self.mother + path, data=raw, method="POST")
        req.add_header("Content-Type", "application/json")
        for k, v in self.headers.items():
            req.add_header(k, v)
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                data = resp.read()
                return resp.status, (json.loads(data) if data else {})
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except Exception:
                return e.code, {}
        except urllib.error.URLError as e:
            # 母端重启/网络中断都会走到这里：进程必须活着退避重连，不能崩
            log(f"连接失败：{getattr(e, 'reason', e)}")
            return 0, {}
        except Exception as e:  # 含 http.client.RemoteDisconnected / 超时中断：常驻进程不能被一次断链打死
            log(f"请求异常：{type(e).__name__}: {e}")
            return 0, {}


def parse_invite(text: str) -> dict:
    """解析 TENDRIL1:<base64> 邀请，校验到期与证书指纹。"""
    raw = text.strip()
    if raw.startswith("TENDRIL1:"):
        raw = raw[len("TENDRIL1:"):]
    elif Path(raw).is_file():
        raw = Path(raw).read_text().strip()
        if raw.startswith("TENDRIL1:"):
            raw = raw[len("TENDRIL1:"):]
    padded = raw + "=" * (-len(raw) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, TypeError) as e:
        raise SystemExit(f"邀请格式无效：{e}") from e
    for key in ("url", "device", "secret", "cert", "fp"):
        if not payload.get(key):
            raise SystemExit(f"邀请缺少字段 {key}")
    if int(payload.get("exp", 0)) < int(time.time()):
        raise SystemExit("邀请已过期，请在母端重新生成")
    der = ssl.PEM_cert_to_DER_cert(payload["cert"])
    if hashlib.sha256(der).hexdigest() != payload["fp"]:
        raise SystemExit("邀请里的证书与指纹不符，拒绝使用")
    return payload


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="tendril-agent")
    ap.add_argument("--invite", help="TENDRIL1:... 邀请串或包含它的文件")
    ap.add_argument("--mother")
    ap.add_argument("--device")
    ap.add_argument("--secret")
    ap.add_argument("--root", action="append", default=[], help="允许访问的目录，可重复")
    ap.add_argument("--ca", default=None, help="母端证书路径（https 必填，固定校验）")
    ap.add_argument("--allow-exec", action="store_true",
                    help="在本机授权命令执行（默认关闭，等同本地确认）")
    args = ap.parse_args(argv)

    if args.invite:
        inv = parse_invite(args.invite)
        args.mother, args.device, args.secret = inv["url"], inv["device"], inv["secret"]
        if not args.ca:
            args.ca = inv["cert"]            # 证书从邀请里来，不需要单独文件
        log(f"使用邀请：设备 {args.device} → {args.mother}")
    elif not (args.mother and args.device and args.secret):
        ap.error("要么给 --invite，要么同时给 --mother/--device/--secret")

    client = Client(args.mother, args.device, args.secret, args.ca)
    confined = Confined(args.root)
    info = {"os": f"{platform.system()} {platform.release()} {platform.machine()}",
            "identity": getpass.getuser(),
            # 授权根以子端为准：母端据此显示真实目录，否则界面会去浏览一个子端不认的路径
            "roots": "|".join(str(r) for r in confined.roots)}
    log(f"连接 {args.mother} 设备 {args.device} 身份 {info['identity']} 授权目录 {confined.roots}")

    running: dict[str, threading.Event] = {}
    lock = threading.Lock()

    def worker(task: dict, cancel: threading.Event) -> None:
        # 先确认收到再执行：母端靠它区分「没送到」与「在跑」
        code, _ = client.post("/agent/ack", {"task_id": task["task_id"]}, 10)
        if code != 200:
            log(f"ack 失败 HTTP {code}，继续执行")
        try:
            result = handle(confined, task, cancel, args.allow_exec)
        finally:
            with lock:
                running.pop(task["task_id"], None)
        log(f"任务 {task['task_id']} ({task.get('kind')}) ok={result.get('ok')}")
        client.post("/agent/result", {"task_id": task["task_id"], "result": result}, 30)

    backoff = 1.0
    while True:
        with lock:
            busy = bool(running)
        wait = POLL_BUSY if busy else POLL_IDLE
        code, item = client.post(f"/agent/poll?wait={wait}", info, timeout=wait + 25)
        if code == 204:
            backoff = 1.0
            continue
        if code == 200 and item.get("task_id"):
            backoff = 1.0
            if item.get("kind") == "__cancel__":
                with lock:
                    ev = running.get(item["task_id"])
                if ev:
                    log(f"收到取消 {item['task_id']}")
                    ev.set()
                continue
            cancel = threading.Event()
            with lock:
                running[item["task_id"]] = cancel
            threading.Thread(target=worker, args=(item, cancel), daemon=True).start()
            continue
        if code == 403:
            if payload.get("paused"):
                log("母端已暂停本设备，30 秒后再试")
                time.sleep(30.0)
                backoff = 1.0
                continue
            log("母端尚未批准此设备，稍后自动重试")
        else:
            log(f"poll 失败 HTTP {code}，{backoff:.0f}s 后重试")
        time.sleep(backoff)
        backoff = min(backoff * 2, 30.0)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(0)
