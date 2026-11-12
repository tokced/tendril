"""Tendril 母端（M1）：设备台账、任务通道、受限文件访问、审计。

只用标准库。传输是长轮询；M2 换 WSS 时 `v1` 语义保持不变，只换通道实现。

设计边界（对应规划 §1、§7）：
- 唯一约束来源是设备侧的上报与授权；母端不推断设备状态。在线 = 最近一次 poll 在窗口内。
- 命令异步：提交返回 task_id，输出按游标读。文件操作同步等待（有上限）。
- 结果未知就是未知：任务只有真的收到子端回执才是 succeeded/failed。

启动：
    python3 mother/server.py serve --port 8901
加设备（打印一次性密钥）：
    python3 mother/server.py add-device zen-sim --root /tmp/tendril-demo --exec
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

def default_state() -> Path:
    """各平台的用户级状态目录；TENDRIL_STATE 始终优先。"""
    env = os.environ.get("TENDRIL_STATE")
    if env:
        return Path(env)
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "Tendril"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Tendril"
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "tendril"


def find_openssl() -> str | None:
    """找 openssl：PATH 里没有时，看常见安装位置（Git for Windows / Homebrew）。"""
    found = shutil.which("openssl")
    if found:
        return found
    candidates: list[Path] = []
    if os.name == "nt":
        for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
            if base:
                candidates += [Path(base) / "Git" / "usr" / "bin" / "openssl.exe",
                               Path(base) / "OpenSSL-Win64" / "bin" / "openssl.exe",
                               Path(base) / "OpenSSL-Win32" / "bin" / "openssl.exe"]
    elif sys.platform == "darwin":
        candidates += [Path("/opt/homebrew/opt/openssl@3/bin/openssl"),
                       Path("/usr/local/opt/openssl@3/bin/openssl")]
    for c in candidates:
        if c.is_file():
            return str(c)
    return None


def local_ipv4s() -> list[str]:
    """本机非回环 IPv4（用于 init-tls 默认 SAN）；不依赖 hostname -I。"""
    ips: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))   # 不发包，只让内核选出口地址
            ips.add(s.getsockname()[0])
        finally:
            s.close()
    except OSError:
        pass
    return sorted(ip for ip in ips if not ip.startswith("127."))[:2]


def private_file(path: Path) -> None:
    """尽力收紧权限：POSIX 用 0600；Windows 上 chmod 只影响只读位，靠目录 ACL。"""
    try:
        path.chmod(0o600)
    except OSError:
        pass


STATE = default_state()
DELIVER = Path(os.environ.get("TENDRIL_DELIVER", str(STATE / "deliver")))
POLL_WAIT = float(os.environ.get("TENDRIL_POLL_WAIT", "25"))
ONLINE_WINDOW = float(os.environ.get("TENDRIL_ONLINE_WINDOW", "15"))
EXEC_CAP = int(os.environ.get("TENDRIL_EXEC_CAP", str(256 * 1024)))
FS_WAIT = float(os.environ.get("TENDRIL_FS_WAIT", "15"))
MAX_COMMAND = int(os.environ.get("TENDRIL_MAX_COMMAND", str(64 * 1024)))
MAX_PATH = int(os.environ.get("TENDRIL_MAX_PATH", str(8192)))
MAX_CHUNK_B64 = int(os.environ.get("TENDRIL_MAX_CHUNK_B64", str(1024 * 1024)))
TASK_GRACE = float(os.environ.get("TENDRIL_TASK_GRACE", "30"))
ACK_GRACE = float(os.environ.get("TENDRIL_ACK_GRACE", "6"))


def now() -> float:
    return time.time()


def init_tls(state: Path, sans: list[str]) -> int:
    """生成本机自签证书（Windows/macOS/Linux 通用）。

    用配置文件而不是 -addext：macOS 自带 LibreSSL，不认 -addext。
    子端按「固定这张证书」验证母端，不做全局跳过校验。
    """
    cert, key = state / "mother-cert.pem", state / "mother-key.pem"
    if cert.is_file():
        print(f"证书已存在：{cert}（如需重签先删除它和 {key.name}）", file=sys.stderr)
    else:
        openssl = find_openssl()
        if not openssl:
            print("找不到 openssl。装一个再跑 init-tls：\n"
                  "  Windows: winget install ShiningLight.OpenSSL  或安装 Git for Windows\n"
                  "  macOS:   brew install openssl@3\n"
                  "  Linux:   发行版的 openssl 包\n"
                  "或者用公网证书部署并加 --tls system，跳过自签证书。", file=sys.stderr)
            return 1
        san = ",".join(f"IP:{s}" if s.replace(".", "").isdigit() else f"DNS:{s}" for s in sans)
        cfg = (f"[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n"
               f"[dn]\nCN=tendril-mother\n"
               f"[v3]\nsubjectAltName={san}\n"
               f"basicConstraints=critical,CA:FALSE\n"
               f"keyUsage=critical,digitalSignature,keyEncipherment\n"
               f"extendedKeyUsage=serverAuth\n")
        fd, cfg_path = tempfile.mkstemp(prefix="tendril-tls-", suffix=".cnf")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(cfg)
            cmd = [openssl, "req", "-x509", "-newkey", "ec",
                   "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                   "-keyout", str(key), "-out", str(cert), "-days", "3650",
                   "-config", cfg_path, "-extensions", "v3"]
            done = subprocess.run(cmd, capture_output=True, text=True)
        finally:
            try:
                os.unlink(cfg_path)
            except OSError:
                pass
        if done.returncode != 0:
            print("openssl 生成证书失败：\n" + done.stderr[-2000:], file=sys.stderr)
            return 1
        private_file(key)
        print(f"已生成：{cert}")
    fp = cert_fingerprint(cert.read_text(encoding="utf-8"))
    pretty = ":".join(fp[i:i + 2] for i in range(0, len(fp), 2)).upper()
    print(f"SAN: {', '.join(sans)}")
    print(f"指纹: SHA256 Fingerprint={pretty}")
    print(f"子端需要这张证书（配对时随邀请下发）：{cert}")
    return 0


def cert_fingerprint(pem: str) -> str:
    """证书 DER 的 sha256（与 openssl -fingerprint -sha256 同义，去掉冒号）。"""
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.sha256(der).hexdigest()


def make_invite(store, device: str, url: str, ttl: int, tls: str = "", addrs=None) -> str:
    """一行邀请：地址 + 设备 + 密钥 + 母端证书 + 到期。

    证书随邀请一起走，子端不用另外拷 PEM 文件；指纹用来防「换了证书也照连」。
    """
    dev = store.device(device)
    if not dev:
        raise SystemExit(f"设备 {device} 未登记")
    payload = {
        "v": 1,
        "url": url.rstrip("/"),
        "device": device,
        "secret": dev["secret"],
        "exp": int(now()) + ttl,
    }
    if tls != "system":
        # 只有固定证书模式才需要自签证书；纯公网 CA 部署可以没有这张文件
        cert = store.state / "mother-cert.pem"
        if not cert.is_file():
            raise SystemExit(f"没有母端证书：{cert}（先跑 init-tls）")
        pem = cert.read_text()
        payload["cert"] = pem
        payload["fp"] = cert_fingerprint(pem)
    if addrs:
        # 明确给出入口 IP：DNS 轮询里可能混有不可达的节点（实测 Funnel 三选一），
        # 让子端按这份列表轮换，不靠解析结果抽签。
        payload["addrs"] = [a for a in addrs if a]
    if tls == "system":
        # 公网 CA（Tailscale Funnel / 反向代理）场景：子端用系统根证书，不再固定自签证书。
        payload.pop("cert", None)
        payload["tls"] = "system"
    blob = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    return f"TENDRIL1:{blob}"


def short_invite(store, token: str) -> str:
    """把长邀请换成一个短 id，只把 id 交给人粘贴。

    邀请串 ~300–1200 字符：手抄容易错，粘贴时也常被聊天工具/日志系统当成密钥打码，
    用户拿到的可能是省略版。邀请本体留在母端状态目录，短 id 只作取用凭据。
    """
    file = store.state / "pending-invites.json"
    now_ts = now()
    data = {}
    if file.is_file():
        try:
            data = {k: v for k, v in json.loads(file.read_text()).items() if v.get("exp", 0) > now_ts}
        except ValueError:
            data = {}
    sid = secrets.token_urlsafe(6).replace("-", "x").replace("_", "y")[:8]
    data[sid] = {"token": token, "exp": decode_invite(token)["exp"]}
    if len(data) > 64:  # 只留最近的一批
        for key in sorted(data, key=lambda k: data[k]["exp"])[:len(data) - 64]:
            data.pop(key, None)
    tmp = file.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False))
    tmp.chmod(0o600)
    os.replace(tmp, file)
    return sid


def decode_invite(token: str) -> dict:
    """解析 TENDRIL1: base64 邀请；只做结构校验，不验签名（密钥本身在子端校验）。"""
    raw = token.split(":", 1)[1] if ":" in token else token
    payload = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    for key in ("url", "device", "secret", "exp"):
        if key not in payload:
            raise ValueError(f"邀请缺字段 {key}")
    if payload.get("tls") != "system" and "cert" not in payload:
        raise ValueError("邀请缺字段 cert")
    return payload


# 自举脚本：下载子端 → 校验 sha256 → 按身份安装。子端不需要额外依赖。
PS_TEMPLATE = r"""# Tendril agent - one-line install (no admin, no UAC prompt)
# Trust anchor: the certificate below comes from the invite you pasted.
$ErrorActionPreference = 'Stop'
$url = '{url}'
$invite = '{invite}'
$ca = Join-Path $env:TEMP 'tendril-ca.pem'
$exe = Join-Path $env:TEMP 'tendril-agent.exe'
@'
{cert}
'@ | Set-Content -Path $ca -Encoding ascii
Write-Host "Downloading agent from $url ..."
curl.exe -fsSL --cacert "$ca" -o "$exe" "$url/files/agent.exe"
if ($LASTEXITCODE -ne 0) {{ throw "download failed (exit $LASTEXITCODE)" }}
$want = (curl.exe -fsSL --cacert "$ca" "$url/files/agent.exe.sha256").Trim().Split()[0]
$have = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
if ($have -ne $want.ToLower()) {{ throw "checksum mismatch (want $want, got $have)" }}
Write-Host "Checksum OK: $have"
# Replace an existing install in place: the old process holds its own exe,
# so stop it first or the copy fails with "file in use".
$dir = Join-Path $env:LOCALAPPDATA 'Tendril'
$old = Join-Path $dir 'tendril-agent.exe'
if (Test-Path $old) {{
  Write-Host "Replacing existing install ..."
  & $old --uninstall-user | Out-Null
  for ($i = 0; $i -lt 25 -and (Test-Path $old); $i++) {{ Start-Sleep -Milliseconds 300 }}
  if (Test-Path $old) {{ throw "previous agent still running; uninstall failed" }}
}}
& $exe --install-user --invite $invite --root "$env:USERPROFILE"{extra}
Remove-Item $ca, $exe -Force -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "Ready: online after this user logs on."
if ("{extra}" -eq "") {{
  Write-Host "Command execution is off by default; to grant it, rerun on this machine with --allow-exec."
}} else {{
  Write-Host "Command execution is granted for this device (local confirmation)."
}}
Write-Host "For boot-online without a logged-on user, use an admin PowerShell:"
Write-Host "  tendril-agent.exe --install-service --invite ... --root `"$env:USERPROFILE`""
"""


PS_TEMPLATE_PUBLIC = r"""# Tendril agent - one-line install (public CA mode; picks a reachable entry)
$ErrorActionPreference = 'Stop'
$url = '{url}'
$invite = '{invite}'
$exe = Join-Path $env:TEMP 'tendril-agent.exe'
$hostName = ([uri]$url).Host
$port = if (([uri]$url).Port -gt 0) {{ ([uri]$url).Port }} else {{ 443 }}
$addrs = @({addrs})
# Some entry IPs behind the public name may be unreachable from here; try each.
$good = $null
foreach ($a in $addrs) {{
  if (-not $a) {{ continue }}
  $null = curl.exe -s --max-time 8 --resolve "${{hostName}}:${{port}}:$a" --fail -o NUL "$url/v1/health" 2>$null
  if ($LASTEXITCODE -eq 0) {{ $good = $a; break }}
}}
function Fetch($remote, $dest) {{
  if ($good) {{ curl.exe -fsSL --resolve "${{hostName}}:${{port}}:$good" -o $dest $remote }}
  else {{ curl.exe -fsSL -o $dest $remote }}
  if ($LASTEXITCODE -ne 0) {{ throw "download failed: $remote" }}
}}
if ($good) {{ Write-Host "Using entry $good" }}
Fetch "$url/files/agent.exe" $exe
$shaArgs = @('-fsSL')
if ($good) {{ $shaArgs += @('--resolve', "${{hostName}}:${{port}}:$good") }}
$want = (curl.exe @shaArgs "$url/files/agent.exe.sha256").Trim().Split()[0]
$have = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
if ($have -ne $want.ToLower()) {{ throw "checksum mismatch" }}
Write-Host "Checksum OK: $have"
# Replace an existing install in place: the old process holds its own exe,
# so stop it first or the copy fails with "file in use".
$dir = Join-Path $env:LOCALAPPDATA 'Tendril'
$old = Join-Path $dir 'tendril-agent.exe'
if (Test-Path $old) {{
  Write-Host "Replacing existing install ..."
  & $old --uninstall-user | Out-Null
  for ($i = 0; $i -lt 25 -and (Test-Path $old); $i++) {{ Start-Sleep -Milliseconds 300 }}
  if (Test-Path $old) {{ throw "previous agent still running; uninstall failed" }}
}}
& $exe --install-user --invite $invite --root "$env:USERPROFILE"{extra}
Remove-Item $exe -Force -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "Ready: online after this user logs on."
if ("{extra}" -eq "") {{
  Write-Host "Command execution is off by default; to grant it, rerun on this machine with --allow-exec."
}} else {{
  Write-Host "Command execution is granted for this device (local confirmation)."
}}
"""


SH_TEMPLATE = r"""#!/usr/bin/env bash
# 触手子端一行安装（内网固定证书模式）：下载 → 校验 → 运行
set -euo pipefail
URL='{url}'
INVITE='{invite}'
BIN="$HOME/.local/bin/tendril-agent"
CA="$HOME/.config/tendril/mother-ca.pem"
mkdir -p "$(dirname "$BIN")" "$(dirname "$CA")"
umask 077
cat > "$CA" <<'CERTEOF'
{cert}
CERTEOF

sha() {{ if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{{print $1}}'; else shasum -a 256 "$1" | awk '{{print $1}}'; fi; }}
curl -fsSL --cacert "$CA" "$URL/files/{bin_name}" -o "$BIN.tmp"
WANT=$(curl -fsSL --cacert "$CA" "$URL/files/{bin_name}.sha256" | awk '{{print $1}}')
HAVE=$(sha "$BIN.tmp")
if [ "$WANT" != "$HAVE" ]; then rm -f "$BIN.tmp"; echo "校验和不匹配，已中止" >&2; exit 1; fi
chmod +x "$BIN.tmp"; mv "$BIN.tmp" "$BIN"
echo "校验通过：$HAVE"
if [ "${{1:-}}" = "--daemon" ]; then
  nohup "$BIN" --invite "$INVITE" --ca "$CA" --root "$HOME" >"$HOME/.tendril-agent.log" 2>&1 &
  echo "已后台运行（日志 $HOME/.tendril-agent.log）"
else
  exec "$BIN" --invite "$INVITE" --ca "$CA" --root "$HOME"{extra}
fi
"""


SH_TEMPLATE_PUBLIC = r"""#!/usr/bin/env bash
set -euo pipefail
URL='{url}'
INVITE='{invite}'
ADDRS=({addrs})
HOSTPORT="${{URL#https://}}"
BIN="$HOME/.local/bin/tendril-agent"
mkdir -p "$(dirname "$BIN")"

RESOLVE=()
for a in "${{ADDRS[@]:-}}"; do
  [ -z "$a" ] && continue
  if curl -sf --max-time 8 --resolve "$HOSTPORT:$a" -o /dev/null "$URL/v1/health"; then
    echo "使用入口 $a"; RESOLVE=(--resolve "$HOSTPORT:$a"); break
  fi
done

sha() {{ if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{{print $1}}'; else shasum -a 256 "$1" | awk '{{print $1}}'; fi; }}
curl -fsSL "${{RESOLVE[@]:-}}" "$URL/files/{bin_name}" -o "$BIN.tmp"
WANT=$(curl -fsSL "${{RESOLVE[@]:-}}" "$URL/files/{bin_name}.sha256" | awk '{{print $1}}')
HAVE=$(sha "$BIN.tmp")
if [ "$WANT" != "$HAVE" ]; then rm -f "$BIN.tmp"; echo "校验和不匹配，已中止" >&2; exit 1; fi
chmod +x "$BIN.tmp"; mv "$BIN.tmp" "$BIN"
echo "校验通过：$HAVE"
if [ "${{1:-}}" = "--daemon" ]; then
  nohup "$BIN" --invite "$INVITE" --root "$HOME" --allow-exec >"$HOME/.tendril-agent.log" 2>&1 &
  echo "已后台运行（日志 $HOME/.tendril-agent.log）"
else
  exec "$BIN" --invite "$INVITE" --root "$HOME"{extra}
fi
"""


def maybe_wrap_tls(srv: ThreadingHTTPServer, state: Path, enabled: bool = True) -> bool:
    """有证书就升级成 TLS。返回是否真的启用了加密。"""
    cert, key = state / "mother-cert.pem", state / "mother-key.pem"
    if not (enabled and cert.is_file() and key.is_file()):
        return False
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return True


class RateLimiter:
    """按来源 IP 统计鉴权失败，超阈值就短暂封禁。

    只有把母端暴露到公网时才有意义：局域网里失败通常是配置错，
    公网里是有人在扫。只统计「鉴权失败」，正常请求不受影响。
    """

    def __init__(self, fails: int = 30, window: float = 60.0, ban: float = 120.0):
        self.fails = fails
        self.window = window
        self.ban = ban
        self.hits: dict[str, list[float]] = {}
        self.banned: dict[str, float] = {}
        self.lock = threading.Lock()

    def blocked(self, ip: str) -> float:
        """返回剩余封禁秒数；0 表示没被封。"""
        with self.lock:
            until = self.banned.get(ip)
            if not until:
                return 0.0
            left = until - now()
            if left <= 0:
                self.banned.pop(ip, None)
                return 0.0
            return left

    def hit(self, ip: str) -> None:
        with self.lock:
            t = now()
            items = [x for x in self.hits.get(ip, []) if t - x < self.window]
            items.append(t)
            self.hits[ip] = items
            if len(items) >= self.fails:
                self.banned[ip] = t + self.ban
                self.hits[ip] = []
            if len(self.hits) > 4096:  # 防止被扫时表无限增长
                for key in [k for k, v in self.hits.items() if not v or t - v[-1] > self.window][:2048]:
                    self.hits.pop(key, None)


RATE = RateLimiter(
    fails=int(os.environ.get("TENDRIL_RATE_FAILS", "30")),
    window=float(os.environ.get("TENDRIL_RATE_WINDOW", "60")),
    ban=float(os.environ.get("TENDRIL_RATE_BAN", "120")),
)


class Store:
    """设备台账 + 控制令牌 + 审计。落盘是为了重启后仍在，但运行状态一律以实况为准。"""

    def __init__(self, state: Path):
        self.state = state
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.devices_file = state / "devices.json"
        self.token_file = state / "control.token"
        self.audit_file = state / "audit.jsonl"
        self.lock = threading.Lock()
        self.devices = json.loads(self.devices_file.read_text()) if self.devices_file.is_file() else {}
        self._mtime = self.devices_file.stat().st_mtime if self.devices_file.is_file() else 0.0
        if not self.token_file.is_file():
            self.token_file.write_text(secrets.token_urlsafe(32))
            private_file(self.token_file)
        self.token = self.token_file.read_text().strip()

    def maybe_reload(self) -> None:
        """外部（CLI/界面）改了 devices.json 就让运行中的母端看见。

        只增删设备、刷新授权字段；内存里的运行状态（last_seen 等）不覆盖，
        否则每 30s 落盘后都会被磁盘里的旧值抹掉，在线状态会来回跳。
        """
        if not self.devices_file.is_file():
            return
        mtime = self.devices_file.stat().st_mtime
        if mtime <= self._mtime:
            return
        self._mtime = mtime
        try:
            disk = json.loads(self.devices_file.read_text())
        except ValueError:
            return
        with self.lock:
            for did, dev in disk.items():
                live = self.devices.get(did)
                if live is None:
                    self.devices[did] = dev
                else:
                    for key in ("secret", "roots", "allow_exec", "name", "approved", "enabled"):
                        if key in dev:
                            live[key] = dev[key]
            for did in list(self.devices):
                if did not in disk:
                    del self.devices[did]

    def save(self) -> None:
        with self.lock:
            tmp = self.devices_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.devices, ensure_ascii=False, indent=1))
            private_file(tmp)
            os.replace(tmp, self.devices_file)

    def add(self, did: str, roots: list[str], allow_exec: bool, name: str = "") -> str:
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,47}", did or ""):
            raise SystemExit("设备 id 只能用 1–48 位小写字母、数字、点、下划线或连字符")
        if did in self.devices:
            raise SystemExit(f"设备 {did} 已存在")
        secret = secrets.token_urlsafe(32)
        self.devices[did] = {
            "name": name or did,
            "secret": secret,
            "enabled": True,
            # 显式状态：add-device 是 owner 的授权动作，所以直接 approved；
            # deny / approve 仍可随时翻转，缺字段的设备一律按未批准处理。
            "approved": True,
            "roots": roots,
            "allow_exec": allow_exec,
            "os": "",
            "identity": "",
            "last_seen": 0.0,
        }
        self.save()
        return secret

    def device(self, did: str):
        return self.devices.get(did)

    def audit(self, event: dict) -> None:
        event = {"ts": now(), **event}
        with self.lock:
            with self.audit_file.open("a") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")


class Tasks:
    """任务表。状态只由回执推进，绝不由超时猜测成功。"""

    def __init__(self):
        self.lock = threading.Lock()
        self.items: dict[str, dict] = {}
        self.done = threading.Condition(self.lock)

    KEEP_FINISHED = float(os.environ.get("TENDRIL_TASK_KEEP", "3600"))

    def _prune_locked(self) -> None:
        """已结束的任务保留一段时间供查询，之后清掉；否则任务表在长跑中只涨不降。"""
        if len(self.items) < 512:
            return
        cutoff = now() - self.KEEP_FINISHED
        for tid in [k for k, v in self.items.items()
                    if v["state"] in ("succeeded", "failed", "cancelled", "interrupted")
                    and (v["finished"] or 0) < cutoff]:
            self.items.pop(tid, None)

    def list_recent(self, limit: int = 50, device: str | None = None) -> list[dict]:
        """近期任务摘要（不含 result 大字段），按创建时间倒序。"""
        with self.lock:
            rows = []
            for tid, t in self.items.items():
                if device and t.get("device") != device:
                    continue
                res = t.get("result") or {}
                rows.append({
                    "id": tid, "device": t.get("device"), "kind": t.get("kind"),
                    "state": t.get("state"), "created": t.get("created"),
                    "finished": t.get("finished"),
                    "elapsed_s": res.get("elapsed_s"),
                    "exit_code": res.get("exit_code"),
                    "command_ok": res.get("command_ok"),
                    "cancelled": res.get("cancelled"),
                    "error": (res.get("error") or "")[:200],
                    "summary": (t.get("summary") or "")[:160],
                })
            rows.sort(key=lambda r: r.get("created") or 0, reverse=True)
            return rows[:limit]

    def create(self, device: str, kind: str, payload: dict) -> str:
        tid = secrets.token_hex(8)
        with self.lock:
            self._prune_locked()
            self.items[tid] = {
                "id": tid,
                "device": device,
                "kind": kind,
                "payload": payload,
                "state": "queued",
                "created": now(),
                "started": None,
                "finished": None,
                "result": None,
                "acked": False,
            }
        return tid

    def state_of(self, tid: str) -> str | None:
        with self.lock:
            task = self.items.get(tid)
            return task["state"] if task else None

    @staticmethod
    def _stale_reason(task: dict, device_online: bool, grace: float) -> str | None:
        """返回「结果未知」的原因；None 表示任务还该继续等着。"""
        started = task["started"] or task["created"]
        age = now() - started
        payload = task.get("payload") or {}
        kind = task.get("kind") or ""
        # fs 类任务很快；exec 用调用方给的超时
        limit = float(payload.get("timeout_s") or (60 if kind.startswith("fs") else 120))
        if not task.get("acked") and age > ACK_GRACE:
            # 任务发出去但子端从未确认收到（典型：连接在派发瞬间断了）
            return f"任务下发后 {ACK_GRACE:.0f}s 内未收到子端确认，结果未知（未重放）"
        if age > limit + grace:
            return f"超过 {limit:.0f}s 未收到设备回执，结果未知"
        if not device_online and age > grace:
            return f"设备在结果回传前失联（超过 {grace:.0f}s），结果未知"
        return None

    def reap_if_stale(self, tid: str, device_online: bool, grace: float) -> dict | None:
        """单条惰性回收（查询任务时用）。"""
        with self.lock:
            task = self.items.get(tid)
            if not task:
                return None
            if task["state"] == "running":
                reason = self._stale_reason(task, device_online, grace)
                if reason:
                    task["state"] = "interrupted"
                    task["finished"] = now()
                    task["result"] = {"ok": False, "cancelled": False, "error": reason}
                    self.done.notify_all()
            return dict(task)

    def reap_all(self, online_fn, grace: float) -> list[tuple[str, str]]:
        """后台巡检：把无望的 running 任务收成 interrupted，并返回 (设备, 任务) 以便释放槽位。

        没有这一步，任务一旦派发给一个随后死掉的子端，槽位会永远被占，
        该设备的后续任务全部排队但永远不执行。
        """
        reaped = []
        with self.lock:
            for tid, task in list(self.items.items()):
                if task["state"] != "running":
                    continue
                reason = self._stale_reason(task, online_fn(task["device"]), grace)
                if reason:
                    task["state"] = "interrupted"
                    task["finished"] = now()
                    task["result"] = {"ok": False, "cancelled": False, "error": reason}
                    reaped.append((task["device"], tid))
            if reaped:
                self.done.notify_all()
        return reaped

    def dispatched(self, tid: str) -> None:
        with self.lock:
            task = self.items.get(tid)
            if task and task["state"] == "queued":
                task["state"] = "running"
                task["started"] = now()

    def finish(self, tid: str, result: dict) -> bool:
        with self.lock:
            task = self.items.get(tid)
            if not task:
                return False
            task["result"] = result
            # 取消的终态优先：子端被杀掉后也会回一次 result，但不能把 cancelled 改回 failed
            if task["state"] != "cancelled":
                task["state"] = "succeeded" if result.get("ok") else "failed"
            task["finished"] = now()
            self.done.notify_all()
            return True

    def cancel(self, tid: str) -> str:
        """把任务标记为 cancelled 并把取消消息塞进该设备的队列。

        返回 cancelled / already-finished / not-found。
        """
        with self.lock:
            task = self.items.get(tid)
            if not task:
                return "not-found"
            if task["state"] in ("succeeded", "failed", "cancelled"):
                return "already-finished"
            task["state"] = "cancelled"
            task["finished"] = now()
            # 取消也要留下可读的结果体：否则调用方拿到的是 result=None，
            # 分不清「已取消」和「没有结果」
            task["result"] = {"ok": False, "cancelled": True, "error": "已按请求取消"}
            self.done.notify_all()
        HUB.enqueue(task["device"], {"task_id": tid, "kind": "__cancel__", "payload": {}})
        return "cancelled"

    def ack(self, tid: str) -> bool:
        with self.lock:
            task = self.items.get(tid)
            if not task:
                return False
            task["acked"] = True
            return True

    def get(self, tid: str):
        with self.lock:
            task = self.items.get(tid)
            return dict(task) if task else None

    def wait(self, tid: str, timeout: float):
        end = now() + timeout
        with self.lock:
            while True:
                task = self.items.get(tid)
                if task is None:
                    return None
                if task["state"] in ("succeeded", "failed", "cancelled", "interrupted"):
                    return dict(task)
                left = end - now()
                if left <= 0:
                    return dict(task)
                self.done.wait(left)


class Hub:
    """设备队列与执行槽位。

    规则：**每台设备同时只派发一个执行类任务**（exec / fs.*）。此前是子端并发跑，
    模型一次并行发两条命令就会在目标机上同时执行，与「一个设备一个写槽位」的约定不符。
    取消消息不受槽位限制，随时可以送达。
    """

    def __init__(self, store: Store):
        self.store = store
        self.tasks = Tasks()
        self.cond = threading.Condition()
        self.pending: dict[str, list[dict]] = {}
        self.active: dict[str, set[str]] = {}
        self.inflight: set[str] = set()          # 有 poll 正在等待（长轮询期间不代表离线）
        self.poll_sources: dict[str, str] = {}
        self._last_save = 0.0

    # ---- 队列 ----
    def enqueue(self, did: str, item: dict) -> None:
        with self.cond:
            self.pending.setdefault(did, []).append(item)
            self.cond.notify_all()

    def dequeue(self, did: str, wait: float):
        """等到有活可派发且该设备没有在跑的任务；超时返回 None。"""
        deadline = now() + wait
        with self.cond:
            while True:
                queue = self.pending.get(did) or []
                # 先看有没有可派的活，再看超时：wait=0 时也必须能立刻取到排队任务
                if queue:
                    if queue[0].get("kind") == "__cancel__":
                        # 取消消息永远优先、不受槽位限制
                        return queue.pop(0)
                    if not self.active.get(did):
                        return queue.pop(0)
                left = deadline - now()
                if left <= 0:
                    return None
                self.cond.wait(min(left, 1.0))

    # ---- 槽位 ----
    def begin(self, did: str, tid: str) -> None:
        with self.cond:
            self.active.setdefault(did, set()).add(tid)

    def end(self, did: str, tid: str) -> None:
        with self.cond:
            self.active.get(did, set()).discard(tid)
            self.cond.notify_all()

    def finish_task(self, did: str, tid: str, result: dict) -> bool:
        ok = self.tasks.finish(tid, result)
        self.end(did, tid)
        return ok

    # ---- 在线判定 ----
    def touch(self, did: str, info: dict | None = None) -> None:
        dev = self.store.device(did)
        if not dev:
            return
        dev["last_seen"] = now()
        changed = False
        if info:
            for k in ("os", "identity", "host_mode", "can_exec"):
                if info.get(k):
                    value = str(info[k])[:200]
                    if dev.get(k) != value:
                        dev[k] = value
                        changed = True
            # 命令执行权限以设备本地为准：子端每次心跳都报 can_exec，
            # 母端跟着同步，避免"本地已授权、母端还记着 False"这种两道闸不一致。
            # 授权根同样以子端为准（安装时 --root 决定），母端只做展示与路径提示
            if info.get("roots"):
                local_roots = [r for r in str(info["roots"]).split("|") if r][:16]
                if local_roots and dev.get("roots") != local_roots:
                    dev["roots"] = local_roots
                    changed = True
            if "can_exec" in info:
                local = str(info["can_exec"]).strip().lower() in ("true", "1", "yes")
                if dev.get("allow_exec") != local:
                    dev["allow_exec"] = local
                    changed = True
        if changed or now() - self._last_save > 30:
            self._last_save = now()
            self.store.save()

    def online(self, did: str) -> bool:
        dev = self.store.device(did)
        if not dev:
            return False
        with self.cond:
            if did in self.inflight:
                return True
        return now() - dev.get("last_seen", 0) < ONLINE_WINDOW

    def polling(self, did: str) -> bool:
        with self.cond:
            return did in self.inflight

    def start_sweeper(self, interval: float = 5.0) -> None:
        """后台巡检：回收无望任务并释放执行槽位。"""
        def loop() -> None:
            while True:
                time.sleep(interval)
                try:
                    for did, tid in self.tasks.reap_all(self.online, TASK_GRACE):
                        self.end(did, tid)
                        self.store.audit({"event": "task.reaped", "device": did, "task": tid})
                except Exception as exc:  # 巡检线程不能死
                    logging.getLogger(__name__).warning("任务巡检失败：%s", exc)

        threading.Thread(target=loop, name="tendril-sweeper", daemon=True).start()

    def submit(self, did: str, kind: str, payload: dict) -> str:
        tid = self.tasks.create(did, kind, payload)
        self.enqueue(did, {"task_id": tid, "kind": kind, "payload": payload})
        return tid


HUB: Hub


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Tendril/0.1"

    # ---- 基础 ----
    def _client_key(self) -> str:
        """限速用的客户端标识。

        经 Tailscale Funnel / 反向代理进来时 peer 全是 127.0.0.1，按 peer 统计会把
        所有公网客户端挤进同一个桶——一个扫描器就能把控制台一起封掉。所以本机
        代理转发过来的请求以 X-Forwarded-For 首跳为准；直连（局域网）仍用 peer。
        """
        peer = self.client_address[0] if self.client_address else "?"
        if peer in ("127.0.0.1", "::1"):
            xff = (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
            if xff:
                return f"xff:{xff}"
            return f"local:{peer}"
        return f"peer:{peer}"

    def _rate_blocked(self) -> bool:
        key = self._client_key()
        left = RATE.blocked(key)
        if left <= 0:
            return False
        self._json(429, {"error": f"失败过多，{int(left) + 1} 秒后再试"})
        return True

    def _rate_hit(self) -> None:
        RATE.hit(self._client_key())

    def _json(self, code: int, body: dict) -> None:
        # 204/304 按 HTTP 规范不能带消息体。带一个 "{}" 会让 Go 的客户端把这两个字节
        # 当成下一个响应的开头，报 malformed HTTP version 并让长轮询循环失效。
        if code in (204, 304):
            self.send_response(code)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return
        raw = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return {}
        if n > 8 * 1024 * 1024:
            raise ValueError("请求体过大")
        try:
            data = json.loads(self.rfile.read(n) or b"{}")
        except ValueError as e:
            raise ValueError("请求体不是 JSON") from e
        if not isinstance(data, dict):
            raise ValueError("请求体必须是 JSON 对象")
        return data

    def _control_ok(self) -> bool:
        auth = self.headers.get("Authorization", "")
        return auth.startswith("Bearer ") and secrets.compare_digest(auth[7:].strip(), HUB.store.token)

    def _device(self, did: str):
        """只校验设备密钥。批准状态由各端点分别处理，好让子端看到「未批准」而不是「身份无效」。"""
        dev = HUB.store.device(did)
        if not dev:
            return None
        key = self.headers.get("X-Tendril-Device-Key", "")
        return dev if (key and secrets.compare_digest(key, dev["secret"])) else None

    def _unsupported(self):
        self._json(405, {"error": f"不支持的方法 {self.command}；只接受 GET / POST"})

    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_TRACE = do_HEAD = _unsupported

    def version_string(self):
        return "Tendril/0.1"          # 不暴露 Python 版本

    def log_message(self, *a):
        pass

    def _reload(self) -> None:
        HUB.store.maybe_reload()

    # ---- GET ----
    def do_GET(self):
        self._reload()
        path = urlparse(self.path).path.strip("/").split("/")
        if path == ["v1", "health"]:
            return self._json(200, {"ok": True, "service": "tendril-mother", "version": "0.1.0"})
        # 装子端不需要母端令牌（新设备还没有凭据）：只放行二进制与其校验和，以及一次性安装脚本
        if len(path) == 2 and path[0] == "files":
            return self._files(path[1])
        if len(path) == 2 and path[0] == "join":
            return self._join(path[1])
        if len(path) == 2 and path[0] == "j":
            return self._join_short(path[1])
        if not self._control_ok():
            # 只惩罚"鉴权失败"的那条路径：持正确令牌的人不该被别人打出来的封禁连坐
            if self._rate_blocked():
                return
            self._rate_hit()
            return self._json(401, {"error": "缺少或错误的控制令牌"})
        if path == ["v1", "devices"]:
            rows = []
            for did, dev in sorted(HUB.store.devices.items()):
                rows.append({
                    "device": did,
                    "name": dev["name"],
                    "os": dev["os"],
                    "identity": dev["identity"],
                    "host_mode": dev.get("host_mode", ""),
                    "can_exec": dev.get("can_exec", ""),
                    "online": HUB.online(did),
                    "polling": HUB.polling(did),
                    "last_seen_age_s": round(now() - dev["last_seen"], 1) if dev["last_seen"] else None,
                    "roots": dev["roots"],
                    "allow_exec": dev["allow_exec"],
                    "approved": bool(dev.get("approved", True)),
                    "enabled": dev.get("enabled", True) is not False,
                })
            return self._json(200, {"devices": rows})
        if path == ["v1", "tasks"]:
            q = parse_qs(urlparse(self.path).query)
            try:
                limit = max(1, min(int((q.get("limit") or ["50"])[0]), 200))
            except ValueError:
                limit = 50
            device = (q.get("device") or [None])[0]
            return self._json(200, {"tasks": HUB.tasks.list_recent(limit, device),
                                    "devices": {did: HUB.online(did) for did in HUB.store.devices}})
        if path == ["v1", "audit"]:
            q = parse_qs(urlparse(self.path).query)
            try:
                limit = max(1, min(int((q.get("limit") or ["80"])[0]), 400))
            except ValueError:
                limit = 80
            lines = []
            audit_file = HUB.store.audit_file
            if audit_file.is_file():
                with open(audit_file, "rb") as f:
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    f.seek(max(0, size - 256 * 1024))
                    tail = f.read().decode("utf-8", "replace").splitlines()[-limit:]
                for line in tail:
                    try:
                        lines.append(json.loads(line))
                    except ValueError:
                        continue
            return self._json(200, {"events": lines[-limit:]})
        if len(path) == 3 and path[:2] == ["v1", "tasks"]:
            tid = path[2]
            probe = HUB.tasks.get(tid)
            if not probe:
                return self._json(404, {"error": "任务不存在"})
            task = HUB.tasks.reap_if_stale(tid, HUB.online(probe["device"]), TASK_GRACE)
            if task and task["state"] in ("succeeded", "failed", "cancelled", "interrupted"):
                HUB.end(task["device"], tid)
            return self._json(200, task)
        return self._json(404, {"error": f"未知路径 /{'/'.join(path)}"})

    # ---- POST ----
    def do_POST(self):
        self._reload()
        path = urlparse(self.path).path.strip("/").split("/")
        try:
            if path == ["agent", "poll"]:
                return self._agent_poll()
            if path == ["agent", "result"]:
                return self._agent_result()
            if path == ["agent", "ack"]:
                return self._agent_ack()
            body = self._body()
        except ValueError as e:
            return self._json(400, {"error": str(e)})
        if not self._control_ok():
            # 只惩罚"鉴权失败"的那条路径：持正确令牌的人不该被别人打出来的封禁连坐
            if self._rate_blocked():
                return
            self._rate_hit()
            return self._json(401, {"error": "缺少或错误的控制令牌"})
        if len(path) == 4 and path[:2] == ["v1", "tasks"] and path[3] == "cancel":
            return self._cancel(path[2])
        if len(path) >= 4 and path[:2] == ["v1", "devices"]:
            did, op = path[2], path[3:]
            dev = HUB.store.device(did)
            if not dev:
                return self._json(404, {"error": "设备未注册"})
            if dev.get("enabled", True) is False and op != ["enable"]:
                return self._json(409, {"error": "设备已被母端暂停，先在控制页启用它"})
            if op == ["enable"]:
                return self._set_enabled(did, body)
            if op == ["approve"]:
                return self._approve(did, True)
            if op == ["deny"]:
                return self._approve(did, False)
            if op == ["exec"]:
                return self._exec(did, body)
            if op == ["fs", "list"]:
                return self._fs(did, "fs.list", body)
            if op == ["fs", "read"]:
                return self._fs(did, "fs.read", body)
            if op == ["fs", "write"]:
                return self._fs(did, "fs.write", body)
            if op == ["fs", "mkdir"]:
                return self._fs(did, "fs.mkdir", body)
            if op == ["fs", "rename"]:
                return self._fs(did, "fs.rename", body)
            if op == ["fs", "remove"]:
                return self._fs(did, "fs.remove", body)
        return self._json(404, {"error": f"未知路径 /{'/'.join(path)}"})

    # ---- 动作 ----
    def _exec(self, did: str, body: dict):
        dev = HUB.store.device(did)
        if not dev["allow_exec"]:
            return self._json(403, {"error": "此设备未授权命令执行"})
        command = body.get("command")
        if not isinstance(command, str) or not command.strip():
            return self._json(400, {"error": "command 必须是非空字符串"})
        if len(command) > MAX_COMMAND:
            return self._json(413, {"error": f"command 超过 {MAX_COMMAND} 字符"})
        cwd = body.get("cwd")
        if cwd is not None and (not isinstance(cwd, str) or len(cwd) > 4096):
            return self._json(400, {"error": "cwd 必须是字符串且不超过 4096 字符"})
        shell = body.get("shell")
        if shell is not None and shell not in ("bash", "powershell", "cmd"):
            return self._json(400, {"error": "shell 只支持 bash / powershell / cmd，或省略由子端决定"})
        timeout = body.get("timeout_s", 120)
        if not isinstance(timeout, int) or not 1 <= timeout <= 3600:
            return self._json(400, {"error": "timeout_s 必须是 1–3600 的整数"})
        if not HUB.online(did):
            return self._json(409, {"error": "设备离线（最近一次通信超出在线窗口），未下发"})
        payload = {"command": command, "shell": shell or "", "timeout_s": timeout,
                   "cwd": cwd or None, "cap": EXEC_CAP}
        tid = HUB.submit(did, "exec", payload)
        HUB.store.audit({"event": "exec.submit", "device": did, "task": tid, "command": command[:200]})
        return self._json(202, {"task_id": tid, "state": "queued"})

    def _files(self, name: str):
        """公开投递：只认真实存在的固定文件名，不做路径拼接。"""
        deliver = DELIVER
        table = {
            "agent.exe": deliver / "tendril-agent.exe",
            "agent-linux": deliver / "tendril-agent-linux",
            "agent-darwin": deliver / "tendril-agent-darwin",
            "agent.exe.sha256": deliver / "tendril-agent.exe.sha256",
            "agent-linux.sha256": deliver / "tendril-agent-linux.sha256",
            "agent-darwin.sha256": deliver / "tendril-agent-darwin.sha256",
        }
        target = table.get(name)
        if not target or not target.is_file():
            return self._json(404, {"error": "没有这个文件"})
        data = target.read_bytes()
        ctype = "text/plain; charset=utf-8" if name.endswith(".sha256") else "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _join(self, token: str):
        """一条命令接入：返回可直接执行的自举脚本（下载 → 校验 → 安装/运行）。"""
        try:
            invite = decode_invite(token)
        except Exception:
            return self._json(400, {"error": "邀请串无效"})
        if invite["exp"] < now():
            return self._json(410, {"error": "邀请已过期，请重新签发"})
        query = parse_qs(urlparse(self.path).query)
        os_kind = (query.get("os") or ["windows"])[0].lower()
        if os_kind in ("macos", "mac", "osx"):
            os_kind = "darwin"
        if os_kind not in ("windows", "linux", "darwin"):
            return self._json(400, {"error": "os 只支持 windows / linux / macos"})
        bin_name = {"windows": "agent.exe", "linux": "agent-linux", "darwin": "agent-darwin"}[os_kind]
        url = invite["url"].rstrip("/")
        # 本机授权命令执行只能由这台机器上的人做：把 ?exec=1 写进脚本，等于"运行这一行"就是授权动作
        extra = " --allow-exec" if (query.get("exec") or [""])[0] in ("1", "true", "yes") else ""
        if invite.get("tls") == "system":
            # PowerShell 用逗号分隔数组，bash 用空格分隔；混用会让 bash 把逗号当成串内容
            sep = "," if os_kind == "windows" else " "
            addrs = sep.join("'%s'" % a for a in (invite.get("addrs") or []))
            body = (PS_TEMPLATE_PUBLIC if os_kind == "windows" else SH_TEMPLATE_PUBLIC).format(
                url=url, invite=token, addrs=addrs, extra=extra, bin_name=bin_name)
        else:
            cert = (invite.get("cert") or "").strip()
            body = (PS_TEMPLATE if os_kind == "windows" else SH_TEMPLATE).format(
                url=url, invite=token, cert=cert, extra=extra, bin_name=bin_name)
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _join_short(self, sid: str) -> None:
        """短 id → 邀请本体。母端只接受有效期内的 id。"""
        file = HUB.store.state / "pending-invites.json"
        try:
            data = json.loads(file.read_text()) if file.is_file() else {}
        except ValueError:
            data = {}
        item = data.get(sid)
        if not item:
            return self._json(404, {"error": "安装链接无效或已过期，请让母端重新生成"})
        if item.get("exp", 0) < now():
            return self._json(410, {"error": "安装链接已过期，请让母端重新生成"})
        return self._join(item["token"])

    def _set_enabled(self, did: str, body: dict) -> None:
        """母端开关：暂停/恢复子端连接。只改一个字段，设备与授权目录都不动。"""
        dev = HUB.store.device(did)
        if not dev:
            return self._json(404, {"error": "设备未注册"})
        if "enabled" not in body:
            return self._json(400, {"error": "缺少 enabled（true/false）"})
        want = bool(body["enabled"])
        dev["enabled"] = want
        HUB.store.save()
        HUB.store.audit({"event": "device.enable" if want else "device.pause",
                         "device": did, "by": "control-api"})
        return self._json(200, {"device": did, "enabled": want})

    def _approve(self, did: str, approved: bool):
        """母端审批：设备在等批准时由母端决定；这不是远程扩权（exec 授权只能设备本地开）。"""
        dev = HUB.store.device(did)
        if not dev:
            return self._json(404, {"error": "设备未注册"})
        dev["approved"] = bool(approved)
        HUB.store.save()
        HUB.store.audit({"event": "device.approve" if approved else "device.deny",
                         "device": did, "by": "control-api"})
        return self._json(200, {"device": did, "approved": bool(approved)})

    def _cancel(self, tid: str):
        task = HUB.tasks.get(tid)
        if not task:
            return self._json(404, {"error": "任务不存在"})
        verdict = HUB.tasks.cancel(tid)
        HUB.store.audit({"event": "task.cancel", "device": task["device"], "task": tid, "verdict": verdict})
        if verdict == "not-found":
            return self._json(404, {"error": "任务不存在"})
        if verdict == "already-finished":
            return self._json(409, {"error": "任务已结束，无法取消", "state": task["state"]})
        return self._json(202, {"task_id": tid, "state": "cancelled"})

    def _fs(self, did: str, kind: str, body: dict):
        # 重命名是双路径操作，不走单 path 的校验。
        if kind == "fs.rename":
            src, dst = body.get("from"), body.get("to")
            for name, value in (("from", src), ("to", dst)):
                if not isinstance(value, str) or not value:
                    return self._json(400, {"error": f"{name} 必须是非空字符串"})
                if len(value) > MAX_PATH:
                    return self._json(413, {"error": f"{name} 超过 {MAX_PATH} 字符"})
            if src == dst:
                return self._json(400, {"error": "from 和 to 相同"})
            return self._dispatch_fs(did, kind, {"from": src, "to": dst}, f"{src} → {dst}")

        path = body.get("path")
        if not isinstance(path, str) or not path:
            return self._json(400, {"error": "path 必须是非空字符串"})
        if len(path) > MAX_PATH:
            return self._json(413, {"error": f"path 超过 {MAX_PATH} 字符"})
        payload = {"path": path}
        if kind == "fs.remove":
            payload = {"path": path, "recursive": bool(body.get("recursive"))}
        if kind == "fs.write":
            data = body.get("data_b64")
            if not isinstance(data, str):
                return self._json(400, {"error": "data_b64 必须是字符串（清空文件请传空串且 final=true）"})
            if len(data) > MAX_CHUNK_B64:
                return self._json(413, {"error": f"单个分块超过 {MAX_CHUNK_B64} 字符（原始数据约 768 KiB）"})
            off = body.get("offset", 0)
            # 空内容只在「一次写完」（offset=0 且 final）时合法：用于清空或创建空文件。
            # 分块中间出现空块一定是调用方算错了，不该静默接受。
            if data == "" and not (off == 0 and bool(body.get("final"))):
                return self._json(400, {"error": "空分块只允许在 offset=0 且 final=true 时出现"})
            if not isinstance(off, int) or off < 0:
                return self._json(400, {"error": "offset 必须是非负整数"})
            payload.update(data_b64=data, offset=off, final=bool(body.get("final")),
                           hash=bool(body.get("hash")))
            for key in ("expect_size", "expect_mtime"):
                value = body.get(key)
                if value is not None:
                    if not isinstance(value, int) or value < 0:
                        return self._json(400, {"error": f"{key} 必须是非负整数或省略"})
                    payload[key] = value
        if kind == "fs.read":
            off = body.get("offset", 0)
            lim = body.get("limit", 65536)
            if not isinstance(off, int) or off < 0:
                return self._json(400, {"error": "offset 必须是非负整数"})
            if not isinstance(lim, int) or not 1 <= lim <= 1024 * 1024:
                return self._json(400, {"error": "limit 必须是 1–1048576 的整数"})
            raw_flag = body.get("raw")
            if raw_flag is not None and not isinstance(raw_flag, bool):
                return self._json(400, {"error": "raw 必须是布尔值或省略"})
            payload.update(offset=off, limit=lim)
            if raw_flag:
                payload["raw"] = True
        hint = path
        return self._dispatch_fs(did, kind, payload, hint)

    def _dispatch_fs(self, did: str, kind: str, payload: dict, hint: str):
        if not HUB.online(did):
            return self._json(409, {"error": "设备离线（最近一次通信超出在线窗口），未下发"})
        tid = HUB.submit(did, kind, payload)
        task = HUB.tasks.wait(tid, FS_WAIT)
        HUB.store.audit({"event": kind + ".done", "device": did, "task": tid, "path": (hint or "")[:300]})
        if task is None:
            return self._json(500, {"error": "任务丢失"})
        if task["state"] not in ("succeeded", "failed"):
            return self._json(504, {"error": f"设备未在 {FS_WAIT:.0f}s 内回执，结果未知", "task_id": tid})
        return self._json(200 if task["state"] == "succeeded" else 422,
                          {"task_id": tid, **(task["result"] or {})})

    # ---- 设备通道 ----
    def _agent_poll(self):
        did = self.headers.get("X-Tendril-Device-Id", "")
        dev = self._device(did)
        if not dev:
            if self._rate_blocked():
                return
            self._rate_hit()
            return self._json(401, {"error": "设备身份无效"})
        if dev.get("approved") is not True:
            return self._json(403, {"error": "设备尚未被母端批准"})
        if dev.get("enabled", True) is False:
            # 母端开关：暂停后子端拿不到任务，但设备记录与文件都保留，随时可恢复
            return self._json(403, {"error": "设备已被母端暂停", "paused": True})
        info = None
        if int(self.headers.get("Content-Length") or 0) > 0:
            try:
                info = self._body()
            except ValueError:
                info = None
        HUB.touch(did, info if isinstance(info, dict) else None)
        # 子端在执行任务期间要能收回取消，所以支持更短的等待窗口
        wait = POLL_WAIT
        query = urlparse(self.path).query
        if query.startswith("wait="):
            try:
                wait = max(0.0, min(float(query[5:]), 30.0))
            except ValueError:
                pass
        # 记录轮询来源：同一设备出现不同来源时能查出「重复安装/旧进程没退」
        src = self.client_address[0]
        prev = HUB.poll_sources.get(did)
        if prev and prev != src:
            HUB.store.audit({"event": "agent.foreign_poller", "device": did,
                             "previous": prev, "current": src})
        HUB.poll_sources[did] = src
        # 不再因为「已有连接在轮询」就拒绝：子端重启时旧连接的 inflight 要等超时才释放，
        # 拒绝会让重启后的子端最多 POLL_WAIT 秒拿不到任务（看起来像坏了）。
        # 并发执行由 Hub 的执行槽位保证，重复实例只记录、不阻断。
        with HUB.cond:
            HUB.inflight.add(did)
        try:
            while True:
                item = HUB.dequeue(did, wait)
                if item is None:
                    return self._json(204, {})
                # 任务在排队期间被取消：不能再下达（否则「已取消」的命令照样执行）
                if item.get("kind") != "__cancel__" and HUB.tasks.state_of(item["task_id"]) == "cancelled":
                    HUB.store.audit({"event": "task.dropped_cancelled", "device": did,
                                     "task": item["task_id"]})
                    continue
                break
        finally:
            with HUB.cond:
                HUB.inflight.discard(did)
        if item.get("kind") != "__cancel__":
            HUB.tasks.dispatched(item["task_id"])
            HUB.begin(did, item["task_id"])       # 占住该设备的执行槽位
        return self._json(200, item)

    def _agent_ack(self):
        """子端确认收到任务。没有这一步就只能靠超时猜「是不是没送到」。"""
        did = self.headers.get("X-Tendril-Device-Id", "")
        if not self._device(did):
            return self._json(401, {"error": "设备身份无效"})
        try:
            body = self._body()
        except ValueError as e:
            return self._json(400, {"error": str(e)})
        tid = body.get("task_id")
        if not isinstance(tid, str):
            return self._json(400, {"error": "缺少 task_id"})
        HUB.touch(did)
        HUB.tasks.ack(tid)
        return self._json(200, {"ok": True})

    def _agent_result(self):
        did = self.headers.get("X-Tendril-Device-Id", "")
        dev = self._device(did)
        if not dev:
            if self._rate_blocked():
                return
            self._rate_hit()
            return self._json(401, {"error": "设备身份无效"})
        if dev.get("approved") is not True:
            return self._json(403, {"error": "设备尚未被母端批准"})
        if dev.get("enabled", True) is False:
            # 母端开关：暂停后子端拿不到任务，但设备记录与文件都保留，随时可恢复
            return self._json(403, {"error": "设备已被母端暂停", "paused": True})
        try:
            body = self._body()
        except ValueError as e:
            return self._json(400, {"error": str(e)})
        tid = body.get("task_id")
        if not isinstance(tid, str):
            return self._json(400, {"error": "缺少 task_id"})
        HUB.touch(did)
        ok = HUB.finish_task(did, tid, body.get("result") or {})
        HUB.store.audit({"event": "task.result", "device": did, "task": tid, "ok": bool(body.get("result", {}).get("ok"))})
        return self._json(200 if ok else 404, {"ok": ok})


def main(argv: list[str]) -> int:
    global HUB
    ap = argparse.ArgumentParser(prog="tendril-mother")
    ap.add_argument("--state", default=str(STATE))
    sub = ap.add_subparsers(dest="cmd", required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8901)
    serve.add_argument("--no-tls", action="store_true", help="即使有证书也只用明文（仅限本机调试）")
    tls = sub.add_parser("init-tls")
    tls.add_argument("--san", action="append", default=None,
                     help="证书里的地址，可重复；默认 127.0.0.1/localhost 加本机主 IP")
    approve = sub.add_parser("approve")
    approve.add_argument("device")
    deny = sub.add_parser("deny")
    deny.add_argument("device")
    add = sub.add_parser("add-device")
    add.add_argument("device")
    add.add_argument("--root", action="append", default=[], help="允许访问的目录，可重复")
    add.add_argument("--exec", action="store_true", help="允许命令执行")
    add.add_argument("--name", default="")
    rm = sub.add_parser("remove-device", aliases=["rm-device"])
    rm.add_argument("device")
    inv = sub.add_parser("invite")
    inv.add_argument("device")
    inv.add_argument("--url", required=True, help="子端要连的母端地址，如 https://mother.example:8911")
    inv.add_argument("--ttl", type=int, default=900, help="有效期秒数，默认 900")
    inv.add_argument("--tls", choices=["", "system"], default="",
                     help="system=母端走公网证书（Tailscale Funnel 等），子端用系统根校验")
    inv.add_argument("--full", action="store_true", help="同时打印长邀请串（写文件/自动化用）")
    inv.add_argument("--addr", action="append", default=None,
                     help="可重复：给子端的入口 IP（绕过 DNS 轮询里的坏节点）")
    args = ap.parse_args(argv)

    store = Store(Path(args.state))

    if args.cmd in ("remove-device", "rm-device"):
        dev = store.device(args.device)
        if not dev:
            print(f"没有这个设备：{args.device}", file=sys.stderr)
            return 2
        store.devices.pop(args.device, None)
        store.save()          # 自己拿锁；这里不能再套一层
        store.audit({"event": "device.removed", "device": args.device})
        print(f"已移除设备 {args.device}；它下次请求会收到 401。")
        return 0
    if args.cmd == "init-tls":
        sans = args.san
        if not sans:
            sans = ["127.0.0.1", "localhost", *local_ipv4s()]
        return init_tls(store.state, sans)
    if args.cmd == "approve":
        dev = store.device(args.device)
        if not dev:
            print(f"没有设备 {args.device}", file=sys.stderr)
            return 1
        dev["approved"] = True
        store.save()
        print(f"设备 {args.device} 已批准，可以开始连入")
        return 0
    if args.cmd == "deny":
        dev = store.device(args.device)
        if not dev:
            print(f"没有设备 {args.device}", file=sys.stderr)
            return 1
        dev["approved"] = False
        store.save()
        print(f"设备 {args.device} 已停用（连接会被 401 拒绝）")
        return 0
    if args.cmd == "add-device":
        secret = store.add(args.device, args.root, args.exec, args.name)
        print(f"设备 {args.device} 已登记")
        print(f"  secret: {secret}")
        print(f"  允许目录: {args.root or '（无）'}")
        print(f"  允许命令: {args.exec}")
        print(f"  控制令牌: {store.token_file}")
        return 0

    if args.cmd == "invite":
        invite = make_invite(store, args.device, args.url, args.ttl, tls=args.tls, addrs=args.addr)
        url = args.url.rstrip("/")
        print(invite)
        print()
        sid = short_invite(store, invite)
        wc = f"{url}/j/{sid}"
        print("子端一条命令接入（复制整行到目标机执行；不需要管理员）：")
        # 两条都用 curl.exe：公网证书下 PS 5.1 的 iwr 会握手失败；内网自签证书下 iwr 没有
        # 跳过校验的参数（-SkipCertificateCheck 是 PS 7+），-k 只用于取脚本这一步。
        kflag = "" if args.tls == "system" else "k"
        print(f'  Windows(PowerShell):  curl.exe -{kflag}fsSL {wc} | Out-String | iex')
        print(f'  Linux:              curl -fsSL "{wc}?os=linux" | bash -s -- --daemon')
        print(f'  macOS:              curl -fsSL "{wc}?os=macos" | bash -s -- --daemon')
        print()
        print(f"有效期 {args.ttl} 秒；命令执行默认关闭，需要时在该机本地加 --allow-exec。")
        if args.full:
            print(f"\n完整邀请串（写入文件用）：{invite}")
        return 0

    HUB = Hub(store)
    HUB.start_sweeper()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    srv.daemon_threads = True
    scheme = "https" if maybe_wrap_tls(srv, store.state, enabled=not args.no_tls) else "http"
    print(f"tendril-mother 监听 {scheme}://{args.host}:{args.port}  状态目录 {store.state}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
