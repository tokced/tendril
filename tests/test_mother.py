"""M1 端到端测试：真起母端 + 真起子端进程，走真实 HTTP。

只验证母端语义（授权、任务、截断、离线），不冒充 Windows 验收。
运行：python3 -m unittest tests.test_mother -v
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import re
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# 故意让长轮询窗口 > 在线窗口，复现「等任务时被误判离线」这个真实缺陷
os.environ.setdefault("TENDRIL_ONLINE_WINDOW", "4")
os.environ.setdefault("TENDRIL_POLL_WAIT", "9")
os.environ.setdefault("TENDRIL_FS_WAIT", "8")
os.environ.setdefault("TENDRIL_TASK_GRACE", "1")

from mother import server as M  # noqa: E402


def http(method: str, url: str, body: dict | None = None, token: str | None = None,
         timeout: float = 15) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw) if raw else {}
        except ValueError:
            return e.code, {}


class M1Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tls = False
        cls.tmp = Path(tempfile.mkdtemp(prefix="tendril-m1-"))
        cls.shared = cls.tmp / "shared"
        cls.shared.mkdir()
        (cls.shared / "hello.txt").write_text("第一行\n第二行\n", encoding="utf-8")
        big = "".join(f"line {i}\n" for i in range(2000))
        (cls.shared / "big.txt").write_text(big, encoding="utf-8")
        (cls.shared / "bin.dat").write_bytes(b"\x00\x01\x02abc\x00")
        (cls.shared / "sub").mkdir()

        cls.store = M.Store(cls.tmp / "state")
        cls.secret = cls.store.add("sim-linux", [str(cls.shared)], allow_exec=True)
        cls.token = cls.store.token
        M.HUB = M.Hub(cls.store)

        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), M.Handler)
        cls.srv.daemon_threads = True
        cls.port = cls.srv.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

        cls.agent = subprocess.Popen(
            [sys.executable, str(ROOT / "agent" / "tendril_agent.py"),
             "--mother", cls.base, "--device", "sim-linux", "--secret", cls.secret,
             "--root", str(cls.shared), "--allow-exec"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        deadline = time.time() + 15
        while time.time() < deadline:
            code, body = http("GET", f"{cls.base}/v1/devices", token=cls.token)
            if code == 200 and body["devices"][0]["online"]:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("子端未在 15s 内上线")

    @classmethod
    def tearDownClass(cls):
        cls.agent.terminate()
        try:
            cls.agent.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.agent.kill()
        if cls.agent.stderr:
            cls.agent.stderr.close()
        cls.srv.shutdown()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # ---- 基础与鉴权 ----
    def test_health_no_auth(self):
        code, body = http("GET", f"{self.base}/v1/health")
        self.assertEqual(code, 200)
        self.assertTrue(body["ok"])

    def test_devices_require_token(self):
        code, _ = http("GET", f"{self.base}/v1/devices")
        self.assertEqual(code, 401)

    def test_devices_reports_live_state(self):
        code, body = http("GET", f"{self.base}/v1/devices", token=self.token)
        self.assertEqual(code, 200)
        dev = next(d for d in body["devices"] if d["device"] == "sim-linux")
        self.assertTrue(dev["online"])
        self.assertTrue(dev["allow_exec"])
        self.assertIn("Linux", dev["os"])
        self.assertLessEqual(dev["last_seen_age_s"], 10)

    def test_wrong_device_key_rejected(self):
        req = urllib.request.Request(f"{self.base}/agent/poll", data=b"{}", method="POST")
        req.add_header("X-Tendril-Device-Id", "sim-linux")
        req.add_header("X-Tendril-Device-Key", "wrong")
        try:
            urllib.request.urlopen(req, timeout=5)
            self.fail("错误密钥竟然成功")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 401)

    # ---- 命令 ----
    def _wait_task(self, tid: str, timeout: float = 20) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            code, body = http("GET", f"{self.base}/v1/tasks/{tid}", token=self.token)
            if code == 200 and body["state"] in ("succeeded", "failed"):
                return body
            time.sleep(0.1)
        self.fail(f"任务 {tid} 未在 {timeout}s 内完成")

    def test_exec_success_with_exit_code(self):
        code, body = http("POST", f"{self.base}/v1/devices/sim-linux/exec",
                          {"command": "echo hi; echo err >&2; exit 3"}, token=self.token)
        self.assertEqual(code, 202)
        task = self._wait_task(body["task_id"])
        # 任务被执行了（succeeded），命令本身非零退出（command_ok=False）—— 两件事分开记
        self.assertEqual(task["state"], "succeeded")
        result = task["result"]
        self.assertFalse(result["command_ok"])
        self.assertEqual(result["exit_code"], 3)
        self.assertIn("hi", result["stdout"])
        self.assertIn("err", result["stderr"])
        self.assertFalse(result["timed_out"])

    def test_exec_zero_exit_succeeds(self):
        code, body = http("POST", f"{self.base}/v1/devices/sim-linux/exec",
                          {"command": "printf 'a\\nb\\n'"}, token=self.token)
        self.assertEqual(code, 202)
        task = self._wait_task(body["task_id"])
        self.assertEqual(task["state"], "succeeded")
        self.assertEqual(task["result"]["stdout"], "a\nb\n")
        self.assertEqual(task["result"]["exit_code"], 0)

    def test_exec_timeout_kills_process_group(self):
        code, body = http("POST", f"{self.base}/v1/devices/sim-linux/exec",
                          {"command": "sleep 30 & wait", "timeout_s": 1}, token=self.token)
        self.assertEqual(code, 202)
        task = self._wait_task(body["task_id"], timeout=15)
        self.assertEqual(task["state"], "failed")
        self.assertTrue(task["result"]["timed_out"])
        self.assertLess(task["result"]["elapsed_s"], 5)

    def test_exec_rejects_bad_input(self):
        code, _ = http("POST", f"{self.base}/v1/devices/sim-linux/exec", {"command": ""}, token=self.token)
        self.assertEqual(code, 400)
        code, _ = http("POST", f"{self.base}/v1/devices/sim-linux/exec",
                       {"command": "ls", "timeout_s": 99999}, token=self.token)
        self.assertEqual(code, 400)

    # ---- 文件 ----
    def test_fs_list(self):
        code, body = http("POST", f"{self.base}/v1/devices/sim-linux/fs/list",
                          {"path": str(self.shared)}, token=self.token)
        self.assertEqual(code, 200, body)
        names = {e["name"] for e in body["entries"]}
        self.assertIn("hello.txt", names)
        self.assertIn("sub", names)
        self.assertEqual(body["entries"][0]["name"], "sub")  # 目录在前

    def test_fs_read_truncates_and_advances_cursor(self):
        code, body = http("POST", f"{self.base}/v1/devices/sim-linux/fs/read",
                          {"path": str(self.shared / "big.txt"), "limit": 50}, token=self.token)
        self.assertEqual(code, 200, body)
        self.assertTrue(body["truncated"])
        self.assertEqual(body["next_offset"], 50)
        self.assertEqual(len(body["content"].encode()), 50)

        code, body2 = http("POST", f"{self.base}/v1/devices/sim-linux/fs/read",
                           {"path": str(self.shared / "big.txt"), "offset": 50, "limit": 50}, token=self.token)
        self.assertEqual(code, 200)
        self.assertEqual(body2["offset"], 50)
        self.assertNotEqual(body["content"], body2["content"])

    def test_fs_read_chinese_and_binary(self):
        code, body = http("POST", f"{self.base}/v1/devices/sim-linux/fs/read",
                          {"path": str(self.shared / "hello.txt")}, token=self.token)
        self.assertEqual(code, 200)
        self.assertIn("第一行", body["content"])
        self.assertFalse(body["binary"])

        code, body = http("POST", f"{self.base}/v1/devices/sim-linux/fs/read",
                          {"path": str(self.shared / "bin.dat")}, token=self.token)
        self.assertEqual(code, 200)
        self.assertTrue(body["binary"])
        self.assertIn("content_base64", body)

    def test_online_survives_long_poll_window(self):
        """长轮询期间没有新请求，只看 last_seen 会把等任务的设备误判离线。"""
        time.sleep(M.ONLINE_WINDOW + 2.0)
        code, body = http("GET", f"{self.base}/v1/devices", token=self.token)
        self.assertEqual(code, 200)
        dev = next(d for d in body["devices"] if d["device"] == "sim-linux")
        self.assertTrue(dev["online"], f"被误判离线: {dev}")
        self.assertTrue(dev["polling"])
        self.assertGreater(dev["last_seen_age_s"], M.ONLINE_WINDOW)


    def test_cancel_running_command(self):
        code, body = http("POST", f"{self.base}/v1/devices/sim-linux/exec",
                          {"command": "sleep 60", "timeout_s": 300}, token=self.token)
        self.assertEqual(code, 202)
        tid = body["task_id"]
        deadline = time.time() + 10
        while time.time() < deadline:
            _, task = http("GET", f"{self.base}/v1/tasks/{tid}", token=self.token)
            if task.get("state") == "running":
                break
            time.sleep(0.1)
        self.assertEqual(task.get("state"), "running", "任务没有进入运行态，取消测试无意义")

        code, verdict = http("POST", f"{self.base}/v1/tasks/{tid}/cancel", token=self.token)
        self.assertEqual(code, 202, verdict)
        self.assertEqual(verdict["state"], "cancelled")

        deadline = time.time() + 10
        while time.time() < deadline:
            _, task = http("GET", f"{self.base}/v1/tasks/{tid}", token=self.token)
            result = task.get("result") or {}
            # 取消瞬间会先放一个 stub 结果；要等子端真实回执（带 elapsed_s）才算终止到位
            if result.get("cancelled") and "elapsed_s" in result:
                break
            time.sleep(0.1)
        result = task.get("result") or {}
        self.assertTrue(result.get("cancelled"), f"未收到取消回执: {task}")
        self.assertLess(result.get("elapsed_s", 99), 10)
        self.assertEqual(task["state"], "cancelled")

    def test_cancel_finished_task_is_rejected(self):
        code, body = http("POST", f"{self.base}/v1/devices/sim-linux/exec",
                          {"command": "true"}, token=self.token)
        tid = body["task_id"]
        self._wait_task(tid)
        code, verdict = http("POST", f"{self.base}/v1/tasks/{tid}/cancel", token=self.token)
        self.assertEqual(code, 409, verdict)

    def test_no_content_has_no_body(self):
        """204 带消息体会让 Go 客户端报 malformed HTTP version，长轮询直接失效。"""
        import http.client
        # 用一个没有子端在轮询的独立设备，避免撞上「同一设备重复轮询」的保护
        if not hasattr(self.__class__, "_raw_secret"):
            self.__class__._raw_secret = self.store.add("raw-probe", [], False)
        conn = http.client.HTTPSConnection("127.0.0.1", self.port) if self.tls else \
            http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("POST", "/agent/poll?wait=0", body=b"{}",
                     headers={"X-Tendril-Device-Id": "raw-probe",
                              "X-Tendril-Device-Key": self.__class__._raw_secret,
                              "Content-Type": "application/json"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 204)
        self.assertEqual(resp.read(), b"", "204 不能带消息体")
        self.assertNotIn("content-length", {k.lower() for k, _ in resp.getheaders()})
        conn.close()

    def test_unapproved_device_rejected(self):
        if not hasattr(self.__class__, "_raw_secret"):
            self.__class__._raw_secret = self.store.add("raw-probe", [], False)
        dev = M.HUB.store.device("raw-probe")
        dev["approved"] = False
        try:
            import http.client
            conn = (http.client.HTTPSConnection("127.0.0.1", self.port) if self.tls
                    else http.client.HTTPConnection("127.0.0.1", self.port))
            conn.request("POST", "/agent/poll?wait=0", body=b"{}",
                         headers={"X-Tendril-Device-Id": "raw-probe",
                                  "X-Tendril-Device-Key": self.__class__._raw_secret,
                                  "Content-Type": "application/json"})
            self.assertEqual(conn.getresponse().status, 403)
            conn.close()
        finally:
            dev["approved"] = True


    def test_fs_write_creates_and_atomically_replaces(self):
        target = self.shared / "written.txt"
        code, body = http("POST", f"{self.base}/v1/devices/sim-linux/fs/write",
                          {"path": str(target), "data_b64": base64.b64encode(b"hello ").decode(),
                           "offset": 0, "final": False}, token=self.token)
        self.assertEqual(code, 200, body)
        self.assertFalse(target.exists(), "分块未完成时不能出现成品文件")

        code, body = http("POST", f"{self.base}/v1/devices/sim-linux/fs/write",
                          {"path": str(target), "data_b64": base64.b64encode("世界".encode()).decode(),
                           "offset": 6, "final": True, "hash": True}, token=self.token)
        self.assertEqual(code, 200, body)
        self.assertEqual(target.read_bytes(), "hello 世界".encode())
        self.assertEqual(len(body.get("sha256", "")), 64, "应返回 sha256")

    def test_fs_write_refuses_when_target_changed(self):
        target = self.shared / "conflict.txt"
        target.write_text("original", encoding="utf-8")
        size = target.stat().st_size
        target.write_text("someone changed it", encoding="utf-8")   # 读完之后别人改了
        code, body = http("POST", f"{self.base}/v1/devices/sim-linux/fs/write",
                          {"path": str(target), "data_b64": base64.b64encode(b"mine").decode(),
                           "offset": 0, "final": True, "expect_size": size}, token=self.token)
        self.assertEqual(code, 422, body)
        self.assertIn("拒绝覆盖", body.get("error", ""))
        self.assertEqual(target.read_text(encoding="utf-8"), "someone changed it", "不许无声覆盖")

    def test_fs_write_outside_root_refused(self):
        code, body = http("POST", f"{self.base}/v1/devices/sim-linux/fs/write",
                          {"path": "/tmp/evil.txt", "data_b64": base64.b64encode(b"x").decode(),
                           "offset": 0, "final": True}, token=self.token)
        self.assertEqual(code, 422, body)
        self.assertIn("不在授权目录内", body.get("error", ""))



    def test_fs_write_empty_truncates(self):
        target = self.shared / "to-empty.txt"
        target.write_text("old content", encoding="utf-8")
        code, body = http("POST", f"{self.base}/v1/devices/sim-linux/fs/write",
                          {"path": str(target), "data_b64": "", "offset": 0, "final": True,
                           "expect_size": len("old content")}, token=self.token)
        self.assertEqual(code, 200, body)
        self.assertEqual(target.read_bytes(), b"", "空写入应清空文件")

        code, body = http("POST", f"{self.base}/v1/devices/sim-linux/fs/write",
                          {"path": str(self.shared / "empty-mid.txt"), "data_b64": "",
                           "offset": 10, "final": True}, token=self.token)
        self.assertEqual(code, 400, "非首块的空分块必须拒绝")

    def test_mkdir_rename_remove_cycle(self):
        base = self.shared
        d = base / "folder-a"
        code, body = http("POST", f"{self.base}/v1/devices/sim-linux/fs/mkdir", {"path": str(d)}, token=self.token)
        self.assertEqual(code, 200, body)
        self.assertTrue(d.is_dir())

        code, body = http("POST", f"{self.base}/v1/devices/sim-linux/fs/mkdir", {"path": str(d)}, token=self.token)
        self.assertEqual(code, 422, "重复创建应报已存在")

        (d / "inner.txt").write_text("x", encoding="utf-8")
        target = base / "folder-b"
        code, body = http("POST", f"{self.base}/v1/devices/sim-linux/fs/rename",
                          {"from": str(d), "to": str(target)}, token=self.token)
        self.assertEqual(code, 200, body)
        self.assertTrue((target / "inner.txt").is_file())

        code, body = http("POST", f"{self.base}/v1/devices/sim-linux/fs/remove",
                          {"path": str(target)}, token=self.token)
        self.assertEqual(code, 422, "非空目录不显式 recursive 必须拒绝")
        self.assertTrue(target.is_dir())

        code, body = http("POST", f"{self.base}/v1/devices/sim-linux/fs/remove",
                          {"path": str(target), "recursive": True}, token=self.token)
        self.assertEqual(code, 200, body)
        self.assertFalse(target.exists())

    def test_rename_refuses_overwrite(self):
        a, b = self.shared / "keep-me.txt", self.shared / "taken.txt"
        a.write_text("a", encoding="utf-8")
        b.write_text("b", encoding="utf-8")
        code, body = http("POST", f"{self.base}/v1/devices/sim-linux/fs/rename",
                          {"from": str(a), "to": str(b)}, token=self.token)
        self.assertEqual(code, 422, body)
        self.assertEqual(b.read_text(encoding="utf-8"), "b", "不许静默覆盖")

    def test_fs_ops_refuse_outside_root(self):
        for op, body in (("fs.mkdir", {"path": "/tmp/nope-dir"}),
                         ("fs.remove", {"path": "/tmp/nope.txt", "recursive": True}),
                         ("fs.rename", {"from": str(self.shared / "x.txt"), "to": "/tmp/x.txt"})):
            code, resp = http("POST", f"{self.base}/v1/devices/sim-linux/{op.replace('.', '/')}",
                              body, token=self.token)
            self.assertEqual(code, 422, f"{op} 应拒绝越界：{resp}")
            self.assertIn("不在授权目录内", resp.get("error", ""))


    def _raw(self, path: str) -> tuple[int, bytes]:
        try:
            with urllib.request.urlopen(self.base + path, timeout=15) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def _ensure_cert(self) -> None:
        """make_invite 需要母端证书；测试里现签一张（只用于跑邀请/自举链路）。"""
        cert = self.store.state / "mother-cert.pem"
        if cert.is_file():
            return
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(self.store.state / "mother-key.pem"), "-out", str(cert),
                        "-days", "1", "-subj", "/CN=tendril-test",
                        "-addext", "subjectAltName=IP:127.0.0.1"],
                       check=True, capture_output=True)

    def test_join_public_template_uses_entry_addresses(self):
        """邀请带入口 IP 时，自举脚本要逐个试并带 --resolve，不能只信 DNS。"""
        self._ensure_cert()  # 公网模式本身不需要自签证书，但测试沿用既有链路
        self.store.add("join-addrs", [], False)
        invite = M.make_invite(self.store, "join-addrs", self.base, 600, tls="system",
                               addrs=["185.40.234.75", "185.40.234.55"])
        code, ps = self._raw(f"/join/{invite}?os=windows")
        self.assertEqual(code, 200)
        ps = ps.decode("utf-8")
        for needle in ("$addrs = @('185.40.234.75','185.40.234.55')", "--resolve", "Get-FileHash"):
            self.assertIn(needle, ps)
        code, sh = self._raw(f"/join/{invite}?os=linux")
        self.assertEqual(code, 200)
        sh = sh.decode("utf-8")
        self.assertIn("ADDRS=('185.40.234.75' '185.40.234.55')", sh)
        self.assertNotIn("ADDRS=('185.40.234.75','185.40.234.55')", sh)  # bash 不能用逗号
        self.assertIn("--resolve", sh)
        # 没有地址时也不能渲染失败
        self.store.add("join-noaddrs", [], False)
        plain = M.make_invite(self.store, "join-noaddrs", self.base, 600, tls="system")
        code, _ = self._raw(f"/join/{plain}?os=windows")
        self.assertEqual(code, 200)

    def test_files_and_join_are_public(self):
        """装子端不需要母端令牌：/files 与 /join 免鉴权，且只放固定文件名。"""
        deliver = self.tmp / "deliver"
        deliver.mkdir(exist_ok=True)
        blob = b"MZ-fake-binary-payload"
        (deliver / "tendril-agent.exe").write_bytes(blob)
        (deliver / "tendril-agent-linux").write_bytes(blob)
        digest = hashlib.sha256(blob).hexdigest()
        for name in ("tendril-agent.exe", "tendril-agent-linux"):
            (deliver / f"{name}.sha256").write_text(f"{digest}  {name}\n")

        old = M.DELIVER
        M.DELIVER = deliver
        try:
            code, raw = self._raw("/files/agent.exe")
            self.assertEqual(code, 200)
            self.assertEqual(raw, blob, "投递的二进制必须原样返回")
            code, raw = self._raw("/files/agent.exe.sha256")
            self.assertIn(digest.encode(), raw)
            code, _ = self._raw("/files/nope.exe")
            self.assertEqual(code, 404, "未声明的文件名一律 404（只查表，不拼路径）")

            self._ensure_cert()
            invite = M.make_invite(self.store, "sim-linux", self.base, 600)
            code, raw = self._raw(f"/join/{invite}?os=linux")
            self.assertEqual(code, 200)
            body = raw.decode()
            self.assertIn("BEGIN CERTIFICATE", body, "自举脚本必须自带母端证书")
            self.assertIn("/files/agent-linux", body)
            self.assertIn("sha256sum", body)

            code, raw = self._raw(f"/join/{invite}?os=windows")
            self.assertEqual(code, 200)
            body = raw.decode()
            self.assertIn("curl.exe", body)
            self.assertIn("--install-user", body, "默认走免管理员的用户级安装")
            self.assertIn("--allow-exec", body, "要提示本地扩权的方式")
            self.assertNotIn("--install-user --invite $invite --root \"$env:USERPROFILE\" --allow-exec", body,
                             "默认安装不能自动开命令执行")
            self.assertIn("--install-service", body, "开机即在线作为可选项保留")

            expired = M.make_invite(self.store, "sim-linux", self.base, -10)
            code, _ = self._raw(f"/join/{expired}?os=linux")
            self.assertEqual(code, 410, "过期邀请必须拒绝")
        finally:
            M.DELIVER = old

    def test_bootstrap_scripts_are_ascii(self):
        """PowerShell 用 ANSI 码页解码 curl 的输出：脚本里有一个中文字符，
        多字节序列就可能吞掉结尾引号，报「字符串缺少终止符」。脚本必须纯 ASCII。"""
        self._ensure_cert()
        self.store.add("ascii-dev", [], False)
        for invite in (M.make_invite(self.store, "ascii-dev", self.base, 600),
                       M.make_invite(self.store, "ascii-dev", self.base, 600, tls="system",
                                     addrs=["1.2.3.4"])):
            code, body = self._raw(f"/join/{invite}?os=windows")
            self.assertEqual(code, 200)
            body.decode("ascii")  # 不是 ASCII 就直接抛，比断言更早暴露

    def test_join_exec_flag_grants_execution(self):
        """?exec=1 必须把 --allow-exec 写进脚本；不带时绝不能悄悄授权命令执行。"""
        self._ensure_cert()
        self.store.add("exec-flag", [], False)
        inv = M.make_invite(self.store, "exec-flag", self.base, 600)
        code, plain = self._raw(f"/join/{inv}")
        self.assertEqual(code, 200)
        self.assertNotIn(b"--allow-exec\r\n", plain)
        self.assertNotIn(b"--root \"$env:USERPROFILE\" --allow-exec", plain)
        code, granted = self._raw(f"/join/{inv}?exec=1")
        self.assertEqual(code, 200)
        self.assertIn(b"--allow-exec", granted)
        code, _ = self._raw(f"/join/{inv}?exec=0")
        self.assertEqual(code, 200)

    def test_invite_cli_prints_one_liner(self):
        self._ensure_cert()
        out = subprocess.run([sys.executable, str(ROOT / "mother" / "server.py"),
                              "--state", str(self.store.state), "invite", "sim-linux",
                              "--url", self.base, "--ttl", "60"],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        # 交给人的是一行短链接：长邀请串留在母端，避免手抄/被聊天工具打码
        self.assertIn("/j/", out.stdout)
        self.assertNotIn("/join/TENDRIL1:", out.stdout)
        self.assertIn("curl.exe -kfsSL", out.stdout, "内网自签证书：iwr 没有跳过校验的参数，必须用 curl -k")
        self.assertIn("--allow-exec", out.stdout)
        sid = re.search(r"/j/([A-Za-z0-9_-]+)", out.stdout).group(1)
        code, body = self._raw(f"/j/{sid}?os=linux")
        self.assertEqual(code, 200, "短链接必须能取到真正的自举脚本")
        self.assertIn(b"agent-linux", body)
        code, _ = self._raw("/j/doesnotexist")
        self.assertEqual(code, 404)


    def _bridge(self):
        """把 MCP 适配器指向测试母端，直接调它的工具函数。"""
        sys.path.insert(0, str(ROOT / "mcp"))
        import tendril_mcp
        tendril_mcp.MOTHER = self.base
        tendril_mcp.TOKEN_FILE = self.store.state / "control.token"
        tendril_mcp.CA_FILE = ""
        tendril_mcp._OPENER = None
        return tendril_mcp

    def test_bridge_push_pull_roundtrip(self):
        """push 到设备、pull 回来，字节与 sha256 都必须一致（含 CRLF 文本）。"""
        B = self._bridge()
        local = self.tmp / "roundtrip.txt"
        payload = "第一行\r\nsecond line\r\n".encode()
        local.write_bytes(payload)
        remote = str(self.shared / "roundtrip.txt")

        res = json.loads(B.call("push", {"device": "sim-linux", "local_path": str(local), "path": remote})["content"][0]["text"])
        self.assertTrue(res.get("ok"), res)
        self.assertEqual(res["size"], len(payload))
        self.assertEqual((self.shared / "roundtrip.txt").read_bytes(), payload, "设备侧字节必须一致")

        back = self.tmp / "back.txt"
        res2 = json.loads(B.call("pull", {"device": "sim-linux", "path": remote, "local_path": str(back)})["content"][0]["text"])
        self.assertTrue(res2.get("ok"), res2)
        self.assertEqual(back.read_bytes(), payload, "拉回来的字节必须一致")
        self.assertEqual(res2["sha256"], res["sha256"])

    def test_bridge_pull_refuses_overwrite_and_bad_size(self):
        B = self._bridge()
        existing = self.tmp / "existing.txt"
        existing.write_text("keep me", encoding="utf-8")
        res = json.loads(B.call("pull", {"device": "sim-linux", "path": str(self.shared / "hello.txt"),
                                        "local_path": str(existing)})["content"][0]["text"])
        self.assertIn("overwrite", res.get("error", ""))
        self.assertEqual(existing.read_text(encoding="utf-8"), "keep me")

        src = self.tmp / "src.txt"
        src.write_text("abc", encoding="utf-8")
        res2 = json.loads(B.call("push", {"device": "sim-linux", "local_path": str(src),
                                          "path": str(self.shared / "hello.txt"), "expect_size": 999})["content"][0]["text"])
        self.assertIn("拒绝覆盖", res2.get("error", ""))


    def test_pause_switch_stops_and_resumes_device(self):
        """母端开关：暂停后子端拿 403 paused、派发被拒 409；恢复后一切照旧。"""
        self.store.add("pause-dev", ["/tmp"], False)
        self.store.devices["pause-dev"]["enabled"] = True
        self.store.save()

        code, body = http("POST", f"{self.base}/v1/devices/pause-dev/enable",
                          {"enabled": False}, token=self.token)
        self.assertEqual(code, 200, body)
        self.assertFalse(body["enabled"])

        # 子端轮询必须是 403 + paused 标记（据此慢速重试，而不是当成"未批准"每秒撞）
        req = urllib.request.Request(f"{self.base}/agent/poll?wait=0",
                                     data=b"{}", method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Tendril-Device-Id", "pause-dev")
        req.add_header("X-Tendril-Device-Key", self.store.device("pause-dev")["secret"])
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=10)
        self.assertEqual(ctx.exception.code, 403)
        self.assertIn(b"paused", ctx.exception.read())

        # 派发必须当场被挡住，不能"任务排进队列等它自己恢复"
        code, body = http("POST", f"{self.base}/v1/devices/pause-dev/exec",
                          {"command": "echo hi"}, token=self.token)
        self.assertEqual(code, 409, body)
        self.assertIn("暂停", body.get("error", ""))

        code, body = http("GET", f"{self.base}/v1/devices", token=self.token)
        row = [d for d in body["devices"] if d["device"] == "pause-dev"][0]
        self.assertFalse(row["enabled"])

        code, body = http("POST", f"{self.base}/v1/devices/pause-dev/enable",
                          {"enabled": True}, token=self.token)
        self.assertEqual(code, 200, body)
        self.assertTrue(body["enabled"])
        # 缺字段必须 400，不能默认成"启用"悄悄把设备放出来
        code, body = http("POST", f"{self.base}/v1/devices/pause-dev/enable", {}, token=self.token)
        self.assertEqual(code, 400, body)

    def test_rate_limit_blocks_repeated_auth_failures(self):
        """公网暴露的前提：连续鉴权失败要被封，正常请求不受影响。"""
        old_fails = M.RATE.fails
        M.RATE.fails = 3
        M.RATE.hits.clear()
        M.RATE.banned.clear()
        try:
            codes = []
            for _ in range(4):
                code, _body = http("GET", f"{self.base}/v1/devices", token="wrong-token")
                codes.append(code)
            self.assertEqual(codes[:3], [401, 401, 401], f"前三次应是鉴权失败：{codes}")
            self.assertEqual(codes[3], 429, f"超过阈值必须封禁：{codes}")

            # 封禁只作用于"鉴权失败"的路径：持正确令牌的人不能被别人打出来的封禁连坐
            # （实测过：本机 UI 用错令牌轮询，把自己的控制面封了 120 秒）
            code, _body = http("GET", f"{self.base}/v1/devices", token=self.token)
            self.assertEqual(code, 200, "正确令牌在封禁期间仍应放行")
            # 但错误令牌必须继续被挡，否则限速形同虚设
            code, body = http("GET", f"{self.base}/v1/devices", token="wrong-token")
            self.assertEqual(code, 429, f"封禁期间错误令牌必须 429：{code}")
            self.assertIn("后再试", body.get("error", ""))
        finally:
            M.RATE.fails = old_fails
            M.RATE.hits.clear()
            M.RATE.banned.clear()

        code, _ = http("GET", f"{self.base}/v1/devices", token=self.token)
        self.assertEqual(code, 200, "封禁清除后应恢复正常")

    def test_fs_confinement_blocks_outside_paths(self):
        for bad in ("/etc/passwd", str(self.shared / ".." / "state" / "devices.json"),
                    "relative/path"):
            code, body = http("POST", f"{self.base}/v1/devices/sim-linux/fs/read",
                              {"path": bad}, token=self.token)
            self.assertEqual(code, 422, f"{bad} 未被拦截: {body}")
            self.assertIn("error", body)


class AgentResilienceTest(unittest.TestCase):
    """母端不可达时子端必须退避重连，而不是崩掉。"""

    def test_agent_survives_unreachable_mother(self):
        proc = subprocess.Popen(
            [sys.executable, str(ROOT / "agent" / "tendril_agent.py"),
             "--mother", "http://127.0.0.1:1", "--device", "ghost", "--secret", "x",
             "--root", tempfile.gettempdir()],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(4)
            self.assertIsNone(proc.poll(), "子端在母端不可达时退出了")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()



def https(method: str, url: str, body: dict | None, token: str | None, cafile: str,
          timeout: float = 15) -> tuple[int, dict]:
    import ssl as _ssl
    ctx = _ssl.create_default_context(cafile=cafile)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        return e.code, {}


class TlsTest(unittest.TestCase):
    """TLS 是必选项而不是可选项：子端没有母端证书时必须拒绝连接，而不是悄悄降级。"""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="tendril-tls-"))
        cls.shared = cls.tmp / "shared"
        cls.shared.mkdir()
        cls.store = M.Store(cls.tmp / "state")
        cls.secret = cls.store.add("tls-dev", [str(cls.shared)], allow_exec=True)
        cls.token = cls.store.token
        if M.init_tls(cls.store.state, ["127.0.0.1"]) != 0:
            raise unittest.SkipTest("openssl 不可用，跳过 TLS 测试")
        cls.cafile = str(cls.store.state / "mother-cert.pem")
        M.HUB = M.Hub(cls.store)

        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), M.Handler)
        cls.srv.daemon_threads = True
        cls.tls_enabled = M.maybe_wrap_tls(cls.srv, cls.store.state)
        cls.port = cls.srv.server_address[1]
        cls.base = f"https://127.0.0.1:{cls.port}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

        cls.agent = subprocess.Popen(
            [sys.executable, str(ROOT / "agent" / "tendril_agent.py"),
             "--mother", cls.base, "--device", "tls-dev", "--secret", cls.secret,
             "--ca", cls.cafile, "--root", str(cls.shared), "--allow-exec"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                code, body = https("GET", f"{cls.base}/v1/devices", None, cls.token, cls.cafile)
            except Exception:
                time.sleep(0.2)
                continue
            if code == 200 and body["devices"][0]["online"]:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("TLS 子端未在 15s 内上线")

    @classmethod
    def tearDownClass(cls):
        cls.agent.terminate()
        try:
            cls.agent.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.agent.kill()
        cls.srv.shutdown()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_plain_http_is_refused(self):
        with self.assertRaises(Exception):
            urllib.request.urlopen(f"http://127.0.0.1:{self.port}/v1/health", timeout=5)

    def test_agent_with_pinned_cert_works(self):
        code, body = https("POST", f"{self.base}/v1/devices/tls-dev/exec", {"command": "echo tls-ok"},
                           self.token, self.cafile)
        self.assertEqual(code, 202)
        tid = body["task_id"]
        deadline = time.time() + 15
        while time.time() < deadline:
            _, task = https("GET", f"{self.base}/v1/tasks/{tid}", None, self.token, self.cafile)
            if task.get("state") in ("succeeded", "failed"):
                break
            time.sleep(0.1)
        self.assertEqual(task["state"], "succeeded", task)
        self.assertIn("tls-ok", task["result"]["stdout"])

    def test_agent_without_ca_refuses_to_start(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "agent" / "tendril_agent.py"),
             "--mother", self.base, "--device", "tls-dev", "--secret", self.secret,
             "--root", str(self.shared)],
            capture_output=True, text=True, timeout=20,
        )
        self.assertNotEqual(proc.returncode, 0, "没有 --ca 竟然启动成功了")
        self.assertIn("--ca", proc.stderr)


class InviteTest(unittest.TestCase):
    """邀请：一行串里带地址/设备/密钥/证书，指纹不符或过期都必须拒绝。"""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="tendril-invite-"))
        cls.state = cls.tmp / "state"
        cls.state.mkdir()
        cls.store = M.Store(cls.state)
        cls.secret = cls.store.add("inv-dev", [str(cls.tmp)], allow_exec=True)
        cmd = ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
               "-nodes", "-keyout", str(cls.state / "mother-key.pem"),
               "-out", str(cls.state / "mother-cert.pem"), "-days", "1",
               "-subj", "/CN=tendril-test", "-addext", "subjectAltName=IP:127.0.0.1"]
        subprocess.run(cmd, capture_output=True, check=True)
        sys.path.insert(0, str(ROOT / "agent"))
        import tendril_agent as A
        cls.A = A

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_invite_roundtrip_and_fingerprint(self):
        inv = M.make_invite(self.store, "inv-dev", "https://127.0.0.1:8911", 600)
        self.assertTrue(inv.startswith("TENDRIL1:"))
        payload = self.A.parse_invite(inv)
        self.assertEqual(payload["device"], "inv-dev")
        self.assertEqual(payload["url"], "https://127.0.0.1:8911")
        self.assertEqual(payload["secret"], self.secret)
        self.assertIn("BEGIN CERTIFICATE", payload["cert"])
        self.assertEqual(payload["fp"], M.cert_fingerprint(payload["cert"]))

    def test_invite_expired_rejected(self):
        inv = M.make_invite(self.store, "inv-dev", "https://127.0.0.1:8911", -1)
        with self.assertRaises(SystemExit) as ctx:
            self.A.parse_invite(inv)
        self.assertIn("过期", str(ctx.exception))

    def test_invite_tampered_fingerprint_rejected(self):
        inv = M.make_invite(self.store, "inv-dev", "https://127.0.0.1:8911", 600)
        raw = inv[len("TENDRIL1:"):]
        payload = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        payload["fp"] = "0" * 64
        forged = "TENDRIL1:" + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
        with self.assertRaises(SystemExit) as ctx:
            self.A.parse_invite(forged)
        self.assertIn("指纹", str(ctx.exception))



class TaskSemanticsTest(unittest.TestCase):
    """排队中被取消的任务不能被执行；设备失联后任务只能算「结果未知」。"""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="tendril-sem-"))
        cls.store = M.Store(cls.tmp / "state")
        cls.secret = cls.store.add("ghost", [str(cls.tmp)], allow_exec=True)
        cls.token = cls.store.token
        M.HUB = M.Hub(cls.store)
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), M.Handler)
        cls.srv.daemon_threads = True
        cls.port = cls.srv.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        """每个用例从干净的队列/槽位开始：槽位是有状态的，残留会让下一个用例误判。"""
        with M.HUB.cond:
            M.HUB.pending.clear()
            M.HUB.active.clear()
            M.HUB.inflight.clear()
        with M.HUB.tasks.lock:
            M.HUB.tasks.items.clear()

    def _poll(self, wait: float = 0) -> tuple[int, dict]:
        req = urllib.request.Request(f"{self.base}/agent/poll?wait={wait}", data=b"{}", method="POST")
        req.add_header("X-Tendril-Device-Id", "ghost")
        req.add_header("X-Tendril-Device-Key", self.secret)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw) if raw else {}
            except ValueError:
                return e.code, {}

    def test_cancelled_queued_task_is_never_dispatched(self):
        self.assertEqual(self._poll()[0], 204)          # 先上线
        code, body = http("POST", f"{self.base}/v1/devices/ghost/exec",
                          {"command": "rm -rf /tmp/should-not-run"}, token=self.token)
        self.assertEqual(code, 202)
        tid = body["task_id"]
        code, verdict = http("POST", f"{self.base}/v1/tasks/{tid}/cancel", token=self.token)
        self.assertEqual(code, 202, verdict)
        # 关键：取消后不能再把这个任务本身下达出去。
        # 队列里可能先来的是 __cancel__ 控制消息（子端据此终止正在跑的任务），这是合法响应。
        seen = []
        for _ in range(2):
            code, item = self._poll()
            seen.append((code, item.get("kind")))
            # __cancel__ 携带同一个 task_id 是正常的；不能出现的是「真正的任务」被下达
            self.assertNotEqual(item.get("kind"), "exec", f"已取消的任务被下达: {item}")
        self.assertIn((204, None), seen, f"队列应已清空，实际: {seen}")
        code, task = http("GET", f"{self.base}/v1/tasks/{tid}", token=self.token)
        self.assertEqual(task["state"], "cancelled")

    def test_second_poller_is_not_blocked(self):
        """子端重启时必须能立刻接上：旧连接的 inflight 不能把设备锁住。"""
        import threading as _t
        results = []

        def first():
            results.append(self._poll(wait=2)[0])

        t1 = _t.Thread(target=first)
        t1.start()
        time.sleep(0.3)
        code, body = self._poll()
        t1.join()
        self.assertIn(code, (200, 204), f"第二个轮询被拒绝了: {code} {body}")



    def test_lost_dispatch_does_not_wedge_the_device(self):
        """任务派发给一个随后死掉的子端：槽位必须被回收，后续任务还能跑。"""
        self.assertEqual(self._poll()[0], 204)
        code, first = http("POST", f"{self.base}/v1/devices/ghost/exec",
                           {"command": "sleep 60", "timeout_s": 1}, token=self.token)
        code, item = self._poll()                     # 领走但不回执
        self.assertEqual(item["task_id"], first["task_id"])

        # 等过「任务超时 + 宽限」，再模拟后台巡检（等价于 sweeper 每 5s 跑一次）
        time.sleep(1 + M.TASK_GRACE + 0.8)
        reaped = M.HUB.tasks.reap_all(M.HUB.online, M.TASK_GRACE)
        for did, tid in reaped:
            M.HUB.end(did, tid)
        self.assertIn(("ghost", first["task_id"]), reaped, "无望的任务没有被回收")

        code, second = http("POST", f"{self.base}/v1/devices/ghost/exec",
                            {"command": "echo ok", "timeout_s": 10}, token=self.token)
        self.assertEqual(code, 202, second)
        code, item2 = self._poll(wait=1)
        self.assertEqual(code, 200, "槽位没释放，后续任务派不下去")
        self.assertEqual(item2["task_id"], second["task_id"])

    def test_one_execution_slot_per_device(self):
        """同一设备同时只派发一个执行类任务：第二条必须排队，不能并发跑。"""
        self.assertEqual(self._poll()[0], 204)                     # 上线
        code, first = http("POST", f"{self.base}/v1/devices/ghost/exec",
                           {"command": "sleep 5", "timeout_s": 30}, token=self.token)
        code2, second = http("POST", f"{self.base}/v1/devices/ghost/exec",
                             {"command": "echo second", "timeout_s": 30}, token=self.token)
        self.assertEqual(code, 202)
        self.assertEqual(code2, 202)

        code, item = self._poll()                                   # 领走第一条
        self.assertEqual(item["task_id"], first["task_id"])
        code, item2 = self._poll(wait=1)                            # 槽位被占，第二条不能下来
        self.assertEqual(code, 204, f"并发派发了第二个任务: {item2}")

        # 模拟子端回执（agent/result 走设备密钥，这里直接打到 Hub 上，等价）
        M.HUB.finish_task("ghost", first["task_id"], {"ok": True, "exit_code": 0, "command_ok": True})
        code, item3 = self._poll(wait=2)
        self.assertEqual(code, 200, "槽位释放后第二条应可派发")
        self.assertEqual(item3["task_id"], second["task_id"])

    def test_running_task_becomes_outcome_unknown_when_device_vanishes(self):
        self.assertEqual(self._poll()[0], 204)
        code, body = http("POST", f"{self.base}/v1/devices/ghost/exec",
                          {"command": "sleep 60", "timeout_s": 120}, token=self.token)
        tid = body["task_id"]
        code, item = self._poll()                       # 领走任务但不回执
        self.assertEqual(code, 200)
        self.assertEqual(item["task_id"], tid)
        # 设备不再 poll，等过在线窗口 + 宽限期
        time.sleep(M.ONLINE_WINDOW + M.TASK_GRACE + 1.5)
        code, task = http("GET", f"{self.base}/v1/tasks/{tid}", token=self.token)
        self.assertEqual(code, 200)
        self.assertEqual(task["state"], "interrupted", task)
        self.assertIn("结果未知", task["result"]["error"])


class BridgePayloadTest(unittest.TestCase):
    """桥接层不能把 cancelled 这类关键字段吞掉。"""

    def test_task_fields_cover_terminal_flags(self):
        sys.path.insert(0, str(ROOT / "mcp"))
        import tendril_mcp as B
        for field in ("cancelled", "state", "exit_code", "command_ok"):
            self.assertIn(field, B.TASK_FIELDS)
        for state in ("succeeded", "failed", "cancelled", "interrupted"):
            self.assertIn(state, B.TERMINAL)


if __name__ == "__main__":
    unittest.main(verbosity=2)
