"""母端在 Windows / macOS / Linux 上的可运行性：平台相关的小单元必须成立。

不替代 tests/test_mother.py（那套要起进程、偏 POSIX），这里只验平台适配点：
状态目录、openssl 探测、本机 IP、证书生成与加载。
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import ssl
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mother import server as M  # noqa: E402


class PlatformTest(unittest.TestCase):
    def test_state_env_override_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"TENDRIL_STATE": tmp}):
                self.assertEqual(M.default_state(), Path(tmp))

    def test_state_default_is_absolute_and_platform_specific(self):
        env = {k: v for k, v in os.environ.items() if k != "TENDRIL_STATE"}
        with mock.patch.dict(os.environ, env, clear=True):
            p = M.default_state()
        self.assertTrue(p.is_absolute())
        if os.name == "nt":
            self.assertEqual(p.name, "Tendril")
            self.assertIn("appdata", str(p).lower().replace("\\", "/"))
        elif sys.platform == "darwin":
            self.assertIn("Library/Application Support", str(p))
        else:
            self.assertTrue(str(p).endswith("tendril"))

    def test_find_openssl_returns_existing_path(self):
        found = M.find_openssl()
        if found is not None:
            self.assertTrue(Path(found).is_file(), found)

    def test_local_ipv4s_are_plain_ips(self):
        for ip in M.local_ipv4s():
            self.assertFalse(ip.startswith("127."))
            self.assertIsInstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)

    @unittest.skipUnless(M.find_openssl(), "没有 openssl，跳过证书生成")
    def test_init_tls_generates_loadable_cert(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            rc = M.init_tls(state, ["localhost", "127.0.0.1"])
            self.assertEqual(rc, 0)
            cert, key = state / "mother-cert.pem", state / "mother-key.pem"
            self.assertTrue(cert.is_file() and key.is_file())
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(cert), str(key))   # 能加载即结构有效
            der = ssl.PEM_cert_to_DER_cert(cert.read_text())
            self.assertEqual(M.cert_fingerprint(cert.read_text()), hashlib.sha256(der).hexdigest())


if __name__ == "__main__":
    unittest.main()
