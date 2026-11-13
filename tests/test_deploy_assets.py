"""母端常驻脚本的结构检查（Linux/macOS 实跑安装脚本，Windows 只做内容检查）。"""
from __future__ import annotations

import os
import plistlib
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"


def run(script: str, tmp: str, extra_env: dict | None = None):
    env = {**os.environ, "HOME": tmp, **(extra_env or {})}
    env.pop("XDG_CONFIG_HOME", None)
    return subprocess.run(["bash", str(DEPLOY / script), "--no-start"], cwd=ROOT, env=env,
                          capture_output=True, text=True)


class DeployAssetsTest(unittest.TestCase):
    def test_shell_scripts_parse(self):
        for name in ("install-mother-linux.sh", "install-mother-macos.sh"):
            r = subprocess.run(["bash", "-n", str(DEPLOY / name)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f"{name}: {r.stderr}")

    def test_linux_installer_writes_systemd_unit(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = run("install-mother-linux.sh", tmp,
                    {"TENDRIL_SKIP_SYSTEMCTL": "1", "TENDRIL_PORT": "8912",
                     "TENDRIL_HOST": "127.0.0.1", "TENDRIL_STATE": f"{tmp}/state"})
            self.assertEqual(r.returncode, 0, r.stderr)
            unit = Path(tmp) / ".config/systemd/user/tendril-mother.service"
            self.assertTrue(unit.is_file(), r.stdout + r.stderr)
            text = unit.read_text()
            for needle in ("[Service]", "ExecStart=", "server.py serve",
                           "--host 127.0.0.1", "--port 8912",
                           "TENDRIL_STATE=" + f"{tmp}/state", "Restart=on-failure"):
                self.assertIn(needle, text)

    def test_macos_installer_writes_parseable_plist(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = run("install-mother-macos.sh", tmp,
                    {"TENDRIL_SKIP_LAUNCHCTL": "1", "TENDRIL_PORT": "8913"})
            self.assertEqual(r.returncode, 0, r.stderr)
            plist = Path(tmp) / "Library/LaunchAgents/ai.tendril.mother.plist"
            self.assertTrue(plist.is_file(), r.stdout + r.stderr)
            data = plistlib.loads(plist.read_bytes())
            self.assertEqual(data["Label"], "ai.tendril.mother")
            self.assertTrue(data["KeepAlive"] and data["RunAtLoad"])
            args = data["ProgramArguments"]
            self.assertIn("server.py", " ".join(args))
            self.assertIn("8913", args)
            self.assertIn("TENDRIL_STATE", data["EnvironmentVariables"])

    def test_windows_installer_has_expected_cmdlets(self):
        text = (DEPLOY / "install-mother-windows.ps1").read_text(encoding="utf-8")
        for needle in ("Register-ScheduledTask", "Unregister-ScheduledTask",
                       "New-ScheduledTaskTrigger -AtLogOn",
                       "ExecutionTimeLimit ([TimeSpan]::Zero)",
                       "TENDRIL_STATE", "mother.log"):
            self.assertIn(needle, text)


if __name__ == "__main__":
    unittest.main()
