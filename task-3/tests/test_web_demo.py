"""Task 3 tests: vulnerable routes really fail, hardened routes really hold.

The suite starts its own PHP built-in server on 127.0.0.1 with a temporary
SQLite database and log directory, so it never touches the demo server's data
and can run while ``run-demo.ps1`` is up on port 8091.

Run:
    python -m unittest discover -s task-3/tests -v
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime
from pathlib import Path

import requests

TASK_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(TASK_ROOT / "scripts"))

from demo_client import DemoClient, payloads  # noqa: E402

ALLOWED_EVENTS = {
    "auth_success", "auth_fail", "auth_lockout",
    "sqli_attempt", "sqli_blocked",
    "xss_reflected", "xss_stored", "xss_blocked",
    "lfi_attempt",
    "csrf_missing", "csrf_blocked",
    "registration", "admin_action",
}


def find_php() -> str:
    candidates = []
    if os.environ.get("APEX_PHP"):
        candidates.append(Path(os.environ["APEX_PHP"]))
    on_path = shutil.which("php")
    if on_path:
        candidates.append(Path(on_path))
    candidates.append(WORKSPACE / "_runtime" / "php" / "php.exe")
    candidates.append(WORKSPACE / "_runtime" / "php" / "php")
    for candidate in candidates:
        if candidate and candidate.exists():
            return str(candidate)
    raise unittest.SkipTest("PHP not found; set APEX_PHP or install the portable runtime")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class WebDemoTests(unittest.TestCase):
    proc: subprocess.Popen | None = None
    base_url = ""
    data_dir: Path
    tmp: tempfile.TemporaryDirectory

    @classmethod
    def setUpClass(cls) -> None:
        php = find_php()
        cls.tmp = tempfile.TemporaryDirectory(prefix="apex-task3-")
        cls.data_dir = Path(cls.tmp.name) / "data"
        cls.data_dir.mkdir(parents=True)
        port = free_port()
        cls.base_url = f"http://127.0.0.1:{port}"

        cls.stdout = open(Path(cls.tmp.name) / "php-stdout.log", "w", encoding="utf-8")
        cls.stderr = open(Path(cls.tmp.name) / "php-stderr.log", "w", encoding="utf-8")
        env = dict(os.environ)
        env["APEX_DEMO_DATA_DIR"] = str(cls.data_dir)
        cls.proc = subprocess.Popen(
            [
                php,
                "-d", "extension=pdo_sqlite",
                "-d", "extension=sqlite3",
                "-S", f"127.0.0.1:{port}",
                "-t", str(TASK_ROOT / "public"),
                str(TASK_ROOT / "public" / "router.php"),
            ],
            cwd=str(TASK_ROOT),
            env=env,
            stdout=cls.stdout,
            stderr=cls.stderr,
        )

        deadline = time.time() + 15
        while time.time() < deadline:
            if cls.proc.poll() is not None:
                break
            try:
                if requests.get(cls.base_url + "/", timeout=0.5).status_code == 200:
                    return
            except requests.RequestException:
                time.sleep(0.15)
        cls.stderr.flush()
        cls.stdout.flush()
        details = (Path(cls.tmp.name) / "php-stderr.log").read_text(encoding="utf-8", errors="replace")
        cls.tearDownClass()
        raise RuntimeError(f"PHP demo server did not become ready on {cls.base_url}\n{details}")

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.proc and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
                cls.proc.wait(timeout=5)
        for stream in ("stdout", "stderr"):
            handle = getattr(cls, stream, None)
            if handle and not handle.closed:
                handle.close()
        if hasattr(cls, "tmp"):
            cls.tmp.cleanup()

    def client(self) -> DemoClient:
        return DemoClient(self.base_url)

    # -- safety ------------------------------------------------------------
    def test_00_home_has_training_warning_and_loopback_only(self) -> None:
        response = self.client().get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("TRAINING ONLY", response.text)
        self.assertIn("never expose", response.text.lower())
        script = (TASK_ROOT / "scripts" / "run-demo.ps1").read_text(encoding="utf-8")
        self.assertIn('127.0.0.1:$Port', script)
        self.assertNotIn("0.0.0.0", script)

    # -- SQL injection -----------------------------------------------------
    def test_10_sqli_vulnerable_auth_bypass(self) -> None:
        response = self.client().login("vuln", payloads()["sqli_login"], "wrong-password")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Signed in as", response.text)
        self.assertIn("<strong>admin</strong>", response.text)

    def test_11_sqli_hardened_auth_rejected(self) -> None:
        response = self.client().login("secure", payloads()["sqli_login"], "wrong-password")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Login failed", response.text)
        self.assertNotIn("Signed in as", response.text)

    def test_12_sqli_union_extraction_and_parameterisation(self) -> None:
        vulnerable = self.client().search("vuln", payloads()["sqli_union"])
        self.assertIn("<td>999</td>", vulnerable.text)
        self.assertIn("<td>leaked</td>", vulnerable.text)

        hardened = self.client().search("secure", payloads()["sqli_union"])
        self.assertNotIn("<td>999</td>", hardened.text)
        self.assertNotIn("<td>leaked</td>", hardened.text)

    # -- XSS ---------------------------------------------------------------
    def test_20_xss_reflected_raw_versus_encoded(self) -> None:
        payload = payloads()["xss_reflected"]
        vulnerable = self.client().greet("vuln", payload)
        self.assertIn(payload, vulnerable.text)

        hardened = self.client().greet("secure", payload)
        self.assertNotIn(payload, hardened.text)
        self.assertIn("&lt;script&gt;", hardened.text)

    def test_21_xss_stored_raw_versus_encoded(self) -> None:
        marker = f"stored-{time.time_ns()}"
        stored = f"<svg onload=alert('stored')><!--{marker}-->"

        self.client().guestbook("vuln", "attacker", stored)
        vulnerable = self.client().get("/vuln/xss")
        self.assertIn(stored, vulnerable.text)

        secure_client = self.client()
        secure_client.guestbook("secure", "attacker", stored)
        hardened = secure_client.get("/secure/xss")
        self.assertNotIn("<svg onload=", hardened.text)
        self.assertIn("&lt;svg", hardened.text)
        self.assertIn(marker, hardened.text)

    # -- CSRF --------------------------------------------------------------
    def test_30_csrf_vulnerable_accepts_forged_post(self) -> None:
        client = self.client()
        response = client.change_email("vuln", "forged@training.local")
        self.assertEqual(response.status_code, 200)
        self.assertIn("no CSRF token was verified", response.text)
        self.assertIn("forged@training.local", client.account_page("vuln").text)

    def test_31_csrf_hardened_rejects_missing_and_forged_tokens(self) -> None:
        client = self.client()
        before = client.account_page("secure").text
        token = client.csrf_token("secure")
        self.assertGreaterEqual(len(token), 32)

        missing = client.change_email("secure", "attacker@training.local")
        self.assertEqual(missing.status_code, 403)
        self.assertIn("not changed", missing.text)

        forged = client.change_email("secure", "attacker@training.local", token="0" * 32)
        self.assertEqual(forged.status_code, 403)

        after = client.account_page("secure").text
        self.assertNotIn("attacker@training.local", after)
        current = before.split("Current email</span><b>")[1].split("</b>")[0]
        self.assertIn(current, after)

        accepted = client.change_email("secure", "validated@training.local", token=token)
        self.assertEqual(accepted.status_code, 200)
        self.assertIn("token verified", accepted.text)
        self.assertIn("validated@training.local", client.account_page("secure").text)

    # -- LFI ---------------------------------------------------------------
    def test_40_lfi_vulnerable_reads_private_fixture(self) -> None:
        response = self.client().lfi("vuln", payloads()["lfi_traversal"])
        self.assertEqual(response.status_code, 200)
        self.assertIn("APEX{TRAINING_ONLY_fake_flag_", response.text)

    def test_41_lfi_vulnerable_is_sandboxed_to_fixtures(self) -> None:
        response = self.client().lfi("vuln", payloads()["lfi_escape"])
        self.assertEqual(response.status_code, 403)
        self.assertIn("outside task-3/fixtures/", response.text)
        self.assertNotIn("# ApexPlanet", response.text)

        source = self.client().lfi("vuln", "../../app/bootstrap.php")
        self.assertEqual(source.status_code, 403)
        self.assertNotIn("APP_ROOT", source.text)

    def test_42_lfi_hardened_allowlist(self) -> None:
        blocked = self.client().lfi("secure", payloads()["lfi_traversal"])
        self.assertEqual(blocked.status_code, 403)
        self.assertNotIn("APEX{TRAINING_ONLY_fake_flag_", blocked.text)

        allowed = self.client().lfi("secure", "welcome.txt")
        self.assertEqual(allowed.status_code, 200)
        self.assertIn("public fixture", allowed.text)

    # -- log contract ------------------------------------------------------
    def test_90_security_log_matches_contract(self) -> None:
        log = self.data_dir / "security.jsonl"
        self.assertTrue(log.exists(), "security.jsonl was not created")
        rows = []
        for line in log.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            self.assertIn("ts", row)
            self.assertIn("ip", row)
            self.assertIn("event", row)
            self.assertIn("path", row)
            self.assertIn(row["event"], ALLOWED_EVENTS)
            datetime.fromisoformat(row["ts"])
            self.assertEqual(row["ip"], "127.0.0.1")
            self.assertTrue(row["path"].startswith("/"))
            rows.append(row)
        self.assertTrue(rows, "no security events were written")

        observed = {row["event"] for row in rows}
        required = {
            "sqli_attempt", "sqli_blocked",
            "xss_reflected", "xss_stored", "xss_blocked",
            "csrf_missing", "csrf_blocked",
            "lfi_attempt", "auth_fail", "auth_success",
        }
        self.assertTrue(required <= observed, f"missing events: {sorted(required - observed)}")

    def test_91_access_log_matches_contract(self) -> None:
        log = self.data_dir / "access.log"
        self.assertTrue(log.exists(), "access.log was not created")
        rows = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertTrue(rows)
        for row in rows:
            self.assertIn("ts", row)
            self.assertIn("ip", row)
            self.assertIn("method", row)
            self.assertIn("path", row)
            self.assertIn("status", row)
            self.assertIn("ua", row)
            self.assertIn("dur_ms", row)
            datetime.fromisoformat(row["ts"])
            self.assertIsInstance(row["status"], int)
            self.assertIsInstance(row["dur_ms"], int)
            self.assertGreaterEqual(row["dur_ms"], 0)
            self.assertTrue(row["ua"])
        self.assertTrue(any("/secure/sqli" in row["path"] for row in rows))


if __name__ == "__main__":
    unittest.main(verbosity=2)
