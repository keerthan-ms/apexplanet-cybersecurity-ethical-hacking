"""Task 5 tests: the SIEM must parse real logs and prove every alert.

Run:
    python -m unittest discover -s task-5/tests -v
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

TASK5 = Path(__file__).resolve().parents[1]
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(TASK5))

from siem.contract import read_access, read_security  # noqa: E402
from siem.rules import DEFAULT_CONFIG, analyze, load_config, merge_config  # noqa: E402

SAMPLES = TASK5 / "samples"
SECURITY = SAMPLES / "security.jsonl"
ACCESS = SAMPLES / "access.log"
DETECT = TASK5 / "siem" / "detect.py"

BASE = datetime(2026, 10, 19, 14, 0, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))


def ev(event: str, offset: int = 0, *, ip: str = "203.0.113.5", user: str | None = None,
       path: str = "/vuln/demo", detail: str = "") -> dict:
    row = {
        "ts": (BASE + timedelta(seconds=offset)).isoformat(),
        "ip": ip,
        "event": event,
        "path": path,
    }
    if detail:
        row["detail"] = detail
    if user:
        row["user"] = user
    return row


def req(offset: int = 0, *, ip: str = "203.0.113.5", path: str = "/vuln/demo",
        status: int = 200) -> dict:
    return {
        "ts": (BASE + timedelta(seconds=offset)).isoformat(),
        "ip": ip,
        "method": "POST",
        "path": path,
        "status": status,
        "ua": "test",
        "dur_ms": 3,
    }


def by_rule(report: dict) -> dict[str, dict]:
    return {alert["rule_id"]: alert for alert in report["alerts"]}


class ContractTests(unittest.TestCase):
    def test_seeded_security_events_parse(self) -> None:
        rows, stats = read_security(SECURITY)
        self.assertGreaterEqual(len(rows), 20)
        self.assertEqual(stats.valid, len(rows))
        self.assertEqual(stats.skipped, 0)
        self.assertEqual(stats.lines, len(rows))
        observed = {row["event"] for row in rows}
        self.assertTrue({
            "sqli_attempt", "sqli_blocked", "xss_reflected", "xss_stored",
            "xss_blocked", "csrf_missing", "csrf_blocked", "lfi_attempt",
            "auth_fail", "auth_success",
        } <= observed)
        for row in rows:
            self.assertEqual(row["ip"], "127.0.0.1")
            self.assertTrue(row["path"].startswith("/"))
            datetime.fromisoformat(row["ts"])

    def test_seeded_access_log_parses(self) -> None:
        rows, stats = read_access(ACCESS)
        self.assertGreaterEqual(len(rows), 20)
        self.assertEqual(stats.skipped, 0)
        for row in rows:
            self.assertIsInstance(row["status"], int)
            self.assertIsInstance(row["dur_ms"], int)

    def test_malformed_lines_are_skipped_not_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "security.jsonl"
            valid = ev("sqli_attempt", detail="' OR 1=1 --")
            path.write_text(
                json.dumps(valid) + "\n"
                + "{not json\n"
                + json.dumps({"ts": "2026-10-19T14:00:00+05:30", "ip": "x", "path": "/"}) + "\n"
                + json.dumps({**valid, "event": "made_up_event"}) + "\n"
                + "\n",
                encoding="utf-8",
            )
            rows, stats = read_security(path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(stats.valid, 1)
        self.assertEqual(stats.skipped, 3)
        self.assertTrue(stats.errors[0].startswith("line 2:"))


class RuleTests(unittest.TestCase):
    def test_blocked_events_are_mitigations_not_compromises(self) -> None:
        events = [
            ev("sqli_blocked", 1, user="admin"),
            ev("xss_blocked", 2),
            ev("csrf_blocked", 3, user="demo"),
            ev("lfi_attempt", 4, detail="blocked=1; input=../private/flag.txt"),
        ]
        report = analyze(events)
        self.assertEqual(report["summary"]["compromise_alerts"], 0)
        self.assertEqual(report["summary"]["mitigated_alerts"], 4)
        self.assertEqual(report["summary"]["mitigated_events"], 4)
        for alert in report["alerts"]:
            self.assertTrue(alert["mitigated"])
            self.assertEqual(alert["severity"], "low")
            self.assertEqual(alert["confidence"], "low")

    def test_benign_events_do_not_alert(self) -> None:
        events = [
            ev("auth_success", 1, user="demo"),
            ev("registration", 2, user="new"),
            ev("admin_action", 3, user="admin", detail="email changed"),
        ]
        report = analyze(events)
        self.assertEqual(report["alerts"], [])
        self.assertEqual(report["summary"]["benign_events"], 3)

    def test_sqli_thresholds(self) -> None:
        one = by_rule(analyze([ev("sqli_attempt", 1, user="admin")]))
        self.assertEqual(one["SQLI-001"]["severity"], "medium")

        six = [ev("sqli_attempt", i, user="admin") for i in range(6)]
        six_report = by_rule(analyze(six))
        self.assertEqual(six_report["SQLI-001"]["severity"], "critical")
        self.assertEqual(six_report["SQLI-001"]["count"], 6)
        self.assertEqual(len(six_report["SQLI-001"]["events"]), 6)

    def test_xss_reflected_and_stored_are_separate(self) -> None:
        reflected = by_rule(analyze([ev("xss_reflected", 1, detail="<script>x</script>")]))
        self.assertEqual(reflected["XSS-001"]["severity"], "high")

        stored = by_rule(analyze([ev("xss_stored", i, user="attacker") for i in range(3)]))
        self.assertEqual(stored["XSS-002"]["severity"], "critical")

    def test_csrf_missing_versus_blocked(self) -> None:
        missing = by_rule(analyze([ev("csrf_missing", 1, user="demo", detail="form=update_email")]))
        self.assertEqual(missing["CSRF-001"]["severity"], "high")
        self.assertFalse(missing["CSRF-001"]["mitigated"])

        blocked = by_rule(analyze([ev("csrf_blocked", 1, user="demo", detail="form=update_email")]))
        self.assertEqual(blocked["CSRF-002"]["severity"], "low")
        self.assertTrue(blocked["CSRF-002"]["mitigated"])

    def test_lfi_traversal_versus_blocked(self) -> None:
        attack = by_rule(analyze([ev("lfi_attempt", 1, detail="../private/flag.txt")]))
        self.assertEqual(attack["LFI-001"]["severity"], "high")
        self.assertFalse(attack["LFI-001"]["mitigated"])

        blocked = by_rule(analyze([
            ev("lfi_attempt", 1, detail="blocked=1; input=../private/flag.txt"),
        ]))
        self.assertEqual(blocked["LFI-002"]["severity"], "low")
        self.assertTrue(blocked["LFI-002"]["mitigated"])

    def test_auth_failure_threshold_and_window(self) -> None:
        below = analyze([ev("auth_fail", i, user="admin") for i in range(4)])
        self.assertNotIn("AUTH-001", by_rule(below))

        at_threshold = by_rule(analyze([ev("auth_fail", i, user="admin") for i in range(5)]))
        self.assertEqual(at_threshold["AUTH-001"]["severity"], "high")
        self.assertEqual(at_threshold["AUTH-001"]["count"], 5)

        ten = by_rule(analyze([ev("auth_fail", i, user="admin") for i in range(10)]))
        self.assertEqual(ten["AUTH-001"]["severity"], "critical")

        # Four failures, then four more 700 seconds later: two buckets below 5.
        split = [ev("auth_fail", i, user="admin") for i in range(4)]
        split += [ev("auth_fail", 700 + i, user="admin") for i in range(4)]
        self.assertNotIn("AUTH-001", by_rule(analyze(split)))

    def test_allowlist_suppresses_and_reports(self) -> None:
        events = [ev("sqli_attempt", 1, ip="198.51.100.9"), ev("xss_reflected", 2, ip="198.51.100.9")]
        report = analyze(events, allow_ips=["198.51.100.9"])
        self.assertEqual(report["alerts"], [])
        self.assertEqual(report["summary"]["suppressed_allowlisted"], 2)
        self.assertEqual(report["summary"]["analyzed_events"], 0)

    def test_min_severity_filters(self) -> None:
        # Three SQL injection events reach the configured high threshold; the
        # blocked CSRF event is low and must be filtered out for this view.
        events = [ev("sqli_attempt", i) for i in range(3)] + [ev("csrf_blocked", 3)]
        report = analyze(events, min_severity="high")
        self.assertEqual([a["rule_id"] for a in report["alerts"]], ["SQLI-001"])
        self.assertEqual(report["summary"]["filtered_out_by_severity"], 1)

    def test_access_correlation_and_5xx_bump(self) -> None:
        plain = by_rule(analyze([ev("sqli_attempt", 1)]))
        self.assertFalse(plain["SQLI-001"]["corroborated"])
        self.assertEqual(plain["SQLI-001"]["severity"], "medium")

        corroborated = by_rule(analyze(
            [ev("sqli_attempt", 1)],
            [req(1, status=500)],
        ))
        self.assertTrue(corroborated["SQLI-001"]["corroborated"])
        self.assertEqual(corroborated["SQLI-001"]["http_statuses"], [500])
        self.assertEqual(corroborated["SQLI-001"]["severity"], "high")
        self.assertEqual(corroborated["SQLI-001"]["confidence"], "high")

    def test_config_override(self) -> None:
        events = [ev("auth_fail", i, user="admin") for i in range(5)]
        stricter = analyze(events, config={"thresholds": {"auth_fail": {"high": 6}}})
        self.assertNotIn("AUTH-001", by_rule(stricter))
        self.assertEqual(merge_config(DEFAULT_CONFIG, {"thresholds": {"sqli": {"high": 2}}})["thresholds"]["sqli"]["critical"], 6)

    def test_alert_schema_matches_contract(self) -> None:
        report = analyze([ev("xss_reflected", 1, detail="<script>x</script>")])
        alert = report["alerts"][0]
        for key in ("rule_id", "severity", "title", "first_seen", "last_seen",
                    "count", "source_ip", "user", "events", "mitre", "recommendation"):
            self.assertIn(key, alert)
        self.assertIn(alert["severity"], ("low", "medium", "high", "critical"))
        self.assertEqual(alert["count"], len(alert["events"]))
        self.assertEqual(alert["events"][0]["event"], "xss_reflected")


class CliTests(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(DETECT), *args],
            cwd=str(REPO), capture_output=True, text=True, timeout=60,
        )

    def test_samples_json_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.json"
            result = self.run_cli("--samples", "--format", "json", "--out", str(out))
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(report["tool"], "apexplanet-mini-siem")
        self.assertEqual(report["sources"]["mode"], "samples")
        self.assertGreaterEqual(report["summary"]["alerts"], 5)
        self.assertGreater(report["summary"]["corroborated_alerts"], 0)
        self.assertTrue(report["false_positive_notes"])
        rules = {a["rule_id"] for a in report["alerts"]}
        self.assertTrue({"SQLI-001", "XSS-001", "CSRF-001", "LFI-001"} <= rules)
        self.assertIn("SQLI-002", rules)

    def test_fail_on_severity(self) -> None:
        result = self.run_cli("--samples", "--format", "json", "--fail-on", "high")
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL", result.stderr)

    def test_allowlist_can_clear_the_demo(self) -> None:
        result = self.run_cli(
            "--samples", "--format", "json", "--allow-ip", "127.0.0.1", "--fail-on", "low"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["alerts"], [])
        self.assertEqual(report["summary"]["suppressed_allowlisted"], report["summary"]["total_events"])

    def test_missing_input_exits_2(self) -> None:
        result = self.run_cli("--events", "does/not/exist.jsonl")
        self.assertEqual(result.returncode, 2)
        self.assertIn("not found", result.stderr)

    def test_malformed_input_still_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "security.jsonl"
            path.write_text(
                json.dumps(ev("sqli_attempt", 1)) + "\n"
                + "truncated-json{\n",
                encoding="utf-8",
            )
            result = self.run_cli("--events", str(path), "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["parsing"]["security"][0]["valid"], 1)
        self.assertEqual(report["parsing"]["security"][0]["skipped"], 1)
        self.assertEqual(report["alerts"][0]["rule_id"], "SQLI-001")

    def test_config_file_is_applied(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cfg.json"
            cfg.write_text(json.dumps({"thresholds": {"auth_fail": {"high": 6}}}), encoding="utf-8")
            result = self.run_cli("--samples", "--format", "json", "--config", str(cfg))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertNotIn("AUTH-001", {a["rule_id"] for a in report["alerts"]})

    def test_example_config_loads(self) -> None:
        config = load_config(TASK5 / "siem" / "config.example.json")
        self.assertIn("thresholds", config)
        self.assertIn("allow_ips", config)


if __name__ == "__main__":
    unittest.main(verbosity=2)
