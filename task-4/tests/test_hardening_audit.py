"""Tests for task-4/scripts/hardening_audit.py.

Scoring, netsh parsing and check construction are tested with fixtures.
The end-to-end class runs the real `quick` profile against this machine
once (every collector only reads configuration), so the suite costs a few
seconds of live PowerShell. Two failure-path tests prove that a non-zero
exit or a hung command becomes an AuditError/AuditTimeout instead of a
crash, and mocked collectors pin down the risky-port and RDP logic.
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

TASK_DIR = Path(__file__).resolve().parents[1]
SCRIPTS = TASK_DIR / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import hardening_audit as ha  # noqa: E402


class CheckTests(unittest.TestCase):
    def test_check_record_shape(self):
        item = ha.check("x_id", "A title", "fail", "detail here",
                        "critical", "do this")
        self.assertEqual(item["id"], "x_id")
        self.assertEqual(item["title"], "A title")
        self.assertEqual(item["status"], "fail")
        self.assertEqual(item["severity"], "critical")
        self.assertEqual(item["weight"], ha.SEVERITY_WEIGHT["critical"])
        self.assertEqual(item["detail"], "detail here")
        self.assertEqual(item["remediation"], "do this")

    def test_bad_status_is_rejected(self):
        with self.assertRaises(ValueError):
            ha.check("x", "T", "nope")

    def test_non_scored_status_forces_info_severity(self):
        for status in ("info", "skipped"):
            with self.subTest(status=status):
                item = ha.check("x", "T", status, "why", "critical")
                self.assertEqual(item["severity"], "info")


class ScoringTests(unittest.TestCase):
    def test_weighted_score(self):
        checks = [
            ha.check("a", "A", "pass", severity="critical"),
            ha.check("b", "B", "warn", severity="medium"),
            ha.check("c", "C", "fail", severity="high"),
            ha.check("d", "D", "info"),
            ha.check("e", "E", "skipped"),
        ]
        score, counts = ha.score_checks(checks)
        self.assertEqual(score, 58.3)
        self.assertEqual(counts, {"pass": 1, "warn": 1, "fail": 1,
                                  "info": 1, "skipped": 1})

    def test_no_scored_checks_yields_none(self):
        score, _ = ha.score_checks([ha.check("a", "A", "info")])
        self.assertIsNone(score)

    def test_bands(self):
        self.assertEqual(ha.score_band(None), "not scored")
        self.assertEqual(ha.score_band(90.0), "strong")
        self.assertEqual(ha.score_band(75.0), "good")
        self.assertEqual(ha.score_band(50.0), "needs attention")
        self.assertEqual(ha.score_band(49.9), "weak")

    def test_remediation_prioritises_failures_and_caps_at_ten(self):
        checks = []
        for index in range(12):
            status = "warn" if index % 2 else "fail"
            checks.append(ha.check(f"c{index:02}", f"T{index}", status,
                                   "d", "low", f"fix {index}"))
        checks.append(ha.check("noadvice", "N", "fail", "d", "critical", ""))
        ordered = ha.top_remediations(checks, limit=10)
        self.assertEqual(len(ordered), 10)
        self.assertEqual([item["priority"] for item in ordered],
                         list(range(1, 11)))
        self.assertTrue(all(item["status"] == "fail"
                            for item in ordered[:6]))
        self.assertNotIn("noadvice", [item["id"] for item in ordered])


class NetshParsingTests(unittest.TestCase):
    SAMPLE = """
Netsh advfirewall show allprofiles

Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound
LocalFirewallRules                    N/A

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Public Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       AllowInbound,AllowOutbound
"""

    def test_parses_three_profiles(self):
        profiles = ha._parse_netsh_firewall(self.SAMPLE)
        self.assertEqual(len(profiles), 3)
        by_name = {p["Name"]: p for p in profiles}
        self.assertTrue(by_name["Domain"]["Enabled"])
        self.assertTrue(by_name["Private"]["Enabled"])
        self.assertFalse(by_name["Public"]["Enabled"])
        self.assertEqual(by_name["Domain"]["DefaultInbound"], "Block")
        self.assertEqual(by_name["Public"]["DefaultInbound"], "Allow")
        self.assertEqual(by_name["Domain"]["Policy"],
                         "BlockInbound,AllowOutbound")

    def test_unrelated_text_yields_no_profiles(self):
        self.assertEqual(ha._parse_netsh_firewall("nothing here"), [])


class NormalisationTests(unittest.TestCase):
    def test_one_passes_dicts_through(self):
        self.assertEqual(ha._one({"a": 1}), {"a": 1})
        self.assertEqual(ha._one([{"a": 1}]), {"a": 1})

    def test_empty_list_raises(self):
        with self.assertRaises(ha.AuditError):
            ha._one([])

    def test_non_object_raises(self):
        with self.assertRaises(ha.AuditError):
            ha._one("text")


class PowerShellFailureTests(unittest.TestCase):
    def test_non_zero_exit_raises_audit_error(self):
        with self.assertRaises(ha.AuditError):
            ha._run_ps("exit 7", timeout=20)

    def test_timeout_raises_audit_timeout(self):
        with self.assertRaises(ha.AuditTimeout):
            ha._run_ps("Start-Sleep -Seconds 30", timeout=1)


class MockedCollectorTests(unittest.TestCase):
    def test_listening_ports_flags_external_risky_services(self):
        rows = [
            {"Port": 3306, "Address": "0.0.0.0", "Process": "mariadbd"},
            {"Port": 3306, "Address": "::", "Process": "mariadbd"},
            {"Port": 5985, "Address": "192.168.220.29", "Process": "wsmprv"},
            {"Port": 49152, "Address": "127.0.0.1", "Process": "labsvc"},
            {"Port": 443, "Address": "::1", "Process": "webfront"},
        ]
        with mock.patch.object(ha, "_ps_json", return_value=rows):
            checks = ha.collect_listening_ports(timeout=5)
        by_id = {c["id"]: c for c in checks}
        external = by_id["listening_external"]
        self.assertEqual(external["status"], "fail")
        self.assertEqual(external["severity"], "high")
        self.assertIn("3306/MySQL", external["detail"])
        self.assertIn("5985/WinRM-HTTP", external["detail"])
        self.assertNotIn("127.0.0.1", external["detail"])
        self.assertIn("5 listener", by_id["listening_summary"]["detail"])

    def test_loopback_only_listeners_pass(self):
        rows = [{"Port": 8080, "Address": "127.0.0.1", "Process": "lab"}]
        with mock.patch.object(ha, "_ps_json", return_value=rows):
            checks = ha.collect_listening_ports(timeout=5)
        by_id = {c["id"]: c for c in checks}
        self.assertEqual(by_id["listening_external"]["status"], "pass")

    def test_remote_services_rdp_failure_paths(self):
        data = {"WinRMStatus": "Running", "WinRMStartType": "Automatic",
                "RDPEnabled": True, "RDPport": 3389, "RDPNLA": False}
        with mock.patch.object(ha, "_ps_json", return_value=data):
            checks = ha.collect_remote_services(timeout=5)
        by_id = {c["id"]: c for c in checks}
        self.assertEqual(by_id["winrm_status"]["status"], "warn")
        self.assertEqual(by_id["rdp_enabled"]["status"], "fail")
        self.assertIn("3389", by_id["rdp_enabled"]["detail"])
        self.assertEqual(by_id["rdp_nla"]["status"], "fail")

    def test_firewall_fallback_path_when_netsh_cannot_be_parsed(self):
        profiles = [{"Name": "Domain", "Enabled": True,
                     "DefaultInbound": "NotConfigured"},
                    {"Name": "Private", "Enabled": False,
                     "DefaultInbound": "Allow"}]
        with mock.patch.object(ha, "_run_ps",
                               side_effect=ha.AuditError("netsh failed")), \
             mock.patch.object(ha, "_ps_json", return_value=profiles):
            checks = ha.collect_firewall_profiles(timeout=5)
        by_id = {c["id"]: c for c in checks}
        self.assertEqual(by_id["firewall_domain"]["status"], "pass")
        self.assertIn("Block", by_id["firewall_domain"]["detail"])
        self.assertEqual(by_id["firewall_private"]["status"], "fail")
        self.assertEqual(by_id["firewall_inbound"]["status"], "pass")


class QuickProfileEndToEndTests(unittest.TestCase):
    """One real run of the quick profile, shared by the assertions."""

    @classmethod
    def setUpClass(cls):
        cls.report = ha.run_audit(profile="quick", timeout=25.0)

    def test_report_shape_and_profile(self):
        report = self.report
        self.assertEqual(report["tool"], "hardening_audit.py")
        self.assertIn("READ-ONLY", report["mode"])
        self.assertEqual(report["profile"], "quick")
        names = [c["name"] for c in report["collectors"]]
        self.assertEqual(names, ["system_context", "firewall_profiles",
                                 "remote_services", "defender_status",
                                 "listening_ports"])
        for group in report["collectors"]:
            self.assertIn(group["status"], ("ok", "error", "timeout"))

    def test_summary_counts_are_consistent(self):
        summary = self.report["summary"]
        self.assertGreater(summary["checks_total"], 0)
        self.assertEqual(sum(summary["counts"].values()),
                         summary["checks_total"])
        self.assertEqual(
            summary["evaluated"],
            summary["counts"]["pass"] + summary["counts"]["warn"]
            + summary["counts"]["fail"])
        self.assertGreater(summary["elapsed_ms"], 0)
        if summary["score"] is None:
            self.assertEqual(summary["band"], "not scored")
        else:
            self.assertGreaterEqual(summary["score"], 0)
            self.assertLessEqual(summary["score"], 100)
            self.assertEqual(summary["band"], ha.score_band(summary["score"]))

    def test_every_check_is_well_formed(self):
        seen_ids = set()
        for group in self.report["collectors"]:
            for item in group["checks"]:
                self.assertIn(item["status"], ha.RESULT_STATUSES)
                self.assertTrue(item["id"])
                self.assertTrue(item["title"])
                self.assertNotIn(item["id"], seen_ids)
                seen_ids.add(item["id"])
        self.assertTrue(any(i.startswith("firewall_")
                            for i in seen_ids))

    def test_remediation_list_shape(self):
        remediation = self.report["remediation"]
        self.assertIsInstance(remediation, list)
        self.assertLessEqual(len(remediation), 10)
        for item in remediation:
            self.assertIn("action", item)
            self.assertIn("priority", item)
            self.assertIn(item["status"], ("fail", "warn"))

    def test_human_format_states_read_only(self):
        text = ha.format_human(self.report)
        self.assertIn("No system setting was changed by this audit.", text)
        self.assertIn("Score", text)

    def test_unknown_profile_raises(self):
        with self.assertRaises(ValueError):
            ha.run_audit(profile="paranoid")


if __name__ == "__main__":
    unittest.main()
