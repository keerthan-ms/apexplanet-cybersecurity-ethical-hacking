"""Tests for task-2/scripts/firewall_audit.py.

The end-to-end test runs the real audit against this machine's firewall
(--max-rules keeps the filter-lookup cost bounded). The degradation tests
prove that a missing cmdlet or a missing PowerShell executable is reported
in-band instead of raising.
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path

TASK_DIR = Path(__file__).resolve().parents[1]
SCRIPTS = TASK_DIR / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import firewall_audit as fw  # noqa: E402


class RunPowerShellDegradationTests(unittest.TestCase):
    def test_missing_cmdlet_degrades_in_band(self):
        result = fw.run_powershell("Get-DefinitelyNotARealCmdlet-84c2",
                                   timeout=30)
        self.assertFalse(result["ok"])
        self.assertIsNotNone(result["error"])
        self.assertIn("PowerShell failed", result["error"])

    def test_missing_executable_degrades_in_band(self):
        result = fw.run_powershell("Get-Date",
                                   executable="definitely-not-real.exe",
                                   timeout=30)
        self.assertFalse(result["ok"])
        self.assertIn("not found", result["error"])

    def test_valid_script_succeeds(self):
        result = fw.run_powershell("Write-Output '{\"x\": 1}'", timeout=30)
        self.assertTrue(result["ok"], result["error"])
        self.assertEqual(json.loads(result["stdout"]), {"x": 1})


class HelperTests(unittest.TestCase):
    def test_as_list_normalises_single_objects(self):
        self.assertEqual(fw._as_list(None), [])
        self.assertEqual(fw._as_list({"a": 1}), [{"a": 1}])
        self.assertEqual(fw._as_list([1, 2]), [1, 2])

    def test_parse_port_field_any(self):
        self.assertEqual(fw.parse_port_field("Any"), ("any", None))
        self.assertEqual(fw.parse_port_field("any"), ("any", None))

    def test_parse_port_field_sets_and_ranges(self):
        self.assertEqual(fw.parse_port_field("80, 443"), ("set", {80, 443}))
        self.assertEqual(fw.parse_port_field("8080-8082"),
                         ("set", {8080, 8081, 8082}))
        self.assertEqual(fw.parse_port_field("5040"), ("set", {5040}))

    def test_parse_port_field_named_set_is_unknown(self):
        kind, raw = fw.parse_port_field("PlayToDiscovery")
        self.assertEqual(kind, "unknown")
        self.assertEqual(raw, "PlayToDiscovery")

    def test_group_rules_counts(self):
        rules = [{"profile": "Public", "direction": "Inbound"},
                 {"profile": "Public", "direction": "Inbound"},
                 {"profile": "Any", "direction": "Inbound"}]
        groups = fw.group_rules(rules)
        self.assertEqual(groups["by_profile"], {"Any": 1, "Public": 2})
        self.assertEqual(groups["by_direction"], {"Inbound": 3})

    def test_permissive_rules_selection(self):
        rules = [
            {"name": "a", "display_name": "A", "profile": "Any",
             "protocol": "TCP", "local_port": "Any", "remote_address": "Any"},
            {"name": "b", "display_name": "B", "profile": "Public",
             "protocol": "TCP", "local_port": "80",
             "remote_address": "192.168.1.5"},
        ]
        permissive = fw.permissive_rules(rules)
        self.assertEqual([r["name"] for r in permissive], ["a"])


class EndToEndTests(unittest.TestCase):
    def test_json_run_degrades_gracefully_and_has_shape(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPTS / "firewall_audit.py"),
             "--json", "--max-rules", "10"],
            capture_output=True, text=True, timeout=180)
        self.assertEqual(proc.returncode, 0,
                         f"stderr: {proc.stderr[:500]}")
        result = json.loads(proc.stdout)

        self.assertTrue(result["read_only"])
        self.assertIn("READ-ONLY", result["elevation_note"])
        self.assertIn("administrator", result["elevation_note"])
        self.assertIsInstance(result["profiles"], list)
        self.assertIsInstance(result["permissive_rules"], list)
        self.assertIsInstance(result["listening_exposed"], list)
        self.assertIsInstance(result["degraded"], list)

        rules_section = result["inbound_allow_rules"]
        self.assertIn("count", rules_section)
        self.assertIn("by_profile", rules_section)
        self.assertIn("by_direction", rules_section)
        self.assertIsInstance(rules_section["rules"], list)

        listeners = result["listening_ports"]
        self.assertIsInstance(listeners["tcp"], list)
        self.assertIsInstance(listeners["udp"], list)

        # On this machine the cmdlets exist, so sections should be populated;
        # if a future environment lacks them the run must still succeed and
        # explain itself in `degraded` rather than crash (asserted above).
        if rules_section["count"] > 0 and "unavailable" not in " ".join(
                result["degraded"]).lower():
            self.assertGreater(rules_section["with_details"], 0)
            self.assertTrue(result["profiles"])
            self.assertTrue(any(p.get("name") for p in result["profiles"]))


if __name__ == "__main__":
    unittest.main()
