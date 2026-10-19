"""Tests for task-2/scripts/portscan.py (no network beyond loopback)."""

import socket
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import portscan  # noqa: E402


class ParsePortSpecTests(unittest.TestCase):
    def test_single_range(self):
        self.assertEqual(portscan.parse_port_spec("1-10"), list(range(1, 11)))

    def test_comma_list(self):
        self.assertEqual(portscan.parse_port_spec("22,80,443"), [22, 80, 443])

    def test_mixed_with_whitespace_and_duplicates(self):
        self.assertEqual(portscan.parse_port_spec(" 1-3 , 22, 3 "),
                         [1, 2, 3, 22])

    def test_single_port_edges(self):
        self.assertEqual(portscan.parse_port_spec("1"), [1])
        self.assertEqual(portscan.parse_port_spec("65535"), [65535])

    def test_invalid_inputs_raise(self):
        invalid = ["", "   ", "abc", "0", "65536", "-1", "10-5", "1-2-3",
                   "80-", "-80", "80,,81", ",", "22;80", "8.0", "1--5"]
        for spec in invalid:
            with self.subTest(spec=spec):
                with self.assertRaises(ValueError):
                    portscan.parse_port_spec(spec)


class TopPortsTests(unittest.TestCase):
    def test_top_ports_count(self):
        ports = portscan.top_ports(5)
        self.assertEqual(len(ports), 5)
        self.assertEqual(ports, sorted(portscan.TOP_PORTS_TABLE[:5]))

    def test_top_ports_bounds(self):
        with self.assertRaises(ValueError):
            portscan.top_ports(0)
        with self.assertRaises(ValueError):
            portscan.top_ports(len(portscan.TOP_PORTS_TABLE) + 1)

    def test_table_is_well_formed(self):
        self.assertTrue(all(1 <= p <= 65535 for p in portscan.TOP_PORTS_TABLE))
        self.assertEqual(len(set(portscan.TOP_PORTS_TABLE)),
                         len(portscan.TOP_PORTS_TABLE), "duplicate ports in table")


class ResolvePortsTests(unittest.TestCase):
    def test_default_when_nothing_given(self):
        self.assertEqual(portscan.resolve_ports(),
                         portscan.parse_port_spec(portscan.DEFAULT_PORTS_SPEC))

    def test_spec_and_top_ports_are_exclusive(self):
        with self.assertRaises(ValueError):
            portscan.resolve_ports("1-10", 5)

    def test_top_n_wins_when_no_spec(self):
        self.assertEqual(portscan.resolve_ports(None, 7), portscan.top_ports(7))


class ServiceGuessTests(unittest.TestCase):
    def test_well_known_guesses(self):
        self.assertEqual(portscan.guess_service(80), "http")
        self.assertEqual(portscan.guess_service(443), "https")
        self.assertEqual(portscan.guess_service(3306), "mysql")

    def test_unknown_port_is_none(self):
        self.assertIsNone(portscan.guess_service(54321))


class BannerHelperTests(unittest.TestCase):
    def test_sanitize_strips_control_characters(self):
        raw = (b"SSH-2.0-OpenSSH_8.9\r\n\x00\x07\x1b[31mwarning\x7f\r\n"
               b"done\x0b")
        clean = portscan.sanitize_banner(raw)
        for forbidden in ("\x00", "\x07", "\x1b", "\r", "\x7f", "\x0b"):
            self.assertNotIn(forbidden, clean)
        self.assertIn("SSH-2.0-OpenSSH_8.9", clean)
        self.assertIn("warning", clean)
        for char in clean:
            self.assertTrue(char.isprintable() or char in "\n\t")

    def test_sanitize_handles_str_and_binary(self):
        self.assertEqual(portscan.sanitize_banner("plain text"), "plain text")
        # invalid utf-8 falls back to latin-1 rather than raising
        self.assertIsInstance(portscan.sanitize_banner(b"\xff\xfe\x00"), str)

    def test_mysql_handshake_parsing(self):
        payload = (b"\x0a" + b"8.0.39\x00" + (42).to_bytes(4, "little")
                   + b"\x00" * 10)
        packet = len(payload).to_bytes(3, "little") + b"\x00" + payload
        parsed = portscan.parse_mysql_handshake(packet)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["detected_protocol"], "mysql")
        self.assertEqual(parsed["server_version"], "8.0.39")
        self.assertEqual(parsed["connection_id"], 42)

    def test_mysql_handshake_rejects_non_mysql(self):
        self.assertIsNone(portscan.parse_mysql_handshake(b"HTTP/1.1 200 OK"))
        self.assertIsNone(portscan.parse_mysql_handshake(b"\x00" * 4))

    def test_http_response_parsing(self):
        raw = (b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"
               b"Content-Length: 2\r\n\r\nok")
        parsed = portscan.parse_http_response(raw)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["status_code"], 200)
        self.assertEqual(parsed["server_header"], "nginx/1.24.0")

    def test_http_parsing_rejects_non_http(self):
        self.assertIsNone(portscan.parse_http_response(b"\x16\x03\x01garbage"))


class RawSocketProbeTests(unittest.TestCase):
    def test_probe_reports_structure(self):
        outcome = portscan.probe_raw_sockets()
        for key in ("raw_tcp", "raw_icmp"):
            self.assertIn(key, outcome)
            self.assertIn("allowed", outcome[key])
            self.assertIsInstance(outcome[key]["allowed"], bool)
        self.assertTrue(outcome["notes"])
        self.assertTrue(all(isinstance(n, str) for n in outcome["notes"]))
        self.assertTrue(any("TCP connect" in note for note in outcome["notes"]))


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.open_port = self.listener.getsockname()[1]

        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        self.closed_port = probe.getsockname()[1]
        probe.close()

    def tearDown(self):
        self.listener.close()

    def test_open_port_is_reported_open(self):
        result = portscan.scan_port("127.0.0.1", self.open_port, timeout=2.0)
        self.assertEqual(result.state, "open")
        self.assertEqual(result.port, self.open_port)

    def test_closed_port_is_not_open(self):
        result = portscan.scan_port("127.0.0.1", self.closed_port, timeout=1.0)
        self.assertNotEqual(result.state, "open")
        self.assertIn(result.state, ("closed", "filtered", "unknown"))

    def test_scan_ports_end_to_end(self):
        results, elapsed = portscan.scan_ports(
            "127.0.0.1", [self.open_port, self.closed_port],
            timeout=1.0, workers=8)
        self.assertEqual(len(results), 2)
        self.assertGreaterEqual(elapsed, 0.0)
        by_port = {r.port: r for r in results}
        self.assertEqual(by_port[self.open_port].state, "open")
        self.assertNotEqual(by_port[self.closed_port].state, "open")
        counts = portscan.summarise(results)
        self.assertEqual(counts["total"], 2)
        self.assertEqual(sum(counts[k] for k in ("open", "closed", "filtered",
                                                 "unknown")), 2)

    def test_scan_attaches_service_guesses(self):
        results, _ = portscan.scan_ports("127.0.0.1", [self.open_port],
                                         timeout=1.0, workers=4)
        self.assertEqual(results[0].service_guess,
                         portscan.guess_service(self.open_port)
                         or portscan.SERVICE_GUESSES.get(self.open_port))


if __name__ == "__main__":
    unittest.main()
