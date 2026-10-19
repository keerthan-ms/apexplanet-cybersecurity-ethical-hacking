"""Tests for task-2/scripts/http_security_audit.py.

A real http.server runs on an ephemeral loopback port with headers the test
controls; the audit is run against it, so nothing here touches the network
beyond 127.0.0.1.
"""

import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import http_security_audit as audit  # noqa: E402

CLEAN_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": ("default-src 'self'; object-src 'none'; "
                               "base-uri 'self'; frame-ancestors 'none'"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Set-Cookie": "session=clean; Path=/; Secure; HttpOnly; SameSite=Strict",
}


class HeaderHandler(BaseHTTPRequestHandler):
    """Serves /clean with the full header set and /dirty with none."""

    def version_string(self):
        return "apex-test/1.0"

    def send_response(self, code, message=None):
        # BaseHTTPRequestHandler would add a Server header; the test needs
        # full control over which headers exist.
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def do_HEAD(self):
        self.send_response(200)
        if self.path.rstrip("/") == "/clean":
            for name, value in CLEAN_HEADERS.items():
                self.send_header(name, value)
        else:
            self.send_header("Server", "EvilHTTPD/0.3")
            self.send_header("X-Powered-By", "SneakyPHP/8.1")
            self.send_header("Set-Cookie", "sid=dirty; Path=/")
            self.send_header("Set-Cookie", "tracking=1")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self.do_HEAD()

    def log_message(self, *_args):
        pass


def _find_check(result, check_id):
    for check in result["checks"]:
        if check["id"] == check_id:
            return check
    raise AssertionError(f"check {check_id} missing from result")


class AuditAgainstLiveServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), HeaderHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def test_clean_scores_higher_than_dirty(self):
        clean = audit.audit_url(f"http://127.0.0.1:{self.port}/clean")
        dirty = audit.audit_url(f"http://127.0.0.1:{self.port}/dirty")
        self.assertNotIn("error", clean)
        self.assertNotIn("error", dirty)
        self.assertGreater(clean["score"], dirty["score"])
        self.assertGreaterEqual(clean["score"], 90)
        self.assertLessEqual(dirty["score"], 15)

    def test_dirty_missing_headers_reported(self):
        dirty = audit.audit_url(f"http://127.0.0.1:{self.port}/dirty")
        for check_id in ("csp", "xcto", "clickjacking", "referrer",
                         "permissions", "coop", "disclosure", "cookies"):
            self.assertEqual(_find_check(dirty, check_id)["status"], "fail",
                             f"expected {check_id} to fail")
        # Absent HSTS over plain HTTP is graded warn, not fail: the header
        # would be ignored by browsers on an http:// response anyway.
        self.assertEqual(_find_check(dirty, "hsts")["status"], "warn")
        disclosure = _find_check(dirty, "disclosure")
        self.assertIn("EvilHTTPD", disclosure["explanation"])
        self.assertIn("SneakyPHP", disclosure["explanation"])

    def test_clean_response_passes_header_checks(self):
        clean = audit.audit_url(f"http://127.0.0.1:{self.port}/clean")
        for check_id in ("hsts", "csp", "xcto", "clickjacking", "referrer",
                         "permissions", "coop", "corp", "cookies",
                         "disclosure"):
            self.assertEqual(_find_check(clean, check_id)["status"], "pass",
                             f"expected {check_id} to pass")

    def test_csp_unsafe_inline_is_flagged(self):
        result = audit.analyse(
            "https://app.example/", 200,
            {"content-security-policy": ["script-src 'unsafe-inline'"]},
            https_available=None)
        check = _find_check(result, "csp")
        self.assertEqual(check["status"], "warn")
        self.assertIn("unsafe-inline", check["explanation"])

    def test_cookie_check_details(self):
        dirty = audit.audit_url(f"http://127.0.0.1:{self.port}/dirty")
        cookies = _find_check(dirty, "cookies")
        self.assertEqual(cookies["status"], "fail")
        self.assertIn("Secure", cookies["explanation"])
        self.assertIn("HttpOnly", cookies["explanation"])

    def test_http_when_https_available_fails(self):
        result = audit.analyse("http://app.example/", 200, {}, True)
        transport = _find_check(result, "transport")
        self.assertEqual(transport["status"], "fail")

    def test_plain_http_without_https_is_warn(self):
        result = audit.audit_url(f"http://127.0.0.1:{self.port}/clean")
        transport = _find_check(result, "transport")
        self.assertEqual(transport["status"], "warn")

    def test_snippets_cover_missing_headers(self):
        dirty = audit.audit_url(f"http://127.0.0.1:{self.port}/dirty")
        apache = dirty["snippets"]["apache"]
        nginx = dirty["snippets"]["nginx"]
        self.assertIn("Header always set Strict-Transport-Security", apache)
        self.assertIn("Header always set Content-Security-Policy", apache)
        self.assertIn("add_header X-Content-Type-Options", nginx)
        self.assertIn("server_tokens off", apache)

    def test_clean_snippet_has_no_header_lines(self):
        clean = audit.audit_url(f"http://127.0.0.1:{self.port}/clean")
        self.assertNotIn("Header always set", clean["snippets"]["apache"])
        self.assertNotIn("add_header", clean["snippets"]["nginx"])

    def test_strict_mode_downgrades_warnings(self):
        loose = audit.audit_url(f"http://127.0.0.1:{self.port}/clean")
        strict = audit.audit_url(f"http://127.0.0.1:{self.port}/clean",
                                 strict=True)
        self.assertLess(strict["score"], loose["score"])
        self.assertTrue(strict["strict"])


class CookieParsingTests(unittest.TestCase):
    def test_all_flags(self):
        cookie = audit.parse_set_cookie(
            "id=abc; Path=/app; Domain=.example.com; Secure; HttpOnly; "
            "SameSite=Strict")
        self.assertEqual(cookie["name"], "id")
        self.assertEqual(cookie["value"], "abc")
        self.assertTrue(cookie["secure"])
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["samesite"], "Strict")
        self.assertEqual(cookie["path"], "/app")
        self.assertEqual(cookie["domain"], ".example.com")

    def test_missing_flags(self):
        cookie = audit.parse_set_cookie("sid=1; Path=/")
        self.assertFalse(cookie["secure"])
        self.assertFalse(cookie["httponly"])
        self.assertIsNone(cookie["samesite"])

    def test_samesite_case_insensitive_attribute(self):
        cookie = audit.parse_set_cookie("a=b; samesite=lax; httponly")
        self.assertEqual(cookie["samesite"], "lax")
        self.assertTrue(cookie["httponly"])


class UrlAndBandTests(unittest.TestCase):
    def test_normalise_bare_host_port(self):
        self.assertEqual(audit.normalise_url("127.0.0.1:8091"),
                         "http://127.0.0.1:8091")

    def test_normalise_full_url(self):
        self.assertEqual(audit.normalise_url("https://example.com/x"),
                         "https://example.com/x")

    def test_normalise_rejects_other_schemes(self):
        for bad in ("ftp://example.com", "", "http://"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    audit.normalise_url(bad)

    def test_bands(self):
        self.assertEqual(audit.band_for(95), ("good", "info"))
        self.assertEqual(audit.band_for(80), ("adequate", "low"))
        self.assertEqual(audit.band_for(60), ("fair", "medium"))
        self.assertEqual(audit.band_for(30), ("poor", "high"))
        self.assertEqual(audit.band_for(5), ("critical", "critical"))

    def test_weights_sum_to_100(self):
        self.assertEqual(sum(weight for _, _, weight in audit.CHECK_WEIGHTS),
                         100)


if __name__ == "__main__":
    unittest.main()
