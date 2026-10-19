"""Tests for task-4/scripts/phishing_sim.py.

Covered: self-contained template rendering (banner, local-only form
action), the phishing-indicator scoring engine, the .eml analyzer, the CLI,
and the loopback simulator end to end - including the request counters:
`requests_handled` must be the number of HTTP requests actually served,
not a copy of the submission count.
"""

import http.client
import io
import json
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path

TASK_DIR = Path(__file__).resolve().parents[1]
SCRIPTS = TASK_DIR / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import phishing_sim as sim  # noqa: E402

FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}


class RenderTests(unittest.TestCase):
    def test_template_list_is_sorted_and_complete(self):
        self.assertEqual(
            sim.available_templates(),
            ["fake-delivery", "fake-invoice", "fake-support"])

    def test_unknown_template_raises(self):
        with self.assertRaises(KeyError):
            sim.render_page("not-a-template")

    def test_every_template_renders_a_self_contained_page(self):
        for name in sim.available_templates():
            with self.subTest(template=name):
                page = sim.render_page(name)
                self.assertEqual(sim.find_external_resources(page), [])
                self.assertIn(sim.BANNER, page)
                self.assertIn('method="post"', page)
                self.assertIn(f'action="{sim.LOCAL_FORM_ACTION}"', page)
                self.assertTrue(page.startswith("<!doctype html>"))

    def test_reveal_page_explains_the_simulation(self):
        page = sim.render_reveal_page("fake-support", 8)
        self.assertIn("This was a simulation", page)
        self.assertIn("8-character string", page)
        self.assertEqual(sim.find_external_resources(page), [])

    def test_external_reference_detection_finds_protocol_relative_urls(self):
        page = ('<a href="https://evil.example/x">x</a>'
                '<img src="//cdn.example/y">')
        found = sim.find_external_resources(page)
        self.assertTrue(any("evil.example" in item for item in found))
        self.assertTrue(any("cdn.example" in item for item in found))


class AnalyzeTests(unittest.TestCase):
    def test_clean_text_has_no_indicator(self):
        result = sim.analyze_text("note", "Lunch is at noon in the usual room.")
        self.assertEqual(result["verdict"], "no indicator found")
        self.assertEqual(result["counts"], {"high": 0, "medium": 0, "low": 0})

    def test_urgency_vocabulary_scores_suspicious(self):
        result = sim.analyze_text(
            "mail", "URGENT: verify your account within 24 hours")
        self.assertEqual(result["verdict"], "suspicious")
        self.assertGreaterEqual(result["counts"]["medium"], 1)
        self.assertTrue(any(item["signal"] == "urgency vocabulary"
                            for item in result["indicators"]))

    def test_ip_link_scores_high(self):
        result = sim.analyze_text(
            "mail", "Sign in now: http://192.168.0.10/login")
        self.assertEqual(result["verdict"], "high risk")
        self.assertGreaterEqual(result["counts"]["high"], 1)
        self.assertTrue(any(item["signal"] == "IP-address link"
                            for item in result["indicators"]))

    def test_unencrypted_link_scores_medium(self):
        result = sim.analyze_text("mail", "Open http://intranet.local/page")
        self.assertTrue(any(item["signal"] == "unencrypted link"
                            for item in result["indicators"]))

    def test_embedded_at_scores_high(self):
        result = sim.analyze_text(
            "mail", "Use http://legit-bank.example@evil.example/ to log in")
        self.assertTrue(any(item["signal"] == "embedded @ in link"
                            for item in result["indicators"]))

    def test_display_text_hiding_destination_scores_high(self):
        markup = ('<a href="https://evil.example/login">'
                  "https://bank.example/login</a>")
        result = sim.analyze_text("mail", markup)
        self.assertTrue(any(
            item["signal"] == "display text hides the real destination"
            for item in result["indicators"]))

    def test_analyze_file_reads_an_eml(self):
        message = (
            "From: it-support@secure-mail-notice.example.com\r\n"
            "To: trainer@lab.example\r\n"
            "Subject: Action required: your mailbox will be suspended\r\n"
            "\r\n"
            "We detected unusual sign-in activity. Verify your account "
            "within 24 hours at http://192.168.0.10/unlock.\r\n")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "suspicious.eml"
            path.write_text(message, encoding="utf-8",
                            newline="")  # keep the bytes as authored
            result = sim.analyze_file(str(path))
            self.assertEqual(result["path"], str(path))
            self.assertEqual(result["bytes"], len(path.read_bytes()))
        self.assertEqual(result["source"], "suspicious.eml")
        self.assertEqual(result["verdict"], "high risk")
        self.assertGreaterEqual(result["counts"]["high"], 1)


class CliTests(unittest.TestCase):
    def test_list_templates(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = sim.main(["--list-templates"])
        self.assertEqual(code, 0)
        self.assertIn("fake-invoice", out.getvalue())

    def test_json_render_declares_no_external_resources(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = sim.main(["--template", "fake-delivery", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["external_resources"], [])
        self.assertEqual(payload["form"]["action"], "/submit")
        self.assertGreater(payload["bytes"], 0)
        self.assertIn("SIMULATED PHISHING EXERCISE", payload["banner"])

    def test_emit_writes_the_page(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "page.html"
            out = io.StringIO()
            with redirect_stdout(out):
                code = sim.main(["--template", "fake-support",
                                 "--emit", str(target), "--json"])
            self.assertEqual(code, 0)
            payload = json.loads(out.getvalue())
            self.assertEqual(payload["path"], str(target))
            page = target.read_text(encoding="utf-8")
        self.assertIn(sim.BANNER, page)


class ServeTests(unittest.TestCase):
    """Loopback end to end: real HTTP requests against serve()."""

    def _serve_and_drive(self, requests, **serve_kwargs):
        """Start serve() on a free port, perform (method, path, body)
        requests in order, and wait for the summary.

        With once=True the submission must be the last request: the server
        stops as soon as one submission has been accepted.
        """
        box: dict = {}
        bound = threading.Event()

        def ready(host: str, port: int) -> None:
            box["host"] = host
            box["port"] = port
            bound.set()

        def target() -> None:
            box["summary"] = sim.serve(
                "127.0.0.1", 0, ready=ready, timeout=8.0, **serve_kwargs)

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        self.assertTrue(bound.wait(5), "server did not bind in time")

        statuses: list[int] = []
        conn = http.client.HTTPConnection(box["host"], box["port"], timeout=5)
        try:
            for method, path, body in requests:
                headers = FORM_HEADERS if body is not None else {}
                conn.request(method, path, body=body, headers=headers)
                response = conn.getresponse()
                response.read()
                statuses.append(response.status)
        finally:
            conn.close()
        thread.join(timeout=12)
        self.assertFalse(thread.is_alive(), "serve() did not stop")
        return box["summary"], statuses

    @staticmethod
    def _submission(password: str = "hunter2") -> str:
        return ("template=fake-support"
                "&email=trainer%40lab.example"
                f"&password={password}")

    def test_request_counts_reflect_every_request_served(self):
        summary, statuses = self._serve_and_drive(
            [("GET", "/", None),
             ("GET", "/missing.png", None),
             ("POST", "/submit", self._submission())],
            once=True, template_name="fake-support")
        self.assertEqual(statuses, [200, 404, 200])
        self.assertEqual(summary["requests_handled"], 3)
        self.assertEqual(summary["page_views"], 1)
        self.assertEqual(summary["not_found"], 1)
        self.assertEqual(summary["submissions"], 1)
        self.assertEqual(len(summary["events"]), 1)

    def test_submission_is_measured_and_discarded(self):
        summary, statuses = self._serve_and_drive(
            [("POST", "/submit", self._submission())],
            once=True)
        self.assertEqual(statuses, [200])
        event = summary["events"][0]
        self.assertTrue(event["password_present"])
        self.assertEqual(event["password_length"], 7)
        self.assertTrue(event["email_present"])
        self.assertEqual(event["template"], "fake-support")
        self.assertNotIn("password", event.keys())
        self.assertNotIn("hunter2", json.dumps(summary))

    def test_post_to_the_wrong_path_counts_as_not_found(self):
        summary, statuses = self._serve_and_drive(
            [("POST", "/wrong-path", self._submission()),
             ("POST", "/submit", self._submission())],
            once=True)
        self.assertEqual(statuses, [404, 200])
        self.assertEqual(summary["requests_handled"], 2)
        self.assertEqual(summary["not_found"], 1)
        self.assertEqual(summary["submissions"], 1)

    def test_counters_start_fresh_for_every_run(self):
        first, _ = self._serve_and_drive(
            [("GET", "/", None), ("POST", "/submit", self._submission())],
            once=True)
        second, _ = self._serve_and_drive(
            [("GET", "/", None), ("POST", "/submit", self._submission())],
            once=True)
        self.assertEqual(first["requests_handled"], 2)
        self.assertEqual(second["requests_handled"], 2)
        self.assertEqual(second["page_views"], 1)
        self.assertEqual(second["submissions"], 1)

    def test_non_loopback_host_is_refused_before_binding(self):
        with self.assertRaises(ValueError):
            sim.serve("0.0.0.0", 0, timeout=1.0)


if __name__ == "__main__":
    unittest.main()
