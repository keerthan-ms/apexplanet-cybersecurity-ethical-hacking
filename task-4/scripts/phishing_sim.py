#!/usr/bin/env python3
"""Phishing awareness simulator (Task 4: security awareness).

Usage:
    python task-4/scripts/phishing_sim.py                     # print the page
    python task-4/scripts/phishing_sim.py --list-templates
    python task-4/scripts/phishing_sim.py --template fake-support --json
    python task-4/scripts/phishing_sim.py --template fake-invoice --emit page.html
    python task-4/scripts/phishing_sim.py --template fake-delivery --serve --timeout 60
    python task-4/scripts/phishing_sim.py --analyze suspicious.eml --json

What this tool does
    Renders a self-contained, deliberately suspicious HTML page (three
    built-in templates) for security-awareness training, optionally serves
    it on 127.0.0.1 so a training group can be shown the real flow, and can
    score a message file against common phishing indicators.

Safety rules baked into the code, not just the documentation
    * Every page carries a visible banner naming it as a simulation.
    * The credential form only ever posts to the local path "/submit";
      render_page() refuses to emit a page that references any external
      resource, so nothing in the page can phone home.
    * The HTTP server binds loopback only - any other --host is rejected.
    * Submitted values are discarded after measuring them: only the UTC
      time, whether a value was typed and its length are recorded. No
      password, session or IP address is ever written to disk.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable

SCRIPT_NAME = "phishing_sim.py"
BANNER = ("SIMULATED PHISHING EXERCISE - AUTHORIZED SECURITY AWARENESS LAB ONLY. "
          "Never enter real credentials on a page you have not verified.")
LOCAL_FORM_ACTION = "/submit"
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
DEFAULT_TIMEOUT = 60.0

INDICATOR_KEYWORDS = (
    "urgent", "immediately", "within 24 hours", "suspended", "suspend",
    "verify your account", "confirm your password", "unusual sign-in",
    "unusual activity", "final notice", "expire", "expires", "gift card",
    "wire transfer", "unlock your account", "act now",
)

EXTERNAL_REF = re.compile(
    r"""(?:href|src|action)\s*=\s*["']\s*(https?:)?//[^"']*""",
    flags=re.IGNORECASE)
URL_IN_TEXT = re.compile(r"https?://[^\s\"'<>]+", flags=re.IGNORECASE)
HREF_ATTR = re.compile(r"""<a\b[^>]*\bhref\s*=\s*["']([^"']+)["']""",
                       flags=re.IGNORECASE)
ANCHOR_TEXT = re.compile(r"""<a\b[^>]*>(.*?)</a>""",
                         flags=re.IGNORECASE | re.DOTALL)


class ExternalResourceError(ValueError):
    """A page tried to reference something outside this machine."""


# ---------------------------------------------------------------- templates --

TEMPLATES: dict[str, dict] = {
    "fake-support": {
        "scenario": "Password reset lure from a help-desk impersonation",
        "sender": "IT Support Desk <it-support@secure-mail-notice.example.com>",
        "subject": "Action required: your mailbox will be suspended",
        "preheader": "We detected unusual sign-in activity on your account.",
        "cta": "Restore my mailbox",
        "body": (
            "<p>Dear user,</p>"
            "<p>We detected an <strong>unusual sign-in</strong> from an "
            "unrecognised device. Your mailbox is scheduled for "
            "<strong>suspension within 24 hours</strong> unless you confirm "
            "your password now.</p>"
            "<p>This link will <strong>expire</strong> after one hour.</p>"),
        "indicators": [
            {"signal": "look-alike sender domain",
             "why": "secure-mail-notice.example.com is not the corporate mail domain"},
            {"signal": "urgency and threat of suspension",
             "why": "pressure stops the reader from checking the request"},
            {"signal": "password requested on a web page",
             "why": "a help desk never needs a user's password"},
            {"signal": "artificial deadline",
             "why": "'expires after one hour' discourages verification"},
        ],
    },
    "fake-invoice": {
        "scenario": "Invoice attachment lure for the finance team",
        "sender": "Billing Department <billing@invoices-review.example.net>",
        "subject": "Overdue invoice INV-20418 - final notice",
        "preheader": "Payment is now 41 days overdue.",
        "cta": "Open the invoice",
        "body": (
            "<p>Hello,</p>"
            "<p>Invoice <strong>INV-20418</strong> is 41 days overdue. "
            "Attached is the final notice; please open the document and "
            "confirm the payment details <strong>immediately</strong>.</p>"
            "<p>If payment is not received today we will begin recovery "
            "procedures.</p>"),
        "indicators": [
            {"signal": "unexpected attachment",
             "why": "invoices that arrive unannounced are a common malware carrier"},
            {"signal": "payment-detail changes",
             "why": "attackers redirect transfers to their own account"},
            {"signal": "third-party look-alike domain",
             "why": "invoices-review.example.net imitates a supplier portal"},
            {"signal": "recovery threat",
             "why": "fear of consequences pushes staff to act without approval"},
        ],
    },
    "fake-delivery": {
        "scenario": "Parcel redelivery lure aimed at everyone",
        "sender": "Delivery Notices <no-reply@parcel-redelivery.example.org>",
        "subject": "Your package could not be delivered",
        "preheader": "A small redelivery fee is required to release the parcel.",
        "cta": "Reschedule delivery",
        "body": (
            "<p>Your parcel could not be delivered because the address was "
            "incomplete.</p>"
            "<p>Pay the redelivery fee of &pound;1.99 and confirm your card "
            "details to release it. The parcel will be returned to sender "
            "<strong>after 24 hours</strong>.</p>"),
        "indicators": [
            {"signal": "small fee for a redelivery",
             "why": "card harvesting is usually disguised as a tiny charge"},
            {"signal": "brand impersonation",
             "why": "the sender domain is unrelated to any carrier"},
            {"signal": "countdown pressure",
             "why": "'returned after 24 hours' rewards fast, unchecked action"},
            {"signal": "no tracking number",
             "why": "real notices quote the consignment reference"},
        ],
    },
}


def available_templates() -> list[str]:
    """Names accepted by --template."""
    return sorted(TEMPLATES)


def _page_shell(title: str, inner: str, footer: str = "") -> str:
    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{html.escape(title)}</title>\n"
        "<style>\n"
        "body{margin:0;font:16px/1.5 Segoe UI,Roboto,Arial,sans-serif;"
        "background:#eef1f5;color:#1b1f24}\n"
        ".banner{background:#7a1f1f;color:#fff;text-align:center;"
        "padding:.75rem 1rem;font-weight:600;letter-spacing:.02em}\n"
        ".card{max-width:34rem;margin:2rem auto;background:#fff;"
        "border:1px solid #d6dbe2;border-radius:8px;padding:1.5rem;"
        "box-shadow:0 1px 3px rgba(0,0,0,.08)}\n"
        ".meta{background:#f6f8fa;border-left:3px solid #8a94a6;"
        "padding:.6rem .8rem;font-size:.92rem;color:#414b58}\n"
        "label{display:block;margin:.8rem 0 .2rem;font-size:.9rem}\n"
        "input{width:100%;padding:.5rem .6rem;border:1px solid #c3cad3;"
        "border-radius:4px;box-sizing:border-box}\n"
        "button{margin-top:1rem;width:100%;padding:.6rem;border:0;border-radius:4px;"
        "background:#1f5fbf;color:#fff;font-size:1rem;cursor:pointer}\n"
        ".note{font-size:.85rem;color:#5a6472;margin-top:1rem}\n"
        ".flags li{margin:.35rem 0}\n"
        "</style>\n</head>\n<body>\n"
        f'<div class="banner">{html.escape(BANNER)}</div>\n'
        f"{inner}\n"
        f"{footer}\n"
        "</body>\n</html>\n"
    )


def find_external_resources(page: str) -> list[str]:
    """Every href/src/action that points outside this machine."""
    return sorted({match.group(0) for match in EXTERNAL_REF.finditer(page)})


def render_page(template_name: str) -> str:
    """Render one template as a fully self-contained HTML page."""
    if template_name not in TEMPLATES:
        raise KeyError(f"unknown template: {template_name}")
    spec = TEMPLATES[template_name]
    flag_items = "".join(
        f"<li><strong>{html.escape(item['signal'])}</strong> - "
        f"{html.escape(item['why'])}</li>"
        for item in spec["indicators"])
    inner = (
        '<div class="card">\n'
        '<p class="meta">'
        f"<strong>From:</strong> {html.escape(spec['sender'])}<br>\n"
        f"<strong>Subject:</strong> {html.escape(spec['subject'])}</p>\n"
        f"<p>{html.escape(spec['preheader'])}</p>\n"
        f"{spec['body']}\n"
        f'<form method="post" action="{LOCAL_FORM_ACTION}">\n'
        '<input type="hidden" name="template" value="'
        f'{html.escape(template_name, quote=True)}">\n'
        "<label for=\"email\">Email address</label>\n"
        '<input id="email" name="email" type="email" autocomplete="off" '
        'placeholder="you@example.com" required>\n'
        "<label for=\"password\">Password</label>\n"
        '<input id="password" name="password" type="password" '
        'autocomplete="off" placeholder="Password" required>\n'
        f"<button type=\"submit\">{html.escape(spec['cta'])}</button>\n"
        "</form>\n"
        '<p class="note">Simulated page served from this lab only. '
        "Nothing you type here is stored.</p>\n"
        "</div>"
    )
    footer = (
        '<div class="card">\n'
        "<h2>What to look for</h2>\n"
        '<ul class="flags">'
        f"{flag_items}</ul>\n"
        "</div>"
    )
    page = _page_shell(spec["subject"], inner, footer)
    external = find_external_resources(page)
    if external:
        raise ExternalResourceError(
            "page references external resources: " + ", ".join(external))
    return page


def render_reveal_page(template_name: str, password_length: int) -> str:
    """Page shown after a submission: explains the exercise, keeps no secret."""
    spec = TEMPLATES[template_name]
    flag_items = "".join(
        f"<li><strong>{html.escape(item['signal'])}</strong> - "
        f"{html.escape(item['why'])}</li>"
        for item in spec["indicators"])
    inner = (
        '<div class="card">\n'
        "<h2>This was a simulation</h2>\n"
        "<p>The message above was created for training. The form posted to "
        "this machine only, and the value you typed was discarded "
        f"immediately (recorded as: a {password_length}-character string, "
        "nothing else).</p>\n"
        "<h3>Red flags in this template</h3>\n"
        f'<ul class="flags">{flag_items}</ul>\n'
        '<p class="note">If you would have clicked: pause, check the sender '
        "domain, and report the message.</p>\n"
        "</div>"
    )
    return _page_shell("Simulation result", inner)


def find_urls(text: str) -> list[str]:
    """Plain-text or HTML anchors that contain an absolute URL."""
    urls = list(URL_IN_TEXT.finditer(text))
    hrefs = HREF_ATTR.findall(text)
    found = [match.group(0) for match in urls]
    found.extend(href for href in hrefs if href.lower().startswith(("http://", "https://")))
    return found


def analyze_text(label: str, text: str) -> dict:
    """Score one message against the built-in phishing indicators."""
    indicators: list[dict] = []

    def add(severity: str, signal: str, why: str) -> None:
        indicators.append({"severity": severity, "signal": signal, "why": why})

    lowered = text.lower()
    hits = sorted({word for word in INDICATOR_KEYWORDS if word in lowered})
    if hits:
        add("medium", "urgency vocabulary",
            "matched: " + ", ".join(hits))
    for url in find_urls(text):
        host = ""
        match = re.match(r"https?://([^/@\s]+)", url, flags=re.IGNORECASE)
        if match:
            host = match.group(1)
        if url.lower().startswith("http://"):
            add("medium", "unencrypted link", url)
        if host and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host.split(":")[0]):
            add("high", "IP-address link", url)
        if "@" in url:
            add("high", "embedded @ in link", url)
        if host and "xn--" in host.lower():
            add("medium", "punycode host", url)
        if host and len(host) > 45:
            add("low", "very long host name", host)
    display_texts = [re.sub(r"<[^>]+>", "", text_part).strip()
                     for text_part in ANCHOR_TEXT.findall(text)]
    hrefs = HREF_ATTR.findall(text)
    for shown, href in zip(display_texts, hrefs):
        if not shown or not href.lower().startswith(("http://", "https://")):
            continue
        shown_host = shown.lower().lstrip("www.")
        href_host = ""
        match = re.match(r"https?://([^/@\s]+)", href, flags=re.IGNORECASE)
        if match:
            href_host = match.group(1).lower().lstrip("www.")
        if shown_host and href_host and shown_host != href_host:
            if shown_host not in href_host and href_host not in shown_host:
                add("high", "display text hides the real destination",
                    f'"{shown}" -> {href}')
    counts = {"high": 0, "medium": 0, "low": 0}
    for item in indicators:
        counts[item["severity"]] += 1
    if counts["high"] >= 1:
        verdict = "high risk"
    elif counts["medium"] >= 1:
        verdict = "suspicious"
    elif counts["low"] >= 1:
        verdict = "worth a second look"
    else:
        verdict = "no indicator found"
    return {"source": label, "verdict": verdict, "counts": counts,
            "indicators": indicators}


def analyze_file(path: str) -> dict:
    """Read a .eml, .html or text file and analyse it."""
    target = Path(path)
    raw = target.read_bytes()
    if target.suffix.lower() == ".eml":
        message = BytesParser(policy=policy.default).parsebytes(raw)
        parts = [f"From: {message.get('From', '')}",
                 f"To: {message.get('To', '')}",
                 f"Subject: {message.get('Subject', '')}"]
        body = ""
        if message.is_multipart():
            for part in message.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_content()
                    break
        else:
            body = message.get_content()
        parts.append(str(body))
        text = "\n".join(parts)
    else:
        text = raw.decode("utf-8", errors="replace")
    result = analyze_text(target.name, text)
    result["path"] = str(target)
    result["bytes"] = len(raw)
    return result


# ------------------------------------------------------------------ server --

class _SimulationHandler(BaseHTTPRequestHandler):
    """Serves the page and accepts the simulated submission."""

    server_version = "PhishingSim/1.0"
    template_name = "fake-support"
    events: list[dict] = []
    counters: dict = {"requests": 0, "page_views": 0, "submissions": 0,
                      "not_found": 0}

    def log_message(self, *args: object) -> None:
        return

    def _count(self, key: str) -> None:
        """Count one served request against the per-run handler class.

        Every HTTP request increments `requests`; `key` records what it was
        (`page_views`, `submissions` or `not_found`). The dict built by
        serve() lives on the handler class of that run, so separate runs
        never share counters.
        """
        cls = type(self)
        counters = cls.__dict__.get("counters")
        if counters is None:
            counters = dict(_SimulationHandler.counters)
            cls.counters = counters
        counters["requests"] += 1
        counters[key] += 1

    def _respond(self, status: int, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._count("page_views")
            self._respond(200, render_page(self.template_name))
        else:
            self._count("not_found")
            self._respond(404, _page_shell(
                "Not found", '<div class="card"><p>Nothing here.</p></div>'))

    def do_POST(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        path = urllib.parse.urlparse(self.path).path
        if path != LOCAL_FORM_ACTION:
            self._count("not_found")
            self._respond(404, _page_shell(
                "Not found", '<div class="card"><p>Nothing here.</p></div>'))
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(length, 64 * 1024))
        fields = urllib.parse.parse_qs(body.decode("utf-8", errors="replace"))
        password = (fields.get("password") or [""])[0]
        template = (fields.get("template") or [self.template_name])[0]
        if template not in TEMPLATES:
            template = self.template_name
        # The typed value is measured and thrown away - never stored.
        event = {
            "utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "template": template,
            "password_present": bool(password),
            "password_length": len(password),
            "email_present": bool((fields.get("email") or [""])[0]),
        }
        self._count("submissions")
        self.events.append(event)
        self._respond(200, render_reveal_page(template, len(password)))

    @property
    def submissions(self) -> int:
        return len(self.events)


def serve(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, *,
          template_name: str = "fake-support", timeout: float | None = DEFAULT_TIMEOUT,
          once: bool = False,
          ready: Callable[[str, int], None] | None = None) -> dict:
    """Serve the simulated page on loopback and return a request summary.

    `ready(host, port)` is called once the socket is bound, which lets a
    caller (or a test) discover the port chosen by `--port 0` before the
    first request arrives. With `once=True` the loop stops after the first
    submission rather than after a plain GET.
    """
    if host not in LOOPBACK_HOSTS:
        raise ValueError(
            f"--host {host} refused: this simulator only binds loopback "
            f"addresses ({', '.join(sorted(LOOPBACK_HOSTS))})")
    if template_name not in TEMPLATES:
        raise KeyError(f"unknown template: {template_name}")
    handler = type("BoundHandler", (_SimulationHandler,),
                   {"template_name": template_name, "events": [],
                    "counters": {"requests": 0, "page_views": 0,
                                 "submissions": 0, "not_found": 0}})
    server = ThreadingHTTPServer((host, port), handler)
    bound_port = server.server_address[1]
    if ready is not None:
        ready(host, bound_port)
    started = time.monotonic()
    deadline = None if timeout is None or timeout <= 0 else started + timeout
    try:
        while True:
            remaining = None if deadline is None else max(
                0.0, deadline - time.monotonic())
            if remaining is not None and remaining <= 0:
                break
            server.timeout = 0.5 if remaining is None else min(0.5, remaining)
            server.handle_request()
            if once and handler.events:
                break
    finally:
        server.server_close()
    events = list(handler.events)
    counters = dict(handler.counters)
    return {
        "host": host,
        "port": bound_port,
        "template": template_name,
        "url": f"http://{host}:{bound_port}/",
        "requests_handled": counters["requests"],
        "page_views": counters["page_views"],
        "not_found": counters["not_found"],
        "submissions": counters["submissions"],
        "events": events,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "storage_note": "passwords were measured and discarded; no value was written",
    }


# ----------------------------------------------------------------- cli ------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=SCRIPT_NAME,
        description="Render, serve and analyse a phishing-awareness "
                    "simulation. Loopback only, banner always visible.")
    parser.add_argument("--template", default="fake-support",
                        choices=available_templates(),
                        help="template to render (default: fake-support)")
    parser.add_argument("--list-templates", action="store_true",
                        help="list the built-in templates and exit")
    parser.add_argument("--emit", metavar="FILE",
                        help="write the rendered page to FILE instead of stdout")
    parser.add_argument("--serve", action="store_true",
                        help="serve the page over HTTP on 127.0.0.1")
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help=f"loopback address to bind (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"TCP port, 0 picks a free one (default: {DEFAULT_PORT})")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"seconds the server runs before it stops "
                             f"(default: {DEFAULT_TIMEOUT:g})")
    parser.add_argument("--once", action="store_true",
                        help="stop the server after the first submission")
    parser.add_argument("--analyze", metavar="FILE",
                        help="score a .eml/.html/.txt message for phishing "
                             "indicators")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_templates:
        for name in available_templates():
            print(f"{name}: {TEMPLATES[name]['scenario']}")
        return 0

    if args.analyze:
        try:
            result = analyze_file(args.analyze)
        except OSError as exc:
            print(f"{SCRIPT_NAME}: {exc}", file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"{result['source']}: {result['verdict']}")
            for item in result["indicators"]:
                print(f"  [{item['severity']:<6}] {item['signal']} - {item['why']}")
            if not result["indicators"]:
                print("  no indicator matched")
        return 0

    if args.serve:
        def announce(bound_host: str, bound_port: int) -> None:
            if not args.json:
                print(f"serving http://{bound_host}:{bound_port}/ "
                      f"(template {args.template})", flush=True)

        try:
            summary = serve(args.host, args.port, template_name=args.template,
                            timeout=args.timeout, once=args.once,
                            ready=announce)
        except (ValueError, OSError) as exc:
            print(f"{SCRIPT_NAME}: {exc}", file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps(summary, indent=2))
        else:
            print(f"simulation served on {summary['url']} "
                  f"({summary['submissions']} submission(s))")
            print(summary["storage_note"])
        return 0

    try:
        page = render_page(args.template)
    except (KeyError, ExternalResourceError) as exc:
        print(f"{SCRIPT_NAME}: {exc}", file=sys.stderr)
        return 2

    if args.emit:
        target = Path(args.emit)
        try:
            target.write_text(page, encoding="utf-8")
        except OSError as exc:
            print(f"{SCRIPT_NAME}: {exc}", file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps({
                "template": args.template,
                "path": str(target),
                "bytes": len(page.encode("utf-8")),
                "banner": BANNER,
                "form": {"method": "post", "action": LOCAL_FORM_ACTION},
                "external_resources": find_external_resources(page),
            }, indent=2))
        else:
            print(f"wrote {len(page.encode('utf-8'))} bytes to {target}")
        return 0

    if args.json:
        print(json.dumps({
            "template": args.template,
            "scenario": TEMPLATES[args.template]["scenario"],
            "banner": BANNER,
            "form": {"method": "post", "action": LOCAL_FORM_ACTION},
            "external_resources": find_external_resources(page),
            "indicators": TEMPLATES[args.template]["indicators"],
            "bytes": len(page.encode("utf-8")),
        }, indent=2))
    else:
        print(page, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
