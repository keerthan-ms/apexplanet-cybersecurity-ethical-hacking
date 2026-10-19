#!/usr/bin/env python3
"""Repeatable proof-of-concept run against the Task 3 training app.

Every request here is harmless and local: a fake admin login bypass, a UNION
SELECT that exposes only synthetic password digests, script payloads that set a
window variable or call alert(), a forged profile update, and a traversal into
task-3/fixtures/private/flag.txt.

Usage:
    python task-3/scripts/demo_attacks.py
    python task-3/scripts/demo_attacks.py --base-url http://127.0.0.1:8091
    python task-3/scripts/demo_attacks.py --only csrf
    python task-3/scripts/demo_attacks.py --json

The app must already be running (see scripts/run-demo.ps1 or task-3/README.md).
Exit code 0 means every expectation held.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests  # noqa: E402

from demo_client import DemoClient, payloads  # noqa: E402

RESULTS: list[dict] = []


def check(name: str, passed: bool, evidence: str) -> None:
    RESULTS.append({"check": name, "passed": bool(passed), "evidence": evidence})
    marker = "PASS" if passed else "FAIL"
    print(f"[{marker}] {name}")
    print(f"       {evidence}")


def run_sqli(client: DemoClient, p: dict[str, str]) -> None:
    print("\n== SQL injection ==")
    vuln = client.login("vuln", p["sqli_login"], "not-the-password")
    check(
        "vulnerable login is bypassed by a comment payload",
        vuln.status_code == 200 and "Signed in as" in vuln.text and "admin" in vuln.text,
        f"HTTP {vuln.status_code}; body contains signed-in admin: {'Signed in as' in vuln.text}",
    )

    hardened = DemoClient(client.base_url).login("secure", p["sqli_login"], "not-the-password")
    check(
        "hardened login rejects the same payload",
        hardened.status_code == 200 and "Login failed" in hardened.text and "Signed in as" not in hardened.text,
        f"HTTP {hardened.status_code}; prepared statement returned no admin session",
    )

    leaked = client.search("vuln", p["sqli_union"])
    check(
        "vulnerable search leaks synthetic rows via UNION SELECT",
        "<td>999</td>" in leaked.text and "<td>leaked</td>" in leaked.text,
        "UNION payload produced a synthetic row (id=999, role=leaked) with a fake digest",
    )

    hard_search = DemoClient(client.base_url).search("secure", p["sqli_union"])
    check(
        "hardened search treats the UNION payload as a literal string",
        "<td>999</td>" not in hard_search.text and "<td>leaked</td>" not in hard_search.text,
        f"HTTP {hard_search.status_code}; payload bound as data, no injected row",
    )


def run_xss(client: DemoClient, p: dict[str, str]) -> None:
    print("\n== Cross-site scripting ==")
    reflected = client.greet("vuln", p["xss_reflected"])
    check(
        "vulnerable greeting renders the script payload as raw HTML",
        p["xss_reflected"] in reflected.text,
        "raw <script> markup present in the response",
    )

    encoded = DemoClient(client.base_url).greet("secure", p["xss_reflected"])
    check(
        "hardened greeting encodes the payload",
        p["xss_reflected"] not in encoded.text and "&lt;script&gt;" in encoded.text,
        "payload appears as &lt;script&gt; text, not markup",
    )

    marker = f"stored-{int(time.time())}"
    stored = f"{p['xss_stored']}<!--{marker}-->"
    client.guestbook("vuln", "attacker", stored)
    vuln_list = client.get("/vuln/xss").text
    check(
        "vulnerable guestbook stores and renders raw markup",
        p["xss_stored"] in vuln_list,
        "stored <svg onload=...> is present unencoded",
    )

    secure = DemoClient(client.base_url)
    secure.guestbook("secure", "attacker", stored)
    secure_list = secure.get("/secure/xss").text
    check(
        "hardened guestbook renders the stored payload as text",
        p["xss_stored"] not in secure_list and "&lt;svg" in secure_list,
        "same row is encoded at the output sink",
    )


def run_csrf(client: DemoClient) -> None:
    print("\n== CSRF ==")
    # Fresh session: keeps the fake account at "demo" instead of inheriting
    # the admin session created by the SQL injection bypass.
    client = DemoClient(client.base_url)
    forged = client.change_email("vuln", "forged-by-cross-site@training.local")
    check(
        "vulnerable state change accepts a POST with no token",
        forged.status_code == 200 and "no CSRF token was verified" in forged.text,
        f"HTTP {forged.status_code}; forged profile update applied",
    )

    secure = DemoClient(client.base_url)
    token = secure.csrf_token("secure")
    check("hardened form issues a per-session CSRF token", len(token) >= 32, f"token length={len(token)}")

    rejected = secure.change_email("secure", "attacker@training.local", token=None)
    check(
        "hardened state change rejects a tokenless POST",
        rejected.status_code == 403 and "not changed" in rejected.text,
        f"HTTP {rejected.status_code}; no database write",
    )

    wrong = secure.change_email("secure", "attacker@training.local", token="0" * 32)
    check(
        "hardened state change rejects a forged token",
        wrong.status_code == 403,
        f"HTTP {wrong.status_code}; hash_equals failed",
    )

    accepted = secure.change_email("secure", "validated@training.local", token=token)
    check(
        "hardened state change accepts the real token",
        accepted.status_code == 200 and "token verified" in accepted.text,
        f"HTTP {accepted.status_code}; profile updated after validation",
    )


def run_lfi(client: DemoClient, p: dict[str, str]) -> None:
    print("\n== LFI / path traversal ==")
    traversed = client.lfi("vuln", p["lfi_traversal"])
    check(
        "vulnerable route reads a sibling private fixture",
        traversed.status_code == 200 and "APEX{TRAINING_ONLY_fake_flag_" in traversed.text,
        "fixtures/private/flag.txt reached via ../",
    )

    escaped = client.lfi("vuln", p["lfi_escape"])
    check(
        "vulnerable route is still sandboxed to task-3/fixtures/",
        escaped.status_code == 403
        and "outside task-3/fixtures/" in escaped.text
        and "ApexPlanet - Cybersecurity" not in escaped.text,
        f"HTTP {escaped.status_code}; traversal to the repository README refused by the lab rail",
    )

    hardened = DemoClient(client.base_url).lfi("secure", p["lfi_traversal"])
    check(
        "hardened route refuses traversal",
        hardened.status_code == 403 and "APEX{TRAINING_ONLY" not in hardened.text,
        f"HTTP {hardened.status_code}; allowlist rejected the path",
    )

    allowed = DemoClient(client.base_url).lfi("secure", "welcome.txt")
    check(
        "hardened route still serves an approved fixture",
        allowed.status_code == 200 and "public fixture" in allowed.text,
        f"HTTP {allowed.status_code}; welcome.txt allowed",
    )


def run_auth(client: DemoClient) -> None:
    print("\n== Authentication noise (for the SIEM brute-force rule) ==")
    attempts = [client.login("vuln", "admin", "wrong-password") for _ in range(5)]
    check(
        "five failed logins generated auth_fail events",
        all(response.status_code == 200 and "Login failed" in response.text for response in attempts),
        "5 x auth_fail written for user=admin (threshold is configurable in Task 5)",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8091")
    parser.add_argument("--only", choices=["all", "sqli", "xss", "csrf", "lfi", "auth"], default="all")
    parser.add_argument("--json", action="store_true", help="print a JSON summary instead of text")
    args = parser.parse_args()

    client = DemoClient(args.base_url)
    try:
        ready = client.get("/")
    except requests.RequestException as exc:
        print(f"ERROR: cannot reach {args.base_url}: {exc}", file=sys.stderr)
        print("Start the app first: powershell -ExecutionPolicy Bypass -File task-3/scripts/run-demo.ps1", file=sys.stderr)
        return 2
    if ready.status_code != 200:
        print(f"ERROR: {args.base_url}/ returned HTTP {ready.status_code}", file=sys.stderr)
        return 2

    p = payloads()
    if args.only in ("all", "sqli"):
        run_sqli(client, p)
    if args.only in ("all", "xss"):
        run_xss(client, p)
    if args.only in ("all", "csrf"):
        run_csrf(client)
    if args.only in ("all", "lfi"):
        run_lfi(client, p)
    if args.only in ("all", "auth"):
        run_auth(client)

    passed = sum(1 for r in RESULTS if r["passed"])
    total = len(RESULTS)
    summary = {
        "base_url": args.base_url,
        "checks": RESULTS,
        "passed": passed,
        "total": total,
    }
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"\n{passed}/{total} checks passed")
        print("Security events: task-3/vulnerable/data/security.jsonl")
        print("Access log:      task-3/vulnerable/data/access.log")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
