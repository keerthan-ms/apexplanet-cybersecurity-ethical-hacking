#!/usr/bin/env python3
"""
Task 2 - HTTP security header audit.

This is the substitute for OpenVAS/Nessus web checks and for services such
as securityheaders.com, all of which are unavailable on this machine. It
performs exactly one HTTP request per URL and grades the response headers it
actually received. Nothing is inferred about pages that were not fetched.

Checks (each pass / fail / warn / n-a, weighted to 100 points total):
    Strict-Transport-Security, Content-Security-Policy (unsafe-inline /
    unsafe-eval noted), X-Content-Type-Options, X-Frame-Options or CSP
    frame-ancestors, Referrer-Policy, Permissions-Policy,
    Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy, Set-Cookie
    flags (Secure / HttpOnly / SameSite), information-disclosure headers
    (Server, X-Powered-By, X-AspNet-Version), and plain-HTTP-when-HTTPS-
    is-available. Output includes copy-pasteable Apache and Nginx snippets
    for whatever is missing.

Usage:
    python task-2/scripts/http_security_audit.py --url http://127.0.0.1:8091/
    python task-2/scripts/http_security_audit.py --url https://example.com --json
    python task-2/scripts/http_security_audit.py --url 127.0.0.1:8091 --strict
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

USER_AGENT = "ApexPlanet-HttpAudit/1.0 (internship lab; one request per URL)"
PROBE_TIMEOUT = 3.0
FETCH_TIMEOUT = 8.0

DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version")
STRICT_SAMPLE_HSTS = 'Strict-Transport-Security "max-age=31536000; includeSubDomains"'
STRICT_SAMPLE_CSP = ("Content-Security-Policy "
                     "\"default-src 'self'; object-src 'none'; "
                     "base-uri 'self'; frame-ancestors 'none'\"")


class FetchError(Exception):
    """The URL could not be fetched at all."""


# ------------------------------------------------------------------ cookies ---

def parse_set_cookie(header: str) -> dict:
    """Parse one Set-Cookie header value into name, value and flag fields.

    Hand-rolled rather than using http.cookies so that unknown attributes
    and modern SameSite values survive parsing unchanged.
    """
    parts = [part.strip() for part in header.split(";")]
    first = parts[0]
    name, _, value = first.partition("=")
    out = {
        "name": name.strip(),
        "value": value.strip(),
        "secure": False,
        "httponly": False,
        "samesite": None,
        "path": None,
        "domain": None,
    }
    for attribute in parts[1:]:
        if not attribute:
            continue
        key, _, attr_value = attribute.partition("=")
        key = key.strip().lower()
        attr_value = attr_value.strip()
        if key == "secure":
            out["secure"] = True
        elif key == "httponly":
            out["httponly"] = True
        elif key == "samesite":
            out["samesite"] = attr_value or None
        elif key == "path":
            out["path"] = attr_value
        elif key == "domain":
            out["domain"] = attr_value
    return out


# ------------------------------------------------------------------- fetch ---

def normalise_url(url: str) -> str:
    """Accept full URLs and bare host:port (default scheme http)."""
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"not an http(s) URL: {url!r}")
    return url


def fetch(url: str, timeout: float = FETCH_TIMEOUT) -> dict:
    """One HEAD request. Status 4xx/5xx still yields auditable headers."""
    request = Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
    start = time.perf_counter()
    try:
        with urlopen(request, timeout=timeout) as response:
            status, headers = response.status, response.headers
            final_url = response.geturl()
    except HTTPError as exc:
        status, headers, final_url = exc.code, exc.headers, url
    except (URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        raise FetchError(f"{type(exc).__name__}: {reason}") from exc

    header_map: dict[str, list[str]] = {}
    for name, value in headers.items():
        header_map.setdefault(name.lower(), []).append(value)
    return {"status": status, "headers": header_map, "final_url": final_url,
            "elapsed_ms": round((time.perf_counter() - start) * 1000, 1)}


def https_service_available(url: str, timeout: float = PROBE_TIMEOUT) -> bool:
    """Does a TLS service answer on the same host and port (or 443)?

    A plain TLS handshake with verification disabled - reachability only.
    Used to detect 'served over HTTP although HTTPS exists'.
    """
    parts = urlsplit(url)
    host = parts.hostname
    if not host:
        return False
    port = parts.port or 443
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock):
                return True
    except (OSError, ssl.SSLError):
        return False


# ------------------------------------------------------------------ checks ---

def _first(headers: dict[str, list[str]], name: str) -> str | None:
    values = headers.get(name)
    return values[0] if values else None


def _frame_ancestors(csp: str | None) -> str | None:
    if not csp:
        return None
    for directive in csp.split(";"):
        parts = directive.strip().split(None, 1)
        if parts and parts[0].lower() == "frame-ancestors":
            return parts[1] if len(parts) > 1 else ""
    return None


def check_hsts(scheme: str, value: str | None) -> dict:
    remediation = STRICT_SAMPLE_HSTS
    if value is None:
        if scheme == "https":
            return {"status": "fail",
                    "explanation": "header absent; browsers are not told to "
                                   "force HTTPS on this origin",
                    "remediation_header": remediation}
        return {"status": "warn",
                "explanation": "header absent, and over plain HTTP any HSTS "
                               "header would be ignored by browsers; configure "
                               "it on the HTTPS response",
                "remediation_header": remediation}
    match = re.search(r"max-age=(\d+)", value, re.IGNORECASE)
    if not match:
        return {"status": "fail",
                "explanation": f"present ({value!r}) but no parsable max-age",
                "remediation_header": remediation}
    age = int(match.group(1))
    if age == 0:
        return {"status": "fail",
                "explanation": "max-age=0 explicitly disables HSTS",
                "remediation_header": remediation}
    notes = [f"max-age={age}"]
    status = "pass"
    if age < 15552000:
        status = "warn"
        notes.append("max-age below the 180-day (15552000s) recommendation")
    if "includeSubDomains" not in value:
        if status == "pass":
            status = "warn"
        notes.append("includeSubDomains missing")
    return {"status": status,
            "explanation": "; ".join(notes),
            "remediation_header": None if status == "pass" else remediation}


def check_csp(value: str | None) -> dict:
    if value is None:
        return {"status": "fail",
                "explanation": "header absent; no allow-list constrains "
                               "script, style or frame sources",
                "remediation_header": STRICT_SAMPLE_CSP}
    weak = [token for token in ("unsafe-inline", "unsafe-eval")
            if token in value.lower()]
    directives = [d for d in value.split(";") if d.strip()]
    if weak:
        return {"status": "warn",
                "explanation": (f"policy present ({len(directives)} directives) "
                                f"but contains {', '.join(weak)}, which weakens "
                                f"it substantially"),
                "remediation_header": STRICT_SAMPLE_CSP}
    return {"status": "pass",
            "explanation": f"policy present with {len(directives)} directives",
            "remediation_header": None}


def check_xcto(value: str | None) -> dict:
    remediation = 'X-Content-Type-Options "nosniff"'
    if value is None:
        return {"status": "fail",
                "explanation": "header absent; browsers may MIME-sniff "
                               "responses",
                "remediation_header": remediation}
    if value.strip().lower() != "nosniff":
        return {"status": "fail",
                "explanation": f"unexpected value {value!r} (expected nosniff)",
                "remediation_header": remediation}
    return {"status": "pass", "explanation": "nosniff",
            "remediation_header": None}


def check_clickjacking(xfo: str | None, csp: str | None) -> dict:
    remediation = 'X-Frame-Options "DENY"'
    ancestors = _frame_ancestors(csp)
    if xfo:
        value = xfo.strip().lower()
        if value in ("deny", "sameorigin"):
            extra = (" plus CSP frame-ancestors" if ancestors else "")
            return {"status": "pass",
                    "explanation": f"X-Frame-Options {xfo.strip()}{extra}",
                    "remediation_header": None}
        if value.startswith("allow-from"):
            return {"status": "warn",
                    "explanation": "ALLOW-FROM is obsolete and ignored by "
                                   "modern browsers",
                    "remediation_header": remediation}
        return {"status": "warn",
                "explanation": f"unrecognised X-Frame-Options value {xfo!r}",
                "remediation_header": remediation}
    if ancestors is not None:
        if "'none'" in ancestors.lower():
            return {"status": "pass",
                    "explanation": "CSP frame-ancestors 'none'",
                    "remediation_header": None}
        if "'self'" in ancestors.lower():
            return {"status": "pass",
                    "explanation": f"CSP frame-ancestors {ancestors.strip()!r}",
                    "remediation_header": None}
        return {"status": "warn",
                "explanation": f"frame-ancestors allows other origins: "
                               f"{ancestors.strip()!r}",
                "remediation_header": remediation}
    return {"status": "fail",
            "explanation": "neither X-Frame-Options nor CSP frame-ancestors "
                           "is set",
            "remediation_header": remediation}


def check_referrer(value: str | None) -> dict:
    remediation = 'Referrer-Policy "strict-origin-when-cross-origin"'
    if value is None:
        return {"status": "fail",
                "explanation": "header absent; full URLs may leak in the "
                               "Referer header",
                "remediation_header": remediation}
    normalised = value.strip().lower()
    if normalised == "unsafe-url":
        return {"status": "warn",
                "explanation": "unsafe-url sends full URLs cross-origin",
                "remediation_header": remediation}
    if normalised == "no-referrer-when-downgrade":
        return {"status": "warn",
                "explanation": "no-referrer-when-downgrade is the lax legacy "
                               "default",
                "remediation_header": remediation}
    return {"status": "pass", "explanation": value.strip(),
            "remediation_header": None}


def check_permissions(value: str | None) -> dict:
    remediation = ('Permissions-Policy '
                   '"camera=(), microphone=(), geolocation=()"')
    if value is None:
        return {"status": "fail",
                "explanation": "header absent; powerful features are not "
                               "explicitly disabled",
                "remediation_header": remediation}
    if not value.strip():
        return {"status": "warn",
                "explanation": "header present but empty",
                "remediation_header": remediation}
    return {"status": "pass", "explanation": value.strip(),
            "remediation_header": None}


def check_coop(value: str | None) -> dict:
    remediation = 'Cross-Origin-Opener-Policy "same-origin"'
    if value is None:
        return {"status": "fail",
                "explanation": "header absent; the browsing context is not "
                               "isolated from cross-origin openers",
                "remediation_header": remediation}
    normalised = value.strip().lower()
    if normalised in ("same-origin", "same-site-allow-popups"):
        return {"status": "pass", "explanation": value.strip(),
                "remediation_header": None}
    if normalised == "unsafe-none":
        return {"status": "warn",
                "explanation": "unsafe-none is the insecure default, set "
                               "explicitly here",
                "remediation_header": remediation}
    return {"status": "warn",
            "explanation": f"unrecognised value {value!r}",
            "remediation_header": remediation}


def check_corp(value: str | None) -> dict:
    remediation = 'Cross-Origin-Resource-Policy "same-origin"'
    if value is None:
        return {"status": "warn",
                "explanation": "header absent; other origins may embed this "
                               "origin's resources",
                "remediation_header": remediation}
    normalised = value.strip().lower()
    if normalised in ("same-origin", "same-site"):
        return {"status": "pass", "explanation": value.strip(),
                "remediation_header": None}
    return {"status": "warn",
            "explanation": "cross-origin allows any site to embed the resource",
            "remediation_header": remediation}


def check_cookies(headers: dict[str, list[str]]) -> dict:
    remediation = None
    raw_cookies = headers.get("set-cookie", [])
    if not raw_cookies:
        return {"status": "n-a",
                "explanation": "no Set-Cookie headers in the response",
                "remediation_header": None}
    problems: list[str] = []
    warns: list[str] = []
    for raw in raw_cookies:
        cookie = parse_set_cookie(raw)
        name = cookie["name"] or "(unnamed)"
        if not cookie["secure"]:
            problems.append(f"cookie {name!r} lacks Secure")
        if not cookie["httponly"]:
            problems.append(f"cookie {name!r} lacks HttpOnly")
        if not cookie["samesite"]:
            warns.append(f"cookie {name!r} lacks SameSite")
    if problems:
        return {"status": "fail",
                "explanation": "; ".join(problems + warns),
                "remediation_header": None}
    if warns:
        return {"status": "warn",
                "explanation": "; ".join(warns),
                "remediation_header": None}
    return {"status": "pass",
            "explanation": f"all {len(raw_cookies)} cookie(s) carry Secure, "
                           f"HttpOnly and SameSite",
            "remediation_header": None}


def check_disclosure(headers: dict[str, list[str]]) -> dict:
    leaked = {name: headers[name] for name in DISCLOSURE_HEADERS
              if headers.get(name)}
    if leaked:
        detail = "; ".join(f"{name}: {', '.join(values)}"
                           for name, values in leaked.items())
        return {"status": "fail",
                "explanation": f"version/product information disclosed - {detail}",
                "remediation_header": None}
    return {"status": "pass",
            "explanation": "no Server / X-Powered-By / X-AspNet-Version headers",
            "remediation_header": None}


def check_transport(scheme: str, https_available: bool | None) -> dict:
    if scheme == "https":
        return {"status": "n-a", "explanation": "response already over HTTPS",
                "remediation_header": None}
    if https_available:
        return {"status": "fail",
                "explanation": "a TLS service answered on this host/port, but "
                               "the audited URL is plain HTTP",
                "remediation_header": None}
    return {"status": "warn",
            "explanation": "plain HTTP; no TLS service answered the "
                           "reachability probe on this host/port (fine for a "
                           "local lab, not for production)",
            "remediation_header": None}


CHECK_WEIGHTS = (
    ("hsts", "Strict-Transport-Security", 10),
    ("csp", "Content-Security-Policy", 15),
    ("xcto", "X-Content-Type-Options", 8),
    ("clickjacking", "Clickjacking (X-Frame-Options / frame-ancestors)", 10),
    ("referrer", "Referrer-Policy", 7),
    ("permissions", "Permissions-Policy", 8),
    ("coop", "Cross-Origin-Opener-Policy", 7),
    ("corp", "Cross-Origin-Resource-Policy", 7),
    ("cookies", "Set-Cookie flags", 10),
    ("disclosure", "Information disclosure headers", 8),
    ("transport", "HTTPS vs HTTP", 10),
)


def analyse(url: str, status: int, headers: dict[str, list[str]],
            https_available: bool | None, strict: bool = False) -> dict:
    """Grade one response. Pure function apart from the supplied probe result."""
    scheme = urlsplit(url).scheme
    hsts = _first(headers, "strict-transport-security")
    csp = _first(headers, "content-security-policy")

    results = {
        "hsts": check_hsts(scheme, hsts),
        "csp": check_csp(csp),
        "xcto": check_xcto(_first(headers, "x-content-type-options")),
        "clickjacking": check_clickjacking(_first(headers, "x-frame-options"), csp),
        "referrer": check_referrer(_first(headers, "referrer-policy")),
        "permissions": check_permissions(_first(headers, "permissions-policy")),
        "coop": check_coop(_first(headers, "cross-origin-opener-policy")),
        "corp": check_corp(_first(headers, "cross-origin-resource-policy")),
        "cookies": check_cookies(headers),
        "disclosure": check_disclosure(headers),
        "transport": check_transport(scheme, https_available),
    }

    checks, score = [], 0.0
    for check_id, title, weight in CHECK_WEIGHTS:
        outcome = results[check_id]
        status_value = outcome["status"]
        if status_value == "pass" or status_value == "n-a":
            earned = weight
        elif status_value == "warn":
            earned = 0 if strict else weight / 2
        else:
            earned = 0
        score += earned
        checks.append({
            "id": check_id,
            "title": title,
            "status": status_value,
            "points": weight,
            "earned": int(earned),
            "explanation": outcome["explanation"],
            "remediation_header": outcome.get("remediation_header"),
        })

    score = int(round(score))
    band, severity = band_for(score)
    return {
        "url": url,
        "status": status,
        "scheme": scheme,
        "https_service_available": https_available,
        "strict": strict,
        "score": score,
        "band": band,
        "severity": severity,
        "checks": checks,
        "snippets": build_snippets(checks, url),
    }


def band_for(score: int) -> tuple[str, str]:
    if score >= 90:
        return "good", "info"
    if score >= 75:
        return "adequate", "low"
    if score >= 50:
        return "fair", "medium"
    if score >= 25:
        return "poor", "high"
    return "critical", "critical"


def build_snippets(checks: list[dict], url: str) -> dict:
    """Apache and Nginx config for every header that is missing or weak."""
    apache: list[str] = []
    nginx: list[str] = []
    for check in checks:
        if check["status"] in ("fail", "warn") and check.get("remediation_header"):
            apache.append(f"Header always set {check['remediation_header']}")
            nginx.append(f"add_header {check['remediation_header']} always;")
    advisory = []
    if any(c["id"] == "disclosure" and c["status"] == "fail" for c in checks):
        advisory.append("# Apache: ServerTokens Prod, ServerSignature Off, "
                        "and unset X-Powered-By")
        advisory.append("# Nginx: server_tokens off; proxy_hide_header "
                        "X-Powered-By; and for PHP-FPM set expose_php=Off")
    if any(c["id"] == "cookies" and c["status"] in ("fail", "warn")
           for c in checks):
        advisory.append("# Cookies: set Secure, HttpOnly and SameSite at the "
                        "application layer (not fixable by response headers alone)")
    return {
        "apache": "\n".join(advisory + apache) if (apache or advisory) else "",
        "nginx": "\n".join(advisory + nginx) if (nginx or advisory) else "",
    }


def audit_url(url: str, strict: bool = False,
              timeout: float = FETCH_TIMEOUT) -> dict:
    """Fetch once, probe HTTPS reachability, grade the response."""
    url = normalise_url(url)
    try:
        response = fetch(url, timeout=timeout)
    except FetchError as exc:
        return {"url": url, "error": str(exc)}
    https_available = None
    if urlsplit(url).scheme == "http":
        https_available = https_service_available(url)
    return analyse(url, response["status"], response["headers"],
                   https_available, strict=strict)


# ---------------------------------------------------------------- output ----

def print_result(result: dict) -> None:
    if "error" in result:
        print(f"== {result['url']} ==")
        print(f"   fetch failed: {result['error']}")
        print()
        return
    print("=" * 78)
    print(f"URL    : {result['url']}")
    print(f"status : {result['status']}   scheme: {result['scheme']}")
    probe = result["https_service_available"]
    if probe is None:
        print("HTTPS probe: not applicable (URL is already HTTPS)")
    else:
        print(f"HTTPS probe: {'reachable' if probe else 'not reachable'} "
              f"on this host/port")
    print("-" * 78)
    print(f"{'CHECK':<44} {'RESULT':<7} {'PTS':<6} NOTE")
    for check in result["checks"]:
        print(f"{check['title']:<44} {check['status']:<7} "
              f"{check['earned']}/{check['points']:<4} {check['explanation'][:60]}")
    print("-" * 78)
    print(f"Score: {result['score']}/100 - band: {result['band']} "
          f"(severity: {result['severity']})")
    if result["snippets"]["apache"]:
        print()
        print("-- Apache snippet (missing or weak items only) --")
        print(result["snippets"]["apache"])
    if result["snippets"]["nginx"]:
        print()
        print("-- Nginx snippet (missing or weak items only) --")
        print(result["snippets"]["nginx"])
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit HTTP response security headers (one request per URL).")
    parser.add_argument("--url", action="append", required=True, metavar="URL",
                        help="URL or host:port to audit (repeatable); "
                             "bare host:port is treated as http://")
    parser.add_argument("--json", action="store_true",
                        help="emit machine-readable JSON on stdout")
    parser.add_argument("--strict", action="store_true",
                        help="treat warnings as failures for scoring and exit status")
    args = parser.parse_args(argv)

    results = []
    for url in args.url:
        try:
            results.append(audit_url(url, strict=args.strict))
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.json:
        print(json.dumps({"tool": "task-2/http_security_audit.py",
                          "strict": args.strict, "results": results}, indent=2))
    else:
        print("=" * 78)
        print("TASK 2 - HTTP SECURITY HEADER AUDIT (one request per URL)")
        print("=" * 78)
        for result in results:
            print_result(result)

    if all("error" in r for r in results):
        return 2
    bad = False
    for result in results:
        for check in result.get("checks", []):
            if check["status"] == "fail":
                bad = True
            if args.strict and check["status"] == "warn":
                bad = True
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
