"""Detection rules for the Task 3 security-event stream.

Design choices that keep this honest and false-positive aware:

* Blocked events (``sqli_blocked``, ``xss_blocked``, ``csrf_blocked`` and
  ``lfi_attempt`` with ``blocked=1``) produce low-severity *mitigation* alerts,
  never compromise alerts. A control doing its job is not an incident.
* One event is enough to alert for XSS, CSRF and LFI because those are only
  emitted for payloads, but confidence stays ``medium`` until the event is
  corroborated or repeats.
* Authentication failures are grouped in a sliding window and only alert at a
  configurable threshold, because a few typos are normal.
* Access-log entries within five seconds on the matching path add HTTP status
  evidence. A 5xx response raises severity for injection rules.
* Source IPs can be allowlisted for known scanners or test runners; suppressed
  counts are reported rather than silently dropped.
"""

from __future__ import annotations

import json
from collections import Counter
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .contract import parse_ts

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

DEFAULT_CONFIG: dict[str, Any] = {
    "allow_ips": [],
    "thresholds": {
        "sqli": {"high": 3, "critical": 6},
        "xss": {"critical": 3},
        "csrf": {"critical": 3},
        "lfi": {"critical": 3},
        "auth_fail": {"high": 5, "critical": 10, "window_minutes": 10},
        "mitigated": {"low": 1},
    },
}

RULE_META = {
    "SQLI-001": {
        "title": "SQL injection attempts against a vulnerable route",
        "category": "sqli", "mitre": ["T1190"], "capec": ["CAPEC-66"],
        "recommendation": "Use parameterised queries (PDO prepared statements), remove string concatenation, and review the affected endpoint for data exposure.",
    },
    "SQLI-002": {
        "title": "Blocked SQL injection attempts",
        "category": "sqli", "mitre": ["T1190"], "capec": ["CAPEC-66"],
        "recommendation": "The prepared statement neutralised the payload. Confirm the client is authorised and keep input validation and logging in place.",
    },
    "XSS-001": {
        "title": "Reflected cross-site scripting payload",
        "category": "xss", "mitre": ["T1059.007"], "capec": ["CAPEC-591"],
        "recommendation": "HTML-encode at the output sink with htmlspecialchars(ENT_QUOTES) and add a Content-Security-Policy as defence in depth.",
    },
    "XSS-002": {
        "title": "Stored cross-site scripting payload",
        "category": "xss", "mitre": ["T1059.007"], "capec": ["CAPEC-592"],
        "recommendation": "Encode on output, not on input; stored payloads affect every later viewer. Audit existing rows and add a CSP.",
    },
    "XSS-003": {
        "title": "Blocked cross-site scripting attempts",
        "category": "xss", "mitre": ["T1059.007"], "capec": ["CAPEC-591"],
        "recommendation": "Output encoding rendered the payload inert. Keep encoding at every sink and verify no template bypasses it.",
    },
    "CSRF-001": {
        "title": "State-changing request without a valid CSRF token",
        "category": "csrf", "mitre": [], "capec": ["CAPEC-62"],
        "recommendation": "Require a session-bound random token compared with hash_equals() before any write; keep cookies HttpOnly and SameSite.",
    },
    "CSRF-002": {
        "title": "Blocked CSRF attempts",
        "category": "csrf", "mitre": [], "capec": ["CAPEC-62"],
        "recommendation": "The token check rejected the request. Monitor the source and confirm the token is unique per session.",
    },
    "LFI-001": {
        "title": "Path traversal / local file inclusion attempt",
        "category": "lfi", "mitre": ["T1190", "T1005"], "capec": ["CAPEC-126"],
        "recommendation": "Never build filesystem paths from user input. Map an identifier to a fixed filename and verify realpath() stays inside the base directory.",
    },
    "LFI-002": {
        "title": "Blocked path traversal / LFI attempts",
        "category": "lfi", "mitre": ["T1190"], "capec": ["CAPEC-126"],
        "recommendation": "The allowlist refused the path. Keep the allowlist narrow and log refused attempts for trend analysis.",
    },
    "AUTH-001": {
        "title": "Repeated authentication failures",
        "category": "auth", "mitre": ["T1110.001"], "capec": ["CAPEC-49"],
        "recommendation": "Confirm with the account owner, then apply rate limiting, lockout with backoff, and MFA. Check for spraying across many usernames.",
    },
    "AUTH-002": {
        "title": "Account lockout triggered",
        "category": "auth", "mitre": ["T1110.001"], "capec": ["CAPEC-49"],
        "recommendation": "A lockout is a symptom, not a fix: identify the source, notify the user, and review whether the lockout policy can be abused for denial of service.",
    },
}


@dataclass
class Alert:
    rule_id: str
    severity: str
    title: str
    first_seen: str
    last_seen: str
    count: int
    source_ip: str
    user: str | None
    events: list[dict[str, Any]]
    mitre: list[str]
    recommendation: str
    confidence: str
    mitigated: bool = False
    category: str = ""
    capec: list[str] = field(default_factory=list)
    http_statuses: list[int] = field(default_factory=list)
    corroborated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "count": self.count,
            "source_ip": self.source_ip,
            "user": self.user,
            "events": self.events,
            "mitre": self.mitre,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "mitigated": self.mitigated,
            "category": self.category,
            "capec": self.capec,
            "http_statuses": self.http_statuses,
            "corroborated": self.corroborated,
        }


def merge_config(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge a user config over the defaults."""
    result = deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge_config(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def load_config(path: str | Path | None) -> dict[str, Any]:
    if path is None:
        return deepcopy(DEFAULT_CONFIG)
    with Path(path).open("r", encoding="utf-8") as handle:
        user = json.load(handle)
    if not isinstance(user, dict):
        raise ValueError("config file must contain a JSON object")
    return merge_config(DEFAULT_CONFIG, user)


def _users(events: Iterable[dict[str, Any]]) -> str | None:
    names = sorted({str(e["user"]) for e in events if e.get("user")})
    return ",".join(names) if names else None


def _sorted_events(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(events, key=lambda e: parse_ts(e["ts"]))


def _correlate(
    events: list[dict[str, Any]],
    access_events: list[dict[str, Any]] | None,
) -> tuple[list[int], bool]:
    """Match security events to access-log rows (same IP/path, +/-5 seconds)."""
    if not access_events:
        return [], False
    statuses: list[int] = []
    matched = False
    for event in events:
        try:
            event_time = parse_ts(event["ts"])
        except ValueError:
            continue
        base_path = str(event["path"]).split("?", 1)[0]
        for request in access_events:
            if request.get("ip") != event.get("ip"):
                continue
            if str(request.get("path", "")).split("?", 1)[0] != base_path:
                continue
            try:
                request_time = parse_ts(request["ts"])
            except ValueError:
                continue
            if abs((request_time - event_time).total_seconds()) <= 5:
                matched = True
                statuses.append(int(request["status"]))
    return sorted(set(statuses)), matched


def _bump(severity: str) -> str:
    reverse = {value: key for key, value in SEVERITY_ORDER.items()}
    return reverse[min(4, SEVERITY_ORDER[severity] + 1)]


def _make_alert(
    rule_id: str,
    events: list[dict[str, Any]],
    severity: str,
    confidence: str,
    access_events: list[dict[str, Any]] | None,
    *,
    mitigated: bool = False,
) -> Alert:
    events = _sorted_events(events)
    meta = RULE_META[rule_id]
    ips = sorted({str(e["ip"]) for e in events})
    statuses, corroborated = _correlate(events, access_events)
    if corroborated and any(status >= 500 for status in statuses) and severity != "critical":
        severity = _bump(severity)
    if corroborated and confidence == "medium":
        confidence = "high"
    return Alert(
        rule_id=rule_id,
        severity=severity,
        title=meta["title"],
        first_seen=str(events[0]["ts"]),
        last_seen=str(events[-1]["ts"]),
        count=len(events),
        source_ip=",".join(ips),
        user=_users(events),
        events=events,
        mitre=list(meta["mitre"]),
        recommendation=meta["recommendation"],
        confidence=confidence,
        mitigated=mitigated,
        category=meta["category"],
        capec=list(meta["capec"]),
        http_statuses=statuses,
        corroborated=corroborated,
    )


def _group_by_ip(events: Iterable[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        groups.setdefault(str(event["ip"]), []).append(event)
    return groups


def _window_buckets(
    events: Iterable[dict[str, Any]], window_minutes: int
) -> list[list[dict[str, Any]]]:
    ordered = _sorted_events(events)
    buckets: list[list[dict[str, Any]]] = []
    bucket: list[dict[str, Any]] = []
    last: datetime | None = None
    for event in ordered:
        moment = parse_ts(event["ts"])
        if last is not None and (moment - last).total_seconds() > window_minutes * 60:
            buckets.append(bucket)
            bucket = []
        bucket.append(event)
        last = moment
    if bucket:
        buckets.append(bucket)
    return buckets


def _count_severity(count: int, thresholds: dict[str, Any], baseline: str) -> str:
    if count >= int(thresholds.get("critical", 10**9)):
        return "critical"
    if count >= int(thresholds.get("high", 10**9)):
        return "high"
    return baseline


def _is_blocked_lfi(event: dict[str, Any]) -> bool:
    return str(event.get("detail", "")).startswith("blocked=1")


def analyze(
    security_events: list[dict[str, Any]],
    access_events: list[dict[str, Any]] | None = None,
    config: dict[str, Any] | None = None,
    allow_ips: Iterable[str] | None = None,
    min_severity: str = "low",
) -> dict[str, Any]:
    """Run all rules and return a JSON-serialisable report."""
    cfg = merge_config(DEFAULT_CONFIG, config or {})
    thresholds = cfg["thresholds"]
    allow = set(str(ip) for ip in cfg.get("allow_ips", []))
    allow.update(str(ip) for ip in (allow_ips or []))

    all_events = list(security_events)
    suppressed = [e for e in all_events if str(e.get("ip")) in allow]
    events = [e for e in all_events if str(e.get("ip")) not in allow]

    alerts: list[Alert] = []
    categorized = 0

    def add_group(rule_id: str, subset: list[dict[str, Any]], severity: str, confidence: str,
                  mitigated: bool = False) -> None:
        nonlocal categorized
        if not subset:
            return
        categorized += len(subset)
        alerts.append(_make_alert(rule_id, subset, severity, confidence, access_events, mitigated=mitigated))

    by_event: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        by_event.setdefault(str(event["event"]), []).append(event)

    # -- SQL injection ------------------------------------------------------
    sqli_thresholds = thresholds["sqli"]
    sqli_attempts = by_event.get("sqli_attempt", [])
    for _ip, group in _group_by_ip(sqli_attempts).items():
        add_group(
            "SQLI-001", group,
            _count_severity(len(group), sqli_thresholds, "medium"),
            "high" if len(group) >= int(sqli_thresholds.get("high", 3)) else "medium",
        )
    for _ip, group in _group_by_ip(by_event.get("sqli_blocked", [])).items():
        add_group("SQLI-002", group, "low", "low", mitigated=True)

    # -- XSS ----------------------------------------------------------------
    xss_thresholds = thresholds["xss"]
    for rule_id, event_name in (("XSS-001", "xss_reflected"), ("XSS-002", "xss_stored")):
        for _ip, group in _group_by_ip(by_event.get(event_name, [])).items():
            add_group(rule_id, group, _count_severity(len(group), xss_thresholds, "high"), "medium")
    for _ip, group in _group_by_ip(by_event.get("xss_blocked", [])).items():
        add_group("XSS-003", group, "low", "low", mitigated=True)

    # -- CSRF ---------------------------------------------------------------
    csrf_thresholds = thresholds["csrf"]
    for _ip, group in _group_by_ip(by_event.get("csrf_missing", [])).items():
        add_group("CSRF-001", group, _count_severity(len(group), csrf_thresholds, "high"), "high")
    for _ip, group in _group_by_ip(by_event.get("csrf_blocked", [])).items():
        add_group("CSRF-002", group, "low", "low", mitigated=True)

    # -- LFI ----------------------------------------------------------------
    lfi_thresholds = thresholds["lfi"]
    lfi_events = by_event.get("lfi_attempt", [])
    lfi_attack = [e for e in lfi_events if not _is_blocked_lfi(e)]
    lfi_blocked = [e for e in lfi_events if _is_blocked_lfi(e)]
    for _ip, group in _group_by_ip(lfi_attack).items():
        add_group("LFI-001", group, _count_severity(len(group), lfi_thresholds, "high"), "medium")
    for _ip, group in _group_by_ip(lfi_blocked).items():
        add_group("LFI-002", group, "low", "low", mitigated=True)

    # -- Authentication failures (windowed) ---------------------------------
    auth_thresholds = thresholds["auth_fail"]
    window = int(auth_thresholds.get("window_minutes", 10))
    auth_groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for event in by_event.get("auth_fail", []):
        auth_groups.setdefault((str(event["ip"]), str(event.get("user", "-"))), []).append(event)
    for _key, group in auth_groups.items():
        for bucket in _window_buckets(group, window):
            if len(bucket) >= int(auth_thresholds.get("high", 5)):
                severity = "critical" if len(bucket) >= int(auth_thresholds.get("critical", 10)) else "high"
                add_group("AUTH-001", bucket, severity, "medium")

    for _ip, group in _group_by_ip(by_event.get("auth_lockout", [])).items():
        add_group("AUTH-002", group, "high", "high")

    # -- filter / sort -------------------------------------------------------
    filtered_out = [a for a in alerts if SEVERITY_ORDER[a.severity] < SEVERITY_ORDER[min_severity]]
    kept = [a for a in alerts if SEVERITY_ORDER[a.severity] >= SEVERITY_ORDER[min_severity]]
    kept.sort(key=lambda a: (-SEVERITY_ORDER[a.severity], a.first_seen, a.rule_id))

    severity_counts = {level: 0 for level in ("critical", "high", "medium", "low")}
    for alert in kept:
        severity_counts[alert.severity] += 1
    rule_counts = Counter(alert.rule_id for alert in kept)

    timestamps = [parse_ts(e["ts"]) for e in events]
    mitigated_events = sum(
        1 for a in alerts if a.mitigated for _ in a.events
    )
    benign = len(events) - categorized
    admin_actions = len(by_event.get("admin_action", []))
    auth_success = len(by_event.get("auth_success", []))

    summary = {
        "total_events": len(all_events),
        "analyzed_events": len(events),
        "suppressed_allowlisted": len(suppressed),
        "alerts": len(kept),
        "compromise_alerts": sum(1 for a in kept if not a.mitigated),
        "mitigated_alerts": sum(1 for a in kept if a.mitigated),
        "mitigated_events": mitigated_events,
        "filtered_out_by_severity": len(filtered_out),
        "severity": severity_counts,
        "by_rule": dict(sorted(rule_counts.items())),
        "corroborated_alerts": sum(1 for a in kept if a.corroborated),
        "benign_events": benign,
        "admin_action_events": admin_actions,
        "auth_success_events": auth_success,
        "first_seen": min(timestamps).isoformat() if timestamps else None,
        "last_seen": max(timestamps).isoformat() if timestamps else None,
    }

    notes: list[str] = []
    if mitigated_events:
        notes.append(
            f"{mitigated_events} event(s) were blocked by a control and appear only as low-severity mitigation records; "
            "they are not evidence of a successful compromise."
        )
    if suppressed:
        notes.append(
            f"{len(suppressed)} event(s) from allowlisted source IP(s) {', '.join(sorted(allow))} were suppressed."
        )
    if any(a.rule_id == "AUTH-001" for a in kept):
        notes.append(
            "Repeated authentication failures can also be a user mistyping a password or a stale client; "
            "confirm with the account owner before locking the account."
        )
    if any(a.count == 1 and not a.mitigated for a in kept):
        notes.append(
            "Some compromise alerts rest on a single event. A payload string can occur in legitimate text, "
            "so confirm the request in the access log and with the application owner."
        )
    if not kept:
        notes.append("No event met the configured thresholds. This is not proof that the application is attack-free.")
    notes.append("Only the supplied log files were analysed; no external telemetry was contacted.")

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": summary,
        "alerts": [a.to_dict() for a in kept],
        "false_positive_notes": notes,
        "config": {
            "thresholds": thresholds,
            "allow_ips": sorted(allow),
            "min_severity": min_severity,
        },
    }
