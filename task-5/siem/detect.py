#!/usr/bin/env python3
"""ApexPlanet Task 5 - minimal local SIEM CLI.

Reads the Task 3 security/access logs (docs/LOG-CONTRACT.md), applies the
thresholded rules in rules.py, and prints a report. It does not call any
network service and does not invent alerts: every alert contains the matching
events that produced it.

Examples:
    # Prefer the real Task 3 logs; fall back to seeded samples if absent
    python task-5/siem/detect.py

    # Explicit integration run
    python task-5/siem/detect.py \
        --events task-3/vulnerable/data/security.jsonl \
        --access task-3/vulnerable/data/access.log

    # Seeded samples, JSON report
    python task-5/siem/detect.py --samples --format json --out task-5/reports/report.json

    # Fail CI on high or worse
    python task-5/siem/detect.py --samples --fail-on high
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from siem import __version__  # noqa: E402
from siem.contract import read_access_many, read_security_many  # noqa: E402
from siem.rules import SEVERITY_ORDER, analyze, load_config  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
TASK3_DATA = REPO_ROOT / "task-3" / "vulnerable" / "data"
SAMPLES = REPO_ROOT / "task-5" / "samples"


def _resolve_sources(args: argparse.Namespace) -> tuple[list[Path], Path | None, str]:
    if args.samples:
        return [SAMPLES / "security.jsonl"], SAMPLES / "access.log", "samples"

    if args.events:
        security = [Path(p) for p in args.events]
        access = Path(args.access) if args.access else None
        if access is None and len(security) == 1:
            sibling = security[0].with_name("access.log")
            if sibling.exists():
                access = sibling
        return security, access, "explicit"

    task3_security = TASK3_DATA / "security.jsonl"
    if task3_security.exists() and task3_security.stat().st_size > 0:
        access = Path(args.access) if args.access else TASK3_DATA / "access.log"
        return [task3_security], access, "task3"

    sample_security = SAMPLES / "security.jsonl"
    if sample_security.exists():
        print(
            "note: Task 3 log not found; using seeded samples in task-5/samples/ "
            "(run the Task 3 demo to generate real events)",
            file=sys.stderr,
        )
        return [sample_security], SAMPLES / "access.log", "samples-fallback"

    return [task3_security], TASK3_DATA / "access.log", "task3-missing"


def _severity_ge(left: str, right: str) -> bool:
    return SEVERITY_ORDER[left] >= SEVERITY_ORDER[right]


def _display(path_like: str | Path) -> str:
    """Repository-relative path for report portability."""
    path = Path(path_like)
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except (ValueError, OSError):
        return str(path)


def render_text(report: dict[str, Any]) -> str:
    summary = report["summary"]
    sources = report["sources"]
    parsing = report["parsing"]
    lines: list[str] = []
    lines.append("")
    lines.append("ApexPlanet Mini SIEM - Task 5")
    lines.append("=============================")
    lines.append(f"Generated: {report['generated_at']}")
    lines.append(f"Source mode: {sources['mode']}")
    lines.append(f"Security events: {', '.join(sources['security'])}")
    lines.append(f"Access log:      {sources['access'] or '(none)'}")
    for part in parsing["security"]:
        lines.append(
            f"Parsed security: {part['valid']} valid, {part['skipped']} skipped, {part['lines']} non-empty lines"
        )
        for error in part["errors"][:3]:
            lines.append(f"  skipped {error}")
    if parsing["access"]:
        part = parsing["access"]
        lines.append(f"Parsed access:   {part['valid']} valid, {part['skipped']} skipped")
        for error in part["errors"][:3]:
            lines.append(f"  skipped {error}")
    lines.append("")
    severity = summary["severity"]
    lines.append(
        f"Events: {summary['analyzed_events']} analysed / {summary['total_events']} read "
        f"({summary['suppressed_allowlisted']} allowlisted, {summary['benign_events']} benign)"
    )
    lines.append(
        f"Alerts: {summary['alerts']} total = {summary['compromise_alerts']} compromise + "
        f"{summary['mitigated_alerts']} mitigated | "
        f"critical={severity['critical']} high={severity['high']} "
        f"medium={severity['medium']} low={severity['low']}"
    )
    lines.append(f"Corroborated by access log: {summary['corroborated_alerts']}/{summary['alerts']}")
    if summary["first_seen"]:
        lines.append(f"Window: {summary['first_seen']} .. {summary['last_seen']}")
    lines.append("")

    if not report["alerts"]:
        lines.append("No alerts matched the configured thresholds.")
    for alert in report["alerts"]:
        tag = "MITIGATED" if alert["mitigated"] else "COMPROMISE"
        lines.append(f"[{alert['severity'].upper():8}] {alert['rule_id']}  {alert['title']}  ({tag})")
        lines.append(
            f"           source_ip={alert['source_ip']} user={alert['user'] or '-'} "
            f"count={alert['count']} confidence={alert['confidence']}"
        )
        lines.append(f"           first={alert['first_seen']}  last={alert['last_seen']}")
        if alert["http_statuses"]:
            lines.append(
                f"           access corroboration: HTTP {', '.join(str(s) for s in alert['http_statuses'])}"
            )
        detail = ""
        if alert["events"]:
            detail = str(alert["events"][0].get("detail", ""))
        if detail:
            lines.append(f"           first detail: {detail[:160]}")
        recommendation = alert["recommendation"]
        lines.append(f"           action: {recommendation}")
        lines.append("")

    lines.append("False-positive awareness")
    for note in report["false_positive_notes"]:
        lines.append(f"- {note}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Minimal SIEM over the Task 3 security logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--events", nargs="+", help="security.jsonl file(s); default Task 3 log, then samples")
    parser.add_argument("--access", help="access.log file; defaults to the sibling of --events")
    parser.add_argument("--samples", action="store_true", help="use the committed seeded samples")
    parser.add_argument("--config", help="JSON thresholds/allowlist file")
    parser.add_argument("--allow-ip", action="append", default=[], help="suppress alerts from this IP (repeatable)")
    parser.add_argument(
        "--min-severity", choices=list(SEVERITY_ORDER), default="low",
        help="hide alerts below this severity",
    )
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--out", help="write the full JSON report to this path")
    parser.add_argument(
        "--fail-on", choices=list(SEVERITY_ORDER),
        help="exit 1 if any alert is at or above this severity",
    )
    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot load config: {exc}", file=sys.stderr)
        return 2

    security_paths, access_path, mode = _resolve_sources(args)
    missing = [str(p) for p in security_paths if not p.exists()]
    if access_path is not None and not access_path.exists():
        missing.append(str(access_path))
    if missing:
        print("ERROR: input file(s) not found:", file=sys.stderr)
        for path in missing:
            print(f"  {path}", file=sys.stderr)
        if mode in ("task3", "task3-missing"):
            print(
                "Start Task 3 and run task-3/scripts/demo_attacks.py to generate them, "
                "or use --samples.",
                file=sys.stderr,
            )
        return 2

    try:
        security_events, security_stats = read_security_many(security_paths)
        access_events = None
        access_stats = None
        if access_path is not None:
            access_events, access_stat_list = read_access_many([access_path])
            access_stats = access_stat_list[0].to_dict() if access_stat_list else None
    except OSError as exc:
        print(f"ERROR: cannot read input: {exc}", file=sys.stderr)
        return 2

    analysis = analyze(
        security_events,
        access_events,
        config=config,
        allow_ips=args.allow_ip,
        min_severity=args.min_severity,
    )

    report: dict[str, Any] = {
        "tool": "apexplanet-mini-siem",
        "version": __version__,
        "sources": {
            "mode": mode,
            "security": [_display(p) for p in security_paths],
            "access": _display(access_path) if access_path else None,
        },
        "parsing": {
            "security": [
                {**s.to_dict(), "path": _display(s.path)} for s in security_stats
            ],
            "access": (
                {**access_stats, "path": _display(access_stats["path"])}
                if access_stats else None
            ),
        },
        **analysis,
    }

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"JSON report written to {out_path}", file=sys.stderr)

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(render_text(report))

    if args.fail_on:
        worst = max((a["severity"] for a in report["alerts"]), key=lambda s: SEVERITY_ORDER[s], default="low")
        if report["alerts"] and _severity_ge(worst, args.fail_on):
            print(f"FAIL: worst alert severity {worst} >= --fail-on {args.fail_on}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
