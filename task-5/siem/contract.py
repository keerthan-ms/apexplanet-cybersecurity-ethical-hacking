"""Readers for the shared log contract in docs/LOG-CONTRACT.md.

Both files are newline-delimited JSON. A malformed line is skipped and counted;
it never aborts a read. That matters in a SIEM: one truncated write at the end
of a log must not hide every event before it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

SECURITY_REQUIRED = ("ts", "ip", "event", "path")
ACCESS_REQUIRED = ("ts", "ip", "method", "path", "status", "ua", "dur_ms")

KNOWN_EVENTS = frozenset({
    "auth_success", "auth_fail", "auth_lockout",
    "sqli_attempt", "sqli_blocked",
    "xss_reflected", "xss_stored", "xss_blocked",
    "lfi_attempt",
    "csrf_missing", "csrf_blocked",
    "registration", "admin_action",
})


@dataclass
class ParseStats:
    """How much of a file was usable, and why the rest was not."""

    path: str
    lines: int = 0
    valid: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)

    def skip(self, line_number: int, reason: str) -> None:
        self.skipped += 1
        if len(self.errors) < 20:
            self.errors.append(f"line {line_number}: {reason}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "lines": self.lines,
            "valid": self.valid,
            "skipped": self.skipped,
            "errors": self.errors,
        }


def parse_ts(value: Any) -> datetime:
    """Parse an ISO 8601 timestamp, accepting a trailing Z."""
    if not isinstance(value, str) or not value:
        raise ValueError("ts must be a non-empty string")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    return datetime.fromisoformat(text)


def _security_ok(row: dict[str, Any]) -> str | None:
    for key in SECURITY_REQUIRED:
        if key not in row:
            return f"missing field {key!r}"
    if not isinstance(row["ip"], str) or not row["ip"]:
        return "ip must be a non-empty string"
    if not isinstance(row["path"], str) or not row["path"].startswith("/"):
        return "path must start with /"
    if row["event"] not in KNOWN_EVENTS:
        return f"event {row['event']!r} is not in the contract"
    try:
        parse_ts(row["ts"])
    except ValueError as exc:
        return f"bad ts: {exc}"
    return None


def _access_ok(row: dict[str, Any]) -> str | None:
    for key in ACCESS_REQUIRED:
        if key not in row:
            return f"missing field {key!r}"
    if not isinstance(row["ip"], str) or not row["ip"]:
        return "ip must be a non-empty string"
    if not isinstance(row["path"], str):
        return "path must be a string"
    if not isinstance(row["method"], str) or not row["method"]:
        return "method must be a non-empty string"
    if not isinstance(row["status"], int) or isinstance(row["status"], bool):
        return "status must be an integer"
    if not isinstance(row["dur_ms"], int) or isinstance(row["dur_ms"], bool) or row["dur_ms"] < 0:
        return "dur_ms must be a non-negative integer"
    if not isinstance(row["ua"], str) or not row["ua"]:
        return "ua must be a non-empty string"
    try:
        parse_ts(row["ts"])
    except ValueError as exc:
        return f"bad ts: {exc}"
    return None


def _read(path: Path, validator) -> tuple[list[dict[str, Any]], ParseStats]:
    stats = ParseStats(path=str(path))
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            stats.lines += 1
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                stats.skip(line_number, f"invalid JSON ({exc.msg})")
                continue
            if not isinstance(row, dict):
                stats.skip(line_number, "line is not a JSON object")
                continue
            problem = validator(row)
            if problem:
                stats.skip(line_number, problem)
                continue
            stats.valid += 1
            rows.append(row)
    return rows, stats


def read_security(path: str | Path) -> tuple[list[dict[str, Any]], ParseStats]:
    return _read(Path(path), _security_ok)


def read_access(path: str | Path) -> tuple[list[dict[str, Any]], ParseStats]:
    return _read(Path(path), _access_ok)


def read_security_many(paths: Iterable[str | Path]) -> tuple[list[dict[str, Any]], list[ParseStats]]:
    rows: list[dict[str, Any]] = []
    stats: list[ParseStats] = []
    for path in paths:
        part, part_stats = read_security(path)
        rows.extend(part)
        stats.append(part_stats)
    return rows, stats


def read_access_many(paths: Iterable[str | Path]) -> tuple[list[dict[str, Any]], list[ParseStats]]:
    rows: list[dict[str, Any]] = []
    stats: list[ParseStats] = []
    for path in paths:
        part, part_stats = read_access(path)
        rows.extend(part)
        stats.append(part_stats)
    return rows, stats
