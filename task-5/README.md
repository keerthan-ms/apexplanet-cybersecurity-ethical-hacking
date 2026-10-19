# Task 5 — Mini SIEM & Detection (Days 49–60)

A small, real, local SIEM that consumes the security events produced by
[Task 3](../task-3/README.md), detects SQLi, XSS, CSRF, LFI and authentication
abuse, and emits a report in which **every alert carries the events that caused
it**. It is a batch detector over JSONL files, not an enterprise platform: no
database, no agent, no external service, no fabricated alerts.

The schema is the shared
[`docs/LOG-CONTRACT.md`](../docs/LOG-CONTRACT.md).

---

## Data flow

```
Task 3 vulnerable/hardened pages
        │  security events + HTTP access rows
        ▼
task-3/vulnerable/data/security.jsonl
task-3/vulnerable/data/access.log
        │  contract.py: validate, skip malformed lines, count them
        ▼
siem/contract.py ──► siem/rules.py ──► siem/detect.py ──► text / JSON report
                       thresholds,        CLI
                       severity,
                       access correlation,
                       allowlist
```

Blocked events (`sqli_blocked`, `xss_blocked`, `csrf_blocked`, and
`lfi_attempt` with `detail` starting `blocked=1`) are reported as **low-severity
mitigation records**, separate from compromise alerts. A control working is not
an incident.

---

## Run

All commands are from `cybersecurity-ethical-hacking/`.

### 1. Generate real events (Task 3)

Terminal 1:

```powershell
powershell -ExecutionPolicy Bypass -File task-3/scripts/run-demo.ps1
```

Terminal 2:

```powershell
python task-3/scripts/demo_attacks.py
```

That writes 23 security events and 25 access rows for one clean run.

### 2. Detect (Task 5)

```powershell
python task-5/siem/detect.py
```

With no arguments the CLI prefers the **real Task 3 logs**. If they do not
exist, it falls back to the seeded samples and says so on stderr.

Explicit integration run:

```powershell
python task-5/siem/detect.py `
  --events task-3/vulnerable/data/security.jsonl `
  --access task-3/vulnerable/data/access.log
```

Seeded samples only (works without starting Task 3):

```powershell
python task-5/siem/detect.py --samples
```

JSON report:

```powershell
python task-5/siem/detect.py --samples --format json `
  --out task-5/reports/SIEM-SAMPLE-REPORT.json
```

### CLI options

| Flag | Meaning |
|---|---|
| `--events PATH [PATH …]` | Security JSONL file(s); default Task 3 log, then samples |
| `--access PATH` | Access log; defaults to `access.log` beside a single `--events` file |
| `--samples` | Use the committed seeded samples |
| `--config PATH` | JSON file overriding thresholds and allowlist |
| `--allow-ip IP` | Suppress a known scanner/test IP (repeatable) |
| `--min-severity {low,medium,high,critical}` | Hide lower-severity alerts |
| `--format {text,json}` | Report format (default `text`) |
| `--out PATH` | Always write the full JSON report |
| `--fail-on SEVERITY` | Exit `1` if any alert is at or above that severity |

Exit codes: `0` success (unless `--fail-on` triggers), `1` fail-on triggered,
`2` input/config error.

---

## Rules

| Rule | Events | Threshold → severity | Notes |
|---|---|---|---|
| `SQLI-001` | `sqli_attempt` | 1–2 medium, 3–5 high, ≥6 critical | Per source IP |
| `SQLI-002` | `sqli_blocked` | any → low | Mitigated, never a compromise |
| `XSS-001` | `xss_reflected` | 1–2 high, ≥3 critical | Payload in a response |
| `XSS-002` | `xss_stored` | 1–2 high, ≥3 critical | Persisted payload, affects later viewers |
| `XSS-003` | `xss_blocked` | any → low | Encoding neutralised the payload |
| `CSRF-001` | `csrf_missing` | 1–2 high, ≥3 critical | State change accepted without a token |
| `CSRF-002` | `csrf_blocked` | any → low | Token check rejected the request |
| `LFI-001` | `lfi_attempt`, not `blocked=1` | 1–2 high, ≥3 critical | Traversal reached the filesystem layer |
| `LFI-002` | `lfi_attempt` with `detail` `blocked=1` | any → low | Allowlist refused it |
| `AUTH-001` | `auth_fail` | ≥5 in 10 min → high, ≥10 → critical | Per IP **and** user, sliding window |
| `AUTH-002` | `auth_lockout` | any → high | Account lockout observed |

Additional behaviour:

- **Access-log correlation** — each alert looks for a request from the same IP
  on the same path within ±5 seconds and records the HTTP statuses as
  `http_statuses`. A 5xx response bumps an injection alert one severity level.
- **Confidence** — `low` for mitigated events, `medium` for a single
  uncorroborated event, `high` when corroborated or repeated past the threshold.
- **MITRE/CAPEC** — every alert carries `mitre` and `capec` identifiers. CSRF
  has no direct ATT&CK technique and is mapped to `CAPEC-62`.
- **Benign events** — `auth_success`, `registration` and `admin_action` are
  counted in the summary, not alerted on.
- **Malformed lines** are skipped and counted per file; a truncated final write
  cannot hide earlier events.

### Configurable thresholds

Copy [`siem/config.example.json`](siem/config.example.json) and pass it with
`--config`. Partial overrides are deep-merged over the defaults:

```json
{
  "thresholds": {
    "sqli": { "high": 5, "critical": 10 },
    "auth_fail": { "high": 3, "critical": 8, "window_minutes": 5 }
  },
  "allow_ips": ["192.0.2.10"]
}
```

```powershell
python task-5/siem/detect.py --samples --config task-5/siem/config.example.json
```

---

## Expected output

**Actual result on 2026-10-19** for `python task-5/siem/detect.py --samples`:

```
Events: 23 analysed / 23 read (0 allowlisted, 4 benign)
Alerts: 10 total = 6 compromise + 4 mitigated | critical=0 high=5 medium=1 low=4
Corroborated by access log: 10/10
```

| Severity | Rule | What fired | Mitigated |
|---|---|---|---|
| high | `XSS-001` | Reflected `<script>` payload | no |
| high | `XSS-002` | Stored `<svg onload=…>` payload | no |
| high | `AUTH-001` | 5 failures for `admin` in one window | no |
| high | `CSRF-001` | Tokenless profile change accepted | no |
| high | `LFI-001` | `../private/flag.txt` + sandbox-refused escape | no |
| medium | `SQLI-001` | 2 SQLi payloads (login bypass + UNION) | no |
| low | `SQLI-002` | 2 payloads neutralised by prepared statements | yes |
| low | `XSS-003` | 2 payloads encoded at the sink | yes |
| low | `CSRF-002` | 2 forged POSTs rejected with 403 | yes |
| low | `LFI-002` | 1 traversal refused by the allowlist | yes |

The complete machine-generated report is committed at
[`reports/SIEM-SAMPLE-REPORT.json`](reports/SIEM-SAMPLE-REPORT.json). It also
contains the four false-positive notes, per-file parse statistics and the full
matching event objects for every alert.

Example alert shape (from that report):

```json
{
  "rule_id": "LFI-001",
  "severity": "high",
  "title": "Path traversal / local file inclusion attempt",
  "first_seen": "2026-10-19T23:18:43+05:30",
  "last_seen": "2026-10-19T23:18:44+05:30",
  "count": 2,
  "source_ip": "127.0.0.1",
  "user": null,
  "events": [ ... ],
  "mitre": ["T1190", "T1005"],
  "recommendation": "Never build filesystem paths from user input...",
  "confidence": "high",
  "mitigated": false,
  "http_statuses": [200, 403],
  "corroborated": true
}
```

---

## Seeded samples

| File | Contents |
|---|---|
| [`samples/security.jsonl`](samples/security.jsonl) | 23 events copied from one real Task 3 demo run |
| [`samples/access.log`](samples/access.log) | 25 matching HTTP requests |

They were produced on 2026-10-19 23:18 +05:30 by `demo_attacks.py` against the
actual PHP application — not hand-written. The access log is un-ignored in
`.gitignore` specifically so the seeded sample can be committed.

To refresh them, run Task 3 and the harness, then copy both files from
`task-3/vulnerable/data/`.

---

## Tests

```powershell
python -m unittest discover -s task-5/tests -v
```

**Actual result on 2026-10-19:**

```
Ran 22 tests in 0.403s

OK
```

Coverage:

- Both seeded logs parse completely; all required contract fields validate.
- Malformed JSON, missing fields and unknown event names are skipped and counted.
- Each rule fires on its event type, with the expected severity at thresholds.
- Blocked-only input yields **zero** compromise alerts and only low-severity
  mitigation records.
- Benign events (`auth_success`, `registration`, `admin_action`) do not alert.
- Brute force needs 5 failures in the window; 4 does not; 4 + 4 across a
  10-minute gap does not.
- The allowlist suppresses and reports the suppressed count.
- `--min-severity` filters correctly.
- A 500 access-log response raises SQLi severity and marks it corroborated.
- Config overrides and the example config load correctly.
- CLI: seeded JSON report, `--fail-on` exit 1, `--allow-ip` clearing the demo,
  missing input exit 2, malformed input still reporting, `--config` applied.
- Every alert contains the contract fields and exactly the events it counted.

---

## Files

```
task-5/
  siem/
    __init__.py             package metadata
    contract.py             JSONL readers, validation, parse stats
    rules.py                thresholds, severity, windows, correlation, summary
    detect.py               CLI report generator
    config.example.json     documented threshold/allowlist example
  samples/
    security.jsonl          real events from one Task 3 demo run
    access.log              matching HTTP access rows
  reports/
    SIEM-SAMPLE-REPORT.json committed output of --samples
  tests/
    test_siem.py            22 tests
```

---

## Video demonstration (5–7 minutes)

1. **Start Task 3** with `run-demo.ps1`; mention the two log paths.
2. **Generate** events with `demo_attacks.py`; show `18/18 checks passed`.
3. **Show evidence** — open one line of `security.jsonl` and one of
   `access.log`; point out `ts`, `ip`, `event`, `path`, `detail`.
4. **Run the SIEM** with `python task-5/siem/detect.py`. Walk through the
   summary: 23 events, 6 compromise alerts, 4 mitigated, 10/10 corroborated.
5. **Explain one alert** — open the `LFI-001` alert in the JSON report and show
   its two underlying events, HTTP 200/403 statuses and recommendation.
6. **Show false-positive awareness** — point out that the four `*-002`/`-003`
   blocked rules are low severity and that the report says blocked events are
   not compromise evidence. Run `--allow-ip 127.0.0.1` to show suppression.
7. **Change a threshold** with `--config` and show `AUTH-001` disappear when the
   threshold rises above the observed count.
8. **Run the tests** and show `Ran 22 tests … OK`.

---

## Limitations and honest notes

- **Batch, not streaming.** It processes complete JSONL files on each run. A
  production SIEM would tail/ingest continuously.
- **No storage or UI.** Reports are text/JSON; there is no database, dashboard
  server or alert queue. This is deliberate for a local capstone.
- **Rules are signature/threshold based.** They are transparent and testable,
  not anomaly detection. False positives are possible; the report says where.
- **Log integrity is out of scope.** If an attacker can edit the source logs,
  the SIEM cannot detect it. Real pipelines ship logs off-host.
- **Correlation is simple.** Same IP + same path ±5 seconds. It adds HTTP
  evidence, not a full request-to-event join.
- **CSRF is not an ATT&CK technique.** It is mapped to `CAPEC-62` and the
  `mitre` list is empty for those rules.
- The demo's only source IP is `127.0.0.1`. Allowlisting it (as the CLI test
  does) suppresses the entire demo; that is the intended way to prove the
  allowlist works, not a recommended production setting.
