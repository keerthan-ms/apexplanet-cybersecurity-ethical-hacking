# Shared log contract

The deliberately vulnerable application in `task-3/` writes two newline-delimited
JSON files. The mini SIEM in `task-5/siem/` reads them. Both sides must agree on
this schema exactly.

Location (gitignored — regenerated at migration time):

```
task-3/vulnerable/data/security.jsonl   security events, one JSON object per line
task-3/vulnerable/data/access.log       HTTP access log, one JSON object per line
```

Every line is a single UTF-8 JSON object terminated by `\n`. A corrupt or
non-JSON line must be skipped and counted, never abort a read.

## `security.jsonl`

| Field | Type | Required | Meaning |
|---|---|---|---|
| `ts` | string | yes | ISO 8601 with offset, e.g. `2026-10-19T14:03:11+05:30` |
| `ip` | string | yes | Client address as seen by the server |
| `event` | string | yes | One of the values below |
| `path` | string | yes | Request path, e.g. `/login.php` |
| `detail` | string | no | Human-readable detail; may contain the offending input |
| `user` | string | no | Username if one was submitted, else absent |

### `event` values

| Value | Emitted when | Typical `detail` |
|---|---|---|
| `auth_success` | A login succeeded | `user=admin` |
| `auth_fail` | A login failed | `user=admin` |
| `auth_lockout` | Too many failures for one user | `user=admin` |
| `sqli_attempt` | Input matched an SQL injection pattern | the raw input |
| `sqli_blocked` | Injection reached a prepared statement and was neutralised | the raw input |
| `xss_reflected` | Unencoded input echoed into a response | the raw input |
| `xss_stored` | Unencoded input persisted for later rendering | the raw input |
| `xss_blocked` | Output encoding defeated the payload | the raw input |
| `lfi_attempt` | Path traversal or include pattern detected | the raw input |
| `csrf_missing` | State-changing POST arrived with no valid token | the form name |
| `csrf_blocked` | Forged POST was rejected | the form name |
| `registration` | A new account was created | `user=x` |
| `admin_action` | An administrator changed data | what changed |

## `access.log`

| Field | Type | Required | Meaning |
|---|---|---|---|
| `ts` | string | yes | ISO 8601 with offset |
| `ip` | string | yes | Client address |
| `method` | string | yes | `GET`, `POST`, … |
| `path` | string | yes | Request path including query string if present |
| `status` | int | yes | HTTP status code |
| `ua` | string | yes | `User-Agent`, or `-` if absent |
| `dur_ms` | int | yes | Server-side duration in milliseconds |

## Detector expectations (`task-5/siem/rules.py`)

A rule consumes a stream of these objects and emits alerts shaped as:

```json
{
  "rule_id": "BRUTEFORCE-001",
  "severity": "high",
  "title": "Repeated authentication failures",
  "first_seen": "…", "last_seen": "…",
  "count": 12,
  "source_ip": "127.0.0.1",
  "user": "admin",
  "events": [ ...the matching events, in order... ],
  "mitre": ["T1110.001"],
  "recommendation": "…"
}
```

Severity is one of `low`, `medium`, `high`, `critical`.
