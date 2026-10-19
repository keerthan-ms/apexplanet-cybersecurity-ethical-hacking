# Task 3 — Web Application Security (Days 25–36)

A deliberately vulnerable local web application and its hardened counterpart,
covering **SQL injection, XSS, CSRF and LFI/path traversal**. Every exploit and
every mitigation runs on this machine against fake SQLite data.

> **TRAINING ONLY.** This application contains real, working vulnerabilities on
> purpose. It binds to `127.0.0.1` only, uses synthetic accounts and fixtures,
> and must never be deployed or exposed on a network interface. The vulnerable
> LFI route is additionally sandboxed to `task-3/fixtures/` so it cannot read
> app source, arbitrary host files or anything outside the demo fixtures.

---

## Stack

| Component | Choice | Why |
|---|---|---|
| Runtime | Portable PHP 8.3 (`..\_runtime\php\php.exe`) | Already installed by the Full Stack track; no new runtime |
| Server | PHP built-in server | No Apache/admin rights needed |
| Data | SQLite (`pdo_sqlite`, enabled per command) | No database service to start |
| Harness / tests | Python 3.11 + `requests` | Already used across Tasks 2 and 4 |

The app writes the two log files defined in
[`docs/LOG-CONTRACT.md`](../docs/LOG-CONTRACT.md):

```
task-3/vulnerable/data/security.jsonl
task-3/vulnerable/data/access.log
```

`vulnerable/data/` is gitignored and recreated automatically.

---

## One-command run

From the repository root (`cybersecurity-ethical-hacking/`):

```powershell
powershell -ExecutionPolicy Bypass -File task-3/scripts/run-demo.ps1
```

It resolves PHP in this order: `$APEX_PHP`, `php` on `PATH`, then
`..\_runtime\php\php.exe`, and starts:

```
http://127.0.0.1:8091/
```

Use `-Port 8095` to change the port. The script hard-codes `127.0.0.1`; there
is no option to bind another interface.

Equivalent raw command:

```powershell
..\_runtime\php\php.exe -d extension=pdo_sqlite -d extension=sqlite3 `
  -S 127.0.0.1:8091 -t task-3\public task-3\public\router.php
```

The `-d extension=...` flags load SQLite from the portable PHP build without
modifying its shared `php.ini`.

### Routes

| Vulnerability | Vulnerable | Hardened |
|---|---|---|
| SQL injection | `/vuln/sqli` | `/secure/sqli` |
| XSS (reflected + stored) | `/vuln/xss` | `/secure/xss` |
| CSRF | `/vuln/csrf` | `/secure/csrf` |
| LFI / traversal | `/vuln/lfi` | `/secure/lfi` |
| Overview | `/` | — |

The banner at the top of every page says **TRAINING ONLY**, and the vulnerable
and hardened sections are visually separated and reachable only through their
own routes.

---

## Generate the proof-of-concept traffic

With the server running, in a second terminal:

```powershell
python task-3/scripts/demo_attacks.py
```

This is the repeatable exploit harness. It sends:

1. SQLi login bypass: `admin' -- ` → vulnerable route signs in as admin,
   hardened route rejects it.
2. SQLi UNION extraction: `' UNION SELECT 999, username, password_hash, 'leaked' FROM users -- `
   → vulnerable route returns a synthetic row containing a **fake** password
   digest; hardened route returns no injected row.
3. Reflected XSS: `<script>window.__xss=1</script>` → raw on the vulnerable
   page, `&lt;script&gt;` on the hardened page.
4. Stored XSS: `<svg onload=alert('stored-xss')>` → raw on the vulnerable
   guestbook, encoded on the hardened guestbook.
5. CSRF: forged email change without a token → accepted by the vulnerable
   route (HTTP 200), rejected by the hardened route (HTTP 403).
6. LFI: `../private/flag.txt` → read by the vulnerable route, 403 on the
   hardened route. `../../../README.md` (outside `task-3/fixtures/`) and
   `../app/bootstrap.php` (app source) are refused by the vulnerable route's
   lab sandbox with 403.
7. Five failed logins → `auth_fail` events for the Task 5 brute-force rule.

Options:

```powershell
python task-3/scripts/demo_attacks.py --only csrf
python task-3/scripts/demo_attacks.py --json
python task-3/scripts/demo_attacks.py --base-url http://127.0.0.1:8091
```

**Actual result on 2026-10-19:**

```
18/18 checks passed
Security events: task-3/vulnerable/data/security.jsonl
Access log:      task-3/vulnerable/data/access.log
```

The harness exits `1` if any expectation fails and `2` if the server cannot be
reached.

---

## Tests

```powershell
python -m unittest discover -s task-3/tests -v
```

**Actual result on 2026-10-19:**

```
Ran 13 tests in 1.235s

OK
```

The suite starts its **own** PHP server on a temporary port with a temporary
data directory, so it does not disturb a running demo on `:8091` and leaves no
state behind. It asserts:

| Area | Assertion |
|---|---|
| Safety | Page carries the TRAINING ONLY warning; launcher contains no `0.0.0.0` |
| SQLi | Vulnerable login returns the admin session; hardened login fails |
| SQLi | UNION row `id=999, role=leaked` appears only on the vulnerable search |
| XSS | Raw `<script>` only in vulnerable reflected output; `&lt;script&gt;` in hardened |
| XSS | Stored `<svg onload=…>` is raw only on the vulnerable guestbook |
| CSRF | Vulnerable POST changes the email; hardened POST returns 403 and does not |
| CSRF | A forged token is rejected; the real session token is accepted |
| LFI | `../private/flag.txt` is read by vulnerable, 403 by hardened |
| LFI | `../../../README.md` and app source (`../../app/bootstrap.php`) are refused by the lab sandbox with 403 |
| Logs | Every security/access line validates against `docs/LOG-CONTRACT.md` |

No test touches a network host other than `127.0.0.1`.

---

## Why each mitigation works

| Weakness | Vulnerable code | Hardened code |
|---|---|---|
| SQLi | `"... WHERE username = '$u' ..."` | `$stmt = $pdo->prepare('... WHERE username = ?'); $stmt->execute([$u]);` |
| XSS | `echo $name` | `htmlspecialchars($name, ENT_QUOTES \| ENT_SUBSTITUTE, 'UTF-8')` at every sink |
| CSRF | no token | `random_bytes(16)` in `$_SESSION`, checked with `hash_equals()` before writes |
| LFI | `FIXTURE_PUBLIC . '/' . $_GET['file']` | exact filename allowlist + `realpath()` inside the public fixture directory |

The hardened pages still record the attempt (`sqli_blocked`, `xss_blocked`,
`csrf_blocked`, `lfi_attempt` with `blocked=1`) so Task 5 can distinguish a
blocked attempt from a successful one.

---

## Files

```
task-3/
  public/router.php          single entry point, access log, security headers
  app/bootstrap.php          SQLite fixtures, contract logger, CSRF/detection helpers
  app/layout.php             TRAINING ONLY banner, navigation, styles
  app/pages/
    home.php                 overview + SIEM instructions
    sqli.php                 login and search, both modes
    xss.php                  reflected and stored, both modes
    csrf.php                 profile email change, both modes
    lfi.php                  fixture reader, both modes
  fixtures/
    public/welcome.txt       allowed in both modes
    public/readme.txt        allowed in both modes
    private/flag.txt         reachable only via vulnerable traversal
    private/internal-memo.txt
  scripts/
    run-demo.ps1             one-command loopback launcher
    demo_client.py           shared HTTP client and payload list
    demo_attacks.py          repeatable 18-check exploit harness
  tests/test_web_demo.py     isolated end-to-end suite (13 tests)
  vulnerable/data/           gitignored: SQLite, security.jsonl, access.log, sessions
```

---

## Video demonstration (7–9 minutes)

1. **Start** `run-demo.ps1`. Show the TRAINING ONLY banner, the URL, and the
   event/access log paths it prints.
2. **SQLi** — open `/vuln/sqli`, sign in with `admin' -- ` and any password.
   Point out the granted admin session. Run the UNION payload in search and
   show the `leaked` row. Repeat both on `/secure/sqli`: login fails, no row.
3. **XSS** — open `/vuln/xss?name=<script>window.__xss=1</script>` and use
   View Source to show raw markup. Post `<svg onload=...>` to the guestbook and
   show it raw. Repeat on `/secure/xss`: source shows encoded text.
4. **CSRF** — on `/vuln/csrf`, change the email; note there is no token. Then
   show `/secure/csrf` has a hidden token, and run
   `demo_attacks.py --only csrf` to show the 403 for the tokenless POST.
5. **LFI** — `/vuln/lfi?file=../private/flag.txt` shows the fake flag.
   `?file=../../../README.md` is refused with 403 (lab sandbox). `/secure/lfi`
   refuses both and still serves `welcome.txt`.
6. **Evidence** — run `demo_attacks.py` fully, show `18/18 checks passed`, then
   open `security.jsonl` and point out the contract fields.
7. **Hand-off** — in `task-5/`, run
   `python task-5/siem/detect.py` and show that the SIEM read these events and
   raised SQLi/XSS/CSRF/LFI alerts, with blocked attempts reported as
   low-severity mitigations.

---

## Limitations and honest notes

- Accounts, password digests, emails and fixtures are synthetic. No real
  credentials, external systems or host files are used.
- The app is single-user by design: every browser session is the fake `demo`
  account until the SQLi demo signs in as `admin`.
- Cookies are not `Secure` because the demo is plain HTTP on loopback; they are
  `HttpOnly` and `SameSite=Lax`.
- Detection regexes in `bootstrap.php` are for **labelling events**, not for
  sanitisation. Every hardened control is structural (prepared statement,
  encoding, token, allowlist).
- The vulnerable LFI route is intentionally weak but sandboxed to
  `task-3/fixtures/`; that rail is a lab safety measure, not part of the
  vulnerability.
