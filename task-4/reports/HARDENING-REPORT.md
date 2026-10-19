# Task 4 - Windows host hardening report

Date: 2026-10-19. Machine: Windows 11 laptop (LAPTOP-EAP7GUSJ), Python
3.11.9, PowerShell 5.1.26100.9711, session **not elevated**
(`BUILTIN\Administrators` is deny-only, and the audit's own collector
reports `admin token: no`).

Every number and every line of output below was produced by the commands
shown, run on this machine on this date. Nothing is illustrative or copied
from elsewhere.

---

## Scope and authorisation

**Audited (with permission - this machine only):** the operator's own
workstation, `LAPTOP-EAP7GUSJ`.

The audit is **read-only by construction**. It only queries
configuration: CIM/WMI instance reads, `netsh advfirewall show
allprofiles`, `Get-Service`, registry *reads*, `Get-SmbShare`,
`Get-MpComputerStatus`, `Get-HotFix`, `Get-NetTCPConnection`, `net
accounts`, `Get-LocalGroupMember`/`Get-LocalUser`. Two collectors would
like to write: `auditpol /get` needs an elevated token (it fails with a
privilege error and is reported as `skipped`), and the password-complexity
check exports a short-lived file to `%TEMP%` via `secedit /export` and
deletes it immediately in a `finally` block. No service, account,
registry value, firewall rule or policy was changed by any run of this
tool, and the tool prints that statement at the end of every human-format
report.

No third-party system was contacted at all. This report contains no CVE
scan: OpenVAS and Nessus are not installed on this machine (see the
repository root README), and the tool does not pretend to be one.

---

## What was run (exact commands)

```powershell
# 1. Full audit, machine-readable (the source of every number below)
python task-4\scripts\hardening_audit.py --profile full --json

# 2. Quick profile - run for real by the test suite (5 collectors)
python -m unittest discover -s task-4/tests -v
```

The full profile runs 12 collectors in order: system context, firewall
profiles, remote services, SMB shares, UAC, password policy, local
admins, Defender, hotfix age, audit policy, Winlogon auto-logon secrets,
listening TCP ports.

---

## How the score is computed

Each check carries a severity weight (critical 3.0, high 2.0, medium 1.0,
low 0.5) and a status. Only `pass`, `warn` and `fail` are scored: a pass
earns the full weight, a warn earns half, a fail earns nothing. The score
is `100 * earned / possible`. Bands: 90+ strong, 75+ good, 50+ needs
attention, below 50 weak. Informational and skipped checks do not change
the score.

This run, with the real captured counts:

```
weighted points earned = 25.5 of 31.5 possible
score                  = 100 * 25.5 / 31.5 = 80.95 -> 81.0
band                   = "good" (75 <= 81.0 < 90)
```

---

## Result at a glance

From the run's own summary block (`--profile full --json`,
2026-10-19T17:17:25+00:00):

| Field | Value |
|---|---|
| Score | **81.0 / 100** |
| Band | **good** |
| Checks | 33 total: 20 pass, 0 warn, 4 fail, 7 info, 2 skipped (24 scored) |
| Collectors | 12 of 12 ran with status `ok` |
| Elapsed | 14,045 ms |
| Elevation | admin token: no - elevation-dependent checks report `skipped` |

### Host context (as reported by the audit)

| Field | Value |
|---|---|
| Host name | LAPTOP-EAP7GUSJ |
| Operating system | Microsoft Windows 11 Home Single Language (build 26300) |
| PowerShell | 5.1.26100.9711 |
| User | Keerthan MS |
| Token elevation | no |
| Time since reboot | 51.4 hours |

---

## Findings

### Passed (20 checks)

| Check | Detail |
|---|---|
| Firewall Domain profile | state=ON, policy=BlockInbound,AllowOutbound |
| Firewall Private profile | state=ON, policy=BlockInbound,AllowOutbound |
| Firewall Public profile | state=ON, policy=BlockInbound,AllowOutbound |
| Default inbound action | all enabled profiles block inbound by default |
| WinRM remote management | service status=Stopped, start type=Manual |
| Remote Desktop (RDP) | RDP is disabled (fDenyTSConnections=1) |
| SMBv1 protocol | EnableSMB1Protocol=False |
| SMB signing | RequireSecuritySignature=True, EncryptData=False |
| Non-default file shares | only the default administrative shares |
| UAC (EnableLUA) | EnableLUA=1 |
| UAC elevation prompt | ConsentPromptBehaviorAdmin=5 |
| UAC secure desktop | PromptOnSecureDesktop=1 |
| Account lockout threshold | 10 failed attempts |
| Local Administrators group | 2 member(s): LAPTOP-EAP7GUSJ\Administrator, LAPTOP-EAP7GUSJ\Keerthan MS |
| Built-in Guest account | Guest enabled=False |
| Antivirus service | AntivirusEnabled=True, AMService=True |
| Malware definition age | definitions updated 0 day(s) ago |
| Most recent Windows update | KB5127648 installed 2026-10-14 (6 day(s) ago, 5 update record(s)) |
| Winlogon DefaultPassword value | no DefaultPassword value stored |
| Automatic logon (AutoAdminLogon) | AutoAdminLogon=(unset) |

### Failed (4 checks)

| # | Check | Severity | Captured detail | Action the audit recommends |
|---|---|---|---|---|
| 1 | Real-time protection | high | RealTimeProtection=False | Enable real-time monitoring: `Set-MpPreference -DisableRealtimeMonitoring $false` |
| 2 | Externally bound TCP listeners | high | bound to a non-loopback address: 5432/PostgreSQL (postgres) | Firewall or rebind these services to loopback only: 5432/PostgreSQL |
| 3 | Password history | medium | 0 previous password(s) remembered | Remember at least 10 previous passwords (Enforce password history) |
| 4 | Minimum password length | medium | minimum length = 0 | Raise the minimum length to 14+ characters (secpol.msc > Account Policies > Password Policy) |

Notes on the two high-severity failures:

- **Real-time protection off.** The Defender *service* is on and the
  definitions are fresh (0 days), but `RealTimeProtectionEnabled=False`
  at the moment of the run, so file activity is not being scanned in
  real time. The audit records the state as found; it does not change it.
- **PostgreSQL on a non-loopback address.** The listener inventory shows
  27 listening sockets, and the risky-port check names
  `5432/PostgreSQL (postgres)` as bound to something other than
  loopback. Port 3306 (MariaDB) also appears in the inventory but is
  *absent* from the risky list, which is exactly how the collector works:
  a risky port is only flagged when a listener row is not loopback, so
  MariaDB is bound to loopback on this machine and PostgreSQL is not.

### Skipped because this session is not elevated (2 checks)

| Check | Captured reason |
|---|---|
| Password complexity requirement | `secedit unavailable: ["SECEdit_EXPORT_FAILED"]` - the security database cannot be exported without elevation |
| Audit policy coverage | `auditpol unavailable: Error 0x00000522 occurred: A required privilege is not held by the client.` |

Both are honest gaps, not passes: the report says what to do (re-run
from an elevated prompt) rather than guessing a value.

### Informational (7 checks)

Host name; OS context; elevation state; uptime; maximum password age =
42 days; Winlogon default user = Keerthan MS (the *name* is shown, and
there is no stored password to show); listener inventory
`27 listener(s): 135, 139, 445, 3306, 5040, 5432, 42050, 49664, 49665,
49666, 49667, 49668, 49669, 49670, 57865, 57866, 57867, 57870, 61632`.

---

## Prioritised remediation (the audit's own output)

Failures before warnings, high severity before medium. All four entries
below are copied from the run's `remediation` array:

```
 1. [high    ] Real-time protection (fail)
    Enable real-time monitoring: Set-MpPreference -DisableRealtimeMonitoring $false
 2. [high    ] Externally bound TCP listeners (fail)
    Firewall or rebind these services to loopback only: 5432/PostgreSQL
 3. [medium  ] Password history (fail)
    Remember at least 10 previous passwords (Enforce password history)
 4. [medium  ] Minimum password length (fail)
    Raise the minimum length to 14+ characters (secpol.msc > Account Policies > Password Policy)
```

After applying 1-4 from an elevated prompt, re-running the same command
would be the verification step. That was **not** done here: this audit
changes nothing, and changing Defender, firewall or password policy is an
operator decision outside a read-only assessment.

---

## Collector timings (as captured)

| Collector | Status | Elapsed (ms) |
|---|---|---|
| system_context | ok | 794 |
| firewall_profiles | ok | 401 |
| remote_services | ok | 429 |
| smb_shares | ok | 3,201 |
| uac_policy | ok | 396 |
| password_policy | ok | 720 |
| local_admins | ok | 494 |
| defender_status | ok | 2,341 |
| hotfix_age | ok | 1,706 |
| audit_policy | ok | 283 |
| autologon_secrets | ok | 411 |
| listening_ports | ok | 2,865 |
| **Total (summary.elapsed_ms)** | | **14,045** |

The slowest collectors are the ones that enumerate objects (SMB shares,
listening ports, Defender status). Firewall profiles took 401 ms because
the tool prefers `netsh advfirewall show allprofiles` (~0.2 s) and only
falls back to `Get-NetFirewallProfile` (~5.6 s) when the netsh text
cannot be parsed.

---

## Test-suite evidence

The test suite runs the quick profile for real against this machine (5
collectors), and asserts the report shape, count consistency, band
derivation, remediation ordering and the read-only statement:

```
Ran 97 tests in 13.569s

OK
```

Full detail: [../README.md](../README.md) (Tests section).

---

## Limitations

1. **One snapshot of one machine.** The score describes this host at
   17:17 UTC on 2026-10-19 and decays as soon as anything changes.
2. **Not elevated.** Password complexity and audit-policy coverage are
   `skipped`, not scored. A full picture needs one run from an elevated
   prompt; the tool is written so that elevation only *adds* checks.
3. **No CVE / vulnerability scanning.** The checks are configuration
   baselines (firewall, UAC, SMB, password policy, patch recency,
   listeners), not CVE matching. OpenVAS/Nessus are not installable
   here (repository root README).
4. **English locale assumed for `netsh`.** The parser matches
   `Domain Profile Settings:` / `State ON` text. On a localised system
   it would fall back to the cmdlet, which costs ~5 s more but produces
   the same checks.
5. **Score weights are a documented convention**, not a standard. They
   are defined in `hardening_audit.py` (`SEVERITY_WEIGHT`) and the
   formula is shown above so the number can be recomputed from the raw
   counts.

---

## Reproducing this report

```powershell
python task-4\scripts\hardening_audit.py --profile full          # human report
python task-4\scripts\hardening_audit.py --profile full --json   # the JSON this report was written from
python task-4\scripts\hardening_audit.py --profile quick         # 5 collectors, ~7 s
python -m unittest discover -s task-4/tests -v                   # suite (runs quick profile too)
```

No system setting was changed by this audit.
