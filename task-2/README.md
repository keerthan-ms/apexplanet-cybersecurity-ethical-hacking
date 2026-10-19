# Task 2 - Network Security & Scanning (Days 13-24)

Everything here runs on this machine, with no administrator rights, using
Python 3.11's standard library plus PowerShell. Every number in
[reports/SCAN-REPORT.md](reports/SCAN-REPORT.md) is a captured output of the
commands in this README - nothing is illustrative.

---

## What the brief asked for, and what exists here

The brief assumes a Kali attacker VM, a Metasploitable2/DVWA target, and the
tools Nmap, Wireshark, OpenVAS and Nessus. None of those exist on this
machine (the repository root README explains why: no hypervisor, no admin
rights to install anything). Task 2's requirements are nevertheless all
covered, either directly or by an explicitly-labelled substitution:

| Brief requirement | What runs here | Notes |
|---|---|---|
| Port scanning (Nmap) | `scripts/portscan.py` - concurrent TCP connect scanner | Full 65535-port sweeps, ranges like `1-1024,3306,8080`, `--top-ports N`, open/closed/filtered classification, `--json` |
| SYN / "stealth" scan | **Not possible** | Raw sockets (`SOCK_RAW` + `IPPROTO_TCP`) are denied without elevation (`WinError 10013`). Every run probes this and prints the result. TCP connect is used instead - see the report's Methodology |
| Banner grabbing / service detection | `portscan.py --banner` | Real grabs: MySQL handshake parsed (version string extracted, e.g. `11.4.7-MariaDB`), plain-HTTP probe, sanitised output. Well-known-port table is labelled a *guess* until a banner confirms it |
| Reconnaissance (DNS, WHOIS, HTTP) | `scripts/recon.py` | A/AAAA via `getaddrinfo`; MX/TXT/NS/CNAME via a hand-written DNS client (wire format, compression pointers, TCP retry on truncation); WHOIS over TCP/43 with the IANA referral chase; one `HEAD` per target |
| Vulnerability scanning (OpenVAS / Nessus) | `scripts/http_security_audit.py` + `scripts/firewall_audit.py` | OpenVAS/Nessus are not installable here. The header audit grades 11 real response-header checks to a /100 score with Apache/Nginx remediation snippets; the firewall audit covers the host-side attack surface. Neither claims to be a CVE scanner |
| Traffic analysis (Wireshark) | **Not possible** | Packet capture on Windows requires Npcap, whose installer requires administrator rights. There is no capture, no workaround, and no invented packet data anywhere in this task |
| Firewall review | `scripts/firewall_audit.py` | Read-only: profiles, enabled inbound-ALLOW rules grouped by profile, rules with remote address `Any`, and a cross-reference of those rules against the machine's actual listening TCP/UDP sockets |
| Evidence / report | `reports/SCAN-REPORT.md` | Real outputs of every command, scope and authorisation statement, limitations, prioritised remediation |

---

## The scripts

### `portscan.py` - TCP connect scanner

```powershell
# Common ports on loopback, with banners
python task-2\scripts\portscan.py --target 127.0.0.1 --top-ports 90 --banner

# Explicit ranges and single ports
python task-2\scripts\portscan.py --ports 1-1024,3306,8080 --banner

# Everything, machine-readable
python task-2\scripts\portscan.py --target 127.0.0.1 --ports 1-65535 --timeout 0.2 --workers 400 --json

# The well-known-port service guess table
python task-2\scripts\portscan.py --service-map
```

Notes: default target is `127.0.0.1` and default ports `1-1024` (a bare run
stays quick). `--top-ports N` and `--ports` are mutually exclusive. On this
machine, connects to non-listening loopback ports time out (the Windows
Filtering Platform drops them instead of sending a RST), so they report as
`filtered`; a port actively refused would report as `closed`. Port 137 is
hard-denied by the platform and is reported as `unknown` with the OS error
verbatim.

### `recon.py` - passive and light-active reconnaissance

```powershell
# DNS + one HEAD per domain
python task-2\scripts\recon.py --domain example.com

# DNS + WHOIS referral chase + HEAD, two domains
python task-2\scripts\recon.py --domain example.com --domain apexplanet.in --whois

# Reverse DNS / WHOIS / HEAD for an IP
python task-2\scripts\recon.py --ip 127.0.0.1

# DNS only (no HTTP), machine-readable
python task-2\scripts\recon.py --domain example.com --dns --whois --json
```

The raw DNS client reads this machine's resolver from the registry
(`Tcpip\Parameters`) and falls back to `ipconfig /all`; it notes in-band if
no resolver can be found. WHOIS starts at `whois.iana.org` and follows the
`refer:` / `whois:` referral, up to three hops.

### `http_security_audit.py` - security header audit

```powershell
# Local app (accepts bare host:port, treats it as http://)
python task-2\scripts\http_security_audit.py --url http://127.0.0.1:8091/

# Public site, machine-readable, warnings count as failures
python task-2\scripts\http_security_audit.py --url https://example.com --json --strict

# Several URLs at once
python task-2\scripts\http_security_audit.py --url https://example.com --url 127.0.0.1:8091
```

Checks (each pass/fail/warn, weighted to 100): Strict-Transport-Security,
Content-Security-Policy (with `unsafe-inline`/`unsafe-eval` detection),
X-Content-Type-Options, X-Frame-Options or CSP `frame-ancestors`,
Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy,
Cross-Origin-Resource-Policy, `Set-Cookie` flags (Secure/HttpOnly/SameSite),
information-disclosure headers, and plain-HTTP-when-HTTPS-is-available.
Output includes copy-pasteable Apache and Nginx snippets for whatever is
missing. Exit codes: 0 clean, 1 failures (or warnings with `--strict`),
2 nothing could be fetched.

### `firewall_audit.py` - read-only Windows Firewall audit

```powershell
# Full audit (about 50 s: each of ~163 rules' filters costs 150-200 ms
# without admin rights; bulk queries are admin-only)
python task-2\scripts\firewall_audit.py

# Quick capped run + machine-readable output
python task-2\scripts\firewall_audit.py --json --max-rules 20
```

Uses `Get-NetFirewallProfile`, `Get-NetFirewallRule`,
`Get-NetFirewallPortFilter`, `Get-NetFirewallAddressFilter`,
`Get-NetTCPConnection -State Listen` and `Get-NetUDPEndpoint` via
`powershell -NoProfile -EncodedCommand`. It only queries: changing rules
needs administrator rights this session does not have, and the tool says so
on every run. If a cmdlet fails, the affected section records the error and
the run continues.

---

## Tests

```powershell
python -m unittest discover -s task-2/tests -v
```

Real result of that command on this machine (2026-10-19):

```
Ran 70 tests in 18.280s

OK
```

The suite is loopback-only and does not depend on external network access:
port parsing (including invalid input), live classification of a socket the
test itself binds, banner sanitisation, MySQL handshake parsing, DNS wire
encode/decode with compression-pointer and loop rejection, WHOIS referral
parsing, two live `http.server` instances with headers under test control
(clean response must out-score dirty), cookie-flag parsing, a capped
end-to-end firewall audit asserting the JSON shape and exit code, and unit
tests that a missing PowerShell cmdlet or executable degrades in-band
instead of raising.

---

## Substitutions

| Brief wanted | Status here | Exact command once the lab exists |
|---|---|---|
| Nmap SYN scan + version + OS detection | Substituted by `portscan.py` (TCP connect only) | `nmap -sS -sV -O -p- 192.168.56.101 -oN nmap-syn-full.txt` |
| Nmap full TCP sweep | Done here as connect scan | `nmap -sT -p- 192.168.56.101 -oN nmap-connect-full.txt` |
| Nmap UDP scan | Not done at all | `nmap -sU --top-ports 50 192.168.56.101 -oN nmap-udp.txt` |
| Wireshark packet capture | **Not possible** (Npcap needs admin) | Install Npcap as admin, then capture on the Host-Only adapter while running `nmap -sS -p 135,445,3306 192.168.56.101` |
| OpenVAS / Nessus vulnerability scan | Substituted by header audit + firewall audit (not a CVE scanner) | `gvm-cli --gmp-username admin --gmp-password <pw> socket --xml "<create_target>..."` or Nessus web UI against `192.168.56.101` |
| Burp Suite interception | Not installed | From Kali: configure browser proxy to `127.0.0.1:8080` with Burp's CA |

---

## Files

```
task-2/
  scripts/
    portscan.py             concurrent TCP connect scanner with banner grabbing
    recon.py                DNS (hand-written wire format) / WHOIS / HEAD recon
    http_security_audit.py  security header audit with scoring and snippets
    firewall_audit.py       read-only Windows Firewall audit
  tests/
    test_portscan.py
    test_recon.py
    test_http_audit.py
    test_firewall_audit.py
  reports/
    SCAN-REPORT.md          real findings from the commands above
```
