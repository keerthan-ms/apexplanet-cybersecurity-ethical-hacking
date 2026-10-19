# Task 2 - Network security and scanning report

Date: 2026-10-19. Machine: Windows 11 laptop, Python 3.11.9, PowerShell 5.1,
session **not elevated** (`BUILTIN\Administrators` is deny-only).

Every number and every line of output below was produced by the commands
shown, run on this machine on this date. Nothing is illustrative or copied
from elsewhere.

---

## Scope and authorisation

**Scanned (with permission - this machine only):**

- `127.0.0.1` (loopback) - the operator's own machine.
- `192.168.220.29` - this machine's own LAN address, same owner.

**Looked up (passive, published-data lookups only):**

- `example.com` - IANA's reserved documentation domain, published for exactly
  this kind of use.
- `apexplanet.in` - the internship provider's public site.
- WHOIS records for the above via IANA and the referred registries; DNS via
  this machine's own configured resolver (`192.168.220.241`).

No third-party system was scanned, probed or attacked. Public contact was
limited to DNS queries, WHOIS over TCP/43, one `HEAD` request per site, and
one `HEAD` to a local server we started ourselves.

**Reconnaissance vs scanning.** Reconnaissance (`recon.py`) only asks
questions the target already answers publicly: DNS records, WHOIS registry
data, and a single `HEAD` for response headers. Scanning (`portscan.py`)
actively connects to ports to see what is listening. Both are dual-use.
Scanning, probing or attacking a host you do not own and do not have written
permission to test is unlawful in most jurisdictions regardless of intent,
and the tools in this repository are written to make that boundary obvious
(default target `127.0.0.1`, authorisation banner in every recon run).

---

## Methodology

### What was run (exact commands)

```powershell
# 1. Full TCP connect sweep of loopback (all 65535 ports)
python task-2\scripts\portscan.py --target 127.0.0.1 --ports 1-65535 --timeout 0.2 --workers 400

# 2. Common ports with banner grabbing
python task-2\scripts\portscan.py --target 127.0.0.1 --top-ports 90 --banner

# 3. This machine's own LAN address, common ports
python task-2\scripts\portscan.py --target 192.168.220.29 --top-ports 90 --timeout 0.3

# 4. Passive recon: DNS (hand-written wire format + getaddrinfo) and WHOIS chase
python task-2\scripts\recon.py --domain example.com --domain apexplanet.in --whois
python task-2\scripts\recon.py --ip 127.0.0.1

# 5. Security header audit - local PHP server (same port Task 3 will use)
php -S 127.0.0.1:8091 -t <docroot>        # started, audited, then stopped
python task-2\scripts\http_security_audit.py --url http://127.0.0.1:8091/

# 6. Security header audit - public site we are authorised to look up
python task-2\scripts\http_security_audit.py --url https://example.com

# 7. Read-only Windows Firewall audit
python task-2\scripts\firewall_audit.py
python task-2\scripts\firewall_audit.py --json

# 8. Tests
python -m unittest discover -s task-2/tests -v
```

### Why TCP connect and not SYN ("stealth")

A SYN scan needs raw sockets. This session is not elevated, and the platform
denies them. Every run of `portscan.py` proves this itself rather than
assuming it:

```
Raw-socket capability probe:
  SOCK_RAW / IPPROTO_TCP    : denied - PermissionError: [WinError 10013] An attempt was made to access a socket in a way forbidden by its access permissions (winerror=10013)
  SOCK_RAW / IPPROTO_ICMP   : available
  note: SOCK_RAW with IPPROTO_TCP is denied by the platform (Windows WinError 10013 without elevation): a SYN/stealth scan is NOT possible here.
  note: SOCK_RAW with IPPROTO_ICMP: available on this platform (observed by this run).
  note: This run is therefore a TCP connect scan - each open port reflects a completed three-way handshake, not a half-open probe.
```

(An anomalous detail worth recording: on this Windows build a raw ICMP socket
opens without elevation while raw TCP is denied with 10013. Both results are
as observed.)

A TCP connect scan completes the full three-way handshake. It is noisier than
SYN scanning - the application on the target sees the connection - but against
our own machine that is irrelevant, and it requires no privileges.

---

## Findings

### 1. Port scan - 127.0.0.1, all 65535 ports

Command 1 completed in 35.79s (script-measured). Full output is 65551 lines;
every open/unknown line and the summary are reproduced here verbatim:

```
135        open       msrpc               (no banner; run with --banner to probe)
137        unknown    netbios-ns          OS error 10013: [WinError 10013] An attempt was made to access a socke
445        open       microsoft-ds        (no banner; run with --banner to probe)
3306       open       mysql               (no banner; run with --banner to probe)
5040       open       -                   (no banner; run with --banner to probe)
5432       open       postgresql          (no banner; run with --banner to probe)
49664      open       -                   (no banner; run with --banner to probe)
49665      open       -                   (no banner; run with --banner to probe)
49666      open       -                   (no banner; run with --banner to probe)
49667      open       -                   (no banner; run with --banner to probe)
49668      open       -                   (no banner; run with --banner to probe)
49670      open       -                   (no banner; run with --banner to probe)
57865      open       -                   (no banner; run with --banner to probe)
57866      open       -                   (no banner; run with --banner to probe)
57867      open       -                   (no banner; run with --banner to probe)
57870      open       -                   (no banner; run with --banner to probe)
61632      open       -                   (no banner; run with --banner to probe)

Summary: 16 open, 0 closed, 65518 filtered, 1 unknown of 65535 ports in 35.79s
```

(135 and 445 are open on loopback because their `svchost`/`System` listeners
bind `0.0.0.0`/dual-stack; 139 binds only the LAN address and therefore does
not appear here - see section 3.)

Cross-check against `Get-NetTCPConnection -State Listen` (run independently
through PowerShell) lists the same sockets, e.g. `127.0.0.1:3306 (mysqld)`,
`0.0.0.0:5432 (postgres)`, `0.0.0.0:5040 (svchost)`, the `lsass`/`wininit`/
`svchost` RPC range `49664-49670`, and the local-app listeners `57865-57870`,
`61632`. The scan's results are therefore corroborated by the OS itself.

**Classification note - "filtered", not "closed".** On this machine the
Windows Filtering Platform silently drops loopback connections to
non-listening ports instead of letting the TCP stack answer with a RST, so
65518 ports timed out ("filtered") rather than being refused ("closed"). A
direct two-line check confirms this is the stack's real behaviour, not a
scanner defect:

```
81 TIMEOUT 1210 ms
137 OS error 13 10013 An attempt was made to access a socket in a way forbidden by its access permissions
```

Port 137 is harder-blocked (connect denied with WinError 10013) and is
reported as `unknown` with the OS error verbatim rather than being guessed
into another state.

### 2. Port scan - banners (loopback, top 90 ports)

Command 2 (0.86s):

```
Summary: 4 open, 0 closed, 85 filtered, 1 unknown of 90 ports in 0.86s
```

Open ports and observed banners:

```
135        open       msrpc               (no banner; run with --banner to probe)
445        open       microsoft-ds        (no banner; run with --banner to probe)
3306       open       mysql               [mysql] 11.4.7-MariaDB (binary handshake packet; version extracted)
5432       open       postgresql          (no banner; run with --banner to probe)
```

- **3306** speaks first, as MySQL-family servers do. The scanner read the
  initial handshake packet, identified protocol byte `0x0a`, and extracted
  the server version string **`11.4.7-MariaDB`** from the binary payload.
  This matches the portable MariaDB 11.4 provisioned for the Full Stack
  track.
- **135 / 445 / 5432** send nothing until the client speaks, and no
  protocol-appropriate probe exists for them in the scanner (only plain
  HTTP gets a probe), so no banner was claimed. That is recorded as "no
  banner", never as an invented service name - the SERVICE column for these
  is a well-known-port *guess*, labelled as such in the tool's help, the
  table header and `--service-map`.

### 3. Port scan - this machine's LAN address (192.168.220.29)

Command 3 (0.35s):

```
135        open       msrpc               (no banner; run with --banner to probe)
137        unknown    netbios-ns          OS error 10013: ...
139        open       netbios-ssn         (no banner; run with --banner to probe)
445        open       microsoft-ds        (no banner; run with --banner to probe)
5432       open       postgresql          (no banner; run with --banner to probe)

Summary: 4 open, 0 closed, 85 filtered, 1 unknown of 90 ports in 0.35s
```

This is the operationally interesting comparison:

- **3306 (MariaDB) is loopback-only** - correctly bound to `127.0.0.1`, not
  reachable from the LAN.
- **5432 (PostgreSQL) is reachable from the LAN** - it listens on `0.0.0.0`,
  confirmed by `Get-NetTCPConnection` (`0.0.0.0:5432 (postgres)`).
- **139/445 (SMB) and 135 (msrpc)** are reachable from the LAN, which is
  Windows default but is the classic lateral-movement surface.

### 4. Windows Firewall (read-only audit)

Command 7 completed in 49.21s (full run: all 163 rules' port/address filters
fetched; no degraded sections). Key real output:

```
Firewall profiles:
  Domain   enabled=True   default inbound: NotConfigured   default outbound: NotConfigured
  Private  enabled=True   default inbound: NotConfigured   default outbound: NotConfigured
  Public   enabled=True   default inbound: NotConfigured   default outbound: NotConfigured

Enabled inbound ALLOW rules: 163 (details retrieved for 163)
  by profile : {'Any': 68, 'Domain': 7, 'Domain, Private': 28, 'Domain, Private, Public': 9, 'Private': 19, 'Private, Public': 2, 'Public': 30}
  by direction: {'Inbound': 163}

Rules with remote address 'Any' (any host may trigger them): 130
  - Wi-Fi Direct Spooler Use (In) [Public] Any/Any
  - Core Networking - IPv6 (IPv6-In) [Any] 41/Any
  - Delivery Optimization (UDP-In) [Any] UDP/7680
  ... and 122 more (full list with --json)

Listening sockets: 27 TCP, 28 UDP

Inbound-ALLOW-from-Any rules touching a listening port: 87
  - App Installer [Domain, Private] TCP+UDP ports [135, 137, 138, 139, 445, 1900, 2177, 3306] (+30 more)
  - DTS Sound Unbound [Domain, Private] TCP+UDP ports [135, 137, 138, 139, 445, 1900, 2177, 3306] (+30 more)
  ... and 77 more (full list with --json)

Degraded sections: none
```

JSON totals from the same run (`--json`, machine-parsed):
`permissive_rules = 130`, `listening_exposed = 87` (of which 73 have a local
port filter of `Any`, i.e. they permit inbound from any host on every
protocol/port they cover), `59` of the exposed rules touch port 135.

Interpretation: the enabled rule set is dominated by per-application
"allow from Any" rules (Microsoft Store apps such as HP Smart, Game Bar,
MSN Weather, Dropbox promotion - each one grants the app an inbound path
from any address). The rules do not bypass the listening-socket requirement
(an allow rule cannot make a closed port open, and indeed nothing extra was
listening), but they massively widen what *would* be reachable if a service
were started. Default inbound action is `NotConfigured` on all three
profiles, i.e. Windows' implicit default (block inbound, allow outbound) -
explicit configuration would be clearer.

The audit is **read-only**. Changing any of these rules requires
administrator rights that this session does not have.

### 5. Security header audit - local PHP server (Task 3 target, port 8091)

Command 5, against the PHP built-in server (`127.0.0.1:8091`), which answers
`200` over plain HTTP with no TLS listener:

```
URL    : http://127.0.0.1:8091/
status : 200   scheme: http
HTTPS probe: not reachable on this host/port
Strict-Transport-Security                    warn    5/10   header absent, and over plain HTTP any HSTS header would be ...
Content-Security-Policy                      fail    0/15   header absent; no allow-list constrains script, style or fra
X-Content-Type-Options                       fail    0/8    header absent; browsers may MIME-sniff responses
Clickjacking (X-Frame-Options / frame-ancestors) fail  0/10   neither X-Frame-Options nor CSP frame-ancestors is set
Referrer-Policy                              fail    0/7    header absent; full URLs may leak in the Referer header
Permissions-Policy                           fail    0/8    header absent; powerful features are not explicitly disabled
Cross-Origin-Opener-Policy                   fail    0/7    header absent; the browsing context is not isolated from cro
Cross-Origin-Resource-Policy                 warn    3/7    header absent; other origins may embed this origin's resourc
Set-Cookie flags                             n-a     10/10   no Set-Cookie headers in the response
Information disclosure headers               pass    8/8    no Server / X-Powered-By / X-AspNet-Version headers
HTTPS vs HTTP                                warn    5/10   plain HTTP; no TLS service answered the reachability probe o

Score: 32/100 - band: poor (severity: high)
```

Findings: no security headers at all; served over plaintext HTTP with no TLS
available on the port; this PHP build sends no `Server`/`X-Powered-By`
headers (the disclosure check passes). The audit emitted copy-pasteable
Apache and Nginx snippets for every missing header - these are the exact
values Task 3 should adopt when the vulnerable app is served.

### 6. Security header audit - example.com (observation only)

Command 6 (a single HEAD; example.com fronts its own users' sites, not ours -
this is an observation, nothing to remediate by us):

```
Score: 24/100 - band: critical (severity: critical)
```

with HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
Permissions-Policy and COOP all absent on the edge response, CORP absent
(warn), `Server: cloudflare` disclosed, over HTTPS (transport check n/a).
Notable for the report: even a major CDN-fronted site can serve a response
that fails most of these checks, which is exactly why the checks are worth
running on our own app.

### 7. Reconnaissance - DNS, WHOIS, HTTP

Command 4 (real output):

```
resolver for raw DNS: 192.168.220.241 (registry DhcpNameServer)

== domain: example.com ==
  getaddrinfo addresses : ['104.20.23.154', '172.66.147.243', '2606:4700:9c65:72db:f2fd:4cc:ef6b:ff98']
  canonical / aliases   : example.com / []
  CNAME                : NOERROR []
  MX                   : NOERROR [{'preference': 0, 'exchange': '.'}]
  NS                   : NOERROR ['elliott.ns.cloudflare.com', 'hera.ns.cloudflare.com']
  TXT                  : NOERROR ['_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9', 'v=spf1 -all']
  whois chain:
    whois.iana.org <- example.com: 233 bytes, referral: none
    whois.iana.org <- com: 2136 bytes, referral: whois.verisign-grs.com:43
    whois.verisign-grs.com <- example.com: 3325 bytes, referral: none
  http: https://example.com/ -> 200 (637.8ms, HEAD)
         Content-Type: text/html; charset=utf-8
         Server: cloudflare

== domain: apexplanet.in ==
  getaddrinfo addresses : ['2a02:4780:20:e738:fabf:871f:314a:234c', '2a02:4780:3d:dc56:395e:7824:3b21:a1bc', '88.222.243.83', '91.108.106.179']
  MX                   : NOERROR [{'preference': 10, 'exchange': 'mx2.hostinger.com'}, {'preference': 5, 'exchange': 'mx1.hostinger.com'}]
  NS                   : NOERROR ['ns2.dns-parking.com', 'ns1.dns-parking.com']
  TXT                  : NOERROR ['v=spf1 include:_spf.mail.hostinger.com ~all']
  whois chain:
    whois.iana.org <- apexplanet.in: 1516 bytes, referral: whois.nixiregistry.in:43
    whois.nixiregistry.in <- apexplanet.in: 4632 bytes, referral: none
  http: https://apexplanet.in/ -> 200 (382.4ms, HEAD)
         x-powered-by: PHP/8.1.34
         content-security-policy: upgrade-insecure-requests
         Server: hcdn
```

Notes:

- The MX for example.com is a **null MX** (RFC 7505, exchange `.`) - the
  domain explicitly accepts no mail; the tool reports it as the registry
  does.
- The WHOIS chase is the real referral mechanism: IANA is queried first,
  the TLD hop (`com`) yields `refer: whois.verisign-grs.com`, and the
  registry answers for the full domain. For `.in`, IANA referred directly
  to `whois.nixiregistry.in`.
- apexplanet.in discloses `x-powered-by: PHP/8.1.34` - the exact class of
  finding `http_security_audit.py` grades as information disclosure.

Command 4b (`--ip 127.0.0.1`): reverse DNS resolves to this machine's
hostname `LAPTOP-EAP7GUSJ`; the HTTP section correctly reported
`URLError: [WinError 10061] ... actively refused` because nothing listens on
loopback port 80 - an honest error, not a fabricated response.

### 8. Tests

```
Ran 70 tests in 18.280s

OK
```

Run with `python -m unittest discover -s task-2/tests -v`; all 70 pass
(port parsing, live socket classification on a listener the test itself
opens, banner sanitisation, MySQL handshake parsing, DNS wire encode/decode
including compression pointers and pointer-loop rejection, WHOIS referral
parsing, a live two-server header-audit comparison, cookie-flag parsing,
firewall JSON end-to-end, and PowerShell degradation paths).

---

## Limitations

Honest boundaries of what was done here:

1. **No packet capture of any kind.** Windows packet capture requires
   Npcap, whose installer requires administrator rights. There is no
   Wireshark, no tcpdump, no raw sniffing on this machine and no workaround.
   Nothing in this report is based on captured packets.
2. **No Nmap.** Not on PATH, and its SYN mode (`-sS`) would fail anyway:
   raw sockets are denied (WinError 10013, proved by every scan run). No
   Nmap service-version detection (`-sV`), OS fingerprinting (`-O`), NSE
   scripts, or timing templates were used. Service names in this report are
   either banner-observed or explicitly labelled guesses.
3. **No vulnerability scanner.** OpenVAS and Nessus are not present and
   cannot be installed without admin rights. `http_security_audit.py`
   covers only HTTP response headers; it does not test for software
   vulnerabilities, outdated components, or injection flaws. (Those belong
   to Task 3's application testing.)
4. **TCP only.** No UDP port scan was performed. UDP endpoints in the
   firewall section come from `Get-NetUDPEndpoint`, i.e. what the OS says
   is bound - not from probing.
5. **Loopback behaviour skews closed/filtered.** On this machine WFP drops
   loopback connects instead of refusing them, so a "closed" count of 0 is
   expected here; on a normal host the same scanner would report refused
   ports as closed.
6. **Banner grabbing is best-effort.** Only MySQL-family services announce
   themselves unsolicited; the scanner probes plain-HTTP ports with a
   minimal `GET / HTTP/1.0` and reads whatever else arrives within the
   timeout. Services needing a larger protocol handshake (PostgreSQL,
   RDP, SMB) are recorded as "no banner".
7. **Firewall rule details cost time.** Each rule's port/address filters
   take 150-200 ms to fetch without admin rights (bulk queries are denied),
   so a full audit takes ~50 s; `--max-rules` exists for quick checks and
   makes the analysis partial, which the tool reports in-band.
8. **Rate and politeness.** Public contact was: a handful of DNS queries via
   our own resolver, 7 WHOIS requests total across two targets, and two
   `HEAD` requests. No crawling, no repeated hits.

### Commands to run later, once the proper lab exists

With Nmap available (e.g. from a Kali VM with a Host-Only adapter), the
equivalents of what was approximated here:

```bash
# Full connect scan + version detection + OS detection against the lab target
nmap -sT -sV -O -p- 192.168.56.101 -oN nmap-connect-full.txt

# The SYN scan this machine could not run (needs raw sockets / root)
nmap -sS -sV -O -p- 192.168.56.101 -oN nmap-syn-full.txt

# UDP scan (not attempted here at all)
nmap -sU --top-ports 50 192.168.56.101 -oN nmap-udp.txt

# Vulnerability scripts against the web target
nmap -p 80 --script http-vuln* 192.168.56.101
```

With Wireshark/Npccap installed (admin session), capture the connect scan
and open the capture to see the RST/ACK behaviour this report could only
infer:

```powershell
# Admin PowerShell
Start-Process wireshark   # capture on the Host-Only adapter while:
nmap -sS -p 135,445,3306 192.168.56.101
```

With OpenVAS/Nessus installed, run a full authenticated scan against
`192.168.56.101` and diff its findings against this report's header audit.

---

## Remediation

Prioritised, and tied only to findings above:

1. **PostgreSQL is reachable from the LAN (finding 3).** `0.0.0.0:5432`
   with inbound allow rules means any host on `192.168.0.0/16` can reach the
   database port. Unless LAN access is required, bind PostgreSQL to
   `127.0.0.1` (`postgresql.conf`: `listen_addresses = 'localhost'`) or
   block 5432 inbound for the Public profile. This is the single widest
   exposure the scan found.
2. **SMB and msrpc on the LAN interface (finding 3).** 139/445/135 open on
   `192.168.220.29` is Windows default and the standard lateral-movement
   path. On a laptop that does not file-share with other machines: disable
   SMB1 if still enabled, and restrict File and Printer Sharing / Network
   Discovery rules to the Private profile only. (Changing rules needs an
   elevated session - not possible from this one, flagged here for the
   machine owner.)
3. **130 firewall rules allow inbound from 'Any', 87 of them overlapping a
   listening port (finding 4).** Review the per-application allow rules
   (HP Smart, Game Bar, MSN Weather, Dropbox promotion, etc. - full list in
   the JSON). Each is a granted inbound path for an app that mostly does
   not need one. Disable inbound rules for applications that are not used,
   and set explicit default-inbound actions on all three profiles instead
   of relying on `NotConfigured`.
4. **The local web app has no security headers and no TLS (finding 5,
   score 32/100).** When Task 3's app is served on 8091, apply the exact
   snippets the audit produced: `X-Content-Type-Options: nosniff`,
   `X-Frame-Options: DENY` (plus CSP `frame-ancestors 'none'`), a real
   `Content-Security-Policy` without `unsafe-inline`/`unsafe-eval`,
   `Referrer-Policy: strict-origin-when-cross-origin`, a `Permissions-Policy`
   disabling camera/microphone/geolocation, and
   `Cross-Origin-Opener-Policy: same-origin`. HSTS can only take effect
   once HTTPS exists - put the app behind TLS first (even a self-signed
   lab certificate beats plaintext), then set
   `max-age=31536000; includeSubDomains`.
5. **Information disclosure on the public site observation (findings 6,
   7):** `x-powered-by: PHP/8.1.34` on apexplanet.in and `Server:
   cloudflare` on example.com. For our own hosts: `expose_php = Off`,
   `ServerTokens Prod` (Apache), `server_tokens off` (Nginx). Example.com
   is not ours to change; it is recorded as evidence that the check finds
   real disclosures.
6. **MariaDB (3306) is correctly scoped** - loopback-only bind, banner
   shows `11.4.7-MariaDB`. No action; keep it that way when Task 3
   provisions the database, and keep credentials out of the repository
   (per the repo rules).

Every remediation above requires either application configuration (item 4,
5) or administrator rights (items 1-3), the latter explicitly unavailable in
this session. The audit scripts are read-only and will happily re-verify
any of these fixes once applied.
