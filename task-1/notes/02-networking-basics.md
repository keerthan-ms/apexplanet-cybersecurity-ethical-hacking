# Task 1 — Networking Basics for Security Work

Prerequisite knowledge for the scanning, capture and web-attack work in Tasks
2–3. Networking first, because every attack in this programme travels over a
network you must be able to read.

---

## 1. The OSI model

Seven layers, each adding a specific job on top of the one below. The model is
a teaching and troubleshooting frame: when something breaks, you can say which
layer failed.

| # | Layer | What it does | Example protocol | Example device |
|---|---|---|---|---|
| 7 | Application | Network services presented to user software — the data and the request semantics | HTTP, DNS, SMTP, SSH | Reverse proxy (nginx), WAF |
| 6 | Presentation | Encoding, serialisation, compression, encryption of the application data | TLS record layer, JPEG, UTF-8 | TLS terminator |
| 5 | Session | Establishing, maintaining and tearing down conversations; who speaks when | NetBIOS session, RPC, SIP dialog setup | — (usually folded into 7 in practice) |
| 4 | Transport | End-to-end delivery of a stream or datagram, segmentation, ports, reliability and flow control | TCP, UDP | Load balancer (L4), firewall port rules |
| 3 | Network | Logical addressing and routing between networks; packet forwarding | IPv4, IPv6, ICMP, OSPF | Router, L3 switch |
| 2 | Data link | Node-to-node delivery on one link; framing, MAC addressing, error detection | Ethernet (802.3), Wi-Fi (802.11), ARP | Switch, access point |
| 1 | Physical | Bits as electrical/optical/radio signals; pinouts, voltage, cable | 1000BASE-T, fibre, radio | Hub, cable, transceiver |

Practical note: the internet stack is really TCP/IP (three or four layers, see
section 2). Layers 5 and 6 rarely appear as separate headers on the wire — TLS
is the main thing people place at layer 6, though it actually rides directly
above TCP. Use OSI to talk about *where a control or an attack sits*, not as a
claim about header layout.

### Which layer does this attack or tool belong to?

| Attack / tool | Layer | Why |
|---|---|---|
| MAC flooding, ARP spoofing / MITM | 2 | Abuses Ethernet addressing; ARP has no authentication |
| Evil twin access point | 1–2 | Radio association and frame injection |
| IP spoofing, Smurf attack, ICMP redirect | 3 | Forges or abuses the IP header and control messages |
| SYN flood, port scanning (Nmap), RST injection | 4 | Targets TCP state machine and port numbers |
| DNS cache poisoning (forged response) | 4 (UDP/53) but abuses a layer-7 service | The forged packet is UDP; the damage is in the name resolution |
| SSL/TLS downgrade (POODLE, legacy renegotiation) | 6 | Attacks the negotiation of the presentation-layer protocol |
| HTTP request smuggling | 7 | Disagreement between proxy and server about where one request ends |
| SQL injection, XSS, CSRF | 7 | Application logic consumes untrusted input |
| Wireshark (capture) | 1–4 | Sees frames, IP packets and TCP streams |
| Wireshark display filter `http.request` | 7 | Decodes payloads above TCP |
| Burp Suite proxy | 7 | Sits in the HTTP conversation between browser and server |
| Nmap TCP connect scan (`-sT`) | 4 | Completes the three-way handshake per port |
| Nmap OS detection (`-O`) | 1–4 | Infers the OS from IP/TCP stack behaviour |

---

## 2. The TCP/IP suite and how it maps onto OSI

TCP/IP is the stack that actually runs. The common teaching form is four
layers; the three-layer form merges application and presentation/session.

| TCP/IP layer | Covers OSI layers | Contents |
|---|---|---|
| Application | 5, 6, 7 | HTTP, DNS, SMTP, SSH, TLS as used by applications |
| Transport | 4 | TCP, UDP |
| Internet | 3 | IPv4, IPv6, ICMP, routing protocols |
| Link (Network Access) | 1, 2 | Ethernet, Wi-Fi, ARP |

Mapping examples you will use constantly:

- An HTTP request is application-layer data. It becomes a TCP segment (layer 4)
  with source and destination ports (client ephemeral port → 80 or 443), then
  an IP packet (layer 3) with source and destination addresses, then Ethernet
  frames (layer 2) addressed MAC-to-MAC on the local link only.
- MAC addresses do not cross a router. Each hop rewrites the layer-2 frame;
  the layer-3 IP header survives (unless NAT changes it — section 5).
- A firewall rule `deny tcp any any eq 23` is a layer-4 control. A WAF rule
  blocking `' OR 1=1` is layer 7. Confusing the two is a common design error.

---

## 3. DNS

### Resolution, end to end

Take `example.com` from a cold cache on a stub resolver (your OS):

1. **Stub resolver** checks the OS cache and the hosts file; if nothing, it
   sends one recursive query to the configured recursive resolver (usually the
   ISP's, or 1.1.1.1 / 8.8.8.8), over **UDP/53**.
2. **Recursive resolver** has nothing cached either. It queries a **root
   server** (13 anycast addresses, e.g. `a.root-servers.net`) for
   `example.com`.
3. The root server does not know the answer; it returns a **referral** — the
   NS records for the `.com` TLD servers.
4. The resolver asks a **`.com` TLD server**; it returns a referral to the
   authoritative servers for `example.com`.
5. The resolver asks the **authoritative server** for `example.com`; this one
   answers from the zone file: the A record, e.g. `93.184.216.34`.
6. The recursive resolver caches the answer (respecting the TTL), returns it to
   the stub resolver, which passes it to the application. The application
   usually gets a **negative** result too — NXDOMAIN is cacheable for the
   negative-caching TTL in SOA.

Every step except the stub-to-resolver hop is iterative. Only the stub's query
is recursive; the resolver does the walking on the client's behalf.

### UDP/53 versus TCP/53

- **UDP/53** is the normal query path: one packet in, one packet out, no
  handshake cost. ~99% of legitimate traffic.
- **TCP/53** is used for responses larger than 512 bytes (or when EDNS0
  advertises a larger UDP buffer and the response still overflows): zone
  transfers (AXFR/IXFR) between authoritative servers, and any query where the
  client sets the TC (truncation) bit fallback.
- Security reading: TCP/53 is a required service on authoritative servers and a
  red flag on random internal hosts (possible tunneling). UDP/53 open to the
  internet on a host that is not a resolver is an amplification-vector risk.

### Common record types

| Record | Purpose | Example value |
|---|---|---|
| A | IPv4 address for a name | `example.com. 3600 IN A 93.184.216.34` |
| AAAA | IPv6 address for a name | `example.com. 3600 IN AAAA 2606:2800:220:1:248:1893:25c8:1946` |
| CNAME | Alias to another name | `www.example.com. 86400 IN CNAME example.com.` |
| MX | Mail exchanger, with preference | `10 mail.example.com.` (lower number = higher priority) |
| TXT | Arbitrary text: SPF, DKIM, domain verification | `"v=spf1 include:_spf.example.net -all"` |
| NS | Authoritative server for a zone | `a.iana-servers.net.` |
| SOA | Zone metadata: serial, timers, primary server | start of authority record |
| PTR | Reverse: IP → name (in-addr.arpa) | `34.216.184.93.in-addr.arpa. IN PTR example.com.` |

### DNS-based attacks, at working altitude

- **Cache poisoning (forging):** the resolver sends UDP/53 to an upstream and
  accepts the first response that matches its transaction ID and source port.
  An attacker who can race a forged response — with the right 16-bit TXID and
  a guessed 16-bit source port (32 bits total, brute-forceable at scale) —
  plants a false A record, e.g. pointing a bank's name at an attacker IP.
  **Kaminsky's 2008 variant** makes this reliable by poisoning a non-existent
  subdomain (`random123.bank.com`) so each guess gets a fresh cache miss.
  Mitigations: DNSSEC (signatures the attacker cannot forge), source-port
  randomisation, 0x20 bit randomisation, and preferring TCP where feasible.
- **DNS tunnelling:** encapsulating arbitrary data (C2, exfiltration) in
  queries and responses, typically TXT or NULL records against an
  attacker-controlled authoritative server. Egress filtering that only allows
  "port 53" does not stop it. Mitigations: force internal clients through
  inspected resolvers, alert on long labels, high TXT volume, and rare record
  types; monitor bytes-per-query ratios.
- **DNS rebinding:** the browser resolves a name, gets a public attacker IP,
  fetches a page (same-origin allowed); shortly after, the attacker changes
  the TTL to 0 and re-resolves the same name to an internal address
  (`127.0.0.1`, `192.168.x.x`, cloud metadata `169.254.169.254`). The browser
  now sends requests to the internal target from the victim's context.
  Mitigations: DNS rebinding protection in browsers, requiring the first and
  subsequent answers to be public, and servers rejecting requests whose Host
  header is not their own.

---

## 4. HTTP and HTTPS

### Request and response structure

Request:

```
POST /login HTTP/1.1
Host: lab.local:8091
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 27
Connection: keep-alive

username=admin&password=x
```

Response:

```
HTTP/1.1 200 OK
Server: PHP/8.3
Content-Type: text/html; charset=UTF-8
Set-Cookie: PHPSESSID=abc123; HttpOnly; SameSite=Lax
Content-Length: 142

<!doctype html><title>Welcome</title>...
```

Start line, headers (name: value, CRLF), blank line, optional body. The body's
length rules: `Content-Length` in bytes, or `Transfer-Encoding: chunked`.

### Methods

| Method | Safe | Idempotent | Typical use |
|---|---|---|---|
| GET | yes | yes | Read a resource. Should have no side effects |
| HEAD | yes | yes | Same as GET without the body — existence and metadata checks |
| POST | no | no | Create a resource, submit a form, trigger an action |
| PUT | no | yes | Replace a resource at a known URL |
| PATCH | no | no | Partial update |
| DELETE | no | yes | Remove a resource |
| OPTIONS | yes | yes | Discover allowed methods; used by CORS preflight |

"Safe" and "idempotent" matter for security review: a GET with side effects
breaks CSRF defences (link prefetching, `<img src>`), and a non-idempotent
method behind a retrying proxy doubles an action.

### Status code classes

| Range | Class | Meaning | Security-relevant examples |
|---|---|---|---|
| 1xx | Informational | Intermediate | 101 Switching Protocols (upgrade to WebSocket) |
| 2xx | Success | Request accepted | 200 OK, 201 Created, 204 No Content |
| 3xx | Redirection | Go elsewhere | 301/302 redirect (open-redirect risk), 304 Not Modified |
| 4xx | Client error | Your request is wrong | 400 Bad Request, 401 Unauthenticated, 403 Forbidden, **404 Not Found (also used deliberately to hide resources)**, 405 Method Not Allowed, 429 Too Many Requests (rate limit working) |
| 5xx | Server error | Server failed | 500 (stack traces here leak paths and versions), 502/504 from proxies |

### Where TLS sits, and what it adds

TLS runs between the transport and the application: in TCP/IP terms, the
application layer uses TLS as its secure transport; in OSI terms it is usually
placed at layer 6. On the wire, after the TCP handshake on port 443 you see
`ClientHello` → `ServerHello`, certificate, `ServerHelloDone` (TLS 1.2) or
the compressed TLS 1.3 flight (server sends its key share and certificate
immediately after `ServerHello`), then keys are derived and application data
is encrypted.

What TLS provides:

- **Confidentiality** — AES-GCM or ChaCha20-Poly1305 encrypts the record stream.
- **Integrity** — the AEAD tag makes modified ciphertext fail to decrypt.
- **Server authentication** — the certificate chain proves the server holds the
  private key for the name in the certificate, validated up to a trusted root.
- **Optional client authentication** — client certificates (mutual TLS).
- **Forward secrecy** — with ECDHE key exchange, a stolen server private key
  cannot decrypt past recorded sessions.

### SNI

Server Name Indication is the hostname the client puts in the `ClientHello`,
in cleartext even under TLS 1.3. It exists so one IP can host many TLS sites
and the server can pick the right certificate. Security consequences:
passive observers learn which site you visited (metadata leak — why ECH/ESNI
proposals exist); middleboxes that route by SNI can block sites without
breaking TLS; and SNI is a useful detection signal in enterprise logs.

### HTTPS encrypts the transport — it does not protect the application

HTTPS stops a passive observer on the path from reading or silently altering
the bytes of a session. It says nothing about:

- **Server-side flaws** — SQL injection, broken access control, CSRF: the
  attacker's requests are perfectly valid TLS sessions; the application is
  fooled, not the cipher. A TLS padlock on a SQLi-vulnerable login page means
  the injection travels encrypted.
- **Host compromise** — TLS terminates at the server; malware on the server
  reads everything in plaintext after decryption.
- **Phishing** — `https://paypa1.com` gets a valid certificate from any CA that
  will issue for that domain. HTTPS authenticates the *domain*, and only as
  far as the user checks it.
- **Client-side threats** — a keylogger records the password before TLS ever
  sees it.

Rule of thumb: TLS is a transport control (confidentiality/integrity in
motion). Application security is a separate discipline — that is Task 3.

---

## 5. IP addressing, subnetting and NAT

### How a subnet mask works

An IPv4 address is 32 bits. The mask marks how many leading bits are the
**network** portion and how many trailing bits are **host**. A host number of
all-zeros is the network address; all-ones is the broadcast address; every
value between is assignable.

`/24` means 24 network bits, 8 host bits:

```
192.168.1.10 = 11000000.10101000.00000001.00001010
mask /24     = 11111111.11111111.11111111.00000000 = 255.255.255.0
network      = 11000000.10101000.00000001.00000000 = 192.168.1.0
```

Host count = 2^8 − 2 = **254** usable (192.168.1.1 … 192.168.1.254).
192.168.1.0 is the network address, 192.168.1.255 the broadcast.

A quick derivation: mask octet = 256 − (number of hosts per block). For /24,
256 − 254 = 2 → 255. The block size in the interesting octet is 256 − mask.

### Worked: carving 192.168.1.0 into /26 subnets

`/26` = 26 network bits, 6 host bits.

```
mask = 11111111.11111111.11111111.11000000 = 255.255.255.192
```

Block size in the fourth octet = 256 − 192 = **64**. Hosts per subnet =
2^6 − 2 = **62**. Four subnets:

| Subnet | Network | First usable | Last usable | Broadcast |
|---|---|---|---|---|
| 1 | 192.168.1.0/26 | 192.168.1.1 | 192.168.1.62 | 192.168.1.63 |
| 2 | 192.168.1.64/26 | 192.168.1.65 | 192.168.1.126 | 192.168.1.127 |
| 3 | 192.168.1.128/26 | 192.168.1.129 | 192.168.1.190 | 192.168.1.191 |
| 4 | 192.168.1.192/26 | 192.168.1.193 | 192.168.1.254 | 192.168.1.255 |

Arithmetic check for 192.168.1.130/26: 130 = 2×64 + 2, so it falls in subnet
starting at 128; host offset 130 − 128 = 2, so it is the third usable address
(128 is the network address, 129 the first usable). Same check with the mask:
130 AND 192 = 128 → network 192.168.1.128.

Why subnetting matters for a lab: a /26 segment lets you put an attacker VM
and a target VM on one broadcast domain while a second /26 holds a "victim
user" segment, so you can demonstrate routing, ACLs and pivot paths without
touching the real LAN.

### Private address ranges (RFC 1918)

| Range | CIDR | Size |
|---|---|---|
| 10.0.0.0 – 10.255.255.255 | 10.0.0.0/8 | 2^24 addresses |
| 172.16.0.0 – 172.31.255.255 | 172.16.0.0/12 | 2^20 addresses |
| 192.168.0.0 – 192.168.255.255 | 192.168.0.0/16 | 2^16 addresses |

These are never routed on the public internet; routers drop them by
convention (and bogon filters). Why they matter for a lab:

- A host-only network uses 192.168.56.0/24 (VirtualBox's default vboxnet0).
  VMs can talk to each other and to the host, and the internet is unreachable
  — which is exactly the isolation you want when one VM is an attack platform
  and the other is deliberately vulnerable.
- An accidentally bridged Metasploitable2 is a real incident. RFC 1918 plus
  host-only is the cheap structural control that prevents it.
- If a scan of 10.x or 192.168.x from your desk returns hits, you are inside
  someone's internal space — the ranges themselves are a reconnaissance
  signal.

### NAT, with a worked before/after

Network address translation rewrites IP headers (and usually ports) at a
boundary so many private hosts share one public address. Port address
translation (PAT) is the usual form: one public IP, many translated sockets,
disambiguated by port numbers in a state table.

Before the packet leaves the home/lab gateway:

```
Host 192.168.56.10 (Kali VM)
  src IP 192.168.56.10   src port 51514
  dst IP 93.184.216.34   dst port 443
  protocol TCP, flags ACK, seq 1000
```

The gateway (public IP 203.0.113.5) rewrites the source, allocates a public
source port, records the mapping, and recomputes the IP header checksum (and
the TCP pseudo-header checksum, because the addresses changed):

```
On the wire, after NAT:
  src IP 203.0.113.5     src port 62000
  dst IP 93.184.216.34   dst port 443
  protocol TCP, flags ACK, seq 1000
  NAT table entry: 203.0.113.5:62000 <-> 192.168.56.10:51514 (TCP, timeout 300s)
```

The return packet from 93.184.216.34:443 arrives at 203.0.113.5:62000; the
gateway looks up the entry and reverses the translation:

```
Delivered to the VM:
  src IP 93.184.216.34   src port 443
  dst IP 192.168.56.10   dst port 51514
```

Security consequences to keep in mind through the whole programme:

- NAT is **not** a firewall, though it behaves like an implicit deny for
  unsolicited inbound connections, because no table entry exists to reverse.
  A port-forward rule punches a hole; the security comes from the rules, not
  from NAT itself.
- It breaks end-to-end addressing: inbound protocols (SIP, FTP active mode,
  IPsec) need helpers or are simply impossible — one reason the industry moved
  to IPv6.
- It hides internal topology from outside observers, which is convenient for a
  lab and is also why an attacker who gets inside immediately gains visibility
  your perimeter never leaked.
- Logging: connection attribution now needs the NAT table's timestamped
  mappings; without them, "which internal host made this request" is
  unrecoverable — a recurring problem in incident response.

---

## 6. Quick self-check

1. A SYN scan shows port 22 open, a banner says `OpenSSH 8.2p1`. Which layers
   did the scan use, and which layer is the banner from?
   (Answer: layer 4 for the scan; layer 7 for the banner.)
2. A host is 172.20.5.9/20. What is its network address and broadcast?
   (172.20.0.0/20, broadcast 172.20.15.255 — block size 16 in the third octet.)
3. Why does DNS use UDP by default but fall back to TCP?
   (Latency for the common small answer; TCP for responses that exceed the
   UDP size limit and for zone transfers.)
4. Your colleague says "the site has HTTPS so we are safe from injection."
   What is wrong with the statement?
   (TLS protects the transport; SQL injection is an application-layer flaw
   executed by the server after decryption.)
