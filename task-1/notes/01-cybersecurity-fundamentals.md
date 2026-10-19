# Task 1 — Cybersecurity Fundamentals

Notes for the ApexPlanet Cybersecurity & Ethical Hacking internship, Task 1.
Written for someone who knows some networking and is now learning security.
Everything here is standard, current practice; where a claim is an observation
from this machine rather than textbook material, it says so.

---

## 1. The CIA triad

The three properties every security control ultimately exists to protect.

### Confidentiality — only authorised parties can read the data

Encryption at rest and in transit, access control lists, need-to-know
policies, and data classification all serve this property.

**What failure looks like:** the 2015 US Office of Personnel Management (OPM)
breach exposed SF-86 background-check forms — home addresses, financial
histories, foreign contacts of clearance holders. No integrity or availability
problem occurred; the harm was entirely that unauthorised parties could read
data they were never meant to see. Controls that would have limited it:
field-level encryption, network segmentation, and least-privilege database
accounts.

### Integrity — data is accurate and only changed by authorised, audited means

Checksums, digital signatures, version control, database constraints, and
write-once audit logs serve this property.

**What failure looks like:** an attacker with write access to a financial
database does not steal a single record — it changes the destination account on
a payment batch. Nothing is missing, so nothing alarms, and the loss is direct
money. This is why integrity controls (separation of duties, append-only audit
trails, signed releases) matter even when the data is not secret.

### Availability — authorised users can get the data and use the system when they need it

Redundancy, load balancing, rate limiting, DDoS mitigation, and tested backups
serve this property.

**What failure looks like:** the 2016 Dyn DNS attack: the Mirai botnet flooded
Dyn's authoritative DNS infrastructure with tens of millions of connections;
Twitter, Netflix, Reddit and banks were unreachable for hours across Europe and
North America. Confidentiality and integrity were untouched — the damage was
pure unavailability. This is why hospitals treat availability as a safety
property, not an IT preference.

All three interact. Backups are an integrity control (restoring a known-good
copy) and an availability control (recovering from ransomware) at once.
Choosing a control means stating which of the three it protects and which
threat it addresses.

---

## 2. Threat types named in the brief

| Threat | One-line definition | How it works | Real-world class of incident | Primary control |
|---|---|---|---|---|
| Phishing | Deceptive message that harvests credentials or delivers malware | Attacker spoofs a trusted sender, crafts urgency, and sends a link or attachment; the victim types their password into a fake login page or enables macros | Spear-phishing emails impersonating IT password resets preceded the 2016 Democratic National Committee email leak — a single credential harvest led to public document release | Multi-factor authentication (MFA): a harvested password alone then cannot open the account |
| Malware | Any software installed on a system without the owner's intent | Delivered by phishing attachment, drive-by download, or dropped by another foothold; ranges from keyloggers to loaders such as Emotet that install follow-on payloads | Banking trojans of the Emotet/TrickBot class: delivered as a macro-enabled document, they persist, harvest mailboxes, and broker access for ransomware operators | Endpoint detection and response (EDR) plus application allowlisting and patching — block the execution path, not just the signature |
| DDoS | Overwhelming a service with traffic from many sources so legitimate users cannot reach it | Volumetric floods (UDP amplification), protocol abuse (SYN floods), or application-layer floods (HTTP GET storms); botnets rent the source volume | The 2016 Dyn attack via the Mirai botnet: IoT devices with default credentials were conscripted to flood DNS infrastructure | Upstream scrubbing / CDN-based DDoS mitigation plus rate limiting at the edge — you cannot out-bandwidth a botnet on your own uplink |
| SQL injection | Untrusted input concatenated into a database query, changing the query's meaning | User input such as `' OR '1'='1` or UNION-based payloads is embedded in a query string; the database executes the attacker's syntax with the application's privileges | The 2015 TalkTalk breach: an SQL injection flaw on the customer portal let attackers extract ~157,000 customer records including bank details | Parameterised queries (prepared statements) — the input is bound as data, never parsed as SQL |
| Brute force | Systematically guessing credentials or keys until one works | Automated tooling tries password lists, or credential-stuffing lists from other breaches, against login endpoints, often from distributed IPs to evade simple lockouts | Credential stuffing against consumer and VPN portals: lists from earlier breaches are replayed at scale; success depends on password reuse, not on breaking crypto | Rate limiting and account lockout, plus MFA and screening passwords against known-breached lists |
| Ransomware | Malware that encrypts the victim's data and demands payment for the key | Initial access via phishing or an exposed service, lateral movement, domain-wide encryption, often with data theft and double extortion ("pay or we publish") | WannaCry (2017) used the EternalBlue SMB exploit against unpatched Windows hosts and hit the NHS among ~200,000 machines across 150 countries | Offline, tested backups plus patching the initial vector — payment is not a recovery strategy |

---

## 3. Attack vectors

An attack vector is the specific path or technique used to reach a target —
"phishing" is a threat type; "a fake Microsoft 365 login page emailed to the
finance team" is the vector.

### Social engineering

**Definition:** manipulating people into performing an action or divulging
information, exploiting trust, authority, urgency or helpfulness rather than a
software flaw.

**Example:** an attacker phones the helpdesk pretending to be a new starter
whose laptop was lost, quotes a real employee name and department picked up
from LinkedIn, and asks for a password reset to a mobile number they control.
The reset is processed; the attacker owns the mailbox and can then approve
their own MFA prompts from the mailbox rules they install.

**Mitigation:** out-of-band verification of reset requests (call the requester
back on a known number), MFA methods the mailbox alone cannot approve
(hardware keys), security-awareness training with simulated phishing, and
helpdesk procedures that treat urgency as a red flag rather than a reason to
skip checks.

### Wireless attacks

**Definition:** attacks against Wi-Fi associations and the authentication
infrastructure — rogue access points, evil twins, deauthentication floods, and
cracking of weak handshakes.

**Example:** an evil twin AP broadcasting the corporate SSID with a stronger
signal in an office car park; clients associate, and the attacker captures the
WPA2 handshake (or proxies all traffic through a captive portal harvesting
credentials). Deauthentication frames force clients to re-associate to the
twin.

**Mitigation:** WPA3 or WPA2-Enterprise with 802.1X (EAP-TLS with certificates
on managed devices), so there is no shared PSK to crack and no open portal to
phish; 802.1X wired ports as the baseline; rogue-AP detection via a wireless
IDS; and client-side rules that refuse networks without the enterprise profile.

### Insider threat

**Definition:** risk originating from people inside the organisation —
employees, contractors, or anyone with legitimate access — whether malicious,
negligent, or compromised.

**Example:** a database administrator with legitimate export rights takes a
copy of the customer table on their final week. Every access-control check
passes; the data leaves through a permitted channel. The 2023 Tesla insider
case (two employees exfiltrated terabytes of customer data) is the public
version of this pattern.

**Mitigation:** least privilege and just-in-time access, separation of duties
so no single person can both approve and execute, data loss prevention on
egress channels, append-only audit logs reviewed by someone other than the
people they monitor, and joiner/mover/leaver processes that revoke access on
the day, not at the end of the notice period.

---

## 4. Threat actors and why motivation changes defensive priorities

| Actor | Motivation | Typical capability | What this changes in your defensive priorities |
|---|---|---|---|
| Script kiddie | Curiosity, bragging rights, sometimes pettycrime | Public tools, run-as-is, no custom development; scans wide, exploits what is easy | Baseline hygiene stops them: patching, no default credentials, no exposed management interfaces. Detection tuning is low priority — volume and obvious signatures dominate |
| Cybercriminal | Money | Ransomware-as-a-service affiliates, credential stuffing at scale, initial-access brokering; organised, measured ROI | Prioritise anti-phishing, EDR coverage, offline tested backups, MFA everywhere, and egress monitoring. Business decisions (cyber insurance, ransom policy) are part of defence |
| Hacktivist | Ideology, publicity | DDoS, defacement, doxxing; operations are loud and timed to news cycles | Availability and reputation dominate: DDoS mitigation, web-application firewalls, rapid patching of public sites. Confidentiality still matters — leaked documents drive the publicity |
| Nation-state (APT) | Intelligence, strategic advantage, pre-positioning | Zero-days, supply-chain compromise, living-off-the-land binaries, multi-year dwell times | Prevention alone fails. Detection engineering, network segmentation, log retention long enough to find dwell time, hardware-token MFA against credential theft, and assume-breach architecture. This is where defence-in-depth earns its cost |

The practical rule: you allocate effort where the likely adversary's cost
exceeds your cost of defence. For script kiddies, a patched default is cheap
and sufficient. Against a nation-state, no amount of perimeter is sufficient —
you shift spend to detection and response, because you must assume the
perimeter is already crossed.

---

## 5. How these notes connect to the rest of Task 1

- Networking foundations for the threat types above: `02-networking-basics.md`.
- Cryptography behind the controls named here (MFA tokens, encryption for
  confidentiality, signatures for integrity): `03-cryptography-basics.md`.
- Linux commands you will use to apply the controls: `04-linux-fundamentals.md`.
- The tools named in the brief (Wireshark, Nmap, Burp Suite, Netcat) and what
  this machine can and cannot run of them: `05-tool-familiarization.md`.
- Why the virtual lab in the brief could not be built here, and what was built
  instead: `../lab/LAB-SETUP-REPORT.md`.
