# ApexPlanet — Cybersecurity & Ethical Hacking Internship

Sixty-day internship programme, **five tasks**, built around a working local lab.

ApexPlanet Software Pvt. Ltd. · `www.apexplanet.in`

---

## Important: what this lab actually is

The brief for Task 1 asks for **Kali Linux as the attacker machine**,
**Metasploitable2 or DVWA as the target**, a **Host-Only Adapter**, and tools
including **Nmap, Wireshark, Burp Suite, Netcat, Metasploit, Hydra, John the
Ripper, OpenVAS and Nessus**.

**This machine could not build that lab.** Stated up front so nothing here is
mistaken for something it is not:

| Requirement | Status | Reason |
|---|---|---|
| VirtualBox / VMware | **Not installed** | The installer requires administrator rights; this session is not elevated (`BUILTIN\Administrators` is *deny only*) and UAC cannot be confirmed non-interactively |
| WSL 2 (Kali) | **Not installed** | `wsl --install` needs admin and a reboot |
| Docker (Metasploitable2, ELK) | **Not present** | No Docker on the machine |
| Nmap, Wireshark, Burp, Netcat, Metasploit, Hydra, John, sqlmap, nikto, gobuster, OpenVAS | **None present** | Nothing on `PATH`; Npcap/Wireshark installers also need admin |
| Raw sockets (`SOCK_RAW`) | **Denied** | `WinError 10013` — a SYN stealth scan is not possible without elevation, so scanning here is **TCP connect only** |
| Packet capture | **Not possible** | Windows packet capture requires Npcap, which requires admin |

**Nothing in this repository is fabricated.** There are no invented scan
outputs, no pasted screenshot descriptions that were never taken, and no
"representative" Metasploit transcripts. Every script here runs on this machine
and every reported result is a real output of it. Where the brief asked for
something this environment cannot produce, the task README says so in a
**Substitutions** section and gives the exact command to run once the lab
is buildable.

### What the lab does have

| Capability | Used for |
|---|---|
| **Python 3.11** with `flask`, `requests`, `cryptography`, `bcrypt` | Exploit development, scanning, detection, cryptography |
| **PowerShell** and readable Windows event logs (`System`, `Application`) | Host auditing, log analysis, firewall review |
| **Portable PHP 8.3 + MariaDB 11.4** (from the Full Stack track) | A genuinely vulnerable web application to attack — Task 3 |
| Network access | Real DNS, WHOIS, TLS and HTTP behaviour of real hosts |

That combination is enough to do honest work on every task: real cryptography,
real port scans, real SQL injection that really extracts rows, real password
cracking, real host hardening findings, and a real detection pipeline running
against logs this machine actually wrote.

---

## Repository

**Public:** `https://github.com/keerthan-ms/apexplanet-cybersecurity-ethical-hacking`

| Task | Title | Timeline | What is real here |
|---|---|---|---|
| [Task 1](task-1/README.md) | Foundation & Environment Setup | Days 1–12 | Cryptography lab (AES-GCM, ChaCha20, hashing, HMAC, TLS inspection), networking and Linux notes, honest lab report |
| [Task 2](task-2/README.md) | Network Security & Scanning | Days 13–24 | TCP connect scanner with banner grabbing, DNS/WHOIS/HTTP recon, security-header audit, Windows Firewall audit |
| [Task 3](task-3/README.md) | Web Application Security | Days 25–36 | A deliberately vulnerable app, working SQLi / XSS / CSRF / LFI exploits, and a hardened counterpart that defeats each one |
| [Task 4](task-4/README.md) | Exploitation & System Security | Days 37–48 | Local reverse shell lab, password cracking against real hashes, host hardening audit, phishing simulation |
| [Task 5](task-5/README.md) | Capstone & Incident Response | Days 49–60 | A mini SIEM over real local logs, detections fired by the Task 3 attacks, and a post-incident report |

---

## Quick start

```powershell
# Python 3.11 with flask, requests, cryptography, bcrypt
python -m pip install cryptography bcrypt

# Task 1 — cryptography lab
python task-1\scripts\crypto_lab.py

# Task 2 — scan the local machine (TCP connect, no admin required)
python task-2\scripts\portscan.py --target 127.0.0.1 --top-ports 200

# Task 3 — start the training app, then run the proof-of-concept harness
powershell -ExecutionPolicy Bypass -File task-3\scripts\run-demo.ps1
python task-3\scripts\demo_attacks.py

# Task 4 — local lab only: reverse shell, cracking, read-only host audit
python task-4\scripts\reverse_shell_lab.py --mode reverse --port 4444
python task-4\scripts\hash_crack.py --gen-samples
python task-4\scripts\hardening_audit.py --profile quick
python task-4\scripts\phishing_sim.py --list-templates

# Task 5 — run detections against logs this machine wrote (falls back to samples)
python task-5\siem\detect.py
```

Each task has its own test suite:

```powershell
python -m unittest discover -s task-1\tests -v
python -m unittest discover -s task-2\tests -v
python -m unittest discover -s task-3\tests -v
python -m unittest discover -s task-4\tests -v
python -m unittest discover -s task-5\tests -v
```

---

## Rules this repository follows

1. **No fabricated evidence.** A result in a report is a captured output, or it
   is not in the report.
2. **No attacking systems we do not own.** Scanning targets are `127.0.0.1`,
   the local MariaDB instance, and the local vulnerable application. Public
   requests are limited to passive, low-rate, standard lookups (DNS, WHOIS,
   a single `HEAD`) against hosts that publish abuse contacts for exactly this
   purpose.
3. **No destructive payloads.** The reverse shell and cracking tools run
   against local test targets and hashes generated for the purpose.
4. **No credentials in the repository.** Test credentials for the deliberately
   vulnerable app are generated at migration time.
5. **State the substitutions.** Anything the brief wanted that this environment
   cannot supply is listed in the task's README with the reason and the command
   to use once the lab is buildable.

---

## Environment and setup

The portable PHP and MariaDB used by Task 3 are provisioned by the sibling
repository's installer; see `fullstack-web-development/tools/setup-runtime.ps1`.
A local copy of the database used here is created by
`task-3\vulnerable\migrate.php`.

---

## Manual items that cannot be done from here

- **Lab setup screenshots** (Kali, Metasploitable, Wireshark capture) — the
  virtual machines cannot be created without administrator rights.
- **The five demo videos** (5-min, 5-min, 8-min, 10-min, 12-min) and the
  LinkedIn upload.
- **ApexPlanet portal submission.**
