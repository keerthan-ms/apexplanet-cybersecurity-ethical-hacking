# Task 4 — Exploitation & System Security

Days 37–48 · ApexPlanet Cybersecurity & Ethical Hacking Internship

---

## 1. Authorisation and safe use — read this first

Everything in this directory is a **local laboratory**. It exists to make the
mechanics concrete for someone learning, and it is built so that it can only be
pointed at things we own:

| Tool | Restriction enforced in code |
|---|---|
| `reverse_shell_lab.py` | Defaults to `127.0.0.1`; commands dispatched through an explicit allow-list, never `shell=True` with arbitrary input |
| `hash_crack.py` | Cracks only hashes you supply or that this script generates for the lab |
| `hardening_audit.py` | **Read-only.** It queries configuration; it never changes anything |
| `phishing_sim.py` | Binds loopback only, refuses `0.0.0.0`, carries a visible training banner, never transmits credentials anywhere |

**Do not point any of this at a system you do not own.** Unauthorised access to
a computer system is a criminal offence in most jurisdictions regardless of
intent. Penetration testing requires written authorisation that defines scope,
timing and rules of engagement *before* any testing starts — see
`methodology/01-pentest-methodology.md`.

---

## 2. What the brief asked for, and what exists here

| Brief requirement | Status |
|---|---|
| Penetration testing methodology (5 phases, documented in detail) | `methodology/01-pentest-methodology.md` |
| Exploit a known vulnerability in Metasploitable2 with Metasploit | **Not available — no Metasploit, no virtualisation.** `methodology/02-exploitation-with-metasploit.md` documents the method and the exact commands; the technique is demonstrated locally by `scripts/reverse_shell_lab.py` |
| Reverse shell + post-exploitation (`sysinfo`, `hashdump`) | `scripts/reverse_shell_lab.py` — a real reverse and bind shell over TCP on loopback, with `sysinfo`, `whoami`, `pwd`, `dir` |
| Brute-force SSH with Hydra | **Not available — Hydra not installed, and no service here is in scope.** `methodology/03-password-attacks.md` gives the command set; `scripts/hash_crack.py` does the offline half |
| Crack hashed passwords with John the Ripper | **Not available — John not installed.** `scripts/hash_crack.py` is the substitute |
| Social-engineering simulation page + awareness training | `scripts/phishing_sim.py` (local, banner-visible) + `methodology/04-social-engineering.md` |
| Malware basics, static vs dynamic analysis | `methodology/05-malware-basics.md` — **no malware sample is included or analysed** |
| System hardening: patches, firewall, unused services | `methodology/06-system-hardening.md` (commands) + `scripts/hardening_audit.py` (**real read-only audit of this machine**) |
| **Deliverable:** pentest report with screenshots | `reports/HARDENING-REPORT.md`, `reports/CRACKING-RESULTS.md` — **no screenshots; see §6** |
| **Deliverable:** GitHub repo documenting exploitation steps and mitigations | this repository |
| **Deliverable:** 10-minute demo video | **Manual — see §7** |

---

## 3. Prerequisites

```powershell
python --version          # 3.11.9
python -m pip install cryptography bcrypt
```

Nothing else is required. There is no database, no server and no build step.
`hardening_audit.py` shells out to PowerShell, which is present on any Windows
10/11 host.

---

## 4. Run it

### Reverse / bind shell lab

```powershell
# Reverse shell: attacker listens, payload dials back (connect-back)
python task-4\scripts\reverse_shell_lab.py --mode reverse --port 4444

# Bind shell: payload listens, attacker dials in
python task-4\scripts\reverse_shell_lab.py --mode bind --port 4444

# Single command, machine readable - what the tests use
python task-4\scripts\reverse_shell_lab.py --port 0 --once --json
```

`reverse` is the direction that matters in practice: it survives a network that
allows outbound TCP but filters inbound, which is the common case. Commands are
allow-listed — `whoami`, `pwd`, `dir`, `sysinfo`, `echo`, `help`, `exit`. An
unrecognised command is rejected with an error, not executed.

### Password cracking

```powershell
# Generate lab hashes (MD5, SHA-256, NTLM, bcrypt cost 4) and print them
python task-4\scripts\hash_crack.py --gen-samples

# Crack a hash you supply against the built-in 35-word list
python task-4\scripts\hash_crack.py --hash 5f4dcc3b5aa765d61d8327deb882cf99

# Supply your own wordlist (e.g. rockyou.txt)
python task-4\scripts\hash_crack.py --hash <value> --wordlist rockyou.txt

# Measure guesses/sec per algorithm - the argument for bcrypt
python task-4\scripts\hash_crack.py --benchmark
```

Format is auto-detected from length and prefix (`$2b$` → bcrypt, `$6$` →
sha512crypt, 32 hex → MD5, 40 → SHA-1, 64 → SHA-256, 128 → SHA-512). Force it
with `--format` when a value is ambiguous — notably **NTLM and MD5 are both 32
hex characters** and cannot be told apart from the string alone; the script says
so rather than guessing.

### Hardening audit (read-only)

```powershell
python task-4\scripts\hardening_audit.py                 # full profile
python task-4\scripts\hardening_audit.py --profile quick # faster
python task-4\scripts\hardening_audit.py --json
```

Twelve fault-tolerant collectors cover firewall profiles and rules, listening
ports, SMBv1, RDP, update recency, password/lockout policy, audit policy,
startup entries and others. A collector that cannot run (missing cmdlet, access
denied) records `unavailable` with the reason and the run continues — the script
never aborts and never changes system state.

### Phishing simulation

```powershell
python task-4\scripts\phishing_sim.py --list-templates
python task-4\scripts\phishing_sim.py --template fake-support --emit page.html
python task-4\scripts\phishing_sim.py --serve --port 8080
python task-4\scripts\phishing_sim.py --analyze suspicious.eml
```

Templates: `fake-delivery`, `fake-invoice`, `fake-support`. Every page carries a
visible training banner and posts only to its own `/submit`. A real simulation
sent to real people needs written organisational approval first — see
`methodology/04-social-engineering.md`.

### Tests

```powershell
python -m unittest discover -s task-4\tests -v
```

```
Ran 97 tests in 13.834s

OK
```

---

## 5. Repeatable demo steps (for the 10-minute video)

1. **Methodology** — open `methodology/01-pentest-methodology.md` and walk the
   five phases plus authorisation; pause on the rules-of-engagement section.
2. **Reverse shell** — run `reverse_shell_lab.py --mode reverse`, then from a
   second terminal `--role attacker`. Send `sysinfo`, then `whoami`. Show that
   `format C:` is rejected by the allow-list.
3. **Password cracking** — `--gen-samples`, pick the MD5 sample, crack it with
   `--hash`; then crack the bcrypt sample and show it takes visibly longer.
4. **Benchmark** — `--benchmark` and compare MD5/sec against bcrypt/sec; do the
   cost-factor arithmetic out loud.
5. **Hardening audit** — run `--profile quick` and read the top three findings
   with their remediations.
6. **Phishing** — `--emit` a template, open it, point at the banner, submit the
   form locally and show the immediate "this was a simulation" reveal; then
   `--analyze` the same page and show the indicators it scores.
7. **Close** on the substitution table below: what still needs the real lab.

---

## 6. Substitutions and honest limits

**This machine is not elevated and has no security tooling installed.** Nothing
here has been faked to look like it ran.

| Brief item | Why it is not here | What to run once the lab exists |
|---|---|---|
| Metasploit / `msfconsole` | Not installed; installing needs admin. Metasploitable2 cannot be created without virtualisation | `msfconsole` → `use exploit/unix/ftp/vsftpd_234_backdoor` → `set RHOSTS 192.168.56.102` → `run` |
| Hydra | Not installed; no SSH service is in scope | `hydra -L users.txt -P rockyou.txt ssh://192.168.56.102` |
| John the Ripper | Not installed | `john --wordlist=rockyou.txt hash.txt` |
| Screenshots in the report | No GUI tooling available to screenshot | Capture from the real lab |
| Malware sample | **Deliberately excluded.** No sample is bundled or analysed | Analyse only in an isolated sandbox you control |
| `hashdump` against a target | Would require a compromised host | Run post-exploitation against the lab VM only |

The reports in `reports/` contain **only output actually produced on this
machine**. `HARDENING-REPORT.md` is a genuine read-only audit of this host;
`CRACKING-RESULTS.md` contains hashes generated for this lab with real measured
guesses/sec. Neither contains invented Metasploit transcripts or scan output.

---

## 7. Manual items still outstanding

- **10-minute demo video** — record per §5, upload to LinkedIn as "Featured",
  submit the link through the ApexPlanet portal.
- **Screenshots** — capture from the real lab once VirtualBox/Kali/
  Metasploitable2 are buildable (requires administrator rights).
- **Portal submission** — needs your offer letter ID and email.
