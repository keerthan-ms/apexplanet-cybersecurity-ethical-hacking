# Task 1 — Foundation & Environment Setup

Days 1–12 · ApexPlanet Cybersecurity & Ethical Hacking Internship

---

## 1. What the brief asked for

| Brief requirement | Where it is |
|---|---|
| Cybersecurity basics: CIA triad, threat types, attack vectors | `notes/01-cybersecurity-fundamentals.md` |
| Lab environment setup (VirtualBox, Kali, Metasploitable2/DVWA, host-only network) | `lab/LAB-SETUP-REPORT.md` — **built as far as the machine allows; see §4** |
| Linux fundamentals (navigation, permissions, packages, networking) | `notes/04-linux-fundamentals.md` (with a real Windows equivalent section) |
| Networking basics (OSI, TCP/IP, DNS, HTTP/HTTPS, IP, subnetting, NAT) | `notes/02-networking-basics.md` |
| Cryptography basics (symmetric vs asymmetric, hashing, certificates, TLS) | `notes/03-cryptography-basics.md` + **`scripts/crypto_lab.py`** |
| Hands-on: encrypt and decrypt messages using OpenSSL | `scripts/crypto_lab.py` — OpenSSL substitute, see §3 |
| Tool familiarisation: Wireshark, Nmap, Burp Suite, Netcat | `notes/05-tool-familiarization.md` |
| **Deliverable:** lab setup report with screenshots | `lab/LAB-SETUP-REPORT.md` |
| **Deliverable:** GitHub repo with notes and a Linux cheat-sheet | this repository; cheat-sheet in `notes/04-linux-fundamentals.md` |
| **Deliverable:** 5-minute video walkthrough of lab setup | **Manual — see §7** |

---

## 2. Run it

```powershell
# Dependencies (already installed on this machine)
python -m pip install cryptography bcrypt

# The cryptography lab - human readable report
python task-1\scripts\crypto_lab.py

# Machine readable, and skips the one network call
python task-1\scripts\crypto_lab.py --json --no-tls

# Tests
python -m unittest discover -s task-1\tests -v
```

### Demo steps (for the video)

1. Run `python task-1\scripts\crypto_lab.py` and walk through the ten sections in order.
2. Point at section 2 — the MD5 length extension — and show that
   `forged == independent computation: True`. Explain that the forgery was computed
   from the digest alone and only *checked* against the secret afterwards.
3. Show section 5, flip a bit mentally, and explain `tampering rejected: True`.
4. Show section 10, the live TLS handshake against `example.com`, and read off the
   negotiated suite and certificate details.
5. Open `notes/04-linux-fundamentals.md` and show the Windows-equivalent mapping.

---

## 3. The OpenSSL substitution

The brief's hands-on item is *"Encrypt and Decrypt messages using OpenSSL"*.
**There is no `openssl` binary on this machine's `PATH`** (checked with
`Get-Command openssl` → not found), and installing one is not necessary when the
same primitives are available directly.

`scripts/crypto_lab.py` uses Python's `hashlib` and `hmac` plus the
`cryptography` package — which wraps the same OpenSSL primitives — to do the
equivalent work:

| Brief item | Demonstrated as |
|---|---|
| Symmetric encryption | AES-256-GCM and ChaCha20-Poly1305, with round trip and tamper rejection |
| Asymmetric encryption | RSA-2048, OAEP encrypt/decrypt and PSS sign/verify |
| Hashing (MD5, SHA-256) | Side-by-side digests, plus measured MD5 throughput |
| Why MD5 is not used | A **verified** length-extension forgery (§4) |
| Password storage | bcrypt, showing per-password salts |
| Digital certificates and SSL/TLS | A **live** handshake to `example.com` |

Once the real lab exists, the OpenSSL equivalents are:

```bash
echo -n "secret" | openssl dgst -sha256
openssl enc -aes-256-gcm -in plain.txt -out enc.bin -K <hex> -iv <hex>
openssl s_client -connect example.com:443 -servername example.com
```

---

## 4. The length-extension demonstration

This is the one result worth watching, because it is an attack that is usually
described but rarely shown working.

`length_extension_demo()` computes `MD5(secret || message)` and then, **using the
digest alone and never the secret**, produces a valid digest for
`MD5(secret || message || pad || "&role=admin")`.

The script does not simply assert that: it also computes the same value
honestly *with* the secret and compares the two. The printed line

```
forged == independent computation: True
```

means the forgery is a genuine MD5 output, not a plausible-looking string. The
test suite asserts this independently in `TestLengthExtension`.

---

## 5. Test results

```
Ran 51 tests in 24.276s

OK
```

Coverage, by class:

| Class | What it proves |
|---|---|
| `TestDigests` | Digests match the standard library exactly; lengths are correct |
| `TestLengthExtension` | The forgery verifies, is well-formed, differs from the original, and varies per message |
| `TestHmac` | Tag matches `hmac.new`; tampering and wrong keys are both rejected |
| `TestPasswordHashing` | bcrypt accepts the right password, rejects the wrong one, and salts each hash |
| `TestAead` | Round trip succeeds, a single-bit flip is rejected, a wrong key cannot decrypt, nonce is 96 bits |
| `TestChacha20` | Round trip succeeds |
| `TestKdf` | Deterministic per password+salt; a different salt or password changes the key; 32-byte output; work factor recorded |
| `TestRsa` | Signature verifies, detects tampering, 2048-bit modulus, e=65537, OAEP round trip |
| `TestEncoding` | Base64 and hex are reversible with no key — the "encoding is not encryption" point |
| `TestTlsInspection` | An unreachable endpoint returns an error record instead of raising; the live handshake reports a real certificate |
| `TestRunAll` | `run_all()` assembles every section; `--no-tls` omits TLS |
| `TestCommandInterface` | `--json` parses, `--help` exits 0, default output is human readable |
| `TestNoMisleadingClaims` | MD5 is presented as the weak case, bcrypt hashes do not contain the password, base64 is not called encryption |

The TLS test skips rather than fails when there is no outbound network.

---

## 6. Substitutions and honest limits

| Brief item | Status on this machine |
|---|---|
| VirtualBox / VMware | **Not installed.** Installers require administrator rights; this session is not elevated and UAC cannot be confirmed non-interactively. |
| Kali Linux attacker VM | **Not created** — depends on the above. |
| Metasploitable2 / DVWA target VM | **Not created** — depends on the above. |
| Host-only lab network | **Not created.** Intended architecture is documented as a diagram in `lab/LAB-SETUP-REPORT.md`. |
| Wireshark test capture | **Not possible.** Packet capture needs Npcap, which needs admin. **No capture is presented.** |
| Nmap | Not installed — see Task 2 for the TCP connect scanner that replaces it. |
| Burp Suite, Netcat | Not installed — see `notes/05-tool-familiarization.md`. |
| Lab setup screenshots | **Not captured, and none are faked.** `lab/LAB-SETUP-REPORT.md` contains a `## Screenshots — NOT CAPTURED` section with the exact checklist to capture later. |
| OpenSSL binary | Absent; substituted as in §3. |

Run later, once the lab is buildable:

```bash
# On the host, as administrator
VBoxManage --version
# Create Host-Only network 192.168.56.0/24, then:
#   Attacker VM : Kali            192.168.56.101
#   Target VM   : Metasploitable2 192.168.56.102
nmap -sS -sV -O -p- 192.168.56.102
tcpdump -i vboxnet0 -w task1-capture.pcap
```

---

## 7. Manual items still outstanding

- **5-minute lab walkthrough video** — record and upload to LinkedIn as "Featured",
  then submit the link through the ApexPlanet portal.
- **Lab setup screenshots** — capture once the VMs exist (checklist in the report).
- **Portal submission** — requires your offer letter ID and email.
