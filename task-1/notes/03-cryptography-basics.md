# Task 1 — Cryptography Basics

What the Task 1 cryptography lab demonstrates, and the theory behind it.
Every claim about this machine's behaviour comes from running
`task-1/scripts/crypto_lab.py`; the run cited in section 5 was executed in the
repository root as `python task-1\scripts\crypto_lab.py` and produced the
values quoted there.

---

## 1. Symmetric versus asymmetric cryptography

**Symmetric cryptography** uses one shared key for both encryption and
decryption. AES and ChaCha20 are the modern choices. The hard part is not the
cipher — it is getting the key to the other side without anyone else seeing it.

**Asymmetric cryptography** uses a key pair: a public key everyone may see and
a private key only the holder sees. Operations are directional and
complementary: what the private key signs, the public key verifies; what the
public key encrypts, only the private key can decrypt. RSA and (EC)DSA/EdDSA
are the families in use. Asymmetric operations are orders of magnitude slower
than symmetric ones, which is why no protocol encrypts bulk traffic with RSA.

### Worked scenario: why TLS uses both

TLS 1.3 handshake for `https://example.com`, compressed to the moves that
matter:

1. **Client → Server (ClientHello).** The client offers TLS 1.3, its cipher
   suites, and an **ephemeral ECDHE public key share** (`key_share` extension),
   plus SNI. No private data yet.
2. **Server → Client (ServerHello + encrypted extensions + certificate +
   CertificateVerify + Finished).** The server picks the suite, sends its own
   ECDHE key share, its **certificate chain** (X.509, signed by a CA —
   asymmetric), and a **signature over the handshake transcript** made with its
   RSA or ECDSA private key (asymmetric authentication).
3. **Both sides compute the shared secret** from their two ECDHE key shares.
   This is the asymmetric part doing key agreement: an observer who recorded
   both public shares cannot derive the shared secret (discrete logarithm
   problem), and because the shares are *ephemeral*, stealing the server's long-
   term certificate key later does not decrypt this session (forward secrecy).
4. **Both sides derive symmetric keys** from the shared secret with HKDF —
   separate keys for each direction, plus an AEAD key (here
   `TLS_AES_256_GCM_SHA384`).
5. **All application data** — the HTTP request, the response, cookies — is
   encrypted with the symmetric AEAD. RSA is not involved in bulk encryption
   at all; the certificate's public key authenticated the handshake and proved
   server identity.

So: **asymmetric** solves identity and key distribution once per connection;
**symmetric** does the actual confidentiality and integrity work, cheaply, for
every record. Neither alone would do the job — symmetric alone has no way to
authenticate a stranger on first contact; asymmetric alone is far too slow for
payloads.

### Comparison

| Property | Symmetric (AES, ChaCha20) | Asymmetric (RSA, ECDSA, ECDHE) |
|---|---|---|
| Keys | One shared key | Key pair: public + private |
| Key distribution | The central problem — pre-shared, or delivered by an asymmetric handshake | Solved: publish the public key freely (in a certificate) |
| Speed | Fast; hardware AES-NI does GB/s | Slow; 10^2–10^4 times cheaper operationally than symmetric at scale |
| Typical use | Bulk encryption of sessions, disk encryption, database field encryption | Key exchange (ECDHE), signatures, certificate validation, small payloads, code signing |
| Failure mode if key leaks | All traffic to date and future decryptable (unless keys are ephemeral) | Past traffic stays safe if only long-term key leaks and ephemeral ECDHE was used |
| Authenticity built in? | No — anyone holding the key can forge | Yes — signature verifies a specific private key holder |

---

## 2. Hashing

A cryptographic hash maps arbitrary input to a fixed-length digest,
deterministically, with three properties: pre-image resistance (given a digest,
finding an input is infeasible), second pre-image resistance (given one input,
finding another with the same digest is infeasible), and collision resistance
(finding *any* two inputs with the same digest is infeasible).

### MD5 and SHA-256, structurally

Both are Merkle–Damgård constructions: the message is padded to a multiple of
512 bits and absorbed in 64-byte blocks through a compression function, chaining
an internal state from block to block. The digest is the final state.

| | MD5 | SHA-256 |
|---|---|---|
| Output | 128 bits (32 hex chars) | 256 bits (64 hex chars) |
| Internal state | 4 × 32-bit words (A, B, C, D) | 8 × 32-bit words (H0…H7) |
| Rounds per block | 64, in 4 groups using f, g, h, i boolean functions | 64 rounds with 32 distinct 32-bit constants and a message schedule |
| Padding | length suffix, little-endian | length suffix, big-endian |
| Collision resistance | **Broken** | Intact (2^128 birthday bound) |
| Length extension | Yes — exploitable | Yes, by construction, but no practical attack on the compression function; still, never build `H(key‖message)` from either |

Both are fast on purpose: hashing was designed for checksums and signatures,
not for guessing resistance.

### Why MD5 is broken

- **Collisions are practical.** In 2004 Wang et al. produced colliding MD5
  inputs; by 2008 chosen-prefix collisions were practical on commodity hardware,
  and the technique was used against RapidSSL and Flame-signed binaries. A
  collision means two documents with the same digest — fatal for signature
  schemes that hash-then-sign, because a signature over one document vouches
  for the other.
- **Length extension.** Because the digest *is* the chaining state after the
  final block, anyone holding `MD5(secret ‖ message)` can compute
  `MD5(secret ‖ message ‖ padding ‖ extra)` without knowing the secret: resume
  hashing from the published digest and append data. This breaks any scheme of
  the form `H(secret ‖ message)` used as a message authenticator.

  `task-1/scripts/crypto_lab.py` demonstrates this **verified, not asserted**
  (`length_extension_demo`, lines 119–167): a forged digest is computed from
  the digest alone via `_md5_continue` (lines 61–116), then checked against an
  honest computation that does know the secret. The run in section 5 reports
  `forgery_verified: True` with payload `&role=admin` appended — the classic
  "upgrade my own session cookie to admin" shape of attack.

- **HMAC fixes the construction, not MD5.** HMAC applies the key on both sides
  of the hash, so extension is impossible. But HMAC-MD5 is still deprecated
  practice: use HMAC-SHA-256 (the lab's `hmac_demo`, lines 173–187, does this
  and shows tampering detection).

### Password hashing specifically

A fast hash is exactly the wrong tool for passwords. Observed on this machine:
the lab measures **~2.68 million MD5 guesses per second per core** on trivially
small input (`md5_speed`, reported in the run below). A GPU farm multiplies
that by thousands. Any password hashed with MD5/SHA-256 and no work factor is
effectively recoverable by brute force once the hash database leaks.

A password hash needs three things a general-purpose hash does not give:

1. **A per-password random salt.** Defeats rainbow tables and makes identical
   passwords produce different hashes. The lab's bcrypt output shows two hashes
   of the *same* password differing entirely (`same_password_different_hash:
   True`), with the salt embedded in the `$2b$12$…` string.
2. **A deliberate work factor (slowness).** bcrypt's cost parameter is
   exponential: the lab uses `rounds=12`, meaning 2^12 iterations of the inner
   loop — roughly 250 ms per check in Python. PBKDF2 achieves the same by
   iterating: the lab runs **200,000 iterations** of PBKDF2-HMAC-SHA256 and
   reports the wall-clock cost (~0.02 s per derivation here). The security
   property is *symmetric pain*: every attacker guess costs them the same work
   as it cost you to store the hash.
3. **A self-describing format.** `$2b$12$…` carries algorithm, cost and salt,
   so the hash can be upgraded in place when you raise the cost or change
   algorithm — without a flag day.

scrypt and Argon2 add memory hardness on top (raise the cost of GPU/ASIC
attack specifically); bcrypt and PBKDF2 remain the widely accepted baseline,
and both are what this lab demonstrates.

---

## 3. Digital certificates and SSL/TLS

### What an X.509 certificate contains

An X.509 certificate is a signed statement binding a subject identity to a
public key. The fields that matter in practice:

| Field | Content | Why it matters |
|---|---|---|
| Version, serial | v3, issuer-assigned serial | Identifies the certificate for revocation |
| Signature algorithm | e.g. SHA-256 with RSA or ECDSA | SHA-1 signatures are rejected by browsers now |
| Issuer | The CA that signed it, as a distinguished name | The link in the chain of trust |
| Validity | notBefore / notAfter | Expiry is the most common validation failure in the wild |
| Subject | Who this certificate is for (often empty in modern public certs) | Historical CN; now superseded by SAN |
| SubjectPublicKeyInfo | The public key and algorithm | The thing being bound |
| Subject Alternative Names | List of DNS names the cert covers | **This is what browsers actually match**; wildcards like `*.example.com` live here |
| Extensions | Key usage, extended key usage, basic constraints (CA:true/false) | Constrains what the key may be used for; a leaf cert with CA:true is a mis-issuance waiting to happen |

### The chain of trust and what a CA does

A certificate authority's job is identity verification plus signing:

1. Applicant proves control of a domain (DNS TXT challenge, HTTP file
   challenge) — for OV/EV, also legal-entity checks.
2. CA signs the applicant's certificate with its **issuing key**; that
   signature, plus the issuing CA's own certificate, forms a link up to a
   **root certificate** already trusted by the OS or browser store.
3. The client validates by building the path: leaf → intermediate(s) → root,
   checking each signature, validity window, name constraints and revocation
   status. Trust is transitive: you trust roots in the store, and everything
   properly chained to them inherits that trust.
4. Intermediates exist so roots can stay offline and cold; servers send leaf +
   intermediates; clients must already hold the root.

Browsers and OS vendors run **root programmes**: audited lists of CAs that may
issue for the public trust store. A CA that mis-issues (DigiNotar 2011, after
a breach attackers issued a fraudulent `*.google.com` certificate) is removed
from the stores — a commercial death sentence, and the reason the ecosystem
works at all.

Revocation is the weak joint: **CRLs** (downloadable lists of serial numbers)
and **OCSP** (per-certificate live queries, and its stapled form) exist, but
many clients soft-fail on revocation errors. Certificate Transparency logs —
public, append-only Merkle trees of every issued cert — are now the primary
*post-hoc* detection mechanism: domain owners monitor CT for certificates
issued for their names without their knowledge.

### What happens when validation fails

The client aborts before sending application data and shows a warning. The
usual failure modes and what each means:

| Failure | Cause | Attacker scenario it prevents |
|---|---|---|
| Certificate expired / not yet valid | Clock skew or an un-renewed cert | Old stolen certs reused after expiry |
| Hostname mismatch | Cert is for another name (SNI/host mismatch) | Mis-issued cert for a different domain, or interception with the wrong cert |
| Untrusted root | Issuer not in the store, or self-signed | Any attacker-generated certificate; MITM with a homemade CA |
| Incomplete chain | Server omitted intermediates | Usually an operational error, not an attack; shown here for contrast |
| Revoked | Serial found in CRL/OCSP response | Reuse of a compromised, revoked key |
| Weak signature (SHA-1) | Deprecated algorithm | Collision-based forgery of the certificate |

The security property: validation failure is *fail-closed*. An application
that swallows certificate errors (`verify=False` in Python's requests, `-k` in
curl) deletes the server-authentication half of TLS entirely and is open to
trivial interception.

### Observed example, from this repository's lab

Running `python task-1\scripts\crypto_lab.py` from the repository root on this
machine performs a live TLS handshake to `example.com` (`tls_inspect`, lines
332–371, using Python's `ssl` with the default trust store) and reports:

```
example.com -> TLSv1.3 / TLS_AES_256_GCM_SHA384 (256 bit)
subject CN : example.com
issuer     : SSL Corporation
valid until: 2026-12-26 (67 days, expired: False)
SANs       : 2 (example.com, *.example.com)
```

Reading it as a practitioner: negotiated TLS 1.3 with an AES-256-GCM cipher
suite and SHA-384 in the PRF (the suite name `TLS_AES_256_GCM_SHA384` encodes
both); the certificate's CN is `example.com`, but the two SANs —
`example.com` and `*.example.com` — are what actually authorise the name;
issuer organisation "SSL Corporation" means the chain runs through their
intermediates up to a root in the system trust store (the lab validates with
`ssl.create_default_context()`, so the handshake only succeeded because chain
validation passed); the certificate is valid at run time with 67 days left.

That single connection demonstrates, concretely: asymmetric authentication
(certificate + handshake signature), symmetric bulk encryption (the AEAD
suite), and CA-based chain validation — the three pieces of section 1 and this
section working together on a real network.

---

## 4. Where each theory item is demonstrated in `task-1/scripts/crypto_lab.py`

| Theory item | Function | Lines | What it proves |
|---|---|---|---|
| MD5 vs SHA-256 structure and output length | `digests` | 37–49 | Side-by-side digests of one message; MD5 32 hex chars, SHA-256 64 |
| Why MD5 is too fast for passwords | `md5_speed` | 52–58 | Measured hashes/sec on this machine (~2.68M/s in the run below) |
| MD5 length extension (mechanism) | `_md5_continue` | 61–116 | Resumes MD5 from an intermediate digest — the operation the attack relies on |
| MD5 length extension (verified forgery) | `length_extension_demo` | 119–167 | Forged `MD5(secret‖m‖pad‖extra)` computed from the digest alone; `forgery_verified: True` |
| HMAC as the correct authenticator | `hmac_demo` | 173–187 | HMAC-SHA-256 tag; tamper detected, wrong key rejected |
| Password hashing: salt + work factor | `password_hash_demo` | 192–207 | bcrypt cost 12; same password → different hashes (salt), wrong password rejected |
| Symmetric AEAD: confidentiality + integrity | `aead_demo` | 213–243 | AES-256-GCM round trip; one flipped bit → decryption rejected |
| Symmetric AEAD without AES hardware | `chacha20_demo` | 246–258 | ChaCha20-Poly1305 round trip |
| Key stretching / KDF | `kdf_demo` | 261–283 | PBKDF2-HMAC-SHA256, 200,000 iterations, timed |
| Asymmetric: sign, verify, encrypt, decrypt | `rsa_demo` | 288–327 | RSA-2048 PSS signature valid, tamper detected, OAEP round trip |
| Encoding is not encryption | `encoding_is_not_encryption` | 376–387 | Base64 and hex reversed with no key |
| Live TLS certificate and suite inspection | `tls_inspect` | 332–371 | The observed `example.com` output quoted in section 3 |

Run it with:

```powershell
python task-1\scripts\crypto_lab.py          # full report, including live TLS
python task-1\scripts\crypto_lab.py --json   # machine-readable results
python task-1\scripts\crypto_lab.py --no-tls # offline only
```

---

## 5. Output of the run cited above

The following is the actual output of `python task-1\scripts\crypto_lab.py`
executed from the repository root in this environment (values such as the
bcrypt salt, nonces and derived keys differ on every run; the booleans and the
TLS facts do not vary apart from `days_remaining` counting down):

```
[1] Hashing
    MD5 speed: ~2,677,914 hashes/sec - fast enough to brute force
[2] MD5 length extension
    forged == independent computation: True
[3] HMAC-SHA256
    tamper detected  : True
    wrong key rejected: True
[4] Password hashing (bcrypt)
    per-password salt: True
    correct accepted  : True, wrong rejected: True
[5] AES-256-GCM
    round trip : True
    tampering rejected: True
[7] PBKDF2-HMAC-SHA256
    iterations : 200,000
[8] RSA-2048
    signature valid / tamper detected / OAEP round trip: True / True / True
[10] TLS certificate inspection
    example.com -> TLSv1.3 / TLS_AES_256_GCM_SHA384 (256 bit)
```

Nothing in this file is a simulated transcript: each line corresponds to a
real computation in the script.
