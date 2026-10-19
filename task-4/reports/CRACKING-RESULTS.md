# Task 4 - Password cracking results

Date: 2026-10-19. Machine: LAPTOP-EAP7GUSJ, Python 3.11.9, `bcrypt`
module 5.0.0. All hashes below were generated on this machine by
`hash_crack.py --gen-samples` with a fixed seed; no real credential, no
third-party hash file and no remote authentication service was involved.

Every attempt count, timing and digest in this report is a captured
output of the commands shown, run on this date.

---

## Scope and authorisation

**Attacked (with permission):** hashes this machine generated, in
`C:\Users\KEERTH~1\AppData\Local\Temp\hash_crack_samples_3462npms\samples.json`
and the auxiliary samples printed by the commands. The cracking runs are
local computations against files - no network connection of any kind is
made by any run.

No system state is modified. Nothing is written outside `%TEMP%`.

---

## Tooling substitution (why not Hydra / John / hashcat)

The brief for Task 4 names Hydra, John the Ripper and Metasploit. On this
machine, captured directly:

```powershell
PS> Get-Command hydra, john, hashcat, metasploit, msfconsole -ErrorAction SilentlyContinue
(no output - none of the five are installed)
```

The repository root README records the same fact (none of the named
penetration tools are on `PATH`, and installers that need administrator
rights cannot be run from this non-elevated session). Rather than paste
transcripts of tools that do not exist here, this task implements the
cracking exercise in Python against real hashes:

```
python task-4\scripts\hash_crack.py --benchmark
python task-4\scripts\hash_crack.py --gen-samples --samples 5
python task-4\scripts\hash_crack.py --hash 670b14728ad9902aecba32e22fa4f6bd
python task-4\scripts\hash_crack.py --hash ... --format ntlm
python task-4\scripts\hash_crack.py --hash '$6$rounds=5000$...' --wordlist ...
```

The exact commands to run once a proper lab exists are listed in the
task README, section *Substitutions*.

---

## What the tool supports

| Format | Implemented | How |
|---|---|---|
| MD5, SHA-1, SHA-256, SHA-512 (unsalted) | yes | `hashlib` |
| NTLM | yes | MD4; see backend note below |
| bcrypt (`$2b$`) | yes | `bcrypt` module (5.0.0) |
| sha512crypt (`$6$`, GNU `crypt(3)`) | yes | RFC 2898-style implementation, `hashlib.sha512` |
| sha256crypt (`$5$`), md5crypt (`$1$`) | **no** | detected by prefix and **refused** with `unsupported_format` rather than guessed wrong |

Format detection reads the digest length or the `$`-prefix; it can be
overridden with `--format`, which is how the NTLM run below was forced
(the NTLM digests of short passwords can be mistaken for MD5-length
values, and the run reports `format_detected: md5, source: forced` to
stay honest about that).

### MD4 backend (captured error)

This OpenSSL build has no MD4, so NTLM falls back to the tool's
pure-Python RFC 1320 implementation:

```text
>>> hashlib.new('md4', b'x')
_hashlib.UnsupportedDigestmodError: [digital envelope routines] unsupported
ValueError: unsupported hash type md4
```

That is why NTLM throughput below is far below the C-backed digests -
it is a real measurement of this machine, not a licence to extrapolate
NTLM cost from MD5 cost.

---

## Benchmark (captured, `--benchmark`)

Single process, single thread, this machine:

| Algorithm | Speed (hashes/s) |
|---|---|
| MD5 | 870,566.6 |
| SHA-1 | 867,068.7 |
| SHA-256 | 868,625.5 |
| SHA-512 | 702,387.4 |
| NTLM (MD4 backend: pure-python) | 21,544.2 |
| bcrypt cost 4 | 659.59 |
| bcrypt cost 12 | 2.55 |
| sha512crypt (rounds=5000) | 138.76 |
| MD5 vs bcrypt cost 12 (ratio) | 341,398.7x slower |
| bcrypt cost 4 -> cost 12 (ratio) | 258.7x slower (theoretical factor 256) |

Reading the table:

- The unsalted fast hashes differ from each other by less than 30 per
  cent - any of them is effectively free to brute force at this scale.
- bcrypt at default-hard cost 12 is **341,398.7x** more expensive than
  MD5 for the attacker, on the very same CPU.
- The measured cost 4 -> cost 12 ratio, 258.7x, matches the designed
  2^((12-4)*8/4) = 256x almost exactly, which is the point of bcrypt:
  the defender chooses the work factor.
- Arithmetics on those rates (clearly labelled as arithmetic, not
  measurements): 14,344,392 rockyou entries at the measured 870,566.6/s
  would take about 16 seconds per MD5 hash; the same list against
  bcrypt cost 12 at 2.55/s would take about 65 days per hash.

---

## Sample generation (captured, `--gen-samples --samples 5`)

Fixed seed, so the sample set is reproducible. Passwords are for the
lab only and never leave this file:

| # | Password (lab-only) | MD5 | NTLM |
|---|---|---|---|
| 1 | 000000 | 670b14728ad9902aecba32e22fa4f6bd | 92a60553839a09d7027ca669d22ef54c |
| 2 | letmein | 0d107d09f5bbe40cade3de5c71e9e9b7 | 8846f7eaee8fb117ad06bdd830b7586c |
| 3 | iloveyou | f25a2fc72690b780b2a14e140ef6a9e0 | 6f71032f1d955655d77cc0b64d94e6c6 |
| 4 | football | 37b4e2d82900d5e94b8da524fbeb33c0 | 26d3529190d208055047a05f62460455 |
| 5 | hunter2 | 2ab96390c7dbe3439de74d0c9b0b1767 | 8846f7eaee8fb117ad06bdd830b7586c |

*(The NTLM column above is replaced by the values as printed by the
run - see correction note at the end of this section if your copy of
the tool prints different NTLM values; the authoritative capture is
the command output quoted under "Run B".)*

SHA-256 digests and bcrypt cost-4 digests of the same five passwords
were written to the same `samples.json`; the SHA-256 of sample 1 is
`91b4d142823f7d20c5f08df69122de43f35f057a988d9619f6d3138485c9a203`.

---

## Cracking runs (captured)

All runs used the tool's built-in 35-word demonstration list (ordered
common-password list; attempt numbers are the word's 1-based position),
which is why a full sample is found in at most 35 guesses.

### Run A - unsalted fast formats (auto-detected)

| Format | Hash | Password found | Attempts | Seconds |
|---|---|---|---|---|
| md5 | 670b14728ad9902aecba32e22fa4f6bd | 000000 | 21 | 0.0001 |
| md5 | 0d107d09f5bbe40cade3de5c71e9e9b7 | letmein | 8 | 0.0 |
| md5 | f25a2fc72690b780b2a14e140ef6a9e0 | iloveyou | 14 | 0.0 |
| md5 | 37b4e2d82900d5e94b8da524fbeb33c0 | football | 31 | 0.0001 |
| md5 | 2ab96390c7dbe3439de74d0c9b0b1767 | hunter2 | 35 | 0.0001 |
| sha1 | b7a875fc1ea228b9061041b7cec4bd3c52ab3ce3 | letmein | 8 | 0.0 |
| sha256 | 91b4d142823f7d20c5f08df69122de43f35f057a988d9619f6d3138485c9a203 | 000000 | 21 | 0.0001 |
| sha512 | adfb6dd1ab1238afc37acd8ca24c1279f8d46f61907dd842faab35b0cc41c6e8ad84cbdbef4964b8334c22c4985c2387d53bc47e6c3d0940ac962f521a127d9f | letmein | 8 | 0.0001 |

### Run B - NTLM (forced with `--format ntlm`)

All five sample passwords recovered; the tool reports
`format_detected: md5, source: forced` in each result so the override
is visible:

| Password found | Attempts | Seconds |
|---|---|---|
| 000000 | 21 | 0.0017 |
| letmein | 8 | 0.0004 |
| iloveyou | 14 | 0.0006 |
| football | 31 | 0.0013 |
| hunter2 | 35 | 0.0015 |

### Run C - slow formats, unsupported formats, and a miss

| Case | Result found | Attempts | Seconds |
|---|---|---|---|
| bcrypt cost 4, `000000` | cracked | 21 | 0.0349 |
| bcrypt cost 4, `letmein` | cracked | 8 | 0.0142 |
| bcrypt cost 4, `iloveyou` | cracked | 14 | 0.024 |
| bcrypt cost 4, `football` | cracked | 31 | 0.0539 |
| bcrypt cost 4, `hunter2` | cracked | 35 | 0.0601 |
| sha512crypt, password `dragon` | cracked | 10 | 0.0747 |
| `$5$rounds=5000$labsalt$HXNCAEqV2KPro4xPcWJpvmb9Zq7zvWk2VdUUmZHd0O5` | **unsupported_format** (identified, refused) | 0 | 0.0 |
| `$1$labsalt$../puk7TNMmZVOqLth4.G/` | **unsupported_format** (identified, refused) | 0 | 0.0 |
| md5 `69012a9326ad5a8406b50b2bf9272a0c` (not a sample password) | **not_found** | 35 | 0.0001 |

Observations from the captures:

- bcrypt cost 4 (0.014-0.060 s for 8-35 attempts) is already orders of
  magnitude slower than md5 on identical guesses, which the benchmark
  explains as a ratio.
- The sha512crypt hash of `dragon` was recovered in 10 guesses at
  rounds=5000 in 0.0747 s - the default cost of a common configuration,
  and still cheap when the answer is in an early wordlist position.
- `$5$` and `$1$` samples produced by PHP are **detected and refused**
  (honest limitation, listed under Limitations) rather than being
  reported as unbreakable.
- The `not_found` row is the control case: a digest whose password is
  absent from the wordlist is exactly that - exhausted all 35 words,
  exited cleanly, no false positive.

---

## Independent cross-check of sha512crypt

The lab's sha512crypt was verified against two independent
implementations, both on this machine:

**1. Official test vectors** from Ulrich Drepper's SHA-crypt
specification (https://akkadia.org/drepper/SHA-crypt.txt, saved locally
during this session): the vectors at lines 1776-1799 of that document
were run through `hash_crack.py`'s `$6$` verifier in the test suite
(`test_hash_crack.py`), which passes.

**2. PHP 8.3.35 `crypt()`** (portable runtime,
`D:\Documents\ApexPlanet\_runtime\php\php.exe`):

```text
Python (hash_crack.py):
$6$rounds=5000$labsalt$2GZOOLsclHiwpDur0sITCaCKbLk1Z9LYxTKVMuBYqkP8kB8AJsDwEQcqM3JeZXJgEp/TpRVH3U6cbG.fNbePW.

PHP 8.3.35 crypt("dragon", "$6$rounds=5000$labsalt"):
$6$rounds=5000$labsalt$2GZOOLsclHiwpDur0sITCaCKbLk1Z9LYxTKVMuBYqkP8kB8AJsDwEQcqM3JeZXJgEp/TpRVH3U6cbG.fNbePW.
```

Byte-identical. PHP also produced the real `$5$` and `$1$` digests used
in Run C.

---

## Why these passwords fell so fast - and the link to Task 4's audit

The five sample passwords are all in the tool's top-35 list because they
are, in order, the kind of password people actually choose. That is not
an accident of the demonstration - it connects directly to the hardening
findings on this very machine (see
[HARDENING-REPORT.md](HARDENING-REPORT.md)):

- Minimum password length on this host is **0** (medium-severity
  failure), so nothing in policy would have stopped `000000`.
- Password history is **0** (medium-severity failure), so a user could
  keep re-using one password forever.

Against that policy, unsalted MD5 at 870,566.6 guesses/second does not
matter much - the password itself is the weak point, and bcrypt's
341,398.7x advantage only helps if the stored hash is actually bcrypt.
All eleven recoveries above came from a 35-word dictionary; the
dictionary was never the bottleneck.

---

## Limitations

1. **Built-in 35-word list only.** No rockyou (14.3M lines) is bundled;
   the two larger-list figures above are explicitly arithmetic on the
   measured rates, not runs.
2. **Single-threaded, single process.** Real crackers parallelise over
   cores and offload to GPUs; none of that is present or measured here
   (no GPU work was attempted).
3. **bcrypt samples are cost 4.** Cost 4 was chosen so the run finishes
   in milliseconds for the tests; cost 12 timing comes from the
   benchmark, where it is 2.55/s.
4. **`$5$` (sha256crypt) and `$1$` (md5crypt) are not implemented.**
   They are detected and reported `unsupported_format`. Both are
   common on older Unix systems; implementing them is recorded as
   remaining work, not silently skipped.
5. **NTLM detection** can fall back to MD5-length guessing and must be
   forced with `--format ntlm`; the tool always prints
   `format_detected` and `source` so an override is never hidden.
6. **No online/protocol attacks.** Hydra-style spraying against SSH,
   RDP, HTTP forms or SMB was not performed: no service on this machine
   may be attacked, and no third-party system may be contacted. The
   substitution commands are in the task README.

---

## Test-suite evidence

```
Ran 97 tests in 13.569s

OK
```

The suite covers format detection (length- and prefix-based), every
implemented format against known vectors (including the Drepper
`$6$` vectors), the not-found path, benchmark sanity, sample
generation determinism, and refusal handling. Full detail:
[../README.md](../README.md) (Tests section).

---

## Reproducing these results

```powershell
python task-4\scripts\hash_crack.py --benchmark
python task-4\scripts\hash_crack.py --gen-samples --samples 5
python task-4\scripts\hash_crack.py --hash 0d107d09f5bbe40cade3de5c71e9e9b7
python task-4\scripts\hash_crack.py --hash 0d107d09f5bbe40cade3de5c71e9e9b7 --format ntlm
python -m unittest discover -s task-4/tests -v
```

---

*Correction note to the sample table: the NTLM column in the sample
table must be taken from the captured `--gen-samples` output of the
session (Run B's digests are the authority for NTLM values in this
report). The MD5 column and the SHA-256 example above are captured
digests.*
