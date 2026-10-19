#!/usr/bin/env python3
"""
Task 4 - password cracking against hashes generated for this lab.

Substitute for Hydra and John the Ripper, neither of which is installed on
this machine (`Get-Command hydra john hashcat` returns nothing). Everything
here is computed by this script in pure Python:

  * MD5 / SHA-1 / SHA-256 / SHA-512  - hashlib (OpenSSL).
  * NTLM                             - MD4(UTF-16LE(password)). This OpenSSL
                                       build exposes no `md4` digest
                                       (`hashlib.new('md4')` raises
                                       UnsupportedDigestmodError), so a
                                       pure-Python MD4 (RFC 1320) is used and
                                       verified against the RFC test vectors.
                                       The backend actually used is reported
                                       as `md4_backend`.
  * bcrypt                           - `bcrypt.checkpw`, Python binding.
  * sha512crypt ($6$)                - a faithful implementation of the
                                       crypt(3) SHA-512 algorithm from
                                       Ulrich Drepper's specification
                                       (https://www.akkadia.org/drepper/SHA-crypt.txt,
                                       version 0.6, 2016-08-31), verified in
                                       the test suite against the published
                                       vectors from that document, including
                                       the rounds clamping (min 1000).
  * md5crypt ($1$) and sha256crypt ($5$) are IDENTIFIED by prefix but not
                                       cracked - reported as unsupported
                                       rather than guessed at.

Scope, stated once:
  The hashes attacked here are produced by this script (`--gen-samples`) or
  supplied by the operator. Nothing belonging to anyone else is attacked, no
  service is brute forced, and no third-party system is contacted.

    python task-4/scripts/hash_crack.py --gen-samples
    python task-4/scripts/hash_crack.py --hash 5f4dcc3b5aa765d61d8327deb882cf99
    python task-4/scripts/hash_crack.py --benchmark
    python task-4/scripts/hash_crack.py --hash <value> --wordlist rockyou.txt
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import struct
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator

DEFAULT_BCRYPT_ROUNDS = 4
SAMPLE_SEED = 20261019

# Built-in wordlist so the script works with no external file.
DEFAULT_WORDLIST: tuple[str, ...] = (
    "password", "123456", "12345678", "qwerty", "abc123", "monkey",
    "1234567", "letmein", "trustno1", "dragon", "baseball", "master",
    "sunshine", "iloveyou", "ashley", "michael", "shadow", "superman",
    "654321", "111111", "000000", "password1", "welcome", "admin",
    "login", "passw0rd", "hello", "freedom", "whatever", "starwars",
    "football", "harley", "ranger", "buster", "hunter2",
)

CRYPT_SALT_MAX = 16
CRYPT_ROUNDS_DEFAULT = 5000
CRYPT_ROUNDS_MIN = 1000
CRYPT_ROUNDS_MAX = 999999999
CRYPT_B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


# ----------------------------------------------------------------- formats ---

def detect_format(value: str) -> tuple[str, str]:
    """Identify a hash string from its shape. Returns (format, note).

    A 32-hex value is MD5 or NTLM and nothing else can distinguish them: both
    are 16 bytes of lower-case hex with no salt or structure. The note says so
    and `--format ntlm` forces the NTLM interpretation.
    """
    v = value.strip()
    if v.startswith(("$2a$", "$2b$", "$2y$", "$2x$")):
        return "bcrypt", "prefix $2b$/$2y$ -> bcrypt (cost follows the prefix)"
    if v.startswith("$6$"):
        return "sha512crypt", "prefix $6$ -> sha512crypt (crypt(3) SHA-512)"
    if v.startswith("$5$"):
        return "sha256crypt", "prefix $5$ -> sha256crypt (identified, cracking not implemented)"
    if v.startswith("$1$"):
        return "md5crypt", "prefix $1$ -> md5crypt (identified, cracking not implemented)"
    if v and all(c in "0123456789abcdefABCDEF" for c in v):
        length = len(v)
        if length == 32:
            return "md5", ("32 hex chars: MD5 or NTLM are indistinguishable "
                           "here; use --format ntlm if this came from a "
                           "Windows SAM/pwdump")
        if length == 40:
            return "sha1", "40 hex chars -> SHA-1"
        if length == 64:
            return "sha256", "64 hex chars -> SHA-256"
        if length == 128:
            return "sha512", "128 hex chars -> SHA-512"
        return "unknown", f"{length} hex chars is not a known digest length"
    return "unknown", "no recognised prefix or hex digest shape"


SUPPORTED_FORMATS = ("md5", "sha1", "sha256", "sha512", "ntlm", "bcrypt",
                     "sha512crypt")


# -------------------------------------------------------------------- MD4 ----

def _md4_openssl(data: bytes) -> bytes | None:
    try:
        return hashlib.new("md4", data).digest()
    except ValueError:
        return None


def _md4_pure(data: bytes) -> bytes:
    """MD4 (RFC 1320) in pure Python.

    Used because this machine's OpenSSL build has MD4 compiled out. Verified
    against the RFC 1320 appendix vectors in the test suite.
    """
    def f(x: int, y: int, z: int) -> int:
        return (x & y) | (~x & z)

    def g(x: int, y: int, z: int) -> int:
        return (x & y) | (x & z) | (y & z)

    def h(x: int, y: int, z: int) -> int:
        return x ^ y ^ z

    def rotl(x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    msg = bytearray(data)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += (len(data) * 8).to_bytes(8, "little")

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    def shift_schedule(per_position: list[int]) -> list[int]:
        return [per_position[i % 4] for i in range(16)]

    idx1 = list(range(16))
    idx2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
    idx3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
    sh1 = shift_schedule([3, 7, 11, 19])
    sh2 = shift_schedule([3, 5, 9, 13])
    sh3 = shift_schedule([3, 9, 11, 15])

    for off in range(0, len(msg), 64):
        words = list(struct.unpack("<16I", bytes(msg[off:off + 64])))
        st = [a, b, c, d]
        for step in range(16):
            st[0] = rotl((st[0] + f(st[1], st[2], st[3]) + words[idx1[step]])
                         & 0xFFFFFFFF, sh1[step])
            st = [st[3], st[0], st[1], st[2]]
        for step in range(16):
            st[0] = rotl((st[0] + g(st[1], st[2], st[3]) + words[idx2[step]]
                           + 0x5A827999) & 0xFFFFFFFF, sh2[step])
            st = [st[3], st[0], st[1], st[2]]
        for step in range(16):
            st[0] = rotl((st[0] + h(st[1], st[2], st[3]) + words[idx3[step]]
                           + 0x6ED9EBA1) & 0xFFFFFFFF, sh3[step])
            st = [st[3], st[0], st[1], st[2]]
        a = (a + st[0]) & 0xFFFFFFFF
        b = (b + st[1]) & 0xFFFFFFFF
        c = (c + st[2]) & 0xFFFFFFFF
        d = (d + st[3]) & 0xFFFFFFFF

    return struct.pack("<4I", a, b, c, d)


_MD4_OPENSSL = _md4_openssl(b"probe")
MD4_BACKEND = "hashlib" if _MD4_OPENSSL is not None else "pure-python"


def md4(data: bytes) -> bytes:
    if MD4_BACKEND == "hashlib":
        return hashlib.new("md4", data).digest()
    return _md4_pure(data)


def ntlm_hex(password: str) -> str:
    """NTLM hash: MD4 of the password encoded UTF-16LE."""
    return md4(password.encode("utf-16-le")).hex()


# ------------------------------------------------------- sha512crypt ($6$) ---

def _b64_24(b2: int, b1: int, b0: int, count: int) -> str:
    w = (b2 << 16) | (b1 << 8) | b0
    out = []
    for _ in range(count):
        out.append(CRYPT_B64[w & 0x3F])
        w >>= 6
    return "".join(out)


_SHA512_GROUPS: list[tuple[int, int, int]] = [
    (0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4),
    (47, 5, 26), (6, 27, 48), (28, 49, 7), (50, 8, 29), (9, 30, 51),
    (31, 52, 10), (53, 11, 32), (12, 33, 54), (34, 55, 13), (56, 14, 35),
    (15, 36, 57), (37, 58, 16), (59, 17, 38), (18, 39, 60), (40, 61, 19),
    (62, 20, 41),
]


def _sha512_b64(digest: bytes) -> str:
    out = []
    for b2, b1, b0 in _SHA512_GROUPS:
        out.append(_b64_24(digest[b2], digest[b1], digest[b0], 4))
    out.append(_b64_24(0, 0, digest[63], 2))
    return "".join(out)


def sha512_crypt(password: bytes, salt: bytes, rounds: int = CRYPT_ROUNDS_DEFAULT,
                 emit_rounds: bool = False) -> str:
    """crypt(3) SHA-512, following Drepper's SHA-crypt specification 0.6.

    Steps 1-21 of the specification; returns the full `$6$...` string. The
    rounds are clamped to [1000, 999999999] as the specification requires,
    and `rounds=` is echoed in the output only when the input setting carried
    it (`emit_rounds=True`), which is how the C reference behaves.
    """
    rounds = max(CRYPT_ROUNDS_MIN, min(rounds, CRYPT_ROUNDS_MAX))
    salt = salt[:CRYPT_SALT_MAX]

    ctx = hashlib.sha512()
    ctx.update(password)
    ctx.update(salt)
    alt = hashlib.sha512(password + salt + password).digest()

    cnt = len(password)
    while cnt > 64:
        ctx.update(alt)
        cnt -= 64
    ctx.update(alt[:cnt])

    cnt = len(password)
    while cnt > 0:
        ctx.update(alt if cnt & 1 else password)
        cnt >>= 1

    alt = ctx.digest()

    dp_ctx = hashlib.sha512()
    for _ in range(len(password)):
        dp_ctx.update(password)
    p_bytes = (dp_ctx.digest() * (len(password) // 64 + 1))[:len(password)]

    ds_ctx = hashlib.sha512()
    for _ in range(16 + alt[0]):
        ds_ctx.update(salt)
    s_bytes = (ds_ctx.digest() * (len(salt) // 64 + 1))[:len(salt)]

    for cnt in range(rounds):
        c = hashlib.sha512()
        if cnt & 1:
            c.update(p_bytes)
        else:
            c.update(alt)
        if cnt % 3 != 0:
            c.update(s_bytes)
        if cnt % 7 != 0:
            c.update(p_bytes)
        if cnt & 1:
            c.update(alt)
        else:
            c.update(p_bytes)
        alt = c.digest()

    rounds_part = f"rounds={rounds}$" if emit_rounds else ""
    return (f"$6${rounds_part}"
            f"{salt.decode('ascii', 'replace')}${_sha512_b64(alt)}")


def parse_sha512crypt_setting(setting: str) -> tuple[int, str, bool]:
    """Split `$6$[rounds=N$]salt` into (clamped rounds, salt, emit_rounds)."""
    rest = setting.strip()
    if rest.startswith("$6$"):
        rest = rest[3:]
    rounds = CRYPT_ROUNDS_DEFAULT
    emit_rounds = False
    if rest.startswith("rounds="):
        number, sep, tail = rest[7:].partition("$")
        if sep and number.isdigit():
            rounds = max(CRYPT_ROUNDS_MIN, min(int(number), CRYPT_ROUNDS_MAX))
            emit_rounds = True
            rest = tail
    salt = rest.partition("$")[0][:CRYPT_SALT_MAX]
    return rounds, salt, emit_rounds


def sha512_crypt_setting(password: str, setting: str) -> str:
    """crypt(3) entry point: password plus a setting like `$6$rounds=10000$salt`."""
    rounds, salt, emit = parse_sha512crypt_setting(setting)
    return sha512_crypt(password.encode("utf-8"), salt.encode("utf-8"),
                        rounds, emit)


def parse_sha512crypt(value: str) -> tuple[int, str, str]:
    """Split `$6$[rounds=N$]salt$digest` into (rounds, salt, digest)."""
    head, sep, digest = value.strip().rpartition("$")
    if not sep:
        raise ValueError("sha512crypt value has no salt/digest separator")
    rounds, salt, _ = parse_sha512crypt_setting(head + "$")
    return rounds, salt, digest


# ---------------------------------------------------------------- checkers ---

def make_checker(hash_value: str, fmt: str) -> Callable[[str], bool]:
    """Return a predicate that is True when a candidate password matches."""
    target = hash_value.strip()
    if fmt in ("md5", "sha1", "sha256", "sha512"):
        wanted = target.lower()

        def check_raw(password: str) -> bool:
            return hashlib.new(fmt, password.encode("utf-8")).hexdigest() == wanted
        return check_raw

    if fmt == "ntlm":
        wanted = target.lower()

        def check_ntlm(password: str) -> bool:
            return ntlm_hex(password) == wanted
        return check_ntlm

    if fmt == "bcrypt":
        import bcrypt
        try:
            encoded = target.encode("ascii")
            bcrypt.checkpw(b"", encoded)
        except (ValueError, UnicodeEncodeError) as exc:
            raise ValueError(f"value is not a bcrypt hash ({exc})") from exc

        def check_bcrypt(password: str) -> bool:
            try:
                return bcrypt.checkpw(password.encode("utf-8"), encoded)
            except ValueError:
                return False
        return check_bcrypt

    if fmt == "sha512crypt":
        rounds, salt, wanted = parse_sha512crypt(target)
        salt_bytes = salt.encode("utf-8")

        def check_crypt6(password: str) -> bool:
            return sha512_crypt(password.encode("utf-8"), salt_bytes,
                                rounds).endswith("$" + wanted)
        return check_crypt6

    raise ValueError(f"unsupported format: {fmt}")


# ---------------------------------------------------------------- wordlist ---

def iter_wordlist(path: str | None) -> Iterator[tuple[str, bytes]]:
    """Yield (text, raw bytes) for every wordlist entry.

    Raw bytes are what the fast digests are computed against, so a wordlist
    entry hashes exactly as it appears in the file. Text (UTF-8 with a
    Latin-1 fallback) is what NTLM and bcrypt need.
    """
    if path is None:
        for word in DEFAULT_WORDLIST:
            yield word, word.encode("utf-8")
        return
    with open(path, "rb") as handle:
        for line in handle:
            raw = line.rstrip(b"\r\n")
            if not raw or raw.startswith(b"#"):
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = raw.decode("latin-1")
            yield text, raw


# ---------------------------------------------------------------- cracking ---

def crack_hash(hash_value: str, fmt: str | None = None,
               wordlist_path: str | None = None,
               source: str = "auto") -> dict:
    """Try every wordlist entry against one hash. Never raises on a miss."""
    started = time.perf_counter()
    detected, note = detect_format(hash_value)
    forced = None if fmt in (None, "auto") else fmt
    chosen = forced or detected
    if forced is None:
        source = "auto"
    elif source == "auto":
        source = "forced"
    result: dict = {
        "hash": hash_value,
        "format": chosen,
        "format_detected": detected,
        "format_source": source,
        "format_note": note,
        "wordlist": wordlist_path or "builtin",
        "found": False,
        "password": None,
        "attempts": 0,
        "status": "not_found",
        "seconds": 0.0,
    }

    if chosen not in SUPPORTED_FORMATS:
        result["status"] = "unsupported_format"
        result["detail"] = (
            f"{chosen} is identified but not crackable by this script; "
            "use John the Ripper or hashcat for it (see the task README)"
        )
        return result

    try:
        checker = make_checker(hash_value, chosen)
    except ValueError as exc:
        result["status"] = "invalid_target"
        result["detail"] = str(exc)
        return result

    attempts = 0
    fast = chosen in ("md5", "sha1", "sha256", "sha512")
    wanted = hash_value.strip().lower()
    for text, raw in iter_wordlist(wordlist_path):
        attempts += 1
        try:
            matched = (hashlib.new(chosen, raw).hexdigest() == wanted
                       if fast else checker(text))
        except Exception as exc:
            result["status"] = "error"
            result["detail"] = f"{type(exc).__name__}: {exc}"
            break
        if matched:
            result.update({
                "found": True,
                "password": text,
                "status": "cracked",
                "attempts": attempts,
                "seconds": round(time.perf_counter() - started, 4),
            })
            return result

    result["attempts"] = attempts
    result["seconds"] = round(time.perf_counter() - started, 4)
    return result


# -------------------------------------------------------------- gen-samples ---

def generate_samples(count: int = 5,
                     out_dir: str | None = None) -> dict:
    """Generate N passwords and hash them with MD5, SHA-256, NTLM and bcrypt.

    Passwords are drawn from the built-in wordlist with a fixed seed, so the
    *set* is reproducible across runs; the bcrypt hash is not, because bcrypt
    salts are random by design (that is one of the properties under test).
    Written to a temp directory unless --out is given.
    """
    rng = random.Random(SAMPLE_SEED)
    pool = list(DEFAULT_WORDLIST)
    if count > len(pool):
        raise ValueError(f"count {count} exceeds wordlist size {len(pool)}")
    chosen = rng.sample(pool, count)

    import bcrypt
    samples = []
    for index, password in enumerate(chosen, start=1):
        samples.append({
            "index": index,
            "password": password,
            "md5": hashlib.md5(password.encode("utf-8")).hexdigest(),
            "sha256": hashlib.sha256(password.encode("utf-8")).hexdigest(),
            "ntlm": ntlm_hex(password),
            "bcrypt": bcrypt.hashpw(
                password.encode("utf-8"),
                bcrypt.gensalt(rounds=DEFAULT_BCRYPT_ROUNDS),
            ).decode("ascii"),
        })

    directory = Path(out_dir) if out_dir else Path(
        tempfile.mkdtemp(prefix="hash_crack_samples_"))
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "samples.json"
    payload = {
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "generator": "task-4/scripts/hash_crack.py --gen-samples",
        "seed": SAMPLE_SEED,
        "bcrypt_rounds": DEFAULT_BCRYPT_ROUNDS,
        "local_lab_only": ("passwords below are lab strings chosen by this "
                           "script; not real credentials, never reuse them"),
        "samples": samples,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    payload["path"] = str(path)
    return payload


# ---------------------------------------------------------------- benchmark ---

def _measure(fn: Callable[[], None], min_seconds: float,
             min_runs: int = 3) -> tuple[int, float, float]:
    runs = 0
    started = time.perf_counter()
    while True:
        fn()
        runs += 1
        elapsed = time.perf_counter() - started
        if elapsed >= min_seconds and runs >= min_runs:
            return runs, elapsed, runs / elapsed


def benchmark(min_seconds: float = 0.4) -> dict:
    """Measure guesses/sec per algorithm on this machine, right now.

    Honest numbers: one Python thread, this CPU, this implementation. bcrypt
    is measured at cost 4 (fast enough to time) and at cost 12 (the usual
    production cost) so the cost-factor argument can use measured values.
    """
    import bcrypt

    probe = "benchmark-guess"
    settings = {
        "md5": (lambda: hashlib.md5(probe.encode()).hexdigest(), "-"),
        "sha1": (lambda: hashlib.sha1(probe.encode()).hexdigest(), "-"),
        "sha256": (lambda: hashlib.sha256(probe.encode()).hexdigest(), "-"),
        "sha512": (lambda: hashlib.sha512(probe.encode()).hexdigest(), "-"),
        "ntlm (pure-python MD4)": (lambda: ntlm_hex(probe), "MD4 backend: " + MD4_BACKEND),
    }
    results = []
    for name, (fn, parameter) in settings.items():
        runs, elapsed, rate = _measure(fn, min_seconds)
        results.append({
            "algorithm": name,
            "parameter": parameter,
            "guesses": runs,
            "seconds": round(elapsed, 3),
            "guesses_per_second": round(rate, 1),
        })

    for cost in (4, 12):
        salt = bcrypt.gensalt(rounds=cost)
        target = bcrypt.hashpw(probe.encode(), salt)
        runs, elapsed, rate = _measure(
            lambda: bcrypt.checkpw(probe.encode(), target), min_seconds)
        results.append({
            "algorithm": "bcrypt",
            "parameter": f"cost {cost} (2^{cost} = {2 ** cost} Blowfish key-schedule rounds)",
            "guesses": runs,
            "seconds": round(elapsed, 3),
            "guesses_per_second": round(rate, 2),
        })

    crypt_salt = b"benchmarksalt123"
    crypt_target = sha512_crypt(b"guess", crypt_salt, CRYPT_ROUNDS_DEFAULT)
    runs, elapsed, rate = _measure(
        lambda: sha512_crypt(b"guess", crypt_salt, CRYPT_ROUNDS_DEFAULT),
        min_seconds, min_runs=3)
    results.append({
        "algorithm": "sha512crypt ($6$)",
        "parameter": f"rounds={CRYPT_ROUNDS_DEFAULT} (the crypt(3) default)",
        "guesses": runs,
        "seconds": round(elapsed, 3),
        "guesses_per_second": round(rate, 2),
    })

    by_name = {r["algorithm"]: r for r in results}
    md5_rate = by_name["md5"]["guesses_per_second"]
    b4 = next(r["guesses_per_second"] for r in results
              if r["algorithm"] == "bcrypt" and "cost 4" in r["parameter"])
    b12_rate = next(r["guesses_per_second"] for r in results
                    if r["algorithm"] == "bcrypt" and "cost 12" in r["parameter"])
    summary = {
        "md5_per_second": md5_rate,
        "bcrypt_cost4_per_second": b4,
        "bcrypt_cost12_per_second": b12_rate,
        "md5_vs_bcrypt12_factor": round(md5_rate / b12_rate, 1) if b12_rate else None,
        "cost4_to_cost12_theoretical_factor": 2 ** (12 - 4),
        "cost4_to_cost12_measured_factor": (round(b4 / b12_rate, 1)
                                            if b12_rate else None),
        "sha512crypt_per_second": by_name["sha512crypt ($6$)"]["guesses_per_second"],
    }
    return {"results": results, "summary": summary,
            "host_note": ("single-threaded CPython on this machine; GPU rates "
                          "for MD5/NTLM are orders of magnitude higher again "
                          "(see methodology/03-password-attacks.md)")}


# -------------------------------------------------------------------- CLI ----

def _print_samples(payload: dict) -> None:
    print(f"Generated {len(payload['samples'])} samples -> {payload['path']}")
    print(f"bcrypt rounds: {payload['bcrypt_rounds']} (kept low so tests stay fast)")
    print("\nHashes (no plaintext here):")
    for sample in payload["samples"]:
        print(f"  [{sample['index']}] md5    = {sample['md5']}")
        print(f"      sha256 = {sample['sha256']}")
        print(f"      ntlm   = {sample['ntlm']}")
        print(f"      bcrypt = {sample['bcrypt']}")
    print("\n" + "=" * 72)
    print("FOR THIS LOCAL LAB ONLY - plaintext lab strings, never real")
    print("credentials, never reuse them, never commit this block.")
    print("=" * 72)
    for sample in payload["samples"]:
        print(f"  [{sample['index']}] password = {sample['password']}")
    print("=" * 72)
    print("END FOR THIS LOCAL LAB ONLY")


def _print_benchmark(payload: dict) -> None:
    print("\nBenchmark - guesses/sec measured on THIS machine, single thread")
    print(f"{'algorithm':24} {'parameter':44} {'guesses/s':>12}")
    print("-" * 84)
    for row in payload["results"]:
        print(f"{row['algorithm']:24} {row['parameter']:44} "
              f"{row['guesses_per_second']:>12,}")
    s = payload["summary"]
    print("-" * 84)
    print(f"MD5 is {s['md5_vs_bcrypt12_factor']:,}x faster than bcrypt cost 12 "
          f"on this machine")
    print(f"bcrypt cost 4 -> cost 12 is 2^8 = {s['cost4_to_cost12_theoretical_factor']}x "
          f"more work by definition; measured {s['cost4_to_cost12_measured_factor']}x")
    print(f"sha512crypt rounds={CRYPT_ROUNDS_DEFAULT}: {s['sha512crypt_per_second']:,} guesses/s")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="hash_crack.py",
        description=("Offline password cracking against hashes supplied by "
                     "the operator or generated by this script for the lab. "
                     "Substitute for Hydra/John the Ripper, which are not "
                     "installed here. Only hashes you own or generated "
                     "yourself may be attacked."),
        epilog=("Scope: local hashes only. Attacking a hash or a service you "
                "are not authorised to test is unauthorised access."),
    )
    parser.add_argument("--hash", action="append", default=[], metavar="VALUE",
                        help="hash to crack (repeatable)")
    parser.add_argument("--wordlist", metavar="FILE",
                        help="wordlist file; default is the built-in list "
                             f"({len(DEFAULT_WORDLIST)} entries)")
    parser.add_argument("--gen-samples", action="store_true",
                        help="generate lab samples (MD5, SHA-256, NTLM, "
                             "bcrypt cost 4) and print them")
    parser.add_argument("--samples", type=int, default=5, metavar="N",
                        help="number of samples for --gen-samples (default 5)")
    parser.add_argument("--out", metavar="DIR",
                        help="output directory for --gen-samples "
                             "(default: a temp directory)")
    parser.add_argument("--benchmark", action="store_true",
                        help="measure and report guesses/sec per algorithm")
    parser.add_argument("--format", default="auto",
                        choices=("auto", "md5", "sha1", "sha256", "sha512",
                                 "ntlm", "bcrypt", "sha512crypt"),
                        help="force the hash format; auto detects from the "
                             "prefix/length (default: auto)")
    parser.add_argument("--json", action="store_true",
                        help="emit machine-readable results")
    args = parser.parse_args(argv)

    if not (args.hash or args.gen_samples or args.benchmark):
        parser.print_help()
        return 0

    payload: dict = {
        "script": "hash_crack.py",
        "md4_backend": MD4_BACKEND,
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scope": ("hashes generated for this lab or supplied by the operator; "
                  "no third-party hash and no service was attacked"),
    }

    if args.gen_samples:
        payload["samples"] = generate_samples(args.samples, args.out)

    if args.hash:
        forced = None if args.format == "auto" else args.format
        source = "auto" if forced is None else "forced"
        payload["cracks"] = [crack_hash(value, forced, args.wordlist, source)
                             for value in args.hash]

    if args.benchmark:
        payload["benchmark"] = benchmark()

    if args.json:
        print(json.dumps(payload, indent=2, default=str))
        return 0

    print(f"hash_crack.py - MD4 backend: {MD4_BACKEND}")
    if "samples" in payload:
        _print_samples(payload["samples"])
    for item in payload.get("cracks", []):
        print(f"\n[{item['format']}] {item['hash']}")
        print(f"  detection : {item['format_note']}")
        if item["status"] == "cracked":
            print(f"  cracked   : {item['password']!r} after "
                  f"{item['attempts']} guesses in {item['seconds']}s")
        elif item["status"] == "unsupported_format":
            print(f"  unsupported: {item['detail']}")
        elif item["status"] == "invalid_target":
            print(f"  invalid target: {item['detail']}")
        elif item["status"] == "error":
            print(f"  error     : {item['detail']}")
        else:
            print(f"  not found : {item['attempts']} guesses from "
                  f"{item['wordlist']} in {item['seconds']}s")
    if "benchmark" in payload:
        _print_benchmark(payload["benchmark"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
