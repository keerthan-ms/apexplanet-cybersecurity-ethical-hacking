#!/usr/bin/env python3
"""
Task 1 - cryptography lab.

The brief's hands-on item is: "Encrypt and Decrypt messages using OpenSSL".
This machine has no OpenSSL binary on PATH, so the equivalent work is done
with Python's hashlib/hmac plus the `cryptography` package, which wraps the
same primitives (AES, ChaCha20, RSA, PBKDF2) OpenSSL exposes.

Everything here is a real computation. Nothing is illustrative.

    python task-1/scripts/crypto_lab.py
    python task-1/scripts/crypto_lab.py --json
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import ssl
import socket
import sys
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ----------------------------------------------------------------- hashing ---

def digests(message: str) -> dict[str, str]:
    """MD5 and SHA-256 of the same message, side by side.

    MD5 is shown deliberately: it is the hashing algorithm the brief names,
    and it is the one to stop using. Comparing the two makes the output-length
    and structure difference concrete.
    """
    raw = message.encode("utf-8")
    return {
        "md5": hashlib.md5(raw).hexdigest(),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "sha512": hashlib.sha512(raw).hexdigest(),
    }


def md5_speed(samples: int = 20000) -> float:
    """Hashes per second for MD5 - the reason it is fast enough to brute force."""
    payload = b"a" * 64
    start = time.perf_counter()
    for _ in range(samples):
        hashlib.md5(payload)
    return round(samples / (time.perf_counter() - start))


def _md5_continue(state_hex: str, stream: bytes, total_bit_length: int) -> str:
    """Resume MD5 from an intermediate 128-bit digest.

    This is the operation a length-extension attack relies on: the digest of
    MD5(secret || message) *is* the chaining state after that input, so an
    attacker who has only the digest can keep hashing.

    `stream` is the data that follows the already-absorbed prefix, and
    `total_bit_length` is the bit length of the complete message (prefix +
    stream) that MD5's final padding block has to declare.
    """
    import struct

    def f(x, y, z): return (x & y) | (~x & z)
    def g(x, y, z): return (x & z) | (y & ~z)
    def h(x, y, z): return x ^ y ^ z
    def i(x, y, z): return y ^ (x | ~z)
    def rotl(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    shifts = (
        [7, 12, 17, 22] * 4 +
        [5, 9, 14, 20] * 4 +
        [4, 11, 16, 23] * 4 +
        [6, 10, 15, 21] * 4
    )
    import math
    table = [int(abs(math.sin(i + 1)) * 2**32) & 0xFFFFFFFF for i in range(64)]

    msg = bytearray(stream)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += int(total_bit_length).to_bytes(8, "little")

    a, b, c, d = struct.unpack("<4I", bytes.fromhex(state_hex))
    for off in range(0, len(msg), 64):
        words = list(struct.unpack("<16I", msg[off:off + 64]))
        A, B, C, D = a, b, c, d
        for n in range(64):
            if n < 16:
                func, k = f(B, C, D), n
            elif n < 32:
                func, k = g(B, C, D), (5 * n + 1) % 16
            elif n < 48:
                func, k = h(B, C, D), (3 * n + 5) % 16
            else:
                func, k = i(B, C, D), (7 * n) % 16
            A, D, C, B = D, C, B, (
                B + rotl((A + func + table[n] + words[k]) & 0xFFFFFFFF, shifts[n])
            ) & 0xFFFFFFFF
        a = (a + A) & 0xFFFFFFFF
        b = (b + B) & 0xFFFFFFFF
        c = (c + C) & 0xFFFFFFFF
        d = (d + D) & 0xFFFFFFFF

    return struct.pack("<4I", a, b, c, d).hex()


def length_extension_demo(message: str = "user=demo&role=user") -> dict:
    """MD5 length extension: forge MD5(secret || m || pad || extra) knowing
    only MD5(secret || m).

    The demonstration is verified rather than asserted: `forged_digest` is
    computed from the digest alone (the attack), `independent_digest` is
    computed with the secret (a check the attacker cannot do). They must match,
    which proves the forgery is a genuine MD5 output and not a plausible
    looking string.
    """
    secret = b"apexplanet-key-not-to-be-guessed"
    message_b = message.encode()

    real = hashlib.md5(secret + message_b).hexdigest()

    # Padding MD5 would apply after (secret || message): length-dependent,
    # reconstructable because the attacker knows len(secret) from disclosure
    # or can brute force it over a small range.
    prefix_len = len(secret) + len(message_b)
    glue_len = (56 - (prefix_len % 64)) % 64
    glue_len = glue_len or 64
    glue = b"\x80" + b"\x00" * (glue_len - 1) + (prefix_len * 8).to_bytes(8, "little")

    extra = b"&role=admin"
    total_bits = (prefix_len + len(glue) + len(extra)) * 8

    # `real` is already the state after absorbing (secret || message || glue),
    # because MD5's digest is taken after its own padding block. So only `extra`
    # is fed to the continuation - feeding the glue again would absorb it twice.
    forged_digest = _md5_continue(real, extra, total_bits)

    # The check: computed honestly with the secret, to prove the forgery.
    independent_digest = hashlib.md5(secret + message_b + glue + extra).hexdigest()

    return {
        "algorithm": "MD5",
        "secret_known_to_attacker": False,
        "original_message": message,
        "original_digest": real,
        "appended_payload": extra.decode(),
        "forged_digest": forged_digest,
        "independent_digest": independent_digest,
        "forgery_verified": forged_digest == independent_digest,
        "note": (
            "forged_digest was produced from the digest alone. It matches a "
            "direct computation, so the extension is real. HMAC-MD5 defeats "
            "this because the key is applied on both sides of the hash."
        ),
    }



# --------------------------------------------------------------------- hmac ---

def hmac_demo(message: str, key: bytes = b"apexplanet-shared-secret") -> dict:
    """HMAC-SHA256 over a message, plus proof that tampering breaks it."""
    tag = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
    tampered = hmac.new(key, (message + " (now role=admin)").encode(), hashlib.sha256).hexdigest()
    wrong_key = hmac.new(b"not-the-key", message.encode(), hashlib.sha256).hexdigest()
    verify = hmac.new(key, message.encode(), hashlib.sha256).digest()

    return {
        "message": message,
        "key_length_bytes": len(key),
        "hmac_sha256": tag,
        "tamper_detected": not hmac.compare_digest(tag, tampered),
        "wrong_key_rejected": not hmac.compare_digest(tag, wrong_key),
        "verify_ok": hmac.compare_digest(verify.hex(), tag),
    }


# -------------------------------------------------------- password hashing ---

def password_hash_demo(password: str = "Correct-Horse-42!") -> dict:
    """bcrypt: salted, deliberately slow, and self-describing in its output."""
    import bcrypt

    hash_a = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    hash_b = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

    return {
        "algorithm": "bcrypt (via $2b$ prefix)",
        "hash_a": hash_a.decode(),
        "hash_b": hash_b.decode(),
        "same_password_different_hash": hash_a != hash_b,   # per-password salt
        "correct_accepted": bcrypt.checkpw(password.encode(), hash_a),
        "wrong_rejected": not bcrypt.checkpw(b"wrong-password", hash_a),
        "salt_embedded": hash_a.decode().split("$")[2][:22],
    }


# ------------------------------------------------------------ symmetric ------


def aead_demo(plaintext: str, key: bytes | None = None) -> dict:
    """AES-256-GCM: confidentiality + integrity in one construction.

    GCM produces an authentication tag, so a modified ciphertext is rejected
    rather than silently decrypted into garbage. That is the difference
    between plain CBC (which malleates) and an AEAD.
    """
    key = key or AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)          # 96-bit nonce, as NIST recommends for GCM
    ct = AESGCM(key).encrypt(nonce, plaintext.encode(), b"header-context")

    # Flip one bit in the ciphertext and try to decrypt it.
    tampered = bytearray(ct)
    tampered[0] ^= 0x01
    rejected = False
    try:
        AESGCM(key).decrypt(nonce, bytes(tampered), b"header-context")
    except Exception:
        rejected = True

    round_trip = AESGCM(key).decrypt(nonce, ct, b"header-context")

    return {
        "cipher": "AES-256-GCM",
        "key_b64": base64.b64encode(key).decode(),
        "nonce_b64": base64.b64encode(nonce).decode(),
        "ciphertext_b64": base64.b64encode(ct).decode(),
        "tag_bytes": 16,
        "round_trip_ok": round_trip.decode() == plaintext,
        "tampered_ciphertext_rejected": rejected,
    }


def chacha20_demo(plaintext: str) -> dict:
    """ChaCha20-Poly1305: the other AEAD, chosen when AES hardware is absent."""
    key = ChaCha20Poly1305.generate_key()
    nonce = bytes(range(12))
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext.encode(), None)
    back = ChaCha20Poly1305(key).decrypt(nonce, ct, None)
    return {
        "cipher": "ChaCha20-Poly1305",
        "key_b64": base64.b64encode(key).decode(),
        "ciphertext_b64": base64.b64encode(ct).decode(),
        "round_trip_ok": back.decode() == plaintext,
        "no_aes_required": True,
    }


def kdf_demo(password: str = "a-low-entropy-password", salt: bytes | None = None) -> dict:
    """PBKDF2-HMAC-SHA256: turns a weak password into a strong key.

    The iteration count is the point: each guess costs the attacker the same
    work as it costs us.
    """
    salt = salt or b"static-salt-for-this-demo"
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000)
    start = time.perf_counter()
    key = kdf.derive(password.encode())
    elapsed = time.perf_counter() - start

    return {
        "algorithm": "PBKDF2-HMAC-SHA256",
        "iterations": 200_000,
        "derived_key_b64": base64.b64encode(key).decode(),
        "time_per_derivation_seconds": round(elapsed, 4),
        "same_salt_same_password_same_key":
            base64.b64encode(
                PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                           iterations=200_000).derive(password.encode())
            ).decode() == base64.b64encode(key).decode(),
    }


# ---------------------------------------------------------- asymmetric ------

def rsa_demo(plaintext: str) -> dict:
    """RSA-2048 keypair: sign and verify, then encrypt and decrypt.

    Signing proves authorship; encrypting protects the message. Different
    paddings, different purposes.
    """
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key()

    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    signature = private.sign(plaintext.encode(), pss, hashes.SHA256())
    try:
        public.verify(signature, plaintext.encode(), pss, hashes.SHA256())
        signature_valid = True
    except Exception:
        signature_valid = False

    try:
        public.verify(signature, (plaintext + "!").encode(), pss, hashes.SHA256())
        tamper_detected = False
    except Exception:
        tamper_detected = True

    cipher = public.encrypt(plaintext.encode(),
                            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                         algorithm=hashes.SHA256(), label=None))
    recovered = private.decrypt(cipher,
                                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                             algorithm=hashes.SHA256(), label=None))

    pub_numbers = public.public_numbers()
    return {
        "algorithm": "RSA-2048",
        "modulus_bits": pub_numbers.n.bit_length(),
        "signature_valid": signature_valid,
        "signature_detects_tampering": tamper_detected,
        "oaep_encrypt_decrypt_ok": recovered.decode() == plaintext,
        "signature_b64": base64.b64encode(signature).decode(),
        "public_exponent": pub_numbers.e,
    }


# ------------------------------------------------------------- TLS check ----

def tls_inspect(host: str = "example.com", port: int = 443, timeout: float = 8.0) -> dict:
    """Connect to a real host and report the certificate and negotiated suite.

    This replaces the brief's "digital certificates and SSL/TLS" theory with an
    observation of an actual handshake. It is a single connection, GET/HEAD
    only, to a host that expects it.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                cipher = tls.cipher()
                version = tls.version()
    except Exception as exc:                                    # pragma: no cover
        return {"host": host, "error": f"{type(exc).__name__}: {exc}"}

    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    not_before = ssl.cert_time_to_seconds(cert["notBefore"])
    not_after = ssl.cert_time_to_seconds(cert["notAfter"])
    now = time.time()

    sans = [v for typ, v in cert.get("subjectAltName", ()) if typ == "DNS"]

    return {
        "host": host,
        "tls_version": version,
        "cipher": cipher[0],
        "cipher_bits": cipher[2],
        "protocol": cert.get("version"),
        "subject_common_name": subject.get("commonName"),
        "issuer_common_name": issuer.get("organizationName") or issuer.get("commonName"),
        "valid_from": time.strftime("%Y-%m-%d", time.localtime(not_before)),
        "valid_until": time.strftime("%Y-%m-%d", time.localtime(not_after)),
        "days_remaining": int((not_after - now) / 86400),
        "certificate_expired": now > not_after,
        "subject_alt_names": sans[:6],
        "san_count": len(sans),
    }


# ---------------------------------------------------------------- encoding ---

def encoding_is_not_encryption(message: str = "confidential") -> dict:
    """Base64 and hex are encodings: anyone can reverse them without a key."""
    b64 = base64.b64encode(message.encode()).decode()
    hexed = message.encode().hex()
    return {
        "original": message,
        "base64": b64,
        "hex": hexed,
        "base64_reversible_without_key": base64.b64decode(b64).decode() == message,
        "hex_reversible_without_key": bytes.fromhex(hexed).decode() == message,
        "note": "Encoding is not encryption. Only a key makes it unreadable.",
    }


# -------------------------------------------------------------------- main ---

def run_all(include_tls: bool = True) -> dict:
    results = {
        "hashing": digests("ApexPlanet cybersecurity task 1"),
        "md5_hashes_per_second": md5_speed(),
        "length_extension": length_extension_demo(),
        "hmac": hmac_demo("user=demo&role=user"),
        "password_hashing": password_hash_demo(),
        "aes_gcm": aead_demo("Attack against the local lab must be reported."),
        "chacha20": chacha20_demo("Same guarantee, different construction."),
        "kdf": kdf_demo(),
        "rsa": rsa_demo("signed and encrypted by the local lab"),
        "encoding": encoding_is_not_encryption(),
    }
    if include_tls:
        results["tls"] = tls_inspect()
    return results


def _print_report(results: dict) -> None:
    print("=" * 68)
    print("TASK 1 - CRYPTOGRAPHY LAB (real computation, no placeholders)")
    print("=" * 68)

    h = results["hashing"]
    print("\n[1] Hashing")
    print(f"    MD5    : {h['md5']}")
    print(f"    SHA256 : {h['sha256']}")
    print(f"    SHA512 : {h['sha512']}")
    print(f"    MD5 speed: ~{results['md5_hashes_per_second']:,} hashes/sec "
          "- fast enough to brute force")

    le = results["length_extension"]
    print("\n[2] MD5 length extension (why MD5 is not an authenticator)")
    print(f"    original digest : {le['original_digest']}")
    print(f"    forged digest   : {le['forged_digest']}")
    print(f"    payload appended: {le['appended_payload']!r}")
    print(f"    forged == independent computation: {le['forgery_verified']}")
    print(f"    {le['note']}")

    hm = results["hmac"]
    print("\n[3] HMAC-SHA256")
    print(f"    tag              : {hm['hmac_sha256']}")
    print(f"    tamper detected  : {hm['tamper_detected']}")
    print(f"    wrong key rejected: {hm['wrong_key_rejected']}")

    pw = results["password_hashing"]
    print("\n[4] Password hashing (bcrypt)")
    print(f"    hash A : {pw['hash_a']}")
    print(f"    hash B : {pw['hash_b']}")
    print(f"    per-password salt: {pw['same_password_different_hash']}")
    print(f"    correct accepted  : {pw['correct_accepted']}, "
          f"wrong rejected: {pw['wrong_rejected']}")

    a = results["aes_gcm"]
    print("\n[5] AES-256-GCM")
    print(f"    ciphertext : {a['ciphertext_b64']}")
    print(f"    round trip : {a['round_trip_ok']}")
    print(f"    tampering rejected: {a['tampered_ciphertext_rejected']}")

    c = results["chacha20"]
    print("\n[6] ChaCha20-Poly1305")
    print(f"    round trip : {c['round_trip_ok']}")

    k = results["kdf"]
    print("\n[7] PBKDF2-HMAC-SHA256 key derivation")
    print(f"    iterations : {k['iterations']:,} "
          f"({k['time_per_derivation_seconds']}s per derivation)")

    r = results["rsa"]
    print("\n[8] RSA-2048")
    print(f"    modulus bits        : {r['modulus_bits']}")
    print(f"    signature valid     : {r['signature_valid']}")
    print(f"    tamper detected     : {r['signature_detects_tampering']}")
    print(f"    OAEP round trip     : {r['oaep_encrypt_decrypt_ok']}")

    e = results["encoding"]
    print("\n[9] Encoding is not encryption")
    print(f"    {e['original']} -> {e['base64']} -> "
          f"{base64.b64decode(e['base64']).decode()}  (no key needed)")

    if "tls" in results:
        t = results["tls"]
        print("\n[10] TLS certificate inspection (live handshake)")
        if "error" in t:
            print(f"    {t['error']}")
        else:
            print(f"    {t['host']} -> {t['tls_version']} / {t['cipher']} "
                  f"({t['cipher_bits']} bit)")
            print(f"    subject CN : {t['subject_common_name']}")
            print(f"    issuer     : {t['issuer_common_name']}")
            print(f"    valid until: {t['valid_until']} "
                  f"({t['days_remaining']} days, expired: {t['certificate_expired']})")
            print(f"    SANs       : {t['san_count']} ({', '.join(t['subject_alt_names'])})")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(description="Task 1 cryptography lab")
    parser.add_argument("--json", action="store_true", help="emit machine-readable results")
    parser.add_argument("--no-tls", action="store_true", help="skip the live TLS handshake")
    args = parser.parse_args()

    results = run_all(include_tls=not args.no_tls)

    if args.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        _print_report(results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
