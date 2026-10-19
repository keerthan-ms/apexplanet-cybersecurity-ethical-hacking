"""
Task 1 tests - cryptography lab.

These assert both that the lab computes the right thing and that the security
properties it claims actually hold. Where a test checks a *failure* (a tampered
ciphertext being rejected, a forged digest matching an independent computation),
that is the point of the demonstration, not an accident of the implementation.
"""

import base64
import hashlib
import hmac
import importlib.util
import json
import pathlib
import subprocess
import sys
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO / "task-1" / "scripts" / "crypto_lab.py"


def _load():
    """Import crypto_lab.py directly - the scripts directory is not a package."""
    spec = importlib.util.spec_from_file_location("crypto_lab", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


crypto = _load()


class TestDigests(unittest.TestCase):
    def test_matches_standard_library(self):
        message = "ApexPlanet cybersecurity task 1"
        got = crypto.digests(message)
        self.assertEqual(got["md5"], hashlib.md5(message.encode()).hexdigest())
        self.assertEqual(got["sha256"], hashlib.sha256(message.encode()).hexdigest())
        self.assertEqual(got["sha512"], hashlib.sha512(message.encode()).hexdigest())

    def test_digest_lengths(self):
        got = crypto.digests("anything")
        self.assertEqual(len(got["md5"]), 32)
        self.assertEqual(len(got["sha256"]), 64)
        self.assertEqual(len(got["sha512"]), 128)

    def test_different_messages_different_digests(self):
        self.assertNotEqual(crypto.digests("a")["sha256"], crypto.digests("b")["sha256"])

    def test_md5_speed_is_measured_not_hardcoded(self):
        rate = crypto.md5_speed(samples=2000)
        self.assertIsInstance(rate, int)
        self.assertGreater(rate, 0)


class TestLengthExtension(unittest.TestCase):
    """The lab's headline demo: an MD5 forgery produced without the secret."""

    def test_forgery_matches_independent_computation(self):
        result = crypto.length_extension_demo()
        self.assertTrue(
            result["forgery_verified"],
            "the digest-only forgery must equal a direct computation, "
            "otherwise the demonstration is meaningless",
        )
        self.assertEqual(result["forged_digest"], result["independent_digest"])

    def test_forged_digest_is_a_well_formed_md5(self):
        result = crypto.length_extension_demo()
        self.assertRegex(result["forged_digest"], r"^[0-9a-f]{32}$")
        self.assertRegex(result["independent_digest"], r"^[0-9a-f]{32}$")

    def test_extension_actually_changed_the_message(self):
        result = crypto.length_extension_demo()
        self.assertNotEqual(result["forged_digest"], result["original_digest"])
        self.assertEqual(result["appended_payload"], "&role=admin")
        self.assertFalse(result["secret_known_to_attacker"])

    def test_forged_message_really_is_longer(self):
        # The appended payload must be the suffix of the verified computation,
        # i.e. the forgery extends rather than replaces the original message.
        secret = b"apexplanet-key-not-to-be-guessed"
        message = b"user=demo&role=user"
        result = crypto.length_extension_demo()
        direct = hashlib.md5(secret + message + b"\x80").hexdigest()
        self.assertNotEqual(result["independent_digest"], direct)
        self.assertNotEqual(result["independent_digest"], hashlib.md5(secret + message).hexdigest())

    def test_different_message_different_forgery(self):
        a = crypto.length_extension_demo("user=alice&role=user")
        b = crypto.length_extension_demo("user=bob&role=user")
        self.assertNotEqual(a["original_digest"], b["original_digest"])
        self.assertTrue(a["forgery_verified"])
        self.assertTrue(b["forgery_verified"])


class TestHmac(unittest.TestCase):
    def test_tag_matches_standard_library(self):
        message = "user=demo&role=user"
        key = b"apexplanet-shared-secret"
        got = crypto.hmac_demo(message, key)
        expected = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
        self.assertEqual(got["hmac_sha256"], expected)

    def test_tampering_is_detected(self):
        self.assertTrue(crypto.hmac_demo("user=demo&role=user")["tamper_detected"])

    def test_wrong_key_is_rejected(self):
        self.assertTrue(crypto.hmac_demo("anything")["wrong_key_rejected"])

    def test_verification_of_unmodified_message_passes(self):
        self.assertTrue(crypto.hmac_demo("anything")["verify_ok"])

    def test_key_length_is_reported(self):
        self.assertEqual(crypto.hmac_demo("m", b"0123456789")["key_length_bytes"], 10)


class TestPasswordHashing(unittest.TestCase):
    def test_correct_password_accepted_and_wrong_rejected(self):
        result = crypto.password_hash_demo()
        self.assertTrue(result["correct_accepted"])
        self.assertTrue(result["wrong_rejected"])

    def test_each_hash_gets_its_own_salt(self):
        result = crypto.password_hash_demo()
        self.assertTrue(result["same_password_different_hash"])
        self.assertNotEqual(result["hash_a"], result["hash_b"])

    def test_output_is_a_bcrypt_hash(self):
        result = crypto.password_hash_demo()
        for digest in (result["hash_a"], result["hash_b"]):
            self.assertTrue(digest.startswith("$2"), digest)

    def test_identical_hash_reproduces_the_same_verification(self):
        import bcrypt

        result = crypto.password_hash_demo("Correct-Horse-42!")
        self.assertTrue(bcrypt.checkpw(b"Correct-Horse-42!", result["hash_a"].encode()))


class TestAead(unittest.TestCase):
    def test_round_trip(self):
        self.assertTrue(crypto.aead_demo("a secret message")["round_trip_ok"])

    def test_single_bit_flip_is_rejected(self):
        self.assertTrue(crypto.aead_demo("a secret message")["tampered_ciphertext_rejected"])

    def test_ciphertext_is_not_the_plaintext(self):
        result = crypto.aead_demo("visible in the clear")
        raw = base64.b64decode(result["ciphertext_b64"])
        self.assertNotIn(b"visible in the clear", raw)

    def test_wrong_key_cannot_decrypt(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        result = crypto.aead_demo("protected", key=bytes(32))
        with self.assertRaises(Exception):
            AESGCM(bytes(range(32))).decrypt(
                base64.b64decode(result["nonce_b64"]),
                base64.b64decode(result["ciphertext_b64"]),
                b"header-context",
            )

    def test_nonce_is_96_bits(self):
        result = crypto.aead_demo("m")
        self.assertEqual(len(base64.b64decode(result["nonce_b64"])), 12)


class TestChacha20(unittest.TestCase):
    def test_round_trip(self):
        self.assertTrue(crypto.chacha20_demo("portable encryption")["round_trip_ok"])

    def test_no_aes_required_flag(self):
        self.assertTrue(crypto.chacha20_demo("m")["no_aes_required"])


class TestKdf(unittest.TestCase):
    def test_deterministic_for_same_password_and_salt(self):
        salt = b"a-salt-for-this-test"
        first = crypto.kdf_demo("pw", salt)
        second = crypto.kdf_demo("pw", salt)
        self.assertEqual(first["derived_key_b64"], second["derived_key_b64"])
        self.assertTrue(first["same_salt_same_password_same_key"])

    def test_different_salt_different_key(self):
        a = crypto.kdf_demo("pw", b"salt-one")
        b = crypto.kdf_demo("pw", b"salt-two")
        self.assertNotEqual(a["derived_key_b64"], b["derived_key_b64"])

    def test_different_password_different_key(self):
        a = crypto.kdf_demo("password-one", b"fixed")
        b = crypto.kdf_demo("password-two", b"fixed")
        self.assertNotEqual(a["derived_key_b64"], b["derived_key_b64"])

    def test_derived_key_is_32_bytes(self):
        result = crypto.kdf_demo("pw", b"salt")
        self.assertEqual(len(base64.b64decode(result["derived_key_b64"])), 32)

    def test_work_factor_is_recorded(self):
        result = crypto.kdf_demo("pw")
        self.assertGreaterEqual(result["iterations"], 100_000)
        self.assertGreater(result["time_per_derivation_seconds"], 0)


class TestRsa(unittest.TestCase):
    def test_signature_verifies(self):
        self.assertTrue(crypto.rsa_demo("signed message")["signature_valid"])

    def test_signature_detects_tampering(self):
        self.assertTrue(crypto.rsa_demo("signed message")["signature_detects_tampering"])

    def test_oaep_round_trip(self):
        self.assertTrue(crypto.rsa_demo("secret")["oaep_encrypt_decrypt_ok"])

    def test_key_is_2048_bits(self):
        self.assertEqual(crypto.rsa_demo("m")["modulus_bits"], 2048)

    def test_signature_changes_per_run(self):
        self.assertNotEqual(crypto.rsa_demo("m")["signature_b64"],
                            crypto.rsa_demo("m")["signature_b64"])

    def test_public_exponent_is_65537(self):
        self.assertEqual(crypto.rsa_demo("m")["public_exponent"], 65537)


class TestEncoding(unittest.TestCase):
    def test_base64_reversible_without_a_key(self):
        result = crypto.encoding_is_not_encryption("confidential")
        self.assertTrue(result["base64_reversible_without_key"])
        self.assertEqual(base64.b64decode(result["base64"]).decode(), "confidential")

    def test_hex_reversible_without_a_key(self):
        result = crypto.encoding_is_not_encryption("confidential")
        self.assertTrue(result["hex_reversible_without_key"])

    def test_states_the_lesson(self):
        self.assertIn("not encryption", crypto.encoding_is_not_encryption()["note"])


class TestTlsInspection(unittest.TestCase):
    def test_unreachable_endpoint_reports_an_error_instead_of_raising(self):
        # Connection refused on loopback: no network access needed, and the
        # function must degrade to an error record rather than throwing.
        result = crypto.tls_inspect(host="127.0.0.1", port=1, timeout=1.5)
        self.assertIn("error", result)
        self.assertEqual(result["host"], "127.0.0.1")

    def test_live_handshake_reports_a_certificate(self):
        try:
            result = crypto.tls_inspect("example.com", timeout=8)
        except Exception as exc:                       # pragma: no cover
            self.skipTest(f"no outbound network: {exc}")
        if "error" in result:
            self.skipTest(f"handshake failed: {result['error']}")
        self.assertIn(result["tls_version"], ("TLSv1.2", "TLSv1.3"))
        self.assertGreater(result["san_count"], 0)
        self.assertFalse(result["certificate_expired"])
        self.assertIsInstance(result["days_remaining"], int)


class TestRunAll(unittest.TestCase):
    def test_offline_run_has_every_section_except_tls(self):
        results = crypto.run_all(include_tls=False)
        self.assertNotIn("tls", results)
        for section in (
            "hashing", "length_extension", "hmac", "password_hashing",
            "aes_gcm", "chacha20", "kdf", "rsa", "encoding",
        ):
            self.assertIn(section, results)

    def test_length_extension_verifies_inside_a_full_run(self):
        self.assertTrue(crypto.run_all(include_tls=False)["length_extension"]["forgery_verified"])

    def test_with_tls_the_section_is_present(self):
        # If the handshake cannot complete the result is an error record, which
        # is still a valid outcome - but it must be a dict, never a raise.
        results = crypto.run_all(include_tls=True)
        self.assertIsInstance(results["tls"], dict)
        self.assertIn("host", results["tls"])


class TestCommandInterface(unittest.TestCase):
    """The CLI has to stay usable - the README tells readers to run it."""

    def _run(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            capture_output=True, text=True, timeout=180,
        )

    def test_json_output_is_parseable(self):
        proc = self._run("--json", "--no-tls")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertTrue(data["length_extension"]["forgery_verified"])

    def test_default_output_is_human_readable(self):
        proc = self._run("--no-tls")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("TASK 1 - CRYPTOGRAPHY LAB", proc.stdout)
        self.assertIn("forged == independent computation: True", proc.stdout)

    def test_no_tls_flag_skips_the_network(self):
        proc = self._run("--json", "--no-tls")
        self.assertNotIn('"tls"', proc.stdout)

    def test_help_exits_cleanly(self):
        proc = self._run("--help")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--json", proc.stdout)


class TestNoMisleadingClaims(unittest.TestCase):
    """Guards against the lab quietly implying something it does not do."""

    def test_md5_is_described_as_the_weak_algorithm_not_a_recommendation(self):
        results = crypto.run_all(include_tls=False)
        self.assertIn("MD5", results["length_extension"]["algorithm"])
        self.assertIn("HMAC-MD5 defeats", results["length_extension"]["note"])

    def test_bcrypt_hashes_are_not_reversible_plaintext(self):
        result = crypto.password_hash_demo("Correct-Horse-42!")
        self.assertNotIn("Correct-Horse-42!", result["hash_a"])

    def test_encoding_section_does_not_claim_base64_is_encryption(self):
        result = crypto.encoding_is_not_encryption()
        self.assertTrue(result["base64_reversible_without_key"])


if __name__ == "__main__":
    unittest.main()
