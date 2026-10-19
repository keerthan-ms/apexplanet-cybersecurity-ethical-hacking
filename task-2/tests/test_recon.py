"""Tests for task-2/scripts/recon.py wire-format helpers (no network)."""

import socket
import struct
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import recon  # noqa: E402


class DnsNameEncodingTests(unittest.TestCase):
    def test_encode_labels(self):
        self.assertEqual(recon.encode_dns_name("example.com"),
                         b"\x07example\x03com\x00")

    def test_encode_rejects_empty(self):
        with self.assertRaises(ValueError):
            recon.encode_dns_name("")

    def test_build_query_header_and_question(self):
        txid, packet = recon.build_dns_query("example.com", recon.QTYPE_MX,
                                             txid=0x1234)
        self.assertEqual(txid, 0x1234)
        header = struct.unpack("!HHHHHH", packet[:12])
        self.assertEqual(header, (0x1234, 0x0100, 1, 0, 0, 0))
        self.assertEqual(packet[12:-4], b"\x07example\x03com\x00")
        qtype, qclass = struct.unpack("!HH", packet[-4:])
        self.assertEqual(qtype, recon.QTYPE_MX)
        self.assertEqual(qclass, 1)


class DnsNameDecodingTests(unittest.TestCase):
    def test_plain_name(self):
        buf = b"\x07example\x03com\x00rest"
        name, offset = recon.read_dns_name(buf, 0)
        self.assertEqual(name, "example.com")
        self.assertEqual(offset, 13)

    def test_compression_pointer(self):
        # buf: [example.com at 0][www + pointer to 0 at 13]
        buf = b"\x07example\x03com\x00" + b"\x03www\xc0\x00"
        name, offset = recon.read_dns_name(buf, 13)
        self.assertEqual(name, "www.example.com")
        self.assertEqual(offset, 19)      # 13 + len(b"\x03www\xc0\x00")

    def test_pointer_loop_rejected(self):
        buf = b"\xc0\x00"           # pointer to itself
        with self.assertRaises(ValueError):
            recon.read_dns_name(buf, 0)

    def test_truncated_name_rejected(self):
        with self.assertRaises(ValueError):
            recon.read_dns_name(b"\x07exam", 0)


class DnsResponseParsingTests(unittest.TestCase):
    def test_parse_mx_answer_with_compression(self):
        header = struct.pack("!HHHHHH", 0xABCD, 0x8180, 1, 1, 0, 0)
        question = recon.encode_dns_name("example.com") + struct.pack(
            "!HH", recon.QTYPE_MX, 1)
        rdata = struct.pack("!H", 10) + b"\xc0\x0c"   # pref 10, ptr to QNAME
        answer = (b"\xc0\x0c"                         # compressed owner name
                  + struct.pack("!HHIH", recon.QTYPE_MX, 1, 60, len(rdata))
                  + rdata)
        parsed = recon.parse_dns_response(header + question + answer)
        self.assertEqual(parsed["txid"], 0xABCD)
        self.assertEqual(parsed["rcode_name"], "NOERROR")
        self.assertFalse(parsed["truncated"])
        self.assertEqual(parsed["questions"][0]["name"], "example.com")
        record = parsed["answers"][0]
        self.assertEqual(record["name"], "example.com")
        self.assertEqual(record["type"], "MX")
        self.assertEqual(record["ttl"], 60)
        self.assertEqual(record["data"], {"preference": 10,
                                          "exchange": "example.com"})

    def test_parse_txt_answer(self):
        header = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0)
        question = recon.encode_dns_name("example.com") + struct.pack(
            "!HH", recon.QTYPE_TXT, 1)
        text = b"v=spf1 -all"
        rdata = bytes([len(text)]) + text
        answer = (b"\xc0\x0c"
                  + struct.pack("!HHIH", recon.QTYPE_TXT, 1, 300, len(rdata))
                  + rdata)
        parsed = recon.parse_dns_response(header + question + answer)
        self.assertEqual(parsed["answers"][0]["data"], "v=spf1 -all")

    def test_parse_nxdomain_rcode(self):
        header = struct.pack("!HHHHHH", 1, 0x8183, 1, 0, 0, 0)
        question = recon.encode_dns_name("nope.example") + struct.pack(
            "!HH", recon.QTYPE_A, 1)
        parsed = recon.parse_dns_response(header + question)
        self.assertEqual(parsed["rcode"], 3)
        self.assertEqual(parsed["rcode_name"], "NXDOMAIN")

    def test_truncated_flag_reported(self):
        header = struct.pack("!HHHHHH", 1, 0x8380, 0, 0, 0, 0)
        parsed = recon.parse_dns_response(header)
        self.assertTrue(parsed["truncated"])

    def test_short_response_rejected(self):
        with self.assertRaises(ValueError):
            recon.parse_dns_response(b"\x00\x01")


class WhoisReferralTests(unittest.TestCase):
    def test_refer_line(self):
        text = "% IANA WHOIS server\nrefer:        whois.arin.net\n\ninetnum: ...\n"
        self.assertEqual(recon.parse_whois_referral(text),
                         ("whois.arin.net", 43))

    def test_whois_field(self):
        text = "domain: COM\norganisation: ...\nwhois: whois.verisign-grs.com\n"
        self.assertEqual(recon.parse_whois_referral(text),
                         ("whois.verisign-grs.com", 43))

    def test_referral_server_rwhois(self):
        text = "ReferralServer: rwhois://rwhois.example.net:4321\n"
        self.assertEqual(recon.parse_whois_referral(text),
                         ("rwhois.example.net", 4321))

    def test_no_referral(self):
        text = "domain: EXAMPLE.COM\norganisation: IANA\n"
        self.assertIsNone(recon.parse_whois_referral(text))


class HelperTests(unittest.TestCase):
    def test_looks_like_ip(self):
        self.assertTrue(recon._looks_like_ip("127.0.0.1"))
        self.assertTrue(recon._looks_like_ip("2001:db8::1"))
        self.assertFalse(recon._looks_like_ip("example.com"))

    def test_getaddrinfo_addresses_shape(self):
        result = recon.getaddrinfo_addresses("127.0.0.1")
        self.assertIn("addresses", result)
        self.assertIn("127.0.0.1", result["addresses"])


if __name__ == "__main__":
    unittest.main()
