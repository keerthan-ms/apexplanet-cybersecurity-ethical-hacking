#!/usr/bin/env python3
"""
Task 2 - passive and light-active reconnaissance.

What this does (and only this):
    - DNS: A/AAAA via socket.getaddrinfo, aliases via gethostbyname_ex, and
      MX / TXT / NS / CNAME via a hand-written DNS client (wire format built
      and parsed in this file - no third-party library) over UDP/53 against
      this machine's configured resolver, with a TCP/53 retry when a
      response is truncated (TC bit).
    - WHOIS: raw TCP to port 43 on whois.iana.org, then the referral chase
      (IANA points at the registry server for the TLD or IP range).
    - HTTP: a single HEAD request per target, capturing status and the
      interesting headers. No crawling, no POSTs, no rate beyond one request.

Scope: look up hosts you are authorised to look up (this machine, its own
domains, public hosts that expect these standard queries). Do not use this
against systems you have no permission to touch.

Usage:
    python task-2/scripts/recon.py --domain example.com
    python task-2/scripts/recon.py --domain example.com --domain apexplanet.in --whois
    python task-2/scripts/recon.py --ip 127.0.0.1 --json
    python task-2/scripts/recon.py --domain example.com --dns --whois
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

USER_AGENT = "ApexPlanet-Recon/1.0 (internship lab; single low-rate lookups)"
DNS_PORT = 53
WHOIS_PORT = 43
WHOIS_SERVER = "whois.iana.org"
WHOIS_MAX_HOPS = 3
WHOIS_STORE_LIMIT = 8192

QTYPE_A, QTYPE_NS, QTYPE_CNAME, QTYPE_SOA = 1, 2, 5, 6
QTYPE_MX, QTYPE_TXT, QTYPE_AAAA = 15, 16, 28
QTYPE_NAMES = {QTYPE_A: "A", QTYPE_NS: "NS", QTYPE_CNAME: "CNAME",
               QTYPE_SOA: "SOA", QTYPE_MX: "MX", QTYPE_TXT: "TXT",
               QTYPE_AAAA: "AAAA"}
RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
               4: "NOTIMP", 5: "REFUSED"}

INTERESTING_HEADERS = (
    "server", "x-powered-by", "content-type", "content-length", "location",
    "strict-transport-security", "content-security-policy",
    "x-content-type-options", "x-frame-options", "referrer-policy",
    "permissions-policy", "cross-origin-opener-policy",
    "cross-origin-resource-policy",
)

AUTHORISATION_BANNER = """\
==============================================================================
TASK 2 - RECONNAISSANCE (passive DNS/WHOIS plus one HEAD per target)
==============================================================================
This tool only performs lookups the targets themselves publish: DNS queries,
WHOIS queries over TCP/43, and at most a single HEAD request per host.
Run it only against hosts you are authorised to look up. Reconnaissance
against someone else's systems without permission is unlawful, even when
the individual requests look harmless.
=============================================================================="""


# ----------------------------------------------------------------- DNS wire ---

def encode_dns_name(name: str) -> bytes:
    """Encode a domain name in DNS wire format (length-prefixed labels)."""
    out = b""
    labels = [label for label in name.rstrip(".").split(".") if label]
    if not labels:
        raise ValueError(f"empty domain name: {name!r}")
    for label in labels:
        raw = label.encode("idna")
        if len(raw) > 63:
            raise ValueError(f"label too long: {label!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_dns_query(name: str, qtype: int, txid: int | None = None
                    ) -> tuple[int, bytes]:
    """Build a standard recursive query. Returns (txid, packet).

    EDNS0 is deliberately not used: the packet must fit the classic 512-byte
    UDP response limit, and truncation is handled by retrying over TCP.
    """
    if txid is None:
        txid = int.from_bytes(os.urandom(2), "big")
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = encode_dns_name(name) + struct.pack("!HH", qtype, 1)
    return txid, header + question


def read_dns_name(buf: bytes, offset: int,
                  visited: set[int] | None = None) -> tuple[str, int]:
    """Read a (possibly compressed) name; returns (name, offset after name).

    Compression pointers (top two bits 11) are followed in full, with a
    visited-offset set that rejects pointer loops. Out-of-bounds offsets
    raise ValueError instead of returning garbage.
    """
    visited = visited if visited is not None else set()
    labels: list[str] = []
    next_offset = offset
    jumped = False
    while True:
        if offset in visited:
            raise ValueError("DNS compression pointer loop")
        visited.add(offset)
        if offset >= len(buf):
            raise ValueError("truncated DNS name")
        length = buf[offset]
        if length == 0:
            offset += 1
            if not jumped:
                next_offset = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(buf):
                raise ValueError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | buf[offset + 1]
            if not jumped:
                next_offset = offset + 2
            jumped = True
            offset = pointer
            continue
        if length & 0xC0:
            raise ValueError(f"unsupported DNS label type 0x{length:02x}")
        offset += 1
        if offset + length > len(buf):
            raise ValueError("truncated DNS label")
        labels.append(buf[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), next_offset


def _decode_rdata(rtype: int, buf: bytes, rdata_offset: int,
                  rdlength: int) -> object:
    """Decode one RDATA field. Names inside RDATA may also use compression."""
    end = rdata_offset + rdlength
    if end > len(buf):
        raise ValueError("truncated rdata")
    if rtype == QTYPE_A and rdlength == 4:
        return socket.inet_ntoa(buf[rdata_offset:end])
    if rtype == QTYPE_AAAA and rdlength == 16:
        return socket.inet_ntop(socket.AF_INET6, buf[rdata_offset:end])
    if rtype in (QTYPE_NS, QTYPE_CNAME):
        name, _ = read_dns_name(buf, rdata_offset)
        return name
    if rtype == QTYPE_MX and rdlength > 2:
        preference = struct.unpack("!H", buf[rdata_offset:rdata_offset + 2])[0]
        exchange, _ = read_dns_name(buf, rdata_offset + 2)
        # RFC 7505 null MX is the root name, which decodes as ''; present it
        # in zone-file form ('.').
        return {"preference": preference, "exchange": exchange or "."}
    if rtype == QTYPE_TXT:
        strings, pos = [], rdata_offset
        while pos < end:
            length = buf[pos]
            pos += 1
            strings.append(buf[pos:pos + length].decode("utf-8", "replace"))
            pos += length
        return " ".join(strings)
    if rtype == QTYPE_SOA:
        mname, pos = read_dns_name(buf, rdata_offset)
        rname, pos = read_dns_name(buf, pos)
        serial, refresh, retry, expire, minimum = struct.unpack(
            "!5I", buf[pos:pos + 20])
        return {"mname": mname, "rname": rname, "serial": serial,
                "refresh": refresh, "retry": retry, "expire": expire,
                "minimum": minimum}
    return buf[rdata_offset:end].hex()


def parse_dns_response(buf: bytes) -> dict:
    """Parse a DNS response message into a plain dict (questions/RRs)."""
    if len(buf) < 12:
        raise ValueError("DNS response shorter than header")
    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        "!HHHHHH", buf[:12])
    rcode = flags & 0x000F
    parsed: dict = {
        "txid": txid,
        "rcode": rcode,
        "rcode_name": RCODE_NAMES.get(rcode, str(rcode)),
        "truncated": bool(flags & 0x0200),
        "recursion_available": bool(flags & 0x0080),
        "questions": [],
        "answers": [],
        "authorities": [],
        "additionals": [],
    }
    offset = 12
    for _ in range(qdcount):
        qname, offset = read_dns_name(buf, offset)
        qtype, qclass = struct.unpack("!HH", buf[offset:offset + 4])
        offset += 4
        parsed["questions"].append(
            {"name": qname, "type": QTYPE_NAMES.get(qtype, qtype), "class": qclass})

    def read_records(count: int) -> tuple[list, int]:
        records, pos = [], offset
        for _ in range(count):
            name, pos = read_dns_name(buf, pos)
            rtype, rclass, ttl, rdlength = struct.unpack(
                "!HHIH", buf[pos:pos + 10])
            pos += 10
            data = _decode_rdata(rtype, buf, pos, rdlength)
            pos += rdlength
            records.append({"name": name,
                            "type": QTYPE_NAMES.get(rtype, rtype),
                            "ttl": ttl, "data": data})
        return records, pos

    parsed["answers"], offset = read_records(ancount)
    parsed["authorities"], offset = read_records(nscount)
    parsed["additionals"], _ = read_records(arcount)
    return parsed


def resolve_raw_resolver() -> tuple[str | None, str]:
    """Find this machine's DNS resolver for the raw UDP queries.

    Windows keeps it in the registry (Tcpip\\Parameters) and in ipconfig
    output; both are tried, in that order. Returns (server, description) -
    (None, reason) if neither yields an address.
    """
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")
        for value_name, source in (("NameServer", "static registry NameServer"),
                                   ("DhcpNameServer", "registry DhcpNameServer")):
            try:
                raw, _ = winreg.QueryValueEx(key, value_name)
            except OSError:
                continue
            candidates = [part for part in str(raw).replace(",", " ").split()
                          if part.strip()]
            for candidate in candidates:
                try:
                    ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                return candidate, f"{candidate} ({source})"
        winreg.CloseKey(key)
    except (ImportError, OSError):
        pass

    try:
        proc = subprocess.run(["ipconfig", "/all"], capture_output=True,
                              text=True, timeout=15)
        for line in proc.stdout.splitlines():
            if "DNS Servers" in line and ":" in line:
                value = line.split(":", 1)[1].strip().split()[0]
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    continue
                return value, f"{value} (ipconfig /all)"
    except (OSError, subprocess.SubprocessError):
        pass

    return None, ("no resolver found in the registry or ipconfig output; "
                  "raw DNS queries skipped (getaddrinfo still works)")


def dns_query_over_wire(name: str, qtype: int, server: str,
                        timeout: float = 5.0) -> dict:
    """One DNS query with the hand-written wire format. UDP, TCP on TC=1."""
    txid, packet = build_dns_query(name, qtype)
    start = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    transport = "udp/53"
    try:
        sock.sendto(packet, (server, DNS_PORT))
        data, _ = sock.recvfrom(4096)
    except OSError as exc:
        return {"name": name, "type": QTYPE_NAMES.get(qtype, qtype),
                "error": f"{type(exc).__name__}: {exc}"}
    finally:
        sock.close()

    try:
        parsed = parse_dns_response(data)
    except ValueError as exc:
        return {"name": name, "type": QTYPE_NAMES.get(qtype, qtype),
                "error": f"unparseable response: {exc}"}
    if parsed["txid"] != txid:
        return {"name": name, "type": QTYPE_NAMES.get(qtype, qtype),
                "error": "response txid mismatch; discarded"}

    if parsed["truncated"]:
        # TC bit set: retry the same query over TCP, where the length prefix
        # removes the 512-byte limit. This is plain RFC 1035 behaviour.
        transport = "tcp/53 (truncated UDP response)"
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.settimeout(timeout)
        try:
            tcp_sock.connect((server, DNS_PORT))
            tcp_sock.sendall(len(packet).to_bytes(2, "big") + packet)
            header = tcp_sock.recv(2)
            if len(header) == 2:
                length = int.from_bytes(header, "big")
                chunks = b""
                while len(chunks) < length:
                    piece = tcp_sock.recv(length - len(chunks))
                    if not piece:
                        break
                    chunks += piece
                parsed = parse_dns_response(chunks)
        except OSError as exc:
            parsed["tcp_retry_error"] = f"{type(exc).__name__}: {exc}"
        finally:
            tcp_sock.close()

    parsed.update({"name": name, "type": QTYPE_NAMES.get(qtype, qtype),
                   "server": server, "transport": transport,
                   "elapsed_ms": round((time.perf_counter() - start) * 1000, 1)})
    return parsed


def getaddrinfo_addresses(host: str) -> dict:
    """A/AAAA as the OS resolver returns them (the only records getaddrinfo gives)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    addresses = sorted({info[4][0] for info in infos})
    return {"addresses": addresses, "source": "socket.getaddrinfo"}


def gethost_aliases(host: str) -> dict:
    """Canonical name and alias list (the closest getaddrinfo-era CNAME view)."""
    try:
        canonical, aliases, _ = socket.gethostbyname_ex(host)
    except socket.gaierror as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    return {"canonical_name": canonical, "aliases": aliases,
            "source": "socket.gethostbyname_ex"}


def collect_dns(host: str, resolver: str | None,
                resolver_note: str) -> dict:
    out: dict = {"host": host,
                 "resolver_for_raw_queries": resolver,
                 "resolver_note": resolver_note,
                 "a_aaaa": getaddrinfo_addresses(host),
                 "aliases": gethost_aliases(host)}
    if resolver is None:
        out["mx"] = out["txt"] = out["ns"] = out["cname"] = {
            "skipped": resolver_note}
        return out
    for key, qtype in (("mx", QTYPE_MX), ("txt", QTYPE_TXT),
                       ("ns", QTYPE_NS), ("cname", QTYPE_CNAME)):
        out[key] = dns_query_over_wire(host, qtype, resolver)
    return out


# ------------------------------------------------------------------ WHOIS ---

def whois_query(server: str, query: str, timeout: float = 6.0) -> str:
    """One WHOIS query: TCP port 43, query + CRLF, read to EOF."""
    with socket.create_connection((server, WHOIS_PORT), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(query.encode("ascii", "replace") + b"\r\n")
        chunks = []
        total = 0
        while total < WHOIS_STORE_LIMIT:
            try:
                piece = sock.recv(4096)
            except (socket.timeout, TimeoutError):
                break
            if not piece:
                break
            chunks.append(piece)
            total += len(piece)
    return b"".join(chunks).decode("latin-1", "replace")


def parse_whois_referral(text: str) -> tuple[str, int] | None:
    """Extract a referral server (host[, port]) from a WHOIS response.

    Handles the 'refer:' line IANA uses for IP ranges, the 'whois:' field
    present in TLD records, and 'ReferralServer: rwhois://host:port'.
    """
    for line in text.splitlines():
        stripped = line.strip()
        lowered = stripped.lower()
        if lowered.startswith("referralserver:"):
            value = stripped.split(":", 1)[1].strip()
            match = re.match(r"(?:rwhois|whois)://([^/\s]+)", value)
            if match:
                hostport = match.group(1)
                if ":" in hostport:
                    host, _, port = hostport.partition(":")
                    if port.isdigit():
                        return host, int(port)
                return hostport, WHOIS_PORT
        for key in ("refer:", "whois:"):
            if lowered.startswith(key):
                value = stripped[len(key):].strip().split()
                if not value:
                    continue
                candidate = value[0].strip().rstrip(".")
                if candidate and " " not in candidate and "." in candidate:
                    return candidate, WHOIS_PORT
    return None


def whois_lookup(target: str, timeout: float = 6.0) -> dict:
    """IANA WHOIS plus the referral chase (max WHOIS_MAX_HOPS total queries).

    Domains: query IANA with the full name; if IANA does not refer, query
    IANA with the TLD to obtain the registry server, then the registry with
    the full domain. IPs: IANA refers to the responsible RIR.
    """
    chain: list[dict] = []
    seen: set[str] = set()
    query, server = target, WHOIS_SERVER
    final_text = ""

    for _hop in range(WHOIS_MAX_HOPS):
        entry: dict = {"server": server, "query": query}
        if server in seen:
            entry["error"] = "referral loop; stopped"
            chain.append(entry)
            break
        seen.add(server)
        try:
            text = whois_query(server, query, timeout=timeout)
        except OSError as exc:
            entry["error"] = f"{type(exc).__name__}: {exc}"
            chain.append(entry)
            break
        entry["response_bytes"] = len(text)
        entry["response_preview"] = "\n".join(text.splitlines()[:10])
        referral = parse_whois_referral(text)
        entry["referral_to"] = f"{referral[0]}:{referral[1]}" if referral else None
        chain.append(entry)
        final_text = text
        if referral is None:
            break
        server, port = referral
        if port != WHOIS_PORT:
            entry["referral_to"] += " (non-standard port; not contacted)"
            break
        query = target
    else:
        chain.append({"note": f"hop limit ({WHOIS_MAX_HOPS}) reached"})

    # Domain fallback: IANA answered the full name without a referral, so ask
    # IANA about the TLD itself to learn the registry server.
    if (len(chain) == 1 and chain[0].get("referral_to") is None
            and "." in target and not _looks_like_ip(target)):
        tld = target.rsplit(".", 1)[-1]
        entry = {"server": WHOIS_SERVER, "query": tld}
        try:
            text = whois_query(WHOIS_SERVER, tld, timeout=timeout)
            referral = parse_whois_referral(text)
            entry["response_bytes"] = len(text)
            entry["response_preview"] = "\n".join(text.splitlines()[:6])
            entry["referral_to"] = (f"{referral[0]}:{referral[1]}"
                                    if referral else None)
            chain.append(entry)
            if referral and referral[1] == WHOIS_PORT:
                registry_server = referral[0]
                entry2 = {"server": registry_server, "query": target}
                try:
                    registry_text = whois_query(registry_server, target,
                                                timeout=timeout)
                    entry2["response_bytes"] = len(registry_text)
                    entry2["response_preview"] = "\n".join(
                        registry_text.splitlines()[:10])
                    entry2["referral_to"] = None
                    chain.append(entry2)
                    final_text = registry_text
                except OSError as exc:
                    entry2["error"] = f"{type(exc).__name__}: {exc}"
                    chain.append(entry2)
        except OSError as exc:
            entry["error"] = f"{type(exc).__name__}: {exc}"
            chain.append(entry)

    return {"target": target, "hops": chain,
            "final_response": final_text[:WHOIS_STORE_LIMIT]}


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# -------------------------------------------------------------------- HTTP ---

def http_head(url: str, timeout: float = 8.0) -> dict:
    """A single HEAD (GET with Range on 405) against one URL."""
    request = Request(url, method="HEAD",
                      headers={"User-Agent": USER_AGENT})
    start = time.perf_counter()
    try:
        with urlopen(request, timeout=timeout) as response:
            status, headers, final_url = response.status, response.headers, response.geturl()
    except HTTPError as exc:
        status, headers, final_url = exc.code, exc.headers, url
    except (URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        return {"url": url, "error": f"{type(exc).__name__}: {reason}"}

    interesting = {name: headers[name] for name in headers
                   if name.lower() in INTERESTING_HEADERS}
    return {"url": url, "final_url": final_url, "status": status,
            "interesting_headers": interesting,
            "header_names": sorted(h.lower() for h in headers),
            "elapsed_ms": round((time.perf_counter() - start) * 1000, 1),
            "method": "HEAD"}


# --------------------------------------------------------------------- CLI ---

def run(args: argparse.Namespace) -> dict:
    resolver, resolver_note = resolve_raw_resolver()
    out: dict = {
        "tool": "task-2/recon.py",
        "authorisation_note": (
            "Passive lookups plus at most one HEAD per target; run only "
            "against hosts you are authorised to look up."),
        "resolver": resolver,
        "resolver_note": resolver_note,
        "domains": [],
        "ips": [],
    }

    # Behaviour (documented in --help):
    #   default            -> DNS + HTTP
    #   --dns              -> DNS only
    #   --whois            -> DNS + WHOIS + HTTP
    #   --dns --whois      -> DNS + WHOIS
    # DNS runs in every case; --dns simply skips the HTTP section.
    do_http = not args.dns
    do_whois = args.whois

    for domain in args.domain or []:
        entry: dict = {"domain": domain}
        entry["dns"] = collect_dns(domain, resolver, resolver_note)
        if do_whois:
            entry["whois"] = whois_lookup(domain)
        if do_http:
            url = f"https://{domain}/"
            result = http_head(url)
            if result.get("error"):
                url = f"http://{domain}/"
                result = http_head(url)
            entry["http"] = result
        out["domains"].append(entry)

    for ip in args.ip or []:
        entry = {"ip": ip}
        try:
            hostname, aliases, _ = socket.gethostbyaddr(ip)
            entry["reverse_dns"] = {"hostname": hostname, "aliases": aliases}
        except (socket.herror, socket.gaierror, OSError) as exc:
            entry["reverse_dns"] = {"error": f"{type(exc).__name__}: {exc}"}
        if do_whois:
            entry["whois"] = whois_lookup(ip)
        if do_http:
            entry["http"] = http_head(f"http://{ip}/")
        out["ips"].append(entry)
    return out


def print_report(result: dict) -> None:
    print(AUTHORISATION_BANNER)
    print(f"resolver for raw DNS: {result['resolver_note']}")
    for domain_entry in result["domains"]:
        print()
        print(f"== domain: {domain_entry['domain']} ==")
        dns = domain_entry.get("dns")
        if dns:
            aaaa = dns.get("a_aaaa", {})
            aliases = dns.get("aliases", {})
            print(f"  getaddrinfo addresses : {aaaa.get('addresses', aaaa.get('error'))}")
            print(f"  canonical / aliases   : {aliases.get('canonical_name', aliases.get('error'))}"
                  f" / {aliases.get('aliases')}")
            for key in ("cname", "mx", "ns", "txt"):
                section = dns.get(key, {})
                if "skipped" in section:
                    print(f"  {key:<21}: skipped - {section['skipped']}")
                elif "error" in section:
                    print(f"  {key:<21}: error - {section['error']}")
                else:
                    rcode = section.get("rcode_name")
                    answers = [rr["data"] for rr in section.get("answers", [])]
                    extra = ""
                    if section.get("truncated"):
                        extra = " [truncated; TCP retry attempted]"
                    print(f"  {key.upper():<21}: {rcode} {answers}{extra}")
        whois = domain_entry.get("whois")
        if whois:
            print("  whois chain:")
            for hop in whois["hops"]:
                if "error" in hop:
                    print(f"    {hop.get('server')} <- {hop.get('query')}: {hop['error']}")
                else:
                    print(f"    {hop['server']} <- {hop['query']}: "
                          f"{hop['response_bytes']} bytes, "
                          f"referral: {hop.get('referral_to') or 'none'}")
        http = domain_entry.get("http")
        if http:
            if "error" in http:
                print(f"  http: {http['url']} -> {http['error']}")
            else:
                print(f"  http: {http['url']} -> {http['status']} "
                      f"({http['elapsed_ms']}ms, {http['method']})")
                for name, value in http["interesting_headers"].items():
                    print(f"         {name}: {value}")
    for ip_entry in result["ips"]:
        print()
        print(f"== ip: {ip_entry['ip']} ==")
        reverse = ip_entry.get("reverse_dns", {})
        print(f"  reverse dns: {reverse.get('hostname', reverse.get('error'))}")
        whois = ip_entry.get("whois")
        if whois:
            print("  whois chain:")
            for hop in whois["hops"]:
                if "error" in hop:
                    print(f"    {hop.get('server')} <- {hop.get('query')}: {hop['error']}")
                else:
                    print(f"    {hop['server']} <- {hop['query']}: "
                          f"{hop['response_bytes']} bytes, "
                          f"referral: {hop.get('referral_to') or 'none'}")
        http = ip_entry.get("http")
        if http:
            if "error" in http:
                print(f"  http: {http['url']} -> {http['error']}")
            else:
                print(f"  http: {http['url']} -> {http['status']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Passive DNS/WHOIS recon plus one HEAD per target. "
                    "Only against hosts you are authorised to look up.")
    parser.add_argument("--domain", action="append", metavar="NAME",
                        help="domain to look up (repeatable)")
    parser.add_argument("--ip", action="append", metavar="ADDR",
                        help="IP for reverse DNS / WHOIS / HEAD (repeatable)")
    parser.add_argument("--json", action="store_true",
                        help="emit machine-readable JSON on stdout")
    parser.add_argument("--whois", action="store_true",
                        help="also perform WHOIS (IANA + referral chase)")
    parser.add_argument("--dns", action="store_true",
                        help="DNS only: skip HTTP (and combine with --whois "
                             "for DNS+WHOIS)")
    args = parser.parse_args(argv)

    if not args.domain and not args.ip:
        parser.error("give at least one --domain or --ip")

    result = run(args)
    if args.json:
        print(AUTHORISATION_BANNER, file=sys.stderr)
        print(json.dumps(result, indent=2))
    else:
        print_report(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
