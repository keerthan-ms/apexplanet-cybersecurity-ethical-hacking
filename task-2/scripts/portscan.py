#!/usr/bin/env python3
"""
Task 2 - concurrent TCP connect scanner with banner grabbing.

What this is:
    A real scanner. Every connection in the output is a socket this script
    opened. Nothing is simulated, and no result is hardcoded.

Why TCP connect and not SYN ("stealth"):
    Raw sockets (SOCK_RAW with IPPROTO_TCP) require administrator rights on
    Windows. This session is not elevated, so a SYN scan is impossible here
    (see the raw-socket probe printed by every run). A TCP connect scan
    completes the three-way handshake, which is noisier but legal, reliable
    and needs no privileges against localhost.

Scope:
    Scan only 127.0.0.1 / localhost / this machine. Scanning a host you do
    not own or have written permission to test is unlawful.

Usage:
    python task-2/scripts/portscan.py --target 127.0.0.1 --top-ports 200
    python task-2/scripts/portscan.py --target 127.0.0.1 --ports 1-1024,3306,8080 --banner
    python task-2/scripts/portscan.py --ports 1-65535 --json
    python task-2/scripts/portscan.py --service-map
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field

DEFAULT_PORTS_SPEC = "1-1024"
MAX_PORT = 65535
BANNER_READ_LIMIT = 1024

# --------------------------------------------------------------------------
# Port lists
# --------------------------------------------------------------------------
# Static, curated ordering of commonly encountered TCP service ports. This is
# a list compiled in this source file - it is NOT scan output and NOT a claim
# about this machine. It exists so --top-ports can offer a sane default the
# way Nmap's --top-ports does.
TOP_PORTS_TABLE: tuple[int, ...] = (
    7, 9, 13, 19, 21, 22, 23, 25, 53, 67, 68, 69, 80, 81, 88, 110, 111,
    123, 135, 137, 138, 139, 143, 161, 389, 443, 445, 464, 465, 500, 514,
    515, 587, 631, 636, 873, 990, 993, 995, 1080, 1194, 1433, 1434, 1521,
    1723, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 2375, 2376, 3000,
    3128, 3306, 3389, 4369, 5000, 5432, 5601, 5672, 5900, 5984, 6379, 6667,
    7001, 7680, 8000, 8008, 8009, 8080, 8081, 8082, 8088, 8443, 8888, 9000,
    9042, 9090, 9200, 9300, 10000, 11211, 15672, 27017, 27018, 28017, 35000,
)

# Well-known port -> service name. Every entry is a GUESS derived from the
# port number alone. A banner grab (or a protocol probe) is what upgrades a
# guess to an observation - the output column is labelled accordingly.
SERVICE_GUESSES: dict[int, str] = {
    7: "echo", 9: "discard", 13: "daytime", 19: "chargen", 21: "ftp",
    22: "ssh", 23: "telnet", 25: "smtp", 53: "domain/dns", 67: "dhcp-server",
    68: "dhcp-client", 69: "tftp", 80: "http", 81: "http-alt", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "microsoft-ds", 464: "kpasswd",
    465: "smtp-tls", 500: "isakmp", 514: "syslog", 515: "lpd",
    587: "submission", 591: "filemaker-http", 631: "ipp", 636: "ldaps",
    873: "rsync", 990: "ftps", 993: "imaps", 995: "pop3s", 1080: "socks",
    1194: "openvpn", 1433: "ms-sql-s", 1434: "ms-sql-m", 1521: "oracle-tns",
    1723: "pptp", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
    2086: "whm", 2087: "whm-ssl", 2095: "cpanel-webmail", 2096: "cpanel-webmail-ssl",
    2181: "zookeeper", 2375: "docker", 2376: "docker-ssl", 3000: "http-dev",
    3128: "squid", 3306: "mysql", 3389: "ms-wbt-server/rdp", 4369: "epmd",
    5000: "http-dev", 5432: "postgresql", 5601: "kibana", 5672: "amqp",
    5900: "vnc", 5984: "couchdb", 6379: "redis", 6667: "irc", 7001: "weblogic",
    7680: "delivery-optimization", 8000: "http-alt", 8008: "http-alt",
    8009: "ajp13", 8080: "http-alt", 8081: "http-alt", 8082: "http-alt",
    8088: "http-alt", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
    9042: "cassandra", 9090: "http-alt", 9200: "elasticsearch",
    9300: "elasticsearch-transport", 10000: "webmin", 11211: "memcached",
    15672: "rabbitmq-management", 27017: "mongodb", 27018: "mongodb",
    28017: "mongodb-http", 35000: "http-dev",
}

# Ports where a plain-HTTP probe is protocol-appropriate. TLS ports (443,
# 8443, 993, ...) are deliberately absent: a plaintext GET there would only
# produce a TLS alert, not a banner.
HTTP_PROBE_PORTS = frozenset({
    80, 81, 591, 593, 3000, 5000, 7001, 8000, 8008, 8009, 8080, 8081, 8082,
    8088, 8888, 9000, 9090, 9200, 35000,
})
HTTP_PROBE = b"GET / HTTP/1.0\r\n\r\n"


def guess_service(port: int) -> str | None:
    """Well-known-port service name, or None. Always a guess, never an observation."""
    return SERVICE_GUESSES.get(port)


# --------------------------------------------------------------------------
# Port specification parsing
# --------------------------------------------------------------------------

def _parse_single_port(text: str) -> int:
    token = text.strip()
    if not token.isdigit():
        raise ValueError(f"port is not a number: {text!r}")
    value = int(token)
    if value < 1 or value > MAX_PORT:
        raise ValueError(f"port out of range 1-{MAX_PORT}: {text!r}")
    return value


def parse_port_spec(spec: str) -> list[int]:
    """Parse '1-1024,3306,8080' into a sorted, de-duplicated port list.

    Accepts individual ports ('22'), inclusive ranges ('20-25'), and comma
    separated mixtures with optional whitespace. Raises ValueError on any
    malformed token rather than silently skipping it.
    """
    if not isinstance(spec, str) or not spec.strip():
        raise ValueError("empty port specification")

    ports: set[int] = set()
    for raw_token in spec.split(","):
        token = raw_token.strip()
        if not token:
            raise ValueError(f"empty entry in port specification: {spec!r}")
        if "-" in token:
            bounds = token.split("-")
            if len(bounds) != 2 or not bounds[0].strip() or not bounds[1].strip():
                raise ValueError(f"malformed range: {token!r}")
            low = _parse_single_port(bounds[0])
            high = _parse_single_port(bounds[1])
            if low > high:
                raise ValueError(f"descending range: {token!r}")
            ports.update(range(low, high + 1))
        else:
            ports.add(_parse_single_port(token))
    return sorted(ports)


def top_ports(count: int) -> list[int]:
    """First N ports of the curated common-port table."""
    if count < 1:
        raise ValueError("--top-ports must be at least 1")
    if count > len(TOP_PORTS_TABLE):
        raise ValueError(
            f"--top-ports maximum is {len(TOP_PORTS_TABLE)} (this script ships a "
            f"table of {len(TOP_PORTS_TABLE)} common ports)"
        )
    return sorted(TOP_PORTS_TABLE[:count])


def resolve_ports(spec: str | None = None, top_n: int | None = None) -> list[int]:
    """Turn CLI options into the final port list.

    --ports and --top-ports are mutually exclusive; with neither, a sane
    default range (1-1024) is used so a bare invocation stays quick.
    """
    if spec and top_n is not None:
        raise ValueError("--ports and --top-ports are mutually exclusive")
    if top_n is not None:
        return top_ports(top_n)
    if spec:
        return parse_port_spec(spec)
    return parse_port_spec(DEFAULT_PORTS_SPEC)


# --------------------------------------------------------------------------
# Raw-socket capability probe
# --------------------------------------------------------------------------

def probe_raw_sockets() -> dict:
    """Try to open raw sockets and report exactly what happened.

    On a non-elevated Windows session SOCK_RAW/IPPROTO_TCP fails with
    WinError 10013 (ACCESS_DENIED), which is why this tool performs a TCP
    connect scan. On this platform a raw ICMP socket may still open; that is
    reported as observed rather than assumed.
    """
    outcome: dict[str, object] = {"raw_tcp": None, "raw_icmp": None, "notes": []}
    for key, proto in (("raw_tcp", socket.IPPROTO_TCP),
                       ("raw_icmp", socket.IPPROTO_ICMP)):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
        except PermissionError as exc:
            winerror = getattr(exc, "winerror", None)
            outcome[key] = {
                "allowed": False,
                "error": f"PermissionError: {exc} (winerror={winerror})",
            }
        except OSError as exc:
            outcome[key] = {
                "allowed": False,
                "error": f"{type(exc).__name__}: {exc} (errno={exc.errno})",
            }
        else:
            sock.close()
            outcome[key] = {"allowed": True, "error": None}

    tcp_ok = bool(outcome["raw_tcp"] and outcome["raw_tcp"]["allowed"])
    icmp_ok = bool(outcome["raw_icmp"] and outcome["raw_icmp"]["allowed"])

    if tcp_ok:
        outcome["notes"].append(
            "SOCK_RAW with IPPROTO_TCP opened: a SYN (stealth) scan would be "
            "possible on this platform, but this script still uses TCP connect."
        )
    else:
        outcome["notes"].append(
            "SOCK_RAW with IPPROTO_TCP is denied by the platform (Windows "
            "WinError 10013 without elevation): a SYN/stealth scan is NOT "
            "possible here."
        )
    outcome["notes"].append(
        "SOCK_RAW with IPPROTO_ICMP: "
        + ("available" if icmp_ok else "denied")
        + " on this platform (observed by this run)."
    )
    outcome["notes"].append(
        "This run is therefore a TCP connect scan - each open port reflects a "
        "completed three-way handshake, not a half-open probe."
    )
    return outcome


# --------------------------------------------------------------------------
# Banner helpers (pure functions - unit tested)
# --------------------------------------------------------------------------

def sanitize_banner(data: bytes | str, limit: int = BANNER_READ_LIMIT) -> str:
    """Return printable banner text with control characters removed.

    Line breaks survive as '\\n' (CR/LF are normalised first); every other
    C0 control byte, DEL, and any other non-printable character is stripped.
    Bytes that are not valid UTF-8 fall back to latin-1 so binary probes
    never raise.
    """
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    chunk = data[:limit]
    try:
        text = chunk.decode("utf-8")
    except UnicodeDecodeError:
        text = chunk.decode("latin-1")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = "".join(ch for ch in text if ch.isprintable() or ch in "\n\t")
    return text.strip()


def parse_mysql_handshake(data: bytes) -> dict | None:
    """Identify a MySQL initial handshake packet.

    The server speaks first: [3-byte length][1-byte sequence][0x0a][version
    NUL][connection id][auth plugin data...]. Returns protocol/server_version
    if the packet matches, else None.
    """
    if len(data) < 9:
        return None
    payload_len = int.from_bytes(data[0:3], "little")
    if payload_len < 6 or len(data) < 4 + payload_len:
        return None
    payload = data[4:4 + payload_len]
    if payload[0] != 0x0A:            # protocol version 10 = MySQL 4.1+
        return None
    end = payload.find(b"\x00", 1)
    if end < 0:
        return None
    version = payload[1:end].decode("latin-1", "replace")
    connection_id = None
    if len(payload) >= end + 5:
        connection_id = int.from_bytes(payload[end + 1:end + 5], "little")
    return {
        "detected_protocol": "mysql",
        "server_version": version,
        "connection_id": connection_id,
        "note": "binary handshake packet identified; version string read from it",
    }


def parse_http_response(data: bytes) -> dict | None:
    """Identify an HTTP response: status line, status code, Server header."""
    if not data.startswith(b"HTTP/"):
        return None
    text = data[:BANNER_READ_LIMIT].decode("latin-1", "replace")
    head = text.split("\r\n\r\n", 1)[0]
    lines = head.split("\r\n")
    status_line = lines[0]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    status_code = None
    parts = status_line.split()
    if len(parts) >= 2 and parts[1].isdigit():
        status_code = int(parts[1])
    return {
        "detected_protocol": "http",
        "status_line": status_line,
        "status_code": status_code,
        "server_header": headers.get("server"),
    }


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------

@dataclass
class PortResult:
    port: int
    state: str                      # open | closed | filtered | unknown
    reason: str
    elapsed_ms: float
    service_guess: str | None = None
    banner: str | None = None
    banner_detected: str | None = None
    banner_detail: dict | None = None
    probe_sent: str | None = None


def scan_port(target: str, port: int, timeout: float) -> PortResult:
    """One TCP connect attempt.

    open     - connect() completed: the peer accepted the handshake.
    closed   - the peer actively refused (RST): nothing is listening.
    filtered - no answer before the timeout (dropped / blocked / unreachable).
    unknown  - any other OS error, reported verbatim rather than guessed.
    """
    start = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
    except ConnectionRefusedError:
        state, reason = "closed", "connection refused (TCP RST)"
    except (socket.timeout, TimeoutError):
        state, reason = "filtered", f"no response within {timeout}s"
    except OSError as exc:
        err = getattr(exc, "winerror", None) or exc.errno
        state, reason = "unknown", f"OS error {err}: {exc}"
    else:
        state, reason = "open", "TCP handshake completed"
    finally:
        elapsed = (time.perf_counter() - start) * 1000
        sock.close()
    return PortResult(port=port, state=state, reason=reason,
                      elapsed_ms=round(elapsed, 2))


def grab_banner(target: str, port: int, timeout: float) -> dict:
    """Connect to an open port and read what it sends back.

    Protocol-appropriate behaviour:
      - plain-HTTP ports get one 'GET / HTTP/1.0\\r\\n\\r\\n' probe;
      - every other port is read first (many services greet on connect,
        e.g. MySQL sends its handshake packet immediately);
      - the reply is sanitised to printable text before display.
    """
    out: dict = {"banner": None, "detected_protocol": None,
                 "detail": None, "probe_sent": None}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
    except OSError as exc:
        out["detail"] = {"error": f"reconnect failed: {exc}"}
        return out

    data = b""
    try:
        if port in HTTP_PROBE_PORTS:
            sock.sendall(HTTP_PROBE)
            out["probe_sent"] = HTTP_PROBE.decode("latin-1")
        deadline = time.perf_counter() + timeout
        while len(data) < BANNER_READ_LIMIT and time.perf_counter() < deadline:
            try:
                chunk = sock.recv(min(512, BANNER_READ_LIMIT - len(data)))
            except (socket.timeout, TimeoutError):
                break
            except OSError:
                break
            if not chunk:
                break
            data += chunk
            mysql = parse_mysql_handshake(data)
            if mysql:
                break
            if b"\r\n\r\n" in data:
                break
    finally:
        sock.close()

    if not data:
        out["detail"] = {"note": "no data received before timeout"}
        return out

    out["banner"] = sanitize_banner(data)
    mysql = parse_mysql_handshake(data)
    http = parse_http_response(data)
    if mysql:
        out["detected_protocol"] = "mysql"
        out["detail"] = mysql
    elif http:
        out["detected_protocol"] = "http"
        out["detail"] = http
    else:
        out["detected_protocol"] = "raw"
        out["detail"] = {"note": "unread bytes; shown sanitised"}
    return out


def scan_ports(target: str, ports: list[int], timeout: float = 0.4,
               workers: int = 200, banner: bool = False) -> tuple[list[PortResult], float]:
    """Scan ports concurrently with a thread pool. Returns (results, seconds)."""
    start = time.perf_counter()
    results: list[PortResult] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(scan_port, target, port, timeout): port
                   for port in ports}
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda r: r.port)

    if banner:
        open_ports = [r for r in results if r.state == "open"]
        with ThreadPoolExecutor(max_workers=min(32, max(1, workers))) as pool:
            futures = {pool.submit(grab_banner, target, r.port, timeout): r
                       for r in open_ports}
            for future in as_completed(futures):
                info = future.result()
                outcome = futures[future]
                outcome.banner = info["banner"]
                outcome.banner_detected = info["detected_protocol"]
                outcome.banner_detail = info["detail"]
                outcome.probe_sent = info["probe_sent"]

    for result in results:
        result.service_guess = guess_service(result.port)
    return results, time.perf_counter() - start


def summarise(results: list[PortResult]) -> dict:
    counts = {"open": 0, "closed": 0, "filtered": 0, "unknown": 0}
    for result in results:
        counts[result.state] = counts.get(result.state, 0) + 1
    counts["total"] = len(results)
    return counts


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def print_service_map() -> None:
    print("Service guess table (well-known port -> GUESS, confirm with a banner)")
    print("-" * 72)
    for port in sorted(SERVICE_GUESSES):
        print(f"  {port:>5}  {SERVICE_GUESSES[port]}")
    print(f"\n{len(SERVICE_GUESSES)} entries. A guess is only a guess until a "
          f"banner confirms it.")


def print_report(target: str, ports_spec: str, results: list[PortResult],
                 elapsed: float, timeout: float, workers: int,
                 raw: dict) -> None:
    print("=" * 78)
    print("TASK 2 - TCP CONNECT SCAN (real sockets, no raw packets)")
    print("=" * 78)
    print(f"target   : {target}")
    print(f"ports    : {len(results)} scanned ({ports_spec})")
    print(f"timeout  : {timeout}s   workers: {workers}")
    print(f"type     : TCP connect (full handshake)")
    print()
    print("Raw-socket capability probe:")
    for key, label in (("raw_tcp", "SOCK_RAW / IPPROTO_TCP"),
                       ("raw_icmp", "SOCK_RAW / IPPROTO_ICMP")):
        info = raw[key]
        status = "available" if info["allowed"] else "denied"
        detail = "" if info["allowed"] else f" - {info['error']}"
        print(f"  {label:<26}: {status}{detail}")
    for note in raw["notes"]:
        print(f"  note: {note}")
    print()

    shown = [r for r in results if r.state != "closed"]
    closed_count = sum(1 for r in results if r.state == "closed")
    print(f"PORT       STATE      SERVICE (GUESS)     BANNER / DETAIL")
    print("-" * 78)
    if not shown:
        print("  (no open, filtered or unknown ports)")
    for result in shown:
        guess = result.service_guess or "-"
        detail = ""
        if result.state == "open" and result.banner:
            protocol = result.banner_detected or "raw"
            version = (result.banner_detail or {}).get("server_version")
            if version:
                # MySQL: the rest of the packet is binary (auth salt); the
                # version string is the meaningful part, the raw smear is not.
                detail = (f"[{protocol}] {version} "
                          f"(binary handshake packet; version extracted)")
            else:
                detail = f"[{protocol}] {result.banner}"
            detail = detail.replace("\n", "\\n")
        elif result.state == "open":
            detail = "(no banner; run with --banner to probe)"
        elif result.state == "unknown":
            detail = result.reason
        print(f"{result.port:<10} {result.state:<10} {guess:<19.19} {detail[:70]}")
    if closed_count:
        print(f"... {closed_count} closed port(s) omitted "
              f"(refused with TCP RST - listed with --json)")

    counts = summarise(results)
    print()
    print(f"Summary: {counts['open']} open, {counts['closed']} closed, "
          f"{counts['filtered']} filtered, {counts['unknown']} unknown "
          f"of {counts['total']} ports in {elapsed:.2f}s")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="TCP connect port scanner (no raw sockets required). "
                    "Scan only hosts you are authorised to test.")
    parser.add_argument("--target", default="127.0.0.1",
                        help="target address (default: 127.0.0.1; keep to "
                             "localhost / this machine)")
    parser.add_argument("--ports", default=None,
                        help="port list, e.g. '1-1024,3306,8080' "
                             "(default: 1-1024)")
    parser.add_argument("--top-ports", type=int, default=None, metavar="N",
                        help=f"scan the N most common ports "
                             f"(max {len(TOP_PORTS_TABLE)}); "
                             "mutually exclusive with --ports")
    parser.add_argument("--timeout", type=float, default=0.4,
                        help="per-port connect timeout in seconds (default 0.4)")
    parser.add_argument("--workers", type=int, default=200,
                        help="concurrent connections (default 200)")
    parser.add_argument("--banner", action="store_true",
                        help="grab a banner from each open port")
    parser.add_argument("--json", action="store_true",
                        help="emit machine-readable JSON on stdout")
    parser.add_argument("--service-map", action="store_true",
                        help="print the well-known-port service guess table and exit")
    args = parser.parse_args(argv)

    if args.service_map:
        print_service_map()
        return 0

    try:
        ports = resolve_ports(args.ports, args.top_ports)
    except ValueError as exc:
        parser.error(str(exc))
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.workers < 1:
        parser.error("--workers must be at least 1")

    try:
        socket.getaddrinfo(args.target, None)
    except socket.gaierror as exc:
        print(f"error: cannot resolve target {args.target!r}: {exc}",
              file=sys.stderr)
        return 2

    raw = probe_raw_sockets()
    results, elapsed = scan_ports(args.target, ports, timeout=args.timeout,
                                  workers=args.workers, banner=args.banner)
    counts = summarise(results)
    ports_spec = args.ports or (f"top-{args.top_ports}" if args.top_ports
                                else DEFAULT_PORTS_SPEC)

    if args.json:
        payload = {
            "tool": "task-2/portscan.py",
            "scan_type": "tcp-connect",
            "target": args.target,
            "ports_spec": ports_spec,
            "timeout_seconds": args.timeout,
            "workers": args.workers,
            "banner_grab": args.banner,
            "raw_socket_probe": raw,
            "summary": counts,
            "elapsed_seconds": round(elapsed, 3),
            "results": [asdict(r) for r in results],
        }
        print(json.dumps(payload, indent=2))
    else:
        print_report(args.target, ports_spec, results, elapsed,
                     args.timeout, args.workers, raw)
    return 0


if __name__ == "__main__":
    sys.exit(main())
