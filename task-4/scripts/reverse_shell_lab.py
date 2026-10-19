#!/usr/bin/env python3
"""
Task 4 - local reverse shell laboratory.

A real shell over a real TCP socket, executed entirely against 127.0.0.1.
Nothing here is simulated output: every byte crosses the loopback interface of
this machine, and every response is produced by the payload process itself.

Two directions are implemented:

    mode=bind    the payload (serve) opens the listening socket and waits;
                 the attacker (connect) dials in to it.
    mode=reverse the attacker (connect) opens the listening socket; the
                 payload (serve) dials back out to it (the "connect-back").

Why reverse is the one that matters
------------------------------------
Bind mode requires the *payload's* listening socket to be reachable from the
attacker. On a modern network it is not: workstation and server firewalls
default to deny-inbound, NAT gives the target no reachable address, and cloud
security groups close every unsolicited inbound port. Reverse mode inverts
the requirement - the payload makes an *outbound* connection, and outbound TCP
is almost always allowed (DNS, HTTP, HTTPS and updates must leave the host).
The one thing the attacker must then be able to do is listen on a port of its
own. That single asymmetry is why connect-back shells dominate real
intrusions, and why outbound default-deny firewalling (see
methodology/06-system-hardening.md, checklist 2c) is the control that beats
them. Both directions are implemented here so the difference can be observed
rather than taken on trust.

Safety engineering
------------------
The "shell" never invokes a shell. Commands are dispatched through an
explicit allow-list dictionary of Python functions; nothing else reaches any
executor, and `subprocess` with `shell=True` is not used anywhere in this
file. `whoami`, `pwd`, `dir`, `sysinfo`, `echo`, `help` and `exit` cannot
become `format C:` or `rm -rf /` because those names are not keys in the
dictionary. That is both the safety control and the correct engineering: an
allow-list scales down to nothing, an deny-list always has a gap.

The wire protocol is line-based: one command line per request, one JSON
object per response, so multi-line output and partial TCP reads are handled
without ambiguity.

    python task-4/scripts/reverse_shell_lab.py --mode reverse
    python task-4/scripts/reverse_shell_lab.py --mode bind --port 5555 --once
    python task-4/scripts/reverse_shell_lab.py --role payload --json
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import socket
import sys
import threading
import time
from typing import Callable

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 4444
DEFAULT_TIMEOUT = 30.0
DIAL_RETRY_INTERVAL = 0.05
MAX_LINE_BYTES = 1 << 20

BANNER = """
========================================================================
 LOCAL REVERSE SHELL LAB - LOCAL DEMONSTRATION ONLY
 ------------------------------------------------------------------------
 Bind address : 127.0.0.1 (loopback). No other host is reachable.
 Remote targeting : none. There is no payload, no malware and no
                    persistence; this is a two-process shell over TCP.
 Commands : allow-listed (whoami, pwd, dir, sysinfo, echo, help, exit).
            Arbitrary commands are rejected before any executor is touched.
========================================================================
"""


class SessionClosed(Exception):
    """Peer closed the connection cleanly."""


class SessionTimeout(Exception):
    """No bytes arrived within the configured timeout."""


# ------------------------------------------------------------- command set ---

def _cmd_whoami(_arg: str) -> str:
    user = getpass.getuser() or os.environ.get("USERNAME") or "unknown"
    domain = os.environ.get("USERDOMAIN")
    return f"{domain}\\{user}" if domain and os.name == "nt" else user


def _cmd_pwd(arg: str) -> str:
    return os.getcwd()


def _cmd_dir(arg: str) -> str:
    target = arg or os.getcwd()
    if not os.path.isdir(target):
        raise NotADirectoryError(target)
    names = sorted(os.listdir(target))
    if not names:
        return f"{target}: (empty)"
    lines = [f"{name}/" if os.path.isdir(os.path.join(target, name)) else name
             for name in names]
    return f"{target} ({len(names)} entries)\n" + "\n".join(lines)


def _cmd_sysinfo(_arg: str) -> str:
    fields = [
        ("platform", platform.platform()),
        ("python", platform.python_version()),
        ("cpu_count", str(os.cpu_count() or 0)),
        ("hostname", platform.node()),
    ]
    return "\n".join(f"{key}: {value}" for key, value in fields)


def _cmd_echo(arg: str) -> str:
    return arg


def _cmd_help(_arg: str) -> str:
    lines = ["allow-listed commands:"]
    lines += [f"  {name}" for name in sorted(COMMANDS)]
    lines.append("anything else is rejected before it reaches an executor")
    return "\n".join(lines)


COMMANDS: dict[str, Callable[[str], str]] = {
    "whoami": _cmd_whoami,
    "pwd": _cmd_pwd,
    "dir": _cmd_dir,
    "sysinfo": _cmd_sysinfo,
    "echo": _cmd_echo,
    "help": _cmd_help,
}

ALIASES: dict[str, str] = {"ls": "dir", "cwd": "pwd", "?": "help"}


def execute(command: str) -> dict:
    """Dispatch one command line through the allow-list.

    Returns a response object with `status` one of: `ok`, `rejected` (not in
    the allow-list - nothing was executed), `error` (allowed command failed),
    `exit`.
    """
    raw = command.strip()
    if not raw:
        return {"command": "", "status": "ok", "output": ""}

    name, _, arg = raw.partition(" ")
    key = ALIASES.get(name.lower(), name.lower())

    if key == "exit":
        return {"command": raw, "status": "exit", "output": "closing session"}

    if key not in COMMANDS:
        return {
            "command": raw,
            "status": "rejected",
            "output": "",
            "error": (f"{name!r} is not in the allow-list; no executor was "
                      f"invoked. Permitted commands: "
                      f"{', '.join(sorted(COMMANDS) + sorted(ALIASES))}"),
            "allowed": sorted(COMMANDS),
        }

    try:
        output = COMMANDS[key](arg.strip())
    except Exception as exc:
        return {"command": raw, "status": "error", "output": "",
                "error": f"{type(exc).__name__}: {exc}"}
    return {"command": raw, "status": "ok", "output": output}


# --------------------------------------------------------------- transport ---

class LineReader:
    """Buffered line reader: loops across partial TCP reads until a newline."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._buf = b""

    def readline(self) -> str:
        while b"\n" not in self._buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise SessionClosed
            self._buf += chunk
            if len(self._buf) > MAX_LINE_BYTES:
                raise SessionClosed
        line, _, self._buf = self._buf.partition(b"\n")
        return line.decode("utf-8", errors="replace")


def _make_listener(host: str, port: int) -> tuple[socket.socket, int]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(1)
    actual_port = listener.getsockname()[1]
    return listener, actual_port


def _accept(listener: socket.socket, timeout: float) -> tuple[socket.socket, tuple]:
    listener.settimeout(timeout)
    try:
        conn, addr = listener.accept()
    except socket.timeout:
        raise SessionTimeout(f"no connection within {timeout:g}s")
    conn.settimeout(timeout)
    return conn, addr


def _dial(host: str, port: int, deadline: float) -> tuple[socket.socket, tuple]:
    """Connect with retry until deadline, so start order of the two sides
    does not matter when they run in the same test or the same shell."""
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            sock = socket.create_connection((host, port), timeout=2.0)
            sock.settimeout(max(deadline - time.monotonic(), 1.0))
            return sock, sock.getpeername()
        except OSError as exc:
            last_error = exc
            time.sleep(DIAL_RETRY_INTERVAL)
    raise SessionTimeout(f"could not connect to {host}:{port} within "
                         f"window ({last_error})")


def _serve_session(conn: socket.socket, *, once: bool, timeout: float,
                   log: list[dict]) -> str:
    """Payload side: read command lines, execute, reply with one JSON line."""
    conn.settimeout(timeout)
    reader = LineReader(conn)
    try:
        while True:
            try:
                line = reader.readline()
            except socket.timeout:
                return "timeout: no command within timeout"
            except SessionClosed:
                return "closed: peer hung up"
            result = execute(line)
            conn.sendall((json.dumps(result) + "\n").encode("utf-8"))
            log.append(result)
            if result["status"] == "exit":
                return "exit"
            if once:
                return "once"
    except SessionClosed:
        return "closed: peer hung up"


def _connect_session(conn: socket.socket, *, once: bool, timeout: float,
                     commands: list[str] | None, prompt: bool) -> tuple[str, list[dict]]:
    """Attacker side: send command lines, receive one JSON response each."""
    conn.settimeout(timeout)
    reader = LineReader(conn)
    log: list[dict] = []
    source = iter(commands) if commands is not None else None

    def next_command() -> str | None:
        if source is not None:
            return next(source, None)
        if prompt:
            try:
                return input("shell> ")
            except EOFError:
                return None
        line = sys.stdin.readline()
        return line if line else None

    try:
        while True:
            command = next_command()
            if command is None:
                return "eof", log
            if command.strip() == "":
                continue
            conn.sendall((command.rstrip("\n") + "\n").encode("utf-8"))
            try:
                line = reader.readline()
            except socket.timeout:
                return "timeout: no response", log
            except SessionClosed:
                return "closed: peer hung up", log
            result = json.loads(line)
            log.append(result)
            if prompt or commands is None:
                _print_exchange(result)
            if result["status"] == "exit":
                return "exit", log
            if once:
                return "once", log
    except SessionClosed:
        return "closed: peer hung up", log


def _print_exchange(result: dict) -> None:
    status = result["status"]
    if status == "ok":
        if result.get("output"):
            print(result["output"])
    elif status == "exit":
        print(result.get("output", ""))
    else:
        print(f"[{status}] {result.get('error', '')}")


# ------------------------------------------------------------------ public ---

def serve(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, *,
          mode: str = "reverse", once: bool = False,
          timeout: float = DEFAULT_TIMEOUT, quiet: bool = True,
          ready: Callable[[int], None] | None = None) -> dict:
    """Payload side of the shell.

    mode=bind    listen on (host, port) and wait for the attacker to dial in.
    mode=reverse dial back out to the attacker's listener on (host, port).
    """
    started = time.monotonic()
    result: dict = {"role": "payload", "mode": mode, "host": host, "port": port,
                    "status": "error", "peer": None, "commands": []}
    listener = None
    conn = None
    try:
        if mode == "bind":
            listener, actual = _make_listener(host, port)
            result["port"] = actual
            if ready:
                ready(actual)
            if not quiet:
                print(f"[payload] bind shell listening on {host}:{actual}")
            conn, addr = _accept(listener, timeout)
        else:
            if ready:
                ready(port)
            if not quiet:
                print(f"[payload] reverse shell dialling back to {host}:{port}")
            conn, addr = _dial(host, port, time.monotonic() + timeout)
        result["peer"] = list(addr)
        result["status"] = "session"
        result["session_end"] = _serve_session(conn, once=once, timeout=timeout,
                                               log=result["commands"])
        result["status"] = "ok"
    except SessionTimeout as exc:
        result["status"] = "timeout"
        result["detail"] = str(exc)
    except OSError as exc:
        result["status"] = "error"
        result["detail"] = f"{type(exc).__name__}: {exc}"
    except KeyboardInterrupt:
        result["status"] = "interrupted"
    finally:
        if conn is not None:
            conn.close()
        if listener is not None:
            listener.close()
        result["duration_s"] = round(time.monotonic() - started, 3)
    return result


def connect(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, *,
            mode: str = "reverse", once: bool = False,
            timeout: float = DEFAULT_TIMEOUT, quiet: bool = True,
            commands: list[str] | None = None,
            ready: Callable[[int], None] | None = None) -> dict:
    """Attacker side of the shell.

    mode=reverse listen on (host, port) and wait for the payload to call back.
    mode=bind    dial in to the payload's listener on (host, port).
    """
    started = time.monotonic()
    result: dict = {"role": "attacker", "mode": mode, "host": host, "port": port,
                    "status": "error", "peer": None, "commands": []}
    listener = None
    conn = None
    interactive = commands is None
    try:
        if mode == "reverse":
            listener, actual = _make_listener(host, port)
            result["port"] = actual
            if ready:
                ready(actual)
            if not quiet:
                print(f"[attacker] reverse handler listening on {host}:{actual}")
            conn, addr = _accept(listener, timeout)
        else:
            if ready:
                ready(port)
            if not quiet:
                print(f"[attacker] connecting to bind shell at {host}:{port}")
            conn, _ = _dial(host, port, time.monotonic() + timeout)
            addr = conn.getpeername()
        result["peer"] = list(addr)
        result["status"] = "session"
        prompt = interactive and sys.stdin.isatty()
        session_end, log = _connect_session(conn, once=once, timeout=timeout,
                                            commands=commands, prompt=prompt)
        result["commands"] = log
        result["session_end"] = session_end
        result["status"] = "ok"
    except SessionTimeout as exc:
        result["status"] = "timeout"
        result["detail"] = str(exc)
    except OSError as exc:
        result["status"] = "error"
        result["detail"] = f"{type(exc).__name__}: {exc}"
    except KeyboardInterrupt:
        result["status"] = "interrupted"
    finally:
        if conn is not None:
            conn.close()
        if listener is not None:
            listener.close()
        result["duration_s"] = round(time.monotonic() - started, 3)
    return result


# -------------------------------------------------------------------- main ---

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="reverse_shell_lab.py",
        description=(
            "Local reverse/bind shell demonstration on 127.0.0.1. "
            "mode=reverse: the attacker listens and the payload dials back "
            "(connect-back) - the direction that survives a network which "
            "allows outbound TCP but filters inbound. mode=bind: the payload "
            "listens and the attacker dials in - usually blocked by modern "
            "inbound filtering. Commands are allow-listed; arbitrary input "
            "never reaches an executor."
        ),
        epilog=(
            "Authorisation: run this against 127.0.0.1 only. A shell against "
            "a system you do not own is unauthorised access."
        ),
    )
    parser.add_argument("--mode", choices=("reverse", "bind"),
                        default="reverse",
                        help="connection direction (default: reverse)")
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help="bind/connect address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help="TCP port (default: 4444); 0 selects a free port")
    parser.add_argument("--once", action="store_true",
                        help="handle exactly one command, then shut down")
    parser.add_argument("--json", action="store_true",
                        help="emit structured results instead of prose")
    parser.add_argument("--role", choices=("both", "payload", "attacker"),
                        default="both",
                        help=("which side this process runs (default: both - "
                              "payload in a thread, attacker on stdin)"))
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="seconds to wait for connection or command "
                             f"(default: {DEFAULT_TIMEOUT:g})")
    parser.add_argument("--quiet", action="store_true",
                        help="suppress progress lines on stderr")
    args = parser.parse_args(argv)

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        parser.error("this lab only runs against 127.0.0.1/localhost; "
                     "remote targeting is refused")

    if args.json:
        sys.stderr.write(BANNER)
    else:
        print(BANNER)

    def note(message: str) -> None:
        if not args.quiet:
            print(message, file=sys.stderr)

    payload_result: dict | None = None
    attacker_result: dict | None = None

    try:
        if args.role == "payload":
            note(f"[payload] mode={args.mode} target {args.host}:{args.port}")
            payload_result = serve(args.host, args.port, mode=args.mode,
                                   once=args.once, timeout=args.timeout,
                                   quiet=args.quiet)
        elif args.role == "attacker":
            note(f"[attacker] mode={args.mode} on {args.host}:{args.port}")
            attacker_result = connect(args.host, args.port, mode=args.mode,
                                      once=args.once, timeout=args.timeout,
                                      quiet=args.quiet)
        else:
            # One process, both cooperating pieces: whichever side listens is
            # started first in a thread; the other side retries, so start
            # order is safe. With --port 0 the bound port is handed across
            # through the ready callback before the dialing side starts.
            listen_side = "attacker" if args.mode == "reverse" else "payload"
            done = threading.Event()
            bound = threading.Event()
            resolved = {"port": args.port}

            def on_ready(actual: int) -> None:
                resolved["port"] = actual
                bound.set()

            def launch_listener() -> None:
                nonlocal payload_result, attacker_result
                if listen_side == "payload":
                    payload_result = serve(args.host, args.port,
                                           mode=args.mode, once=args.once,
                                           timeout=args.timeout,
                                           quiet=args.quiet,
                                           ready=on_ready)
                else:
                    attacker_result = connect(args.host, args.port,
                                              mode=args.mode, once=args.once,
                                              timeout=args.timeout,
                                              quiet=args.quiet,
                                              ready=on_ready)
                done.set()

            note(f"[lab] mode={args.mode}: {listen_side} side listens first")
            thread = threading.Thread(target=launch_listener, daemon=True)
            thread.start()
            bound.wait(timeout=args.timeout)
            port = resolved["port"]
            if listen_side == "payload":
                attacker_result = connect(args.host, port, mode=args.mode,
                                          once=args.once,
                                          timeout=args.timeout,
                                          quiet=args.quiet)
            else:
                payload_result = serve(args.host, port, mode=args.mode,
                                       once=args.once, timeout=args.timeout,
                                       quiet=args.quiet)
            done.wait(timeout=args.timeout + 5)
            thread.join(timeout=5)
    except KeyboardInterrupt:
        print("\n[lab] interrupted - closing sockets", file=sys.stderr)
        if payload_result is None:
            payload_result = {"role": "payload", "status": "interrupted"}
        if attacker_result is None:
            attacker_result = {"role": "attacker", "status": "interrupted"}

    if args.json:
        reported_port = args.port
        for res in (attacker_result, payload_result):
            if res and res.get("port"):
                reported_port = res["port"]
                break
        out = {"mode": args.mode, "host": args.host, "port": reported_port,
               "scope": "127.0.0.1 only - no remote targeting"}
        if payload_result is not None:
            out["payload"] = payload_result
        if attacker_result is not None:
            out["attacker"] = attacker_result
        print(json.dumps(out, indent=2, default=str))
    else:
        for label, res in (("payload", payload_result),
                           ("attacker", attacker_result)):
            if res is None:
                continue
            executed = len(res.get("commands", []))
            print(f"[{label}] status={res.get('status')} "
                  f"session_end={res.get('session_end', '-')} "
                  f"commands={executed} duration={res.get('duration_s', 0)}s")

    ok = True
    for res in (payload_result, attacker_result):
        if res is not None and res.get("status") in ("error", "timeout"):
            ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
