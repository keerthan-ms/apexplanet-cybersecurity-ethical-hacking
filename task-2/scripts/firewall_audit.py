#!/usr/bin/env python3
"""
Task 2 - read-only Windows Firewall audit.

READ-ONLY by construction: this script only runs Get-NetFirewall* and
Get-Net*Connection queries through PowerShell (-NoProfile). Querying the
firewall needs no administrator rights on Windows; changing rules does.
This session is not elevated, so no change was attempted or is possible.

What it reports:
    - profile states (Domain / Private / Public) and their default actions;
    - enabled inbound ALLOW rules, grouped by direction and profile;
    - rules whose remote address is 'Any' (any host may trigger them);
    - rules allowing inbound traffic from 'Any' that touch a port this
      machine is actually listening on;
    - the listening TCP/UDP ports themselves (Get-NetTCPConnection /
      Get-NetUDPEndpoint) with owning processes.

Performance note: Get-NetFirewallPortFilter / Get-NetFirewallAddressFilter
cost roughly 150-200 ms per rule when associated with a rule (a bulk,
unassociated query is admin-only and returns Access denied for a standard
user). A full run therefore takes around half a minute on this machine;
--max-rules N caps how many rules get that treatment when a quick check is
enough (the JSON shape is unchanged and the cap is reported in-band).

Graceful degradation: if any cmdlet is unavailable or access is denied the
affected section records the error and the run continues.

Usage:
    python task-2/scripts/firewall_audit.py
    python task-2/scripts/firewall_audit.py --json
    python task-2/scripts/firewall_audit.py --json --max-rules 20
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

PS_TIMEOUT_RULES = 60
PS_TIMEOUT_WORKER = 300
PS_TIMEOUT_LISTEN = 60

READ_ONLY_BANNER = """\
==============================================================================
TASK 2 - WINDOWS FIREWALL AUDIT   *** READ-ONLY ***
==============================================================================
This audit only QUERIES the firewall (Get-NetFirewallProfile,
Get-NetFirewallRule, Get-NetFirewallPortFilter, Get-NetFirewallAddressFilter,
Get-NetTCPConnection, Get-NetUDPEndpoint) via PowerShell -NoProfile.
Querying needs no administrator rights; MODIFYING rules does, and this
session is not elevated - no change was attempted and none is possible here.
=============================================================================="""

META_SCRIPT = r"""
$ErrorActionPreference = "Stop"
$profileRows = @(Get-NetFirewallProfile | ForEach-Object {
  [pscustomobject]@{
    name                   = [string]$_.Name
    enabled                = [bool]$_.Enabled
    default_inbound_action = [string]$_.DefaultInboundAction
    default_outbound_action= [string]$_.DefaultOutboundAction
  }
})
$ruleRows = @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | ForEach-Object {
  [pscustomobject]@{
    name         = [string]$_.Name
    display_name = [string]$_.DisplayName
    profile      = [string]$_.Profile
    direction    = [string]$_.Direction
    action       = [string]$_.Action
    grouping     = [string]$_.Group
  }
})
ConvertTo-Json -InputObject ([pscustomobject]@{ profiles = $profileRows; rules = $ruleRows }) -Depth 4 -Compress
"""

LISTEN_SCRIPT = r"""
$ErrorActionPreference = "Stop"
$procNames = @{}
Get-Process | ForEach-Object { $procNames[[int]$_.Id] = [string]$_.ProcessName }
$tcpRows = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
  [pscustomobject]@{
    protocol = "TCP"
    address  = [string]$_.LocalAddress
    port     = [int]$_.LocalPort
    pid      = [int]$_.OwningProcess
    process  = $procNames[[int]$_.OwningProcess]
  }
})
$udpRows = @(Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
  [pscustomobject]@{
    protocol = "UDP"
    address  = [string]$_.LocalAddress
    port     = [int]$_.LocalPort
    pid      = [int]$_.OwningProcess
    process  = $procNames[[int]$_.OwningProcess]
  }
})
ConvertTo-Json -InputObject ([pscustomobject]@{ tcp = $tcpRows; udp = $udpRows }) -Depth 4 -Compress
"""

WORKER_SCRIPT = r"""
$ErrorActionPreference = "Stop"
$names = ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%%NAMES_B64%%')))
$rows = @(foreach ($rule in @(Get-NetFirewallRule -Name $names)) {
  $portFilter = $rule | Get-NetFirewallPortFilter
  $addrFilter = $rule | Get-NetFirewallAddressFilter
  [pscustomobject]@{
    name           = [string]$rule.Name
    display_name   = [string]$rule.DisplayName
    profile        = [string]$rule.Profile
    protocol       = [string]$portFilter.Protocol
    local_port     = [string]$portFilter.LocalPort
    remote_port    = [string]$portFilter.RemotePort
    local_address  = [string](@($addrFilter.LocalAddress) -join ",")
    remote_address = [string](@($addrFilter.RemoteAddress) -join ",")
  }
})
ConvertTo-Json -InputObject $rows -Depth 4 -Compress
"""


# ------------------------------------------------------- PowerShell bridge ---

def run_powershell(script: str, timeout: float = PS_TIMEOUT_RULES,
                   executable: str = "powershell") -> dict:
    """Run one PowerShell snippet via -EncodedCommand. Never raises.

    Returns {"ok", "stdout", "stderr", "returncode", "error"}. Any failure
    (missing executable, timeout, non-zero exit) is reported in-band so the
    caller can degrade instead of crashing.
    """
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    command = [executable, "-NoProfile", "-NonInteractive",
               "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded]
    try:
        proc = subprocess.run(command, capture_output=True, text=True,
                              timeout=timeout)
    except FileNotFoundError:
        return {"ok": False, "stdout": "", "stderr": "",
                "returncode": None,
                "error": f"executable not found: {executable}"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "stdout": "", "stderr": "",
                "returncode": None,
                "error": f"timed out after {timeout:.0f}s"}
    except OSError as exc:
        return {"ok": False, "stdout": "", "stderr": "",
                "returncode": None,
                "error": f"{type(exc).__name__}: {exc}"}

    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()
    if proc.returncode != 0:
        detail = stderr.splitlines()[0] if stderr else f"exit code {proc.returncode}"
        return {"ok": False, "stdout": stdout, "stderr": stderr,
                "returncode": proc.returncode,
                "error": f"PowerShell failed: {detail}"}
    if not stdout:
        return {"ok": False, "stdout": stdout, "stderr": stderr,
                "returncode": proc.returncode,
                "error": "PowerShell produced no output"}
    return {"ok": True, "stdout": stdout, "stderr": stderr,
            "returncode": proc.returncode, "error": None}


def _load_json_blob(result: dict, what: str, degraded: list[str]):
    """Parse the JSON a PowerShell run should have produced, or degrade."""
    if not result["ok"]:
        degraded.append(f"{what}: {result['error']}")
        return None
    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError as exc:
        degraded.append(f"{what}: unparseable JSON ({exc})")
        return None


def _as_list(value) -> list:
    """ConvertTo-Json turns single-element arrays into bare objects; normalise."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


# ------------------------------------------------------------- collectors ---

def collect_meta() -> tuple[dict, list[dict], list[str]]:
    degraded: list[str] = []
    result = run_powershell(META_SCRIPT, timeout=PS_TIMEOUT_RULES)
    blob = _load_json_blob(result, "firewall profiles/rules", degraded)
    if blob is None:
        return [], [], degraded
    profiles = _as_list(blob.get("profiles"))
    rules = _as_list(blob.get("rules"))
    return profiles, rules, degraded


def collect_listeners() -> tuple[list[dict], list[dict], list[str]]:
    degraded: list[str] = []
    result = run_powershell(LISTEN_SCRIPT, timeout=PS_TIMEOUT_LISTEN)
    blob = _load_json_blob(result, "listening sockets", degraded)
    if blob is None:
        return [], [], degraded
    return _as_list(blob.get("tcp")), _as_list(blob.get("udp")), degraded


def collect_rule_details(rule_names: list[str], workers: int) -> tuple[dict, list[str]]:
    """Per-rule port/address details through PowerShell.

    Each rule's filters are fetched by explicit association
    (``$rule | Get-NetFirewallPortFilter``) rather than a bulk query: an
    unassociated bulk query needs administrator rights and fails with
    Access denied for a standard user. Each associated lookup costs roughly
    150-200 ms, and parallel PowerShell processes contend on the same WMI
    provider (measured slower overall), so the default is one worker.
    """
    degraded: list[str] = []
    details: dict[str, dict] = {}
    if not rule_names:
        return details, degraded

    chunk_size = max(1, math.ceil(len(rule_names) / max(1, workers)))
    slices = [rule_names[i:i + chunk_size]
              for i in range(0, len(rule_names), chunk_size)]

    def run_slice(names: list[str]) -> dict:
        names_b64 = base64.b64encode(
            json.dumps(names).encode("utf-8")).decode("ascii")
        # Placeholder replacement, not str.format: the PowerShell script
        # itself is full of braces.
        script = WORKER_SCRIPT.replace("%%NAMES_B64%%", names_b64)
        return run_powershell(script, timeout=PS_TIMEOUT_WORKER)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(run_slice, slice_): slice_ for slice_ in slices}
        for future in as_completed(futures):
            slice_ = futures[future]
            result = future.result()
            blob = _load_json_blob(
                result, f"rule detail slice ({len(slice_)} rules)", degraded)
            if blob is None:
                continue
            for row in _as_list(blob):
                name = row.get("name")
                if name:
                    details[name] = row
    return details, degraded


# -------------------------------------------------------------- analysis ---

def parse_port_field(value: str | None) -> tuple[str, object]:
    """Interpret a firewall LocalPort field.

    Returns ('any', None), ('set', {ports}) or ('unknown', raw string).
    Handles comma lists ('80, 443'), ranges ('80-90') and named sets the
    cmdlet sometimes reports, which are kept verbatim as unknown.
    """
    if value is None:
        return "unknown", ""
    text = str(value).strip()
    if text.lower() == "any":
        return "any", None
    ports: set[int] = set()
    for token in text.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            bounds = token.split("-", 1)
            if bounds[0].strip().isdigit() and bounds[1].strip().isdigit():
                ports.update(range(int(bounds[0]), int(bounds[1]) + 1))
            else:
                return "unknown", text
        elif token.isdigit():
            ports.add(int(token))
        else:
            return "unknown", text
    if ports:
        return "set", ports
    return "unknown", text


def group_rules(rules: list[dict]) -> dict:
    by_profile: dict[str, int] = {}
    by_direction: dict[str, int] = {}
    for rule in rules:
        profile = rule.get("profile") or "?"
        direction = rule.get("direction") or "?"
        by_profile[profile] = by_profile.get(profile, 0) + 1
        by_direction[direction] = by_direction.get(direction, 0) + 1
    return {"by_profile": dict(sorted(by_profile.items())),
            "by_direction": dict(sorted(by_direction.items()))}


def permissive_rules(rules: list[dict]) -> list[dict]:
    """Inbound ALLOW rules whose remote address includes Any."""
    out = []
    for rule in rules:
        remote = str(rule.get("remote_address") or "")
        parts = [part.strip() for part in remote.split(",") if part.strip()]
        if "Any" in parts:
            out.append({
                "name": rule.get("name"),
                "display_name": rule.get("display_name"),
                "profile": rule.get("profile"),
                "protocol": rule.get("protocol"),
                "local_port": rule.get("local_port"),
                "remote_address": remote,
            })
    return out


def _listening_ports(listeners: list[dict], protocol: str) -> set[int]:
    return {int(row["port"]) for row in listeners
            if row.get("protocol") == protocol and str(row.get("port")).isdigit()}


def exposed_rules(rules: list[dict], tcp_listeners: list[dict],
                  udp_listeners: list[dict]) -> list[dict]:
    """Inbound ALLOW + remote Any + a local port this machine listens on."""
    tcp_ports = _listening_ports(tcp_listeners, "TCP")
    udp_ports = _listening_ports(udp_listeners, "UDP")
    findings = []
    for rule in permissive_rules(rules):
        remote_parts = [p.strip() for p in str(rule.get("remote_address", "")).split(",")]
        if "Any" not in remote_parts:
            continue
        proto = str(rule.get("protocol") or "").upper()
        kind, ports = parse_port_field(rule.get("local_port"))
        if proto == "TCP":
            listening, proto_label = tcp_ports, "TCP"
        elif proto == "UDP":
            listening, proto_label = udp_ports, "UDP"
        elif proto in ("", "ANY"):
            listening, proto_label = tcp_ports | udp_ports, "TCP+UDP"
        else:
            continue  # ICMP etc. - no listening-socket equivalent here
        if kind == "any":
            matches = sorted(listening)
            basis = "local port filter is Any (applies to every listening port)"
        elif kind == "set":
            matches = sorted(ports & listening)
            basis = f"local port filter {rule.get('local_port')!r}"
        else:
            continue
        if matches:
            findings.append({
                "name": rule.get("name"),
                "display_name": rule.get("display_name"),
                "profile": rule.get("profile"),
                "protocol": proto_label,
                "local_port": rule.get("local_port"),
                "remote_address": rule.get("remote_address"),
                "matching_listening_ports": matches[:40],
                "match_count": len(matches),
                "basis": basis,
            })
    findings.sort(key=lambda item: (-item["match_count"],
                                    str(item.get("display_name"))))
    return findings


# -------------------------------------------------------------------- run ---

def audit(ps_workers: int = 1, max_rules: int = 0) -> dict:
    start = time.perf_counter()
    degraded: list[str] = []

    # Listening sockets are collected concurrently with the rule work; the
    # filter lookups below dominate the runtime.
    listen_pool = ThreadPoolExecutor(max_workers=1)
    listen_future = listen_pool.submit(collect_listeners)

    profiles, rules, meta_degraded = collect_meta()
    degraded.extend(meta_degraded)

    detailed_rules = rules if max_rules <= 0 else rules[:max_rules]
    if 0 < max_rules < len(rules):
        degraded.append(
            f"--max-rules {max_rules}: port/address details fetched for only "
            f"the first {max_rules} of {len(rules)} rules; permissive-rule "
            f"and exposure analysis is partial")

    details, detail_degraded = collect_rule_details(
        [rule["name"] for rule in detailed_rules if rule.get("name")],
        ps_workers)
    degraded.extend(detail_degraded)

    tcp_listeners, udp_listeners, listen_degraded = listen_future.result()
    listen_pool.shutdown(wait=False)
    degraded.extend(listen_degraded)

    enriched = []
    missing_details = 0
    capped_names = {rule.get("name") for rule in rules[len(detailed_rules):]}
    for rule in rules:
        row = dict(rule)
        detail = details.get(rule.get("name"))
        if detail:
            row.update({key: detail.get(key) for key in
                        ("protocol", "local_port", "remote_port",
                         "local_address", "remote_address")})
        else:
            missing_details += 1
            row["detail_error"] = ("not fetched (--max-rules cap)"
                                   if rule.get("name") in capped_names
                                   else "port/address filter not retrieved")
        enriched.append(row)

    groups = group_rules(enriched)
    permissive = [row for row in permissive_rules(enriched)]
    exposed = exposed_rules(enriched, tcp_listeners, udp_listeners)

    return {
        "tool": "task-2/firewall_audit.py",
        "generated": datetime.now().astimezone().isoformat(timespec="seconds"),
        "read_only": True,
        "elevation_note": (
            "READ-ONLY: querying the firewall needs no administrator rights; "
            "changing rules does. This session is not elevated, so no change "
            "was attempted or is possible."),
        "ps_worker_processes": ps_workers,
        "max_rules_cap": max_rules if max_rules > 0 else "all",
        "profiles": profiles,
        "inbound_allow_rules": {
            "count": len(enriched),
            "with_details": len(enriched) - missing_details,
            "missing_details": missing_details,
            "by_profile": groups["by_profile"],
            "by_direction": groups["by_direction"],
            "rules": enriched,
        },
        "permissive_rules": permissive,
        "listening_ports": {"tcp": tcp_listeners, "udp": udp_listeners},
        "listening_exposed": exposed,
        "degraded": degraded,
        "elapsed_seconds": round(time.perf_counter() - start, 2),
    }


# ----------------------------------------------------------------- output ---

def print_report(result: dict) -> None:
    print(READ_ONLY_BANNER)
    print(f"generated: {result['generated']}   "
          f"({result['elapsed_seconds']}s, "
          f"{result['ps_worker_processes']} PowerShell worker processes)")
    print()

    print("Firewall profiles:")
    if not result["profiles"]:
        print("  (unavailable - see degraded notes)")
    for profile in result["profiles"]:
        print(f"  {profile.get('name', '?'):<8} "
              f"enabled={profile.get('enabled')}   "
              f"default inbound: {profile.get('default_inbound_action')}   "
              f"default outbound: {profile.get('default_outbound_action')}")
    print()

    rules = result["inbound_allow_rules"]
    print(f"Enabled inbound ALLOW rules: {rules['count']} "
          f"(details retrieved for {rules['with_details']})")
    print(f"  by profile : {rules['by_profile']}")
    print(f"  by direction: {rules['by_direction']}")
    print()

    permissive = result["permissive_rules"]
    print(f"Rules with remote address 'Any' (any host may trigger them): "
          f"{len(permissive)}")
    for rule in permissive[:8]:
        print(f"  - {rule['display_name']} [{rule['profile']}] "
              f"{rule['protocol']}/{rule['local_port']}")
    if len(permissive) > 8:
        print(f"  ... and {len(permissive) - 8} more (full list with --json)")
    print()

    listeners = result["listening_ports"]
    print(f"Listening sockets: {len(listeners['tcp'])} TCP, "
          f"{len(listeners['udp'])} UDP")
    for row in sorted(listeners["tcp"], key=lambda r: int(r["port"]))[:12]:
        print(f"  TCP {row['address']}:{row['port']} ({row.get('process')})")
    if len(listeners["tcp"]) > 12:
        print(f"  ... and {len(listeners['tcp']) - 12} more TCP listeners")
    print()

    exposed = result["listening_exposed"]
    print(f"Inbound-ALLOW-from-Any rules touching a listening port: "
          f"{len(exposed)}")
    for finding in exposed[:10]:
        ports = finding["matching_listening_ports"][:8]
        more = "" if finding["match_count"] <= 8 else f" (+{finding['match_count'] - 8} more)"
        print(f"  - {finding['display_name']} [{finding['profile']}] "
              f"{finding['protocol']} ports {ports}{more}")
    if len(exposed) > 10:
        print(f"  ... and {len(exposed) - 10} more (full list with --json)")
    print()

    if result["degraded"]:
        print("Degraded sections (run continued anyway):")
        for note in result["degraded"]:
            print(f"  - {note}")
    else:
        print("Degraded sections: none")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only Windows Firewall audit (no elevation required "
                    "to query; changes are out of scope by design).")
    parser.add_argument("--json", action="store_true",
                        help="emit machine-readable JSON on stdout")
    parser.add_argument("--ps-workers", type=int, default=1, metavar="N",
                        help="PowerShell worker processes for rule details "
                             "(default 1; parallel workers contend on the "
                             "WMI provider and are usually slower)")
    parser.add_argument("--max-rules", type=int, default=0, metavar="N",
                        help="fetch port/address details for only the first "
                             "N rules (0 = all, the default); a quick-run "
                             "mode that makes the analysis partial")
    args = parser.parse_args(argv)

    result = audit(ps_workers=max(1, args.ps_workers),
                   max_rules=max(0, args.max_rules))
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_report(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
