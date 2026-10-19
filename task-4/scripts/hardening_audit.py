#!/usr/bin/env python3
"""Read-only Windows hardening audit (Task 4: system security).

Usage:
    python task-4/scripts/hardening_audit.py
    python task-4/scripts/hardening_audit.py --profile quick
    python task-4/scripts/hardening_audit.py --profile quick --json
    python task-4/scripts/hardening_audit.py --profile full --host-label lab-box

What this tool does
    Runs a fixed set of PowerShell/OS queries that only *read* configuration
    (system context, firewall profiles, remote services, SMB, UAC, password
    policy, local administrators, Defender, hotfix recency, audit policy,
    Winlogon auto-logon secrets, listening TCP ports), turns every finding
    into a scored check, and prints a report with a total score, a severity
    band and the top remediation actions.

What it never does
    No system setting is written, no service or account is changed, no
    process is stopped. The only file ever created is a short-lived secedit
    export inside %TEMP% (password-complexity check, full profile only) that
    is deleted immediately afterwards; it does not alter any configuration.

Profiles
    quick  - five fast collectors (context, firewall, remote services,
             Defender, listening ports); this is what the test suite runs.
    full   - all twelve collectors. Collectors that need an elevated token
             (audit policy, secedit export) come back as "skipped" instead
             of aborting the run.

Output
    Human report by default, or a single JSON document with --json:
    {tool, mode, generated_utc, profile, host, collectors, summary,
    remediation} where summary holds score/band/counts and remediation is
    the priority-ordered list of at most ten actions.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Callable

SCRIPT_NAME = "hardening_audit.py"
MODE = ("READ-ONLY: configuration values were read only - no system setting "
        "was changed, no service, account or registry value was modified")
POWERSHELL = "powershell"
DEFAULT_TIMEOUT = 20.0
PROFILES = ("quick", "full")
RESULT_STATUSES = ("pass", "warn", "fail", "info", "skipped")

SEVERITY_WEIGHT = {"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.5}
STATUS_MARKER = {"pass": "PASS", "warn": "WARN", "fail": "FAIL",
                 "info": "INFO", "skipped": "SKIP"}
RISKY_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 69: "TFTP", 512: "rexec",
    513: "rlogin", 514: "rsh", 3389: "RDP", 5000: "DB2/UPnP?",
    5900: "VNC", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
    27017: "MongoDB",
}


class AuditError(Exception):
    """A collector command failed (non-zero exit, bad JSON, no output)."""


class AuditTimeout(AuditError):
    """A collector command exceeded its time budget."""


# --------------------------------------------------------------- collectors --

SYSTEM_CONTEXT_PS = r"""
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
$up = New-TimeSpan -Start $os.LastBootUpTime -End (Get-Date)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$obj = [pscustomobject]@{
  Caption = [string]$os.Caption
  Version = [string]$os.Version
  Build = [string]$os.BuildNumber
  PSVersion = "$($PSVersionTable.PSVersion)"
  IsAdmin = [bool]$isAdmin
  UptimeHours = [math]::Round($up.TotalHours, 1)
  Computer = [string]$env:COMPUTERNAME
  User = [string]$env:USERNAME
}
ConvertTo-Json -InputObject @($obj) -Compress -Depth 4
"""

FIREWALL_NETSH_CMD = "netsh advfirewall show allprofiles"

FIREWALL_PS = r"""
$profiles = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
  [pscustomobject]@{
    Name = [string]$_.Name
    Enabled = [bool]$_.Enabled
    DefaultInbound = [string]$_.DefaultInboundAction
    DefaultOutbound = [string]$_.DefaultOutboundAction
  }
})
ConvertTo-Json -InputObject @($profiles) -Compress -Depth 4
"""

REMOTE_PS = r"""
$svc = Get-Service -Name WinRM -ErrorAction Stop
$ts = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop
$station = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction Stop
$obj = [pscustomobject]@{
  WinRMStatus = "$($svc.Status)"
  WinRMStartType = "$($svc.StartType)"
  RDPEnabled = [bool](-not $ts.fDenyTSConnections)
  RDPport = [int]$station.PortNumber
  RDPNLA = [bool]($station.UserAuthentication -eq 1)
}
ConvertTo-Json -InputObject @($obj) -Compress -Depth 4
"""

SMB_PS = r"""
$cfg = Get-SmbServerConfiguration -ErrorAction Stop
$defaults = @('C$','D$','E$','F$','G$','H$','ADMIN$','IPC$')
$shares = @(Get-SmbShare -ErrorAction Stop | Where-Object { $defaults -notcontains $_.Name } | ForEach-Object {
  [pscustomobject]@{ Name = [string]$_.Name; Description = [string]$_.Description }
})
$obj = [pscustomobject]@{
  SMBv1 = [bool]$cfg.EnableSMB1Protocol
  RequireSigning = [bool]$cfg.RequireSecuritySignature
  EncryptData = [bool]$cfg.EncryptData
  Shares = @($shares)
}
ConvertTo-Json -InputObject @($obj) -Compress -Depth 6
"""

UAC_PS = r"""
$p = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
$obj = [pscustomobject]@{
  EnableLUA = [int]$p.EnableLUA
  ConsentPromptBehaviorAdmin = [int]$p.ConsentPromptBehaviorAdmin
  PromptOnSecureDesktop = [int]$p.PromptOnSecureDesktop
}
ConvertTo-Json -InputObject @($obj) -Compress -Depth 4
"""

NET_ACCOUNTS_CMD = "net accounts"

SECEDIT_PS = r"""
$f = Join-Path $env:TEMP ('hardening_' + [guid]::NewGuid().ToString('N') + '.inf')
try {
  & secedit.exe /export /cfg $f /areas SECURITYPOLICY *> $null
  if (Test-Path -LiteralPath $f) {
    $lines = @(Get-Content -LiteralPath $f | Where-Object { $_ -match '^PasswordComplexity' })
    ConvertTo-Json -InputObject @($lines) -Compress
  } else {
    ConvertTo-Json -InputObject @('SECEdit_EXPORT_FAILED') -Compress
  }
} catch {
  ConvertTo-Json -InputObject @('SECEdit_ERROR: ' + $_.Exception.Message) -Compress
} finally {
  Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
}
"""

LOCAL_ADMINS_PS = r"""
$members = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object { [string]$_.Name })
$guest = $null
try { $guest = [bool](Get-LocalUser -Name 'Guest' -ErrorAction Stop).Enabled } catch { $guest = $null }
$obj = [pscustomobject]@{
  Admins = @($members)
  Count = $members.Count
  GuestEnabled = $guest
}
ConvertTo-Json -InputObject @($obj) -Compress -Depth 5
"""

DEFENDER_PS = r"""
$s = Get-MpComputerStatus -ErrorAction Stop
$obj = [pscustomobject]@{
  AntivirusEnabled = [bool]$s.AntivirusEnabled
  RealTimeProtection = [bool]$s.RealTimeProtectionEnabled
  AMService = [bool]$s.AMServiceEnabled
  SignatureAgeDays = [int]$s.AntivirusSignatureAge
  SignatureUpdated = "$($s.AntivirusSignatureLastUpdated)"
}
ConvertTo-Json -InputObject @($obj) -Compress -Depth 4
"""

HOTFIX_PS = r"""
$items = @(Get-HotFix -ErrorAction Stop | ForEach-Object {
  $d = $null
  try { if ($_.InstalledOn) { $d = [datetime]$_.InstalledOn } } catch { $d = $null }
  if ($d) { [pscustomobject]@{ HotFixID = [string]$_.HotFixID; InstalledOn = $d.ToString('yyyy-MM-dd'); AgeDays = [int]((New-TimeSpan -Start $d -End (Get-Date)).TotalDays) } }
})
$latest = $null
if ($items.Count -gt 0) { $latest = @($items | Sort-Object AgeDays | Select-Object -First 1)[0] }
$age = -1
$hid = ''
$idate = ''
if ($latest) { $age = [int]$latest.AgeDays; $hid = "$($latest.HotFixID)"; $idate = "$($latest.InstalledOn)" }
$obj = [pscustomobject]@{
  ParsedCount = $items.Count
  LatestHotFix = $hid
  LatestDate = $idate
  AgeDays = $age
}
ConvertTo-Json -InputObject @($obj) -Compress -Depth 4
"""

AUDITPOL_CMD = "auditpol /get /category:*"

WINLOGON_PS = r"""
$p = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction Stop
$pwdPresent = $false
if ($null -ne $p.DefaultPassword -and ([string]$p.DefaultPassword).Length -gt 0) { $pwdPresent = $true }
$obj = [pscustomobject]@{
  AutoAdminLogon = [string]$p.AutoAdminLogon
  DefaultUserName = [string]$p.DefaultUserName
  DefaultDomainName = [string]$p.DefaultDomainName
  DefaultPasswordPresent = [bool]$pwdPresent
}
ConvertTo-Json -InputObject @($obj) -Compress -Depth 4
"""

LISTENING_PS = r"""
$rows = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
  $pname = ''
  try { $pname = (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName } catch { $pname = '' }
  [pscustomobject]@{ Port = [int]$_.LocalPort; Address = [string]$_.LocalAddress; Process = $pname }
})
$uniq = @($rows | Sort-Object Address, Port -Unique)
ConvertTo-Json -InputObject @($uniq) -Compress -Depth 4
"""


def _run_ps(command: str, timeout: float) -> str:
    """Run one PowerShell command and return its stdout."""
    body = ("try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false) } catch { }; "
            + command)
    try:
        proc = subprocess.run(
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
             "Bypass", "-Command", body],
            capture_output=True, encoding="utf-8", errors="replace",
            timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise AuditTimeout("powershell timed out after "
                           f"{exc.timeout:.0f}s") from exc
    except OSError as exc:
        raise AuditError(f"could not start powershell: {exc}") from exc
    if proc.returncode != 0:
        message = (proc.stderr or proc.stdout or "").strip()
        if not message:
            message = f"powershell exited {proc.returncode}"
        raise AuditError(" ".join(message.split())[:300])
    return (proc.stdout or "").strip()


def _ps_json(command: str, timeout: float) -> object:
    """Run a PowerShell command that emits a JSON document and parse it."""
    text = _run_ps(command, timeout)
    if not text:
        raise AuditError("no output from powershell")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise AuditError(f"non-JSON output: {text[:200]}") from exc


def _one(parsed: object) -> dict:
    """Normalise `ConvertTo-Json -InputObject @($obj)` single-item arrays."""
    if isinstance(parsed, list):
        if not parsed:
            raise AuditError("empty JSON array")
        parsed = parsed[0]
    if not isinstance(parsed, dict):
        raise AuditError(f"unexpected JSON type: {type(parsed).__name__}")
    return parsed


def check(cid: str, title: str, status: str, detail: str = "",
          severity: str = "medium", remediation: str = "") -> dict:
    """Build one scored check record."""
    if status not in RESULT_STATUSES:
        raise ValueError(f"bad check status: {status}")
    return {
        "id": cid,
        "title": title,
        "status": status,
        "severity": severity if status in ("pass", "warn", "fail") else "info",
        "detail": detail,
        "remediation": remediation,
        "weight": SEVERITY_WEIGHT.get(severity, 1.0),
    }


def collect_system_context(timeout: float) -> list[dict]:
    """Host identity, elevation state and uptime (informational)."""
    data = _one(_ps_json(SYSTEM_CONTEXT_PS, timeout))
    uptime = float(data.get("UptimeHours") or 0.0)
    return [
        check("computer_name", "Host name", "info",
              str(data.get("Computer", "?"))),
        check("os_context", "Operating system", "info",
              f"{data.get('Caption', '?')} (build {data.get('Build', '?')}), "
              f"PowerShell {data.get('PSVersion', '?')}, user {data.get('User', '?')}"),
        check("elevation", "Token elevation", "info",
              "admin token: {flag} - collectors needing elevation report 'skipped'"
              .format(flag="yes" if data.get("IsAdmin") else "no")),
        check("uptime", "Time since last reboot", "info",
              f"{uptime} hour(s)"),
    ]


def _parse_netsh_firewall(text: str) -> list[dict]:
    """Split `netsh advfirewall show allprofiles` into profile dictionaries."""
    profiles: dict[str, dict] = {}
    current: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        header = re.match(r"^(Domain|Private|Public)\s+Profile\s+Settings\s*:\s*$",
                          line, flags=re.IGNORECASE)
        if header:
            current = header.group(1).capitalize()
            profiles[current] = {"Name": current, "Enabled": False,
                                 "DefaultInbound": "?", "Policy": ""}
            continue
        if current is None:
            continue
        state = re.match(r"^State\s+(\S+)\s*$", line, flags=re.IGNORECASE)
        if state:
            profiles[current]["Enabled"] = state.group(1).upper() == "ON"
            continue
        policy = re.match(r"^Firewall Policy\s+(\S+)\s*$", line,
                          flags=re.IGNORECASE)
        if policy:
            first = policy.group(1).split(",")[0].lower()
            profiles[current]["Policy"] = policy.group(1)
            profiles[current]["DefaultInbound"] = (
                "Allow" if "allowinbound" in first else "Block")
    return list(profiles.values())


def collect_firewall_profiles(timeout: float) -> list[dict]:
    """Windows Defender Firewall: profile state and inbound policy.

    `netsh advfirewall show allprofiles` reports the *effective* policy and
    costs about 0.2 s; Get-NetFirewallProfile costs about 5.6 s, so the
    cmdlet is only the fallback if the netsh text cannot be parsed (for
    example on a localised system).
    """
    profiles: list[dict] = []
    try:
        profiles = _parse_netsh_firewall(_run_ps(FIREWALL_NETSH_CMD, timeout))
    except AuditError:
        profiles = []
    if not profiles:
        parsed = _ps_json(FIREWALL_PS, timeout)
        if isinstance(parsed, dict):
            parsed = [parsed]
        profiles = [{
            "Name": str(item.get("Name", "?")),
            "Enabled": bool(item.get("Enabled")),
            # "NotConfigured" means the Windows default, which is Block
            "DefaultInbound": ("Allow"
                               if str(item.get("DefaultInbound", "")).lower() == "allow"
                               else "Block"),
        } for item in parsed]
    checks: list[dict] = []
    for profile in profiles:
        name = str(profile.get("Name", "?"))
        enabled = bool(profile.get("Enabled"))
        checks.append(check(
            f"firewall_{name.lower()}", f"Firewall {name} profile",
            "pass" if enabled else "fail",
            detail=f"state={'ON' if enabled else 'OFF'}, "
                   f"policy={profile.get('Policy') or profile.get('DefaultInbound')}",
            severity="high" if not enabled else "medium",
            remediation="" if enabled else
            f"Enable the {name} profile: Set-NetFirewallProfile -Profile {name} -Enabled True",
        ))
    enabled_profiles = [p for p in profiles if p.get("Enabled")]
    if not enabled_profiles:
        checks.append(check("firewall_inbound", "Default inbound action",
                            "skipped", "no enabled profile to inspect"))
    else:
        allowing = [p.get("Name") for p in enabled_profiles
                    if str(p.get("DefaultInbound", "")).lower() == "allow"]
        checks.append(check(
            "firewall_inbound", "Default inbound action",
            "pass" if not allowing else "warn",
            detail=("all enabled profiles block inbound by default"
                    if not allowing else
                    f"Allow by default on: {', '.join(map(str, allowing))}"),
            severity="medium",
            remediation="" if not allowing else
            "Set the default inbound action to Block: Set-NetFirewallProfile -Profile "
            + ", ".join(map(str, allowing)) + " -DefaultInboundAction Block",
        ))
    return checks


def collect_remote_services(timeout: float) -> list[dict]:
    """WinRM service state and Remote Desktop exposure."""
    data = _one(_ps_json(REMOTE_PS, timeout))
    winrm = str(data.get("WinRMStatus", ""))
    rdp_on = bool(data.get("RDPEnabled"))
    rdp_port = data.get("RDPport")
    checks = [
        check(
            "winrm_status", "WinRM remote management",
            "pass" if winrm.lower() != "running" else "warn",
            detail=f"service status={winrm}, start type={data.get('WinRMStartType')}",
            severity="medium",
            remediation="" if winrm.lower() == "running" else
            "If remote PowerShell is not required, disable it: "
            "Set-Service WinRM -StartupType Disabled",
        ),
        check(
            "rdp_enabled", "Remote Desktop (RDP)",
            "fail" if rdp_on else "pass",
            detail=(f"RDP enabled on port {rdp_port}, "
                    f"NLA={'on' if data.get('RDPNLA') else 'off'}" if rdp_on
                    else "RDP is disabled (fDenyTSConnections=1)"),
            severity="high",
            remediation="" if not rdp_on else
            "Disable RDP or restrict it to a management VLAN "
            "(fDenyTSConnections=1 and the firewall rule 'Remote Desktop (TCP-In)')",
        ),
    ]
    if rdp_on and not data.get("RDPNLA"):
            checks.append(check(
                "rdp_nla", "RDP Network Level Authentication",
                "fail", "RDP is reachable without NLA",
                severity="high",
                remediation="Require NLA for RDP: set UserAuthentication=1 under "
                            "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
            ))
    return checks


def collect_smb_shares(timeout: float) -> list[dict]:
    """SMB server hardening: SMBv1, signing and non-default shares."""
    data = _one(_ps_json(SMB_PS, timeout))
    shares = data.get("Shares") or []
    share_names = [str(s.get("Name")) for s in shares] if isinstance(shares, list) else []
    return [
        check(
            "smb_v1", "SMBv1 protocol",
            "fail" if data.get("SMBv1") else "pass",
            detail=f"EnableSMB1Protocol={bool(data.get('SMBv1'))}",
            severity="critical" if data.get("SMBv1") else "medium",
            remediation="" if data.get("SMBv1") else
            "Disable the legacy SMBv1 protocol: "
            "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force (elevated)",
        ),
        check(
            "smb_signing", "SMB signing",
            "pass" if data.get("RequireSigning") else "warn",
            detail=f"RequireSecuritySignature={bool(data.get('RequireSigning'))}, "
                   f"EncryptData={bool(data.get('EncryptData'))}",
            severity="medium",
            remediation="" if data.get("RequireSigning") else
            "Require SMB signing: Set-SmbServerConfiguration -RequireSecuritySignature $true -Force",
        ),
        check(
            "smb_shares", "Non-default file shares",
            "warn" if share_names else "pass",
            detail=(f"{len(share_names)} share(s): " + ", ".join(share_names[:8])
                    if share_names else "only the default administrative shares"),
            severity="medium",
            remediation="" if share_names else
            "Review and remove shares that are not business-required: Remove-SmbShare -Name <name>",
        ),
    ]


def collect_uac_policy(timeout: float) -> list[dict]:
    """User Account Control settings."""
    data = _one(_ps_json(UAC_PS, timeout))
    lua = int(data.get("EnableLUA") or 0)
    consent = int(data.get("ConsentPromptBehaviorAdmin") or 0)
    secure = int(data.get("PromptOnSecureDesktop") or 0)
    if consent == 0:
        consent_status, consent_note = "fail", "elevation happens without any prompt"
    elif consent in (1, 3, 5):
        consent_status, consent_note = "pass", f"ConsentPromptBehaviorAdmin={consent}"
    else:
        consent_status, consent_note = "warn", f"ConsentPromptBehaviorAdmin={consent} (prompt off the secure desktop or credential-style)"
    return [
        check("uac_enabled", "UAC (EnableLUA)",
              "pass" if lua == 1 else "fail",
              detail=f"EnableLUA={lua}",
              severity="high" if lua != 1 else "medium",
              remediation="" if lua == 1 else
              "Turn UAC on: Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' EnableLUA 1 (reboot required)"),
        check("uac_prompt", "UAC elevation prompt", consent_status, consent_note,
              severity="medium",
              remediation="" if consent_status == "pass" else
              "Set ConsentPromptBehaviorAdmin to 5 (prompt for consent on the secure desktop)"),
        check("uac_secure_desktop", "UAC secure desktop",
              "pass" if secure == 1 else "warn",
              detail=f"PromptOnSecureDesktop={secure}",
              severity="low",
              remediation="" if secure == 1 else
              "Set PromptOnSecureDesktop to 1 so the elevation prompt dims the desktop"),
    ]


def collect_password_policy(timeout: float) -> list[dict]:
    """Account policy from `net accounts`, plus complexity via secedit."""
    text = _run_ps(NET_ACCOUNTS_CMD, timeout)
    checks: list[dict] = []

    def field(pattern: str) -> str | None:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        return match.group(1).strip() if match else None

    minimum = field(r"Minimum password length:\s*(\d+)")
    if minimum is None:
        checks.append(check("password_min_length", "Minimum password length",
                            "skipped", "value not reported by 'net accounts'"))
    else:
        length = int(minimum)
        status = "pass" if length >= 12 else ("warn" if length >= 8 else "fail")
        checks.append(check(
            "password_min_length", "Minimum password length", status,
            detail=f"minimum length = {length}",
            severity="medium",
            remediation="" if status == "pass" else
            "Raise the minimum length to 14+ characters "
            "(secpol.msc > Account Policies > Password Policy)",
        ))

    history = field(r"Length of password history maintained:\s*(\S+)")
    kept: int | None = None
    if history is not None:
        if history.isdigit():
            kept = int(history)
        elif history.lower() in ("none", "never"):
            kept = 0
    if kept is None:
        checks.append(check("password_history", "Password history",
                            "skipped", "value not reported by 'net accounts'"))
    else:
        status = "pass" if kept >= 10 else ("warn" if kept >= 5 else "fail")
        checks.append(check(
            "password_history", "Password history", status,
            detail=f"{kept} previous password(s) remembered",
            severity="medium",
            remediation="" if status == "pass" else
            "Remember at least 10 previous passwords (Enforce password history)",
        ))

    maximum = field(r"Maximum password age \(days\):\s*(\S+)")
    checks.append(check(
        "password_max_age", "Maximum password age", "info",
        detail=f"maximum age = {maximum}" if maximum else "not reported",
        remediation="",
    ))

    threshold = field(r"Lockout threshold:\s*(\S+)")
    if threshold is None:
        checks.append(check("lockout_threshold", "Account lockout threshold",
                            "skipped", "value not reported by 'net accounts'"))
    else:
        attempts = int(threshold) if threshold.isdigit() else 0
        if attempts >= 5:
            lock_status, lock_note = "pass", f"{attempts} failed attempts"
            lock_fix = ""
        elif attempts >= 1:
            lock_status, lock_note = ("warn",
                                      f"{attempts} attempt(s) - a small threshold "
                                      "lets an attacker lock every account on purpose")
            lock_fix = ("Set the lockout threshold to 5-10 attempts "
                        "(secpol.msc > Account Policies > Lockout Policy)")
        else:
            lock_status, lock_note = ("warn",
                                      "no lockout threshold - password guessing "
                                      "is never slowed down or recorded")
            lock_fix = ("Enable account lockout: threshold 5, duration 10 minutes, "
                        "reset counter after 10 minutes")
        checks.append(check(
            "lockout_threshold", "Account lockout threshold", lock_status,
            detail=lock_note, severity="medium", remediation=lock_fix,
        ))

    try:
        raw = _run_ps(SECEDIT_PS, timeout)
        parsed = json.loads(raw) if raw else []
        if isinstance(parsed, dict):
            parsed = [parsed]
        complexity = None
        for line in parsed:
            match = re.search(r"PasswordComplexity\s*=\s*(\d+)", str(line))
            if match:
                complexity = int(match.group(1))
                break
        if complexity is None:
            checks.append(check(
                "password_complexity", "Password complexity requirement",
                "skipped",
                detail=str(parsed[0])[:200] if parsed else "secedit export empty",
                severity="medium",
                remediation="Run elevated so the security database can be exported, or "
                            "check secpol.msc > Account Policies > Password Policy",
            ))
        else:
            checks.append(check(
                "password_complexity", "Password complexity requirement",
                "pass" if complexity == 1 else "fail",
                detail=f"PasswordComplexity={complexity} (secedit export, temp file deleted)",
                severity="medium",
                remediation="" if complexity == 1 else
                "Require complex passwords: secedit /set /cfg <file> /db SECENGINE "
                "PasswordComplexity 1 (or Local Security Policy)",
            ))
    except AuditError as exc:
        checks.append(check(
            "password_complexity", "Password complexity requirement",
            "skipped", detail=f"secedit unavailable: {exc}",
            severity="medium",
            remediation="Run the full audit from an elevated prompt to read the "
                        "password-complexity setting",
        ))
    return checks


def collect_local_admins(timeout: float) -> list[dict]:
    """Local Administrators membership and the built-in Guest account."""
    data = _one(_ps_json(LOCAL_ADMINS_PS, timeout))
    admins = data.get("Admins") or []
    count = int(data.get("Count") or len(admins))
    status = "pass" if count <= 2 else ("warn" if count <= 3 else "fail")
    checks = [
        check(
            "local_admins", "Local Administrators group", status,
            detail=f"{count} member(s): " + (", ".join(map(str, admins[:6]))
                                             if admins else "none reported"),
            severity="medium",
            remediation="" if status == "pass" else
            "Reduce standing admin rights: remove accounts that only need "
            "standard user work and use a separate admin identity",
        ),
    ]
    guest = data.get("GuestEnabled")
    if guest is None:
        checks.append(check("guest_account", "Built-in Guest account",
                            "skipped", "could not read the Guest account state",
                            severity="medium",
                            remediation="Confirm Guest is disabled: Get-LocalUser -Name Guest"))
    else:
        checks.append(check(
            "guest_account", "Built-in Guest account",
            "fail" if guest else "pass",
            detail=f"Guest enabled={bool(guest)}",
            severity="medium",
            remediation="" if guest else
            "Disable the Guest account: Disable-LocalUser -Name Guest",
        ))
    return checks


def collect_defender_status(timeout: float) -> list[dict]:
    """Microsoft Defender: service, real-time protection, signature age."""
    data = _one(_ps_json(DEFENDER_PS, timeout))
    age = int(data.get("SignatureAgeDays") if data.get("SignatureAgeDays") is not None else -1)
    if age < 0:
        sig_status, sig_note = "skipped", "signature age not reported"
    elif age <= 7:
        sig_status, sig_note = "pass", f"definitions updated {age} day(s) ago"
    elif age <= 14:
        sig_status, sig_note = "warn", f"definitions are {age} days old"
    else:
        sig_status, sig_note = "fail", f"definitions are {age} days old"
    return [
        check("defender_av", "Antivirus service",
              "pass" if data.get("AntivirusEnabled") else "fail",
              detail=f"AntivirusEnabled={bool(data.get('AntivirusEnabled'))}, "
                     f"AMService={bool(data.get('AMService'))}",
              severity="high",
              remediation="" if data.get("AntivirusEnabled") else
              "Enable Microsoft Defender antivirus, or onboard an approved EDR"),
        check("defender_realtime", "Real-time protection",
              "pass" if data.get("RealTimeProtection") else "fail",
              detail=f"RealTimeProtection={bool(data.get('RealTimeProtection'))}",
              severity="high",
              remediation="" if data.get("RealTimeProtection") else
              "Enable real-time monitoring: Set-MpPreference -DisableRealtimeMonitoring $false"),
        check("defender_signatures", "Malware definition age", sig_status, sig_note,
              severity="medium",
              remediation="" if sig_status in ("pass", "skipped") else
              "Refresh definitions: Update-MpSignature (or wait for the scheduled task)"),
    ]


def collect_hotfix_age(timeout: float) -> list[dict]:
    """Recency of the most recent Windows update."""
    data = _one(_ps_json(HOTFIX_PS, timeout))
    age = int(data.get("AgeDays") if data.get("AgeDays") is not None else -1)
    latest = data.get("LatestHotFix") or ""
    if age < 0:
        return [check("hotfix_age", "Most recent Windows update", "skipped",
                      "no dated hotfix record could be parsed", severity="high",
                      remediation="Check Settings > Windows Update for pending updates")]
    status = "pass" if age <= 30 else ("warn" if age <= 90 else "fail")
    return [check(
        "hotfix_age", "Most recent Windows update", status,
        detail=f"{latest} installed {data.get('LatestDate')} ({age} day(s) ago, "
               f"{data.get('ParsedCount')} update record(s))",
        severity="high",
        remediation="" if status == "pass" else
        "Install pending Windows updates and reboot, then re-run this audit",
    )]


def collect_audit_policy(timeout: float) -> list[dict]:
    """Advanced audit policy coverage (needs an elevated token)."""
    try:
        text = _run_ps(AUDITPOL_CMD, timeout)
    except AuditError as exc:
        return [check(
            "audit_coverage", "Audit policy coverage", "skipped",
            detail=f"auditpol unavailable: {exc}", severity="medium",
            remediation="Re-run from an elevated prompt, then enable success and "
                        "failure auditing for Logon and Account Management",
        )]
    pattern = re.compile(
        r"^\s{2,}(.+?)\s{2,}(No Auditing|Success|Failure|Success and Failure)\s*$")
    total = 0
    audited = 0
    for line in text.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        total += 1
        if match.group(2) != "No Auditing":
            audited += 1
    if total == 0:
        return [check("audit_coverage", "Audit policy coverage", "skipped",
                      "auditpol returned no subcategory lines", severity="medium",
                      remediation="Verify auditpol runs under this account")]
    ratio = audited / total
    status = "pass" if ratio >= 0.6 else ("warn" if ratio >= 0.3 else "fail")
    return [check(
        "audit_coverage", "Audit policy coverage", status,
        detail=f"{audited} of {total} subcategories audited ({ratio:.0%})",
        severity="medium",
        remediation="" if status == "pass" else
        "Enable success/failure auditing (auditpol /set /subcategory:\"...\" "
        "/success:enable /failure:enable) or apply an Advanced Audit Policy GPO",
    )]


def collect_autologon_secrets(timeout: float) -> list[dict]:
    """Winlogon auto-logon configuration - values are reported, never printed."""
    data = _one(_ps_json(WINLOGON_PS, timeout))
    stored = bool(data.get("DefaultPasswordPresent"))
    auto = str(data.get("AutoAdminLogon", "")) == "1"
    user = str(data.get("DefaultUserName", "") or "")
    return [
        check(
            "winlogon_default_password", "Winlogon DefaultPassword value",
            "fail" if stored else "pass",
            detail=("a DefaultPassword value exists - the value itself is NOT "
                    "shown by this tool" if stored else "no DefaultPassword value stored"),
            severity="critical",
            remediation="" if stored else
            "Delete DefaultPassword from HKLM\\SOFTWARE\\Microsoft\\Windows NT\\"
            "CurrentVersion\\Winlogon - it holds the password in plaintext",
        ),
        check(
            "winlogon_auto_logon", "Automatic logon (AutoAdminLogon)",
            "fail" if auto else "pass",
            detail=f"AutoAdminLogon={auto or '(unset)'}",
            severity="high",
            remediation="" if auto else
            "Set AutoAdminLogon to 0 so the workstation always requires a sign-in",
        ),
        check(
            "winlogon_default_user", "Winlogon default user", "info",
            detail=f"DefaultUserName={user or '(not set)'}"
                   + (f", domain={data.get('DefaultDomainName')}"
                      if data.get("DefaultDomainName") else ""),
        ),
    ]


def collect_listening_ports(timeout: float) -> list[dict]:
    """TCP listeners: which ports are bound, and to which addresses."""
    parsed = _ps_json(LISTENING_PS, timeout)
    rows = parsed if isinstance(parsed, list) else [parsed]
    external: list[str] = []
    risky: list[str] = []
    seen: set[tuple[int, str]] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        address = str(row.get("Address", ""))
        port = int(row.get("Port") or 0)
        process = str(row.get("Process") or "?")
        if address.startswith("127.") or address == "::1":
            continue
        if (port, process) in seen:      # the same socket on IPv4 and IPv6
            continue
        seen.add((port, process))
        label = f"{port} ({process})"
        external.append(label)
        if port in RISKY_PORTS:
            risky.append(f"{port}/{RISKY_PORTS[port]} ({process})")
    if risky:
        status, severity = "fail", "high"
        detail = "bound to a non-loopback address: " + ", ".join(risky[:8])
        remediation = ("Firewall or rebind these services to loopback only: "
                       + ", ".join(sorted({r.split(' ')[0] for r in risky})))
    elif external:
        status, severity = "warn", "low"
        detail = f"{len(external)} non-loopback listener(s): " + ", ".join(external[:8])
        remediation = ("Review each external listener and block it in the firewall "
                       "if it is not deliberately exposed")
    else:
        status, severity = "pass", "low"
        detail = "all listeners are bound to loopback addresses"
        remediation = ""
    return [
        check("listening_external", "Externally bound TCP listeners", status,
              detail, severity=severity, remediation=remediation),
        check("listening_summary", "Listener inventory", "info",
              f"{len(rows)} listener(s): "
              + ", ".join(str(p) for p in sorted({
                  int(r.get("Port") or 0) for r in rows if isinstance(r, dict)
              })[:20])),
    ]


COLLECTORS: tuple[tuple[str, Callable[[float], list[dict]], frozenset[str]], ...] = (
    ("system_context", collect_system_context, frozenset({"quick", "full"})),
    ("firewall_profiles", collect_firewall_profiles, frozenset({"quick", "full"})),
    ("remote_services", collect_remote_services, frozenset({"quick", "full"})),
    ("smb_shares", collect_smb_shares, frozenset({"full"})),
    ("uac_policy", collect_uac_policy, frozenset({"full"})),
    ("password_policy", collect_password_policy, frozenset({"full"})),
    ("local_admins", collect_local_admins, frozenset({"full"})),
    ("defender_status", collect_defender_status, frozenset({"quick", "full"})),
    ("hotfix_age", collect_hotfix_age, frozenset({"full"})),
    ("audit_policy", collect_audit_policy, frozenset({"full"})),
    ("autologon_secrets", collect_autologon_secrets, frozenset({"full"})),
    ("listening_ports", collect_listening_ports, frozenset({"quick", "full"})),
)


# ------------------------------------------------------------------ scoring --

def score_checks(checks: list[dict]) -> tuple[float | None, dict]:
    """Weighted score (0-100) plus raw status counts."""
    counts = Counter(c["status"] for c in checks)
    earned = 0.0
    possible = 0.0
    for item in checks:
        if item["status"] not in ("pass", "warn", "fail"):
            continue
        weight = float(item.get("weight", 1.0))
        possible += weight
        if item["status"] == "pass":
            earned += weight
        elif item["status"] == "warn":
            earned += weight * 0.5
    score = round(100.0 * earned / possible, 1) if possible else None
    return score, dict(counts)


def score_band(score: float | None) -> str:
    """Severity band for the numeric score."""
    if score is None:
        return "not scored"
    if score >= 90:
        return "strong"
    if score >= 75:
        return "good"
    if score >= 50:
        return "needs attention"
    return "weak"


def top_remediations(checks: list[dict], limit: int = 10) -> list[dict]:
    """Priority-ordered remediation actions (failures before warnings)."""
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    status_order = {"fail": 0, "warn": 1}
    candidates = [c for c in checks
                  if c["status"] in status_order and c["remediation"]]
    candidates.sort(key=lambda c: (status_order[c["status"]],
                                   severity_order.get(c["severity"], 9),
                                   c["id"]))
    return [{"priority": index, "id": item["id"], "title": item["title"],
             "status": item["status"], "severity": item["severity"],
             "detail": item["detail"], "action": item["remediation"]}
            for index, item in enumerate(candidates[:limit], start=1)]


def run_audit(profile: str = "full", timeout: float = DEFAULT_TIMEOUT,
              host_label: str | None = None) -> dict:
    """Run every collector of the profile and assemble the report."""
    if profile not in PROFILES:
        raise ValueError(f"unknown profile: {profile}")
    started = time.perf_counter()
    results: list[dict] = []
    all_checks: list[dict] = []
    for name, collector, profiles in COLLECTORS:
        if profile not in profiles:
            continue
        call_started = time.perf_counter()
        status = "ok"
        detail = ""
        try:
            found = collector(timeout)
        except AuditTimeout as exc:
            status, detail = "timeout", str(exc)
            found = [check(f"{name}_timeout", f"{name} collector timed out",
                           "skipped", str(exc), "low")]
        except AuditError as exc:
            status, detail = "error", str(exc)
            found = [check(f"{name}_error", f"{name} collector failed",
                           "skipped", str(exc), "low")]
        except Exception as exc:  # one collector must never sink the report
            status, detail = "error", f"{type(exc).__name__}: {exc}"
            found = [check(f"{name}_error", f"{name} collector raised {type(exc).__name__}",
                           "skipped", detail, "low")]
        elapsed = int((time.perf_counter() - call_started) * 1000)
        all_checks.extend(found)
        results.append({"name": name, "status": status,
                        "detail": detail[:300], "elapsed_ms": elapsed,
                        "checks": found})
    score, counts = score_checks(all_checks)
    by_id = {item["id"]: item for item in all_checks}
    host = {
        "label": host_label or by_id.get("computer_name", {}).get("detail", ""),
        "computer": by_id.get("computer_name", {}).get("detail", ""),
        "is_admin": by_id.get("elevation", {}).get("detail", "")
                    .startswith("admin token: yes"),
        "description": by_id.get("os_context", {}).get("detail", ""),
    }
    return {
        "tool": SCRIPT_NAME,
        "mode": MODE,
        "generated_utc": datetime.now(timezone.utc)
        .replace(microsecond=0).isoformat(),
        "profile": profile,
        "host": host,
        "collectors": results,
        "summary": {
            "score": score,
            "band": score_band(score),
            "counts": {state: counts.get(state, 0) for state in RESULT_STATUSES},
            "evaluated": sum(counts.get(s, 0) for s in ("pass", "warn", "fail")),
            "checks_total": len(all_checks),
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
        },
        "remediation": top_remediations(all_checks),
    }


# ------------------------------------------------------------------ output --

def format_human(report: dict) -> str:
    """Plain-text report (ASCII markers, no colour, no emoji)."""
    summary = report["summary"]
    lines = [
        f"{SCRIPT_NAME} - Windows hardening audit",
        MODE,
        "",
        f"Host      : {report['host'].get('label') or '(this machine)'} - "
        f"{report['host'].get('description', 'n/a')}",
        f"Profile   : {report['profile']}",
        f"Generated : {report['generated_utc']}",
        "",
        "Findings",
        "--------",
    ]
    for group in report["collectors"]:
        state = group["status"] if group["status"] != "ok" else "ok"
        lines.append(f"# {group['name']} [{state}]"
                     + (f" - {group['detail']}" if group["detail"] else ""))
        for item in group["checks"]:
            marker = STATUS_MARKER[item["status"]]
            suffix = f" - {item['detail']}" if item["detail"] else ""
            lines.append(f"[{marker}] {item['title']}{suffix}")
            if item["remediation"] and item["status"] in ("warn", "fail"):
                lines.append(f"        fix: {item['remediation']}")
    counts = summary["counts"]
    score_text = "n/a" if summary["score"] is None else f"{summary['score']}/100"
    lines += [
        "",
        "Summary",
        "-------",
        f"Score {score_text} - band: {summary['band']} "
        f"({summary['evaluated']} scored check(s) of {summary['checks_total']})",
        "  ".join(f"{state}={counts.get(state, 0)}" for state in RESULT_STATUSES),
        f"Elapsed {summary['elapsed_ms']} ms",
        "",
        "Top remediation actions",
        "-----------------------",
    ]
    if not report["remediation"]:
        lines.append("(nothing to fix - no failing or warning check with advice)")
    for item in report["remediation"]:
        lines.append(f"{item['priority']:>2}. [{item['severity']:<8}] "
                     f"{item['title']} ({item['status']})")
        lines.append(f"    {item['action']}")
    lines.append("")
    lines.append("No system setting was changed by this audit.")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=SCRIPT_NAME,
        description="Read-only Windows hardening audit: score the current "
                    "configuration and list the highest-value fixes.")
    parser.add_argument("--profile", choices=PROFILES, default="full",
                        help="collector set to run (default: full)")
    parser.add_argument("--json", action="store_true",
                        help="emit one JSON document instead of text")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"seconds allowed per PowerShell command "
                             f"(default: {DEFAULT_TIMEOUT:g})")
    parser.add_argument("--host-label", default=None,
                        help="label recorded in the report instead of the "
                             "host name detected by the collectors")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = run_audit(profile=args.profile, timeout=args.timeout,
                           host_label=args.host_label)
    except ValueError as exc:
        print(f"{SCRIPT_NAME}: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=False))
    else:
        print(format_human(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
