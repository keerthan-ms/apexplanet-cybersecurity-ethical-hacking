# 06 — System Hardening (Methodology)

Brief for this deliverable: apply security patches, configure a firewall to
block malicious traffic, and disable unused services — on Windows.

---

## Status on this machine

**This session is not elevated**, so nothing that changes system state can be
applied here. Verify that yourself with:

```powershell
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# returns False in this session
```

Every `Set-*`, `New-*`, `Disable-*`, `reg add`, `auditpol /set` and
`Install-WindowsUpdate` command below therefore requires **administrator
rights that this session does not have**. They are written for execution
later, on a machine where you do have them, ideally inside a maintenance
window with a rollback plan (a snapshot or a restore point).

Instead of applying changes, Task 4 performs a **read-only audit** of this
machine:

- **`task-4/scripts/hardening_audit.py`** — checks the current state (update
  status, firewall posture, SMBv1, listening services, and related settings)
  and reports findings without modifying anything. Written and tested
  separately from this document; this file only points at it.

**Readings genuinely captured on this machine while writing this document**
(only `Get-*` queries — no changes made):

```text
PS> Get-NetFirewallProfile | Select Name,Enabled,DefaultInboundAction,DefaultOutboundAction
Name     Enabled DefaultInboundAction DefaultOutboundAction
----     ------- -------------------- ---------------------
Domain      True         NotConfigured         NotConfigured
Private     True         NotConfigured         NotConfigured
Public      True         NotConfigured         NotConfigured

PS> Get-SmbServerConfiguration | Select EnableSMB1Protocol
EnableSMB1Protocol : False

PS> Get-HotFix | Sort InstalledOn -Descending | Select -First 3
HotFixID    InstalledOn Description
--------    ----------- -----------
KB5127648   14-10-2026  Security Update
KB5127647   14-10-2026  Security Update
KB5121794   14-10-2026  Update
```

Interpretation for this host: the firewall is on for all three profiles
(good); the outbound default action is not explicitly set to Block, so the
host is default-allow outbound (the gap addressed in checklist 2); SMBv1 is
already disabled (one item off the list); the most recent installed update is
from 2026-10-14 — recent, but check the *latest* release before assuming it
is complete (checklist 1).

---

## Checklist 1 — Apply security patches

- [ ] Record the current patch state before changing anything.
- [ ] Scan for missing updates.
- [ ] Install in a maintenance window; reboot if required; verify afterwards.
- [ ] Subscribe the machine to an update source you actually control.

```powershell
# 1. What is installed (read-only)
Get-HotFix | Sort-Object InstalledOn -Descending |
  Select-Object -First 20 HotFixID, InstalledOn, Description
# Latest build/version context
Get-ComputerInfo | Select-Object OsName, OsVersion, OsBuildNumber

# 2. Scan for what is missing. PSWindowsUpdate installs per-user without admin;
#    installing the updates themselves needs an elevated shell.
Install-Module PSWindowsUpdate -Scope CurrentUser -Force
Import-Module PSWindowsUpdate
Get-WindowsUpdate                      # read-only list of pending updates
#    Install-WindowsUpdate -AcceptAll -AutoReboot     # ELEVATED ONLY

# 3. Fallback when the module is unavailable (built-in clients)
UsoClient StartScan                    # trigger a scan
# Windows Update settings GUI, or wsus/GPO in a domain environment

# 4. Verify after the window
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5
Get-ComputerInfo | Select-Object OsBuildNumber
```

Notes that matter in practice:

- `Get-HotFix` shows **installed** hotfixes only; it is a record, not a
  compliance check. `Get-WindowsUpdate` (or the Update Compliance/
  Microsoft Intune reports) shows what is *missing*.
- Prioritise by exposure, not by CVE count: internet-facing and
  RCE-over-network CVEs first, then credential-theft and privilege-escalation
  ones, then the rest.
- Keep a record of the last successful update per machine. An unpatched host
  is usually not a technical failure — it is a process gap.

---

## Checklist 2 — Firewall: block by default, allow by exception

### 2a. Read the current posture

```powershell
Get-NetFirewallProfile |
  Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked |
  Format-Table -AutoSize

# Count and review enabled inbound allows that accept traffic from Any
$allowAny = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow
$allowAny | ForEach-Object {
  $addr = $_ | Get-NetFirewallAddressFilter
  [pscustomobject]@{ Name = $_.DisplayName; Profile = $_.Profile; Remote = ($addr.RemoteAddress -join ',') }
} | Where-Object Remote -eq 'Any' | Sort-Object Name
```

### 2b. Turn on logging before you tighten anything

```powershell
Set-NetFirewallProfile -Profile Domain,Private,Public `
  -LogAllowed True -LogBlocked True `
  -LogFileName '%systemroot%\system32\logfiles\firewall\pfirewall.log' `
  -LogMaxSizeKilobytes 16384
# then read what is being dropped
Get-Content "$env:systemroot\system32\logfiles\firewall\pfirewall.log" -Tail 200 |
  Select-String 'DROP'
```

Logging first means you can see what a default-deny change would break,
before it breaks it.

### 2c. Worked example — allow-by-default, deny outbound

Outbound default-deny is high-friction: DNS, DHCP, proxies, telemetry and
every business app must be allowlisted, or the host silently stops working.
Stage it.

```powershell
# Step 1 — create the allows BEFORE flipping the default. ELEVATED ONLY.
New-NetFirewallRule -DisplayName 'Allow DNS (UDP) out' -Direction Outbound -Action Allow `
  -Protocol UDP -RemotePort 53 -Enabled True -Profile Any
New-NetFirewallRule -DisplayName 'Allow DNS (TCP) out' -Direction Outbound -Action Allow `
  -Protocol TCP -RemotePort 53 -Enabled True -Profile Any
New-NetFirewallRule -DisplayName 'Allow DHCP client' -Direction Outbound -Action Allow `
  -Protocol UDP -LocalPort 68 -RemotePort 67 -Enabled True -Profile Any
New-NetFirewallRule -DisplayName 'Allow HTTPS out' -Direction Outbound -Action Allow `
  -Protocol TCP -RemotePort 443 -Enabled True -Profile Any
New-NetFirewallRule -DisplayName 'Allow HTTP out' -Direction Outbound -Action Allow `
  -Protocol TCP -RemotePort 80 -Enabled True -Profile Any

# Step 2 — enable logging, watch for a day, add allows for what legitimately fails

# Step 3 — flip the default. ELEVATED ONLY.
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block

# Step 4 — rollback if it breaks something critical
# Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow
```

Why this control earns its place: it is the host-level answer to the reverse
shell problem in
[`02-exploitation-with-metasploit.md`](02-exploitation-with-metasploit.md) —
malware that has dialled out to an attacker's `LHOST` on a port you never
allowlisted gets nowhere.

### 2d. Worked example — restrict an inbound rule to a management subnet

```powershell
# ELEVATED ONLY. Scope the ALLOW, and rely on the default inbound Block.
New-NetFirewallRule -DisplayName 'RDP from management subnet only' `
  -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389 `
  -RemoteAddress 192.168.56.0/24 -Profile Domain,Private -Enabled True
```

**Rule of evaluation you must know:** Windows Firewall processes rules in
this order — *authenticated bypass* rules, then **block** rules, then **allow**
rules. An explicit block rule therefore overrides a matching allow rule
regardless of which is "more specific". So the pattern "allow the subnet,
then add a catch-all block for everything else" does **not** work: the
catch-all block also blocks your subnet. The correct pattern is:

1. `DefaultInboundAction = Block` on the profiles (the normal default), and
2. allow rules that are *scoped* to the subnet, host or user you intend.

If you need finer control than IP scoping — "only the jump-host account may
RDP" — that is the job of just-in-time access or RestrictedAdmin, not of
another firewall rule.

---

## Checklist 3 — Disable unused services

- [ ] Inventory what is running before changing anything.
- [ ] Identify what is genuinely unused *on this host's role*.
- [ ] Prefer `Manual` (or trigger-start) over `Disabled` for anything
      uncertain; disable outright only what you can prove is unneeded.
- [ ] Change one service at a time, in a window, with a test after each.

```powershell
# Inventory (read-only)
Get-Service | Where-Object Status -eq 'Running' |
  Sort-Object DisplayName | Select-Object Name, DisplayName, Status, StartType |
  Format-Table -AutoSize

# Startup types across all services
Get-Service | Group-Object StartType | Select-Object Name, Count

# Change one service. ELEVATED ONLY.
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled

# Verify it stayed down and nothing broke
Get-Service -Name Spooler | Select-Object Name, Status, StartType

# Remove an unused Windows feature entirely (example: SMBv1). ELEVATED ONLY.
Get-WindowsOptionalFeature -Online | Where-Object State -eq 'Enabled' |
  Select-Object FeatureName, State
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
```

**Do not disable these on a normal Windows host** (each takes something you
probably need):

| Service | What breaks |
|---|---|
| `RpcSs`, `RpcEptMapper` | RPC — almost everything, including Windows Update and Group Policy |
| `SamSs`, `LanmanServer`, `LanmanWorkstation` | Local account database, inbound/outbound SMB, mapped drives, domain access |
| `Dhcp`, `Dnscache` | IP addressing and name resolution |
| `EventLog` | All logging, and with it detection |
| `WinDefend` (and the Defender service stack) | Endpoint protection itself |
| `PlugPlay`, `Power`, `ProfSvc`, `LSM`, `DcomLaunch` | Core OS function; expect a non-bootable or unusable machine |

**Reasonable disable candidates on a workstation that never prints, never
serves files, and is not an RDP target:** `Spooler` (also removes a historical
privilege-escalation surface), `RemoteRegistry` (often already disabled;
prevents remote registry editing), `XblAuthManager`/`XblGameSave` (legacy
Xbox services), `Fax`, `wisvc` (Windows Insider), `MapsBroker`, `lfsvc`
(location, if unused), `SEMgrSvc` (payments, if unused), `RetailDemo`.

`RemoteRegistry` check before changing anything:

```powershell
Get-Service -Name RemoteRegistry | Select-Object Name, Status, StartType
```

---

## Checklist 4 — The extras worth covering

All `Set-*` / `reg add` / `Add-MpPreference` commands below are **elevated
only**.

### 4a. Attack surface reduction (ASR) rules

Defender's ASR rules block the specific behaviours ransomware and loaders
rely on, and they support audit mode before enforcement.

```powershell
# What is configured now (read-only)
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions

# Enable by GUID. Confirm current GUIDs against Microsoft's ASR rule list —
# rules are added over time. Example: block credential stealing from LSASS.
Add-MpPreference -AttackSurfaceReductionRules_Ids `
  '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' `
  -AttackSurfaceReductionRules_Actions Enabled
```

High-value rules to review (each with a one-line rationale):

| Rule | Effect |
|---|---|
| Block credential stealing from LSASS | Directly defeats mimikatz-style dumping — the technique behind hashdump in [`02-exploitation-with-metasploit.md`](02-exploitation-with-metasploit.md) |
| Block executable content from email and webmail | Kills macro/dropper attachments at execution |
| Block Office child process creation | Stops Word/Excel spawning PowerShell or cmd |
| Block untrusted and unsigned processes from USB | Stops autorun-style loaders from removable media |
| Block JavaScript/VBA from downloaded content | Defeats weaponised documents |

Related, and cheap:

```powershell
Set-MpPreference -EnableNetworkProtection Enabled      # block known-bad URLs
Set-MpPreference -PUAProtection Enabled                # block "potentially unwanted" apps
Set-MpPreference -EnableControlledFolderAccess Enabled # ransomware: only approved apps write to Documents/Desktop
Get-MpComputerStatus | Select-Object AMServiceEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated
```

### 4b. Disable SMBv1

SMBv1 is a 1980s protocol with no modern security properties and a history
of wormable bugs (EternalBlue/WannaCry). Nothing needs it unless a very old
NAS or scanner insists.

```powershell
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol    # read-only
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force     # ELEVATED
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart  # ELEVATED, client side too
```

*(Already `False` on this machine — see the readings at the top.)*

### 4c. LSA protection, WDigest, and related credential controls

```powershell
# RunAsPPL: stops non-PPL processes from reading LSASS memory. Reboot required.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
# Blank passwords cannot be used over the network
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
# Stop WDigest holding plaintext credentials in memory (mimikatz bait)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
```

Caution: RunAsPPL can break older backup/AV products that read LSASS
directly; test first. Credential Guard (GPO: virtualisation-based protection
of code integrity) is the stronger control but needs UEFI, SLAT and
virtualisation enabled in firmware.

### 4d. RDP: unnecessary exposure, and how to restrict it if required

RDP is the most common initial-access vector for ransomware. Disable it if
you do not use it; if you do, restrict it hard.

```powershell
# Is it listening? (read-only)
Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue

# Disable. ELEVATED.
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
  -Name fDenyTSConnections -Value 1
Get-NetFirewallRule -DisplayName 'Remote Desktop*' | Disable-NetFirewallRule

# If RDP must stay: require Network Level Authentication and scope the allow
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
  -Name UserAuthentication -Value 1
Get-NetFirewallRule -DisplayName 'Remote Desktop*' | Enable-NetFirewallRule
Get-NetFirewallRule -DisplayName 'Remote Desktop*' |
  Set-NetFirewallRule -RemoteAddress 192.168.56.0/24
```

Never expose 3389 to the internet; use a VPN or a broker (RD Gateway,
just-in-time access) instead.

### 4e. Audit policy — you cannot detect what you do not log

```powershell
# Read-only
auditpol /get /category:*
# Enable a useful baseline. ELEVATED.
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable

# Command lines in process-creation events (Security 4688). ELEVATED.
New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
  -Name ProcessCreationIncludeCmdLine_Enabled -Value 1

# PowerShell logging (script blocks are the modern detection surface). ELEVATED.
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
  -Name EnableScriptBlockLogging -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' `
  -Name EnableModuleLogging -Value 1 -Type DWord
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' `
  -Name '*' -Value '*' -Type String
```

Also disable LLMNR (poisonable name resolution, feeds NTLM relay):

```powershell
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
  -Name EnableMulticast -Value 0 -Type DWord
```

### 4f. Local administrator password solution (LAPS) — concept

The problem: a cloned image gives every machine the same local admin
password, so one workstation compromise equals domain-wide local admin
(reuse of a dumped hash — pass-the-hash — is exactly the attack in
[`02-exploitation-with-metasploit.md`](02-exploitation-with-metasploit.md)).

LAPS fixes it by generating a **unique, random password per machine** for the
local administrator account, rotating it on a schedule (commonly 30 days),
and storing the current and previous values in Active Directory (or Intune),
where only delegated groups may read them. Windows LAPS is in-box now:

```powershell
# ELEVATED, in a domain, as a schema admin
Update-LapsADSchema                                   # extend the schema once
Set-LapsADComputerSelfPermission -Identity 'OU=Computers,DC=example,DC=internal'
# Then enable via Group Policy: Computer Configuration > Policies > Windows
# Settings > Security Settings > Local Administrator Password Solution,
# set Password Backup Directory = Active Directory, password length ~24,
# password age ~30 days.
```

Conceptually: one leaked hash is one machine, not every machine.

---

## Do these first — the ten highest-value actions

1. **Install missing security updates** — removes the exploit the majority of
   real intrusions actually use.
2. **Disable SMBv1** — eliminates a wormable, decades-old protocol that
   nothing modern needs.
3. **Turn on LSASS protection (RunAsPPL) + disable WDigest credentials** —
   directly defeats the dominant credential-dumping technique.
4. **Ensure real-time antivirus/Defender is enabled and signatures current** —
   the baseline that everything else assumes.
5. **Enable ASR rules, starting with "block credential stealing from LSASS"
   and "block Office child processes"** — blocks the two most common
   ransomware behaviours at the point of execution.
6. **Restrict or disable RDP; never expose 3389 to the internet** — the most
   common initial-access vector for ransomware crews.
7. **Disable unused services (Spooler, RemoteRegistry, and whatever your
   role does not need)** — fewer services, fewer privilege-escalation paths.
8. **Enable outbound default-deny firewall (with staged allows and logging)** —
   stops reverse shells and C2 dial-outs, the failure mode shown in Task 4's
   exploitation lab.
9. **Turn on audit policy + process-creation command lines + PowerShell
   script-block logging** — you cannot detect what you do not log (this is
   the feed Task 5's detection pipeline consumes).
10. **Deploy LAPS (unique local admin passwords per machine)** — turns one
    compromised host from a domain-wide breach into a single-host incident.

---

## Related material

- Read-only audit of this machine: `task-4/scripts/hardening_audit.py`.
- The attacks these controls defend against:
  [`02-exploitation-with-metasploit.md`](02-exploitation-with-metasploit.md)
  (reverse shells, hashdump) and
  [`03-password-attacks.md`](03-password-attacks.md) (cracking, pass-the-hash).
- Scoring the findings the audit produces:
  [`01-pentest-methodology.md`](01-pentest-methodology.md).
