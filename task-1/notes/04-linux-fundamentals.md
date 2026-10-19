# Task 1 — Linux Fundamentals (Cheat-Sheet)

The Linux commands the brief expects you to know for the Kali/Metasploitable
lab, with the security-relevant detail on permissions. Every command here is
standard; none of them were run on this machine, because **this machine runs
Windows and has no Linux environment** — see the final section, which maps each
command to what you can actually execute here.

Examples assume a Debian-family system (Kali, Metasploitable2's Ubuntu 8.04
base, Ubuntu servers). Prompts: `$` for an unprivileged user, `#` for root.

---

## 1. File system navigation

| Command | Purpose | Common flags |
|---|---|---|
| `pwd` | Print working directory | `-P` resolve symlinks in the path |
| `cd` | Change directory | `cd -` back to previous; `cd ..` up one |
| `ls` | List directory contents | `-l` long form, `-a` include dotfiles, `-h` human sizes, `-R` recursive, `-t` sort by mtime, `-Z` SELinux labels |
| `find` | Search a tree by name, type, size, permission, time | `-name`, `-type f/d/l`, `-perm`, `-user`, `-mtime`, `-size`, `-exec`/`-delete` |
| `tree` | Visual directory listing | `-L 2` depth limit, `-a` all, `-d` directories only |
| `file` | Identify a file's real type from its magic bytes | (crucial on attacker boxes — `.jpg` may be an ELF) |
| `less` / `head` / `tail` | Page through or sample a file | `tail -f` follow live (logs) |
| `realpath` | Resolve a path fully | |

Worked combinations you will use constantly:

```sh
ls -lah                      # everything, human sizes, including dotfiles
find /var/www -name '*.php' -type f -mtime -7      # PHP files changed last week
find / -perm -4000 -type f 2>/dev/null             # every setuid binary (see section 2)
find / -name 'id_rsa' -o -name '*.pem' 2>/dev/null # hunt for keys (lab exercise)
tree -L 2 /etc               # structure of a config tree, two levels
```

Note the `2>/dev/null`: without it, every permission-denied error on a
`find /` pollutes the output. Redirecting stderr is a habit, not decoration.

---

## 2. Permissions

### The `rwx` notation

Every file has an owner, a group, and an "other" class, each with three
permits:

- **r** — read: list the directory / read the file's contents
- **w** — write: create or delete entries in the directory / modify the file
- **x** — enter/traverse the directory / execute the file as a program or
  script, and (for directories) `cd` into it and access its children

`ls -l` output decodes them:

```
-rwxr-xr-x 1 root www-data  4096 ...  /usr/bin/passwd
```

Owner (root) rwx, group (www-data) r-x, other r-x. The leading `-` means
regular file; `d` would be a directory.

### Octal equivalents, worked

Each class is a 3-bit number: r=4, w=2, x=1. Sum per class, concatenate owner
→ group → other.

| Symbolic | Octal | Arithmetic | Meaning |
|---|---|---|---|
| `rw-------` | 600 | 4+2+0 = 6, and 0, 0 | Private key material: owner only |
| `rw-r--r--` | 644 | 6, 4, 4 | Normal readable file |
| `rwxr-xr-x` | 755 | 7, 5, 5 | Normal executable / world-traversable directory |
| `rwxrwxrwx` | 777 | 7, 7, 7 | Everyone can do everything — almost always a finding, not a fix |
| `rw-r-----` | 640 | 6, 4, 0 | Log file readable by the owning group (e.g. `adm`) only |
| `rwx------` | 700 | 7, 0, 0 | User's `~/.ssh`: only the owner may enter |

Worked example — `chmod 750 script.sh`:

```
7 = 4+2+1 → owner: rwx
5 = 4+0+1 → group: r-x
0 = 0+0+0 → other: ---
```

Symbolic mode does the same job incrementally:
`chmod u+x,g-w,o-rwx file` — add execute for owner, remove write from group,
remove everything from others. `chmod -R` applies recursively, and is dangerous
on a big tree; `chmod a+w /` is a rite of passage and a disaster.

`chown` changes ownership: `chown www-data:www-data /var/www/app/uploads`,
`chown -R root:root /etc` after a compromise. Ownership matters as much as
modes: a world-writable file owned by `root` that only root can write is not
world-writable — the owner field changes the effective access.

### Special bits: setuid, setgid, sticky

Numerically they are a fourth octet prepended: setuid = 4, setgid = 2,
sticky = 1.

| Bit | On a file | On a directory |
|---|---|---|
| setuid (4) | Runs with the **owner's** euid, not the caller's | Ignored on most modern systems (System V semantics) |
| setgid (2) | Runs with the **group's** egid | New files inherit the directory's group |
| sticky (1) | Ignored | Only file owners (or root) may delete/rename entries — the `/tmp` rule |

Examples:

```
chmod 4755 /usr/bin/passwd      # rwsr-xr-x — runs as root, so it can write /etc/shadow
chmod 2755 /usr/local/bin/team   # rwxr-sr-x — runs with the group's privileges
chmod 1777 /tmp                  # rwxrwxrwt — everyone may create, nobody may delete others' files
ls -l /tmp → drwxrwxrwt          # the `t` replaces the last x
```

**Why setuid matters for security.** A setuid-root binary is a small piece of
code that runs with the highest privileges on the box *whenever any user runs
it*. That makes it one of the two classic local privilege-escalation surfaces
(the other being kernel and driver bugs):

- If a setuid binary has a bug — buffer overflow, command injection, unsafe
  `system()` on user input, TOCTOU on a temp file — any local user who
  triggers it gets root. Half of the classic "kernel exploit or SUID abuse"
  privesc write-ups are exactly this.
- Attackers enumerate them first after getting any shell:
  `find / -perm -4000 -type f 2>/dev/null`, then check each binary against
  GTFOBins for abused functionality (e.g. a setuid `find` with `-exec`, or
  `vim` with `:!sh`).
- Hardening: setuid only where the operation genuinely requires privilege
  elevation, never on interpreters, drop capabilities instead where possible
  (file capabilities, `setcap cap_net_raw+ep`), and keep the binary statically
  auditable — no shared libraries from writable paths (another reason not to
  put application directories on the dynamic-linker path).

On the defender's side, an unexpected new setuid file is a persistence
indicator worth alerting on: legitimate ones change rarely, and `auditd` can
watch for it.

---

## 3. Package management: apt versus dpkg

Debian-family systems have two layers, and the distinction matters when you
are installing lab tooling:

- **dpkg** is the low-level backend. It unpacks and configures `.deb` archives
  and maintains the local database of installed packages. It does **not**
  resolve dependencies — `dpkg -i foo.deb` with missing dependencies leaves
  the package "unpacked but not configured" (`ii` vs `iU` states).
- **apt** (Advanced Package Tool) is the front end. It talks to configured
  repositories, resolves and downloads dependencies, and calls dpkg to do the
  actual installation.

| Task | apt | dpkg |
|---|---|---|
| Update package index | `apt update` | — |
| Upgrade installed packages | `apt upgrade` / `apt full-upgrade` | — |
| Install (with dependencies) | `apt install nmap` | `dpkg -i nmap.deb` |
| Remove | `apt remove nmap` (keeps config) / `apt purge nmap` | `dpkg -r nmap` / `dpkg -P nmap` |
| Search | `apt search nmap` | `dpkg -l 'nmap*'` (installed list, not a search) |
| Show package details | `apt show nmap` | `dpkg -s nmap` (status), `dpkg -L nmap` (file list) |
| Reinstall | `apt install --reinstall nmap` | — |
| Fix broken deps | `apt --fix-broken install` | `dpkg --configure -a` |

Typical first-day sequence on a fresh Kali:

```sh
apt update && apt full-upgrade -y     # index, then newest versions
apt install -y nmap wireshark netcat-openbsd sqlmap nikto
dpkg -l | grep -E 'nmap|wireshark'    # confirm what landed
apt remove -y nikto                   # change of mind
```

Security note: `apt upgrade` is patch management. On a target like
Metasploitable2 you deliberately *do not* upgrade — its value is that it is
vulnerable. On anything real, unpatched packages are the top initial-access
vector; the NHS WannaCry damage was overwhelmingly unpatched Windows hosts, and
the Linux equivalent story is the same mechanism.

---

## 4. Networking commands

| Command | Purpose | Typical invocation |
|---|---|---|
| `ifconfig` | Show/set interfaces (legacy, net-tools) | `ifconfig -a` or `ifconfig eth0 192.168.56.10 netmask 255.255.255.0` |
| `ip` | Modern replacement (iproute2): addresses, links, routes | `ip a`, `ip -br link`, `ip route`, `ip neigh` |
| `ping` | ICMP reachability and round-trip time | `ping -c 4 192.168.56.101` |
| `netstat` | Sockets, listening ports, established connections (legacy) | `netstat -tulnp` (TCP/UDP listeners with owning process) |
| `ss` | Modern socket statistics, faster than netstat | `ss -tulnp`, `ss -tn state established` |
| `traceroute` | Path to a host, hop by hop (TTL increment) | `traceroute -n 8.8.8.8` |
| `curl` | HTTP(S) client for anything: headers, methods, transfers | `curl -I https://example.com` (HEAD only), `curl -X POST -d 'a=1' http://lab.local/api` |
| `dig` | DNS lookup, any record type, with full answer detail | `dig example.com A +short`, `dig example.com MX`, `dig +trace example.com` |

Supplementary ones worth knowing for the lab: `arp -n` / `ip neigh` (ARP
table — what MAC owns which IP on the link), `route -n` / `ip route` (routing
table), `nc -zv host 1-1024` (port check without a full scanner), `tcpdump -i
any -nn port 53` (capture from the shell when Wireshark is not installed —
needs root for capture), `hostname -I` (this host's addresses, quickly).

Reading the output matters more than memorising flags: `ss -tulnp` splitting
into `LISTEN` (attack surface) versus `ESTAB` (live sessions) is the first
thing to look at on an unfamiliar host, and it is the same mental pass Nmap
does from the outside.

---

## 5. Running these on Windows

**This machine runs Windows 10/11 and cannot run any of the commands above.**
There is no Linux environment available: WSL cannot be installed without
administrator rights and a reboot — `wsl --status` on this machine reports
"The Windows Subsystem for Linux is not installed", and `wsl --install` is
elevation-gated. VirtualBox and VMware are likewise not installed and their
installers require elevation (see `../lab/LAB-SETUP-REPORT.md`). Everything in
sections 1–4 is therefore written for the lab you will build later, not for
this host.

What you *can* run here, command by command:

| Linux | Windows / PowerShell equivalent | Notes |
|---|---|---|
| `pwd` | `Get-Location` or `Get-Location`.Path | |
| `cd /var/www` | `Set-Location C:\inetpub\wwwroot` | `cd /d D:` switches drive in cmd |
| `ls -la` | `Get-ChildItem -Force` or `Get-ChildItem -File \| Select Name,Length,LastWriteTime` | `dir /a` in cmd |
| `tree -L 2` | `tree.com /F /A` | Depth flags differ; PowerShell: `Get-ChildItem -Recurse -Depth 2` |
| `find / -name id_rsa` | `Get-ChildItem -Recurse -Filter id_rsa -ErrorAction SilentlyContinue` | Native `find.exe` is a text filter, not a file finder — do not confuse it with bash `find` |
| `grep -r password .` | `Select-String -Path *.* -Pattern password -Recurse` or `rg password` | `Select-String` is the workhorse |
| `cat /etc/passwd` | `Get-Content C:\Windows\System32\drivers\etc\hosts` | `type` in cmd |
| `chmod 600 key` | No mode bits; use ACLs: `icacls key.pem /inheritance:r /grant:r "$env:USERNAME:(R,W)"` | NTFS permissions replace Unix modes |
| `chown www-data file` | `icacls file /setowner user` or `(Get-Acl file).SetOwner(...)`; via WMI: `Invoke-CimMethod` | Ownership exists but works differently; no group-owned model like Unix |
| `apt install nmap` | `winget install Insecure.Nmap` or `choco install nmap` | winget is built into Windows 11 and recent 10 |
| `apt update && apt upgrade` | `winget upgrade --all` or Windows Update | |
| `apt search nmap` | `winget search nmap` | |
| `ifconfig` / `ip a` | `ipconfig /all` or `Get-NetIPAddress -AddressFamily IPv4` | |
| `ip route` | `Get-NetRoute` or `route print` | |
| `ping -c 4 host` | `Test-NetConnection host -InformationLevel Detailed` (TCP-capable) or `ping.exe -n 4 host` | PowerShell's `ping` alias resolves to `Test-Connection`, which behaves differently from the exe |
| `netstat -tulnp` | `netstat -ano` or `Get-NetTCPConnection -State Listen \| Select LocalAddress,LocalPort,OwningProcess` | `-p` process association needs elevation on Windows for foreign processes |
| `ss -tulnp` | `Get-NetTCPConnection -State Listen` | Same role, different cmdlet |
| `traceroute -n host` | `tracert -d host` or `Test-NetConnection host -TraceRoute` | `-d`/no-DNS for speed |
| `curl -I https://example.com` | `curl.exe -I https://example.com` | Windows 10 1803+ ships curl; use `curl.exe` explicitly because PowerShell has a `curl` alias for `Invoke-WebRequest` |
| `dig example.com A` | `Resolve-DnsName example.com -Type A` | `nslookup` also exists in both worlds |
| `nc -lvnp 4444` | No built-in netcat; Python sockets (see `05-tool-familiarization.md`) or install ncat with Nmap | |
| `tcpdump -i any` | Not possible: capture needs Npcap, which needs administrator rights | Wireshark likewise unavailable here |

The honest summary: this host gives you Windows equivalents for navigation,
permissions (via ACLs), DNS, TCP connections and HTTP — enough to do the
networking and web-security work of Tasks 2–3 in Python and PowerShell — but
no Linux shell, no packet capture, and no hypervisor. The cheat-sheet above is
for the Kali VM you will build once administrator rights are available; the
right-hand column is what applies here and now.
