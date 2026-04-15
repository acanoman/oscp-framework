# ARGUS — OSCP Enumeration Framework

```text
 ██████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
███████║██████╔╝██║  ███╗██║   ██║███████╗
██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
```

> **Assisted recon. Never autopwn.**  
> Enumerate → Synthesize → Attack Path

☠ by acanoman ☠

---

## What is ARGUS

ARGUS is a modular, OSCP+ compliant enumeration framework. It runs a full
structured recon pipeline against a single target, streams all tool output in
real time, and at the end produces a **prioritized attack path** with exact
manual commands to run — nothing is executed automatically.

**What ARGUS does:**

- Runs 12 enumeration modules in strict tier order (Tier 1 → 2 → 3)
- Streams every tool's stdout to the terminal in real time with colour-coded prefixes
- Generates a `notes.md` report after every module (always up to date)
- Synthesizes all findings into a **🎯 Prioritized Attack Path** panel at end of run
- Detects SMBv1, NTLM relay risk, AS-REP Roastable users, Kerberoastable SPNs, SSH CVEs, Apache versions, high-value web paths, downloadable files, LDAP description-field passwords, vhosts, DNS AXFR results, and more
- Emits every attack-adjacent command as a `[MANUAL]` hint — copy-paste ready, never auto-executed
- Writes `_manual_commands.txt` — a standalone file with every manual hint, one per line, ready to paste
- Writes `_commands.log` — a full timestamped audit trail of every command executed
- Applies per-module hard timeouts to prevent any single scan from blocking the exam clock
- Persists state in `session.json` so `--resume` skips completed modules
- **`--quick` mode**: caps every module at 120 s — ideal for a fast first pass across all exam machines

**What ARGUS does NOT do:**

- Exploit anything
- Brute-force credentials without explicit operator action
- Auto-download files from shares or web paths
- Chain discoveries into automated attack sequences
- Use Metasploit or any prohibited tool

---

## OSCP+ Compliance

| Requirement | ARGUS Behaviour |
| ----------- | --------------- |
| No automated exploitation | All attack chains are `[MANUAL]` hints only — the framework never executes exploits |
| No prohibited tools | SQLMap, mass scanners, and automated brute-force are never invoked |
| Metasploit not used | Zero Metasploit references in any wrapper or Python module |
| All commands shown first | Every subprocess call is logged with a `[CMD]` prefix before execution |
| Attack commands = hints only | AS-REP Roast, Kerberoast, NTLM Relay, spray commands appear as `[MANUAL]` hints |
| No auto-download from shares | SMB share download commands shown as manual hints only |
| Full transparency | `--dry-run` prints every command without executing any |
| Audit trail | `_commands.log` records every executed command with timestamp |
| Exam safety | Per-module timeouts and `--quick` mode prevent scans from blocking the clock |

---

## Requirements

### Python

Python **3.8 or newer** is required. 3.10+ is recommended.

### pip packages

```text
rich>=13.0.0
```

Install with:

```bash
pip install -r requirements.txt
```

### External tools

ARGUS skips any tool that is not installed and warns you — a scan never aborts
because a secondary tool is missing.

| Category | Tool | Role |
| -------- | ---- | ---- |
| **Required** | `nmap` | Port scanning and NSE scripts |
| **Required** | `smbclient` | SMB share listing |
| **Required** | `smbmap` | SMB share access mapping |
| **Required** | `rpcclient` | RPC/SMB user enumeration |
| **Required** | `ldapsearch` | LDAP anonymous bind (`ldap-utils` package) |
| **Required** | `curl` | HTTP header grab |
| **Required** | `gobuster` | Web directory and DNS brute-force |
| **Required** | `whatweb` | Web technology fingerprinting |
| **Required** | `showmount` | NFS export listing (`nfs-common` package) |
| **Required** | `snmpwalk` | SNMP MIB walk (`snmp` package) |
| **Required** | `smtp-user-enum` | SMTP user verification via VRFY/EXPN/RCPT |
| Optional | `feroxbuster` | Recursive web directory fuzzer |
| Optional | `ffuf` | Vhost and parameter fuzzing |
| Optional | `nikto` | Web vulnerability scanner |
| Optional | `sslscan` | TLS/SSL certificate and cipher enumeration |
| Optional | `rustscan` | Faster all-port scanner (falls back to nmap) |
| Optional | `nxc` / `netexec` | SMB sessions, RID cycling, share spider, user enum |
| Optional | `enum4linux-ng` | SMB/LDAP/RPC full enumeration |
| Optional | `kerbrute` | Kerberos username enumeration (AS-REQ probe, no auth) |
| Optional | `windapsearch` | AD user/group/SPN enumeration via LDAP |
| Optional | `wpscan` | WordPress scanner (enumerate-only mode) |
| Optional | `ssh-audit` | SSH key exchange and cipher audit |
| Optional | `onesixtyone` | SNMP community string sweep |
| Optional | `impacket-*` | AS-REP Roast, Kerberoast, SID/RID lookup — manual hints |
| Optional | `bloodhound-python` | BloodHound data collection — manual hint |
| Optional | `evil-winrm` | WinRM shell — manual hint only |

**OS:** Kali Linux or any Debian-based distribution.

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/acanoman/oscp-framework
cd oscp-framework

# 2. Run the installer (creates .venv/, installs pip packages, generates run.sh)
sudo bash install.sh

# 3. Run — always use run.sh, it uses the project virtualenv automatically
./run.sh --target <IP> --lhost <LHOST>
```

`install.sh` creates a `.venv/` Python virtual environment, installs pip
packages into it, sets `+x` on all wrappers, checks which optional tools
are available, and generates `run.sh` — a one-line launcher that calls
`.venv/bin/python main.py` directly.

**`./run.sh` is the correct entry point.** Use it for every run.
`python main.py` also works if you activate the venv first:

```bash
source .venv/bin/activate
python main.py --target <IP> --lhost <LHOST>
```

All tool checks are non-fatal — missing optional tools are reported as
warnings, not errors.

---

## Usage

> **Use `./run.sh` after installing** — it automatically uses the project
> virtualenv created by `install.sh`. `python main.py` only works if the venv
> is active (`source .venv/bin/activate`) or if the pip packages are installed
> globally.

### Standard exam run

```bash
./run.sh --target 10.10.10.5 --lhost 10.10.14.5
```

`--lhost` pre-fills every `<LHOST>` placeholder in transfer and reverse-shell
commands inside `notes.md`, making them copy-paste ready without manual editing.

### With a known AD domain

```bash
./run.sh --target 10.10.10.5 --domain corp.local --lhost 10.10.14.5
```

Passes the domain to LDAP, SMB, DNS, kerbrute, and web modules so they all
operate with the correct base DN and hostname context.

### Resume an interrupted session

```bash
./run.sh --target 10.10.10.5 --resume --lhost 10.10.14.5
```

Re-reads `session.json`, skips Nmap and completed modules, and continues from
where the scan stopped. Without `--resume` a fresh scan always starts even if
`session.json` exists.

### Preview every command without running anything

```bash
./run.sh --target 10.10.10.5 --dry-run
```

Prints the exact shell command that *would* run at each step. Safe for scope
review, auditing, or extracting individual commands for manual execution.

### Force specific modules only

```bash
./run.sh --target 10.10.10.5 --modules smb ldap web
```

Skips auto-detection and runs exactly the listed modules in tier order.

### Quick mode — OSCP exam first pass

```bash
./run.sh --target 10.10.10.5 --quick --lhost 10.10.14.5
```

`--quick` caps every module at **120 seconds** and then moves on. Use this
for a fast first pass over all exam machines to collect low-hanging fruit,
then run a second full pass (without `--quick`) on the most promising targets.

### Custom output directory

```bash
./run.sh --target 10.10.10.5 --output-dir /root/oscp/exam --lhost 10.10.14.5
```

### All flags

| Flag | Short | Default | Description |
| ---- | ----- | ------- | ----------- |
| `--target` | `-t` | *(required)* | Target IP address |
| `--domain` | `-d` | `""` | Target domain (e.g. `corp.local`). Passed to LDAP, DNS, SMB, Kerberos, and web modules |
| `--lhost` | | `""` | Your attacker/VPN IP. Pre-fills all `<LHOST>` placeholders in `notes.md` |
| `--resume` | | `false` | Resume from `session.json`. Skips Nmap and completed modules |
| `--modules` | `-m` | *(auto)* | Force specific modules. Choices: `smb ftp ldap dns snmp nfs services network databases remote mail web` |
| `--quick` | `-q` | `false` | Quick mode — abort each module after 120 s and move on. Ideal for OSCP first-pass recon |
| `--dry-run` | | `false` | Print commands without executing any |
| `--output-dir` | | `output/targets` | Base directory for scan output |
| `--verbose` | `-v` | `false` | Show DEBUG-level log messages in the terminal |

---

## Terminal Output

ARGUS streams all tool output directly to the terminal with colour-coded prefixes:

| Prefix | Colour | Meaning |
| ------ | ------ | ------- |
| `[+]` | Green | Discovery / confirmed finding |
| `[!]` | Yellow | Warning / high-value finding |
| `[CMD]` | Yellow dim | Command about to be executed |
| `[MANUAL]` | Magenta | Attack-adjacent hint — run manually |
| `[SKIP]` | Dim | Tool not installed — step skipped |
| `[*]` | Cyan | Informational progress line |
| *(plain)* | Dim | Raw subprocess output |

### Module tier banners

```text
════════════════ TIER 1 — LIGHTNING FAST (smb · ftp · ldap · dns · snmp · nfs · services) ════
  [CMD] bash wrappers/smb_enum.sh --target 10.10.10.5 --output-dir output/targets/10.10.10.5
  [+] SMB shares found: ['backups', 'Samantha Konstan']
  [MANUAL] List SMB share: smbclient '//10.10.10.5/backups' -N -c 'ls'
  [!] SMB signing disabled — NTLM relay risk
  completed in 1m 23s

════════════════ TIER 3 — HEAVY (web enumeration — always last) ════════════════════════════
  [CMD] bash wrappers/web_enum.sh --target 10.10.10.5 --port 80 ...
  [+] HIGH-VALUE PATH: /backup_migrate
  [+] Apache 2.4.18 on port 80 — check searchsploit apache 2.4.18
```

### Attack path panel (end of run)

After all modules complete, ARGUS prints a synthesized panel showing every
manual step in priority order:

```text
══════════════════ 🎯  ATTACK PATH — RUN THESE MANUALLY ══════════════════

┌─ PRIORITIZED NEXT STEPS ────────────────────────────────────────────────┐
│                                                                          │
│  🔴 CRITICAL  NTLM relay viable — SMB signing disabled                 │
│               sudo responder -I tun0 -wd                                │
│                                                                          │
│  🔴 CRITICAL  SMBv1 detected — verify EternalBlue (MS17-010)           │
│               nmap -p 445 --script smb-vuln-ms17-010 10.10.10.5        │
│                                                                          │
│  🟠 HIGH      Readable SMB share: 'Samantha Konstan'                   │
│               smbclient '//10.10.10.5/Samantha Konstan' -N -c 'ls'    │
│                                                                          │
│  🟠 HIGH      SSH password auth enabled — brute-force viable           │
│               hydra -L users.txt -P rockyou.txt ssh://10.10.10.5       │
│                                                                          │
│  🟡 MEDIUM    CHECK PASSWORD POLICY before ANY spray                   │
│               crackmapexec smb 10.10.10.5 --pass-pol                   │
│                                                                          │
│  🟡 MEDIUM    AS-REP Roasting — find accounts without pre-auth         │
│               impacket-GetNPUsers CORP/ -dc-ip 10.10.10.5 -no-pass ... │
│                                                                          │
│  🔵 INFO      47 web paths discovered                                  │
│               cat output/.../web/gobuster*.txt | sort | uniq           │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

The same content is written to the top of `notes.md` as the **Prioritized
Attack Path** section with full commands.

---

## Module Reference

Modules run in strict tier order within each tier. Auto-detection is based on
Nmap's service detection output and well-known port fallbacks.

| Module | Tier | Wrapper | What it enumerates |
| ------ | ---- | ------- | ------------------ |
| **RECON** | — | `recon.sh` | TTL OS detection; RustScan/nmap all-port TCP sweep; UDP top-100; deep `-sC -sV -O` targeted scan; DNS zone transfer; background NSE `vuln,auth` scan in parallel |
| **SMB** | 1 | `smb_enum.sh` | Nmap SMB scripts (vuln, shares, os-discovery, smb2-security-mode); enum4linux-ng; smbmap null+guest; rpcclient user/group enum; nxc shares, users, password policy; RID cycling; SMBv1 detection; signing check; share name → username inference; manual smbclient hints per readable share; authenticated enum if credentials provided |
| **FTP** | 1 | `ftp_enum.sh` | Banner grab; Nmap FTP NSE (ftp-anon, vsftpd-backdoor, bounce); anonymous login test; recursive directory listing; interesting file flagging |
| **LDAP** | 1 | `ldap_enum.sh` | Nmap LDAP scripts; ldapsearch anonymous bind + full object dump; windapsearch user/privileged/groups/computers/AS-REP candidates; targeted search for password-in-description fields and Kerberoastable SPNs; Kerberos port 88 DC detection; kerbrute username enumeration via AS-REQ (no auth) |
| **DNS** | 1 | `services_enum.sh` + direct `dig` | Nmap zone-transfer scripts; reverse PTR lookups; `dig AXFR` zone transfer attempt (results in `dns/axfr_dig.txt`); discovered hostnames parsed and added to `domains_found`; subdomain brute-force hints |
| **SNMP** | 1 | `services_enum.sh` | onesixtyone community string sweep; snmpwalk full MIB walk; process list; network interfaces (pivot detection); user extraction |
| **NFS** | 1 | `nfs_enum.sh` | rpcinfo portmapper dump; showmount export listing; Nmap NFS scripts; `no_root_squash` detection |
| **SVC** | 1 | `services_enum.sh` | SSH audit (ssh-audit) + auth method enumeration; Telnet banner; MSRPC rpcdump; banner grabs for non-standard ports |
| **NET** | 1 | `network_enum.sh` | ICMP TTL; traceroute; ARP /24 sweep; dual-homed host detection |
| **DB** | 2 | `db_enum.sh` | MSSQL, MySQL, PostgreSQL, Redis, MongoDB — version fingerprint and anonymous access tests |
| **RMT** | 2 | `remote_enum.sh` | RDP NLA detection and BlueKeep version check; WinRM fingerprint; VNC probe |
| **MAIL** | 2 | `mail_enum.sh` | SMTP banner + NSE; user enumeration via VRFY/EXPN/RCPT; NTLM info-disclosure; open relay; POP3/IMAP banner; TLS detection |
| **WEB** | 3 | `web_enum.sh` | curl headers; whatweb tech detection + Apache/nginx version flagging; gobuster directory brute-force; feroxbuster recursive scan (`--no-state`, stdin disconnected); nikto; sslscan TLS/cert; ffuf vhost fuzzing; CMS scanner routing (wpscan/droopescan/joomscan); CGI sniper for Shellshock; high-value path detection; downloadable file detection with wget+strings analysis hints |

### What each module adds to `notes.md`

| Module | Key findings surfaced |
| ------ | --------------------- |
| SMB | Shares accessible, manual smbclient commands, username inference from share names, SMBv1/signing flags, password spray hints, AS-REP Roasting hint |
| LDAP | Base DN, user list, description-field password detection, Kerberoastable SPNs, kerbrute validated users, credential correlation across all open services |
| WEB | CMS detected, Apache/nginx version, high-value paths (`.git`, `phpmyadmin`, `backup_migrate`…), sensitive file extensions, downloadable file analysis hints |
| SVC | SSH CVEs, password auth enabled with hydra command, MSRPC high-value endpoints |
| NFS | Export paths with manual mount commands |
| SNMP | Community strings, processes, users |
| MAIL | Valid SMTP users |
| DB | Empty/unauthenticated database access |

---

## Output Structure

All output is written under `output/targets/<IP>/` (configurable with `--output-dir`):

```text
output/targets/10.10.10.5/
│
├── session.json          ← Persistent state: ports, domain, users, findings
├── notes.md              ← Structured Markdown report, rebuilt after every module
├── users.txt             ← All discovered usernames (auto-updated, deduplicated)
├── domain.txt            ← Discovered domain name, read by subsequent wrappers
├── session.jsonl         ← Structured JSON Lines audit log (DEBUG level)
├── _commands.log         ← Timestamped list of every command executed (audit trail)
├── _manual_commands.txt  ← All [MANUAL] hints collected in one file, copy-paste ready
│
├── scans/
│   ├── allports.txt          ← Fast TCP scan — all 65535 ports
│   ├── open_ports.txt        ← Comma-separated open TCP port list
│   ├── udp.txt               ← UDP top-100 scan
│   ├── open_ports_udp.txt    ← Comma-separated open UDP ports
│   ├── targeted.nmap         ← Deep -sC -sV -O scan (human-readable)
│   ├── targeted.xml          ← Deep scan XML (parsed by Python engine)
│   ├── nmap_initial.xml      ← Copy used by port parser
│   └── vulns.txt             ← NSE vuln+auth scan (background)
│
├── smb/
│   ├── nmap_smb.txt           ← Nmap SMB NSE scripts
│   ├── enum4linux.txt         ← enum4linux-ng output
│   ├── smbmap_null.txt        ← Null session share map
│   ├── smbclient.txt          ← Share list
│   ├── rpcclient.txt          ← User/group enumeration
│   ├── nxc_shares.txt         ← nxc share listing (used for SMBv1, signing, domain)
│   ├── nxc_users.txt          ← nxc user enumeration
│   └── users_rpc.txt          ← Consolidated user list from rpcclient
│
├── ldap/
│   ├── ldapsearch_base.txt    ← Naming context discovery
│   ├── ldapsearch_full.txt    ← Full anonymous dump
│   ├── ldap_users.txt         ← Extracted sAMAccountName list
│   ├── ldap_computers.txt     ← Computer accounts
│   ├── ldap_groups.txt        ← Group names
│   ├── ldap_descriptions.txt  ← Accounts with description fields (password check)
│   ├── ldap_spns.txt          ← Kerberoastable SPNs
│   ├── windapsearch_*.txt     ← windapsearch module outputs
│   ├── kerbrute_users.txt     ← Raw kerbrute output
│   ├── valid_users.txt        ← Confirmed Kerberos usernames
│   └── asrep_candidates.txt   ← Accounts without pre-auth (windapsearch)
│
├── web/
│   ├── whatweb<suffix>.txt    ← Technology fingerprint + version detection
│   ├── gobuster<suffix>.txt   ← Directory brute-force
│   ├── feroxbuster<suffix>.txt← Recursive directory scan
│   ├── nikto<suffix>.txt      ← Nikto vulnerability scan
│   ├── sslscan<suffix>.txt    ← TLS/SSL enumeration
│   ├── ffuf_vhost<suffix>.txt ← Vhost fuzzing results
│   └── wpscan<suffix>.txt     ← WordPress scan (if CMS detected)
│
├── dns/
│   ├── dns_nmap.txt           ← Nmap DNS zone-transfer / recursion scripts
│   └── axfr_dig.txt           ← Full dig AXFR zone transfer output
│
├── ssh/                       ← ssh-audit output, auth methods
├── ftp/                       ← Banner, NSE scripts, directory tree
├── db/                        ← Per-engine NSE and CLI output
├── smtp/ mail/                ← SMTP/POP3/IMAP enumeration
├── nfs/                       ← rpcinfo, showmount, NSE
├── snmp/                      ← Community strings, processes, users
├── msrpc/                     ← rpcdump, Nmap MSRPC
├── remote/                    ← RDP/WinRM/VNC enumeration
├── network/                   ← traceroute, ARP sweep, PTR lookups
└── loot/                      ← Reserved for operator-downloaded files
```

### notes.md structure

The report is rebuilt after every module. Sections appear in this order:

| Section | Content |
| ------- | ------- |
| **🎯 Prioritized Attack Path** | Dynamic attack path synthesized from ALL findings — ordered critical → high → medium → info, with exact manual commands |
| **Target Overview** | IP, domain, OS guess, scan date, open ports table |
| **Vulnerabilities & Critical Findings** | CVE matches, signing disabled, `no_root_squash`, unauthenticated access |
| **Confirmed Access & Anonymous Sessions** | Anonymous FTP/SMB, null sessions, Redis unauthenticated |
| **Enumeration Discoveries** | Shares, users, web paths, hostnames, domains |
| **SMB Shares** | Table of accessible shares + manual smbclient commands |
| **User Accounts** | All discovered usernames across all modules |
| **CGI / Shellshock Alert** | Per-URL Shellshock test template (if CGI scripts found) |
| **Web Paths** | Up to 50 discovered paths |
| **OSCP Manual Checklist** | Per-port action items with copy-paste commands |
| **Manual Follow-Up Commands** | All `[MANUAL]` hints from every module as `- [ ]` checklist |
| **Session Timeline** | Full timestamped log of every finding |
| **Arsenal Recommender** | OS-appropriate PrivEsc, file transfer, and post-shell survival kit |

---

## How Manual Hints Work

ARGUS never executes attack-adjacent commands. When a module detects a
condition that warrants further action, it records a `[MANUAL]` note. These
appear in four places:

1. **Terminal** — inline during the scan with a magenta `[MANUAL]` prefix
2. **Attack path panel** — at end of run, ordered by priority
3. **`notes.md`** — under "Manual Follow-Up Commands" as `- [ ]` checklist items
4. **`_manual_commands.txt`** — a standalone plain-text file with every manual command,
   one per block, grouped by context — the fastest way to copy-paste during an exam

```bash
# View all manual commands at end of run
cat output/targets/10.10.10.5/_manual_commands.txt
```

### Example — SMBv1 detected

```text
[!] SMBv1 ENABLED on 10.10.10.5 — potential EternalBlue (MS17-010) target.
[MANUAL] nmap -p 445 --script smb-vuln-ms17-010 10.10.10.5
```

### Example — Readable SMB share with spaces in the name

```text
[+] SMB shares accessible: ['Samantha Konstan', 'backups']
[MANUAL] List SMB share: smbclient '//10.10.10.5/Samantha Konstan' -N -c 'ls'
[MANUAL] Download SMB share: smbclient '//10.10.10.5/Samantha Konstan' -N -c 'recurse ON; prompt OFF; mget *'
```

### Example — Users found → spray pipeline

```text
[MANUAL] Password policy check (before spraying): crackmapexec smb 10.10.10.5 --pass-pol
[MANUAL] AS-REP Roasting (no pre-auth accounts): impacket-GetNPUsers CORP/ -dc-ip 10.10.10.5 -no-pass -usersfile users.txt ...
[MANUAL] SMB spray: crackmapexec smb 10.10.10.5 -u users.txt -p /usr/share/wordlists/rockyou.txt --no-bruteforce
[MANUAL] SSH spray (rate-limited): hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.5 -t 4 -w 3
```

### Example — LDAP description field password

```text
[!] LDAP: 3 accounts have description fields — review for embedded passwords
[CRITICAL] LDAP description field looks like a password: 'Welcome2023!'
```

### Example — Downloadable file found by web scanner

```text
[+] Potential download/loot file at: http://10.10.10.5/files/backup
[MANUAL] Download and inspect: wget 'http://10.10.10.5/files/backup' -O /tmp/backup &&
         file /tmp/backup && strings /tmp/backup | grep -iE 'pass|user|admin|secret|key|token' | head -20
```

---

## Module Timeouts

Every module has a hard timeout. If a tool hangs (e.g. feroxbuster on a huge
site), the process group is killed and the next module starts automatically.
This prevents a single slow scan from blocking the entire exam clock.

| Module | Default timeout |
| ------ | --------------- |
| `web` | 60 min |
| `smb` | 10 min |
| `ldap` | 10 min |
| `snmp` | 5 min |
| `services` | 5 min |
| `databases` | 5 min |
| `ftp` | 3 min |
| `dns` | 3 min |
| `nfs` | 3 min |
| `remote` | 3 min |
| `mail` | 3 min |
| `network` | 2 min |

`--quick` overrides all of these with a flat **120 s** limit per module.

---

## Audit Trail

Two files are written to the target directory during every run:

### `_commands.log`

Every command executed is appended with a timestamp:

```text
[10:23:01] [CMD] bash wrappers/smb_enum.sh --target 10.10.10.5 --output-dir ...
[10:24:34] [CMD] bash wrappers/ldap_enum.sh --target 10.10.10.5 ...
[10:31:07] [CMD] bash wrappers/web_enum.sh --target 10.10.10.5 --port 80 ...
```

`--dry-run` commands are also logged with a `[DRY-RUN]` prefix — useful for
reviewing scope before starting a live scan.

### `_manual_commands.txt`

Every `[MANUAL]` hint is appended as an executable block:

```text
# Check password policy before any spray (avoid lockouts)
crackmapexec smb 10.10.10.5 --pass-pol

# List SMB share: backups
smbclient '//10.10.10.5/backups' -N -c 'ls'

# AS-REP Roasting — extract hashes from accounts without pre-auth
impacket-GetNPUsers CORP/ -dc-ip 10.10.10.5 -no-pass -usersfile users.txt ...

# VHost discovered — add to /etc/hosts and re-enumerate: dev.corp.local
echo '10.10.10.5  dev.corp.local' | sudo tee -a /etc/hosts
```

---

## Legal & Ethics

This tool is intended for **authorized penetration testing only**.

Always obtain written permission before running any enumeration or attack tools
against a target. Running ARGUS against systems you do not own or do not have
explicit written authorization to test is illegal in most jurisdictions.

The author is not responsible for misuse. Use responsibly and ethically.

---

## Author

☠ by **acanoman** ☠

---

*ARGUS Enumeration Framework — Assisted recon. Never autopwn.*
