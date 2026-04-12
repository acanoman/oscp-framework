# ARGUS — Enumeration Framework

```
 ██████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
███████║██████╔╝██║  ███╗██║   ██║███████╗
██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
```

> **Assisted recon. Never autopwn.**
> Recon → Enumerate → Report

☠ by acanoman ☠

---

## What is ARGUS

ARGUS is a modular enumeration framework for penetration testing and OSCP+ exam preparation.
It orchestrates a structured, tiered reconnaissance pipeline against a single target, then
surfaces all discovered attack surface as human-readable **manual hints** — copy-paste
commands for the operator to decide whether and when to execute.

**What ARGUS does:**

- Runs 11 enumeration modules in the correct dependency order (Tier 1 → 2 → 3)
- Streams every tool's stdout into a cyberpunk terminal UI in real time
- Writes a structured `notes.md` with OSCP-style manual checklists after every module
- Persists session state so you can `--resume` interrupted scans without repeating work
- Surfaces attack-adjacent commands (AS-REP Roast, Kerberoast, NTLM relay) as **manual
  hints only** — none are executed automatically

**What ARGUS does NOT do:**

- Exploit anything
- Brute-force credentials without explicit operator action
- Run prohibited tools (SQLMap, mass scanners) automatically
- Chain discoveries into automated attack sequences

---

## OSCP+ Compliance

> Reviewed for OSCP+ exam compliance — manual operator control at every step.

| Requirement | ARGUS Behaviour |
|-------------|-----------------|
| No automated exploitation | All attack chains appear as `[MANUAL]` hints only — the framework never executes exploits |
| No prohibited tools | SQLMap, mass scanners, and automated brute-force are never invoked |
| Metasploit not used | Zero Metasploit references in any wrapper or Python module |
| All commands shown first | Every subprocess call is logged with a `[CMD]` prefix before execution |
| Attack commands = hints only | AS-REP Roast, Kerberoast, NTLM Relay, xp_cmdshell appear as `[MANUAL]` hints in the TUI and `notes.md` |
| No credential caching violations | Discovered usernames and hashes are written only to the local output directory |
| Full transparency | `--dry-run` prints every command without executing any |

Every wrapper script opens with an explicit OSCP compliance block. For example, `ldap_enum.sh`:

```bash
# OSCP compliance:
#   - AS-REP Roasting and Kerberoasting → manual hints only
#   - No password attacks of any kind
#   - Prints every command before execution
```

---

## Requirements

### Python

Python **3.8 or newer** is required. 3.10+ is recommended.

### pip packages

```
rich>=13.0.0
pyfiglet>=0.8.0
```

Install with:

```bash
pip install -r requirements.txt
```

### External tools (must be installed separately)

ARGUS will skip any tool that is not installed and warn you — it will never abort a scan
because a secondary tool is missing.

| Category | Tool | Role |
|----------|------|------|
| **Required** | `nmap` | Port scanning and NSE scripts |
| **Required** | `smbclient` | SMB share listing |
| **Required** | `smbmap` | SMB share access mapping |
| **Required** | `rpcclient` | RPC/SMB user enumeration |
| **Required** | `ldapsearch` | LDAP anonymous bind and dump (`ldap-utils` package) |
| **Required** | `curl` | HTTP header grab |
| **Required** | `gobuster` | Web directory and DNS brute-force |
| **Required** | `nikto` | Web vulnerability scanner |
| **Required** | `whatweb` | Web technology fingerprinting |
| **Required** | `showmount` | NFS export listing (`nfs-common` package) |
| **Required** | `snmpwalk` | SNMP MIB walk (`snmp` package) |
| **Required** | `smtp-user-enum` | SMTP user verification via VRFY/EXPN/RCPT |
| Optional | `rustscan` | Faster all-port scanner (falls back to nmap) |
| Optional | `feroxbuster` | Recursive web directory fuzzer |
| Optional | `ffuf` | Vhost and parameter fuzzing |
| Optional | `sslscan` | TLS/SSL certificate and cipher enumeration |
| Optional | `wpscan` | WordPress scanner (enumerate-only mode) |
| Optional | `nxc` / `netexec` | SMB sessions, RID cycling, share spider |
| Optional | `enum4linux-ng` | SMB/LDAP/RPC full enumeration (preferred over enum4linux) |
| Optional | `kerbrute` | Kerberos username enumeration (AS-REQ probe, no auth) |
| Optional | `windapsearch` | AD user/group/SPN enumeration via LDAP |
| Optional | `evil-winrm` | WinRM shell — manual use only (`gem install evil-winrm`) |
| Optional | `xfreerdp` | RDP client — manual use only (`freerdp2-x11` package) |
| Optional | `impacket-*` | AS-REP Roast, Kerberoast, SID/RID lookup — manual hints |
| Optional | `bloodhound-python` | BloodHound data collection — manual hint |
| Optional | `onesixtyone` | SNMP community string sweep |

**OS:** Kali Linux or any Debian-based distribution is strongly recommended.

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/acanoman/oscp-framework
cd oscp-framework

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Make all wrappers executable
chmod +x wrappers/*.sh

# 4. Run the full installer
#    Sets permissions, installs apt packages, verifies tool availability,
#    and runs a Python import smoke test across all modules.
sudo bash install.sh
```

`install.sh` does **not** download any tools from the internet during an exam. It installs
only packages available through `apt` and `gem`, and checks whether optional tools are
already present. All checks are non-fatal — the installer reports missing tools as warnings.

---

## Usage

### Basic scan — auto-detect modules from open ports

```bash
python3 main.py --target 10.10.10.5
```

### With a known AD domain

```bash
python3 main.py --target 10.10.10.5 --domain corp.local
```

### Full exam run — target + domain + attacker IP

```bash
python3 main.py --target 10.10.10.5 --domain corp.local --lhost 10.10.14.5
```

`--lhost` pre-fills every `<LHOST>` placeholder in transfer and reverse-shell commands
inside `notes.md`, making them copy-paste ready without manual editing.

### Resume an interrupted session

```bash
python3 main.py --target 10.10.10.5 --resume
```

Re-reads `session.json`, skips Nmap and completed modules, and continues from where the
session stopped. Without `--resume`, the framework always starts a fresh scan — even if
`session.json` exists — so you never accidentally skip a service that appeared after a
network change.

### Preview every command without running anything

```bash
python3 main.py --target 10.10.10.5 --dry-run
```

Prints the exact shell command that *would* run at each step. Safe for scope review,
auditing, or copying individual commands for manual execution.

### Force specific modules only

```bash
python3 main.py --target 10.10.10.5 --modules smb ldap web
```

Skips auto-detection and runs exactly the listed modules in tier order.

### Custom output directory

```bash
python3 main.py --target 10.10.10.5 --output-dir /root/oscp/exam --lhost 10.10.14.5
```

### Preview the TUI without running anything

```bash
python3 ui/tui.py --demo
```

Plays through a simulated scan with fake log lines. Use this to learn the keyboard
shortcuts and panel layout before an exam.

### All flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--target` | `-t` | *(required)* | Target IP address |
| `--domain` | `-d` | `""` | Target domain (e.g. `corp.local`). Passed to LDAP, DNS, SMB, and web modules |
| `--lhost` | | `""` | Your attacker/VPN IP. Pre-fills all `<LHOST>` placeholders in `notes.md` |
| `--resume` | | `false` | Resume from `session.json`. Skips Nmap and completed modules |
| `--modules` | `-m` | *(auto)* | Force specific modules. Choices: `smb ftp ldap dns snmp nfs services network databases remote mail web` |
| `--dry-run` | | `false` | Print commands without executing any |
| `--output-dir` | | `output/targets` | Base directory for scan output |
| `--verbose` | `-v` | `false` | Show DEBUG-level log messages |

---

## TUI — Terminal Interface

The cyberpunk terminal UI runs automatically when you launch `main.py`. To preview it
standalone without running any real commands:

```bash
python3 ui/tui.py --demo
```

### Layout overview

```
┌─ ● ● ●  A R G U S  —  T E R M I N A L  ─────────────────────────────┐
│   ██████╗ ██████╗  ██████╗ ██╗   ██╗███████╗                         │
│   ...                                                                  │
│   E N U M E R A T I O N   F R A M E W O R K  v1.0                    │
│                            Assisted recon. Never autopwn.  ☠ acanoman │
├──────────────┬─────────────────────────────────────────────────────────┤
│  MODULES     │  LIVE OUTPUT                                            │
│  [✓] RECON   │  08:42:11  [✓] RECON complete — 8 ports open          │
│  [✓] SMB     │  08:42:15  [+] SMB signing disabled                   │
│  [>] LDAP    │  08:42:25  [+] Kerbrute: 4 valid users found          │
│  [ ] WEB     │  08:42:26  [!] Users saved to valid_users.txt         │
│  [ ] DB      │  08:42:28  [-] LDAP running...                        │
│  [ ] FTP     ├─────────────────────────────────────────────────────────┤
│  [ ] MAIL    │  MANUAL HINTS  [H to toggle]                           │
│  [ ] NFS     │  AS-REP Roast:                                         │
│  [ ] NET     │    impacket-GetNPUsers CORP/ -usersfile valid_users.txt│
│  [ ] SVC     │    -no-pass -dc-ip 10.10.10.5                         │
│  [ ] RMT     │                                                        │
├──────────────┴─────────────────────────────────────────────────────────┤
│ TARGET 10.10.10.5 │ DOMAIN CORP.LOCAL │ MODULE LDAP │ RUNNING │ 00:01:47│
│                    [H] hints  [SPACE] pause  [Q] quit                  │
└────────────────────────────────────────────────────────────────────────┘
```

### Module sidebar — colour coding

| Icon | Colour | Meaning |
|------|--------|---------|
| `[✓]` | Green `#00ff88` | Module completed successfully |
| `[>]` | Cyan `#00d4ff` (blinking) | Module currently running |
| `[ ]` | Dim purple `#3a2060` | Module pending — not yet started |

### Live output — log line colours

| Prefix | Colour | Meaning |
|--------|--------|---------|
| `[+]` | Cyan | Discovery / finding |
| `[!]` | Yellow | Warning / high-value finding |
| `[>]` | Bright purple | Command echoed before execution |
| `[✓]` | Green | Success / module complete |
| `[-]` | Muted grey | Informational |

### MANUAL HINTS panel

The hints panel surfaces commands that ARGUS found evidence for but will **never execute
automatically** — AS-REP Roast targets, Kerberoastable SPNs, NFS shares with
`no_root_squash`, NTLM relay conditions, and more. Each hint shows a label and the exact
copy-paste command pre-filled with the target's IP, domain, and discovered usernames.

The same hints appear in `notes.md` under "Manual Follow-Up Commands".

### Keyboard shortcuts

| Key | Action |
|-----|--------|
| `H` | Toggle MANUAL HINTS panel on/off |
| `SPACE` | Pause / resume auto-scroll of live output |
| `↑` / `↓` | Scroll live output manually while paused |
| `Q` | Quit — stops the TUI and prints a session summary to stdout |
| `Ctrl+C` | Same as Q — clean exit with session state saved |

---

## Module Reference

Modules run in strict tier order: **Tier 1** (fast, ≤2 min each) → **Tier 2** (medium)
→ **Tier 3** (heavy, always last). Within each tier, modules run in the order they were
discovered from Nmap's service detection output.

| Module | Sidebar | Wrapper | Tier | What it enumerates |
|--------|---------|---------|------|--------------------|
| **RECON** | `RECON` | `recon.sh` | — | TTL OS detection via ping; RustScan/nmap full TCP sweep (all 65535 ports); UDP top-100; deep `-sC -sV -O` targeted scan on open ports; DNS zone transfer if port 53 is open; background NSE `vuln,auth` scan (runs in parallel, alerts when done) |
| **SMB** | `SMB` | `smb_enum.sh` | 1 | Nmap SMB NSE scripts (smb-vuln\*, smb-enum-shares, smb-os-discovery, smb2-security-mode); enum4linux-ng/enum4linux null session; smbmap null + guest recursive listing; smbclient share list; rpcclient user and group enumeration; nxc/netexec shares, users, password policy; RID cycling (null → guest → impacket-lookupsid fallback); per-share deep spider for interesting file types; authenticated enum if `--user/--pass` supplied |
| **LDAP** | `LDAP` | `ldap_enum.sh` | 1 | Nmap LDAP scripts; ldapsearch anonymous bind + naming context discovery + full object dump; windapsearch: full user list, privileged accounts (adminCount=1), groups, computers, AS-REP candidates; targeted ldapsearch for password-in-description fields and Kerberoastable SPNs; Kerberos port 88 detection; kerbrute Kerberos username enumeration via AS-REQ (no auth attempted) |
| **WEB** | `WEB` | `web_enum.sh` | 3 | curl headers and response fingerprint; whatweb technology detection; gobuster/feroxbuster recursive directory brute-force; nikto vulnerability scan; sslscan with TLS certificate SAN extraction; ffuf vhost fuzzing; wpscan (WordPress), droopescan (Drupal/Joomla), joomscan; CGI script sniper for Shellshock (CVE-2014-6271) attack surface |
| **DB** | `DB` | `db_enum.sh` | 2 | MSSQL (1433): Nmap NSE probes, anonymous connection test; MySQL (3306): version fingerprint, anonymous access; PostgreSQL (5432): version, anonymous access; Redis (6379): ping, key listing, config dump; MongoDB (27017): unauthenticated database listing |
| **FTP** | `FTP` | `ftp_enum.sh` | 1 | Banner grab; Nmap FTP NSE scripts (ftp-anon, ftp-bounce, ftp-syst, ftp-vsftpd-backdoor); anonymous login test; recursive directory listing; interesting file type flagging (.zip, .bak, .conf, .key, etc.); FTPS/TLS detection |
| **MAIL** | `MAIL` | `mail_enum.sh` | 2 | SMTP banner + Nmap NSE scripts; SMTP user enumeration via VRFY → EXPN → RCPT fallback (uses SMB/LDAP user lists from earlier modules); NTLM info disclosure probe; open relay detection via NSE; POP3/IMAP banner grab; TLS/STARTTLS version detection |
| **NFS** | `NFS` | `nfs_enum.sh` | 1 | rpcinfo portmapper endpoint dump; showmount -e export listing; Nmap NFS NSE scripts; `no_root_squash` detection flagged as a privilege escalation finding |
| **NET** | `NET` | `network_enum.sh` | 1 | ICMP TTL probe; traceroute to map hops; Nmap topology/neighbour scan; ARP /24 segment sweep; reverse DNS / PTR lookups; dual-homed host detection and pivot indicator analysis |
| **SVC** | `SVC` | `services_enum.sh` | 1 | SSH banner grab and authentication method enumeration (ssh-audit); Nmap service scripts for SSH, Telnet, MSRPC, SNMP, IMAP, POP3, RDP; onesixtyone SNMP community string sweep; snmpwalk network interface OID walk (dual-homed detection); generic banner grabs for non-standard ports |
| **RMT** | `RMT` | `remote_enum.sh` | 2 | RDP (3389): Nmap rdp-enum-encryption, NLA detection, CVE-2019-0708 BlueKeep version check; WinRM (5985/5986): version fingerprint and authentication method; VNC port detection and version probe |

---

## Output Structure

All output is written under `output/targets/<IP>/` (configurable with `--output-dir`):

```
output/targets/10.10.10.5/
│
├── session.json          ← Persistent state: ports, domain, users, module status
├── notes.md              ← Structured Markdown report, updated after every module
├── users.txt             ← All discovered usernames, auto-updated
├── domain.txt            ← Discovered domain name, read by subsequent wrappers
├── session.jsonl         ← Structured JSON Lines audit log
│
├── scans/
│   ├── allports.txt          ← Fast TCP scan — all 65535 ports
│   ├── open_ports.txt        ← Comma-separated open TCP port list
│   ├── udp.txt               ← UDP top-100 scan
│   ├── open_ports_udp.txt    ← Comma-separated open UDP ports
│   ├── targeted.nmap         ← Deep -sC -sV -O scan (human-readable)
│   ├── targeted.xml          ← Deep scan XML (parsed by Python engine)
│   ├── nmap_initial.xml      ← Copy used by port parser
│   ├── ttl.txt               ← Raw TTL value from ping
│   ├── vulns.txt             ← NSE vuln+auth scan (background)
│   └── vulns.pid             ← PID of background vuln scan
│
├── smb/
│   ├── nmap_smb.txt           ← Nmap SMB NSE scripts
│   ├── enum4linux.txt         ← enum4linux-ng output
│   ├── smbmap_null.txt        ← Null session share map
│   ├── smbmap_null_recursive.txt
│   ├── smbclient.txt          ← Share list
│   ├── rpcclient.txt          ← User/group enumeration
│   ├── nxc_shares.txt         ← nxc share listing
│   ├── nxc_rid_brute.txt      ← RID cycling output
│   ├── users_rpc.txt          ← Consolidated user list
│   └── spider_<SHARE>.txt     ← Per-share file tree
│
├── ldap/
│   ├── ldap_nmap.txt          ← Nmap LDAP scripts
│   ├── ldapsearch_base.txt    ← Naming context discovery
│   ├── ldapsearch_full.txt    ← Full anonymous dump
│   ├── ldap_users.txt         ← Extracted sAMAccountName list
│   ├── ldap_computers.txt     ← Computer accounts
│   ├── ldap_groups.txt        ← Group names
│   ├── ldap_descriptions.txt  ← Accounts with Description fields
│   ├── ldap_spns.txt          ← Kerberoastable SPNs
│   ├── windapsearch_users.txt
│   ├── windapsearch_privusers.txt
│   ├── kerbrute_users.txt     ← Raw kerbrute output
│   ├── valid_users.txt        ← Confirmed Kerberos usernames
│   └── asrep_candidates.txt   ← Accounts without pre-auth
│
├── web/
│   ├── headers_<port>.txt     ← HTTP response headers
│   ├── whatweb_<port>.txt     ← Technology fingerprint
│   ├── gobuster_<port>.txt    ← Directory brute-force
│   ├── feroxbuster_<port>.txt ← Recursive directory scan
│   ├── nikto_<port>.txt       ← Nikto vulnerability scan
│   ├── sslscan_<port>.txt     ← TLS/SSL enumeration
│   └── wpscan_<port>.txt      ← WordPress scan (if detected)
│
├── ftp/                       ← FTP banner, NSE, directory tree
├── db/                        ← Per-engine NSE and CLI output
├── mail/ smtp/                ← SMTP/POP3/IMAP enumeration
├── nfs/                       ← rpcinfo, showmount, NSE
├── network/                   ← traceroute, ARP sweep, PTR lookups
├── remote/                    ← RDP/WinRM/VNC enumeration
└── loot/                      ← Files downloaded from shares or FTP
```

### notes.md structure

The report is written after every module and fully rebuilt at session end. Sections include:

| Section | Content |
|---------|---------|
| **Target Overview** | IP, domain, OS guess, scan date, services table |
| **Vulnerabilities & Critical Findings** | CVE matches, signing disabled, no_root_squash, unauthenticated access |
| **Confirmed Access & Anonymous Sessions** | Anonymous FTP/SMB, null sessions, Redis ping |
| **Enumeration Discoveries** | Shares, users, web paths, SAN hostnames, DNS entries |
| **OSCP Manual Checklist** | Per-port action items with copy-paste commands |
| **Manual Follow-Up Commands** | All `[MANUAL]` hints from every module as `- [ ]` checklist items |
| **Session Timeline** | Full timestamped log of every finding |
| **Arsenal Recommender** | OS-appropriate PrivEsc, file transfer, and post-shell survival kit |

---

## Manual Hints

ARGUS never executes attack-adjacent commands. When a module detects a condition that
warrants further action, it emits a `[MANUAL]` hint. These appear in two places:

1. **TUI hints panel** (press `H` to show/hide) — live during the scan
2. **`notes.md`** under "Manual Follow-Up Commands" — persistent in the report

### Example — LDAP → AS-REP Roast hint

When kerbrute confirms valid usernames and Kerberos port 88 is open:

```
[MANUAL] AS-REP Roasting — run manually after enumeration:
    impacket-GetNPUsers CORP/ \
        -usersfile /path/to/valid_users.txt \
        -no-pass \
        -dc-ip 10.10.10.5 \
        -format hashcat \
        -outputfile ldap/asrep_hashes.txt

    # Crack captured hashes:
    hashcat -m 18200 ldap/asrep_hashes.txt /usr/share/wordlists/rockyou.txt \
        -r /usr/share/john/rules/best64.rule
```

### Example — SMB → NTLM relay hint

When SMB signing disabled is detected:

```
[MANUAL] NTLM Relay (requires separate interface + authorization):
    Responder + ntlmrelayx must be run manually after reviewing scope.
    Do NOT automate relay attacks.
```

The operator reads each hint, reviews the discovered evidence, and decides whether to
run the command. ARGUS has already done the enumeration — the decision to act is always
the operator's.

---

## Legal & Ethics

This tool is intended for **authorized penetration testing only**.

Always obtain written permission before running any enumeration or attack tools against
a target. Running ARGUS against systems you do not own or do not have explicit written
authorization to test is illegal in most jurisdictions.

The author is not responsible for misuse. Use responsibly and ethically.

---

## Author

☠ by **acanoman** ☠

---

*ARGUS Enumeration Framework — Assisted recon. Never autopwn.*
