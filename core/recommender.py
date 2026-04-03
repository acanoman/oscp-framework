"""
core/recommender.py — OSCP-style suggestion engine
"""

import logging
from typing import TYPE_CHECKING, Optional

from rich.console import Console
from rich.table import Table

if TYPE_CHECKING:
    from core.session import TargetInfo

# Port → human-readable service label
_PORT_LABELS = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    88:    "Kerberos",
    110:   "POP3",
    111:   "RPC",
    135:   "MSRPC",
    139:   "NetBIOS",
    143:   "IMAP",
    161:   "SNMP",
    389:   "LDAP",
    443:   "HTTPS",
    445:   "SMB",
    636:   "LDAPS",
    873:   "Rsync",
    1433:  "MSSQL",
    1521:  "Oracle",
    2049:  "NFS",
    3268:  "LDAP-GC",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    5985:  "WinRM",
    5986:  "WinRM-S",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    9200:  "Elasticsearch",
    27017: "MongoDB",
}

# Per-service manual suggestions (OSCP-style hints, no exploitation)
_SUGGESTIONS = {
    "FTP": [
        "Try anonymous login: ftp {ip}",
        "Check for writable directories",
        "Look for sensitive files (config, backup, etc.)",
    ],
    "SSH": [
        "Note the banner / version for CVE research",
        "Check for username enumeration if version is old",
        "Try default credentials only if explicitly in scope",
    ],
    "HTTP": [
        "Run gobuster/ffuf for directory enumeration",
        "Check robots.txt and sitemap.xml",
        "Identify the web stack (Wappalyzer, headers)",
        "Look for LFI/RFI, SQLi on all parameters",
        "Check for default credentials on login pages",
    ],
    "HTTPS": [
        "Run gobuster/ffuf for directory enumeration",
        "Check TLS version and certificate for domain names",
        "Look for virtual hosts via certificate SANs",
    ],
    "SMB": [
        "Try null session: smbclient -L //{ip} -N",
        "Enumerate shares: smbmap -H {ip}",
        "Check guest access on each share",
        "Run enum4linux -a {ip}",
        "Check for EternalBlue (MS17-010) if older Windows",
    ],
    "LDAP": [
        "Anonymous bind: ldapsearch -x -H ldap://{ip} -b ''",
        "Enumerate base DN and users",
        "Check for AS-REP roasting (no pre-auth accounts)",
        "Dump naming contexts for domain info",
    ],
    "MSSQL": [
        "Try sa:sa or sa:(blank) credentials",
        "Check for xp_cmdshell if authenticated",
        "Enumerate linked servers",
    ],
    "MySQL": [
        "Try root:(blank) or root:root",
        "Enumerate databases if authenticated",
    ],
    "RDP": [
        "Note version — check for BlueKeep (CVE-2019-0708) on old systems",
        "Try known credentials if obtained",
    ],
    "WinRM": [
        "If credentials obtained: evil-winrm -i {ip} -u USER -p PASS",
        "Check HTTP and HTTPS ports (5985/5986)",
    ],
    "DNS": [
        "Try zone transfer: dig axfr @{ip} {domain}",
        "Enumerate subdomains with dnsrecon or gobuster dns",
    ],
    "NFS": [
        "List shares: showmount -e {ip}",
        "Mount and inspect: mount -t nfs {ip}:/share /mnt/",
        "Check for no_root_squash permission",
    ],
    "SNMP": [
        "Try community string 'public': snmpwalk -c public -v1 {ip}",
        "Enumerate with onesixtyone: onesixtyone -c community.txt {ip}",
    ],
}

# OS guess → colour for the table
_OS_COLOUR = {
    "Linux":          "green",
    "Windows":        "cyan",
    "Network Device": "yellow",
}


class Recommender:
    """
    Generates OSCP-style next-step suggestions based on discovered services.
    Never suggests exploitation — only enumeration and manual investigation.
    """

    def __init__(
        self,
        info:    "TargetInfo",
        log:     logging.Logger,
        console: Optional[Console] = None,
    ) -> None:
        self.info    = info
        self.log     = log
        self.console = console or Console()

    def print_summary(self) -> None:
        """Print full findings + manual next-step suggestions using rich."""
        ip = self.info.ip
        self.console.rule("[bold green] FINDINGS SUMMARY [/bold green]")

        if not self.info.open_ports:
            self.console.print("  [yellow]No open ports discovered yet.[/yellow]")
            return

        # ── Port table ──────────────────────────────────────────────
        table = Table(
            title=f"Open Ports — {ip}",
            border_style="blue",
            show_header=True,
            header_style="bold white",
            min_width=60,
        )
        table.add_column("Port",    style="bold cyan", width=8,  no_wrap=True)
        table.add_column("Service", style="white",     width=16, no_wrap=True)
        table.add_column("Version", style="dim")

        for port in sorted(self.info.open_ports):
            details = self.info.port_details.get(port, {})
            svc     = details.get("service", _PORT_LABELS.get(port, "?"))
            ver     = details.get("version", "") or ""
            table.add_row(str(port), svc, ver)

        self.console.print()
        self.console.print(table)
        self.console.print()

        # ── OS / domain / shares / users ────────────────────────────
        if self.info.os_guess and self.info.os_guess != "Unknown":
            colour = _OS_COLOUR.get(self.info.os_guess, "white")
            self.console.print(
                f"  [bold]OS Guess[/bold]  : [bold {colour}]{self.info.os_guess}[/bold {colour}]"
            )

        if self.info.domains_found:
            self.console.print(
                f"  [bold]🌐 Domains[/bold]  : {', '.join(self.info.domains_found)}"
            )

        if self.info.shares_found:
            self.console.print(
                f"  [bold]📂 Shares[/bold]   : [green]{', '.join(self.info.shares_found)}[/green]"
            )

        if self.info.users_found:
            self.console.print(
                f"  [bold]🔑 Users[/bold]    : [green]{', '.join(self.info.users_found)}[/green]"
            )

        if self.info.web_paths:
            self.console.print(
                f"\n  [bold]🌐 Web Paths[/bold] ({len(self.info.web_paths)} found):"
            )
            for p in self.info.web_paths[:20]:
                self.console.print(f"    [dim]{p}[/dim]")
            if len(self.info.web_paths) > 20:
                self.console.print(
                    f"    [dim]... and {len(self.info.web_paths) - 20} more[/dim]"
                )

        # ── Manual next steps ───────────────────────────────────────
        self.console.print()
        self.console.rule("[bold yellow] MANUAL NEXT STEPS [/bold yellow]")

        suggested_any = False
        for port in sorted(self.info.open_ports):
            label = _PORT_LABELS.get(port, "")
            hints = _SUGGESTIONS.get(label, [])
            if hints:
                self.console.print(
                    f"\n  [bold cyan][ {label} — port {port} ][/bold cyan]"
                )
                for hint in hints:
                    formatted = hint.format(
                        ip=ip,
                        domain=self.info.domain or "TARGET_DOMAIN",
                    )
                    self.console.print(f"    [dim]-[/dim] {formatted}")
                suggested_any = True

        if not suggested_any:
            self.console.print(
                "  [dim]No specific suggestions — investigate manually.[/dim]"
            )

        self.console.print()
