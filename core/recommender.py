"""
core/recommender.py — OSCP-style suggestion engine
"""

import logging
from typing import TYPE_CHECKING, Optional

from rich.console import Console
from rich.markup import escape as _esc
from rich.table import Table

from core.oscp_compliance import check_command, print_reminder
from core.cve_database import match_by_port

if TYPE_CHECKING:
    from core.session import TargetInfo

# Port → human-readable service label
_PORT_LABELS = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    69:    "TFTP",
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
    464:   "KerberosPW",
    636:   "LDAPS",
    873:   "Rsync",
    993:   "IMAPS",
    995:   "POP3S",
    1433:  "MSSQL",
    1521:  "Oracle",
    2049:  "NFS",
    2375:  "Docker-API",
    3268:  "LDAP-GC",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    5985:  "WinRM",
    5986:  "WinRM-S",
    6379:  "Redis",
    8000:  "HTTP-8000",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    9200:  "Elasticsearch",
    10000: "Webmin",
    11211: "Memcached",
    27017: "MongoDB",
}

# Per-service manual suggestions (OSCP-style hints, no exploitation)
_SUGGESTIONS = {
    "FTP": [
        "Try anonymous login: ftp {ip}",
        "Check for writable directories (put test file)",
        "Look for sensitive files (config, backup, .sql, id_rsa)",
        "Check banner for version → searchsploit vsftpd/proftpd/pure-ftpd",
        "If bounce scan works: nmap -b anonymous@{ip} -p 22,80 TARGET2",
    ],
    "SSH": [
        "Note the banner / version for CVE research",
        "Check for username enumeration if version is old",
        "Try default credentials only if explicitly in scope",
    ],
    "TELNET": [
        "Capture banner: nc -nv {ip} 23",
        "Try default credentials (router/IoT admin:admin, root:root)",
        "Check if cleartext creds flow (Wireshark / tcpdump)",
    ],
    "SMTP": [
        "Enumerate users: smtp-user-enum -M VRFY -U users.txt -t {ip}",
        "Check open relay: swaks --to test@example.com --from test@{ip} --server {ip}",
        "Grab banner: nc -nv {ip} 25 → note SMTP server for CVEs",
    ],
    "TFTP": [
        "Try to fetch config files: tftp {ip} -c get config.cfg (Cisco/router)",
        "Common filenames: startup-config, running-config, /etc/passwd",
        "Check writable: tftp {ip} -c put test.txt",
    ],
    "DNS": [
        "Try zone transfer: dig axfr @{ip} {domain}",
        "Enumerate subdomains with dnsrecon or gobuster dns",
        "Check for DNSSEC and BIND version: dig @{ip} version.bind CHAOS TXT",
        "Try reverse lookup for nearby hosts: dig -x {ip} @{ip}",
    ],
    "POP3": [
        "Grab banner: nc -nv {ip} 110",
        "Try auth: USER/PASS with known credentials if obtained",
        "Check for CAPA / STLS support",
    ],
    "POP3S": [
        "Grab cert: openssl s_client -connect {ip}:995",
        "Check for SANs / domain names in cert",
    ],
    "RPC": [
        "Enumerate services: rpcinfo -p {ip}",
        "Check for NFS exports via RPC: showmount -e {ip}",
        "Look for exposed ypbind/nis services",
    ],
    "MSRPC": [
        "Enumerate endpoints: rpcclient -U '' -N {ip}",
        "Commands: srvinfo, enumdomusers, enumdomgroups, querydominfo",
        "Cross-reference with 135/139/445 for SMB/AD context",
    ],
    "NETBIOS": [
        "Enumerate NetBIOS names: nmblookup -A {ip}",
        "Check null session: smbclient -L //{ip} -N",
        "Useful for pre-Windows 2000 systems and workgroups",
    ],
    "IMAP": [
        "Grab banner: nc -nv {ip} 143",
        "Check CAPABILITY for STARTTLS/LOGIN support",
        "Try auth with known credentials if obtained",
    ],
    "IMAPS": [
        "Grab cert: openssl s_client -connect {ip}:993",
        "Note server software and domain names in cert",
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
    "HTTP-ALT": [
        "Same as HTTP (port 80) — directory brute, vhost, headers",
        "Often admin panels, Jenkins, Tomcat manager, dev environments",
        "Check /manager/html (Tomcat), /console (WebLogic), /jmx-console (JBoss)",
    ],
    "HTTPS-ALT": [
        "Same as HTTPS (port 443) — directory brute, cert SANs, TLS version",
        "Often admin/management UI — check /admin, /login, /console",
    ],
    "HTTP-8000": [
        "Common for dev servers, Django, SimpleHTTPServer, Python web apps",
        "Check directory indexing: curl -s http://{ip}:8000/",
        "Try /admin, /api, /debug endpoints",
    ],
    "KERBEROS": [
        "Enumerate users: kerbrute userenum -d {domain} --dc {ip} users.txt",
        "AS-REP roast: GetNPUsers.py {domain}/ -no-pass -usersfile users.txt -dc-ip {ip}",
        "Kerberoast with valid creds: GetUserSPNs.py {domain}/USER:PASS -dc-ip {ip}",
    ],
    "KERBEROSPW": [
        "Companion port to 88/Kerberos — password change protocol",
        "Confirms AD DC presence — investigate 88, 389, 445 together",
    ],
    "LDAP": [
        "Anonymous bind: ldapsearch -x -H ldap://{ip} -b ''",
        "Enumerate base DN and users",
        "Check for AS-REP roasting (no pre-auth accounts)",
        "Dump naming contexts for domain info",
    ],
    "LDAPS": [
        "Same as LDAP but over TLS: ldapsearch -x -H ldaps://{ip} -b ''",
        "Grab cert SANs: openssl s_client -connect {ip}:636",
    ],
    "LDAP-GC": [
        "Global Catalog port (3268) — queries whole AD forest",
        "ldapsearch -x -H ldap://{ip}:3268 -b '' — broader scope than 389",
    ],
    "SMB": [
        "Try null session: smbclient -L //{ip} -N",
        "Enumerate shares: smbmap -H {ip}",
        "Check guest access on each share",
        "Run enum4linux -a {ip}",
        "Check for EternalBlue (MS17-010) if older Windows",
    ],
    "SNMP": [
        "Try community string 'public': snmpwalk -c public -v1 {ip}",
        "Enumerate with onesixtyone: onesixtyone -c community.txt {ip}",
        "Bulk community brute: hydra -P community.txt {ip} snmp",
        "Full MIB walk: snmpwalk -c public -v1 {ip} .1.3.6.1.2.1.25.4.2",
        "Users/processes: snmpwalk -c public -v1 {ip} 1.3.6.1.4.1.77.1.2.25 (Windows)",
    ],
    "MSSQL": [
        "Try sa:sa or sa:(blank) credentials",
        "Check for xp_cmdshell if authenticated",
        "Enumerate linked servers",
    ],
    "ORACLE": [
        "SID enumeration: odat sidguesser -s {ip} -p 1521",
        "Try default creds: system/manager, sys/change_on_install",
        "Enumerate with oscanner or tnscmd10g",
    ],
    "NFS": [
        "List shares: showmount -e {ip}",
        "Mount and inspect: mount -t nfs {ip}:/share /mnt/",
        "Check for no_root_squash permission",
    ],
    "DOCKER-API": [
        "Check exposed API: curl -s http://{ip}:2375/version",
        "List containers: curl -s http://{ip}:2375/containers/json",
        "If writable → container escape / host compromise (high impact)",
    ],
    "MYSQL": [
        "Try root:(blank) or root:root",
        "Enumerate databases if authenticated",
    ],
    "POSTGRESQL": [
        "Try default: postgres:postgres, postgres:(blank)",
        "Check version: psql -h {ip} -U postgres -c 'SELECT version();'",
        "If auth: check pg_read_server_files, COPY FROM PROGRAM (RCE)",
    ],
    "RDP": [
        "Note version — check for BlueKeep (CVE-2019-0708) on old systems",
        "Try known credentials if obtained",
    ],
    "VNC": [
        "Check auth required: vncviewer {ip}",
        "Some versions allow no-auth or weak passwords",
        "Grab password hash if local access available",
    ],
    "WINRM": [
        "If credentials obtained: evil-winrm -i {ip} -u USER -p PASS",
        "Check HTTP and HTTPS ports (5985/5986)",
    ],
    "WINRM-S": [
        "HTTPS variant of WinRM — evil-winrm -i {ip} -S -u USER -p PASS",
        "Accept self-signed cert: -S flag",
    ],
    "RSYNC": [
        "List modules: rsync rsync://{ip}/",
        "Download if readable: rsync -av rsync://{ip}/module/ ./loot/",
        "Check for writable modules (could drop ssh keys, cron jobs)",
    ],
    "REDIS": [
        "Unauth check: redis-cli -h {ip} INFO",
        "Config get dir — look for /var/lib/redis, /home/USER/.ssh",
        "Known attack: write SSH key via CONFIG SET dir + SAVE (manual only)",
    ],
    "ELASTICSEARCH": [
        "Cluster info: curl -s http://{ip}:9200/",
        "List indices: curl -s http://{ip}:9200/_cat/indices",
        "Dump docs: curl -s http://{ip}:9200/INDEX/_search?pretty",
    ],
    "WEBMIN": [
        "Check version: curl -sI http://{ip}:10000/",
        "Historical RCEs: CVE-2019-15107 (<=1.920), CVE-2019-15231",
        "Try default creds admin:admin, root:(blank)",
    ],
    "MEMCACHED": [
        "Stats: echo 'stats' | nc {ip} 11211",
        "Dump keys: memcdump --servers={ip}:11211",
        "Check for sensitive data caches (sessions, tokens)",
    ],
    "MONGODB": [
        "Unauth check: mongo --host {ip} --eval 'db.adminCommand({{listDatabases:1}})'",
        "Enumerate DBs: show dbs",
        "Look for sensitive collections (users, tokens, credit)",
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
            details  = self.info.port_details.get(port, {})
            svc      = details.get("service", _PORT_LABELS.get(port, "?"))
            ver      = details.get("version", "") or ""
            resolved = details.get("resolved_proto", "")
            if resolved:
                svc = f"{svc} → {resolved}"
            table.add_row(str(port), svc, ver)

        self.console.print()
        self.console.print(table)
        self.console.print()

        # ── OS / domain / shares / users ────────────────────────────
        if self.info.os_guess and self.info.os_guess != "Unknown":
            colour = _OS_COLOUR.get(self.info.os_guess, "white")
            self.console.print(
                f"  [bold]OS Guess[/bold]  : "
                f"[bold {colour}]{_esc(self.info.os_guess)}[/bold {colour}]"
            )

        if self.info.domains_found:
            self.console.print(
                f"  [bold]🌐 Domains[/bold]  : "
                f"{_esc(', '.join(self.info.domains_found))}"
            )

        if self.info.shares_found:
            self.console.print(
                f"  [bold]📂 Shares[/bold]   : "
                f"[green]{_esc(', '.join(self.info.shares_found))}[/green]"
            )

        if self.info.users_found:
            self.console.print(
                f"  [bold]🔑 Users[/bold]    : "
                f"[green]{_esc(', '.join(self.info.users_found))}[/green]"
            )

        if self.info.web_paths:
            # Defensive case-insensitive dedup — should already be deduped on
            # insertion, but guard against case-only variants from different
            # scanners (ffuf vs gobuster).
            seen_lower = set()
            unique_paths = []
            for p in self.info.web_paths:
                key = p.lower()
                if key not in seen_lower:
                    seen_lower.add(key)
                    unique_paths.append(p)

            self.console.print(
                f"\n  [bold]🌐 Web Paths[/bold] ({len(unique_paths)} found):"
            )
            for p in unique_paths[:20]:
                self.console.print(f"    [dim]{_esc(p)}[/dim]")
            if len(unique_paths) > 20:
                self.console.print(
                    f"    [dim]... and {len(unique_paths) - 20} more[/dim]"
                )

        # ── Manual next steps ───────────────────────────────────────
        self.console.print()
        self.console.rule("[bold yellow] MANUAL NEXT STEPS [/bold yellow]")

        suggested_any = False
        for port in sorted(self.info.open_ports):
            details  = self.info.port_details.get(port, {})
            resolved = details.get("resolved_proto", "").strip().lower()
            if resolved == "http":
                label = "HTTP"
            elif resolved == "https":
                label = "HTTPS"
            else:
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
                    is_restricted, tool = check_command(formatted)
                    if is_restricted:
                        self.console.print(
                            f"    [bold yellow][OSCP-RESTRICTED: {tool}][/bold yellow] "
                            f"[dim]{formatted}[/dim]"
                        )
                    else:
                        self.console.print(f"    [dim]-[/dim] {formatted}")
                suggested_any = True

            # Known CVEs sub-block (from cve_database — pre-sorted by severity,
            # capped at 5 per port; critical entries preserved by the sort).
            known_cves = match_by_port(port)[:5]
            if known_cves:
                if not hints:
                    header_label = label or "port"
                    self.console.print(
                        f"\n  [bold cyan][ {header_label} — port {port} ][/bold cyan]"
                    )
                self.console.print("    [bold red]Known CVEs:[/bold red]")
                for cve in known_cves:
                    cve_id = cve.get("id", "?")
                    name = cve.get("name", "")
                    sev = cve.get("severity", "INFO")
                    sev_color = {
                        "CRITICAL": "red",
                        "HIGH": "bright_yellow",
                        "MEDIUM": "yellow",
                    }.get(sev, "dim")
                    line = (
                        f"      [{sev_color}][{sev}][/{sev_color}] "
                        f"{cve_id} — {_esc(name)}"
                    )
                    msf = cve.get("msf_module")
                    if msf:
                        msf_cmd = f"msfconsole -x 'use {msf}; run'"
                        is_r, tool = check_command(msf_cmd)
                        if is_r:
                            line += (
                                f"  [bold yellow][OSCP-RESTRICTED: {tool}][/bold yellow]"
                            )
                    self.console.print(line)
                suggested_any = True

        if not suggested_any:
            self.console.print(
                "  [dim]No specific suggestions — investigate manually.[/dim]"
            )

        self.console.print()

        # OSCP exam-compliance reminder (always last)
        print_reminder(self.console)
