"""
modules/services.py — Service-specific enumeration module

Routes to wrappers/services_enum.sh with the full open port list and
any UDP ports discovered during recon. After the wrapper runs, parses
output files to pull structured findings back into session.info.

Covers: FTP, SSH, SMTP, NFS, SNMP, IMAP/POP3, RDP, WinRM, databases,
        Redis, and banner grabbing for non-standard ports.
"""

import re
import subprocess
from pathlib import Path

WRAPPERS_DIR = Path(__file__).resolve().parent.parent / "wrappers"

# Ports this module is responsible for
_SERVICE_PORTS = {
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    135,   # MSRPC / RPC Endpoint Mapper
    110,   # POP3
    143,   # IMAP
    161,   # SNMP (UDP — checked separately)
    993,   # IMAPS
    995,   # POP3S
    1433,  # MSSQL
    2049,  # NFS
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5985,  # WinRM HTTP
    5986,  # WinRM HTTPS
    6379,  # Redis
    27017, # MongoDB
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(target: str, session, dry_run: bool = False) -> None:
    log = session.log
    log.info("Services module starting for %s", target)

    # Collect relevant TCP ports
    tcp_ports = session.info.open_ports & _SERVICE_PORTS
    if not tcp_ports:
        log.info("No service-specific ports open — skipping services module.")
        return

    log.info("Service ports to enumerate: %s", sorted(tcp_ports))

    script = WRAPPERS_DIR / "services_enum.sh"
    if not script.exists():
        log.error("Wrapper not found: %s", script)
        return

    # -----------------------------------------------------------------------
    # Read UDP open ports (written by recon.sh to scans/open_ports_udp.txt)
    # -----------------------------------------------------------------------
    udp_ports_csv = _read_udp_ports(session)

    # -----------------------------------------------------------------------
    # Build command
    # -----------------------------------------------------------------------
    ports_csv = ",".join(str(p) for p in sorted(tcp_ports))

    cmd = [
        "bash", str(script),
        "--target",     target,
        "--output-dir", str(session.target_dir),
        "--ports",      ports_csv,
    ]
    if udp_ports_csv:
        cmd += ["--udp-ports", udp_ports_csv]
        log.info("UDP ports passed to wrapper: %s", udp_ports_csv)

    if session.info.domain:
        cmd += ["--domain", session.info.domain]

    _exec(cmd, log, dry_run, label="services_enum.sh")

    if dry_run:
        return

    # -----------------------------------------------------------------------
    # Parse output files → update session.info
    # -----------------------------------------------------------------------
    _parse_ftp(session, log)
    _parse_ssh(session, log)
    _parse_snmp(session, log)
    _parse_nfs(session, log)
    _parse_smtp(session, log)
    _parse_databases(session, log)
    _parse_telnet(session, log)
    _parse_msrpc(session, log)

    log.info("Services module complete.")


# ---------------------------------------------------------------------------
# UDP port discovery
# ---------------------------------------------------------------------------

def _read_udp_ports(session) -> str:
    """Read UDP open ports from the file written by recon.sh."""
    udp_file = session.path("scans", "open_ports_udp.txt")
    if udp_file.exists() and udp_file.stat().st_size > 0:
        content = udp_file.read_text(errors="ignore").strip()
        if content:
            return content
    return ""


# ---------------------------------------------------------------------------
# Service-specific output parsers
# ---------------------------------------------------------------------------

def _parse_ftp(session, log) -> None:
    """Check if FTP anonymous login was allowed."""
    ftp_dir = session.target_dir / "ftp"
    anon_test = ftp_dir / "ftp_anon_test.txt"
    if not anon_test.exists():
        return

    content = anon_test.read_text(errors="ignore")
    if re.search(r'230|logged in|Login successful', content, re.IGNORECASE):
        log.warning("FTP anonymous login PERMITTED on %s", session.info.ip)
        session.add_note(
            f"FINDING: FTP anonymous login permitted — "
            f"wget -m ftp://anonymous:anonymous@{session.info.ip}/"
        )

    nmap_ftp = ftp_dir / "nmap_ftp.txt"
    if nmap_ftp.exists():
        if re.search(r'ftp-anon.*allowed|Anonymous FTP login allowed',
                     nmap_ftp.read_text(errors="ignore"), re.IGNORECASE):
            log.warning("Nmap confirms FTP anonymous access allowed")


def _parse_ssh(session, log) -> None:
    """Check SSH audit findings and auth method results."""
    ssh_dir = session.target_dir / "ssh"

    audit_file = ssh_dir / "ssh_audit.txt"
    if audit_file.exists():
        content = audit_file.read_text(errors="ignore")
        cves = re.findall(r'CVE-\d{4}-\d+', content)
        if cves:
            unique_cves = sorted(set(cves))
            log.warning("SSH CVEs found: %s", unique_cves)
            session.add_note(f"SSH CVEs: {unique_cves}")

    auth_file = ssh_dir / "ssh_auth_methods.txt"
    if auth_file.exists():
        content = auth_file.read_text(errors="ignore")
        for user in ("root", "admin", "user", "www-data"):
            pattern = rf'ssh-auth-methods.*{user}.*\n.*password'
            block = re.search(
                r'Supported authentication methods.*?(?=\n\n|\Z)',
                content, re.DOTALL,
            )
            if block and "password" in block.group().lower():
                log.info("SSH password auth available (check individual user files)")
                break


def _parse_snmp(session, log) -> None:
    """Extract SNMP findings — processes, users, community strings."""
    snmp_dir = session.target_dir / "snmp"
    if not snmp_dir.exists():
        return

    communities = snmp_dir / "communities.txt"
    if communities.exists():
        content = communities.read_text(errors="ignore")
        hits = [
            line.strip() for line in content.splitlines()
            if line.strip() and not line.startswith("#")
        ]
        if hits:
            log.info("SNMP community strings found: %d", len(hits))
            session.add_note(f"SNMP community strings found: {hits[:5]}")

    # Interesting data from process list (credentials sometimes in cmdline)
    procs = snmp_dir / "snmp_processes.txt"
    if procs.exists() and procs.stat().st_size > 0:
        session.add_note(
            f"SNMP processes enumerated — check {procs} for credentials in cmdline args"
        )

    users = snmp_dir / "snmp_users.txt"
    if users.exists() and users.stat().st_size > 0:
        snmp_users = [
            line.split('"')[1] for line in users.read_text(errors="ignore").splitlines()
            if '"' in line
        ]
        if snmp_users:
            new = [u for u in snmp_users if u not in session.info.users_found]
            session.info.users_found.extend(new)
            log.info("Users from SNMP: %s", snmp_users)
            session.add_note(f"SNMP users: {snmp_users}")


def _parse_nfs(session, log) -> None:
    """Parse NFS share listing."""
    nfs_dir = session.target_dir / "nfs"
    shares_file = nfs_dir / "nfs_shares.txt"
    if not shares_file.exists():
        return

    content = shares_file.read_text(errors="ignore")
    exports = [
        line.split()[0]
        for line in content.splitlines()
        if line.startswith("/")
    ]
    if exports:
        log.warning(
            "NFS exports found: %s — mount manually to inspect contents", exports
        )
        for export in exports:
            note = (
                f"NFS export: {session.info.ip}:{export} — "
                f"mount -t nfs {session.info.ip}:{export} /mnt/nfs_enum"
            )
            session.add_note(note)


def _parse_smtp(session, log) -> None:
    """Parse SMTP user enumeration results."""
    smtp_dir = session.target_dir / "smtp"
    users_file = smtp_dir / "smtp_users.txt"
    if not users_file.exists():
        return

    users: list = []
    for line in users_file.read_text(errors="ignore").splitlines():
        # smtp-user-enum format: "10.10.10.10: root EXISTS"
        m = re.search(r':\s+(\S+)\s+EXISTS', line)
        if m:
            user = m.group(1)
            if user not in session.info.users_found:
                users.append(user)

    if users:
        session.info.users_found.extend(users)
        log.info("SMTP valid users found: %s", users)
        session.add_note(f"SMTP valid users: {users}")


def _parse_databases(session, log) -> None:
    """Check database NSE scan results for empty passwords or misconfigs."""
    db_dir = session.target_dir / "db"
    if not db_dir.exists():
        return

    checks = {
        "mysql.txt":  (r'mysql-empty-password.*\n.*root.*empty password', "MySQL root with empty password"),
        "mssql.txt":  (r'ms-sql-empty-password',                          "MSSQL empty password account"),
        "redis.txt":  (r'redis-info.*\n.*role:master',                    "Redis unauthenticated"),
    }
    for fname, (pattern, message) in checks.items():
        fpath = db_dir / fname
        if fpath.exists():
            content = fpath.read_text(errors="ignore")
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                log.warning("DATABASE FINDING: %s", message)
                session.add_note(f"DATABASE: {message} — review {fpath}")


def _parse_telnet(session, log) -> None:
    """Extract Telnet banner and NTLM info-disclosure findings."""
    telnet_dir = session.target_dir / "telnet"

    banner_f = telnet_dir / "telnet_banner.txt"
    if banner_f.exists():
        content = banner_f.read_text(errors="ignore").strip()
        if content:
            banner_line = next(
                (l for l in content.splitlines() if l.strip()), ""
            )[:100]
            log.info("Telnet banner: %s", banner_line)
            session.add_note(f"Telnet banner: {banner_line}")

    nmap_f = telnet_dir / "telnet_nmap.txt"
    if nmap_f.exists():
        nmap_content = nmap_f.read_text(errors="ignore")
        if re.search(r"Target_Name|NetBIOS|Domain_Name", nmap_content, re.IGNORECASE):
            hostname_m = re.search(r"NetBIOS_Computer_Name:\s*(\S+)", nmap_content)
            domain_m   = re.search(r"NetBIOS_Domain_Name:\s*(\S+)", nmap_content)
            if hostname_m:
                log.info("Telnet NTLM hostname: %s", hostname_m.group(1))
                session.add_note(f"Telnet NTLM hostname: {hostname_m.group(1)}")
            if domain_m:
                d = domain_m.group(1)
                if d not in session.info.domains_found:
                    session.info.domains_found.append(d)
                log.info("Telnet NTLM domain: %s", d)


def _parse_msrpc(session, log) -> None:
    """Parse impacket-rpcdump output for high-value RPC endpoints."""
    msrpc_dir = session.target_dir / "msrpc"
    rpcdump_f = msrpc_dir / "rpcdump.txt"
    if not rpcdump_f.exists():
        return

    content = rpcdump_f.read_text(errors="ignore")

    # Flag interesting RPC interfaces
    interesting = re.findall(
        r"(svcctl|samr|lsarpc|drsuapi|atsvc|schedsvc|wkssvc|srvsvc)",
        content, re.IGNORECASE,
    )
    if interesting:
        unique = sorted(set(i.lower() for i in interesting))
        log.info("MSRPC: high-value endpoints found: %s", unique)
        session.add_note(f"MSRPC endpoints: {unique}")

        if "samr" in unique or "lsarpc" in unique:
            session.add_note(
                f"💡 [MANUAL] SAMR/LSARPC present — try anonymous user enum: "
                f"impacket-samrdump {session.info.ip}"
            )
        if "svcctl" in unique:
            session.add_note(
                "⚠️  MSRPC: svcctl (Service Control Manager) endpoint exposed — "
                "useful for lateral movement with credentials"
            )

    # Also check nmap output for any additional notes
    nmap_f = msrpc_dir / "msrpc_nmap.txt"
    if nmap_f.exists():
        nmap_content = nmap_f.read_text(errors="ignore")
        endpoints = re.findall(r"uuid\s+([\w-]+)", nmap_content, re.IGNORECASE)
        if endpoints:
            log.info("MSRPC: %d RPC UUIDs discovered via Nmap", len(endpoints))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _exec(cmd: list, log, dry_run: bool, label: str = "") -> int:
    display = " ".join(str(c) for c in cmd)
    prefix  = "[DRY-RUN]" if dry_run else "[CMD]"
    log.info("%s %s", prefix, display)

    if dry_run:
        return 0

    try:
        result = subprocess.run(cmd, text=True, check=False)
        if result.returncode != 0:
            log.warning("%s exited with code %d", label or cmd[0], result.returncode)
        return result.returncode
    except FileNotFoundError:
        log.error("Command not found: %s", cmd[0])
        return -1
