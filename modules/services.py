"""
modules/services.py — Service-specific enumeration module

Routes to wrappers/services_enum.sh with the full open port list and
any UDP ports discovered during recon. After the wrapper runs, parses
output files to pull structured findings back into session.info.

Covers: FTP, SSH, SMTP, NFS, SNMP, IMAP/POP3, RDP, WinRM, databases,
        Redis, and banner grabbing for non-standard ports.
"""

import re
from pathlib import Path

from core.runner import run_wrapper

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

    run_wrapper(cmd, session, label="services_enum.sh", dry_run=dry_run)

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
    _record_version_notes(session, log)

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
            session.add_note(f"HIGH: SSH CVEs detected: {unique_cves}")

    # OpenSSH version → CVE-2018-15473 username enumeration (affects < 7.7)
    # The version string comes from Nmap: "OpenSSH 7.4 protocol 2.0"
    ssh_ver_str = session.info.port_details.get(22, {}).get("version", "") or ""
    m_ver = re.search(r'OpenSSH\s+([\d]+)\.([\d]+)', ssh_ver_str, re.IGNORECASE)
    if m_ver:
        ssh_major, ssh_minor = int(m_ver.group(1)), int(m_ver.group(2))
        ver_label = f"{ssh_major}.{ssh_minor}"
        if ssh_major < 7 or (ssh_major == 7 and ssh_minor < 7):
            log.warning(
                "OpenSSH %s < 7.7 — CVE-2018-15473 username enumeration possible",
                ver_label,
            )
            session.add_note(
                f"HIGH: OpenSSH {ver_label} < 7.7 — CVE-2018-15473 username enumeration. "
                f"MANUAL (OSCP-safe): `searchsploit -m 45233` → python3 ssh_user_enum.py "
                f"--userList {session.target_dir}/users.txt --ip {session.info.ip}. "
                f"[MSF-RESTRICTED] Metasploit alternative: auxiliary/scanner/ssh/ssh_enumusers "
                f"(⚠️ limited to 1 machine per OSCP exam)"
            )

    # Check which users have password auth enabled (nmap ssh-auth-methods)
    # Output format:
    #   22/tcp open ssh
    #   | ssh-auth-methods:
    #   |   Supported authentication methods:
    #   |     publickey
    #   |     password
    auth_file = ssh_dir / "ssh_auth_methods.txt"
    if auth_file.exists():
        content = auth_file.read_text(errors="ignore")

        # Detect password auth globally (single-block output)
        if re.search(r'\bpassword\b', content, re.IGNORECASE):
            log.warning("SSH password authentication enabled on %s", session.info.ip)
            session.add_note(
                f"HIGH: SSH password auth enabled — brute-force is possible: "
                f"hydra -l <user> -P /usr/share/wordlists/rockyou.txt "
                f"ssh://{session.info.ip}"
            )

        # Also parse per-user blocks if the script was run for specific users
        # Format: "22/tcp ... | ssh-auth-methods: (username: root) ... password"
        for m in re.finditer(
            r'ssh-auth-methods[^|]*\(username[:\s]+([^\)]+)\)(.*?)(?=ssh-auth-methods|\Z)',
            content, re.DOTALL | re.IGNORECASE,
        ):
            user = m.group(1).strip()
            methods_block = m.group(2)
            if re.search(r'\bpassword\b', methods_block, re.IGNORECASE):
                log.warning("SSH password auth available for user: %s", user)
                session.add_note(
                    f"HIGH: SSH password auth available for '{user}' — "
                    f"hydra -l {user} -P /usr/share/wordlists/rockyou.txt "
                    f"ssh://{session.info.ip}"
                )


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


def _record_version_notes(session, log) -> None:
    """
    Iterate ALL port_details and record a version note + searchsploit hint for
    every service where Nmap detected a specific version string.

    Called once after all service parsers so every discovered version ends up
    in session.info.notes regardless of which dedicated parser runs.

    Skips:
      - Empty / placeholder version strings ("—", "-")
      - Range strings ("3.X - 4.X") — not specific enough for searchsploit
      - Services already handled by dedicated parsers (apache, samba, openssh)
        to avoid duplicate notes
    """
    # Services handled by dedicated module parsers — skip to avoid duplicates
    _SKIP = {"apache", "samba", "openssh"}

    # (substring_in_version_lower) → canonical searchsploit term
    _NORM = [
        ("microsoft iis",  "iis"),
        ("iis httpd",      "iis"),
        ("apache tomcat",  "tomcat"),
        ("nginx",          "nginx"),
        ("proftpd",        "proftpd"),
        ("vsftpd",         "vsftpd"),
        ("filezilla",      "filezilla server"),
        ("postfix",        "postfix"),
        ("sendmail",       "sendmail"),
        ("dovecot",        "dovecot"),
        ("exim",           "exim"),
        ("mysql",          "mysql"),
        ("mariadb",        "mariadb"),
        ("postgresql",     "postgresql"),
        ("microsoft sql",  "mssql"),
        ("ms-sql",         "mssql"),
        ("redis",          "redis"),
        ("mongodb",        "mongodb"),
        ("elasticsearch",  "elasticsearch"),
        ("tomcat",         "tomcat"),
        ("jboss",          "jboss"),
        ("weblogic",       "weblogic"),
        ("glassfish",      "glassfish"),
        ("jenkins",        "jenkins"),
        ("phpmyadmin",     "phpmyadmin"),
        ("openssl",        "openssl"),
        ("php",            "php"),
        ("wordpress",      "wordpress"),
        ("drupal",         "drupal"),
        ("joomla",         "joomla"),
        ("vnc",            "vnc"),
        ("rdp",            "rdp"),
        ("telnet",         "telnet"),
        ("pure-ftpd",      "pure-ftpd"),
        ("wsftp",          "wsftp"),
    ]

    seen: set = set()

    for port in sorted(session.info.open_ports):
        ver_str = session.info.port_details.get(port, {}).get("version", "") or ""

        # Skip empty, placeholder, or non-specific range versions
        if not ver_str or ver_str.strip() in {"—", "-", ""}:
            continue
        if re.search(r'\d+\.X', ver_str, re.IGNORECASE):
            continue

        # Must contain at least one concrete version number
        ver_m = re.search(r'(\d+\.\d+(?:\.\d+)?)', ver_str)
        if not ver_m:
            continue
        version = ver_m.group(1)

        # Normalise to canonical searchsploit term
        svc_lower = ver_str.lower()
        canonical = ""
        for pattern, name in _NORM:
            if pattern in svc_lower:
                canonical = name
                break
        if not canonical:
            # Fallback: first word before the version number
            pre = ver_str[:ver_m.start()].strip()
            canonical = re.split(r'[\s/]', pre)[-1].lower() if pre else ""

        if not canonical or canonical in _SKIP:
            continue

        dedup_key = f"{canonical}_{version}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        ver_mm = ".".join(version.split(".")[:2])
        note = (
            f"VERSION: port {port} — {canonical} {version} detected "
            f"| searchsploit {canonical} {version}"
        )
        session.add_note(note)
        log.info("Version recorded: port %d — %s %s", port, canonical, version)


