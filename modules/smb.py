"""
modules/smb.py — SMB enumeration module

Calls wrappers/smb_enum.sh, then parses the output files to update
session.info with discovered shares, users, and domain information.

Credentials are pulled from session.info if they were stored there
(e.g., by a future credential-capture module or passed via CLI).
"""

import re
from pathlib import Path

from core.runner import run_wrapper

WRAPPERS_DIR = Path(__file__).resolve().parent.parent / "wrappers"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(target: str, session, dry_run: bool = False) -> None:
    log = session.log
    log.info("SMB module starting for %s", target)

    # Verify 445 or 139 is actually open before proceeding
    smb_ports = session.info.open_ports & {139, 445}
    if not smb_ports:
        log.warning("No SMB ports (139/445) in open port list — skipping SMB module.")
        return

    script = WRAPPERS_DIR / "smb_enum.sh"
    if not script.exists():
        log.error("Wrapper not found: %s", script)
        return

    # -----------------------------------------------------------------------
    # Build command — pull credentials and domain from session state
    # -----------------------------------------------------------------------
    cmd = [
        "bash", str(script),
        "--target",     target,
        "--output-dir", str(session.target_dir),
    ]

    if session.info.domain:
        cmd += ["--domain", session.info.domain]

    # Credentials: stored in session.info as "smb_user" / "smb_pass" keys
    # (set by engine if --user/--pass were passed on CLI — Phase 4 addition)
    smb_user = getattr(session.info, "smb_user", None)
    smb_pass = getattr(session.info, "smb_pass", None)
    if smb_user and smb_pass:
        cmd += ["--user", smb_user, "--pass", smb_pass]
        log.info("Running authenticated SMB enum as: %s", smb_user)
    else:
        log.info("Running null/guest SMB enum (no credentials in session)")

    run_wrapper(cmd, session, label="smb_enum.sh", dry_run=dry_run)

    if dry_run:
        return

    # -----------------------------------------------------------------------
    # Parse output files → update session.info
    # -----------------------------------------------------------------------
    smb_dir = session.target_dir / "smb"

    _parse_shares(smb_dir, session, log)
    _parse_users(smb_dir, session, log)
    _parse_domain_info(smb_dir, session, log)
    _parse_signing(smb_dir, session, log)
    _parse_smbv1(smb_dir, session, log)
    _parse_samba_version(smb_dir, session, log)
    _generate_spray_hints(session, log)

    log.info("SMB module complete.")


# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------

def _parse_shares(smb_dir: Path, session, log) -> None:
    """Extract readable share names and access levels from smbmap and nxc output."""
    shares: set = set()
    share_access: dict = {}  # share_name → "READ ONLY" | "READ, WRITE"

    # smbmap null session — fixed-width columns, share name may contain spaces
    # Line format: "\t<ShareName (padded)>\t<Permissions>\t<Comment>"
    smbmap_file = smb_dir / "smbmap_null.txt"
    if smbmap_file.exists():
        for line in smbmap_file.read_text(errors="ignore").splitlines():
            m_access = re.search(r'(READ ONLY|READ,\s*WRITE)', line, re.IGNORECASE)
            if not m_access:
                continue
            if re.search(r'IPC\$|print\$', line, re.IGNORECASE):
                continue
            access_level = m_access.group(1).upper().replace("  ", " ")
            # Strip permissions suffix to capture share names that may include spaces
            stripped = re.sub(
                r'\s{2,}(?:READ ONLY|READ,\s*WRITE|NO ACCESS).*$', '',
                line, flags=re.IGNORECASE,
            ).strip()
            if stripped and not re.search(r'^-+$|Disk|Permissions', stripped):
                shares.add(stripped)
                share_access[stripped] = access_level

    # nxc shares (null + guest combined)
    # Line format: "SMB  IP  PORT  HOST  [+] <ShareName (padded)>  READ ONLY"
    nxc_file = smb_dir / "nxc_shares.txt"
    if nxc_file.exists():
        for line in nxc_file.read_text(errors="ignore").splitlines():
            m_access = re.search(r'(READ ONLY|READ,\s*WRITE)', line, re.IGNORECASE)
            if not m_access:
                continue
            if re.search(r'IPC\$|ACCESS_DENIED', line, re.IGNORECASE):
                continue
            access_level = m_access.group(1).upper().replace("  ", " ")
            # Require [+] (not [*] status lines) then capture up to 2+ spaces
            m = re.search(
                r'\[\+\]\s+([\w][\w\s._$-]*?)\s{2,}(?:READ|NO ACCESS|WRITE)',
                line, re.IGNORECASE,
            )
            if m:
                name = m.group(1).strip()
                shares.add(name)
                share_access.setdefault(name, access_level)

    if shares:
        new_shares = [s for s in sorted(shares) if s not in session.info.shares_found]
        session.info.shares_found.extend(new_shares)
        log.info("SMB shares found: %s", sorted(shares))
        session.add_note(f"SMB shares accessible: {sorted(shares)}")

        # Record per-share access level for report table
        for share, access in share_access.items():
            session.add_note(f"SMB share '{share}' access: {access}")

        # Add manual smbclient commands for each readable share (dynamic, not hardcoded)
        ip = session.info.ip
        for share in sorted(shares):
            session.add_note(
                f"[MANUAL] List SMB share: smbclient '//{ip}/{share}' -N -c 'ls'"
            )
            session.add_note(
                f"[MANUAL] Download SMB share: smbclient '//{ip}/{share}' -N "
                f"-c 'recurse ON; prompt OFF; mget *'"
            )

        # Infer potential usernames from share names.
        # "Samantha Konstan" → ["samantha", "konstan", "skonstan", "samanthakonstan"]
        # "john.doe"         → ["john.doe", "john", "jdoe"]
        _inferred: set = set()
        for share in shares:
            parts = re.split(r'[\s._-]+', share.strip())
            parts = [p for p in parts if len(p) > 1 and p.isalpha()]
            if len(parts) >= 2:
                first, last = parts[0].lower(), parts[-1].lower()
                _inferred.add(first)                     # first name alone
                _inferred.add(last)                      # last name alone
                _inferred.add(f"{first[0]}{last}")       # f.last format
                _inferred.add(f"{first}{last}")          # firstlast concatenated
                _inferred.add(f"{first}.{last}")         # first.last format
            elif len(parts) == 1:
                _inferred.add(parts[0].lower())

        # Filter out noise tokens that aren't real usernames
        _noise_tokens = {"backup", "backups", "share", "data", "files",
                         "public", "common", "recycler", "temp", "admin",
                         "users", "homes", "documents", "desktop", "downloads"}
        _inferred -= _noise_tokens

        new_inferred = [u for u in sorted(_inferred)
                        if u not in session.info.users_found]
        if new_inferred:
            session.info.users_found.extend(new_inferred)
            log.info("Potential usernames inferred from share names: %s", new_inferred)
            session.add_note(
                f"Potential usernames (inferred from share names): {new_inferred}"
            )


def _parse_users(smb_dir: Path, session, log) -> None:
    """Extract user accounts from rpcclient and nxc output."""
    users: set = set()

    # rpcclient enumdomusers output written by smb_enum.sh
    rpc_user_file = smb_dir / "users_rpc.txt"
    if rpc_user_file.exists():
        for line in rpc_user_file.read_text(errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                users.add(line)

    # Also try parsing rpcclient.txt directly
    rpc_raw = smb_dir / "rpcclient.txt"
    if rpc_raw.exists():
        for line in rpc_raw.read_text(errors="ignore").splitlines():
            m = re.search(r'user:\[([^\]]+)\]', line)
            if m:
                users.add(m.group(1))

    # nxc --users output
    # NXC prints status lines with [*] and user lines with or without prefix.
    # Format A: "SMB  IP  PORT  HOST  [+] DOMAIN\username  badpwdcount: 0"
    # Format B: "SMB  IP  PORT  HOST  DOMAIN\username  badpwdcount: 0"
    nxc_users = smb_dir / "nxc_users.txt"
    if nxc_users.exists():
        for line in nxc_users.read_text(errors="ignore").splitlines():
            # Only match [+] lines (not [*] status/info lines)
            m = re.search(r'\[\+\]\s+(?:[^\\]+\\)?(\S+)', line)
            if m and not m.group(1).startswith("-"):
                users.add(m.group(1))
            # Also catch "DOMAIN\username  badpwdcount" format (no prefix)
            m2 = re.search(r'\b[A-Za-z0-9._-]+\\([A-Za-z0-9._-]+)\s+badpwdcount', line)
            if m2:
                users.add(m2.group(1))

    # Filter out known output artefacts — NOT usernames.
    # Catches NXC status message words like "Enumerated" from lines such as:
    #   [+] Enumerated unix users:  or  [+] Unix users:
    # Single-char tokens and blank strings are always dropped.
    _noise = {
        "",
        # rpcclient column headers / field labels
        "account_name", "account_flags", "group_name", "group_flags",
        "full_name", "description", "logon_script", "profile_path",
        "comment", "parameters", "workstations",
        # nxc / netexec status message words (appear on [+] / [*] lines)
        "memberof", "badpwdcount", "lastlogon", "badpasswordcount",
        "enumerated", "unix", "windows", "linux", "local", "domain",
        "added", "adding", "starting", "started", "completed", "running",
        "searching", "found", "checking", "testing", "skipping", "failed",
        "error", "warning", "success", "info", "debug", "smb", "nxc",
        "netexec", "crackmapexec", "extra", "share", "shares",
        # enum4linux section markers
        "users", "groups", "password", "enabled", "disabled", "true", "false",
    }
    users = {u for u in users if len(u) > 1 and u.lower() not in _noise}

    if users:
        new_users = [u for u in sorted(users) if u not in session.info.users_found]
        session.info.users_found.extend(new_users)
        log.info("Users discovered via SMB: %s", sorted(users))
        session.add_note(f"SMB users: {sorted(users)}")


def _parse_domain_info(smb_dir: Path, session, log) -> None:
    """Extract domain/hostname from nxc and enum4linux output."""

    # nxc share output: (name:HOSTNAME) (domain:DOMAIN)
    for fname in ("nxc_shares.txt", "nxc_users.txt"):
        nxc_file = smb_dir / fname
        if not nxc_file.exists():
            continue
        content = nxc_file.read_text(errors="ignore")

        hostname = re.search(r'\(name:([^)]+)\)', content)
        domain   = re.search(r'\(domain:([^)]+)\)', content)

        if hostname:
            h = hostname.group(1).strip()
            if h and h not in session.info.domains_found:
                session.info.domains_found.append(h)
                log.info("Hostname discovered: %s", h)

        if domain:
            d = domain.group(1).strip()
            if d and "." in d and d not in session.info.domains_found:
                session.info.domains_found.append(d)
                log.info("Domain discovered: %s", d)
                if not session.info.domain:
                    session.info.domain = d

        # NXC explicitly labels DCs: "(domain:...) ... Domain Controller"
        if re.search(r"domain.controller", content, re.IGNORECASE):
            if not session.info.is_domain_controller:
                session.info.is_domain_controller = True
                log.info("Domain Controller confirmed via NXC output in %s", fname)

        # -------------------------------------------------------------------
        # OS version fallback: NXC reports the exact Windows build even when
        # Nmap -O fails on hardened hosts.
        # Example NXC line:
        #   SMB  10.10.10.10  445  HOST  [*] Windows 10.0 Build 17763 x64 (name:…)
        # Parse this and populate session.info.os_version if not already set.
        # -------------------------------------------------------------------
        if not session.info.os_version:
            for line in content.splitlines():
                # Match "Windows X.Y Build NNNNN" with optional arch suffix
                m = re.search(
                    r'\bWindows\s+([\d.]+\s+Build\s+\d+)',
                    line,
                    re.IGNORECASE,
                )
                if m:
                    nxc_ver = m.group(1).strip()
                    session.info.os_version = nxc_ver
                    if not session.info.os_type:
                        session.info.os_type = "Windows"
                    log.info(
                        "OS version from NXC SMB banner: Windows %s", nxc_ver
                    )
                    break

        if hostname or domain:
            break  # found what we need

    # enum4linux domain line: "Domain Name: CORP" or "Domain: CORP.LOCAL"
    e4l = smb_dir / "enum4linux.txt"
    if e4l.exists():
        for line in e4l.read_text(errors="ignore").splitlines():
            m = re.search(r'Domain(?:\s+Name)?[:\s]+([A-Za-z0-9._-]+)', line, re.IGNORECASE)
            if m:
                d = m.group(1).strip()
                if d and d not in session.info.domains_found:
                    session.info.domains_found.append(d)
                    log.info("Domain from enum4linux: %s", d)
                break


def _parse_signing(smb_dir: Path, session, log) -> None:
    """Check for SMB signing disabled — critical NTLM relay risk."""
    for fname in ("nxc_shares.txt", "nmap_smb.txt"):
        f = smb_dir / fname
        if not f.exists():
            continue
        content = f.read_text(errors="ignore")
        if re.search(r'signing[:\s]+False|message signing.*disabled', content, re.IGNORECASE):
            log.warning(
                "SMB SIGNING DISABLED on %s — NTLM relay attack possible. "
                "Run Responder + ntlmrelayx MANUALLY after confirming scope.",
                session.info.ip,
            )
            session.add_note("CRITICAL: SMB signing disabled — NTLM relay risk")
            break


def _parse_smbv1(smb_dir: Path, session, log) -> None:
    """Detect SMBv1 enabled — EternalBlue / WannaCry attack surface."""
    for fname in ("nxc_shares.txt", "nmap_smb.txt", "enum4linux.txt"):
        f = smb_dir / fname
        if not f.exists():
            continue
        content = f.read_text(errors="ignore")
        # NXC reports "(SMBv1:True)" in its banner line
        # Nmap smb-security-mode script: "message_signing: disabled"
        # Nmap vuln scripts: "MS17-010" / "EternalBlue"
        if re.search(r'SMBv1[:\s(]+True|smb-vuln-ms17-010|EternalBlue|NT LM 0\.12', content, re.IGNORECASE):
            log.warning(
                "SMBv1 ENABLED on %s — potential EternalBlue (MS17-010) target. "
                "Verify manually: nmap -p 445 --script smb-vuln-ms17-010 %s",
                session.info.ip, session.info.ip,
            )
            session.add_note(
                f"HIGH: SMBv1 enabled — check EternalBlue: "
                f"nmap -p 445 --script smb-vuln-ms17-010 {session.info.ip}"
            )
            break


def _parse_samba_version(smb_dir: Path, session, log) -> None:
    """
    Detect the Samba version from nmap/nxc/enum4linux output and add a
    searchsploit hint.  Also checks for SambaCry (CVE-2017-7494) eligibility
    (Samba < 4.6.4 with a writable share — the flag is advisory only).
    """
    samba_ver: str = ""

    # Priority 1: port_details from nmap version scan
    for port in (139, 445):
        ver_str = session.info.port_details.get(port, {}).get("version", "") or ""
        m = re.search(r'Samba\s+smbd?\s+([\d]+\.[\d]+\.?[\d]*)', ver_str, re.IGNORECASE)
        if m:
            samba_ver = m.group(1)
            break

    # Priority 2: scan output files
    if not samba_ver:
        for fname in ("nmap_smb.txt", "nxc_shares.txt", "enum4linux.txt"):
            fpath = smb_dir / fname
            if not fpath.exists():
                continue
            content = fpath.read_text(errors="ignore")
            m = re.search(r'Samba\s+smbd?\s+([\d]+\.[\d]+\.?[\d]*)', content, re.IGNORECASE)
            if m:
                samba_ver = m.group(1)
                break

    if not samba_ver:
        return

    log.info("Samba version detected: %s", samba_ver)
    ver_major_minor = ".".join(samba_ver.split(".")[:2])
    session.add_note(
        f"INFO: Samba {samba_ver} detected — research CVEs: "
        f"searchsploit samba {ver_major_minor}"
    )

    # SambaCry (CVE-2017-7494): affects Samba < 4.6.4 with a writable share
    try:
        parts = [int(x) for x in samba_ver.split(".")]
        major, minor = parts[0], parts[1] if len(parts) > 1 else 0
        patch = parts[2] if len(parts) > 2 else 0
        if major < 4 or (major == 4 and minor < 6) or (major == 4 and minor == 6 and patch < 4):
            session.add_note(
                f"HIGH: Samba {samba_ver} < 4.6.4 — potential SambaCry (CVE-2017-7494): "
                f"searchsploit sambacry"
            )
            log.warning(
                "Samba %s may be vulnerable to SambaCry (CVE-2017-7494)", samba_ver
            )
    except (ValueError, IndexError):
        pass


def _generate_spray_hints(session, log) -> None:
    """
    When users have been discovered, inject manual spray commands as notes.
    Ordering: password policy check FIRST, then per-service spray hints.
    Nothing is run automatically — all entries land in the [MANUAL] section.
    """
    if not session.info.users_found:
        return

    ip         = session.info.ip
    domain     = session.info.domain or ""
    users_file = session.target_dir / "users.txt"
    uf         = str(users_file)
    ldap_dir   = session.target_dir / "ldap"

    # Password policy MUST be checked before ANY spray to avoid lockouts
    session.add_note(
        f"[MANUAL] Password policy check (before spraying): "
        f"crackmapexec smb {ip} --pass-pol"
    )
    log.info("Spray hints added: %d users discovered — policy check + per-service commands",
             len(session.info.users_found))

    # NTLM relay / capture — workgroup vs domain context
    for note in session.info.notes:
        if re.search(r'smb signing disabled|ntlm relay', note, re.IGNORECASE):
            if domain:
                session.add_note(
                    f"[MANUAL] NTLM relay (domain target): "
                    f"sudo responder -I tun0 -wd && "
                    f"impacket-ntlmrelayx -t smb://{ip} -smb2support"
                )
            else:
                # Workgroup: relay is harder — capture and crack hash offline
                session.add_note(
                    f"[MANUAL] NTLM capture (workgroup — no relay target): "
                    f"sudo responder -I tun0 -wrf  "
                    f"# then crack: hashcat -m 5600 <hash.txt> /usr/share/wordlists/rockyou.txt"
                )
            break

    # AS-REP Roasting — only makes sense with a domain
    if domain:
        session.add_note(
            f"[MANUAL] AS-REP Roasting (no pre-auth accounts): "
            f"impacket-GetNPUsers {domain}/ -dc-ip {ip} -no-pass "
            f"-usersfile {uf} -format hashcat "
            f"-outputfile {ldap_dir}/asrep_hashes.txt"
        )
        session.add_note(
            f"[MANUAL] Crack AS-REP hashes: "
            f"hashcat -m 18200 {ldap_dir}/asrep_hashes.txt "
            f"/usr/share/wordlists/rockyou.txt -r /usr/share/john/rules/best64.rule"
        )

    # Per-service spray — only for ports that are actually open
    open_ports = session.info.open_ports
    if 445 in open_ports or 139 in open_ports:
        session.add_note(
            f"[MANUAL] SMB spray: "
            f"crackmapexec smb {ip} -u {uf} "
            f"-p /usr/share/wordlists/rockyou.txt --no-bruteforce --continue-on-success"
        )
    if 22 in open_ports:
        session.add_note(
            f"[MANUAL] SSH spray (rate-limited): "
            f"hydra -L {uf} -P /usr/share/wordlists/rockyou.txt ssh://{ip} -t 4 -w 3"
        )
    if 5985 in open_ports or 5986 in open_ports:
        session.add_note(
            f"[MANUAL] WinRM spray: "
            f"crackmapexec winrm {ip} -u {uf} -p '<FOUND_PASSWORD>'"
        )
    if 21 in open_ports:
        session.add_note(
            f"[MANUAL] FTP cred test: "
            f"hydra -L {uf} -P /usr/share/wordlists/rockyou.txt ftp://{ip}"
        )
    if 3306 in open_ports:
        session.add_note(
            f"[MANUAL] MySQL cred test: "
            f"hydra -L {uf} -P /usr/share/wordlists/rockyou.txt mysql://{ip}"
        )
    if 1433 in open_ports:
        session.add_note(
            f"[MANUAL] MSSQL cred test: "
            f"crackmapexec mssql {ip} -u {uf} -p '<FOUND_PASSWORD>'"
        )

    # Credential reuse reminder
    session.add_note(
        f"[MANUAL] Credential reuse — test any found creds against all services: "
        f"crackmapexec all {ip} -u '<USER>' -p '<PASS>'"
    )
