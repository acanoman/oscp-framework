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

    log.info("SMB module complete.")


# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------

def _parse_shares(smb_dir: Path, session, log) -> None:
    """Extract readable share names from smbmap and nxc output."""
    shares: set = set()

    # smbmap null session
    smbmap_file = smb_dir / "smbmap_null.txt"
    if smbmap_file.exists():
        for line in smbmap_file.read_text(errors="ignore").splitlines():
            if re.search(r'READ ONLY|READ, WRITE', line, re.IGNORECASE):
                if re.search(r'IPC\$|print\$', line, re.IGNORECASE):
                    continue
                m = re.match(r'^\s*([A-Za-z0-9._$-]+)', line)
                if m:
                    shares.add(m.group(1))

    # nxc shares (null + guest combined)
    nxc_file = smb_dir / "nxc_shares.txt"
    if nxc_file.exists():
        for line in nxc_file.read_text(errors="ignore").splitlines():
            if re.search(r'\bREAD\b|\bWRITE\b', line, re.IGNORECASE):
                if re.search(r'IPC\$|ACCESS_DENIED', line, re.IGNORECASE):
                    continue
                # NXC format: "... ShareName   READ ONLY ..."
                m = re.search(r'([A-Za-z0-9._$-]+)\s+(?:READ|NO ACCESS)', line)
                if m:
                    shares.add(m.group(1))

    if shares:
        new_shares = [s for s in sorted(shares) if s not in session.info.shares_found]
        session.info.shares_found.extend(new_shares)
        log.info("SMB shares found: %s", sorted(shares))
        session.add_note(f"SMB shares accessible: {sorted(shares)}")


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
    nxc_users = smb_dir / "nxc_users.txt"
    if nxc_users.exists():
        for line in nxc_users.read_text(errors="ignore").splitlines():
            # NXC format: "... [+] domain\username ..."
            m = re.search(r'\[[\+\*]\]\s+(?:[^\\]+\\)?(\S+)', line)
            if m and not m.group(1).startswith("-"):
                users.add(m.group(1))

    # Filter out noise tokens
    _noise = {"", "account", "user", "group", "password", "enabled", "disabled"}
    users = {u for u in users if u.lower() not in _noise and len(u) > 1}

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


