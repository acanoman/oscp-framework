"""
modules/ldap.py — LDAP / Active Directory enumeration module

Calls wrappers/ldap_enum.sh, then parses the output files to update
session.info with discovered users, computers, base DN, and domain info.

OSCP routing logic:
  - Port 88 (Kerberos) → DC detection; kerbrute username enumeration
  - Port 389 or 636 → LDAP anonymous + authenticated enum
  - Port 3268/3269 → Global Catalog (AD forest-wide queries)

Credentials: pulled from session.info if available.
AS-REP Roasting and Kerberoasting are NEVER automated — manual hints only.
"""

import re
from pathlib import Path

from core.runner import run_wrapper
from rich.console import Console
from rich.panel import Panel

WRAPPERS_DIR = Path(__file__).resolve().parent.parent / "wrappers"

_LDAP_PORTS = {389, 636, 3268, 3269}
_KERB_PORT  = 88


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(target: str, session, dry_run: bool = False) -> None:
    log = session.log
    log.info("LDAP module starting for %s", target)

    # Check at least one LDAP-related port is open
    ldap_ports = session.info.open_ports & _LDAP_PORTS
    kerb_open  = _KERB_PORT in session.info.open_ports

    if not ldap_ports and not kerb_open:
        log.warning(
            "No LDAP/Kerberos ports (389/636/88/3268) open — skipping LDAP module."
        )
        return

    if ldap_ports:
        log.info("LDAP ports open: %s", sorted(ldap_ports))
    if kerb_open:
        log.info("Kerberos (88) open — likely a Domain Controller")

    script = WRAPPERS_DIR / "ldap_enum.sh"
    if not script.exists():
        log.error("Wrapper not found: %s", script)
        return

    # -----------------------------------------------------------------------
    # Build command
    # -----------------------------------------------------------------------
    cmd = [
        "bash", str(script),
        "--target",     target,
        "--output-dir", str(session.target_dir),
    ]

    if session.info.domain:
        cmd += ["--domain", session.info.domain]

    # Credentials stored by engine (Phase 4 addition)
    ldap_user = getattr(session.info, "ldap_user", None)
    ldap_pass = getattr(session.info, "ldap_pass", None)
    if ldap_user and ldap_pass:
        cmd += ["--user", ldap_user, "--pass", ldap_pass]
        log.info("Running authenticated LDAP enum as: %s", ldap_user)
    else:
        log.info("Running anonymous LDAP bind (no credentials in session)")

    run_wrapper(cmd, session, label="ldap_enum.sh", dry_run=dry_run)

    if dry_run:
        return

    # -----------------------------------------------------------------------
    # Parse output → update session.info
    # -----------------------------------------------------------------------
    ldap_dir = session.target_dir / "ldap"

    _parse_base_dn(ldap_dir, session, log)
    _parse_users(ldap_dir, session, log)
    _parse_domain_info(ldap_dir, session, log)

    # Print manual hints if Kerberos is open and we found users
    if kerb_open and session.info.users_found:
        _print_kerberos_hints(ldap_dir, session, log)

    # Parse kerbrute output — integrates confirmed usernames into session state
    # and surfaces them in notes.md for immediate AS-REP Roasting follow-up.
    _parse_kerbrute_output(ldap_dir, session, log)

    # OSCP+ COMPLIANT — manual only
    # _check_for_existing_hash_files() is intentionally not called here.
    # The automated kill chain that wrote asreproast.hashes has been removed
    # from ldap_enum.sh. Call this function manually if you ran GetNPUsers
    # outside the framework and want to parse the resulting hash file.
    # _check_for_existing_hash_files(ldap_dir, session, log)  # IMP-5 applied

    log.info("LDAP module complete.")


# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------

def _parse_base_dn(ldap_dir: Path, session, log) -> None:
    """Read the base DN and update session domain if not already set."""
    base_dn_file = ldap_dir / "base_dn.txt"
    if not base_dn_file.exists():
        return

    base_dn = base_dn_file.read_text(errors="ignore").strip()
    if not base_dn:
        return

    log.info("LDAP base DN: %s", base_dn)
    session.add_note(f"LDAP base DN: {base_dn}")

    # Convert DC=corp,DC=local → corp.local and store as domain
    domain_parts = re.findall(r'DC=([^,]+)', base_dn, re.IGNORECASE)
    if domain_parts:
        inferred_domain = ".".join(domain_parts)
        if inferred_domain not in session.info.domains_found:
            session.info.domains_found.append(inferred_domain)
            log.info("Domain inferred from base DN: %s", inferred_domain)
        if not session.info.domain:
            session.info.domain = inferred_domain
            log.info("Domain set to: %s", session.info.domain)


def _parse_users(ldap_dir: Path, session, log) -> None:
    """Read extracted user list from ldap_users.txt."""
    users_file = ldap_dir / "ldap_users.txt"
    if not users_file.exists():
        return

    users: list = []
    for line in users_file.read_text(errors="ignore").splitlines():
        u = line.strip()
        # Filter out computer accounts (end with $) and empty lines
        if u and not u.endswith("$") and u not in session.info.users_found:
            users.append(u)

    if users:
        session.info.users_found.extend(users)
        log.info("LDAP users discovered: %d accounts", len(users))
        session.add_note(f"LDAP users ({len(users)}): {', '.join(users[:20])}")
        if len(users) > 20:
            session.add_note(f"  ... and {len(users) - 20} more — see ldap/ldap_users.txt")


def _parse_domain_info(ldap_dir: Path, session, log) -> None:
    """Extract domain/DC info from Nmap LDAP script output."""
    nmap_file = ldap_dir / "ldap_nmap.txt"
    if not nmap_file.exists():
        return

    content = nmap_file.read_text(errors="ignore")

    # ldap-rootdse often returns the domain DNS name
    dns_matches = re.findall(r'(?:dnsHostName|defaultNamingContext)[:\s]+(\S+)', content)
    for match in dns_matches:
        match = match.strip().rstrip(",")
        if "." in match and match not in session.info.domains_found:
            session.info.domains_found.append(match)
            log.info("Domain/hostname from LDAP NSE: %s", match)
            if not session.info.domain:
                session.info.domain = match


def _print_kerberos_hints(ldap_dir: Path, session, log) -> None:
    """
    Log manual Kerberos attack hints.
    These are NEVER automated — they require conscious user action.
    """
    users_file = ldap_dir / "ldap_users.txt"
    domain     = session.info.domain or "<DOMAIN>"
    target     = session.info.ip

    log.warning(
        "Kerberos open + LDAP users found — run AS-REP Roasting MANUALLY:\n"
        "  impacket-GetNPUsers %s/ -dc-ip %s -no-pass -usersfile %s",
        domain, target, users_file,
    )
    log.warning(
        "Kerberoasting (needs valid credentials — run MANUALLY):\n"
        "  impacket-GetUserSPNs %s/<USER>:<PASS> -dc-ip %s -request",
        domain, target,
    )
    session.add_note(
        f"💡 AS-REP Roasting — "
        f"impacket-GetNPUsers {domain}/ -dc-ip {target} -no-pass "
        f"-usersfile {users_file}"
    )


def _parse_kerbrute_output(ldap_dir: Path, session, log) -> None:
    """
    Parse kerbrute userenum output to extract Kerberos-confirmed usernames.

    kerbrute writes two artefacts:
      ldap/kerbrute_users.txt      — structured output from --output flag
      ldap/kerbrute_users.txt.log  — full tee'd stdout (richer format)

    Both files use the same line format for valid accounts:
        <timestamp> >  [+] VALID USERNAME:       user@domain.com

    Only the username part (before @) is extracted — domain suffix is
    redundant since session.info.domain already holds it.

    Confirmed usernames are merged into session.info.users_found (de-duped)
    and the AS-REP Roasting manual command is injected as a 💡 note so the
    operator can copy-paste it immediately from notes.md.
    """
    kerb_out = ldap_dir / "kerbrute_users.txt"
    if not kerb_out.exists() or kerb_out.stat().st_size == 0:
        return

    confirmed: list = []
    for line in kerb_out.read_text(errors="ignore").splitlines():
        # kerbrute format: "... [+] VALID USERNAME:       user@domain.com"
        m = re.search(
            r'VALID USERNAME:\s+([A-Za-z0-9_\.\-]+)(?:@\S+)?',
            line, re.IGNORECASE,
        )
        if not m:
            continue
        user = m.group(1).strip()
        if user and user not in session.info.users_found:
            session.info.users_found.append(user)
            confirmed.append(user)
            log.info("kerbrute confirmed valid user: %s", user)

    if not confirmed:
        log.info("kerbrute output parsed — no new usernames added")
        return

    domain = session.info.domain or "<DOMAIN>"
    target = session.info.ip

    log.info(
        "kerbrute: %d new confirmed user(s) added to session: %s",
        len(confirmed), confirmed[:10],
    )
    session.add_note(
        f"✅ kerbrute validated {len(confirmed)} user(s) via Kerberos: "
        f"{', '.join(confirmed[:20])}"
        + (f" ... and {len(confirmed) - 20} more" if len(confirmed) > 20 else "")
    )
    # Inject ready-to-run AS-REP Roasting command so the operator can act
    # immediately — marked 💡 so finalize_notes() surfaces it in the
    # "Manual Follow-Up Commands" section of notes.md.
    session.add_note(
        f"💡 AS-REP Roast confirmed users: "
        f"impacket-GetNPUsers {domain}/ -dc-ip {target} -no-pass "
        f"-usersfile {ldap_dir / 'ldap_users.txt'} "
        f"-outputfile {ldap_dir / 'asrep_hashes.txt'}"
    )


def _check_for_existing_hash_files(ldap_dir: Path, session, log) -> None:  # IMP-5 applied
    """
    Check whether AS-REP hash files exist from a previous manual run.

    If asreproast.hashes exists and has content, display a neutral
    informational panel and record the path in session state so advisor.py
    can reference it.
    """
    hash_file = ldap_dir / "asreproast.hashes"
    if not hash_file.exists() or hash_file.stat().st_size == 0:
        return

    lines = [l for l in hash_file.read_text(errors="ignore").splitlines()
             if l.startswith("$krb5asrep$")]
    if not lines:
        return

    hash_count = len(lines)
    log.info("Hash file detected (from a previous manual run): %d hash(es) in %s", hash_count, hash_file)

    # Mark on session so advisor.py knows hashes exist
    session.info.ntlm_hashes_found = True  # reuse existing flag — triggers PTH section too
    # Store path so advisor.py can reference the exact file
    if not hasattr(session.info, "asreproast_hash_file"):
        session.info.asreproast_hash_file = str(hash_file)

    session.add_note(
        f"📄 Hash files found (from a previous manual run): {hash_count} hash(es) → {hash_file}\n"
        f"   Hash files detected at {hash_file}. These were not captured by this framework.\n"
        f"   If you ran impacket-GetNPUsers manually, review and crack these files manually if applicable.\n"
        f"   hashcat -m 18200 {hash_file} /usr/share/wordlists/rockyou.txt "
        f"-r /usr/share/john/rules/best64.rule"
    )

    console = Console()
    console.print()
    console.print(
        Panel(
            f"[bold white]{hash_count} hash file(s) detected[/bold white]\n\n"
            f"[bold yellow]File:[/bold yellow] [cyan]{hash_file}[/cyan]\n\n"
            f"[dim]Hash files detected at {hash_file}. These were not captured\n"
            f"by this framework. If you ran impacket-GetNPUsers manually,\n"
            f"review and crack these files manually if applicable.[/dim]\n\n"
            f"[bold yellow]Crack command:[/bold yellow]\n"
            f"[white]hashcat -m 18200 {hash_file} \\\n"
            f"    /usr/share/wordlists/rockyou.txt \\\n"
            f"    -r /usr/share/john/rules/best64.rule[/white]",
            title="[bold blue] 📄  Hash files found (from a previous manual run) [/bold blue]",
            border_style="blue",
            padding=(1, 4),
        )
    )
    console.print()


