"""
modules/creds.py — One-credential protocol sweep

Runs first (Tier 1) whenever a credential was supplied on the CLI
(-u/-p or -u/-H). Routes to wrappers/cred_sweep.sh, which checks — with a
single login attempt per protocol — which services the credential can
authenticate to (SMB, LDAP, WinRM, MSSQL, SSH, RDP, FTP).

OSCP compliance:
  - One authenticated bind per protocol as a single user — NOT a spray,
    so there is no account-lockout risk
  - Reports access only ("Pwn3d!" = execution possible); it never opens a
    shell or runs a command — exploitation stays a manual step
  - Stops the sweep immediately if any protocol reports a locked-out account
"""

from pathlib import Path

from core.runner import run_wrapper

WRAPPERS_DIR = Path(__file__).resolve().parent.parent / "wrappers"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(target: str, session, dry_run: bool = False) -> None:
    log = session.log

    cred_user = getattr(session.info, "cred_user", "")
    cred_pass = getattr(session.info, "cred_pass", "")
    cred_hash = getattr(session.info, "cred_hash", "")
    if not (cred_user and (cred_pass or cred_hash)):
        log.info("No credentials in session — skipping credential sweep.")
        return

    if not session.info.open_ports:
        log.info("No open ports known — skipping credential sweep.")
        return

    script = WRAPPERS_DIR / "cred_sweep.sh"
    if not script.exists():
        log.error("Wrapper not found: %s", script)
        return

    ports_csv = ",".join(str(p) for p in sorted(session.info.open_ports))
    cmd = [
        "bash", str(script),
        "--target",     target,
        "--output-dir", str(session.target_dir),
        "--ports",      ports_csv,
        "--user",       cred_user,
    ]
    if cred_pass:
        cmd += ["--pass", cred_pass]
    if cred_hash:
        cmd += ["--hash", cred_hash]
    if session.info.domain:
        cmd += ["--domain", session.info.domain]
    if getattr(session.info, "local_auth", False):
        cmd += ["--local-auth"]

    log.info("Running one-credential sweep as %s", cred_user)
    run_wrapper(cmd, session, label="cred_sweep.sh", dry_run=dry_run)

    if dry_run:
        return

    _parse_sweep(session, log)
    log.info("Credential sweep complete.")


# ---------------------------------------------------------------------------
# Parser — surface where the credential works into notes.md
# ---------------------------------------------------------------------------

def _parse_sweep(session, log) -> None:
    summary = session.target_dir / "creds" / "sweep_summary.txt"
    if not summary.exists():
        return

    user = session.info.cred_user
    for line in summary.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        status, _, rest = line.partition(" ")
        label = rest.strip().split("  ")[0].strip()
        if status == "PWN3D":
            log.warning("Credential sweep: %s can EXECUTE on %s", user, label)
            session.add_note(
                f"🚨 CRED SWEEP: '{user}' can EXECUTE CODE on {label} (Pwn3d) — foothold candidate"
            )
        elif status == "VALID":
            log.info("Credential sweep: %s valid on %s", user, label)
            session.add_note(f"✅ CRED SWEEP: '{user}' authenticates on {label}")
        elif status == "LOCKED":
            log.error("Credential sweep: account locked out on %s", label)
            session.add_note(
                f"⛔ CRED SWEEP: account LOCKED OUT on {label} — sweep halted, review before retrying"
            )
