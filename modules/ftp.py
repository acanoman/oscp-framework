"""
modules/ftp.py — FTP enumeration module

Routes to wrappers/services_enum.sh (port 21) for banner grabbing and
anonymous-login checks via Nmap NSE scripts.
After the wrapper runs, parses output and injects [MANUAL] hints into
session notes so they appear in notes.md.

OSCP compliance:
  - NSE scripts only (ftp-anon, ftp-bounce, banner grab)
  - NO brute force
  - Exploitation steps → hint only
"""

import re
import subprocess
from pathlib import Path

WRAPPERS_DIR = Path(__file__).resolve().parent.parent / "wrappers"

# Ports this module owns
_FTP_PORTS = {
    21,    # FTP control
    990,   # FTPS (implicit TLS)
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(target: str, session, dry_run: bool = False) -> None:
    log = session.log

    open_ftp = session.info.open_ports & _FTP_PORTS
    if not open_ftp:
        log.info("No FTP ports open — skipping ftp module.")
        return

    log.info("FTP ports to enumerate: %s", sorted(open_ftp))

    # Inject MANUAL hints immediately — visible even if wrapper is interrupted
    _add_manual_hints(session, open_ftp)

    script = WRAPPERS_DIR / "ftp_enum.sh"
    if not script.exists():
        log.error("Wrapper not found: %s", script)
        return

    # Use the lowest open FTP port (21 or 990) as the primary target
    primary_port = min(open_ftp)
    cmd = [
        "bash", str(script),
        "--target",     target,
        "--output-dir", str(session.target_dir),
        "--port",       str(primary_port),
    ]

    # Pass credentials if already known (e.g. from session state)
    ftp_user = getattr(session.info, "ftp_user", None)
    ftp_pass = getattr(session.info, "ftp_pass", None)
    if ftp_user and ftp_pass:
        cmd += ["--user", ftp_user, "--pass", ftp_pass]
        log.info("Running authenticated FTP enum as: %s", ftp_user)

    _exec(cmd, log, dry_run, label="ftp_enum.sh")

    if dry_run:
        return

    _parse_ftp(session, log)

    log.info("FTP module complete.")


# ---------------------------------------------------------------------------
# MANUAL hints — written to notes.md regardless of what the wrapper finds
# ---------------------------------------------------------------------------

def _add_manual_hints(session, open_ftp: set) -> None:
    ip = session.info.ip

    if 21 in open_ftp:
        session.add_note(
            f"💡 [MANUAL] Anonymous login: ftp {ip}"
        )
        session.add_note(
            f"💡 [MANUAL] Anonymous login (curl): curl -v ftp://{ip}/"
        )
        session.add_note(
            f"💡 [MANUAL] Anonymous login (nmap): "
            f"nmap -p 21 --script ftp-anon,ftp-bounce,ftp-syst {ip}"
        )
        session.add_note(
            f"💡 [MANUAL] FTP with creds: ftp {ip}  (then: user USER, pass PASS)"
        )

    if 990 in open_ftp:
        session.add_note(
            f"💡 [MANUAL] FTPS connection: "
            f"curl -v --ftp-ssl ftp://{ip}/ --user anonymous:anonymous"
        )


# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------

def _parse_ftp(session, log) -> None:
    ftp_dir = session.target_dir / "ftp"
    ftp_f   = ftp_dir / "ftp_nmap.txt"
    if not ftp_f.exists():
        # Fallback: services output might land elsewhere
        ftp_f = session.target_dir / "services" / "ftp_nmap.txt"
    if not ftp_f.exists():
        return

    content = ftp_f.read_text(errors="ignore")

    # Anonymous login confirmed by NSE
    if re.search(r"ftp-anon:.*Login correct|Anonymous FTP login allowed", content, re.IGNORECASE):
        log.warning("FTP: anonymous login allowed")
        session.add_note(
            f"🚨 FTP FINDING: Anonymous login allowed — {ftp_f}"
        )
        # Try to extract the directory listing
        listing = re.findall(r"^\|.+$", content, re.MULTILINE)
        if listing:
            session.add_note(f"FTP anonymous directory listing:\n" + "\n".join(listing[:20]))

    # Banner / version
    banner = re.search(r"ftp-syst:\s*\n(\|.+)", content)
    if banner:
        log.info("FTP banner: %s", banner.group(1).strip())

    # FTP bounce
    if re.search(r"ftp-bounce.*VULNERABLE|bounce.*allowed", content, re.IGNORECASE):
        log.warning("FTP: bounce scan possible (PORT-mode proxying)")
        session.add_note("⚠️  FTP: bounce scan allowed — potential for port proxying")


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
