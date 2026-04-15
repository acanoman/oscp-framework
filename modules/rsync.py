"""
modules/rsync.py — Rsync enumeration module

Calls wrappers/rsync_enum.sh, then parses the output files to update
session notes with discovered modules, accessible shares, and interesting
files found during unauthenticated enumeration.

OSCP compliance:
  - Read-only module listing and content enumeration
  - NO automatic file download or upload
  - Exploitation steps → hint only
"""

import re
from pathlib import Path

from core.runner import run_wrapper

WRAPPERS_DIR = Path(__file__).resolve().parent.parent / "wrappers"

# Ports this module owns
_RSYNC_PORTS = {
    873,   # rsync default port
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(target: str, session, dry_run: bool = False) -> None:
    log = session.log

    open_rsync = session.info.open_ports & _RSYNC_PORTS
    if not open_rsync:
        log.info("No rsync ports open — skipping rsync module.")
        return

    log.info("Rsync ports to enumerate: %s", sorted(open_rsync))

    # Inject MANUAL hints immediately — visible even if wrapper is interrupted
    _add_manual_hints(session, open_rsync)

    script = WRAPPERS_DIR / "rsync_enum.sh"
    if not script.exists():
        log.error("Wrapper not found: %s", script)
        return

    primary_port = min(open_rsync)
    cmd = [
        "bash", str(script),
        "--target",     target,
        "--output-dir", str(session.target_dir),
        "--ports",      str(primary_port),
    ]

    run_wrapper(cmd, session, label="rsync_enum.sh", dry_run=dry_run)

    if dry_run:
        return

    _parse_rsync(session, log)

    log.info("Rsync module complete.")


# ---------------------------------------------------------------------------
# MANUAL hints — written to notes.md regardless of what the wrapper finds
# ---------------------------------------------------------------------------

def _add_manual_hints(session, open_rsync: set) -> None:
    ip = session.info.ip

    if 873 in open_rsync:
        session.add_note(
            f"[MANUAL] List rsync modules: rsync --list-only rsync://{ip}/"
        )
        session.add_note(
            f"[MANUAL] List module contents: rsync --list-only rsync://{ip}/<MODULE>/"
        )
        session.add_note(
            f"[MANUAL] Download module: rsync -avz rsync://{ip}/<MODULE>/ ./loot/<MODULE>/"
        )
        session.add_note(
            f"[MANUAL] Rsync NSE scripts: "
            f"nmap -p 873 --script rsync-list-modules -Pn {ip}"
        )
        session.add_note(
            f"[MANUAL] Authenticated rsync: "
            f"rsync -avz rsync://<USER>@{ip}/<MODULE>/ ./loot/<MODULE>/"
        )


# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------

def _parse_rsync(session, log) -> None:
    rsync_dir = session.target_dir / "rsync"
    if not rsync_dir.exists():
        return

    ip = session.info.ip

    # Parse module list
    modules_file = rsync_dir / "rsync_modules.txt"
    modules_found: list = []

    if modules_file.exists():
        content = modules_file.read_text(errors="ignore")
        for line in content.splitlines():
            line = line.strip()
            # rsync module listing lines: "<module_name>    <comment>"
            # Skip header lines, blank lines, and error messages
            if not line or line.startswith("#") or line.startswith("@"):
                continue
            if re.match(r"^(ERROR|WARNING|rsync:|opening|sending|receiving)", line, re.IGNORECASE):
                continue
            # Module name is typically the first whitespace-separated token
            m = re.match(r'^(\S+)', line)
            if m:
                mod_name = m.group(1)
                # Filter out non-module output lines
                if not re.match(r'^(Protocol|Connecting|receiving|sending|total)', mod_name, re.IGNORECASE):
                    modules_found.append(mod_name)

    if modules_found:
        log.warning("Rsync modules exposed: %s", modules_found)
        session.add_note(f"RSYNC FINDING: Exposed modules — {modules_found}")
        for mod in modules_found:
            session.add_note(
                f"[MANUAL] List rsync module '{mod}': "
                f"rsync --list-only rsync://{ip}/{mod}/"
            )
            session.add_note(
                f"[MANUAL] Download rsync module '{mod}': "
                f"rsync -avz rsync://{ip}/{mod}/ ./loot/{mod}/"
            )
            session.add_manual_command(
                f"rsync --list-only rsync://{ip}/{mod}/",
                f"List contents of rsync module: {mod}",
            )
            session.add_manual_command(
                f"rsync -avz rsync://{ip}/{mod}/ ./loot/{mod}/",
                f"Download rsync module: {mod}",
            )

    # Parse per-module listings for interesting files
    interesting_patterns = re.compile(
        r'(id_rsa|authorized_keys|\.pem|\.key|\.conf|\.config|\.ini|'
        r'\.yml|\.yaml|\.env|\.bak|\.backup|\.old|\.tar|\.zip|\.gz|'
        r'password|passwd|credentials|secret|web\.config|\.htpasswd|'
        r'wp-config\.php)',
        re.IGNORECASE,
    )

    for listing_file in rsync_dir.glob("*_listing.txt"):
        mod_name = listing_file.stem.replace("_listing", "")
        content = listing_file.read_text(errors="ignore")
        file_count = len([l for l in content.splitlines() if re.match(r'^\s*-', l)])

        interesting = [
            line.strip()
            for line in content.splitlines()
            if interesting_patterns.search(line)
        ]

        if interesting:
            log.warning(
                "Rsync module '%s' contains %d interesting file(s)", mod_name, len(interesting)
            )
            session.add_note(
                f"RSYNC FINDING: Module '{mod_name}' has interesting files:\n"
                + "\n".join(interesting[:20])
            )

        if file_count > 0:
            log.info("Rsync module '%s': %d files enumerated (no auth required)", mod_name, file_count)
            session.add_note(
                f"RSYNC FINDING: Module '{mod_name}' accessible without authentication "
                f"({file_count} files)"
            )
