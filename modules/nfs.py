"""
modules/nfs.py — NFS / RPC enumeration module

Routes to wrappers/services_enum.sh (ports 111, 2049) for RPC portmapper
enumeration and NFS export listing.
After the wrapper runs, parses output and injects [MANUAL] hints into
session notes so they appear in notes.md.

OSCP compliance:
  - Read-only export enumeration (showmount, rpcinfo, NSE)
  - NO automatic mount/read — hint only
  - File read via mounted share → hint only
"""

import re
import subprocess
from pathlib import Path

WRAPPERS_DIR = Path(__file__).resolve().parent.parent / "wrappers"

# Ports this module owns
_NFS_PORTS = {
    111,   # RPC portmapper
    2049,  # NFS
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(target: str, session, dry_run: bool = False) -> None:
    log = session.log

    open_nfs = session.info.open_ports & _NFS_PORTS
    if not open_nfs:
        log.info("No NFS/RPC ports open — skipping nfs module.")
        return

    log.info("NFS/RPC ports to enumerate: %s", sorted(open_nfs))

    # Inject MANUAL hints immediately — visible even if wrapper is interrupted
    _add_manual_hints(session, open_nfs)

    script = WRAPPERS_DIR / "nfs_enum.sh"
    if not script.exists():
        log.error("Wrapper not found: %s", script)
        return

    cmd = [
        "bash", str(script),
        "--target",     target,
        "--output-dir", str(session.target_dir),
    ]

    _exec(cmd, log, dry_run, label="nfs_enum.sh")

    if dry_run:
        return

    _parse_nfs(session, log)

    log.info("NFS module complete.")


# ---------------------------------------------------------------------------
# MANUAL hints — written to notes.md regardless of what the wrapper finds
# ---------------------------------------------------------------------------

def _add_manual_hints(session, open_nfs: set) -> None:
    ip = session.info.ip

    if 111 in open_nfs or 2049 in open_nfs:
        session.add_note(
            f"💡 [MANUAL] List exports: showmount -e {ip}"
        )
        session.add_note(
            f"💡 [MANUAL] RPC portmapper dump: rpcinfo -p {ip}"
        )
        session.add_note(
            f"💡 [MANUAL] NFS NSE scripts: "
            f"nmap -p 111,2049 --script nfs-ls,nfs-showmount,nfs-statfs,rpcinfo {ip}"
        )
        session.add_note(
            f"💡 [MANUAL] Mount export (root squash OFF → UID 0 trick): "
            f"mount -t nfs {ip}:/EXPORT /mnt/nfs -o nolock"
        )
        session.add_note(
            f"💡 [MANUAL] Mount with specific UID: "
            f"mount -t nfs {ip}:/EXPORT /mnt/nfs && "
            f"useradd -u UID pwned && su pwned"
        )


# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------

def _parse_nfs(session, log) -> None:
    nfs_dir = session.target_dir / "nfs"
    nfs_f   = nfs_dir / "nfs_nmap.txt"
    if not nfs_f.exists():
        nfs_f = session.target_dir / "services" / "nfs_nmap.txt"
    if not nfs_f.exists():
        return

    content = nfs_f.read_text(errors="ignore")

    # Export paths
    exports = re.findall(r"(/[^\s,]+)\s+(?:\*|\d{1,3}\.\d{1,3})", content)
    if exports:
        unique = sorted(set(exports))
        log.warning("NFS exports found: %s", unique)
        session.add_note(f"🚨 NFS FINDING: Exports available — {unique}")
        for export in unique:
            session.add_note(
                f"💡 [MANUAL] Mount: mount -t nfs {session.info.ip}:{export} /mnt/nfs"
            )

    # no_root_squash — privilege escalation primitive
    if re.search(r"no_root_squash", content, re.IGNORECASE):
        log.warning("NFS: no_root_squash detected — UID 0 SUID binary plant possible")
        session.add_note(
            "🚨 NFS FINDING: no_root_squash on export — "
            "SUID binary plant via mount as local root is possible (PrivEsc path)"
        )

    # Access-unrestricted exports
    if re.search(r"nfs-showmount:.*\*", content, re.IGNORECASE):
        log.warning("NFS: export open to all hosts (*)")
        session.add_note("⚠️  NFS: Export accessible by all hosts (*) — no IP restriction")

    # Files visible
    files = re.findall(r"nfs-ls:.*?(-[rwx-]{9}.*?\s+(\S+))", content, re.DOTALL)
    if files:
        log.info("NFS: file listing retrieved — review output for sensitive files")
        session.add_note("NFS file listing obtained — check output for .ssh, passwords, configs")


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
