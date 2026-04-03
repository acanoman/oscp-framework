"""
modules/snmp.py — SNMP enumeration module

Routes to wrappers/services_enum.sh (ports 161/162) for community string
probing and MIB walk via Nmap NSE scripts and onesixtyone.
After the wrapper runs, parses output and injects [MANUAL] hints into
session notes so they appear in notes.md.

OSCP compliance:
  - Read-only community string probing (GET/WALK)
  - NO SET operations (write attacks) — hint only
  - NO automatic credential extraction
"""

import re
import subprocess
from pathlib import Path

WRAPPERS_DIR = Path(__file__).resolve().parent.parent / "wrappers"

# Ports this module owns
_SNMP_PORTS = {
    161,   # SNMP (UDP)
    162,   # SNMPTRAP (UDP)
}

# Common community strings to highlight in hints
_COMMUNITY_STRINGS = ["public", "private", "manager", "community"]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(target: str, session, dry_run: bool = False) -> None:
    log = session.log

    open_snmp = session.info.open_ports & _SNMP_PORTS
    if not open_snmp:
        log.info("No SNMP ports open — skipping snmp module.")
        return

    log.info("SNMP ports to enumerate: %s", sorted(open_snmp))

    # Inject MANUAL hints immediately — visible even if wrapper is interrupted
    _add_manual_hints(session, open_snmp)

    script = WRAPPERS_DIR / "services_enum.sh"
    if not script.exists():
        log.error("Wrapper not found: %s", script)
        return

    # SNMP runs over UDP — the wrapper's has_udp_port() checks $UDP_PORTS,
    # not $PORTS.  Pass port 161 via --udp-ports so the SNMP section fires.
    # We still pass --ports with a placeholder so the wrapper's argument
    # parser doesn't error on a missing required flag.
    cmd = [
        "bash", str(script),
        "--target",     target,
        "--output-dir", str(session.target_dir),
        "--ports",      "",          # no TCP ports for this module
        "--udp-ports",  "161",       # triggers has_udp_port 161 in wrapper
    ]

    _exec(cmd, log, dry_run, label="services_enum.sh (snmp)")

    if dry_run:
        return

    _parse_snmp(session, log)

    log.info("SNMP module complete.")


# ---------------------------------------------------------------------------
# MANUAL hints — written to notes.md regardless of what the wrapper finds
# ---------------------------------------------------------------------------

def _add_manual_hints(session, open_snmp: set) -> None:
    ip = session.info.ip

    if 161 in open_snmp:
        session.add_note(
            f"💡 [MANUAL] SNMP Walk (v2c public): snmpwalk -v2c -c public {ip}"
        )
        session.add_note(
            f"💡 [MANUAL] SNMP Walk (v1): snmpwalk -v1 -c public {ip}"
        )
        session.add_note(
            f"💡 [MANUAL] Community string brute-force: "
            f"onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt {ip}"
        )
        session.add_note(
            f"💡 [MANUAL] SNMP extended MIB (users): "
            f"snmpwalk -v2c -c public {ip} 1.3.6.1.4.1.77.1.2.25"
        )
        session.add_note(
            f"💡 [MANUAL] SNMP process list: "
            f"snmpwalk -v2c -c public {ip} 1.3.6.1.2.1.25.4.2.1.2"
        )
        session.add_note(
            f"💡 [MANUAL] SNMP nmap script: "
            f"nmap -p 161,162 -sU --script snmp-brute,snmp-info,snmp-sysdescr {ip}"
        )


# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------

def _parse_snmp(session, log) -> None:
    snmp_dir = session.target_dir / "snmp"
    snmp_f   = snmp_dir / "snmp_nmap.txt"
    if not snmp_f.exists():
        snmp_f = session.target_dir / "services" / "snmp_nmap.txt"
    if not snmp_f.exists():
        return

    content = snmp_f.read_text(errors="ignore")

    # Community string confirmed
    for cs in _COMMUNITY_STRINGS:
        if re.search(rf"community.*{cs}|{cs}.*community", content, re.IGNORECASE):
            log.warning("SNMP: community string '%s' appears valid", cs)
            session.add_note(
                f"🚨 SNMP FINDING: Community string '{cs}' accepted — {snmp_f}"
            )

    # System description (reveals OS/version)
    sysdescr = re.search(r"SNMPv2-MIB::sysDescr\.0\s*=\s*(.+)", content)
    if sysdescr:
        log.info("SNMP sysDescr: %s", sysdescr.group(1).strip())
        session.add_note(f"SNMP sysDescr: {sysdescr.group(1).strip()}")

    # Hostname revealed via SNMP
    sysname = re.search(r"SNMPv2-MIB::sysName\.0\s*=\s*(\S+)", content)
    if sysname:
        hostname = sysname.group(1).strip()
        log.info("SNMP hostname: %s", hostname)
        session.add_note(f"SNMP hostname disclosed: {hostname}")
        if hostname not in session.info.domains_found:
            session.info.domains_found.append(hostname)

    # Windows users from OID 1.3.6.1.4.1.77.1.2.25
    users = re.findall(r"hrSWRunName|iso\.3\.6.*STRING: \"([^\"]+)\"", content)
    if users:
        log.info("SNMP potential process/user names: %s", users[:10])


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
