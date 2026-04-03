"""
modules/network.py — Network recon module

Calls wrappers/recon.sh and parses the resulting Nmap XML back into
session.info so the engine can route subsequent modules correctly.

This module is the entry point when --modules network is forced, or when
the engine needs to re-run recon against a target with known ports.
"""

import subprocess
from pathlib import Path

from core.parser import NmapParser

WRAPPERS_DIR = Path(__file__).resolve().parent.parent / "wrappers"

# Web port heuristics (used to annotate port_details with proto)
_HTTPS_PORTS = {443, 8443, 9443, 4443}
_WEB_PORTS   = {
    80, 443, 8000, 8008, 8080, 8443, 8888,
    9090, 9443, 3000, 5000, 7001,
}


# ---------------------------------------------------------------------------
# Public entry point (called by engine._run_module)
# ---------------------------------------------------------------------------

def run(target: str, session, dry_run: bool = False) -> None:
    log = session.log
    log.info("Network module starting for %s", target)

    script = WRAPPERS_DIR / "recon.sh"
    if not script.exists():
        log.error("Wrapper not found: %s", script)
        return

    # Build command — pass everything the wrapper accepts
    cmd = [
        "bash", str(script),
        "--target",     target,
        "--output-dir", str(session.target_dir),
    ]
    if session.info.domain:
        cmd += ["--domain", session.info.domain]

    # Execute initial port scan
    _exec(cmd, log, dry_run, label="recon.sh")

    # Supplemental topology discovery (traceroute, ICMP, ARP, reverse DNS)
    net_script = WRAPPERS_DIR / "network_enum.sh"
    if net_script.exists():
        net_cmd = [
            "bash", str(net_script),
            "--target",     target,
            "--output-dir", str(session.target_dir),
        ]
        if session.info.domain:
            net_cmd += ["--domain", session.info.domain]
        _exec(net_cmd, log, dry_run, label="network_enum.sh")
    else:
        log.warning("network_enum.sh not found — skipping topology discovery")

    if dry_run:
        return

    # -----------------------------------------------------------------------
    # Parse Nmap XML → update session.info
    # -----------------------------------------------------------------------
    nmap_xml = session.path("scans", "nmap_initial.xml")

    if not nmap_xml.exists():
        log.warning(
            "Nmap XML not found at %s — recon.sh may have failed or nmap is not installed.",
            nmap_xml,
        )
        return

    parser = NmapParser(log)
    parser.parse_xml(nmap_xml, session.info)

    open_ports = sorted(session.info.open_ports)
    if not open_ports:
        log.warning("No open ports discovered. Verify the target is reachable.")
        return

    log.info("Open TCP ports: %s", open_ports)
    session.add_note(f"Nmap discovered {len(open_ports)} port(s): {open_ports}")

    # Annotate each port with protocol type for downstream modules
    for port, details in session.info.port_details.items():
        if not details.get("proto"):
            details["proto"] = "https" if port in _HTTPS_PORTS else "http" \
                if port in _WEB_PORTS else "tcp"

    # -----------------------------------------------------------------------
    # Read UDP ports from file (written by recon.sh step 3)
    # -----------------------------------------------------------------------
    udp_file = session.path("scans", "open_ports_udp.txt")
    if udp_file.exists() and udp_file.stat().st_size > 0:
        udp_raw = udp_file.read_text(encoding="utf-8").strip()
        if udp_raw:
            udp_ports = [int(p) for p in udp_raw.split(",") if p.strip().isdigit()]
            # Store in notes (TargetInfo has no udp_ports field — added as metadata)
            session.info.notes.append(f"UDP open ports: {udp_ports}")
            log.info("Open UDP ports: %s", udp_ports)

    # -----------------------------------------------------------------------
    # OS detection note
    # -----------------------------------------------------------------------
    if session.info.os_guess and session.info.os_guess != "Unknown":
        log.info("OS guess: %s", session.info.os_guess)
        session.add_note(f"OS guess: {session.info.os_guess}")

    log.info("Network module complete.")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _exec(
    cmd: list,
    log,
    dry_run: bool,
    label: str = "",
) -> int:
    """Log and optionally execute a command, streaming output to the terminal."""
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
        log.error("Command not found: %s — is bash available?", cmd[0])
        return -1
