"""
modules/web.py — Web enumeration module

Calls wrappers/web_enum.sh once per detected web port, then parses
gobuster/feroxbuster output to populate session.info.web_paths.

Port → protocol detection:
  443, 8443, 9443 → https
  Everything else → http (unless deep scan banner says ssl/https)
"""

import os
import re
import signal
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

from rich.console import Console

WRAPPERS_DIR = Path(__file__).resolve().parent.parent / "wrappers"

# Ports that look like web but are NOT browsable web services
_NON_WEB_PORTS = {5985, 5986, 47001, 593, 9389}
_HTTPS_PORTS   = {443, 8443, 9443, 4443, 7443}

# All ports we treat as web even without a confirmed Nmap service name.
# Ports NOT in this set are still scanned if Nmap identifies an http/https
# service on them (handles non-standard ports like 50000 automatically).
_WEB_PORTS = {
    80,    443,   # standard HTTP / HTTPS
    8000,  8001,  8002,  8003,  # common alternates
    8008,  8080,  8180,  8800,  # common alternates
    8443,  8888,  9000,  9001,  # common alternates
    9080,  9090,  9443,         # common alternates
    3000,  4000,  4443,         # dev / Node / misc
    5000,  7001,  7443,         # Flask / WebLogic
    10000,                       # Webmin
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(target: str, session, dry_run: bool = False) -> None:
    log = session.log
    log.info("Web module starting for %s", target)

    # Collect web ports from open port list
    web_targets = _detect_web_ports(session)

    if not web_targets:
        log.warning("No web ports detected in session — skipping web module.")
        return

    log.info("Web ports to enumerate: %s", [(p, proto) for p, proto in web_targets])

    script = WRAPPERS_DIR / "web_enum.sh"
    if not script.exists():
        log.error("Wrapper not found: %s", script)
        return

    console = Console()

    # -----------------------------------------------------------------------
    # Run one wrapper invocation per web port.
    #
    # Each port is wrapped in its own try/except KeyboardInterrupt so that
    # Ctrl+C skips only the CURRENT port and the loop continues for the
    # remaining ports.  The subprocess is launched with start_new_session=True
    # so the bash wrapper and ALL its children (nmap, feroxbuster, gobuster …)
    # share a single process group — a single os.killpg() signal reaches every
    # grandchild, preventing zombie scan processes.
    # -----------------------------------------------------------------------
    for port, proto in web_targets:
        # ── Resume guard — skip ports the user aborted in a previous run ──
        if port in session.info.skipped_ports:
            log.info(
                "Port %d was skipped by user in a previous session — skipping again. "
                "Remove 'skipped_ports' from session.json to force a rerun.",
                port,
            )
            console.print(
                f"  [bold yellow][SKIP][/bold yellow] Port [cyan]{port}[/cyan] "
                f"was aborted in a previous session — skipping."
            )
            continue

        log.info("-" * 50)
        log.info("Enumerating web port %d (%s)", port, proto)

        cmd = [
            "bash", str(script),
            "--target",     target,
            "--output-dir", str(session.target_dir),
            "--port",       str(port),
            "--proto",      proto,
        ]
        if session.info.domain:
            cmd += ["--domain", session.info.domain]

        display = " ".join(str(c) for c in cmd)
        log.info("[CMD] %s", display)
        console.print(f"  [bold yellow][CMD][/bold yellow] {display}")

        proc: Optional[subprocess.Popen] = None
        try:
            if not dry_run:
                proc = subprocess.Popen(
                    cmd,
                    text=True,
                    start_new_session=True,  # own process group for clean kill
                )
                proc.wait()
                if proc.returncode not in (0, None):
                    log.warning(
                        "web_enum.sh port %d exited with code %d",
                        port, proc.returncode,
                    )
                _parse_web_output(port, session, log)

        except KeyboardInterrupt:
            _kill_proc_group(proc, log)
            console.print(
                f"\n  [bold yellow][WARNING][/bold yellow] Skipping port "
                f"[cyan]{port}[/cyan] by user request (Ctrl+C)... "
                f"Moving to next port."
            )
            log.warning("Port %d web scan skipped by user (Ctrl+C)", port)

            # Flush any partial output written before the interrupt
            _parse_web_output(port, session, log)

            # Record skip so --resume doesn't endlessly retry this port
            session.add_note(
                f"⚠️  Port {port} ({proto}) web scan SKIPPED by user (Ctrl+C)"
            )
            session.info.skipped_ports.add(port)
            session.finalize_notes()
            session.save_state()
            continue

    log.info("Web module complete.")


# ---------------------------------------------------------------------------
# Port detection logic
# ---------------------------------------------------------------------------

def _detect_web_ports(session) -> list:
    """
    Return list of (port, proto) tuples for all discovered web ports.
    Respects the port_details 'service' field from Nmap for accuracy.
    """
    results: list = []
    seen:    set  = set()

    for port in sorted(session.info.open_ports):
        if port in _NON_WEB_PORTS or port in seen:
            continue

        details = session.info.port_details.get(port, {})
        service = details.get("service", "")

        # Explicit web port OR Nmap detected any http/https variant.
        # Catches non-standard ports (e.g. HTTP on 50000, HTTPS on 7443).
        is_web = (port in _WEB_PORTS) or bool(re.search(
            r'https?|http-alt|http-proxy|http-mgmt|http-rpc-epmap|ssl/http',
            service, re.IGNORECASE,
        ))

        if not is_web:
            continue

        # Determine protocol: HTTPS ports + any service with ssl/tls in the name
        if port in _HTTPS_PORTS or re.search(r'https|ssl/http|ssl', service, re.IGNORECASE):
            proto = "https"
        else:
            proto = "http"

        results.append((port, proto))
        seen.add(port)

    return results


# ---------------------------------------------------------------------------
# Output parsers — run after each wrapper completes
# ---------------------------------------------------------------------------

def _parse_web_output(port: int, session, log) -> None:
    """Parse gobuster, feroxbuster, whatweb, and CGI sniper output for a given port."""
    suffix = "" if port in {80, 443} else f"_port{port}"
    web_dir = session.target_dir / "web"

    _parse_directory_scan(web_dir, suffix, session, log)
    _parse_whatweb(web_dir, suffix, session, log)
    _parse_hostnames(web_dir, session, log)
    _parse_cgi_sniper(web_dir, suffix, session, log)


def _parse_directory_scan(web_dir: Path, suffix: str, session, log) -> None:
    """
    Parse gobuster and feroxbuster output files.
    Extracts 200/301 paths and stores them in session.info.web_paths.
    """
    paths: set = set()

    for fname in (f"gobuster{suffix}.txt", f"feroxbuster{suffix}.txt"):
        fpath = web_dir / fname
        if not fpath.exists() or fpath.stat().st_size == 0:
            continue

        for line in fpath.read_text(errors="ignore").splitlines():
            # Gobuster format:  /path  (Status: 200)  [Size: 1234]
            m_gb = re.match(r'^(/\S+)\s+\(Status:\s*(200|301|302)', line)
            if m_gb:
                paths.add(m_gb.group(1))
                continue

            # Feroxbuster format: 200  GET  1234l  56w  8900c  http://host/path
            m_fx = re.search(r'\s(https?://\S+)', line)
            if m_fx and re.match(r'^(200|301|302)\s', line):
                url = m_fx.group(1).rstrip("/")
                # Strip to path component only
                m_path = re.search(r'https?://[^/]+(/.*)$', url)
                if m_path:
                    paths.add(m_path.group(1))

        # Flag sensitive file extensions
        sensitive = [
            p for p in paths
            if re.search(r'\.(bak|old|zip|tar\.gz|sql|conf|env|ini|log|swp)$', p, re.IGNORECASE)
        ]
        if sensitive:
            log.warning("Sensitive files in web scan: %s", sensitive)
            for s in sensitive:
                session.add_note(f"SENSITIVE FILE: {s}")

    if paths:
        new_paths = [p for p in sorted(paths) if p not in session.info.web_paths]
        session.info.web_paths.extend(new_paths)
        log.info("Web paths discovered (%s): %d total", suffix or "port 80/443", len(paths))


def _parse_whatweb(web_dir: Path, suffix: str, session, log) -> None:
    """Extract tech stack info from whatweb output and store as notes."""
    whatweb_file = web_dir / f"whatweb{suffix}.txt"
    if not whatweb_file.exists() or whatweb_file.stat().st_size == 0:
        return

    content = whatweb_file.read_text(errors="ignore")

    # Look for CMS indicators
    cms_patterns = {
        "WordPress": r'WordPress',
        "Joomla":    r'Joomla',
        "Drupal":    r'Drupal',
    }
    for cms, pattern in cms_patterns.items():
        if re.search(pattern, content, re.IGNORECASE):
            note = f"CMS detected: {cms} (port{suffix or ' 80/443'})"
            if note not in session.info.notes:
                session.add_note(note)
                log.info("CMS detected: %s", cms)

    # Extract server/framework info (first line summary)
    first_line = content.splitlines()[0] if content.strip() else ""
    if first_line:
        session.add_note(f"WhatWeb{suffix}: {first_line[:120]}")


def _parse_hostnames(web_dir: Path, session, log) -> None:
    """Pick up any new hostnames discovered during redirect detection."""
    hostname_file = web_dir / "discovered_hostnames.txt"
    if not hostname_file.exists():
        return

    for line in hostname_file.read_text(errors="ignore").splitlines():
        hostname = line.strip()
        if hostname and hostname not in session.info.domains_found:
            session.info.domains_found.append(hostname)
            log.info("Hostname discovered via redirect: %s", hostname)
            session.add_note(
                f"Hostname via redirect: {hostname} — add to /etc/hosts if needed"
            )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_cgi_sniper(web_dir: Path, suffix: str, session, log) -> None:
    """
    Parse dynamic_cgi_sniper<suffix>.txt written by web_enum.sh step 6.

    Any line containing a URL that resolves to a .cgi / .sh / .pl script
    (status 200 only — the bash side already filters for that) is extracted
    and added to session.info.cgi_scripts_found.

    finalize_notes() will generate a ready-to-run Shellshock exploitation
    template for each unique URL found here.

    Feroxbuster output format (common variants):
        200      GET      ...  http://host/path/script.cgi
        200 GET  ...           http://host/cgi-bin/vuln.sh
    We match on any line that contains an http(s) URL ending in a script ext.
    """
    sniper_file = web_dir / f"dynamic_cgi_sniper{suffix}.txt"
    if not sniper_file.exists() or sniper_file.stat().st_size == 0:
        return

    newly_found: List[str] = []
    for line in sniper_file.read_text(errors="ignore").splitlines():
        m = re.search(r'https?://\S+\.(?:cgi|sh|pl)\b', line, re.IGNORECASE)
        if not m:
            continue
        url = m.group(0).rstrip('/?')
        if url not in session.info.cgi_scripts_found:
            session.info.cgi_scripts_found.append(url)
            newly_found.append(url)
            log.warning("CGI script discovered by sniper: %s", url)
            session.add_note(f"⚠️  CGI script found: {url}")

    if newly_found:
        log.warning(
            "CGI sniper total for port%s: %d script(s) — Shellshock template added to notes.md",
            suffix or " 80/443",
            len(session.info.cgi_scripts_found),
        )


def _kill_proc_group(proc: Optional[subprocess.Popen], log) -> None:
    """
    Terminate a Popen process and its entire process group.

    Because the wrapper is launched with start_new_session=True, the bash
    script and every child it spawned (nmap, feroxbuster, gobuster …) share
    one process group ID.  os.killpg() reaches all of them in one call,
    preventing orphaned background processes from consuming RAM.

    Falls back to proc.terminate() on Windows (no killpg) or if the process
    group is gone by the time we try.
    """
    if proc is None or proc.poll() is not None:
        return  # already exited — nothing to do

    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGTERM)
        log.info("Sent SIGTERM to process group %d", pgid)
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        # Still running after 5 s — escalate to SIGKILL
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGKILL)
            log.warning("Process group %d did not exit cleanly — SIGKILL sent", pgid)
        except (ProcessLookupError, PermissionError):
            pass  # process group already gone
        proc.wait()
    except (ProcessLookupError, PermissionError, AttributeError):
        # Windows, or process already exited between poll() and getpgid()
        proc.terminate()
