"""
modules/web.py — Web enumeration module

Calls wrappers/web_enum.sh once per detected web port, then parses
gobuster/feroxbuster output to populate session.info.web_paths.

Port → protocol detection:
  443, 8443, 9443 → https
  Everything else → http (unless deep scan banner says ssl/https)
"""

import re
import shutil
from pathlib import Path
from typing import List, Optional, Tuple

from rich.console import Console

from core.runner import run_wrapper

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
        console.print(f"  [bold yellow][CMD][/bold yellow] {display}")

        cms: Optional[str] = None
        try:
            run_wrapper(cmd, session, label=f"web_enum.sh port {port}", dry_run=dry_run)
            if not dry_run:
                cms = _parse_web_output(port, session, log)

        except KeyboardInterrupt:
            # run_wrapper already sent SIGTERM/SIGKILL to the process group
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

        # CMS router — runs OUTSIDE the port-abort block so Ctrl+C during
        # the CMS scan is handled by _run_cms_scanner() internally and does
        # NOT falsely mark this port as skipped.
        if cms and not dry_run:
            _run_cms_scanner(port, proto, target, cms, session, log, dry_run)

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

def _parse_web_output(port: int, session, log) -> Optional[str]:
    """Parse gobuster, feroxbuster, whatweb, and CGI sniper output for a given port.

    Returns the first CMS name detected by whatweb (e.g. "WordPress"), or None.
    The caller uses this to decide whether to invoke the CMS-specific scanner.
    """
    suffix = "" if port in {80, 443} else f"_port{port}"
    web_dir = session.target_dir / "web"

    _parse_quick_fingerprint(web_dir, suffix, port, session, log)
    _parse_directory_scan(web_dir, suffix, session, log)
    cms = _parse_whatweb(web_dir, suffix, session, log)
    _parse_hostnames(web_dir, session, log)
    _parse_vhost_scan(web_dir, suffix, session, log)
    _parse_sslscan(web_dir, suffix, session, log)
    _parse_cgi_sniper(web_dir, suffix, session, log)
    _parse_download_files(web_dir, suffix, session, log)
    return cms


def _parse_quick_fingerprint(web_dir: Path, suffix: str, port: int, session, log) -> None:
    """
    Parse quick_fingerprint<suffix>.txt written by web_enum.sh step 0.

    This file is written in the first ~3 seconds of the wrapper (before any
    long-running tool), so it contains server identification even when the
    user Ctrl+C's the full scan early.

    Extracts Server, X-Powered-By headers and any APP_HINT lines written
    by the bash fingerprint block and records them as notes.
    """
    fp_file = web_dir / f"quick_fingerprint{suffix}.txt"
    if not fp_file.exists() or fp_file.stat().st_size == 0:
        return

    content = fp_file.read_text(errors="ignore")
    port_label = str(port)

    # Server header
    m_srv = re.search(r'^Server:\s*(.+)$', content, re.IGNORECASE | re.MULTILINE)
    if m_srv:
        server = m_srv.group(1).strip()
        note = f"Web server on port {port_label}: {server}"
        if note not in session.info.notes:
            session.add_note(note)
            log.info("Quick fingerprint port %s: Server=%s", port_label, server)

    # X-Powered-By header
    m_xpb = re.search(r'^X-Powered-By:\s*(.+)$', content, re.IGNORECASE | re.MULTILINE)
    if m_xpb:
        powered = m_xpb.group(1).strip()
        note = f"Web powered-by on port {port_label}: {powered}"
        if note not in session.info.notes:
            session.add_note(note)
            log.info("Quick fingerprint port %s: X-Powered-By=%s", port_label, powered)

    # App hint written by bash (e.g. "APP_HINT=tomcat")
    _APP_HINTS = {
        "tomcat":   ("HIGH", "Apache Tomcat on port {p} — check /manager/html for default creds",
                     "curl -sv http://{ip}:{p}/manager/html  # try tomcat:tomcat, admin:s3cret"),
        "jenkins":  ("HIGH", "Jenkins on port {p} — check /login for default creds",
                     "curl -sv http://{ip}:{p}/login  # default: admin:admin"),
        "jboss":    ("HIGH", "JBoss/WildFly on port {p} — check /jmx-console",
                     "curl -sv http://{ip}:{p}/jmx-console"),
        "weblogic": ("HIGH", "WebLogic on port {p} — check /console for default creds",
                     "curl -sv http://{ip}:{p}/console"),
        "glassfish":("HIGH", "GlassFish on port {p} — check admin console",
                     "curl -sv http://{ip}:{p}/common/logon/logon.jsf"),
    }
    m_hint = re.search(r'^APP_HINT=(\w+)$', content, re.MULTILINE)
    if m_hint:
        app_key = m_hint.group(1).lower()
        if app_key in _APP_HINTS:
            sev, desc_tmpl, cmd_tmpl = _APP_HINTS[app_key]
            ip = session.info.ip
            desc = desc_tmpl.format(p=port_label)
            cmd  = cmd_tmpl.format(ip=ip, p=port_label)
            note = f"{sev}: {desc}"
            if note not in session.info.notes:
                session.add_note(note)
                session.add_note(f"[MANUAL] {desc}: {cmd}")
                log.warning("Quick fingerprint detected %s on port %s", app_key, port_label)


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

        # Flag high-value paths that often contain credentials or admin interfaces
        _HIGH_VALUE = re.compile(
            r'/(backup[s_-]?|\.git|\.svn|phpinfo|config|setup|install|admin'
            r'|phpmyadmin|manager|console|dashboard|wp-admin|xmlrpc'
            r'|\.env|\.htpasswd|web\.config|passwd|shadow'
            r'|backup_migrate|cron\.php|update\.php'
            r'|download[s]?|upload[s]?)',
            re.IGNORECASE,
        )
        for p in paths:
            if _HIGH_VALUE.search(p):
                note = f"HIGH-VALUE PATH: {p}"
                if note not in session.info.notes:
                    session.add_note(note)
                    log.warning("High-value web path found: %s", p)

        # README/LICENSE files often reveal the CMS or framework version
        _INFO_FILES = re.compile(
            r'/(README|LICENSE|CHANGELOG|VERSION|INSTALL|COPYING)(\.txt|\.md|\.html|$)',
            re.IGNORECASE,
        )
        ip = session.info.ip
        port_int = int(suffix.lstrip("_port")) if suffix and suffix.lstrip("_port").isdigit() else 80
        proto = "https" if port_int in {443, 8443, 9443, 4443} else "http"
        base = f"{proto}://{ip}" if port_int in {80, 443} else f"{proto}://{ip}:{port_int}"
        for p in paths:
            if _INFO_FILES.search(p):
                note = f"[MANUAL] Inspect info file (may reveal CMS/framework version): curl -s '{base}{p}' | head -20"
                if note not in session.info.notes:
                    session.add_note(note)
                    log.info("Info file found at %s — may reveal CMS version", p)

    if paths:
        new_paths = [p for p in sorted(paths) if p not in session.info.web_paths]
        session.info.web_paths.extend(new_paths)
        log.info("Web paths discovered (%s): %d total", suffix or "port 80/443", len(paths))


def _parse_whatweb(web_dir: Path, suffix: str, session, log) -> Optional[str]:
    """Extract tech stack info from whatweb output and store as notes.

    Returns the first CMS name matched (e.g. "WordPress"), or None.
    Priority order: WordPress > Drupal > Joomla (most OSCP-common first).
    """
    whatweb_file = web_dir / f"whatweb{suffix}.txt"
    if not whatweb_file.exists() or whatweb_file.stat().st_size == 0:
        return None

    content = whatweb_file.read_text(errors="ignore")

    # CMS patterns in priority order — first match wins and is returned to
    # the caller for routing; all matches are noted regardless.
    cms_patterns = {
        "WordPress": r'WordPress',
        "Drupal":    r'Drupal',
        "Joomla":    r'Joomla',
    }
    detected: Optional[str] = None
    for cms, pattern in cms_patterns.items():
        if re.search(pattern, content, re.IGNORECASE):
            note = f"CMS detected: {cms} (port{suffix or ' 80/443'})"
            if note not in session.info.notes:
                session.add_note(note)
                log.info("CMS detected: %s", cms)
            if detected is None:
                detected = cms

    # Extract server/framework info (first line summary)
    first_line = content.splitlines()[0] if content.strip() else ""
    if first_line:
        session.add_note(f"WhatWeb{suffix}: {first_line[:120]}")

    # Apache version detection — extract and flag potentially old versions
    apache_m = re.search(r'Apache[/\[\s]+([\d]+\.[\d]+\.?[\d]*)', content, re.IGNORECASE)
    if apache_m:
        version_str = apache_m.group(1)
        try:
            parts = [int(x) for x in version_str.split(".")]
            major, minor = parts[0], parts[1] if len(parts) > 1 else 0
            patch = parts[2] if len(parts) > 2 else 0
            port_label = "443" if suffix == "" else suffix.lstrip("_port")
            if major < 2 or (major == 2 and minor < 4):
                log.warning("Old Apache version detected: %s (port %s)", version_str, port_label)
                session.add_note(
                    f"HIGH: Apache {version_str} on port {port_label} — "
                    f"EOL/old version, check: searchsploit apache {version_str}"
                )
            elif major == 2 and minor == 4 and patch < 30:
                # 2.4.0–2.4.29: many public CVEs, released before 2017 security era
                log.warning(
                    "Old Apache 2.4.x detected: %s (port %s) — "
                    "released pre-2017, many known CVEs",
                    version_str, port_label,
                )
                session.add_note(
                    f"HIGH: Apache {version_str} on port {port_label} — "
                    f"old release (pre-2017), check: searchsploit apache {version_str}"
                )
            elif major == 2 and minor == 4 and patch < 50:
                log.info("Potentially outdated Apache 2.4.x: %s (port %s)", version_str, port_label)
                session.add_note(
                    f"INFO: Apache {version_str} on port {port_label} — "
                    f"verify if patched: searchsploit apache {version_str}"
                )
            else:
                log.info("Apache %s detected on port %s", version_str, port_label)
        except (ValueError, IndexError):
            pass

    # nginx version detection
    nginx_m = re.search(r'nginx[/\[\s]+([\d]+\.[\d]+\.?[\d]*)', content, re.IGNORECASE)
    if nginx_m:
        version_str = nginx_m.group(1)
        port_label = "443" if suffix == "" else suffix.lstrip("_port")
        log.info("nginx %s detected on port %s", version_str, port_label)
        session.add_note(f"INFO: nginx {version_str} on port {port_label}")

    return detected


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


def _parse_vhost_scan(web_dir: Path, suffix: str, session, log) -> None:
    """
    Parse ffuf and gobuster vhost scan output for new virtual hostname
    discoveries.  Handles both tool output formats and de-duplicates against
    session.info.domains_found.

    ffuf text output (via -s / silent mode):
        admin.corp.local [Status: 200, Size: 4096, Words: 231, Lines: 47]

    gobuster vhost output:
        Found: admin.corp.local (Status: 200) [Size: 4096]

    Any newly discovered hostname is added to session.info.domains_found and
    noted with an /etc/hosts reminder so the operator acts on it immediately.
    """
    new_hosts: List[str] = []

    # Check both possible output files — ffuf preferred, gobuster fallback
    for fname in (f"ffuf_vhost{suffix}.txt", f"vhosts{suffix}.txt"):
        fpath = web_dir / fname
        if not fpath.exists() or fpath.stat().st_size == 0:
            continue

        for line in fpath.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # ffuf silent output:  "subdomain.domain.tld [Status: NNN, ...]"
            # gobuster vhost:      "Found: subdomain.domain.tld (Status: NNN)"
            m = re.search(
                r'^(?:Found:\s+)?([A-Za-z0-9][A-Za-z0-9\-\.]+\.[A-Za-z]{2,})'
                r'\s+[\[\(](?:Status:)?\s*\d{3}',
                line, re.IGNORECASE,
            )
            if not m:
                continue

            host = m.group(1).strip().lower()
            # Skip bare IPs
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
                continue
            if host not in session.info.domains_found:
                session.info.domains_found.append(host)
                new_hosts.append(host)
                log.info("VHost discovered: %s", host)

    for host in new_hosts:
        session.add_note(
            f"🌐 VHost discovered: {host} — "
            f"add to /etc/hosts and re-enumerate: "
            f"echo '{session.info.ip}  {host}' | sudo tee -a /etc/hosts"
        )

    if new_hosts:
        log.info(
            "VHost scan found %d new hostname(s): %s",
            len(new_hosts), new_hosts,
        )


def _parse_sslscan(web_dir: Path, suffix: str, session, log) -> None:
    """
    Parse sslscan --no-colour output for critical TLS weaknesses.

    Severity tiers:
      ⚠️  CRITICAL  — Heartbleed, SSLv2 (active exploit potential)
      ⚠️  HIGH      — SSLv3/POODLE, EXPORT ciphers (FREAK/LOGJAM)
      ℹ️  INFO       — TLSv1.0, RC4, self-signed cert, expiry

    Each unique finding is added to session.info.notes exactly once.
    Heartbleed is promoted to log.warning() so it appears in the console
    output immediately rather than only in notes.md.
    """
    sslscan_file = web_dir / f"sslscan{suffix}.txt"
    if not sslscan_file.exists() or sslscan_file.stat().st_size == 0:
        return

    content    = sslscan_file.read_text(errors="ignore")
    port_label = "443" if suffix == "" else suffix.lstrip("_port")

    # Ordered by severity — first match wins the log level
    _CHECKS: List[Tuple[str, str, str]] = [
        # (regex pattern, note text, log level: "warn" | "info")
        (
            r'Heartbleed.*?vulnerable|vulnerable.*?Heartbleed',
            f"⚠️  HEARTBLEED (CVE-2014-0160) on port {port_label} — "
            f"memory leak; private keys and credentials may be extractable",
            "warn",
        ),
        (
            r'SSLv2\s+enabled|SSLv2.*?Enabled',
            f"⚠️  SSLv2 enabled on port {port_label} — "
            f"deprecated since 1996; multiple published exploits",
            "warn",
        ),
        (
            r'SSLv3\s+enabled|SSLv3.*?Enabled',
            f"⚠️  SSLv3 enabled on port {port_label} — "
            f"POODLE (CVE-2014-3566); CBC padding oracle attack",
            "warn",
        ),
        (
            r'EXP-[A-Z0-9\-]+\s+Accepted|EXPORT.*?cipher|cipher.*?EXPORT',
            f"⚠️  EXPORT cipher suites accepted on port {port_label} — "
            f"FREAK (CVE-2015-0204) / LOGJAM (CVE-2015-4000) attack surface",
            "warn",
        ),
        (
            r'TLSv1\.0\s+enabled|TLSv1\.0.*?Enabled',
            f"ℹ️   TLSv1.0 enabled on port {port_label} — "
            f"BEAST overlap; best-practice is to disable",
            "info",
        ),
        (
            r'RC4.*?Accepted|Accepted.*?RC4',
            f"ℹ️   RC4 cipher(s) accepted on port {port_label} — "
            f"statistically weak; biased keystream attacks",
            "info",
        ),
    ]

    for pattern, note_text, level in _CHECKS:
        if re.search(pattern, content, re.IGNORECASE):
            if note_text not in session.info.notes:
                session.add_note(note_text)
                if level == "warn":
                    log.warning("sslscan: %s", note_text)
                else:
                    log.info("sslscan: %s", note_text)

    # Certificate status — informational only
    if re.search(r'self.?signed|Self.?Signed', content, re.IGNORECASE):
        note = f"ℹ️   TLS cert on port {port_label}: self-signed (no CA validation)"
        if note not in session.info.notes:
            session.add_note(note)

    # Expired cert — flag for credential/session reuse scenarios
    if re.search(r'Not valid after.*?20[01]\d', content, re.IGNORECASE):
        note = f"ℹ️   TLS cert on port {port_label}: may be expired — verify dates"
        if note not in session.info.notes:
            session.add_note(note)

    log.info("sslscan output parsed for port%s", suffix or " 443")


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


# ---------------------------------------------------------------------------
# Download / large file detection
# ---------------------------------------------------------------------------

def _parse_download_files(web_dir: Path, suffix: str, session, log) -> None:
    """
    Scan gobuster/feroxbuster output for paths that look like downloadable files
    with no extension (e.g. /files/backup, /download/dump) or non-HTML binary
    extensions (.bin, .img, .iso, .db, .sqlite, .dump, .tar, .tar.gz, .7z).

    For each match: add a manual wget + analysis command to notes so the
    operator can inspect the file contents offline.
    No automatic download is performed.
    """
    # Patterns that strongly suggest a binary/archive download worth inspecting
    _DOWNLOAD_NAMES = re.compile(
        r'/(backup|download|dump|export|loot|migrate|db|database|archive|snapshot'
        r'|data|files?|documents?|uploads?)(?:/|$)',
        re.IGNORECASE,
    )
    _DOWNLOAD_EXTS = re.compile(
        r'\.(bin|img|iso|db|sqlite|sqlite3|dump|tar|tar\.gz|tar\.bz2|tgz|7z'
        r'|dmp|bak|old|backup|mdb|accdb|csv|xml|json)$',
        re.IGNORECASE,
    )

    # Reconstruct base URL from session info
    port_label  = suffix.lstrip("_port") if suffix else "80"
    port_int    = int(port_label) if port_label.isdigit() else 80
    proto       = "https" if port_int in {443, 8443, 9443, 4443} else "http"
    base_url    = (
        f"{proto}://{session.info.ip}"
        if port_int in {80, 443}
        else f"{proto}://{session.info.ip}:{port_int}"
    )

    seen_dl: set = set()
    for fname in (f"gobuster{suffix}.txt", f"feroxbuster{suffix}.txt"):
        fpath = web_dir / fname
        if not fpath.exists() or fpath.stat().st_size == 0:
            continue

        for line in fpath.read_text(errors="ignore").splitlines():
            # Extract path from both gobuster and feroxbuster formats
            path: Optional[str] = None
            m_gb = re.match(r'^(/\S+)\s+\(Status:\s*200', line)
            if m_gb:
                path = m_gb.group(1).rstrip("/")
            else:
                m_fx = re.search(r'(https?://\S+)', line)
                if m_fx and re.match(r'^200\s', line):
                    m_p = re.search(r'https?://[^/]+(/.*)', m_fx.group(1))
                    if m_p:
                        path = m_p.group(1).rstrip("/")

            if not path or path in seen_dl:
                continue

            is_download = _DOWNLOAD_NAMES.search(path) or _DOWNLOAD_EXTS.search(path)
            if not is_download:
                continue

            seen_dl.add(path)
            url       = f"{base_url}{path}"
            filename  = Path(path).name or "loot_file"
            out_path  = f"/tmp/{filename}"

            log.warning("Potential download/loot file at: %s", url)
            session.add_note(f"DOWNLOAD FILE: {url}")
            session.add_note(
                f"[MANUAL] Download and inspect: "
                f"wget '{url}' -O {out_path} && "
                f"file {out_path} && "
                f"strings {out_path} | grep -iE 'pass|user|admin|secret|key|token' | head -20"
            )


# ---------------------------------------------------------------------------
# CMS Smart Router — triggered by _parse_whatweb() return value
# ---------------------------------------------------------------------------

# Maps CMS name → (binary name, command builder, output filename template,
#                   install hint)
_CMS_TOOL_MAP = {
    "WordPress": {
        "bin":     "wpscan",
        "cmd":     lambda url, out: [
            "wpscan", "--url", url, "--no-update",
            "--enumerate", "u,vp,vt,cb,dbe",
            "--output", str(out), "--format", "cli",
        ],
        "out":     "wpscan{suffix}.txt",
        "install": "gem install wpscan  OR  apt install wpscan",
    },
    "Drupal": {
        "bin":     "droopescan",
        "cmd":     lambda url, out: [
            "droopescan", "scan", "drupal", "-u", url,
        ],
        "out":     "droopescan{suffix}.txt",
        "install": "pip3 install droopescan",
    },
    "Joomla": {
        "bin":     "joomscan",
        "cmd":     lambda url, out: [
            "joomscan", "--url", url,
        ],
        "out":     "joomscan{suffix}.txt",
        "install": "apt install joomscan  OR  git clone https://github.com/OWASP/joomscan",
    },
}


def _run_cms_scanner(
    port: int,
    proto: str,
    target: str,
    cms: str,
    session,
    log,
    dry_run: bool,
) -> None:
    """
    Dispatch the appropriate CMS scanner for the detected platform.

    Design decisions
    ----------------
    - Called from run() OUTSIDE the per-port KeyboardInterrupt block so a
      Ctrl+C here does not mark the port as skipped in session state.
    - Handles its own KeyboardInterrupt internally — the scan is skipped but
      the session continues cleanly to the next port.
    - Gracefully degrades when the scanner binary is not installed: logs a
      warning and records a manual-follow-up note rather than erroring out.
    - Output is written to web/<tool><suffix>.txt, mirroring the existing
      naming convention for all other web module outputs.
    """
    spec = _CMS_TOOL_MAP.get(cms)
    if not spec:
        return

    console   = Console()
    tool      = spec["bin"]
    suffix    = "" if port in {80, 443} else f"_port{port}"
    web_dir   = session.target_dir / "web"
    base_url  = (
        f"{proto}://{target}"
        if port in {80, 443}
        else f"{proto}://{target}:{port}"
    )
    out_file  = web_dir / spec["out"].format(suffix=suffix)
    cmd       = spec["cmd"](base_url, out_file)

    console.print()
    console.print(
        f"  [bold cyan][CMS ROUTER][/bold cyan] "
        f"[bold]{cms}[/bold] detected on port [cyan]{port}[/cyan] "
        f"→ launching [bold]{tool}[/bold]"
    )

    # Graceful degradation — warn but never crash if tool is absent
    if not shutil.which(tool):
        log.warning(
            "CMS router: '%s' not in PATH — skipping %s scan (install: %s)",
            tool, cms, spec["install"],
        )
        console.print(
            f"  [bold yellow][!][/bold yellow] [yellow]{tool}[/yellow] not installed "
            f"— skipping {cms} scan.\n"
            f"  Install: [dim]{spec['install']}[/dim]"
        )
        session.add_note(
            f"⚠️  {cms} detected on port {port} but {tool} not found — "
            f"manual scan required. Install: {spec['install']}"
        )
        return

    display = " ".join(str(c) for c in cmd)
    console.print(f"  [bold yellow][CMD][/bold yellow] {display}")
    log.info("CMS router: %s on port %d → %s", cms, port, tool)

    if dry_run:
        return

    try:
        run_wrapper(cmd, session, label=f"{tool} port {port}", dry_run=False)
        if out_file.exists() and out_file.stat().st_size > 0:
            session.add_note(
                f"✅ {tool} completed for port {port} — see web/{out_file.name}"
            )
            _parse_cms_output(cms, out_file, session, log)
        else:
            log.warning("%s produced no output for port %d", tool, port)

    except KeyboardInterrupt:
        console.print(
            f"\n  [bold yellow][WARNING][/bold yellow] "
            f"{tool} scan on port [cyan]{port}[/cyan] skipped by user (Ctrl+C) "
            f"— continuing to next port."
        )
        log.warning("%s scan on port %d skipped by user (Ctrl+C)", tool, port)
        session.add_note(
            f"⚠️  {tool} scan on port {port} SKIPPED by user (Ctrl+C)"
        )


def _parse_cms_output(cms: str, out_file: Path, session, log) -> None:
    """
    Extract high-value findings from CMS scanner output.

    Parses just enough to surface actionable items into session notes:
    - WordPress: vulnerability lines, enumerated usernames
    - Drupal/Joomla: vulnerability/CVE references

    Full detail is always available in the output file itself.
    """
    content = out_file.read_text(errors="ignore")

    if cms == "WordPress":
        for line in content.splitlines():
            stripped = line.strip()
            # wpscan marks exploitable findings with [!]
            if re.search(r'\[!\]', stripped) and re.search(
                r'vulnerab|exploit|CVE-', stripped, re.IGNORECASE
            ):
                session.add_note(f"⚠️  WPScan: {stripped[:140]}")
                log.warning("WPScan finding: %s", stripped[:140])

            # Username enumeration results
            m = re.search(
                r'(?:Username|user)\s+found\s*:?\s+([A-Za-z0-9_\-\.]+)',
                stripped, re.IGNORECASE,
            )
            if m:
                user = m.group(1)
                if user not in session.info.users_found:
                    session.info.users_found.append(user)
                    log.info("WPScan user found: %s", user)
                    session.add_note(f"👤 WPScan user enumerated: {user}")

    else:
        # Drupal / Joomla — flag any vulnerability or CVE references
        for line in content.splitlines():
            stripped = line.strip()
            if re.search(r'vulnerab|CVE-\d{4}-\d+|exploit', stripped, re.IGNORECASE):
                session.add_note(f"⚠️  {cms} scanner: {stripped[:140]}")
                log.warning("%s scanner finding: %s", cms, stripped[:140])
