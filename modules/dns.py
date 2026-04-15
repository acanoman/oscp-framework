"""
modules/dns.py — DNS enumeration module

Routes to wrappers/services_enum.sh (port 53) for zone-transfer attempts,
DNS version probing, and subdomain enumeration hints.
After the wrapper runs, parses output and injects [MANUAL] hints into
session notes so they appear in notes.md.

Also runs dig AXFR directly for a full zone transfer attempt and parses
discovered hostnames into session.info.domains_found.

OSCP compliance:
  - Passive queries + AXFR attempt only
  - NO DNS brute-force / zone-walking automation
  - Subdomain wordlist attacks → hint only
"""

import re
import shutil
import subprocess
from pathlib import Path

from core.display import info, success, warn
from core.runner import run_wrapper

WRAPPERS_DIR = Path(__file__).resolve().parent.parent / "wrappers"

# Ports this module owns
_DNS_PORTS = {
    53,    # DNS (UDP + TCP)
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(target: str, session, dry_run: bool = False) -> None:
    log    = session.log
    domain = session.info.domain or target

    open_dns = session.info.open_ports & _DNS_PORTS
    if not open_dns:
        log.info("No DNS ports open — skipping dns module.")
        return

    log.info("DNS port open — beginning enumeration against %s", target)

    # Inject MANUAL hints immediately — visible even if wrapper is interrupted
    _add_manual_hints(session, domain)

    script = WRAPPERS_DIR / "services_enum.sh"
    if not script.exists():
        log.error("Wrapper not found: %s", script)
        return

    ports_csv = ",".join(str(p) for p in sorted(open_dns))
    cmd = [
        "bash", str(script),
        "--target",     target,
        "--output-dir", str(session.target_dir),
        "--ports",      ports_csv,
    ]

    run_wrapper(cmd, session, label="services_enum.sh (dns)", dry_run=dry_run)

    if dry_run:
        return

    _parse_dns(session, log, domain)

    # Run dig AXFR directly for a comprehensive zone transfer attempt
    _run_axfr_dig(target, session, log, domain)

    log.info("DNS module complete.")


# ---------------------------------------------------------------------------
# MANUAL hints — written to notes.md regardless of what the wrapper finds
# ---------------------------------------------------------------------------

def _add_manual_hints(session, domain: str) -> None:
    ip = session.info.ip

    hints = [
        (
            f"dig axfr @{ip} {domain}",
            "Zone transfer attempt (AXFR)",
        ),
        (
            f"host -l {domain} {ip}",
            "Zone transfer attempt (host)",
        ),
        (
            f"dig -x {ip} @{ip}",
            "Reverse lookup",
        ),
        (
            f"dig any {domain} @{ip}",
            "ANY record query",
        ),
        (
            f"nmap -p 53 --script dns-nsid,dns-recursion,dns-zone-transfer {ip}",
            "DNS version probe",
        ),
        (
            f"gobuster dns -d {domain} -r {ip}:53 "
            f"-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
            "Subdomain brute-force",
        ),
    ]

    for cmd, ctx in hints:
        session.add_note(f"💡 [MANUAL] {ctx}: {cmd}")
        session.add_manual_command(cmd, ctx)


# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------

def _parse_dns(session, log, domain: str) -> None:
    dns_dir = session.target_dir / "dns"
    dns_f   = dns_dir / "dns_nmap.txt"
    if not dns_f.exists():
        dns_f = session.target_dir / "services" / "dns_nmap.txt"
    if not dns_f.exists():
        return

    content = dns_f.read_text(errors="ignore")

    # Zone transfer success
    if re.search(r"dns-zone-transfer:|Transfer failed", content, re.IGNORECASE):
        if re.search(r"dns-zone-transfer:.*\|", content, re.DOTALL):
            log.warning("DNS: zone transfer may have succeeded — review %s", dns_f)
            session.add_note(
                f"🚨 DNS FINDING: Zone transfer data present — review {dns_f}"
            )
        else:
            log.info("DNS: zone transfer denied (expected for hardened servers)")

    # Recursion allowed
    if re.search(r"dns-recursion.*Recursion appears to be enabled", content, re.IGNORECASE):
        log.warning("DNS: open recursion enabled")
        session.add_note("⚠️  DNS: Open recursion enabled — potential for amplification")

    # NSID (server identity)
    nsid = re.search(r"dns-nsid:\s*\n(\|.+)", content)
    if nsid:
        log.info("DNS NSID: %s", nsid.group(1).strip())
        session.add_note(f"DNS NSID: {nsid.group(1).strip()}")

    # Hostnames found
    hostnames = re.findall(r"\b([a-z0-9._-]+\." + re.escape(domain) + r")\b", content, re.IGNORECASE)
    if hostnames:
        unique = sorted(set(hostnames))
        log.info("DNS hostnames found: %s", unique)
        session.add_note(f"DNS hostnames discovered: {unique}")


# ---------------------------------------------------------------------------
# AXFR via dig — direct subprocess, no bash wrapper needed
# ---------------------------------------------------------------------------

def _run_axfr_dig(target: str, session, log, domain: str) -> None:
    """
    Attempt a full zone transfer (AXFR) using dig and save the raw output.

    Unlike the nmap NSE zone-transfer script, dig returns the complete zone
    in standard BIND format which is easier to parse for hostnames and IPs.
    Both the supplied domain and the bare target IP are attempted as the zone
    name so the transfer works even when the domain is unknown.

    Output is written to <target_dir>/dns/axfr_dig.txt for manual review.
    Discovered hostnames are added to session.info.domains_found.
    """
    if not shutil.which("dig"):
        log.info("dig not found — skipping AXFR")
        return

    ip = session.info.ip
    dns_dir = session.target_dir / "dns"
    dns_dir.mkdir(parents=True, exist_ok=True)
    axfr_file = dns_dir / "axfr_dig.txt"

    zones_to_try = [domain] if domain and domain != target else []
    # Always try reverse lookup zone (in-addr.arpa) and bare IP as fallback
    octets = ip.split(".")
    if len(octets) == 4:
        zones_to_try.append(".".join(reversed(octets[:-1])) + ".in-addr.arpa")

    found_any = False
    with axfr_file.open("w", encoding="utf-8") as fh:
        for zone in zones_to_try:
            cmd = ["dig", f"@{ip}", zone, "AXFR", "+time=5", "+tries=1"]
            info(f"> {' '.join(cmd)}")
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                output = result.stdout or ""
                fh.write(f"# AXFR attempt: dig @{ip} {zone} AXFR\n")
                fh.write(output)
                fh.write("\n")

                if _axfr_succeeded(output):
                    found_any = True
                    hostnames = _parse_axfr_output(output, domain)
                    if hostnames:
                        for h in hostnames:
                            if h not in session.info.domains_found:
                                session.info.domains_found.append(h)
                        log.warning(
                            "AXFR zone transfer succeeded for %s — %d hostnames",
                            zone, len(hostnames),
                        )
                        session.add_note(
                            f"🚨 HIGH: AXFR zone transfer succeeded for {zone} — "
                            f"hostnames: {hostnames[:10]}"
                        )
                        session.add_note(
                            f"💡 Add all discovered hostnames to /etc/hosts: "
                            f"cat {axfr_file} | grep -v '^;' | awk '{{print $1}}'"
                        )
                        session.add_manual_command(
                            f"dig @{ip} {zone} AXFR | grep -v '^;' | awk '{{print $1}}'",
                            f"Extract all hostnames from AXFR zone transfer ({zone})",
                        )
                else:
                    log.info("AXFR denied for zone %s (expected for hardened servers)", zone)
            except subprocess.TimeoutExpired:
                log.info("AXFR timed out for zone %s", zone)
                fh.write(f"# AXFR timed out for {zone}\n\n")
            except FileNotFoundError:
                log.info("dig not available — skipping AXFR")
                return

    if found_any:
        success(f"AXFR zone transfer succeeded — results in {axfr_file}")
    else:
        log.info("AXFR zone transfer denied for all attempted zones (normal for hardened servers)")


def _axfr_succeeded(output: str) -> bool:
    """Return True if dig AXFR output contains actual zone records (not just SOA errors)."""
    lines = [l for l in output.splitlines() if l.strip() and not l.startswith(";")]
    # A successful AXFR has at least SOA + one other record
    return len(lines) >= 2 and "XFR size" not in output or bool(
        re.search(r'\s+IN\s+(?:A|AAAA|CNAME|MX|NS|PTR|TXT|SRV)\s+', output)
    )


def _parse_axfr_output(output: str, domain: str) -> list:
    """Extract hostnames from dig AXFR output (standard BIND zone format)."""
    hostnames = []
    seen = set()
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        # Standard zone record format: <name> [<ttl>] IN <type> <rdata>
        m = re.match(r'^([A-Za-z0-9][A-Za-z0-9._-]*)\s+', line)
        if not m:
            continue
        name = m.group(1).rstrip(".")
        # Only keep FQDNs that look like hostnames (not bare @ or numbers)
        if "." in name and not re.match(r'^\d+$', name.split(".")[0]):
            if name not in seen:
                seen.add(name)
                hostnames.append(name)
    return hostnames


