"""
modules/dns.py — DNS enumeration module

Routes to wrappers/services_enum.sh (port 53) for zone-transfer attempts,
DNS version probing, and subdomain enumeration hints.
After the wrapper runs, parses output and injects [MANUAL] hints into
session notes so they appear in notes.md.

OSCP compliance:
  - Passive queries + AXFR attempt only
  - NO DNS brute-force / zone-walking automation
  - Subdomain wordlist attacks → hint only
"""

import re
from pathlib import Path

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

    log.info("DNS module complete.")


# ---------------------------------------------------------------------------
# MANUAL hints — written to notes.md regardless of what the wrapper finds
# ---------------------------------------------------------------------------

def _add_manual_hints(session, domain: str) -> None:
    ip = session.info.ip

    session.add_note(
        f"💡 [MANUAL] Zone transfer: dig axfr @{ip} {domain}"
    )
    session.add_note(
        f"💡 [MANUAL] Zone transfer (host): host -l {domain} {ip}"
    )
    session.add_note(
        f"💡 [MANUAL] Reverse lookup: dig -x {ip} @{ip}"
    )
    session.add_note(
        f"💡 [MANUAL] ANY record query: dig any {domain} @{ip}"
    )
    session.add_note(
        f"💡 [MANUAL] DNS version probe: "
        f"nmap -p 53 --script dns-nsid,dns-recursion,dns-zone-transfer {ip}"
    )
    session.add_note(
        f"💡 [MANUAL] Subdomain brute-force: "
        f"gobuster dns -d {domain} -r {ip}:53 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
    )


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


