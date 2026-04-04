"""
modules/remote.py — Remote access enumeration module

Routes to wrappers/remote_enum.sh for RDP (3389) and WinRM (5985/5986).
After the wrapper runs, parses output and injects [MANUAL] hints into
session notes so they appear in notes.md.

OSCP compliance:
  - NSE scripts + passive curl probe only
  - NO automatic login (evil-winrm, xfreerdp)
  - No brute force of any kind
"""

import re
from pathlib import Path

from core.runner import run_wrapper

WRAPPERS_DIR = Path(__file__).resolve().parent.parent / "wrappers"

# Ports this module owns
_REMOTE_PORTS = {
    3389,   # RDP
    5985,   # WinRM HTTP
    5986,   # WinRM HTTPS
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(target: str, session, dry_run: bool = False) -> None:
    log = session.log

    open_remote = session.info.open_ports & _REMOTE_PORTS
    if not open_remote:
        log.info("No remote-access ports open — skipping remote module.")
        return

    log.info("Remote access ports to enumerate: %s", sorted(open_remote))

    # Inject MANUAL hints immediately
    _add_manual_hints(session, open_remote)

    script = WRAPPERS_DIR / "remote_enum.sh"
    if not script.exists():
        log.error("Wrapper not found: %s", script)
        return

    ports_csv = ",".join(str(p) for p in sorted(open_remote))
    cmd = [
        "bash", str(script),
        "--target",     target,
        "--output-dir", str(session.target_dir),
        "--ports",      ports_csv,
    ]

    run_wrapper(cmd, session, label="remote_enum.sh", dry_run=dry_run)

    if dry_run:
        return

    _parse_rdp(session, log)
    _parse_winrm(session, log)

    log.info("Remote module complete.")


# ---------------------------------------------------------------------------
# MANUAL hints
# ---------------------------------------------------------------------------

def _add_manual_hints(session, open_remote: set) -> None:
    ip = session.info.ip

    if 3389 in open_remote:
        session.add_note(
            f"💡 [MANUAL] RDP connection: "
            f"xfreerdp /u:USER /p:PASS /v:{ip} /cert-ignore +clipboard"
        )
        session.add_note(
            f"💡 [MANUAL] RDP Pass-the-Hash: "
            f"xfreerdp /u:USER /pth:NTLM_HASH /v:{ip} /cert-ignore"
        )

    if 5985 in open_remote:
        session.add_note(
            f"💡 [MANUAL] WinRM shell (HTTP): evil-winrm -i {ip} -u USER -p PASS"
        )
        session.add_note(
            f"💡 [MANUAL] WinRM Pass-the-Hash: evil-winrm -i {ip} -u USER -H NTLM_HASH"
        )

    if 5986 in open_remote:
        session.add_note(
            f"💡 [MANUAL] WinRM shell (HTTPS): evil-winrm -i {ip} -u USER -p PASS -S"
        )


# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------

def _parse_rdp(session, log) -> None:
    rdp_f = session.target_dir / "remote" / "rdp_nmap.txt"
    if not rdp_f.exists():
        return

    content = rdp_f.read_text(errors="ignore")

    # NLA enforcement
    if re.search(r"NLA.*True|CredSSP.*True", content, re.IGNORECASE):
        log.info("RDP: NLA enforced — pre-auth attack surface limited")
        session.add_note("RDP: NLA (Network Level Auth) is enforced")
    else:
        log.warning("RDP: NLA may NOT be enforced — check for pre-auth vulnerabilities")
        session.add_note(
            "⚠️  RDP: NLA not confirmed — potential pre-auth exposure (BlueKeep era)"
        )

    # MS12-020 (DoS — informational only)
    if re.search(r"ms12-020.*VULNERABLE|rdp-vuln-ms12-020.*VULNERABLE", content, re.IGNORECASE):
        log.warning("RDP: MS12-020 VULNERABLE")
        session.add_note(f"🚨 RDP: MS12-020 vulnerability found — review {rdp_f}")

    # Extract RDP version / build
    ver_f = session.target_dir / "remote" / "rdp_version.txt"
    if ver_f.exists():
        ver_content = ver_f.read_text(errors="ignore")
        ver = re.search(r"Microsoft Terminal Services.*|Windows.*Remote", ver_content)
        if ver:
            log.info("RDP version: %s", ver.group(0).strip())


def _parse_winrm(session, log) -> None:
    winrm_f = session.target_dir / "remote" / "winrm_nmap.txt"
    if not winrm_f.exists():
        return

    content = winrm_f.read_text(errors="ignore")

    # Confirm service is alive
    if re.search(r"HTTP/1\.1 405|HTTP/1\.1 401|WSMan", content, re.IGNORECASE):
        log.info("WinRM service confirmed active")
        session.add_note("WinRM service confirmed (responded to /wsman probe)")

    # Auth methods advertised
    auth_methods = re.findall(r"(Negotiate|NTLM|Kerberos|Basic)", content)
    if auth_methods:
        unique_auth = sorted(set(auth_methods))
        log.info("WinRM auth methods: %s", unique_auth)
        session.add_note(f"WinRM auth methods: {unique_auth}")


