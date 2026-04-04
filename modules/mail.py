"""
modules/mail.py — Mail service enumeration module

Routes to wrappers/services_enum.sh for SMTP (25/465/587), POP3 (110/995),
and IMAP (143/993) banner grabbing and user enumeration via NSE scripts.
After the wrapper runs, parses output and injects [MANUAL] hints into
session notes so they appear in notes.md.

OSCP compliance:
  - Banner grabs and NSE user enumeration (VRFY/EXPN/RCPT) only
  - NO brute force of any kind
  - Relay and open-proxy tests → hint only
"""

import re
from pathlib import Path

from core.runner import run_wrapper

WRAPPERS_DIR = Path(__file__).resolve().parent.parent / "wrappers"

# Ports this module owns
_MAIL_PORTS = {
    25,    # SMTP
    110,   # POP3
    143,   # IMAP
    465,   # SMTPS (implicit TLS)
    587,   # SMTP submission (STARTTLS)
    993,   # IMAPS
    995,   # POP3S
}

_SMTP_PORTS  = {25, 465, 587}
_POP3_PORTS  = {110, 995}
_IMAP_PORTS  = {143, 993}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(target: str, session, dry_run: bool = False) -> None:
    log = session.log

    open_mail = session.info.open_ports & _MAIL_PORTS
    if not open_mail:
        log.info("No mail ports open — skipping mail module.")
        return

    log.info("Mail ports to enumerate: %s", sorted(open_mail))

    # Inject MANUAL hints immediately — visible even if wrapper is interrupted
    _add_manual_hints(session, open_mail)

    script = WRAPPERS_DIR / "mail_enum.sh"
    if not script.exists():
        log.error("Wrapper not found: %s", script)
        return

    ports_csv = ",".join(str(p) for p in sorted(open_mail))
    cmd = [
        "bash", str(script),
        "--target",     target,
        "--output-dir", str(session.target_dir),
        "--ports",      ports_csv,
    ]
    if session.info.domain:
        cmd += ["--domain", session.info.domain]

    run_wrapper(cmd, session, label="mail_enum.sh", dry_run=dry_run)

    if dry_run:
        return

    _parse_smtp(session, log)
    _parse_pop3_imap(session, log)

    log.info("Mail module complete.")


# ---------------------------------------------------------------------------
# MANUAL hints — written to notes.md regardless of what the wrapper finds
# ---------------------------------------------------------------------------

def _add_manual_hints(session, open_mail: set) -> None:
    ip = session.info.ip

    if open_mail & _SMTP_PORTS:
        smtp_port = min(open_mail & _SMTP_PORTS)
        session.add_note(
            f"💡 [MANUAL] SMTP VRFY / IMAP login tests: "
            f"nc -nv {ip} {smtp_port}  (then: EHLO x, VRFY root, EXPN admin)"
        )
        session.add_note(
            f"💡 [MANUAL] SMTP user enum (nmap): "
            f"nmap -p {smtp_port} --script smtp-enum-users,smtp-open-relay,smtp-commands {ip}"
        )
        session.add_note(
            f"💡 [MANUAL] SMTP user enum (smtp-user-enum): "
            f"smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt "
            f"-t {ip} -p {smtp_port}"
        )
        session.add_note(
            f"💡 [MANUAL] Send test email (swaks): "
            f"swaks --to admin@target --from test@test.com --server {ip}"
        )

    if open_mail & _POP3_PORTS:
        pop3_port = min(open_mail & _POP3_PORTS)
        session.add_note(
            f"💡 [MANUAL] POP3 manual login: "
            f"nc -nv {ip} {pop3_port}  (then: USER admin, PASS password, LIST, RETR 1)"
        )
        session.add_note(
            f"💡 [MANUAL] POP3 (curl): "
            f"curl -v pop3://{ip} --user USER:PASS"
        )

    if open_mail & _IMAP_PORTS:
        imap_port = min(open_mail & _IMAP_PORTS)
        session.add_note(
            f"💡 [MANUAL] IMAP manual login: "
            f"nc -nv {ip} {imap_port}  "
            f"(then: a1 LOGIN user@domain PASS, a2 LIST \"\" \"*\", a3 SELECT INBOX)"
        )
        session.add_note(
            f"💡 [MANUAL] IMAP (curl): "
            f"curl -v imap://{ip}/INBOX --user USER:PASS"
        )


# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------

def _parse_smtp(session, log) -> None:
    mail_dir = session.target_dir / "mail"
    smtp_f   = mail_dir / "smtp_nmap.txt"
    if not smtp_f.exists():
        smtp_f = session.target_dir / "services" / "smtp_nmap.txt"
    if not smtp_f.exists():
        return

    content = smtp_f.read_text(errors="ignore")

    # Open relay
    if re.search(r"smtp-open-relay.*Server is an open relay|RELAY OK", content, re.IGNORECASE):
        log.warning("SMTP: open relay detected")
        session.add_note(
            f"🚨 SMTP FINDING: Open relay — can send email as any sender ({smtp_f})"
        )

    # Valid users found via VRFY/EXPN
    valid_users = re.findall(
        r"smtp-enum-users:\s*\|.+?(\w[\w.@-]+).*?Valid", content, re.IGNORECASE
    )
    if not valid_users:
        # Alternative format: nmap output lines like "| root - Valid"
        valid_users = re.findall(r"\|\s+(\S+)\s+-\s+Valid", content)
    if valid_users:
        unique = sorted(set(valid_users))
        log.warning("SMTP: valid users found via VRFY: %s", unique)
        session.add_note(f"🚨 SMTP FINDING: Valid usernames confirmed: {unique}")
        session.info.users_found.extend(
            u for u in unique if u not in session.info.users_found
        )

    # STARTTLS support
    if re.search(r"STARTTLS", content, re.IGNORECASE):
        log.info("SMTP: STARTTLS supported")

    # Server banner / version
    banner = re.search(r"220\s+(.+)", content)
    if banner:
        log.info("SMTP banner: %s", banner.group(1).strip())
        session.add_note(f"SMTP banner: {banner.group(1).strip()}")


def _parse_pop3_imap(session, log) -> None:
    mail_dir = session.target_dir / "mail"
    for proto in ("pop3", "imap"):
        out_f = mail_dir / f"{proto}_nmap.txt"
        if not out_f.exists():
            out_f = session.target_dir / "services" / f"{proto}_nmap.txt"
        if not out_f.exists():
            continue

        content = out_f.read_text(errors="ignore")

        # Banner
        banner = re.search(r"\+OK (.+)|^\* OK (.+)", content, re.MULTILINE)
        if banner:
            b = (banner.group(1) or banner.group(2)).strip()
            log.info("%s banner: %s", proto.upper(), b)
            session.add_note(f"{proto.upper()} banner: {b}")

        # Capabilities
        caps = re.findall(r"CAPABILITY.*?:(.*?)(?:\n|\|_)", content, re.DOTALL)
        if caps:
            log.info("%s capabilities: %s", proto.upper(), caps[0].strip())


