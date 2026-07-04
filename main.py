#!/usr/bin/env python3
"""
main.py — OSCP Enumeration Framework
Usage: python main.py --target <IP> [options]
"""

import argparse
import sys
import time

from core.display import banner, status_line, warn, error
from core.engine import Engine


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="oscp-framework",
        description="OSCP Enumeration Framework — Assisted recon, never autopwn.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Standard exam run — full auto, pre-filled LHOST for Arsenal Recommender
  python main.py --target 10.10.10.10 --lhost 10.10.14.5

  # With a known AD domain
  python main.py --target 10.10.10.10 --domain corp.local --lhost 10.10.14.5

  # Resume after interruption (loads session.json, skips already-done modules)
  python main.py --target 10.10.10.10 --resume --lhost 10.10.14.5

  # Preview every command without executing (scope review / exam prep)
  python main.py --target 10.10.10.10 --dry-run

  # Force specific modules only (skip discovery)
  python main.py --target 10.10.10.10 --modules smb ldap web

  # Custom output directory (e.g. OSCP exam folder)
  python main.py --target 10.10.10.10 --output-dir /root/oscp/exam --lhost 10.10.14.5
        """,
    )

    parser.add_argument(
        "--target", "-t",
        required=True,
        metavar="IP",
        help="Target IP address.",
    )
    parser.add_argument(
        "--domain", "-d",
        default="",
        metavar="DOMAIN",
        help="Target domain / hostname (e.g. corp.local). Passed to LDAP, DNS, SMB, and web modules.",
    )
    parser.add_argument(
        "--lhost",
        default="",
        metavar="IP",
        help=(
            "Your attacker/VPN IP address (e.g. tun0: 10.10.14.5). "
            "Pre-fills all <LHOST> placeholders in the Arsenal Recommender section of notes.md "
            "so transfer and reverse-shell commands are copy-paste ready. "
            "Example: --lhost 10.10.14.5"
        ),
    )
    # ── Authenticated enumeration ────────────────────────────────────────────
    # Supplying a valid credential re-runs the framework in AUTHENTICATED mode:
    # every credential-aware module (SMB, LDAP, MSSQL, WinRM, Kerberos) binds
    # ONCE as this single user. No password spraying, no brute force — a handful
    # of logins with a known-good password, so no account-lockout risk.
    parser.add_argument(
        "--user", "-u",
        default="",
        metavar="USER",
        help=(
            "Domain or local username for AUTHENTICATED enumeration. "
            "Requires --password or --hash. Enables authenticated SMB/LDAP/MSSQL/"
            "WinRM enum, BloodHound collection, and Kerberoast/AS-REP hash capture. "
            "Enumeration only — never exploitation, never password spraying."
        ),
    )
    parser.add_argument(
        "--password", "-p",
        default="",
        metavar="PASS",
        help="Password for --user (plaintext). Use --hash instead for pass-the-hash.",
    )
    parser.add_argument(
        "--hash", "-H",
        default="",
        metavar="NTLM",
        help=(
            "NTLM hash for --user (pass-the-hash). Format: LM:NT or just NT. "
            "Alternative to --password when you have a hash but not the plaintext."
        ),
    )
    parser.add_argument(
        "--local-auth",
        action="store_true",
        help=(
            "Authenticate against the LOCAL account database instead of the domain "
            "(passes --local-auth to nxc/netexec). Use for standalone hosts or local admin creds."
        ),
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help=(
            "Resume a previous session from session.json. "
            "Without this flag a fresh scan always starts, even if session.json exists. "
            "With this flag, Nmap is skipped when ports are already known and only "
            "pending modules are queued. "
            "Example: python main.py --target 10.10.10.10 --resume"
        ),
    )
    parser.add_argument(
        "--modules", "-m",
        nargs="+",
        choices=[
            # Tier 0 — Authenticated credential sweep (needs -u/-p or -u/-H)
            "creds",
            # Tier 1 — Lightning Fast
            "smb", "ftp", "ldap", "dns", "snmp", "nfs", "services", "network",
            # Tier 2 — Medium
            "databases", "remote", "mail",
            # Tier 3 — Heavy
            "web",
        ],
        metavar="MODULE",
        help=(
            "Run specific modules only (default: auto-detect from open ports). "
            "Tier 0: creds (authenticated sweep) | "
            "Tier 1: smb ftp ldap dns snmp nfs services network | "
            "Tier 2: databases remote mail | "
            "Tier 3: web"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands that would be executed without running them. Useful for scope review.",
    )
    parser.add_argument(
        "--output-dir",
        default="output/targets",
        metavar="DIR",
        help="Base directory for scan output (default: output/targets).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output — show DEBUG-level log messages.",
    )
    parser.add_argument(
        "--quick", "-q",
        action="store_true",
        help=(
            "Quick mode — abort each module after 120 s and move to the next. "
            "Useful for OSCP exam: do a fast first pass over all machines, "
            "then run a second full pass on promising targets."
        ),
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    banner()

    # Credential sanity checks — a username needs a secret, and a secret
    # without a username is meaningless.
    if args.user and not (args.password or args.hash):
        error("--user requires --password or --hash. Aborting.")
        sys.exit(1)
    if (args.password or args.hash) and not args.user:
        error("--password/--hash given without --user. Aborting.")
        sys.exit(1)
    if args.password and args.hash:
        warn("Both --password and --hash supplied — using --password, ignoring --hash.")
        args.hash = ""

    start = time.time()
    engine = Engine(
        target=args.target,
        domain=args.domain,
        output_base=args.output_dir,
        dry_run=args.dry_run,
        verbose=args.verbose,
        forced_modules=args.modules,
        lhost=args.lhost,
        resume=args.resume,
        quick=args.quick,
        user=args.user,
        password=args.password,
        ntlm_hash=args.hash,
        local_auth=args.local_auth,
    )

    try:
        engine.run()
    except KeyboardInterrupt:
        warn("Interrupted by user. Session state saved.")
    except Exception as exc:
        error(f"Fatal error: {exc}")
        if args.verbose:
            raise
        sys.exit(1)
    finally:
        total = int(time.time() - start)
        mins, secs = total // 60, total % 60
        elapsed_str = f"{mins}m {secs:02d}s" if mins else f"{secs}s"
        status_line(args.target, "session complete", elapsed_str)


if __name__ == "__main__":
    main()
