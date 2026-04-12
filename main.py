#!/usr/bin/env python3
"""
main.py — OSCP Enumeration Framework
Usage: python main.py --target <IP> [options]
"""

import argparse
import queue
import sys

from rich.console import Console

from core.engine import Engine

# ARGUS-TUI integration — import the TUI class
from ui import ArgusUI

console = Console()


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

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # ARGUS-TUI integration — create the shared queue and start the TUI
    # before the engine so the first log lines are captured from the start.
    tui_queue: queue.Queue = queue.Queue()
    tui = ArgusUI(
        tui_queue=tui_queue,
        target=args.target,
        domain=args.domain,
    )
    tui.start()
    # IMP-applied: TUI runs in a daemon thread; engine output is non-blocking.

    engine = Engine(
        target=args.target,
        domain=args.domain,
        output_base=args.output_dir,
        dry_run=args.dry_run,
        verbose=args.verbose,
        forced_modules=args.modules,
        lhost=args.lhost,
        resume=args.resume,
        tui_queue=tui_queue,  # ARGUS-TUI integration
    )

    try:
        engine.run()
        tui.signal_done()           # ARGUS-TUI integration — mark session complete
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Interrupted by user. Session state saved.[/bold yellow]")
    except Exception as exc:
        console.print(f"[bold red][✗] Fatal error:[/bold red] {exc}")
        if args.verbose:
            tui.stop()
            raise
        sys.exit(1)
    finally:
        # ARGUS-TUI integration — cleanly stop TUI and print summary
        tui.stop()
        tui.print_summary()


if __name__ == "__main__":
    main()
