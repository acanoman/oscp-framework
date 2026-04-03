#!/usr/bin/env python3
"""
main.py — OSCP Enumeration Framework
Usage: python main.py --target <IP> [options]
"""

import argparse
import sys

from rich.console import Console

from core.engine import Engine

console = Console()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="oscp-framework",
        description="OSCP Enumeration Framework — Assisted recon, never autopwn.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target 10.10.10.10
  python main.py --target 10.10.10.10 --domain corp.local
  python main.py --target 10.10.10.10 --modules smb web
  python main.py --target 10.10.10.10 --dry-run
        """,
    )

    parser.add_argument(
        "--target", "-t",
        required=True,
        metavar="IP",
        help="Target IP address",
    )
    parser.add_argument(
        "--domain", "-d",
        default="",
        metavar="DOMAIN",
        help="Target domain / hostname (e.g. corp.local)",
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
        help="Print commands that would be executed without running them",
    )
    parser.add_argument(
        "--output-dir",
        default="output/targets",
        metavar="DIR",
        help="Base directory for scan output (default: output/targets)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    engine = Engine(
        target=args.target,
        domain=args.domain,
        output_base=args.output_dir,
        dry_run=args.dry_run,
        verbose=args.verbose,
        forced_modules=args.modules,
    )

    try:
        engine.run()
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Interrupted by user. Session state saved.[/bold yellow]")
        sys.exit(0)
    except Exception as exc:
        console.print(f"[bold red][✗] Fatal error:[/bold red] {exc}")
        if args.verbose:
            raise
        sys.exit(1)


if __name__ == "__main__":
    main()
