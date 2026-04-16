"""
core/display.py — Classic terminal output functions for the OSCP framework.

All output goes through Rich so colors are portable and consistent.
No ANSI escape codes are hardcoded here.
"""

from typing import Dict, List, Tuple

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

console = Console()


def info(msg: str) -> None:
    """[*] in cyan — general informational line from the framework."""
    console.print(f"[cyan][*][/cyan] {escape(msg)}")


def pipe(msg: str) -> None:
    """Neutral subprocess output line — dim indented, no prefix clutter."""
    console.print(f"  [dim]{escape(msg)}[/dim]")


def success(msg: str) -> None:
    """[+] in green — positive discovery."""
    console.print(f"[green][+][/green] {escape(msg)}")


def done(msg: str) -> None:
    """[✓] in green — task completed."""
    console.print(f"[green][✓][/green] {escape(msg)}")


def warn(msg: str) -> None:
    """[!] in yellow — warning or non-fatal issue."""
    console.print(f"[yellow][!][/yellow] {escape(msg)}")


def error(msg: str) -> None:
    """[x] in red — error or failure."""
    console.print(f"[red][x][/red] {escape(msg)}")


def hint(msg: str) -> None:
    """[MANUAL] block in dim magenta — manual command suggestion."""
    console.print(f"\n[magenta][MANUAL][/magenta] Run manually:")
    for line in msg.strip().split("\n"):
        console.print(f"[dim magenta]       {escape(line)}[/dim magenta]")
    console.print()


def module_start(name: str) -> None:
    """Print a separator and 'Starting <name>...' line."""
    console.print(f"\n[cyan]{'═' * 44}[/cyan]")
    console.print(f"[cyan][*][/cyan] Starting [bold cyan]{name}[/bold cyan]...")


def module_done(name: str) -> None:
    """Print a '[✓] <name> complete' line."""
    console.print(f"[green][✓][/green] [bold]{name}[/bold] complete")


def findings_panel(module_name: str, findings: List[Tuple[str, str]]) -> None:
    """
    Print a Rich table panel summarising key findings from a module.

    findings: list of (severity, message) tuples where severity is one of:
        "critical"  → red    ⚠
        "high"      → yellow ⚡
        "access"    → cyan   ✅
        "info"      → green  •
    """
    if not findings:
        return

    _SEV = {
        "critical": ("⚠  CRIT",  "bold red"),
        "high":     ("⚡ HIGH",   "bold yellow"),
        "access":   ("✅ ACCESS", "bold cyan"),
        "info":     ("•  INFO",   "green"),
    }

    table = Table(
        show_header=True,
        header_style="bold bright_white",
        border_style="bright_blue",
        show_edge=False,
        padding=(0, 1),
        expand=True,
    )
    table.add_column("SEV", width=10, no_wrap=True)
    table.add_column("FINDING")

    for sev, msg in findings:
        label, color = _SEV.get(sev, _SEV["info"])
        table.add_row(
            f"[{color}]{label}[/{color}]",
            f"[{color}]{escape(msg)}[/{color}]",
        )

    console.print(
        Panel(
            table,
            title=f"[bold white] {module_name.upper()} FINDINGS [/bold white]",
            border_style="bright_blue",
            padding=(0, 1),
        )
    )


def recon_port_table(ip: str, os_guess: str, port_details: Dict[int, dict]) -> None:
    """
    Print a Rich table with discovered ports/services after initial recon.

    port_details: dict mapping port (int) → {"service": str, "version": str}
    """
    if not port_details:
        return

    table = Table(
        show_header=True,
        header_style="bold bright_white",
        border_style="cyan",
        show_edge=False,
        padding=(0, 1),
        expand=False,
    )
    table.add_column("PORT",    style="bold cyan",  width=7,  no_wrap=True)
    table.add_column("SERVICE", style="bold white", width=12, no_wrap=True)
    table.add_column("VERSION", style="dim white")

    for port in sorted(port_details.keys()):
        d   = port_details[port]
        svc = d.get("service", "")
        ver = d.get("version", "")
        table.add_row(str(port), svc, ver)

    console.print()
    console.print(
        Panel(
            table,
            title=f"[bold cyan] RECON — {ip} [/bold cyan]",
            subtitle=f"[dim] OS guess: {os_guess} [/dim]" if os_guess else None,
            border_style="cyan",
            padding=(0, 1),
        )
    )
    console.print()


def banner() -> None:
    """Print the ARGUS ASCII art banner."""
    console.print("""[magenta]
 █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
███████║██████╔╝██║  ███╗██║   ██║███████╗
██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
[/magenta]""")
    console.print("[cyan]  ENUMERATION FRAMEWORK v1.0[/cyan]")
    console.print(
        "[dim]  Assisted recon. Never autopwn.  "
        "☠ by acanoman ☠[/dim]"
    )
    console.print(f"[cyan]{'═' * 44}[/cyan]\n")


def status_line(target: str, module: str, elapsed: str) -> None:
    """Print a compact status summary line."""
    console.print(
        f"\n[dim]TARGET [white]{target}[/white] │ "
        f"MODULE [cyan]{module}[/cyan] │ "
        f"ELAPSED [white]{elapsed}[/white][/dim]"
    )
