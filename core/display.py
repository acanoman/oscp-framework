"""
core/display.py — Classic terminal output functions for the OSCP framework.

All output goes through Rich so colors are portable and consistent.
No ANSI escape codes are hardcoded here.
"""

from typing import List, Tuple

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel

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
    Print a Rich panel summarising key findings from a module.

    findings: list of (severity, message) tuples where severity is one of:
        "critical"  → red    ⚠
        "high"      → yellow ⚡
        "access"    → cyan   ✅
        "info"      → green  •
    """
    if not findings:
        return

    _SEVERITY_FMT = {
        "critical": ("[bold red]  ⚠  [/bold red]",        "red"),
        "high":     ("[bold yellow]  ⚡  [/bold yellow]",  "yellow"),
        "access":   ("[bold cyan]  ✅  [/bold cyan]",      "cyan"),
        "info":     ("[green]  •  [/green]",               "green"),
    }

    lines = []
    for sev, msg in findings:
        prefix, color = _SEVERITY_FMT.get(sev, _SEVERITY_FMT["info"])
        lines.append(f"{prefix}[{color}]{escape(msg)}[/{color}]")

    console.print(
        Panel(
            "\n".join(lines),
            title=f"[bold white] {module_name.upper()} FINDINGS [/bold white]",
            border_style="bright_blue",
            padding=(0, 2),
        )
    )


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
