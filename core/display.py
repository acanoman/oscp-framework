"""
core/display.py — Classic terminal output functions for the OSCP framework.

All output goes through Rich so colors are portable and consistent.
No ANSI escape codes are hardcoded here.
"""

from rich.console import Console

console = Console()


def info(msg: str) -> None:
    """[-] in white — general informational line."""
    console.print(f"[white][-][/white] {msg}")


def success(msg: str) -> None:
    """[+] in cyan — positive discovery."""
    console.print(f"[cyan][+][/cyan] {msg}")


def done(msg: str) -> None:
    """[✓] in green — task completed."""
    console.print(f"[green][✓][/green] {msg}")


def warn(msg: str) -> None:
    """[!] in yellow — warning or non-fatal issue."""
    console.print(f"[yellow][!][/yellow] {msg}")


def error(msg: str) -> None:
    """[x] in red — error or failure."""
    console.print(f"[red][x][/red] {msg}")


def hint(msg: str) -> None:
    """[HINT] block in dim magenta — manual command suggestion."""
    console.print(f"\n[magenta][HINT][/magenta] Run manually:")
    for line in msg.strip().split("\n"):
        console.print(f"[dim magenta]       {line}[/dim magenta]")
    console.print()


def module_start(name: str) -> None:
    """Print a separator and 'Starting <name>...' line."""
    console.print(f"\n[cyan]{'═' * 44}[/cyan]")
    console.print(f"[cyan][*][/cyan] Starting [bold cyan]{name}[/bold cyan]...")


def module_done(name: str) -> None:
    """Print a '[✓] <name> complete' line."""
    console.print(f"[green][✓][/green] [bold]{name}[/bold] complete")


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
