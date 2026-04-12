"""
ui/panels.py — Individual panel render functions for the ARGUS TUI.

Each function returns a Rich renderable (Panel, Table, Text, Group, etc.).
All colors are imported exclusively from ui.theme — nothing hardcoded here.
"""

from typing import Dict, List, Optional, Tuple

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

import ui.theme as T


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _styled(text: str, style: str) -> Text:
    """Shorthand: return a Text object with a single style applied."""
    return Text(text, style=style)


def _make_titlebar() -> Text:
    """
    Traffic-light dots + centred 'ARGUS — TERMINAL' title.
    Used as the title= argument of the outermost banner panel.
    """
    t = Text(no_wrap=True)
    t.append(" ● ", style=f"bold {T.ACCENT_RED}")
    t.append("● ",  style=f"bold {T.ACCENT_YELLOW}")
    t.append("● ",  style=f"bold {T.ACCENT_GREEN}")
    t.append("  A R G U S  —  T E R M I N A L  ", style=f"bold {T.TITLE_COLOR}")
    return t


# ---------------------------------------------------------------------------
# 1. BANNER
# Titlebar is embedded as the Panel title; ASCII art + subtitles are content.
# ---------------------------------------------------------------------------

def render_banner() -> Panel:
    """Top banner: titlebar dots, ASCII ARGUS art, subtitle lines."""
    # ASCII art
    art = Text(T.ARGUS_ASCII, style=T.PRIMARY_PURPLE, no_wrap=True)

    # Subtitle row — left / right using a grid table
    sub_grid = Table.grid(expand=True, padding=(0, 1))
    sub_grid.add_column(ratio=1)
    sub_grid.add_column(ratio=1, justify="right")
    sub_grid.add_row(
        Text(
            "E N U M E R A T I O N   F R A M E W O R K  v1.0",
            style=T.CYAN,
            no_wrap=True,
        ),
        Text(
            "Assisted recon. Never autopwn.   ☠ by acanoman ☠",
            style=T.BANNER_RIGHT,
            no_wrap=True,
        ),
    )

    content = Group(art, Text(""), sub_grid)

    return Panel(
        content,
        title=_make_titlebar(),
        title_align="center",
        border_style=T.BORDER_OUTER,
        style=f"on {T.BG_BANNER}",
        padding=(0, 1),
    )


# ---------------------------------------------------------------------------
# 2. MODULE SIDEBAR
# ---------------------------------------------------------------------------

def _module_row(label: str, status: str, blink_on: bool) -> Table:
    """
    Return a one-row Table.grid with icon + name styled for the given status.

    status: "done" | "running" | "pending"
    blink_on: toggled at ~2 Hz by the TUI thread to animate the running icon.
    """
    row = Table.grid(padding=(0, 0))
    row.add_column(width=4, no_wrap=True)
    row.add_column(no_wrap=True)

    if status == "done":
        icon = Text(T.ICON_DONE,  style=T.SUCCESS_GREEN)
        name = Text(label,        style=T.SUCCESS_GREEN)
    elif status == "running":
        # Blink: full brightness on / dim-but-visible off
        if blink_on:
            icon = Text(T.ICON_RUNNING, style=f"bold {T.CYAN}")
            name = Text(label,          style=f"bold {T.CYAN}")
        else:
            icon = Text(T.ICON_RUNNING, style=T.CYAN)
            name = Text(label,          style=T.DIM_PURPLE)
    else:
        icon = Text(T.ICON_PENDING, style=T.DIM_PURPLE)
        name = Text(label,          style=T.DIM_PURPLE)

    row.add_row(icon, name)
    return row


def render_modules(
    statuses: Dict[str, str],
    blink_on: bool = True,
) -> Panel:
    """
    Module status sidebar.

    statuses: {module_key → "done" | "running" | "pending"}
    """
    parts: List = [
        Text("M O D U L E S", style=T.STYLE_HEADER),
        Text(""),
    ]

    for label, key in T.MODULE_LIST:
        status = statuses.get(key, "pending")
        parts.append(_module_row(label, status, blink_on))

    return Panel(
        Group(*parts),
        border_style=T.BORDER_OUTER,
        style=f"on {T.BG_SIDEBAR}",
        padding=(1, 1),
    )


# ---------------------------------------------------------------------------
# 3. LIVE OUTPUT PANEL
# ---------------------------------------------------------------------------

def _style_log_line(timestamped_line: str) -> Text:
    """
    Colour-code a pre-timestamped log line.

    Expected input format: "HH:MM:SS  [prefix] message body"
    Unknown formats fall back to MUTED info style.
    """
    t = Text(no_wrap=True)

    # Split timestamp from body
    if (
        len(timestamped_line) >= 10
        and timestamped_line[2] == ":"
        and timestamped_line[5] == ":"
    ):
        ts   = timestamped_line[:8]
        rest = timestamped_line[8:].strip()
        t.append(ts + "  ", style=T.STYLE_TIMESTAMP)
    else:
        ts   = ""
        rest = timestamped_line

    # Match known log prefixes (theme.py defines LOG_STYLES)
    for prefix, style in T.LOG_STYLES.items():
        if rest.startswith(prefix):
            t.append(prefix,                         style=style)
            t.append(" " + rest[len(prefix):].strip(), style=style)
            return t

    # No recognised prefix
    t.append(rest, style=T.STYLE_INFO)
    return t


def render_live_output(
    lines: List[str],
    paused: bool = False,
    scroll_offset: int = 0,
    max_lines: int = 30,
) -> Panel:
    """
    Scrollable live output panel.

    When not paused: always shows the last max_lines entries.
    When paused:     scroll_offset shifts the view window upward from the
                     bottom (0 = bottom, 1 = one line above bottom, …).
    """
    # Header
    header = Text(no_wrap=True)
    header.append("L I V E  O U T P U T", style=T.STYLE_HEADER)
    if paused:
        header.append("   ⏸ PAUSED — ↑↓ to scroll", style=f" {T.WARN_YELLOW}")

    # Determine visible window
    total = len(lines)
    if paused and scroll_offset > 0:
        end   = max(0, total - scroll_offset)
        start = max(0, end - max_lines)
        visible = lines[start:end]
    else:
        visible = lines[-max_lines:] if total > max_lines else lines

    parts: List = [header, Text("")]
    for raw in visible:
        parts.append(_style_log_line(raw))

    # Scroll hint when there is content above the view
    if paused and total > max_lines:
        above = max(0, total - max_lines - scroll_offset)
        if above > 0:
            parts.append(Text(f"  … {above} more line(s) above ↑", style=T.MUTED))

    return Panel(
        Group(*parts),
        border_style=T.BORDER_OUTER,
        padding=(0, 1),
    )


# ---------------------------------------------------------------------------
# 4. HINTS PANEL
# ---------------------------------------------------------------------------

def render_hints(hints: List[Tuple[str, str]]) -> Panel:
    """
    Manual hints panel (collapsible — caller decides whether to include it).

    hints: list of (label, command) tuples fed from advisor / recommender.
    """
    header = Text(no_wrap=True)
    header.append("MANUAL HINTS", style=T.STYLE_HINT_TITLE)
    header.append("  [H to toggle]", style=T.WARN_YELLOW)

    parts: List = [header, Text("")]

    if hints:
        for label, cmd in hints:
            row = Text()
            row.append(f"{label}:", style=T.STYLE_HINT_LABEL)
            row.append(f"\n  {cmd}",  style=T.STYLE_HINT_CMD)
            parts.append(row)
            parts.append(Text(""))
    else:
        parts.append(Text("No hints yet — run a module to populate.", style=T.MUTED))

    return Panel(
        Group(*parts),
        border_style=T.BORDER_INNER,
        padding=(0, 1),
    )


# ---------------------------------------------------------------------------
# 5. STATUS BAR
# ---------------------------------------------------------------------------

def _kbd(key: str) -> Text:
    """Render a keyboard shortcut badge."""
    t = Text(no_wrap=True)
    t.append(f"[{key}]", style=f"bold {T.TITLE_COLOR}")
    return t


def render_statusbar(
    target:        str,
    domain:        str,
    active_module: str,
    status:        str,    # "RUNNING" | "DONE" | "PAUSED" | "IDLE"
    elapsed:       str,
    paused:        bool = False,
) -> Panel:
    """
    Bottom status bar with target/domain/module info and keyboard hints.
    All sections separated by styled dividers.
    """
    DIV = Text("  │  ", style=T.BORDER_INNER)

    # ── Main info row ────────────────────────────────────────────────────
    info = Text(no_wrap=True)

    info.append("TARGET ", style=T.STYLE_HEADER)
    info.append(target or "—", style=T.BRIGHT_PURPLE)

    info.append("  │  ", style=T.BORDER_INNER)
    info.append("DOMAIN ", style=T.STYLE_HEADER)
    info.append(domain or "—", style=T.BRIGHT_PURPLE)

    info.append("  │  ", style=T.BORDER_INNER)
    info.append("MODULE ", style=T.STYLE_HEADER)
    mod_style = (
        T.CYAN          if status == "RUNNING"
        else T.SUCCESS_GREEN if status == "DONE"
        else T.WARN_YELLOW
    )
    info.append(active_module.upper() if active_module else "—", style=mod_style)

    info.append("  │  ", style=T.BORDER_INNER)
    if status == "RUNNING":
        info.append("RUNNING", style=f"bold {T.CYAN}")
    elif status == "DONE":
        info.append("DONE",    style=f"bold {T.SUCCESS_GREEN}")
    elif status == "PAUSED":
        info.append("PAUSED",  style=f"bold {T.WARN_YELLOW}")
    else:
        info.append(status or "IDLE", style=T.MUTED)

    info.append("  │  ", style=T.BORDER_INNER)
    info.append(elapsed, style=T.BRIGHT_PURPLE)

    # ── Keyboard hints row ───────────────────────────────────────────────
    kb = Text(justify="center", no_wrap=True)
    kb.append("[H]",     style=f"bold {T.TITLE_COLOR}")
    kb.append(" hints  ", style=T.MUTED)
    kb.append("[SPACE]", style=f"bold {T.TITLE_COLOR}")
    kb.append(" pause  ", style=T.MUTED)
    kb.append("[Q]",     style=f"bold {T.TITLE_COLOR}")
    kb.append(" quit",   style=T.MUTED)

    return Panel(
        Group(info, kb),
        border_style=T.BORDER_OUTER,
        style=f"on {T.BG_STATUSBAR}",
        padding=(0, 1),
    )
