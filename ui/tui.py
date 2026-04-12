"""
ui/tui.py — ARGUS Terminal User Interface

Runs entirely in its own thread using rich.Live. Accepts log lines and
control messages via a queue.Queue. Keyboard input is handled in a
secondary daemon thread.

Usage (standalone demo):
    python ui/tui.py --demo

Usage (integrated, from main.py):
    from ui import ArgusUI
    import queue
    tui_q = queue.Queue()
    tui = ArgusUI(tui_q, target="10.10.10.5", domain="CORP.LOCAL")
    tui.start()
    # ... run engine ...
    tui.stop()
"""

from __future__ import annotations

import argparse
import queue
import random
import sys
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from ui.panels import (
    render_banner,
    render_hints,
    render_live_output,
    render_modules,
    render_statusbar,
)
import ui.theme as T

# ---------------------------------------------------------------------------
# Queue message protocol
#
# String  → raw log line (will be timestamped on receipt)
# Dict    → control message, keyed by "type":
#   {"type": "module_status", "module": str, "state": "pending|running|done"}
#   {"type": "hint",          "label": str,  "command": str}
#   {"type": "set_module",    "module": str}    ← update active module name
#   {"type": "set_domain",    "domain": str}    ← update domain in status bar
#   {"type": "done"}                            ← engine finished, set DONE
#   {"type": "quit"}                            ← request graceful shutdown
# ---------------------------------------------------------------------------

CTRL_MODULE_STATUS = "module_status"
CTRL_HINT          = "hint"
CTRL_SET_MODULE    = "set_module"
CTRL_SET_DOMAIN    = "set_domain"
CTRL_DONE          = "done"
CTRL_QUIT          = "quit"


# ---------------------------------------------------------------------------
# Keyboard listener — platform-aware
# ---------------------------------------------------------------------------

def _start_kb_listener(callback) -> Optional[threading.Thread]:
    """
    Spawn a daemon thread that reads single keypresses and calls callback(ch).
    Returns the thread on success, None if keyboard capture is unavailable.
    ch is always a lowercase single character or a sentinel string:
      'q', 'h', ' ', 'up', 'down'
    """
    def _win_listener():
        import msvcrt  # type: ignore[import]
        while True:
            if msvcrt.kbhit():
                raw = msvcrt.getch()
                try:
                    ch = raw.decode("utf-8", errors="ignore").lower()
                except Exception:
                    ch = ""
                if ch in ("q", "h", " "):
                    callback(ch)
                elif raw == b"\xe0":          # extended key prefix
                    raw2 = msvcrt.getch()
                    if raw2 == b"H":
                        callback("up")
                    elif raw2 == b"P":
                        callback("down")
            time.sleep(0.05)

    def _unix_listener():
        import tty      # type: ignore[import]
        import termios  # type: ignore[import]
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while True:
                ch = sys.stdin.read(1)
                if ch.lower() in ("q", "h", " "):
                    callback(ch.lower())
                elif ch == "\x1b":             # ESC — possible arrow key
                    seq = sys.stdin.read(2)
                    if seq == "[A":
                        callback("up")
                    elif seq == "[B":
                        callback("down")
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)

    try:
        if sys.platform == "win32":
            t = threading.Thread(target=_win_listener, daemon=True)
        else:
            t = threading.Thread(target=_unix_listener, daemon=True)
        t.start()
        return t
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Elapsed timer helper
# ---------------------------------------------------------------------------

def _elapsed(start: float) -> str:
    secs  = int(time.time() - start)
    h     = secs // 3600
    m     = (secs % 3600) // 60
    s     = secs % 60
    if h:
        return f"{h:02d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


# ---------------------------------------------------------------------------
# ArgusUI — main TUI class
# ---------------------------------------------------------------------------

class ArgusUI:
    """
    ARGUS Terminal User Interface.

    Thread-safe: all mutations to shared state go through _process_queue()
    which runs inside the render thread.  The keyboard thread only sets
    simple boolean/int flags (GIL-safe on CPython).
    """

    # Sidebar width in terminal columns
    SIDEBAR_WIDTH  = 16
    # Live output visible rows (approximate; layout height governs actual)
    MAX_LOG_LINES  = 200   # internal buffer cap
    RENDER_HZ      = 8     # refreshes per second
    BLINK_HZ       = 2     # blinking animation frequency

    def __init__(
        self,
        tui_queue:  queue.Queue,
        target:     str = "",
        domain:     str = "",
        start_time: Optional[float] = None,
    ) -> None:
        self._q             = tui_queue
        self._target        = target
        self._domain        = domain
        self._start_time    = start_time or time.time()

        # Mutable state — only mutated in _tick() or by GIL-safe flag writes
        self._log_lines:  List[str]            = []
        self._hints:      List[Tuple[str, str]]= []
        self._statuses:   Dict[str, str]       = {
            key: "pending" for _, key in T.MODULE_LIST
        }
        self._active_module: str  = ""
        self._run_status:    str  = "RUNNING"

        # Keyboard-driven flags (GIL-safe single-word writes)
        self._hints_visible: bool = True
        self._paused:        bool = False
        self._scroll_offset: int  = 0
        self._running:       bool = False

        # Blink state (toggled by render loop)
        self._blink_on: bool = True
        self._last_blink: float = 0.0

        # Rich console — stderr avoids colliding with subprocess stdout pipes
        self._console = Console(stderr=True, highlight=False)

        # Thread handle
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the TUI render thread and keyboard listener."""
        self._running = True
        self._thread = threading.Thread(
            target=self._render_loop,
            name="argus-tui",
            daemon=True,
        )
        self._thread.start()
        _start_kb_listener(self._on_key)

    def stop(self, wait: bool = True) -> None:
        """Signal the TUI to stop and optionally block until it exits."""
        self._running = False
        if wait and self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)

    def push(self, line: str) -> None:
        """Convenience: put a raw log string directly into the queue."""
        self._q.put(line)

    def set_module_status(self, module: str, state: str) -> None:
        """Convenience shortcut for engine/runner touch points."""
        self._q.put({
            "type":   CTRL_MODULE_STATUS,
            "module": module,
            "state":  state,
        })

    def add_hint(self, label: str, command: str) -> None:
        """Convenience shortcut for advisor/recommender touch points."""
        self._q.put({"type": CTRL_HINT, "label": label, "command": command})

    def signal_done(self) -> None:
        """Mark all modules complete; update status bar to DONE."""
        self._q.put({"type": CTRL_DONE})

    # ------------------------------------------------------------------
    # Keyboard callback (called from kb listener thread — keep minimal)
    # ------------------------------------------------------------------

    def _on_key(self, ch: str) -> None:
        if ch == "q":
            self._running = False
        elif ch == "h":
            self._hints_visible = not self._hints_visible
        elif ch == " ":
            self._paused = not self._paused
            if not self._paused:
                self._scroll_offset = 0   # resume → jump to bottom
        elif ch == "up" and self._paused:
            self._scroll_offset = min(
                self._scroll_offset + 1,
                max(0, len(self._log_lines) - 1),
            )
        elif ch == "down" and self._paused:
            self._scroll_offset = max(0, self._scroll_offset - 1)

    # ------------------------------------------------------------------
    # Queue processing
    # ------------------------------------------------------------------

    def _drain_queue(self) -> None:
        """Process all pending queue items without blocking."""
        try:
            while True:
                msg = self._q.get_nowait()
                self._handle_message(msg)
        except queue.Empty:
            pass

    def _handle_message(self, msg) -> None:
        if isinstance(msg, str):
            ts   = datetime.now().strftime("%H:%M:%S")
            line = f"{ts}  {msg}"
            self._log_lines.append(line)
            # Cap buffer
            if len(self._log_lines) > self.MAX_LOG_LINES:
                self._log_lines = self._log_lines[-self.MAX_LOG_LINES:]
        elif isinstance(msg, dict):
            mtype = msg.get("type", "")
            if mtype == CTRL_MODULE_STATUS:
                key   = msg.get("module", "")
                state = msg.get("state", "pending")
                if key:
                    self._statuses[key] = state
                    if state == "running":
                        self._active_module = key
                    # Also timestamp a log entry
                    label = next(
                        (lbl for lbl, k in T.MODULE_LIST if k == key), key.upper()
                    )
                    ts = datetime.now().strftime("%H:%M:%S")
                    if state == "running":
                        self._log_lines.append(
                            f"{ts}  [-] {label} running..."
                        )
                    elif state == "done":
                        self._log_lines.append(
                            f"{ts}  [✓] {label} complete"
                        )
            elif mtype == CTRL_HINT:
                label = msg.get("label", "")
                cmd   = msg.get("command", "")
                if label and cmd:
                    self._hints.append((label, cmd))
                    ts = datetime.now().strftime("%H:%M:%S")
                    self._log_lines.append(
                        f"{ts}  [>] MANUAL hint added: {label}"
                    )
            elif mtype == CTRL_SET_MODULE:
                self._active_module = msg.get("module", self._active_module)
            elif mtype == CTRL_SET_DOMAIN:
                self._domain = msg.get("domain", self._domain)
            elif mtype == CTRL_DONE:
                self._run_status = "DONE"
                ts = datetime.now().strftime("%H:%M:%S")
                self._log_lines.append(f"{ts}  [✓] All modules complete")
            elif mtype == CTRL_QUIT:
                self._running = False

    # ------------------------------------------------------------------
    # Layout construction
    # ------------------------------------------------------------------

    def _build_layout(self) -> Layout:
        """
        Construct the full display layout for one render tick.

        Layout tree:
          root (column)
            banner   — ASCII art + titlebar
            body (row)
              sidebar  — module status list
              content (column)
                output  — live log stream
                hints   — manual hints (conditional)
            status   — target/module/elapsed + kbd hints
        """
        # Blink toggle (~2 Hz)
        now = time.time()
        if now - self._last_blink >= (1.0 / self.BLINK_HZ):
            self._blink_on    = not self._blink_on
            self._last_blink  = now

        # Panels
        banner  = render_banner()
        sidebar = render_modules(self._statuses, self._blink_on)
        output  = render_live_output(
            self._log_lines,
            paused=self._paused,
            scroll_offset=self._scroll_offset,
        )
        hints   = render_hints(self._hints)
        status  = render_statusbar(
            target=self._target,
            domain=self._domain,
            active_module=self._active_module,
            status=self._run_status if not self._paused else "PAUSED",
            elapsed=_elapsed(self._start_time),
            paused=self._paused,
        )

        # Root layout
        root = Layout()
        root.split_column(
            Layout(banner, name="banner", size=11),
            Layout(name="body"),
            Layout(status, name="status", size=5),
        )
        root["body"].split_row(
            Layout(sidebar, name="sidebar", size=self.SIDEBAR_WIDTH),
            Layout(name="content"),
        )

        # Content column: output always present, hints conditional
        if self._hints_visible:
            root["body"]["content"].split_column(
                Layout(output, name="output", ratio=2),
                Layout(hints,  name="hints",  ratio=1),
            )
        else:
            root["body"]["content"].split_column(
                Layout(output, name="output"),
            )

        return root

    # ------------------------------------------------------------------
    # Render loop
    # ------------------------------------------------------------------

    def _render_loop(self) -> None:
        """Main TUI thread: drain queue + refresh display at RENDER_HZ."""
        interval = 1.0 / self.RENDER_HZ
        try:
            with Live(
                self._build_layout(),
                console=self._console,
                refresh_per_second=self.RENDER_HZ,
                screen=True,
                transient=False,
            ) as live:
                while self._running:
                    self._drain_queue()
                    live.update(self._build_layout())
                    time.sleep(interval)
        except Exception:
            # Degrade gracefully — TUI crashes should not kill the engine
            self._running = False

    # ------------------------------------------------------------------
    # Exit summary
    # ------------------------------------------------------------------

    def print_summary(self) -> None:
        """Print a plain-text session summary after TUI exits."""
        c = Console()
        c.print()
        c.rule(f"[bold {T.CYAN}] ARGUS — SESSION SUMMARY [/]", style=T.BORDER_OUTER)
        c.print(f"  [bold {T.CYAN}]Target :[/]  {self._target}")
        c.print(f"  [bold {T.CYAN}]Domain :[/]  {self._domain or '—'}")
        c.print(f"  [bold {T.CYAN}]Elapsed:[/]  {_elapsed(self._start_time)}")
        c.print()
        c.print(f"  [{T.STYLE_HEADER}]Module results:[/]")
        for label, key in T.MODULE_LIST:
            st = self._statuses.get(key, "pending")
            if st == "done":
                icon  = f"[{T.SUCCESS_GREEN}]{T.ICON_DONE}[/]"
                style = T.SUCCESS_GREEN
            elif st == "running":
                icon  = f"[{T.WARN_YELLOW}]{T.ICON_RUNNING}[/]"
                style = T.WARN_YELLOW
            else:
                icon  = f"[{T.DIM_PURPLE}]{T.ICON_PENDING}[/]"
                style = T.DIM_PURPLE
            c.print(f"    {icon} [{style}]{label}[/]")
        c.print()


# ---------------------------------------------------------------------------
# Demo mode
# ---------------------------------------------------------------------------

_DEMO_MODULES = ["recon", "smb", "ldap", "web", "databases", "ftp",
                  "mail", "nfs", "network", "services", "remote"]

_DEMO_LINES = [
    "[✓] RECON complete — 8 ports open",
    "[+] SMB signing disabled on 10.10.10.5",
    "[+] SMB share: SYSVOL (READ)",
    "[+] SMB share: IPC$ (READ)",
    "[✓] SMB complete",
    "[+] Kerbrute: 4 valid users found",
    "[!] Users saved to valid_users.txt",
    "[>] MANUAL hint added: AS-REP Roast",
    "[-] LDAP running anonymous bind...",
    "[+] LDAP base DN: DC=CORP,DC=LOCAL",
    "[+] Found 23 LDAP objects",
    "[!] LDAP: do NOT cache credentials to disk",
    "[✓] LDAP complete",
    "[+] FTP anonymous login allowed",
    "[+] FTP: found backup.zip in /pub",
    "[✓] FTP complete",
    "[-] WEB feroxbuster starting on port 80...",
    "[+] WEB /admin (302 → /login)",
    "[+] WEB /api/v1 (200)",
    "[!] WEB potential SQLi parameter: ?id=",
    "[✓] WEB complete",
    "[-] NFS exports: /data (everyone)",
    "[!] NFS no_root_squash on /data",
    "[✓] NFS complete",
]

_DEMO_HINTS = [
    ("AS-REP Roast",
     "impacket-GetNPUsers CORP/ -usersfile valid_users.txt -no-pass -dc-ip 10.10.10.5"),
    ("Kerberoast (needs creds)",
     "impacket-GetUserSPNs CORP/user:pass -dc-ip 10.10.10.5 -request"),
    ("SMB null session",
     "smbclient -L //10.10.10.5 -N"),
    ("NFS mount",
     "sudo mount -t nfs 10.10.10.5:/data /mnt/nfs && ls -la /mnt/nfs"),
]


def run_demo() -> None:
    """
    Simulate a live ARGUS session without any real commands.
    Cycles through fake log lines and module state transitions.
    """
    q: queue.Queue = queue.Queue()

    tui = ArgusUI(
        tui_queue=q,
        target="10.10.10.5",
        domain="CORP.LOCAL",
    )
    tui.start()

    try:
        idx = 0
        mod_idx = 0
        hint_idx = 0
        modules = list(_DEMO_MODULES)

        # Seed initial log
        q.put("[-] ARGUS demo mode — simulating live scan output")
        time.sleep(0.5)

        # Mark RECON as running
        q.put({
            "type":   CTRL_MODULE_STATUS,
            "module": "recon",
            "state":  "running",
        })
        time.sleep(1.0)

        # Stream fake log lines; advance modules periodically
        lines_per_module = max(1, len(_DEMO_LINES) // len(modules))
        line_counter = 0

        for line in _DEMO_LINES:
            if not tui._running:
                break
            q.put(line)
            time.sleep(random.uniform(0.3, 1.1))

            line_counter += 1
            if line_counter % lines_per_module == 0 and mod_idx < len(modules):
                # Mark previous module done
                if mod_idx > 0:
                    q.put({
                        "type":   CTRL_MODULE_STATUS,
                        "module": modules[mod_idx - 1],
                        "state":  "done",
                    })
                # Start next module
                if mod_idx < len(modules):
                    q.put({
                        "type":   CTRL_MODULE_STATUS,
                        "module": modules[mod_idx],
                        "state":  "running",
                    })
                    mod_idx += 1

            # Drop a hint every few lines
            if line_counter % 6 == 0 and hint_idx < len(_DEMO_HINTS):
                lbl, cmd = _DEMO_HINTS[hint_idx]
                q.put({"type": CTRL_HINT, "label": lbl, "command": cmd})
                hint_idx += 1

        # Finish remaining modules
        for i in range(mod_idx, len(modules)):
            if not tui._running:
                break
            q.put({"type": CTRL_MODULE_STATUS, "module": modules[i], "state": "done"})
            time.sleep(0.2)

        q.put({"type": CTRL_DONE})

        # Keep running until Q pressed
        while tui._running:
            time.sleep(0.1)

    except KeyboardInterrupt:
        pass
    finally:
        tui.stop()
        tui.print_summary()


# ---------------------------------------------------------------------------
# Entry point — demo mode
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ARGUS TUI — standalone demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  Keys during demo:\n"
            "    H      — toggle hints panel\n"
            "    SPACE  — pause/resume auto-scroll\n"
            "    ↑ / ↓  — scroll when paused\n"
            "    Q      — quit and print summary\n"
        ),
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        required=True,
        help="Run in demo mode (required flag).",
    )
    args = parser.parse_args()

    if args.demo:
        run_demo()
