"""
core/runner.py — Centralized subprocess execution for all enumeration modules.

All modules import and call run_wrapper() instead of maintaining their own
private _exec() functions.  Using Popen with start_new_session=True means the
bash wrapper and every child it spawns (nmap, feroxbuster, gobuster …) share
a single process group — one os.killpg() call reaches all grandchildren on
Ctrl+C, preventing orphaned background scan processes from consuming RAM.

Every command executed (or dry-run previewed) is appended to _commands.log
inside the target directory so the operator has a complete audit trail.
"""

import os
import re
import signal
import subprocess
import threading
import time
from subprocess import PIPE, STDOUT
from datetime import datetime
from pathlib import Path
from typing import Optional

from core.display import (
    info, success, warn, error, pipe, done, console,
    cmd_executed, cmd_output_end, cmd_suggested,
)

# Compiled once — strips all ANSI/VT100 color escape sequences
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mGKHFJA-Z]')

# Feroxbuster output format:
#   STATUS METHOD Nl Nw Nc http://host/path [=> redirect]
# We strip the noisy l/w/c columns and suppress 301→trailing-slash redirects.
_FEROX_LINE_RE = re.compile(
    r'^(\d{3})\s+\w+\s+\d+l\s+\d+w\s+\d+c\s+(https?://\S+?)(?:\s+=>\s+(\S+))?$'
)


def _append_commands_log(session, display: str, dry_run: bool) -> None:
    """Append one command line to <target_dir>/_commands.log."""
    try:
        prefix = "[DRY-RUN]" if dry_run else "[CMD]"
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] {prefix} {display}\n"
        commands_log: Path = session.target_dir / "_commands.log"
        with commands_log.open("a", encoding="utf-8") as fh:
            fh.write(line)
    except Exception:
        pass  # never let logging failures break a scan


def run_wrapper(
    cmd: list,
    session,
    label: str = "",
    dry_run: bool = False,
    timeout: Optional[int] = None,
) -> int:
    """
    Execute *cmd* in its own process group, stream output to the terminal,
    and return the exit code.

    On KeyboardInterrupt the entire process group is terminated (SIGTERM,
    escalating to SIGKILL after 5 s) and the exception is re-raised so the
    caller can decide how to react (e.g. web.py skips to the next port;
    other modules let it propagate to the engine).

    Every invocation is logged to <target_dir>/_commands.log regardless of
    the dry_run flag so the operator always has a full audit trail.

    Args:
        cmd:     Command list passed to Popen (e.g. ["bash", "wrapper.sh", ...]).
        session: Active Session object — session.log is used for all output.
        label:   Human-readable name for warning messages (defaults to cmd[0]).
        dry_run: If True, log the command but do not execute it.
        timeout: Optional hard timeout in seconds.  The process group is killed
                 and -2 is returned if the subprocess exceeds this limit.
                 None means no timeout (default behaviour).

    Returns:
        Exit code of the subprocess, or -1 if the binary was not found,
        or -2 if the timeout was exceeded.
        Returns 0 immediately when dry_run is True.
    """
    log = session.log
    display = " ".join(str(c) for c in cmd)
    prefix  = "[DRY-RUN]" if dry_run else "[CMD]"
    log.info("%s %s", prefix, display)
    # Boxed [CMD EXECUTED] marker — replaces the old inline [CMD] print
    from rich.markup import escape as _esc
    cmd_executed(display)

    # Always write to _commands.log — even dry-run previews are useful
    _append_commands_log(session, display, dry_run)

    # Use session.module_timeout as fallback when no explicit timeout given
    if timeout is None:
        timeout = getattr(session, "module_timeout", None)

    if dry_run:
        cmd_output_end()  # close the box we opened above
        return 0

    proc: Optional[subprocess.Popen] = None
    _timed_out = False

    def _timeout_killer():
        """Background thread: kill process group when timeout expires."""
        nonlocal _timed_out
        _timed_out = True
        warn(
            f"{label or cmd[0]} exceeded {timeout}s timeout — killing process group"
        )
        log.warning(
            "%s exceeded %ds timeout — killing process group",
            label or cmd[0], timeout,
        )
        _kill_proc_group(proc, log)

    _last_int_time: float = 0.0   # tracks first Ctrl+C time for this invocation

    # Mutable container so the nested _display_line can update "box open" state.
    # When True, a [CMD EXECUTED] box is open and its output is being streamed;
    # the next [CMD] (or EOF / [*] step header) must close it with a separator.
    _cmd_state = {"active": True}  # wrapper itself opened a box on launch

    # Suggestion buffer — accumulates [MANUAL]/[SUGGESTED] header + every
    # indented marker-less continuation line that follows, so a multi-line
    # bash `hint "..."` heredoc renders as one [SUGGESTED] block.
    _sug_buffer: list = []

    def _close_cmd_box_if_open() -> None:
        if _cmd_state["active"]:
            cmd_output_end()
            _cmd_state["active"] = False

    def _flush_suggestions() -> None:
        # Fix #3: drop empty strings so a bare [MANUAL] never prints an
        # empty yellow header.
        cmds = [s for s in _sug_buffer if s.strip()]
        _sug_buffer.clear()
        if cmds:
            cmd_suggested(cmds)

    def _display_line(line: str) -> None:
        from rich.markup import escape as _esc
        # Strip ANSI escape codes (e.g. ssh-audit colour output)
        clean    = _ANSI_RE.sub('', line)
        stripped = clean.lstrip()
        has_indent = clean != stripped  # leading whitespace present?

        # ── Multi-line [SUGGESTED] buffering ──────────────────────────
        # Rule:
        #   * [MANUAL]/[SUGGESTED] marker  → start/append to buffer.
        #   * Indented, marker-less line while buffer open → continuation.
        #   * Anything else → flush buffer first, then handle normally.
        if stripped.startswith("[MANUAL]"):
            _close_cmd_box_if_open()
            content = stripped[8:].strip()
            if content:
                _sug_buffer.append(content)
            return
        if stripped.startswith("[SUGGESTED]"):
            _close_cmd_box_if_open()
            content = stripped[11:].strip()
            if content:
                _sug_buffer.append(content)
            return
        if _sug_buffer and has_indent and not stripped.startswith("["):
            # Indented continuation of the current hint block
            if stripped:
                _sug_buffer.append(stripped)
            return
        # Any other line ends the suggestion block
        _flush_suggestions()

        if stripped.startswith("[+]"):
            success(stripped[3:].strip())
        elif stripped.startswith("[!]"):
            warn(stripped[3:].strip())
        elif stripped.startswith("[-]"):
            console.print(f"  [red][-][/red] [dim]{_esc(stripped[3:].strip())}[/dim]")
        elif stripped.startswith("[*]"):
            content = stripped[3:].strip()
            # Step header: [N/X] or [N.M/X] — close any open cmd box and
            # render as visual separator rule, padded with blank lines for
            # readability (B2).
            if re.match(r'\[\d+\.?\d*/\d+\]', content):
                _close_cmd_box_if_open()
                console.print()
                console.rule(f"[bold cyan] {_esc(content)} [/bold cyan]", style="cyan")
                console.print()
            else:
                info(content)
        elif stripped.startswith("[CMD]"):
            # Close previous box (if any), then open a new [CMD EXECUTED] box
            _close_cmd_box_if_open()
            cmd_executed(stripped[5:].strip())
            _cmd_state["active"] = True
        elif stripped.startswith("[SKIP]"):
            console.print(f"  [dim][SKIP][/dim] {_esc(stripped[6:].strip())}")
        elif stripped.startswith("[✓]"):
            done(stripped[3:].strip())
        else:
            plain = clean.strip()
            # Highlight nmap open port lines in green/bold
            if re.match(r'\d+/(tcp|udp)\s+open\s+', plain):
                console.print(f"  [bold green]{_esc(plain)}[/bold green]")
            else:
                # Reformat feroxbuster result lines — strip noisy l/w/c columns
                fm = _FEROX_LINE_RE.match(plain)
                if fm:
                    status, url, redirect = fm.group(1), fm.group(2), fm.group(3)
                    # Suppress 301/302 redirects to the same path + trailing slash
                    if redirect and status in ("301", "302"):
                        url_norm    = url.rstrip("/")
                        redir_norm  = redirect.rstrip("/")
                        if url_norm == redir_norm:
                            return   # trailing-slash self-redirect — silent
                    parts = f"{status} {url}"
                    if redirect:
                        parts += f" => {redirect}"
                    pipe(parts)
                else:
                    pipe(plain)   # plain tool output — dim, no prefix
        log.debug("wrapper: %s", clean)

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=PIPE,
            stderr=STDOUT,
            text=True,
            start_new_session=True,
        )

        timer: Optional[threading.Timer] = None
        if timeout is not None:
            timer = threading.Timer(timeout, _timeout_killer)
            timer.daemon = True
            timer.start()

        try:
            # Outer while-loop allows re-entering the read loop after a skip.
            # On first Ctrl+C  → send SIGINT to the wrapper's process group,
            #                    let bash's trap skip the step, continue reading.
            # On second Ctrl+C → send SIGTERM to kill everything, re-raise.
            _stdout_done = False
            while not _stdout_done:
                try:
                    for raw_line in proc.stdout:  # type: ignore[union-attr]
                        # Preserve leading whitespace so multi-line [MANUAL]
                        # continuations (indented, marker-less) can be detected.
                        line = raw_line.rstrip("\r\n")
                        if line.strip():
                            _display_line(line)
                    _stdout_done = True  # EOF reached — wrapper finished normally
                except KeyboardInterrupt:
                    now = time.monotonic()
                    if now - _last_int_time < 5.0:
                        # Second Ctrl+C within 5 s — abort the whole module
                        warn(
                            f"Second Ctrl+C — aborting {label or cmd[0]} entirely"
                        )
                        log.warning(
                            "Second Ctrl+C — killing process group for %s",
                            label or cmd[0],
                        )
                        _kill_proc_group(proc, log)
                        raise  # propagates to outer except → re-raises to engine
                    else:
                        # First Ctrl+C — skip current step, continue to next
                        _last_int_time = now
                        warn(
                            f"Ctrl+C — skipping current step "
                            f"(press again within 5s to abort {label or cmd[0]})"
                        )
                        log.info(
                            "First Ctrl+C for %s — sending SIGINT to wrapper pgroup (step skip)",
                            label or cmd[0],
                        )
                        _sigint_proc_group(proc, log)
                        # Loop continues: keep reading stdout from the next step
            proc.wait()
        finally:
            if timer is not None:
                timer.cancel()
            # Flush any pending [SUGGESTED] block and close the box still
            # open when the wrapper ends.
            _flush_suggestions()
            _close_cmd_box_if_open()

        if _timed_out:
            return -2

        rc = proc.returncode if proc.returncode is not None else 0
        # Exit code 130 = killed by SIGINT (user skipped last step) — treat as OK
        if rc not in (0, 130):
            warn(f"{label or cmd[0]} exited with code {rc}")
            log.warning("%s exited with code %d", label or cmd[0], rc)
        return 0 if rc == 130 else rc
    except KeyboardInterrupt:
        _flush_suggestions()
        _close_cmd_box_if_open()
        _kill_proc_group(proc, log)
        raise
    except FileNotFoundError:
        _flush_suggestions()
        _close_cmd_box_if_open()
        error(f"Command not found: {cmd[0]}")
        log.error("Command not found: %s", cmd[0])
        return -1


def _kill_proc_group(proc: Optional[subprocess.Popen], log) -> None:
    """
    Terminate a Popen process and its entire process group.

    Because wrappers are launched with start_new_session=True, the bash
    script and every child it spawned share one process group ID.
    os.killpg() reaches all of them in one call, preventing orphaned
    background processes from consuming RAM.

    Falls back to proc.terminate() on Windows (no killpg) or if the
    process group is gone by the time we try.
    """
    if proc is None or proc.poll() is not None:
        return  # already exited — nothing to do

    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGTERM)
        log.info("Sent SIGTERM to process group %d", pgid)
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        # Still running after 5 s — escalate to SIGKILL
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGKILL)
            log.warning("Process group %d did not exit cleanly — SIGKILL sent", pgid)
        except (ProcessLookupError, PermissionError):
            pass  # process group already gone
        proc.wait()
    except (ProcessLookupError, PermissionError, AttributeError):
        # Windows, or process already exited between poll() and getpgid()
        proc.terminate()


def _sigint_proc_group(proc: Optional[subprocess.Popen], log) -> None:
    """
    Send SIGINT to the wrapper's process group to interrupt only the currently
    running step.  The bash wrapper's INT trap catches this, prints a skip
    message, and continues to the next step.

    Unlike _kill_proc_group() (which sends SIGTERM to terminate everything),
    this function sends SIGINT so bash can handle it gracefully.
    """
    if proc is None or proc.poll() is not None:
        return  # already exited

    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGINT)
        log.info("Sent SIGINT to process group %d (step skip)", pgid)
    except (ProcessLookupError, PermissionError):
        pass  # process group already gone — nothing to do
    except AttributeError:
        # Windows fallback — no killpg
        try:
            proc.send_signal(signal.SIGINT)
        except (ProcessLookupError, PermissionError):
            pass
