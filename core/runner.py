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
import signal
import subprocess
import threading
import time
from subprocess import PIPE, STDOUT
from datetime import datetime
from pathlib import Path
from typing import Optional

from core.display import info, success, warn, error


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
    info(f"> {display}")

    # Always write to _commands.log — even dry-run previews are useful
    _append_commands_log(session, display, dry_run)

    # Use session.module_timeout as fallback when no explicit timeout given
    if timeout is None:
        timeout = getattr(session, "module_timeout", None)

    if dry_run:
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

    def _display_line(line: str) -> None:
        if line.startswith("[+]"):
            success(line[3:].strip())
        elif line.startswith("[!]"):
            warn(line[3:].strip())
        elif line.startswith("[-]"):
            info(line[3:].strip())
        else:
            info(line)
        log.debug("wrapper: %s", line)

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
                        line = raw_line.strip()
                        if line:
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

        if _timed_out:
            return -2

        rc = proc.returncode if proc.returncode is not None else 0
        # Exit code 130 = killed by SIGINT (user skipped last step) — treat as OK
        if rc not in (0, 130):
            warn(f"{label or cmd[0]} exited with code {rc}")
            log.warning("%s exited with code %d", label or cmd[0], rc)
        return 0 if rc == 130 else rc
    except KeyboardInterrupt:
        _kill_proc_group(proc, log)
        raise
    except FileNotFoundError:
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
