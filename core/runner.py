"""
core/runner.py — Centralized subprocess execution for all enumeration modules.

All modules import and call run_wrapper() instead of maintaining their own
private _exec() functions.  Using Popen with start_new_session=True means the
bash wrapper and every child it spawns (nmap, feroxbuster, gobuster …) share
a single process group — one os.killpg() call reaches all grandchildren on
Ctrl+C, preventing orphaned background scan processes from consuming RAM.
"""

import os
import signal
import subprocess
from subprocess import PIPE, STDOUT
from typing import Optional

from core.display import info, success, warn, error


def run_wrapper(
    cmd: list,
    session,
    label: str = "",
    dry_run: bool = False,
) -> int:
    """
    Execute *cmd* in its own process group, stream output to the terminal,
    and return the exit code.

    On KeyboardInterrupt the entire process group is terminated (SIGTERM,
    escalating to SIGKILL after 5 s) and the exception is re-raised so the
    caller can decide how to react (e.g. web.py skips to the next port;
    other modules let it propagate to the engine).

    Args:
        cmd:     Command list passed to Popen (e.g. ["bash", "wrapper.sh", ...]).
        session: Active Session object — session.log is used for all output.
        label:   Human-readable name for warning messages (defaults to cmd[0]).
        dry_run: If True, log the command but do not execute it.

    Returns:
        Exit code of the subprocess, or -1 if the binary was not found.
        Returns 0 immediately when dry_run is True.
    """
    log = session.log
    display = " ".join(str(c) for c in cmd)
    prefix  = "[DRY-RUN]" if dry_run else "[CMD]"
    log.info("%s %s", prefix, display)
    info(f"> {display}")

    if dry_run:
        return 0

    proc: Optional[subprocess.Popen] = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=PIPE,
            stderr=STDOUT,
            text=True,
            start_new_session=True,
        )
        for raw_line in proc.stdout:  # type: ignore[union-attr]
            line = raw_line.strip()
            if line:
                if line.startswith("[+]"):
                    success(line[3:].strip())
                elif line.startswith("[!]"):
                    warn(line[3:].strip())
                else:
                    info(line)
                log.debug("wrapper: %s", line)
        proc.wait()

        rc = proc.returncode if proc.returncode is not None else 0
        if rc != 0:
            warn(f"{label or cmd[0]} exited with code {rc}")
            log.warning("%s exited with code %d", label or cmd[0], rc)
        return rc
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
