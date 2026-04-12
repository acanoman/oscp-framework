"""
ui/__init__.py — ARGUS Terminal User Interface package.

Public exports:
    ArgusUI  — main TUI class (runs in its own thread)
    run_demo — standalone demo runner (see tui.py --demo)

Queue message protocol (pass dicts or strings to tui_queue):
    str  → raw log line, timestamped on receipt
    dict → control message; keys: "type", plus type-specific fields

Control message types (use the CTRL_* constants from tui.py or raw strings):
    "module_status"  {"module": str, "state": "pending|running|done"}
    "hint"           {"label": str, "command": str}
    "set_module"     {"module": str}
    "set_domain"     {"domain": str}
    "done"           {}   ← marks the session complete
    "quit"           {}   ← stops the TUI thread

Quick-start example:
    import queue
    from ui import ArgusUI

    tui_q = queue.Queue()
    tui = ArgusUI(tui_q, target="10.10.10.5", domain="CORP.LOCAL")
    tui.start()

    tui_q.put("[+] nmap found port 445 open")
    tui_q.put({"type": "module_status", "module": "smb", "state": "running"})
    tui_q.put({"type": "hint",
               "label": "SMB null session",
               "command": "smbclient -L //10.10.10.5 -N"})
    tui_q.put({"type": "module_status", "module": "smb", "state": "done"})
    tui_q.put({"type": "done"})

    # ... engine work ...

    tui.stop()
    tui.print_summary()
"""

from ui.tui import ArgusUI, run_demo  # noqa: F401
