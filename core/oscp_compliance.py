"""
core/oscp_compliance.py — OSCP exam-rule compliance helpers

OffSec restricts certain tools during the OSCP exam:
  - Metasploit / Meterpreter / msfvenom: limited to ONE target machine (AD set
    counts as one). Using it on a second machine → automatic fail.
  - SQLMap: entirely prohibited.
  - LLM chatbots (ChatGPT, Claude, Gemini, etc.): prohibited during the exam.

This module provides:
  - RESTRICTED_TOOLS: canonical set of tool names to watch for
  - check_command(cmd): (is_restricted, tool_name) detector
  - MANUAL_SQLI_GUIDE: replacement snippet for sqlmap usage
  - EXAM_REMINDER: multi-line reminder text
  - print_reminder(console): render the reminder with rich formatting

Reference: https://help.offsec.com/hc/en-us/articles/360040165632
"""

import re
from typing import Optional, Tuple

from rich.console import Console
from rich.panel import Panel

RESTRICTED_TOOLS = {"msfconsole", "meterpreter", "msfvenom", "sqlmap"}

MANUAL_SQLI_GUIDE = (
    "SQLi manual (sqlmap prohibited in OSCP):\n"
    "  - UNION-based: ?id=1 UNION SELECT 1,2,3,@@version--\n"
    "  - Boolean blind: ?id=1 AND 1=1-- vs ?id=1 AND 1=2--\n"
    "  - Time-based: ?id=1 AND SLEEP(5)--"
)

EXAM_REMINDER = (
    "OSCP EXAM COMPLIANCE REMINDER:\n"
    "  • Metasploit / Meterpreter / msfvenom: max 1 target machine\n"
    "    (AD set counts as ONE machine, not three)\n"
    "  • SQLMap: PROHIBITED entirely — use manual UNION/boolean/time-based\n"
    "  • No LLM chatbots during exam (ChatGPT, Claude, Gemini, etc.)\n"
    "  • Reference: https://help.offsec.com/hc/en-us/articles/360040165632"
)


def check_command(cmd: str) -> Tuple[bool, Optional[str]]:
    """
    Inspect a command string for OSCP-restricted tool names.

    Returns (True, tool_name) if any restricted tool appears as a standalone
    token, else (False, None). Match is case-insensitive; only whole-word
    tokens trigger (so '/usr/share/wordlists/metasploit/unix_users.txt' does
    NOT flag — that path is a wordlist, not an MSF invocation).
    """
    if not cmd:
        return (False, None)

    low = cmd.lower()
    for tool in RESTRICTED_TOOLS:
        if re.search(rf"\b{re.escape(tool)}\b", low):
            return (True, tool)
    return (False, None)


def print_reminder(console: Console) -> None:
    """Render the OSCP compliance reminder as a yellow-bordered panel."""
    console.print()
    console.print(
        Panel(
            EXAM_REMINDER,
            title="[bold yellow] ⚠️  OSCP EXAM COMPLIANCE [/bold yellow]",
            border_style="yellow",
            padding=(1, 2),
        )
    )
    console.print()
