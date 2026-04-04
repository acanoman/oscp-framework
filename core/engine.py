"""
core/engine.py — Main orchestrator

Responsibilities:
  - TTL-based OS detection before recon
  - Run initial Nmap recon via wrappers/recon.sh
  - Parse open ports from Nmap XML output
  - Decide which modules to invoke based on discovered ports
  - Invoke modules (each calls its bash wrapper)
  - Hand findings to the Recommender and print next-step guidance

OSCP compliance:
  - NO automatic exploitation
  - NO autopwn logic
  - Prints every command before it runs (full transparency)
  - User can abort at any stage (Ctrl-C)
"""

import importlib
import os
import re
import subprocess
import platform
import time
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console
from rich.panel import Panel

from core.session import Session, TargetInfo
from core.parser import NmapParser
from core.recommender import Recommender


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _format_elapsed(seconds: float) -> str:
    """Return a human-readable elapsed-time string, e.g. '12m 04s' or '47s'."""
    total = int(seconds)
    mins  = total // 60
    secs  = total % 60
    return f"{mins}m {secs:02d}s" if mins else f"{secs}s"


# ---------------------------------------------------------------------------
# Service-name → module routing (PRIMARY — uses Nmap service detection)
#
# Keys are lowercase Nmap service strings exactly as they appear in XML
# output (with ssl/ prefix variants and common aliases included).
# ---------------------------------------------------------------------------

SERVICE_MODULE_MAP: Dict[str, str] = {
    # ── Web ─────────────────────────────────────────────────────────────
    "http":               "web",
    "https":              "web",
    "http-proxy":         "web",
    "http-alt":           "web",
    "http?":              "web",
    "ssl/http":           "web",
    "ssl/https":          "web",
    "ssl/http-proxy":     "web",
    "ssl/http-alt":       "web",
    # ── FTP ─────────────────────────────────────────────────────────────
    "ftp":                "ftp",
    "ftp-data":           "ftp",
    "ftps":               "ftp",
    "ssl/ftp":            "ftp",
    # ── SMB / NetBIOS ───────────────────────────────────────────────────
    "microsoft-ds":       "smb",
    "netbios-ssn":        "smb",
    "netbios-ns":         "smb",
    "smb":                "smb",
    # ── LDAP / Active Directory ─────────────────────────────────────────
    "ldap":               "ldap",
    "ldapssl":            "ldap",
    "ssl/ldap":           "ldap",
    "globalcatldap":      "ldap",
    "globalcatldapssl":   "ldap",
    # ── DNS ─────────────────────────────────────────────────────────────
    "domain":             "dns",
    "dns":                "dns",
    "mdns":               "dns",
    # ── SNMP ────────────────────────────────────────────────────────────
    "snmp":               "snmp",
    "snmptrap":           "snmp",
    # ── NFS / RPC ───────────────────────────────────────────────────────
    "nfs":                "nfs",
    "rpcbind":            "nfs",
    "mountd":             "nfs",
    "nlockmgr":           "nfs",
    # ── Databases ───────────────────────────────────────────────────────
    "ms-sql-s":           "databases",   # MSSQL
    "ms-sql-m":           "databases",   # MSSQL monitor
    "mysql":              "databases",
    "postgresql":         "databases",
    "redis":              "databases",
    "mongodb":            "databases",
    "couchdb":            "databases",
    "elasticsearch":      "databases",
    "cassandra":          "databases",
    "ssl/ms-sql-s":       "databases",
    # ── Remote Access ───────────────────────────────────────────────────
    "ms-wbt-server":      "remote",      # RDP
    "rdp":                "remote",
    "wsman":              "remote",      # WinRM HTTP
    "wsmans":             "remote",      # WinRM HTTPS
    "ssl/wsman":          "remote",
    "vnc":                "remote",
    "ssl/vnc":            "remote",
    # ── Mail ────────────────────────────────────────────────────────────
    "smtp":               "mail",
    "smtps":              "mail",
    "ssl/smtp":           "mail",
    "submission":         "mail",        # port 587
    "pop3":               "mail",
    "pop3s":              "mail",
    "ssl/pop3":           "mail",
    "imap":               "mail",
    "imaps":              "mail",
    "ssl/imap":           "mail",
    # ── MSRPC / RPC Endpoint Mapper ─────────────────────────────────────
    "msrpc":              "services",
    "epmap":              "services",   # Nmap alternate name for 135
    "microsoft-rpc":      "services",
    # ── Generic services ────────────────────────────────────────────────
    "ssh":                "services",
    "telnet":             "services",
}

# ---------------------------------------------------------------------------
# Port-number fallback map (SECONDARY — used when Nmap service is "unknown"
# or missing; catches services running on their well-known port even when
# version detection failed)
# ---------------------------------------------------------------------------

_PORT_FALLBACK_MAP: Dict[int, str] = {
    # ── Tier 1 ──────────────────────────────────────────────────────────
    21:    "ftp",
    22:    "services",
    23:    "services",   # Telnet
    53:    "dns",
    135:   "services",   # MSRPC / RPC Endpoint Mapper
    111:   "nfs",
    139:   "smb",
    161:   "snmp",
    162:   "snmp",
    389:   "ldap",
    445:   "smb",
    636:   "ldap",
    2049:  "nfs",
    3268:  "ldap",
    3269:  "ldap",
    # ── Tier 2 ──────────────────────────────────────────────────────────
    25:    "mail",
    110:   "mail",
    143:   "mail",
    465:   "mail",
    587:   "mail",
    993:   "mail",
    995:   "mail",
    1433:  "databases",
    3306:  "databases",
    3389:  "remote",
    5432:  "databases",
    5900:  "remote",
    5984:  "databases",
    5985:  "remote",
    5986:  "remote",
    6379:  "databases",
    9200:  "databases",
    27017: "databases",
    # ── Tier 3 ──────────────────────────────────────────────────────────
    80:    "web",
    443:   "web",
    8000:  "web",
    8008:  "web",
    8080:  "web",
    8443:  "web",
    8888:  "web",
    9090:  "web",
}


def _svc_to_module(service: str) -> Optional[str]:
    """
    Resolve a raw Nmap service string to a module name.

    Normalisation steps applied before dict lookup:
      1. Strip whitespace and lowercase
      2. Exact match against SERVICE_MODULE_MAP
      3. Strip trailing '?' (Nmap uncertainty marker) and retry
      4. Strip leading 'ssl/' and retry (catches ssl/foo variants not
         explicitly listed)

    Returns None if no mapping exists.
    """
    svc = service.strip().lower()

    if svc in SERVICE_MODULE_MAP:
        return SERVICE_MODULE_MAP[svc]

    # Remove Nmap uncertainty marker
    svc_clean = svc.rstrip("?")
    if svc_clean in SERVICE_MODULE_MAP:
        return SERVICE_MODULE_MAP[svc_clean]

    # ssl/foo → try bare foo (handles unlisted ssl/ variants)
    if svc_clean.startswith("ssl/"):
        bare = svc_clean[4:]
        if bare in SERVICE_MODULE_MAP:
            return SERVICE_MODULE_MAP[bare]

    return None

# Map module name → Python module path  (imported lazily to avoid circular deps)
MODULE_REGISTRY = {
    # Tier 1
    "smb":       "modules.smb",
    "ftp":       "modules.ftp",
    "ldap":      "modules.ldap",
    "dns":       "modules.dns",
    "snmp":      "modules.snmp",
    "nfs":       "modules.nfs",
    "services":  "modules.services",
    # Tier 2
    "databases": "modules.databases",
    "remote":    "modules.remote",
    "mail":      "modules.mail",
    # Tier 3
    "web":       "modules.web",
    # Utility
    "network":   "modules.network",
}

WRAPPERS_DIR = Path(__file__).resolve().parent.parent / "wrappers"

# ---------------------------------------------------------------------------
# Strict 3-Tier execution order
#   Tier 1 — Lightning Fast : smb, ftp, ldap, dns, snmp, nfs, services
#   Tier 2 — Medium         : databases, remote, mail
#   Tier 3 — Heavy          : web  (ALWAYS runs last)
# ---------------------------------------------------------------------------

MODULE_TIERS: Dict[str, int] = {
    # ── Tier 1 — Lightning Fast ──────────────────────────────────────────
    "smb":       1,
    "ftp":       1,
    "ldap":      1,
    "dns":       1,
    "snmp":      1,
    "nfs":       1,
    "services":  1,
    "network":   1,
    # ── Tier 2 — Medium ──────────────────────────────────────────────────
    "databases": 2,
    "remote":    2,
    "mail":      2,
    # ── Tier 3 — Heavy (always last) ─────────────────────────────────────
    "web":       3,
}
_DEFAULT_TIER = 1  # unknown modules are treated as Tier 1 (fast)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class Engine:
    """
    Orchestrates the full enumeration lifecycle for a single target.

    Flow
    ----
    1. Initialize Session (dirs, logging, state)
    2. TTL-based OS detection (single ping)
    3. Run initial Nmap scan via recon.sh wrapper
    4. Parse open ports from Nmap XML
    5. Determine which modules to run (auto or forced)
    6. Run each module (each invokes its bash wrapper)
    7. Feed findings to Recommender → print guidance
    8. Write final structured notes.md
    9. Persist state
    """

    def __init__(
        self,
        target:         str,
        domain:         str         = "",
        output_base:    str         = "output/targets",
        dry_run:        bool        = False,
        verbose:        bool        = False,
        forced_modules: Optional[List[str]] = None,
        lhost:          str         = "",
        resume:         bool        = False,
    ) -> None:
        self.target         = target
        self.domain         = domain
        self.dry_run        = dry_run
        self.verbose        = verbose
        self.forced_modules = forced_modules or []
        self.lhost          = lhost
        self.resume         = resume

        # Timing — set at the start of _run_inner()
        self._run_start: float = 0.0
        # PID of the background NSE vuln scan written by recon.sh
        self._vuln_pid: Optional[int] = None

        self.console = Console()
        self.session    = Session(
            target, domain, output_base, verbose,
            lhost=lhost, resume=resume,
        )
        self.info: TargetInfo = self.session.info
        self.log        = self.session.log
        self.recommender = Recommender(self.info, self.log, self.console)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        try:
            self._run_inner()
        except KeyboardInterrupt:
            self.console.print()
            self.console.rule(
                "[bold yellow] ⚠️  Framework interrupted by user — flushing notes [/bold yellow]",
                style="yellow",
            )
            self.console.print()
            self.log.warning("Framework interrupted by user during setup/recon phase")
            self.session.finalize_notes()
            self.session.save_state()
            self.console.print(
                f"  [bold yellow][!][/bold yellow] Partial output saved → "
                f"[cyan]{self.session.target_dir}[/cyan]"
            )

    def _run_inner(self) -> None:
        self._run_start = time.time()
        self._banner()
        self._detect_os_ttl()

        # Phase 1 — Nmap initial recon (always runs unless ports already known)
        if not self.info.open_ports:
            self.console.rule("[bold blue] PHASE 1 — INITIAL RECON [/bold blue]")
            self._run_initial_recon()
            self._read_vuln_pid()
        else:
            # Only reachable when --resume loaded a previous session.json
            from rich.panel import Panel as _Panel
            self.console.print(
                _Panel(
                    f"[bold green]Previous session loaded — Nmap skipped.[/bold green]\n"
                    f"[dim]Known ports: {sorted(self.info.open_ports)}[/dim]\n"
                    f"[dim]Delete session.json or omit --resume to start a fresh scan.[/dim]",
                    title="[bold green] ↩️  SESSION RESUMED [/bold green]",
                    border_style="green",
                    padding=(1, 4),
                )
            )
            self.log.info(
                "Skipping Nmap — ports already known from previous session: %s",
                sorted(self.info.open_ports),
            )

        # Phase 2 — Determine modules
        modules_to_run = self._resolve_modules()

        if not modules_to_run:
            self.console.print(
                "[bold yellow][!] No modules to run. "
                "Check open ports or use --modules.[/bold yellow]"
            )
            self.log.warning("No modules to run. Check open ports or use --modules.")
            self.recommender.print_summary()
            self.session.finalize_notes()
            return

        # Phase 3 — Run modules (Tier 1 → Tier 2 → Tier 3, strictly ordered)
        _TIER_RULES = {
            1: (
                "[bold green] TIER 1 — LIGHTNING FAST "
                "(smb · ftp · ldap · dns · snmp · nfs · services) [/bold green]",
                "green",
            ),
            2: (
                "[bold yellow] TIER 2 — MEDIUM "
                "(databases · remote · mail) [/bold yellow]",
                "yellow",
            ),
            3: (
                "[bold red] TIER 3 — HEAVY "
                "(web enumeration — always last) [/bold red]",
                "red",
            ),
        }

        current_tier = 0
        for module_name in modules_to_run:
            tier = MODULE_TIERS.get(module_name, _DEFAULT_TIER)
            if tier != current_tier:
                current_tier = tier
                rule_label, rule_style = _TIER_RULES.get(
                    tier,
                    (f"[bold] TIER {tier} [/bold]", "white"),
                )
                self.console.print()
                self.console.rule(rule_label, style=rule_style)
                self.console.print()
                self.log.info("--- Tier %d modules starting ---", tier)

            module_start = time.time()
            try:
                self._run_module(module_name)
            except KeyboardInterrupt:
                self.console.print()
                self.console.rule(
                    f"[bold yellow] ⚠️  Module [{module_name.upper()}] aborted by user "
                    f"— saving progress and continuing [/bold yellow]",
                    style="yellow",
                )
                self.console.print()
                self.log.warning("Module '%s' interrupted by user (Ctrl+C)", module_name)
                # Flush notes immediately so nothing is lost
                self.session.finalize_notes()
                self.session.save_state()
                continue

            module_elapsed = time.time() - module_start
            self.console.print(
                f"  [bold green][✓][/bold green] [bold]{module_name.upper()}[/bold] "
                f"completed in [cyan]{_format_elapsed(module_elapsed)}[/cyan]"
            )
            self.log.info(
                "Module '%s' completed in %.1fs", module_name, module_elapsed
            )

            # Non-blocking check: alert if the background NSE vuln scan finished
            self._check_vuln_scan()

            # Incremental flush — notes.md is always current after each module
            self.session.finalize_notes()
            self.session.save_state()

        # Phase 4 — Recommendations + final report
        self.recommender.print_summary()
        self.session.finalize_notes()   # Final flush with recommender additions
        self.session.save_state()

        # Final vuln scan check (handles the case where it finishes during the
        # last module but the check hasn't fired yet)
        self._check_vuln_scan()

        total_elapsed = time.time() - self._run_start
        self.console.print(
            f"\n  [bold green][✓][/bold green] Session complete in "
            f"[bold cyan]{_format_elapsed(total_elapsed)}[/bold cyan] → "
            f"[cyan]{self.session.target_dir}[/cyan]"
        )
        self.log.info(
            "Session complete in %.1fs. Output: %s", total_elapsed, self.session.target_dir
        )

    # ------------------------------------------------------------------
    # Internal phases
    # ------------------------------------------------------------------

    def _detect_os_ttl(self) -> None:
        """Send one ICMP ping, read TTL, infer OS, update session.info.os_guess."""
        if platform.system() == "Windows":
            ping_cmd = ["ping", "-n", "1", "-w", "2000", self.target]
        else:
            ping_cmd = ["ping", "-c", "1", "-W", "2", self.target]

        try:
            with self.console.status(
                "[bold cyan]⏳ OS detection via TTL ping...[/bold cyan]",
                spinner="dots",
            ):
                result = subprocess.run(
                    ping_cmd,
                    capture_output=True,
                    text=True,
                    timeout=6,
                    check=False,
                )

            output = result.stdout + result.stderr
            match = re.search(r"[Tt][Tt][Ll]=(\d+)", output)

            if match:
                ttl = int(match.group(1))
                if ttl <= 64:
                    guess, color = "Linux", "green"
                elif ttl <= 128:
                    guess, color = "Windows", "cyan"
                else:
                    guess, color = "Network Device", "yellow"

                self.info.os_guess = guess
                # Coarse os_type from TTL — parser.py may refine this later
                # with a more precise Nmap OS match string.
                if guess in ("Linux", "Windows") and not self.info.os_type:
                    self.info.os_type = guess
                self.console.print(
                    f"  [bold green][+][/bold green] TTL={ttl} → "
                    f"OS Guess: [bold {color}]{guess}[/bold {color}]"
                )
                self.session.add_note(f"OS guess via TTL: {guess} (TTL={ttl})")
                self.log.info("OS guess: %s (TTL=%d)", guess, ttl)
            else:
                self.console.print(
                    "  [bold yellow][!][/bold yellow] No ping response — "
                    "target may block ICMP. Scans will use -Pn."
                )
                self.log.warning("TTL detection: no ping response from %s", self.target)

        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.console.print(
                "  [bold yellow][!][/bold yellow] TTL ping failed (ping not available)"
            )

        self.console.print()

    def _run_initial_recon(self) -> None:
        """
        Call wrappers/recon.sh for initial Nmap discovery.
        Wrapper writes XML to output/targets/<IP>/scans/nmap_initial.xml
        """
        self.log.info("=" * 60)
        self.log.info("PHASE 1 — Initial Nmap Recon")
        self.log.info("=" * 60)

        script = WRAPPERS_DIR / "recon.sh"

        cmd = [
            "bash", str(script),
            "--target",     self.target,
            "--output-dir", str(self.session.target_dir),
        ]
        if self.domain:
            cmd += ["--domain", self.domain]

        self._exec(cmd, label="Initial Nmap scan")

        # recon.sh writes XML to scans/nmap_initial.xml
        nmap_xml = self.session.path("scans", "nmap_initial.xml")

        # Parse results into session info
        if nmap_xml.exists():
            parser = NmapParser(self.log)
            parser.parse_xml(nmap_xml, self.info)
            self.log.info(
                "Discovered %d open port(s): %s",
                len(self.info.open_ports),
                sorted(self.info.open_ports),
            )
            self.session.add_note(
                f"Nmap found ports: {sorted(self.info.open_ports)}"
            )

            # Auto-detect Domain Controller from port fingerprint:
            # Kerberos (88) + any LDAP variant is a near-certain DC indicator.
            if (
                not self.info.is_domain_controller
                and 88 in self.info.open_ports
                and self.info.open_ports & {389, 636, 3268, 3269}
            ):
                self.info.is_domain_controller = True
                self.log.info(
                    "Domain Controller inferred from port fingerprint "
                    "(Kerberos 88 + LDAP)"
                )
                self.session.add_note(
                    "Domain Controller detected via port fingerprint "
                    "(port 88 + LDAP)"
                )
        else:
            self.console.print(
                f"  [bold yellow][!][/bold yellow] Nmap XML not found at {nmap_xml} "
                "— did recon.sh run correctly?"
            )
            self.log.warning(
                "Nmap XML not found at %s — did recon.sh run correctly?", nmap_xml
            )

    def _read_vuln_pid(self) -> None:
        """
        Read the PID written by recon.sh for the background NSE vuln scan.
        Stored in scans/vulns.pid.  Called once after initial recon completes.
        """
        pid_file = self.session.path("scans", "vulns.pid")
        if not pid_file.exists():
            return
        try:
            self._vuln_pid = int(pid_file.read_text(encoding="utf-8").strip())
            self.log.info(
                "Background NSE vuln scan running (PID %d) — "
                "will alert when it finishes",
                self._vuln_pid,
            )
            self.console.print(
                f"  [dim][*] Background NSE vuln scan running (PID {self._vuln_pid}) "
                f"— you'll be notified when it completes.[/dim]"
            )
        except (ValueError, OSError):
            self._vuln_pid = None

    def _check_vuln_scan(self) -> None:
        """
        Non-blocking poll: if the background NSE vuln scan has finished since
        the last check, print a prominent alert.  Called after every module.
        Uses os.kill(pid, 0) which only tests process existence (no signal sent).
        """
        if self._vuln_pid is None:
            return

        try:
            os.kill(self._vuln_pid, 0)
            # Process is still alive — nothing to do
        except ProcessLookupError:
            old_pid    = self._vuln_pid
            self._vuln_pid = None
            vuln_out   = self.session.path("scans", "vulns.txt")

            self.console.print()
            self.console.rule(
                "[bold yellow] 🔔  DING!  Background NSE Vuln Scan Finished  🔔 [/bold yellow]",
                style="yellow",
            )
            self.console.print(
                f"  [bold white]Check [cyan]{vuln_out}[/cyan] for critical findings.[/bold white]"
            )
            self.console.rule(style="yellow")
            self.console.print()

            self.log.info("Background NSE vuln scan (PID %d) has finished", old_pid)
            self.session.add_note(
                f"[ALERT] Background NSE vuln scan (PID {old_pid}) finished — "
                f"review scans/vulns.txt"
            )
        except (PermissionError, OSError):
            # Process exists but owned by a different UID, or platform doesn't
            # support kill(0) the same way — skip silently.
            pass

    def _resolve_modules(self) -> List[str]:
        """
        Return a tier-sorted list of module names to execute.

        If --modules was passed the user-supplied order is preserved but still
        grouped by tier so Tier-1 modules always run before Tier-2.

        Auto-detection uses a two-pass strategy per port:
          1. SERVICE (primary)  — look up the Nmap-detected service name in
             SERVICE_MODULE_MAP via _svc_to_module().  Catches services on
             non-standard ports (e.g. HTTP on 50000, RDP on 3390).
          2. PORT FALLBACK      — used only when Nmap reported "unknown" or
             returned no service name; consults _PORT_FALLBACK_MAP.

        Both passes are logged so the operator can see exactly which routing
        path fired for every open port.

        Sort key is (tier, original_index) so within a tier the discovery
        order (port-ascending) is maintained.
        """
        if self.forced_modules:
            raw = list(self.forced_modules)
            self.log.info("Using forced module list: %s", raw)
        else:
            raw:  List[str] = []
            seen: set       = set()

            for port in sorted(self.info.open_ports):
                details = self.info.port_details.get(port, {})
                svc_raw = details.get("service", "").strip()
                mod     = None

                # ── Pass 1: service-name routing ────────────────────────
                if svc_raw and svc_raw.lower() not in ("unknown", ""):
                    mod = _svc_to_module(svc_raw)
                    if mod:
                        self.log.info(
                            "Port %-5d service %-22s → %-10s [service-based]",
                            port, f"'{svc_raw}'", mod,
                        )
                    else:
                        self.log.debug(
                            "Port %-5d service %-22s → no mapping; trying port fallback",
                            port, f"'{svc_raw}'",
                        )

                # ── Pass 2: port-number fallback ─────────────────────────
                if mod is None:
                    mod = _PORT_FALLBACK_MAP.get(port)
                    if mod:
                        self.log.info(
                            "Port %-5d service %-22s → %-10s [port-fallback]",
                            port, f"'{svc_raw or 'none'}'", mod,
                        )
                    else:
                        self.log.debug(
                            "Port %-5d service %-22s → no mapping found; skipping",
                            port, f"'{svc_raw or 'none'}'",
                        )

                if mod and mod not in seen:
                    raw.append(mod)
                    seen.add(mod)

        # Stable sort by tier — preserves relative order within each tier
        ordered = sorted(raw, key=lambda m: (MODULE_TIERS.get(m, _DEFAULT_TIER), raw.index(m)))

        self.log.info(
            "Modules selected (tier-sorted): %s", ordered if ordered else ["(none)"]
        )
        return ordered

    def _run_module(self, module_name: str) -> None:
        """Dynamically import and run a module by name."""
        self.console.rule(f"[bold blue] MODULE — {module_name.upper()} [/bold blue]")
        self.log.info("MODULE — %s", module_name.upper())

        if module_name not in MODULE_REGISTRY:
            self.console.print(
                f"  [bold red][✗][/bold red] Unknown module: [yellow]{module_name}[/yellow]"
            )
            self.log.error("Unknown module '%s' — skipping.", module_name)
            return

        try:
            mod = importlib.import_module(MODULE_REGISTRY[module_name])
        except ImportError as exc:
            self.console.print(
                f"  [bold red][✗][/bold red] Cannot import module "
                f"[yellow]{module_name}[/yellow]: {exc}"
            )
            self.log.error("Cannot import module '%s': %s", module_name, exc)
            return

        try:
            mod.run(
                target=self.target,
                session=self.session,
                dry_run=self.dry_run,
            )
        except Exception as exc:
            self.console.print(
                f"  [bold red][✗][/bold red] Module [yellow]{module_name}[/yellow] failed: {exc}"
            )
            self.log.error("Module '%s' failed: %s", module_name, exc)
            if self.verbose:
                raise

    # ------------------------------------------------------------------
    # Command execution
    # ------------------------------------------------------------------

    # Exit codes that indicate a transient network/execution failure and
    # are worth retrying.  127 = shell "command not found" (wrapper may not
    # be executable yet on first run); 255 = SSH-layer / network-level error.
    _RETRYABLE_CODES = {127, 255}
    _RETRY_DELAY     = 5   # seconds between attempts

    def _exec(self, cmd: List[str], label: str = "", retries: int = 1) -> Optional[int]:
        """
        Print the command (always), then optionally execute it.
        Returns the process return code, or None in dry-run mode.

        If the command exits with a retryable error code (127, 255) it is
        retried up to `retries` additional times with a 5-second pause between
        each attempt.  Non-retryable failures and FileNotFoundError are
        reported immediately without retrying.

        KeyboardInterrupt is intentionally NOT caught here — Ctrl+C propagates
        up to the per-module handler in _run_inner() so the user stays in full
        control of when to skip a running tool.
        """
        display = " ".join(str(c) for c in cmd)
        tag = "DRY-RUN" if self.dry_run else "CMD"
        self.log.info("[%s] %s", tag, display)
        self.console.print(f"  [bold yellow][CMD][/bold yellow] {display}")

        if self.dry_run:
            return None

        name         = label or cmd[0]
        attempts     = 1 + max(0, retries)   # total executions
        last_rc: int = -1

        for attempt in range(1, attempts + 1):
            try:
                result  = subprocess.run(cmd, text=True, check=False)
                last_rc = result.returncode

                if last_rc == 0:
                    self.console.print(
                        f"  [bold green][✓][/bold green] {name} complete"
                    )
                    return last_rc

                if last_rc in self._RETRYABLE_CODES and attempt < attempts:
                    self.console.print(
                        f"  [bold yellow][!][/bold yellow] {name} exited with code "
                        f"[yellow]{last_rc}[/yellow] — "
                        f"⚠️  Network/Execution error detected. "
                        f"Retrying in {self._RETRY_DELAY} seconds... "
                        f"(attempt {attempt}/{attempts - 1})"
                    )
                    self.log.warning(
                        "%s exited with retryable code %d (attempt %d/%d) — retrying",
                        name, last_rc, attempt, attempts - 1,
                    )
                    time.sleep(self._RETRY_DELAY)
                    continue

                # Non-retryable failure or final attempt
                self.console.print(
                    f"  [bold yellow][!][/bold yellow] {name} exited with code "
                    f"[yellow]{last_rc}[/yellow]"
                )
                self.log.warning("%s exited with code %d", name, last_rc)
                return last_rc

            except FileNotFoundError:
                self.console.print(
                    f"  [bold red][✗][/bold red] Command not found: "
                    f"[yellow]{cmd[0]}[/yellow] — is the wrapper executable?"
                )
                self.log.error("Command not found: %s", cmd[0])
                return -1

        return last_rc

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------

    def _banner(self) -> None:
        # ── ASCII art logo (OSCP block letters) ─────────────────────────────
        _ART = [
            "  ██████╗ ███████╗ ██████╗██████╗ ",
            " ██╔═══██╗██╔════╝██╔════╝██╔══██╗",
            " ██║   ██║███████╗██║     ██████╔╝ ",
            " ██║   ██║╚════██║██║     ██╔═══╝  ",
            " ╚██████╔╝███████║╚██████╗██║      ",
            "  ╚═════╝ ╚══════╝ ╚═════╝╚═╝     ",
        ]
        # Side-column text aligned to the right of rows 1-5
        _SIDE = [
            "",
            "    [bold cyan]E N U M E R A T I O N   F R A M E W O R K[/bold cyan]",
            "    [dim]Assisted recon.  Never autopwn.[/dim]",
            "    [dim]Recon  →  Enumerate  →  Report[/dim]",
            "",
            "    [bold bright_red]☠   by acanoman   ☠[/bold bright_red]",
        ]

        self.console.print()
        for art_line, side_line in zip(_ART, _SIDE):
            self.console.print(
                f"[bold bright_green]{art_line}[/bold bright_green]{side_line}"
            )

        # Divider
        self.console.print()
        self.console.print(
            "  [bold red]" + "━" * 62 + "[/bold red]"
        )

        # ── Target info panel ────────────────────────────────────────────────
        info_lines = [
            f"[bold white]Target :[/bold white] [bold cyan]{self.target}[/bold cyan]"
        ]
        if self.domain:
            info_lines.append(
                f"[bold white]Domain :[/bold white] [bold cyan]{self.domain}[/bold cyan]"
            )
        info_lines.append(
            f"[bold white]Output :[/bold white] [dim]{self.session.target_dir}[/dim]"
        )
        if self.lhost:
            info_lines.append(
                f"[bold white]LHOST  :[/bold white] [bold green]{self.lhost}[/bold green]"
                "  [dim](Arsenal Recommender)[/dim]"
            )
        if self.dry_run:
            info_lines.append(
                "[bold yellow]Mode   :[/bold yellow] "
                "[bold yellow]DRY-RUN — commands printed but NOT executed[/bold yellow]"
            )
        if self.resume:
            info_lines.append(
                "[bold green]Mode   :[/bold green] "
                "[bold green]RESUME — continuing previous session[/bold green]"
            )

        self.console.print(
            Panel(
                "\n".join(info_lines),
                title="[bold red] ☠  TARGET  ☠ [/bold red]",
                border_style="red",
                padding=(1, 4),
            )
        )
        self.console.print()

        self.session.add_note(
            f"Engine started for {self.target}"
            + (f" / {self.domain}" if self.domain else "")
        )
