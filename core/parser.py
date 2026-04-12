"""
core/parser.py — Output parsing (nmap XML, gobuster, smbmap)
Full implementation: Phase 2
"""

import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, Tuple, TYPE_CHECKING

from core.display import success

if TYPE_CHECKING:
    from core.session import TargetInfo


class NmapParser:
    """Parses Nmap XML output into TargetInfo."""

    def __init__(self, log: logging.Logger) -> None:
        self.log = log

    def parse_xml(self, xml_path: Path, info: "TargetInfo") -> None:
        """
        Extract open TCP ports and service details from an Nmap XML file.
        Populates info.open_ports and info.port_details in-place.
        """
        try:
            tree = ET.parse(xml_path)
        except ET.ParseError as exc:
            self.log.error("Failed to parse Nmap XML %s: %s", xml_path, exc)
            return

        root = tree.getroot()

        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue

            ports_el = host.find("ports")
            if ports_el is None:
                continue

            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                port_num = int(port_el.get("portid", 0))
                if port_num == 0:
                    continue

                service_el = port_el.find("service")
                service  = ""
                version  = ""
                banner   = ""

                if service_el is not None:
                    service = service_el.get("name", "")
                    product = service_el.get("product", "")
                    ver     = service_el.get("version", "")
                    extra   = service_el.get("extrainfo", "")
                    parts   = filter(None, [product, ver, extra])
                    version = " ".join(parts)
                    banner  = service_el.get("tunnel", "")

                info.add_port(port_num, service=service, version=version, banner=banner)
                self.log.debug(
                    "Port %d/tcp open — %s %s", port_num, service, version
                )

            # Best-effort OS detection from Nmap <os> element
            os_el = host.find("os")
            if os_el is not None and (not info.os_guess or info.os_guess == "Unknown"):
                osmatch = os_el.find("osmatch")
                if osmatch is not None:
                    info.os_guess = osmatch.get("name", "Unknown")
                    os_type, os_version = _parse_os_guess(info.os_guess)
                    if os_type and not info.os_type:
                        info.os_type = os_type
                    if os_version and not info.os_version:
                        info.os_version = os_version
                    self.log.debug(
                        "OS parsed: type=%s version=%s (from '%s')",
                        os_type, os_version, info.os_guess,
                    )

            # Also scan version strings for Active Directory / DC markers
            # and for kernel/OS version clues embedded in service banners
            for port_num, details in info.port_details.items():
                ver = details.get("version", "")
                _enrich_from_version_string(port_num, ver, info, self.log)

        # DC heuristic: Kerberos (88) + LDAP/GC → almost certainly a DC
        if 88 in info.open_ports and (info.open_ports & {389, 636, 3268, 3269}):
            if not info.is_domain_controller:
                info.is_domain_controller = True
                success("Domain Controller inferred: Kerberos (88) + LDAP/GC ports open")
                self.log.info(
                    "Domain Controller inferred: Kerberos (88) + LDAP/GC ports open"
                )


# ---------------------------------------------------------------------------
# OS parsing helpers (module-level, used by NmapParser)
# ---------------------------------------------------------------------------

def _parse_os_guess(os_guess: str) -> Tuple[str, str]:
    """
    Derive (os_type, os_version) from an Nmap OS match string.

    Examples:
        "Windows Server 2019 Standard"     → ("Windows", "2019")
        "Windows 7 SP1"                    → ("Windows", "7")
        "Linux 5.15 - 5.19"               → ("Linux",   "5.15")
        "Ubuntu 20.04"                     → ("Linux",   "Ubuntu 20.04")
        "Linux 4.4.0-21-generic"           → ("Linux",   "4.4.0")

    Returns ("", "") if the string is empty or unrecognised.
    """
    if not os_guess:
        return "", ""

    lower = os_guess.lower()
    os_type = ""
    os_version = ""

    if "windows" in lower:
        os_type = "Windows"
        # Prefer a year like 2012/2019; fall back to a version number like 7, 10
        m = re.search(r"\b(2003|2008|2012|2016|2019|2022)\b", os_guess)
        if not m:
            m = re.search(r"\b(xp|vista|7|8|8\.1|10|11)\b", os_guess, re.IGNORECASE)
        os_version = m.group(1) if m else ""

    elif any(kw in lower for kw in ("linux", "ubuntu", "debian", "centos",
                                     "fedora", "redhat", "kali", "alpine")):
        os_type = "Linux"
        # Prefer a kernel version (X.Y or X.Y.Z)
        m = re.search(r"(\d+\.\d+(?:\.\d+)?)", os_guess)
        if m:
            os_version = m.group(1)
        else:
            # Distro name + version, e.g. "Ubuntu 20.04"
            m = re.search(
                r"(ubuntu|debian|centos|fedora|kali)\s+(\d+(?:\.\d+)?)",
                os_guess, re.IGNORECASE,
            )
            os_version = f"{m.group(1)} {m.group(2)}" if m else ""

    return os_type, os_version


def _enrich_from_version_string(
    port: int,
    version: str,
    info: "TargetInfo",
    log: logging.Logger,
) -> None:
    """
    Extract additional context from an Nmap service version string.

    Currently:
      - Detects "Active Directory" / "Domain Controller" in LDAP banners → sets is_domain_controller
      - Extracts kernel version from SSH banners (e.g. "OpenSSH 7.9 Debian 4.19") → os_version
    """
    if not version:
        return

    lower = version.lower()

    # LDAP banner explicitly identifying a Domain Controller
    if port in (389, 636, 3268, 3269):
        if re.search(r"active.directory|domain.controller", lower):
            if not info.is_domain_controller:
                info.is_domain_controller = True
                success(f"DC confirmed via LDAP banner on port {port}")
                log.info("DC confirmed via LDAP banner on port %d", port)

    # SSH banner often contains kernel/OS info: "OpenSSH 7.9p1 Debian 4.19.0-13"
    if port == 22 and not info.os_version:
        # Linux kernel embedded in SSH extra-info
        m = re.search(r"(\d+\.\d+\.\d+)", version)
        if m and not info.os_type:
            # Heuristic: SSH version with kernel-like string → Linux
            info.os_type    = "Linux"
            info.os_version = m.group(1)
            log.debug("OS version from SSH banner: %s", m.group(1))
