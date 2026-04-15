"""
modules/docker.py — Docker API enumeration module

Routes to wrappers/docker_enum.sh for Docker daemon enumeration on
ports 2375 (plain HTTP) and 2376 (TLS).
After the wrapper runs, parses output files for key findings and injects
[MANUAL] hints directly into session notes so they appear in notes.md.

OSCP compliance:
  - Read-only API enumeration (version, containers, images, info, networks)
  - NO container creation or deletion
  - NO command execution inside containers
  - Host-escape technique → manual hint only
"""

import re
from pathlib import Path

from core.runner import run_wrapper

WRAPPERS_DIR = Path(__file__).resolve().parent.parent / "wrappers"

# Ports this module owns
_DOCKER_PORTS = {
    2375,   # Docker daemon — plain HTTP (no TLS)
    2376,   # Docker daemon — TLS (mTLS normally required)
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(target: str, session, dry_run: bool = False) -> None:
    log = session.log
    ip  = session.info.ip

    open_docker = session.info.open_ports & _DOCKER_PORTS
    if not open_docker:
        log.info("No Docker API ports open — skipping docker module.")
        return

    log.info("Docker ports to enumerate: %s", sorted(open_docker))

    # Inject MANUAL hints immediately — visible even if wrapper is interrupted
    _add_manual_hints(session, open_docker)

    script = WRAPPERS_DIR / "docker_enum.sh"
    if not script.exists():
        log.error("Wrapper not found: %s", script)
        return

    ports_csv = ",".join(str(p) for p in sorted(open_docker))
    cmd = [
        "bash", str(script),
        "--target",     target,
        "--output-dir", str(session.target_dir),
        "--ports",      ports_csv,
    ]

    run_wrapper(cmd, session, label="docker_enum.sh", dry_run=dry_run)

    if dry_run:
        return

    # Parse results for each port
    for port in sorted(open_docker):
        _parse_docker_version(session, log, port)
        _parse_docker_containers(session, log, port)
        _parse_docker_images(session, log, port)

    log.info("Docker module complete.")


# ---------------------------------------------------------------------------
# MANUAL hints — written to notes.md regardless of what the wrapper finds
# ---------------------------------------------------------------------------

def _add_manual_hints(session, open_docker: set) -> None:
    ip = session.info.ip

    for port in sorted(open_docker):
        scheme = "https" if port == 2376 else "http"
        session.add_note(
            f"[MANUAL] Docker version check: "
            f"curl -sk {scheme}://{ip}:{port}/version"
        )
        session.add_note(
            f"[MANUAL] Docker CLI (unauthenticated): "
            f"docker -H tcp://{ip}:{port} ps"
        )
        session.add_note(
            f"[MANUAL] Docker container list: "
            f"docker -H tcp://{ip}:{port} ps -a"
        )
        session.add_note(
            f"[MANUAL] Docker image list: "
            f"docker -H tcp://{ip}:{port} images"
        )

    if 2375 in open_docker:
        session.add_note(
            f"[MANUAL / OSCP SCOPE CHECK] Docker host escape via API (port 2375): "
            f"docker -H tcp://{ip}:2375 run -v /:/mnt --rm -it alpine chroot /mnt sh"
        )
        session.add_note(
            f"[MANUAL / OSCP SCOPE CHECK] Read /etc/shadow via Docker: "
            f"docker -H tcp://{ip}:2375 run -v /etc:/mnt/etc --rm alpine cat /mnt/etc/shadow"
        )

    if 2376 in open_docker:
        session.add_note(
            f"[MANUAL] Docker TLS port 2376 — try without client cert first: "
            f"curl -sk https://{ip}:2376/version"
        )


# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------

def _parse_docker_version(session, log, port: int) -> None:
    docker_dir = session.target_dir / "docker"
    version_f  = docker_dir / f"docker_version_{port}.txt"
    if not version_f.exists():
        return

    content = version_f.read_text(errors="ignore")

    # API accessible without authentication
    if re.search(r'"Version"\s*:', content, re.IGNORECASE):
        log.warning("Docker API on port %d accessible WITHOUT authentication", port)
        session.add_note(
            f"DOCKER FINDING: Docker API on port {port} exposed — no auth required — {version_f}"
        )

        docker_ver = re.search(r'"Version"\s*:\s*"([^"]+)"', content)
        api_ver    = re.search(r'"ApiVersion"\s*:\s*"([^"]+)"', content)
        os_ver     = re.search(r'"Os"\s*:\s*"([^"]+)"', content)
        kernel_ver = re.search(r'"KernelVersion"\s*:\s*"([^"]+)"', content)

        if docker_ver:
            log.info("Docker version: %s", docker_ver.group(1))
            session.add_note(f"Docker version: {docker_ver.group(1)}")
        if api_ver:
            log.info("Docker API version: %s", api_ver.group(1))
        if os_ver:
            log.info("Docker OS: %s", os_ver.group(1))
        if kernel_ver:
            log.info("Docker kernel: %s", kernel_ver.group(1))


def _parse_docker_containers(session, log, port: int) -> None:
    docker_dir   = session.target_dir / "docker"
    containers_f = docker_dir / f"docker_containers_{port}.txt"
    if not containers_f.exists():
        return

    content = containers_f.read_text(errors="ignore")

    # Host root mount — critical privilege escalation indicator
    if re.search(r'"Source"\s*:\s*"/"', content) or re.search(r'Source.*?:\s*"/"', content):
        log.warning("Docker port %d: container has HOST ROOT (/) mounted — CRITICAL", port)
        session.add_note(
            f"DOCKER CRITICAL: Container on port {port} has host root (/) mounted — "
            f"host escape trivial — {containers_f}"
        )

    # Privileged containers
    if re.search(r'"Privileged"\s*:\s*true', content, re.IGNORECASE):
        log.warning("Docker port %d: privileged container detected — host escape possible", port)
        session.add_note(
            f"DOCKER CRITICAL: Privileged container found on port {port} — "
            f"host escape via /dev/mem or cgroup — {containers_f}"
        )

    # Count running containers (basic heuristic)
    running = len(re.findall(r'"Status"\s*:\s*"running"', content, re.IGNORECASE))
    if running:
        log.info("Docker port %d: %d running container(s) found", port, running)
        session.add_note(f"Docker port {port}: {running} running container(s) — review {containers_f}")


def _parse_docker_images(session, log, port: int) -> None:
    docker_dir = session.target_dir / "docker"
    images_f   = docker_dir / f"docker_images_{port}.txt"
    if not images_f.exists():
        return

    content = images_f.read_text(errors="ignore")

    # Extract image names for quick summary
    tags = re.findall(r'"RepoTags"\s*:\s*\["([^"]+)"', content)
    if tags:
        log.info("Docker port %d images: %s", port, tags[:10])
        session.add_note(
            f"Docker port {port} images found: {', '.join(tags[:10])} — review {images_f}"
        )
