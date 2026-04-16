#!/usr/bin/env bash
# =============================================================================
#  wrappers/rsync_enum.sh — Rsync Enumeration Wrapper
#
#  Covers: rsync (873) — module listing, per-module content enumeration,
#          sensitive file detection, unauthenticated access detection.
#
#  Tools: rsync, nmap
#
#  OSCP compliance:
#    - No file modification/upload (read-only enumeration)
#    - No exploitation
#    - Prints every command before execution
#
#  Usage:
#    bash wrappers/rsync_enum.sh --target <IP> --output-dir <DIR> [--ports 873]
#
#  Output: <DIR>/rsync/
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

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
TARGET=""; OUTPUT_DIR=""; RSYNC_PORTS="873"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)     TARGET="$2";       shift 2 ;;
        --output-dir) OUTPUT_DIR="$2";   shift 2 ;;
        --ports)      RSYNC_PORTS="$2";  shift 2 ;;
        *) err "Unknown argument: $1"; exit 1 ;;
    esac
done

if [[ -z "$TARGET" || -z "$OUTPUT_DIR" ]]; then
    err "Usage: $0 --target <IP> --output-dir <DIR> [--ports 873]"
    exit 1
fi

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
RSYNC_DIR="${OUTPUT_DIR}/rsync"
mkdir -p "$RSYNC_DIR"

echo ""
echo -e "  ${BOLD}============================================================${NC}"
echo -e "  ${BOLD}  RSYNC ENUM — ${TARGET}:${RSYNC_PORTS}${NC}"
echo -e "  ${BOLD}============================================================${NC}"
echo ""

# ===========================================================================
# Per-step interrupt handler
# Ctrl+C (1st) → skip step, continue  |  Ctrl+C (2nd, <5s) → abort module
# ===========================================================================
STEP_SKIPPED=false; _LAST_SIGINT_TS=0; SKIP_ABORT_WINDOW=5
_sigint_step() {
    local now; now=$(date +%s)
    if (( now - _LAST_SIGINT_TS < SKIP_ABORT_WINDOW )); then
        warn "Second Ctrl+C — aborting enumeration for ${TARGET}"; exit 130
    fi
    _LAST_SIGINT_TS=$now; STEP_SKIPPED=true
    echo ""; warn "⚡ Step interrupted — continuing to next step"
    warn "   (press Ctrl+C again within ${SKIP_ABORT_WINDOW}s to abort entire module)"; echo ""
}
trap '_sigint_step' INT

# Guard — rsync must be installed for meaningful enumeration
if ! command -v rsync &>/dev/null; then
    skip "rsync"
    warn "rsync binary not found — module listing and content enumeration skipped."
    warn "Install with: sudo apt-get install -y rsync"
    hint "Manual rsync enumeration (run from a host with rsync installed):
  rsync --list-only rsync://${TARGET}/
  rsync --list-only rsync://${TARGET}/<MODULE>/
  rsync -avz rsync://${TARGET}/<MODULE>/ ./loot/<MODULE>/"
    echo ""
    ok "Rsync enumeration complete (partial — rsync not installed) → ${RSYNC_DIR}/"
    echo ""
    exit 0
fi

# ===========================================================================
# Step 1/4 — Nmap rsync scripts
# ===========================================================================
info "[1/4] Nmap rsync-list-modules script"
cmd "nmap -p${RSYNC_PORTS} --script rsync-list-modules --script-timeout 30s -Pn ${TARGET}"
nmap -p"${RSYNC_PORTS}" \
    --script 'rsync-list-modules' \
    --script-timeout 30s \
    -Pn "$TARGET" \
    -oN "${RSYNC_DIR}/rsync_nmap.txt" 2>&1 | tee "${RSYNC_DIR}/rsync_nmap.txt" || {
    warn "nmap (rsync) failed — output may be incomplete. Check ${RSYNC_DIR}/rsync_nmap.txt"
}

# Extract any modules surfaced by NSE
NSE_MODULES=$(grep -oP '^\|\s+\K\S+' "${RSYNC_DIR}/rsync_nmap.txt" 2>/dev/null | grep -v '^$' || true)
if [[ -n "$NSE_MODULES" ]]; then
    ok "NSE rsync-list-modules output:"
    echo "$NSE_MODULES"
fi

# ===========================================================================
# Step 2/4 — Module listing (unauthenticated)
# ===========================================================================
info "[2/4] Listing rsync modules exposed on ${TARGET}"
MODULES_FILE="${RSYNC_DIR}/rsync_modules.txt"
MODULE_LIST=""

cmd "rsync --list-only rsync://${TARGET}/"
if timeout 15 rsync --list-only "rsync://${TARGET}/" 2>&1 | tee "$MODULES_FILE"; then
    MODULE_LIST=$(grep -vE '^\s*$|^(ERROR|WARNING|rsync:|@ERROR|opening|sending|receiving|Protocol|Connecting)' \
        "$MODULES_FILE" 2>/dev/null | awk '{print $1}' | grep -v '^$' || true)
else
    warn "Primary module listing failed — trying alternative syntax"
    cmd "rsync rsync://${TARGET}/"
    timeout 15 rsync "rsync://${TARGET}/" 2>&1 | tee "$MODULES_FILE" || true
    MODULE_LIST=$(grep -vE '^\s*$|^(ERROR|WARNING|rsync:|@ERROR|opening|sending|receiving|Protocol|Connecting)' \
        "$MODULES_FILE" 2>/dev/null | awk '{print $1}' | grep -v '^$' || true)
fi

MODULE_COUNT=0
if [[ -n "$MODULE_LIST" ]]; then
    MODULE_COUNT=$(echo "$MODULE_LIST" | grep -c '.' || true)
    ok "Found ${WHITE}${MODULE_COUNT}${NC} rsync module(s):"
    echo "$MODULE_LIST" | while IFS= read -r MOD; do
        [[ -n "$MOD" ]] && ok "  Module: ${WHITE}${MOD}${NC}" || true
    done
    warn "Modules accessible — check each for unauthenticated read access"
else
    info "No rsync modules listed (service may require authentication or be filtered)"
fi

# ===========================================================================
# Step 3/4 — Per-module enumeration
# ===========================================================================
info "[3/4] Per-module content enumeration"

if [[ -z "$MODULE_LIST" ]]; then
    info "No modules to enumerate — skipping per-module step."
else
    echo "$MODULE_LIST" | while IFS= read -r MODULE; do
        [[ -z "$MODULE" ]] && continue

        info "  Enumerating module: ${WHITE}${MODULE}${NC}"
        LISTING_FILE="${RSYNC_DIR}/${MODULE}_listing.txt"

        cmd "rsync --list-only rsync://${TARGET}/${MODULE}/"
        if timeout 30 rsync --list-only "rsync://${TARGET}/${MODULE}/" \
                2>&1 | tee "$LISTING_FILE"; then

            # Count files (lines starting with - or d in rsync listing)
            FILE_COUNT=$(grep -cE '^-' "$LISTING_FILE" 2>/dev/null || echo 0)
            DIR_COUNT=$(grep -cE '^d' "$LISTING_FILE" 2>/dev/null || echo 0)
            ok "  Module '${MODULE}': ${FILE_COUNT} files, ${DIR_COUNT} directories"

            # Module was accessible without authentication
            warn "  Module '${MODULE}' accessible without authentication"

            # Detect interesting files
            INTERESTING=$(grep -iE \
                '(id_rsa|authorized_keys|\.pem|\.key|\.conf|\.config|\.ini|\.yml|\.yaml|\.env|\.bak|\.backup|\.old|\.tar\.gz|\.tar|\.zip|\.gz|password|passwd|credentials|secret|web\.config|\.htpasswd|wp-config\.php)' \
                "$LISTING_FILE" 2>/dev/null || true)

            if [[ -n "$INTERESTING" ]]; then
                warn "  INTERESTING FILES in module '${MODULE}':"
                echo "$INTERESTING" | head -30
                echo "$INTERESTING" > "${RSYNC_DIR}/${MODULE}_interesting.txt"
                ok "  Saved → ${RSYNC_DIR}/${MODULE}_interesting.txt"
            fi

        else
            warn "  Module '${MODULE}' listing failed — may require authentication"
            echo "# Listing failed — authentication may be required" > "$LISTING_FILE"
        fi

        echo ""
    done
fi

# ===========================================================================
# Step 4/4 — Manual hints
# ===========================================================================
info "[4/4] Manual rsync commands"

hint "Rsync manual enumeration steps:

  # List all exposed modules:
  rsync --list-only rsync://${TARGET}/

  # List contents of a specific module:
  rsync --list-only rsync://${TARGET}/<MODULE>/

  # Recursive content listing (all subdirectories):
  rsync --list-only -r rsync://${TARGET}/<MODULE>/

  # Download entire module to local loot directory:
  rsync -avz rsync://${TARGET}/<MODULE>/ ./loot/<MODULE>/

  # If authentication is required (prompted interactively):
  rsync -avz rsync://<USER>@${TARGET}/<MODULE>/ ./loot/<MODULE>/

  # Environment variable for non-interactive password:
  RSYNC_PASSWORD='<PASS>' rsync -avz rsync://<USER>@${TARGET}/<MODULE>/ ./loot/<MODULE>/

  # Upload a file (OSCP: only if write access is confirmed AND in scope):
  rsync -avz ./payload rsync://${TARGET}/<MODULE>/

  # SSH key injection (if .ssh/ directory is writable — PrivEsc path):
  rsync -avz ~/.ssh/id_rsa.pub rsync://${TARGET}/<MODULE>/.ssh/authorized_keys"

# ===========================================================================
# Summary box
# ===========================================================================
echo ""
echo -e "  ${BOLD}------------------------------------------------------------${NC}"
echo -e "  ${BOLD}  RSYNC SUMMARY — ${TARGET}${NC}"
echo -e "  ${BOLD}------------------------------------------------------------${NC}"

if [[ -n "$MODULE_LIST" ]]; then
    TOTAL_MODULES=$(echo "$MODULE_LIST" | grep -c '.' || true)
    echo -e "  ${GREEN}[+]${NC} Modules exposed (no auth): ${WHITE}${TOTAL_MODULES}${NC}"
    echo "$MODULE_LIST" | while IFS= read -r MOD; do
        [[ -z "$MOD" ]] && continue
        INTERESTING_COUNT=0
        if [[ -f "${RSYNC_DIR}/${MOD}_interesting.txt" ]]; then
            INTERESTING_COUNT=$(grep -c '.' "${RSYNC_DIR}/${MOD}_interesting.txt" 2>/dev/null || echo 0)
        fi
        if [[ "$INTERESTING_COUNT" -gt 0 ]]; then
            echo -e "  ${YELLOW}[!]${NC}   ${MOD} — ${RED}${INTERESTING_COUNT} interesting file(s)${NC}"
        else
            echo -e "  ${GREEN}[+]${NC}   ${MOD}"
        fi
    done
else
    echo -e "  ${CYAN}[*]${NC} No modules accessible without authentication"
fi

TOTAL_INTERESTING=0
TOTAL_INTERESTING=$(find "${RSYNC_DIR}" -name "*_interesting.txt" 2>/dev/null | wc -l || echo 0)
if [[ "$TOTAL_INTERESTING" -gt 0 ]]; then
    warn "Modules with interesting files: ${TOTAL_INTERESTING} — review *_interesting.txt files"
fi

echo -e "  ${BOLD}------------------------------------------------------------${NC}"
echo ""
ok "Rsync enumeration complete → ${RSYNC_DIR}/"
echo ""
