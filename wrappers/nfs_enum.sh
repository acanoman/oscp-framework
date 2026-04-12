#!/usr/bin/env bash
# =============================================================================
#  wrappers/nfs_enum.sh — Dedicated NFS / RPC Enumeration Wrapper
#
#  Covers: RPC portmapper (111) and NFS (2049) — endpoint dump, export listing,
#          file system stat, NSE scripts, sensitive file detection.
#
#  OSCP compliance:
#    - Read-only export enumeration (showmount, rpcinfo, NSE)
#    - NO automatic mount or file read (hint only)
#    - no_root_squash flagged as a PrivEsc finding
#    - Prints every command before execution
#
#  Usage:
#    bash wrappers/nfs_enum.sh --target <IP> --output-dir <DIR>
#
#  Output: <DIR>/nfs/
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
TARGET=""; OUTPUT_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)     TARGET="$2";     shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        *) err "Unknown argument: $1"; exit 1 ;;
    esac
done

if [[ -z "$TARGET" || -z "$OUTPUT_DIR" ]]; then
    err "Usage: $0 --target <IP> --output-dir <DIR>"
    exit 1
fi

NFS_DIR="${OUTPUT_DIR}/nfs"
mkdir -p "$NFS_DIR"

echo ""
echo -e "  ${BOLD}============================================================${NC}"
echo -e "  ${BOLD}  NFS / RPC ENUM — ${TARGET}${NC}"
echo -e "  ${BOLD}============================================================${NC}"
echo ""

# ===========================================================================
# Step 1 — RPC portmapper dump (always run first — reveals all RPC services)
# ===========================================================================
info "[1/4] RPC portmapper dump"
if command -v rpcinfo &>/dev/null; then
    cmd "rpcinfo -p $TARGET"
    rpcinfo -p "$TARGET" 2>&1 | tee "${NFS_DIR}/rpcinfo.txt" || true

    NFS_VERS=$(grep -i '\bnfs\b' "${NFS_DIR}/rpcinfo.txt" 2>/dev/null \
        | awk '{print "NFS v"$2" ("$3") port "$4}' | sort -u || true)
    [[ -n "$NFS_VERS" ]] && ok "RPC NFS services: ${WHITE}${NFS_VERS}${NC}"

    MOUNT_VERS=$(grep -i 'mountd\|mount' "${NFS_DIR}/rpcinfo.txt" 2>/dev/null \
        | awk '{print "mountd v"$2" ("$3") port "$4}' | sort -u || true)
    [[ -n "$MOUNT_VERS" ]] && ok "mountd: ${WHITE}${MOUNT_VERS}${NC}"
else
    skip "rpcinfo"
    hint "Install NFS tools: sudo apt-get install -y nfs-common rpcbind"
fi

# ===========================================================================
# Step 2 — Nmap NFS scripts (enumerate exports + file listings without mounting)
# ===========================================================================
info "[2/4] Nmap NFS enumeration scripts"
cmd "nmap -p111,2049 --script nfs-ls,nfs-showmount,nfs-statfs,rpcinfo -Pn $TARGET"
nmap -p111,2049 \
    --script 'nfs-ls,nfs-showmount,nfs-statfs,rpcinfo' \
    -Pn "$TARGET" \
    -oN "${NFS_DIR}/nfs_nmap.txt" 2>&1 | tee "${NFS_DIR}/nfs_nmap.txt" || {
    warn "nmap (NFS) failed — output may be incomplete. Check ${NFS_DIR}/nfs_nmap.txt for details."
} # IMP-7 applied

if grep -qi "no_root_squash" "${NFS_DIR}/nfs_nmap.txt" 2>/dev/null; then
    warn "NFS: no_root_squash detected — SUID binary plant via local-root mount is a PrivEsc path"
fi

# ===========================================================================
# Step 3 — showmount export list
# ===========================================================================
info "[3/4] showmount export listing"
NFS_SHARES="${NFS_DIR}/nfs_shares.txt"
if command -v showmount &>/dev/null; then
    cmd "showmount -e $TARGET"
    showmount -e "$TARGET" 2>&1 | tee "$NFS_SHARES" || true

    if grep -qP '^\/' "$NFS_SHARES" 2>/dev/null; then
        ok "NFS exports found:"
        while IFS= read -r LINE; do
            SHARE_PATH=$(echo "$LINE" | awk '{print $1}')
            ALLOWED=$(echo "$LINE" | awk '{print $2}')
            [[ "$SHARE_PATH" != /* ]] && continue
            ok "  Export: ${WHITE}${TARGET}:${SHARE_PATH}${NC}  (allowed hosts: ${ALLOWED})"

            # Flag world-accessible exports
            if echo "$ALLOWED" | grep -qE '^\*$|^0\.0\.0\.0/0$'; then
                warn "  ⚠  Export ${SHARE_PATH} accessible from ALL hosts (*) — no IP restriction!"
            fi
        done < <(grep -P '^/' "$NFS_SHARES" 2>/dev/null)

        hint "Mount and explore NFS exports manually:
    sudo mkdir -p /mnt/nfs_enum
    sudo mount -t nfs ${TARGET}:<SHARE_PATH> /mnt/nfs_enum -o nolock
    ls -laR /mnt/nfs_enum/
    find /mnt/nfs_enum/ -name '*.bak' -o -name '*.key' -o -name 'id_rsa' 2>/dev/null
    sudo umount /mnt/nfs_enum

    # no_root_squash exploit (SUID binary plant — requires root on attacker):
    cp /bin/bash /mnt/nfs_enum/bash_suid && chmod +s /mnt/nfs_enum/bash_suid
    # (then on target): /mnt/nfs_enum/bash_suid -p  → root shell"
    else
        info "No NFS exports found."
    fi
else
    skip "showmount"
    hint "Install NFS tools: sudo apt-get install -y nfs-common"
fi

# ===========================================================================
# Step 4 — Sensitive file detection in NSE listing output
# ===========================================================================
info "[4/4] Checking NSE output for sensitive file paths"
if [[ -f "${NFS_DIR}/nfs_nmap.txt" ]]; then
    SENSITIVE=$(grep -iP '\.(ssh|id_rsa|authorized_keys|passwd|shadow|htpasswd|conf|config|bak|key|pem|pfx|kdbx)(\b|$)' \
        "${NFS_DIR}/nfs_nmap.txt" 2>/dev/null | head -20 || true)
    if [[ -n "$SENSITIVE" ]]; then
        warn "Sensitive files visible in NFS listing — review carefully:"
        echo "$SENSITIVE"
        echo "$SENSITIVE" > "${NFS_DIR}/nfs_sensitive_files.txt"
        ok "Saved → ${NFS_DIR}/nfs_sensitive_files.txt"
    fi
fi

hint "NFS manual enumeration:
  showmount -e ${TARGET}
  rpcinfo -p ${TARGET}
  nmap -p111,2049 --script nfs-ls,nfs-showmount,nfs-statfs,rpcinfo -Pn ${TARGET}
  # After mounting — check UIDs of files before accessing:
  ls -lan /mnt/nfs_enum/      ← note UID/GID numbers
  useradd -u <UID> pwned && su pwned   ← impersonate file owner"

echo ""
ok "NFS enumeration complete → ${NFS_DIR}/"
echo ""
