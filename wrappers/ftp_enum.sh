#!/usr/bin/env bash
# =============================================================================
#  wrappers/ftp_enum.sh — Dedicated FTP Enumeration Wrapper
#
#  Covers: FTP (21) and FTPS (990) — anonymous login test, Nmap NSE scripts,
#          recursive directory listing, interesting file flagging, TLS probe.
#
#  OSCP compliance:
#    - Anonymous and banner-only enumeration
#    - NO brute-force automation (hint provided instead)
#    - NO automatic file download (hint provided for manual wget/ftp)
#    - Prints every command before execution
#
#  Usage:
#    bash wrappers/ftp_enum.sh --target <IP> --output-dir <DIR> \
#         [--port <PORT>] [--user <USER>] [--pass <PASS>]
#
#  Output: <DIR>/ftp/
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
TARGET=""; OUTPUT_DIR=""; FTP_PORT="21"; FTP_USER=""; FTP_PASS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)     TARGET="$2";     shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --port)       FTP_PORT="$2";   shift 2 ;;
        --user)       FTP_USER="$2";   shift 2 ;;
        --pass)       FTP_PASS="$2";   shift 2 ;;
        *) err "Unknown argument: $1"; exit 1 ;;
    esac
done

if [[ -z "$TARGET" || -z "$OUTPUT_DIR" ]]; then
    err "Usage: $0 --target <IP> --output-dir <DIR> [--port <PORT>]"
    exit 1
fi

FTP_DIR="${OUTPUT_DIR}/ftp"
mkdir -p "$FTP_DIR"

echo ""
echo -e "  ${BOLD}============================================================${NC}"
echo -e "  ${BOLD}  FTP ENUM — ${TARGET}:${FTP_PORT}${NC}"
echo -e "  ${BOLD}============================================================${NC}"
echo ""

# ===========================================================================
# Step 1 — Banner grab via nc
# ===========================================================================
info "[1/5] Banner grab"
cmd "nc -nv -w 5 $TARGET $FTP_PORT"
BANNER=$(timeout 5 bash -c "echo '' | nc -nv -w 5 $TARGET $FTP_PORT" 2>&1 || true)
echo "$BANNER" > "${FTP_DIR}/ftp_banner.txt"
BANNER_LINE=$(echo "$BANNER" | grep -vE '^$|^\(UNKNOWN\)|^Connection' | head -1 | cut -c1-100)
[[ -n "$BANNER_LINE" ]] && ok "FTP banner: ${WHITE}${BANNER_LINE}${NC}"

# ===========================================================================
# Step 2 — Anonymous login probe
# ===========================================================================
info "[2/5] Anonymous login test"
cmd "ftp -inv $TARGET $FTP_PORT (anonymous probe)"
FTP_ANON_RESULT=$(timeout 15 bash -c \
    "printf 'open ${TARGET} ${FTP_PORT}\nuser anonymous anonymous\nls -la\npwd\nquit\n' | ftp -inv" \
    2>&1 || true)
echo "$FTP_ANON_RESULT" > "${FTP_DIR}/ftp_anon_test.txt"

ANON_ALLOWED=false
if echo "$FTP_ANON_RESULT" | grep -qiE '230|logged in|Login successful'; then
    ANON_ALLOWED=true
    ok "Anonymous login: ${RED}PERMITTED${NC}"
else
    info "Anonymous login: denied."
fi

# ===========================================================================
# Step 3 — Nmap NSE FTP scripts
# ===========================================================================
info "[3/5] Nmap FTP scripts (ftp-anon, ftp-bounce, ftp-syst, ftp-vsftpd-backdoor)"
cmd "nmap -p${FTP_PORT} --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor -Pn $TARGET"
nmap -p"${FTP_PORT}" \
    --script 'ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor' \
    -Pn "$TARGET" \
    -oN "${FTP_DIR}/ftp_nmap.txt" 2>&1 | tee "${FTP_DIR}/ftp_nmap.txt" || {
    warn "nmap (FTP) failed — output may be incomplete. Check ${FTP_DIR}/ftp_nmap.txt for details."
} # IMP-7 applied

if grep -qi "vsftpd.*backdoor\|VULNERABLE" "${FTP_DIR}/ftp_nmap.txt" 2>/dev/null; then
    warn "vsftpd BACKDOOR detected — review ${FTP_DIR}/ftp_nmap.txt"
fi
if grep -qi "ftp-bounce.*allowed" "${FTP_DIR}/ftp_nmap.txt" 2>/dev/null; then
    warn "FTP bounce scan allowed — potential port proxying via PORT command"
fi

# Authenticated NSE scan if credentials provided
if [[ -n "$FTP_USER" && -n "$FTP_PASS" ]]; then
    info "[3b/5] Authenticated NSE scan"
    cmd "nmap -p${FTP_PORT} --script ftp-anon,ftp-syst --script-args ftp.user=$FTP_USER,ftp.password=$FTP_PASS -Pn $TARGET"
    nmap -p"${FTP_PORT}" \
        --script 'ftp-anon,ftp-syst' \
        --script-args "ftp.user=${FTP_USER},ftp.password=${FTP_PASS}" \
        -Pn "$TARGET" \
        -oN "${FTP_DIR}/ftp_nmap_auth.txt" 2>&1 | tee "${FTP_DIR}/ftp_nmap_auth.txt" || true
fi

# ===========================================================================
# Step 4 — Recursive directory listing (no download)
# ===========================================================================
if [[ "$ANON_ALLOWED" == "true" ]]; then
    info "[4/5] Recursive directory listing (listing only — no downloads)"
    FTP_TREE="${FTP_DIR}/ftp_tree.txt"
    cmd "ftp -inv $TARGET $FTP_PORT (recursive ls -R)"
    timeout 30 bash -c \
        "printf 'open ${TARGET} ${FTP_PORT}\nuser anonymous anonymous\nls -R\nquit\n' | ftp -inv" \
        2>&1 | tee "$FTP_TREE" || true

    FILE_COUNT=$(grep -cP '^-' "$FTP_TREE" 2>/dev/null || echo 0)
    DIR_COUNT=$(grep -cP '^d' "$FTP_TREE" 2>/dev/null || echo 0)
    ok "FTP tree: ~${FILE_COUNT} files, ~${DIR_COUNT} directories → ${FTP_TREE}"

    # Flag interesting extensions
    INTERESTING=$(grep -iP '\.(ps1|bat|cmd|vbs|conf|config|ini|bak|old|zip|sql|key|pem|pfx|txt|xml|log|db|sqlite|kdbx)$' \
        "$FTP_TREE" 2>/dev/null | head -30 || true)
    if [[ -n "$INTERESTING" ]]; then
        warn "Potentially interesting files found via anonymous FTP:"
        echo "$INTERESTING"
        echo "$INTERESTING" > "${FTP_DIR}/ftp_interesting.txt"
        ok "Saved → ${FTP_DIR}/ftp_interesting.txt"
    fi

    hint "Download ALL files (manual — verify disk space first):
    wget -m --no-passive --no-check-certificate ftp://anonymous:anonymous@${TARGET}/
    # Files save to ./${TARGET}/ in current directory.
    # Use --limit-rate=500k on unstable VPNs."

elif [[ -n "$FTP_USER" && -n "$FTP_PASS" ]]; then
    info "[4/5] Recursive listing with provided credentials"
    FTP_TREE="${FTP_DIR}/ftp_tree_auth.txt"
    timeout 30 bash -c \
        "printf 'open ${TARGET} ${FTP_PORT}\nuser ${FTP_USER} ${FTP_PASS}\nls -R\nquit\n' | ftp -inv" \
        2>&1 | tee "$FTP_TREE" || true
    ok "Authenticated directory listing → ${FTP_TREE}"
else
    info "[4/5] Skipping recursive listing — anonymous access denied and no credentials."
fi

# ===========================================================================
# Step 5 — STARTTLS / FTPS check
# ===========================================================================
info "[5/5] STARTTLS / FTPS probe"
if command -v openssl &>/dev/null; then
    cmd "openssl s_client -connect $TARGET:$FTP_PORT -starttls ftp"
    timeout 5 bash -c \
        "echo 'QUIT' | openssl s_client -connect ${TARGET}:${FTP_PORT} -starttls ftp -quiet" \
        2>&1 | head -20 | tee "${FTP_DIR}/ftp_tls.txt" || true
    if grep -qi "STARTTLS\|TLSv\|BEGIN CERTIFICATE" "${FTP_DIR}/ftp_tls.txt" 2>/dev/null; then
        ok "FTPS/STARTTLS supported on port ${FTP_PORT}"
    fi
else
    skip "openssl"
fi

hint "FTP manual steps:
  ftp ${TARGET}                                   ← interactive login (anonymous / creds)
  curl -v ftp://${TARGET}/                        ← anonymous listing
  curl -v --ftp-ssl ftp://${TARGET}/ --user USER:PASS  ← FTPS with credentials
  nmap -p${FTP_PORT} --script ftp-anon,ftp-syst,ftp-bounce -Pn ${TARGET}
  # Brute force (authorized only):
  hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://${TARGET}"

echo ""
ok "FTP enumeration complete → ${FTP_DIR}/"
echo ""
