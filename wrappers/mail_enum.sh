#!/usr/bin/env bash
# =============================================================================
#  wrappers/mail_enum.sh — Dedicated Mail Service Enumeration Wrapper
#
#  Covers: SMTP (25/465/587), POP3 (110/995), IMAP (143/993) — banner grabbing,
#          NSE scripts, SMTP user enumeration (VRFY → RCPT fallback),
#          TLS/STARTTLS detection, NTLM info disclosure.
#
#  OSCP compliance:
#    - Banner grabs and NSE user enumeration (VRFY/EXPN/RCPT) only
#    - NO brute force of any kind
#    - Relay and open-proxy tested via NSE only (no actual relay attempt)
#    - smtp-user-enum prioritises already-discovered users from SMB/LDAP
#    - Prints every command before execution
#
#  Usage:
#    bash wrappers/mail_enum.sh --target <IP> --output-dir <DIR> \
#         --ports <comma-list> [--domain <DOMAIN>]
#
#  Output: <DIR>/mail/, <DIR>/smtp/
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
TARGET=""; OUTPUT_DIR=""; PORTS=""; DOMAIN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)     TARGET="$2";     shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --ports)      PORTS="$2";      shift 2 ;;
        --domain)     DOMAIN="$2";     shift 2 ;;
        *) err "Unknown argument: $1"; exit 1 ;;
    esac
done

if [[ -z "$TARGET" || -z "$OUTPUT_DIR" || -z "$PORTS" ]]; then
    err "Usage: $0 --target <IP> --output-dir <DIR> --ports <PORTS>"
    exit 1
fi

MAIL_DIR="${OUTPUT_DIR}/mail"
SMTP_DIR="${OUTPUT_DIR}/smtp"
mkdir -p "$MAIL_DIR" "$SMTP_DIR"

echo ""
echo -e "  ${BOLD}============================================================${NC}"
echo -e "  ${BOLD}  MAIL ENUM — ${TARGET} (ports: ${PORTS})${NC}"
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

# ---------------------------------------------------------------------------
# Shared wordlist selection: prefer already-discovered users from SMB/LDAP
# ---------------------------------------------------------------------------
SMTP_UE_WL=""
for WL_CANDIDATE in \
    "${OUTPUT_DIR}/smb/users_rpc.txt" \
    "${OUTPUT_DIR}/ldap/ldap_users.txt" \
    "/usr/share/seclists/Usernames/Names/names.txt" \
    "/usr/share/wordlists/metasploit/unix_users.txt"; do
    if [[ -s "$WL_CANDIDATE" ]]; then
        SMTP_UE_WL="$WL_CANDIDATE"
        info "User wordlist: ${WHITE}${SMTP_UE_WL}${NC}"
        break
    fi
done

# ===========================================================================
# SMTP — ports 25, 465, 587
# ===========================================================================
for SMTP_PORT in 25 465 587; do
    has_port "$SMTP_PORT" || continue

    info "[SMTP] Port ${SMTP_PORT} — banner + NSE + user enumeration"

    # Banner grab
    cmd "nc -nv -w 5 $TARGET $SMTP_PORT"
    SMTP_BANNER=$(timeout 5 bash -c "echo 'QUIT' | nc -nv -w 5 $TARGET $SMTP_PORT" 2>&1 || true)
    echo "$SMTP_BANNER" > "${SMTP_DIR}/smtp_banner_${SMTP_PORT}.txt"
    BANNER_LINE=$(echo "$SMTP_BANNER" | grep -E '^220' | head -1 | cut -c1-100 || true)
    [[ -n "$BANNER_LINE" ]] && ok "SMTP ${SMTP_PORT} banner: ${WHITE}${BANNER_LINE}${NC}" || true

    # Nmap SMTP scripts
    cmd "nmap -p${SMTP_PORT} --script smtp-commands,smtp-enum-users,smtp-open-relay,smtp-vuln* -Pn $TARGET"
    nmap -p"${SMTP_PORT}" \
        --script 'smtp-commands,smtp-enum-users,smtp-open-relay,smtp-vuln*' \
        -Pn "$TARGET" \
        -oN "${SMTP_DIR}/smtp_nmap_${SMTP_PORT}.txt" 2>&1 \
        | tee "${SMTP_DIR}/smtp_nmap_${SMTP_PORT}.txt" || {
        warn "nmap (SMTP:${SMTP_PORT}) failed — output may be incomplete. Check ${SMTP_DIR}/smtp_nmap_${SMTP_PORT}.txt for details."
    } # IMP-7 applied

    # Canonical output path that mail.py parser expects
    if [[ "$SMTP_PORT" == "25" ]]; then
        cp "${SMTP_DIR}/smtp_nmap_${SMTP_PORT}.txt" "${SMTP_DIR}/smtp_nmap.txt"  2>/dev/null || true
        cp "${SMTP_DIR}/smtp_nmap_${SMTP_PORT}.txt" "${MAIL_DIR}/smtp_nmap.txt"  2>/dev/null || true
    fi

    if grep -qi "smtp-open-relay.*RELAYING\|Server is an open relay" \
        "${SMTP_DIR}/smtp_nmap_${SMTP_PORT}.txt" 2>/dev/null; then
        warn "SMTP ${SMTP_PORT}: OPEN RELAY detected — can send email as any sender"
    fi

    # smtp-user-enum (VRFY first, RCPT fallback)
    if command -v smtp-user-enum &>/dev/null && [[ -n "$SMTP_UE_WL" ]]; then
        cmd "smtp-user-enum -M VRFY -U $SMTP_UE_WL -t $TARGET -p $SMTP_PORT"
        smtp-user-enum -M VRFY -U "$SMTP_UE_WL" -t "$TARGET" -p "$SMTP_PORT" \
            2>&1 | tee "${SMTP_DIR}/smtp_users_vrfy_${SMTP_PORT}.txt" || true

        VRFY_HITS=$(grep -c 'exists\|250\|^250' \
            "${SMTP_DIR}/smtp_users_vrfy_${SMTP_PORT}.txt" 2>/dev/null || echo 0)

        if [[ "$VRFY_HITS" -eq 0 ]] || \
           grep -qi "not implemented\|502\|Disallowed\|disabled" \
               "${SMTP_DIR}/smtp_users_vrfy_${SMTP_PORT}.txt" 2>/dev/null; then
            info "VRFY returned no results — falling back to RCPT method"
            cmd "smtp-user-enum -M RCPT -U $SMTP_UE_WL -t $TARGET -p $SMTP_PORT"
            smtp-user-enum -M RCPT -U "$SMTP_UE_WL" -t "$TARGET" -p "$SMTP_PORT" \
                2>&1 | tee "${SMTP_DIR}/smtp_users_rcpt_${SMTP_PORT}.txt" || true
            cat "${SMTP_DIR}/smtp_users_vrfy_${SMTP_PORT}.txt" \
                "${SMTP_DIR}/smtp_users_rcpt_${SMTP_PORT}.txt" \
                > "${SMTP_DIR}/smtp_users.txt" 2>/dev/null || true
        else
            cp "${SMTP_DIR}/smtp_users_vrfy_${SMTP_PORT}.txt" \
               "${SMTP_DIR}/smtp_users.txt" 2>/dev/null || true
        fi

        VALID=$(grep -oP '(?<=\] )\S+(?= exists)' "${SMTP_DIR}/smtp_users.txt" 2>/dev/null \
            | sort -u || true)
        [[ -n "$VALID" ]] && ok "SMTP valid users: ${WHITE}$(echo "$VALID" | tr '\n' ' ')${NC}"
    else
        hint "SMTP user enumeration (smtp-user-enum not found or no wordlist):
    smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt \\
        -t ${TARGET} -p ${SMTP_PORT}
    smtp-user-enum -M RCPT -U ${OUTPUT_DIR}/smb/users_rpc.txt \\
        -t ${TARGET} -p ${SMTP_PORT}"
    fi

    hint "SMTP manual interaction (port ${SMTP_PORT}):
  nc -nv ${TARGET} ${SMTP_PORT}
  > EHLO test
  > VRFY root
  > EXPN admin
  swaks --to root@localhost --from test@test.com --server ${TARGET}:${SMTP_PORT}"
    echo ""
done

# ===========================================================================
# POP3 — ports 110, 995
# ===========================================================================
for POP3_PORT in 110 995; do
    has_port "$POP3_PORT" || continue

    info "[POP3] Port ${POP3_PORT} — banner + capabilities"

    cmd "nc -nv -w 5 $TARGET $POP3_PORT"
    POP3_BANNER=$(timeout 5 bash -c "echo 'QUIT' | nc -nv -w 5 $TARGET $POP3_PORT" 2>&1 || true)
    echo "$POP3_BANNER" > "${MAIL_DIR}/pop3_banner.txt"
    BANNER_LINE=$(echo "$POP3_BANNER" | grep -E '^\+OK' | head -1 | cut -c1-100 || true)
    [[ -n "$BANNER_LINE" ]] && ok "POP3 ${POP3_PORT} banner: ${WHITE}${BANNER_LINE}${NC}" || true

    cmd "nmap -p${POP3_PORT} --script pop3-capabilities,pop3-ntlm-info -Pn $TARGET"
    nmap -p"${POP3_PORT}" \
        --script 'pop3-capabilities,pop3-ntlm-info' \
        -Pn "$TARGET" \
        -oN "${MAIL_DIR}/pop3_nmap.txt" 2>&1 | tee "${MAIL_DIR}/pop3_nmap.txt" || true

    if grep -qi "Target_Name\|NetBIOS" "${MAIL_DIR}/pop3_nmap.txt" 2>/dev/null; then
        ok "POP3 NTLM info disclosure — hostname/domain revealed (check pop3_nmap.txt)"
    fi

    hint "POP3 manual login (port ${POP3_PORT}):
  nc -nv ${TARGET} ${POP3_PORT}
  > USER <username>
  > PASS <password>
  > LIST          ← list messages
  > RETR 1        ← read message 1
  curl -v pop3://${TARGET} --user USER:PASS"
    echo ""
done

# ===========================================================================
# IMAP — ports 143, 993
# ===========================================================================
for IMAP_PORT in 143 993; do
    has_port "$IMAP_PORT" || continue

    info "[IMAP] Port ${IMAP_PORT} — capabilities + NTLM check"

    cmd "nc -nv -w 5 $TARGET $IMAP_PORT"
    IMAP_BANNER=$(timeout 5 bash -c "echo 'A1 LOGOUT' | nc -nv -w 5 $TARGET $IMAP_PORT" 2>&1 || true)
    echo "$IMAP_BANNER" > "${MAIL_DIR}/imap_banner.txt"
    BANNER_LINE=$(echo "$IMAP_BANNER" | grep -E '^\* OK' | head -1 | cut -c1-100 || true)
    [[ -n "$BANNER_LINE" ]] && ok "IMAP ${IMAP_PORT} banner: ${WHITE}${BANNER_LINE}${NC}" || true

    cmd "nmap -p${IMAP_PORT} --script imap-capabilities,imap-ntlm-info -Pn $TARGET"
    nmap -p"${IMAP_PORT}" \
        --script 'imap-capabilities,imap-ntlm-info' \
        -Pn "$TARGET" \
        -oN "${MAIL_DIR}/imap_nmap.txt" 2>&1 | tee "${MAIL_DIR}/imap_nmap.txt" || true

    if grep -qi "Target_Name\|NetBIOS" "${MAIL_DIR}/imap_nmap.txt" 2>/dev/null; then
        ok "IMAP NTLM info disclosure — hostname/domain may be in output"
    fi

    hint "IMAP manual login (port ${IMAP_PORT}):
  nc -nv ${TARGET} ${IMAP_PORT}
  > A1 LOGIN <user> <pass>
  > A2 LIST '' '*'       ← list all mailboxes
  > A3 SELECT INBOX
  > A4 FETCH 1 BODY[]    ← read message 1
  curl -v imap://${TARGET}/INBOX --user USER:PASS
  openssl s_client -connect ${TARGET}:993  ← IMAPS"
    echo ""
done

echo ""
ok "Mail enumeration complete → ${MAIL_DIR}/, ${SMTP_DIR}/"
echo ""
