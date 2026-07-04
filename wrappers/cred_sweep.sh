#!/usr/bin/env bash
# =============================================================================
#  wrappers/cred_sweep.sh — One-Credential Protocol Sweep
#
#  Takes ONE known-good credential and checks, across every relevant open
#  port, which protocols it can authenticate to. One login attempt per
#  protocol as a single user — this is NOT a password spray, so there is no
#  account-lockout risk.  Pure enumeration: it reports where the credential
#  works ("Pwn3d!" = code execution possible) but never opens a shell or runs
#  a command on the target.
#
#  OSCP compliance:
#    - Single authenticated bind per protocol (no brute force, no spraying)
#    - Reports access only — exploitation (evil-winrm, mssqlclient, psexec)
#      stays a manual step
#    - Every command printed before execution
#
#  Usage:
#    bash wrappers/cred_sweep.sh --target <IP> --output-dir <DIR> --ports <CSV> \
#         --user <USER> (--pass <PASS> | --hash <NTLM>) [--domain <D>] [--local-auth]
#
#  Output directory: <DIR>/creds/
# =============================================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; WHITE='\033[1;37m'; NC='\033[0m'; BOLD='\033[1m'
[ -t 1 ] || { RED=""; GREEN=""; YELLOW=""; CYAN=""; WHITE=""; NC=""; BOLD=""; }

info() { echo -e "  ${CYAN}[*]${NC} $*"; }
ok()   { echo -e "  ${GREEN}[+]${NC} $*"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $*"; }
err()  { echo -e "  ${RED}[-]${NC} $*"; }
cmd()  { echo -e "  ${YELLOW}[CMD]${NC} $*"; }
skip() { echo -e "  ${YELLOW}[SKIP]${NC} $1 not installed — skipping."; }

has_port() { echo ",$PORTS," | grep -q ",$1,"; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
TARGET=""; OUTPUT_DIR=""; PORTS=""; CUSER=""; CPASS=""; CHASH=""; DOMAIN=""; LOCAL_AUTH=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)     TARGET="$2";     shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --ports)      PORTS="$2";      shift 2 ;;
        --user)       CUSER="$2";      shift 2 ;;
        --pass)       CPASS="$2";      shift 2 ;;
        --hash)       CHASH="$2";      shift 2 ;;
        --domain)     DOMAIN="$2";     shift 2 ;;
        --local-auth) LOCAL_AUTH=1;    shift ;;
        *) err "Unknown argument: $1"; exit 1 ;;
    esac
done

if [[ -z "$TARGET" || -z "$OUTPUT_DIR" || -z "$CUSER" || ( -z "$CPASS" && -z "$CHASH" ) ]]; then
    err "Usage: $0 --target <IP> --output-dir <DIR> --ports <CSV> --user <U> (--pass P | --hash H)"
    exit 1
fi

CRED_DIR="${OUTPUT_DIR}/creds"
mkdir -p "$CRED_DIR"
SUMMARY="${CRED_DIR}/sweep_summary.txt"
: > "$SUMMARY"

# Preferred tool
NXC=""
command -v nxc          &>/dev/null && NXC="nxc"
command -v netexec      &>/dev/null && [[ -z "$NXC" ]] && NXC="netexec"
command -v crackmapexec &>/dev/null && [[ -z "$NXC" ]] && NXC="crackmapexec"

echo ""
echo -e "  ${BOLD}============================================================${NC}"
echo -e "  ${BOLD}  ONE-CREDENTIAL SWEEP — ${TARGET}${NC}"
AUTH_KIND="password"; [[ -n "$CHASH" ]] && AUTH_KIND="NTLM hash (PTH)"
echo -e "  ${BOLD}  User   : ${CUSER} (${AUTH_KIND})${NC}"
echo -e "  ${BOLD}============================================================${NC}"
echo ""
warn "One login attempt per protocol as a single user — no spraying, no lockout risk."

if [[ -z "$NXC" ]]; then
    skip "nxc/netexec/crackmapexec"
    err "Credential sweep needs nxc/netexec — install it to use authenticated mode."
    exit 0
fi

# Common credential args
BASE_CRED=( -u "$CUSER" )
if [[ -n "$CPASS" ]]; then BASE_CRED+=( -p "$CPASS" ); else BASE_CRED+=( -H "$CHASH" ); fi
LA_ARGS=()
if [[ "$LOCAL_AUTH" == "1" ]]; then
    LA_ARGS=( --local-auth )
elif [[ -n "$DOMAIN" ]]; then
    LA_ARGS=( -d "$DOMAIN" )
fi

# ---------------------------------------------------------------------------
# Run one protocol check. $1 = nxc protocol, $2 = human label, rest = ports we
# already know are open (any match triggers the check).
# ---------------------------------------------------------------------------
sweep_proto() {
    local proto="$1"; local label="$2"; shift 2
    local hit=0 p
    for p in "$@"; do has_port "$p" && hit=1; done
    [[ "$hit" == "0" ]] && return 0

    local out="${CRED_DIR}/nxc_${proto}.txt"
    cmd "$NXC $proto $TARGET ${BASE_CRED[*]} ${LA_ARGS[*]}"
    $NXC "$proto" "$TARGET" "${BASE_CRED[@]}" "${LA_ARGS[@]}" \
        2>&1 | tee "$out" || true

    if grep -qi 'Pwn3d' "$out" 2>/dev/null; then
        ok "${label}: ${WHITE}${CUSER} CAN EXECUTE (Pwn3d!)${NC} — foothold candidate"
        echo "PWN3D  ${label}  — ${CUSER} can execute code" >> "$SUMMARY"
    elif grep -qiE '\[\+\]' "$out" 2>/dev/null; then
        ok "${label}: credential VALID (login OK)"
        echo "VALID  ${label}  — login accepted" >> "$SUMMARY"
    elif grep -qiE 'STATUS_ACCOUNT_LOCKED_OUT' "$out" 2>/dev/null; then
        err "${label}: ACCOUNT LOCKED OUT — stopping further checks to avoid harm"
        echo "LOCKED ${label}  — account locked out" >> "$SUMMARY"
        return 1
    else
        info "${label}: credential rejected or protocol not exposed"
        echo "FAIL   ${label}  — rejected" >> "$SUMMARY"
    fi
    return 0
}

# Sweep each protocol whose port is open. Stop early if a lockout is seen.
sweep_proto smb   "SMB"   445 139   || { warn "Halting sweep after lockout."; exit 0; }
sweep_proto ldap  "LDAP"  389 636   || { warn "Halting sweep after lockout."; exit 0; }
sweep_proto winrm "WinRM" 5985 5986 || { warn "Halting sweep after lockout."; exit 0; }
sweep_proto mssql "MSSQL" 1433      || { warn "Halting sweep after lockout."; exit 0; }
sweep_proto ssh   "SSH"   22        || { warn "Halting sweep after lockout."; exit 0; }
sweep_proto rdp   "RDP"   3389      || { warn "Halting sweep after lockout."; exit 0; }
sweep_proto ftp   "FTP"   21        || { warn "Halting sweep after lockout."; exit 0; }

echo ""
if [[ -s "$SUMMARY" ]]; then
    ok "Credential sweep summary → ${SUMMARY}"
    grep -q '^PWN3D' "$SUMMARY" && \
        warn "At least one protocol allows CODE EXECUTION — see manual shell hints (evil-winrm / psexec / mssqlclient)."
fi
ok "One-credential sweep complete — output: ${CRED_DIR}/"
echo ""
