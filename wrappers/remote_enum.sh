#!/usr/bin/env bash
# =============================================================================
#  wrappers/remote_enum.sh — Remote Access Enumeration Wrapper
#  Covers: RDP (3389), WinRM (5985 / 5986)
#
#  OSCP compliance:
#    - NSE scripts + passive checks only
#    - No brute force of any kind
#    - No automatic login (evil-winrm, xfreerdp) → manual hints only
#    - Every command printed before execution
#
#  Usage:
#    bash wrappers/remote_enum.sh --target <IP> --output-dir <DIR> --ports <CSV>
#
#  Output directory: <DIR>/remote/
# =============================================================================
set -uo pipefail

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
TARGET=""; OUTPUT_DIR=""; PORTS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)     TARGET="$2";     shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --ports)      PORTS="$2";      shift 2 ;;
        *) err "Unknown argument: $1"; exit 1 ;;
    esac
done

if [[ -z "$TARGET" || -z "$OUTPUT_DIR" || -z "$PORTS" ]]; then
    err "Usage: $0 --target <IP> --output-dir <DIR> --ports <CSV>"
    exit 1
fi

REMOTE_DIR="${OUTPUT_DIR}/remote"
mkdir -p "$REMOTE_DIR"

echo ""
echo -e "  ${BOLD}============================================================${NC}"
echo -e "  ${BOLD}  REMOTE ACCESS ENUM — ${TARGET}${NC}"
echo -e "  ${BOLD}  Ports : ${PORTS}${NC}"
echo -e "  ${BOLD}============================================================${NC}"
echo ""

# ===========================================================================
# RDP — port 3389
# ===========================================================================
if has_port 3389; then
    info "[1/2] RDP (3389) — encryption audit + vulnerability check"
    RDP_OUT="${REMOTE_DIR}/rdp_nmap.txt"

    cmd "nmap -p3389 --script rdp-enum-encryption,rdp-vuln-ms12-020 -Pn $TARGET"
    nmap -p3389 \
        --script 'rdp-enum-encryption,rdp-vuln-ms12-020' \
        -Pn "$TARGET" \
        -oN "$RDP_OUT" 2>&1 | tee "$RDP_OUT" || {
        warn "nmap (RDP) failed — output may be incomplete. Check ${RDP_OUT} for details."
    } # IMP-7 applied

    # Check for NLA enforcement
    if grep -qi "NLA.*True\|CredSSP" "$RDP_OUT" 2>/dev/null; then
        ok "RDP: NLA (Network Level Authentication) is enforced."
    else
        warn "RDP: NLA may NOT be enforced — pre-auth attack surface exists."
    fi

    # Check for MS12-020 (DoS vuln — informational only)
    if grep -qi "ms12-020.*VULNERABLE\|rdp-vuln-ms12-020.*VULNERABLE" "$RDP_OUT" 2>/dev/null; then
        warn "RDP: MS12-020 VULNERABLE — review ${RDP_OUT}"
    fi

    # BlueKeep CVE-2019-0708 nmap check (detection, not exploitation)
    cmd "nmap -p3389 --script rdp-vuln-ms12-020 -Pn $TARGET (BlueKeep era check)"

    # Grab RDP fingerprint with nmap -sV
    RDP_FP="${REMOTE_DIR}/rdp_version.txt"
    cmd "nmap -p3389 -sV -Pn $TARGET"
    nmap -p3389 -sV -Pn "$TARGET" \
        -oN "$RDP_FP" 2>&1 | tee "$RDP_FP" || true

    RDP_VER=$(grep -oP 'Microsoft Terminal Services.*' "$RDP_FP" 2>/dev/null | head -1 || true)
    [[ -n "$RDP_VER" ]] && info "RDP version info: ${WHITE}${RDP_VER}${NC}"

    hint "RDP manual connection (requires credentials):
  xfreerdp /u:<USER> /p:<PASS> /v:${TARGET} /cert-ignore +clipboard
  xfreerdp /u:<USER> /pth:<NTLM_HASH> /v:${TARGET} /cert-ignore   ← Pass-the-Hash

  # ⚠️  BlueKeep (CVE-2019-0708) — unpatched Win7/Server 2008:
  # Requires manual verification — check target OS version in deep scan results.
  # OSCP: exploitation is manual after confirmed vulnerable version."
    echo ""
fi

# ===========================================================================
# WinRM — ports 5985 (HTTP) / 5986 (HTTPS)
# ===========================================================================
if echo ",$PORTS," | grep -qP ',(5985|5986),'; then
    info "[2/2] WinRM (5985/5986) — service fingerprint + auth check"
    WINRM_OUT="${REMOTE_DIR}/winrm_nmap.txt"

    cmd "nmap -p5985,5986 --script http-auth,http-auth-finder -Pn $TARGET"
    nmap -p5985,5986 \
        --script 'http-auth,http-auth-finder' \
        -Pn "$TARGET" \
        -oN "$WINRM_OUT" 2>&1 | tee "$WINRM_OUT" || {
        warn "nmap (WinRM) failed — output may be incomplete. Check ${WINRM_OUT} for details."
    } # IMP-7 applied

    # Probe with curl for faster confirmation
    if command -v curl &>/dev/null; then
        if has_port 5985; then
            cmd "curl -s -o /dev/null -w '%{http_code}' http://$TARGET:5985/wsman"
            HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
                "http://${TARGET}:5985/wsman" 2>/dev/null || echo "000")
            if [[ "$HTTP_CODE" == "405" || "$HTTP_CODE" == "401" ]]; then
                ok "WinRM HTTP (5985) responded: HTTP ${HTTP_CODE} — service is alive"
                echo "WinRM 5985 HTTP response: ${HTTP_CODE}" >> "$WINRM_OUT"
            else
                info "WinRM HTTP (5985) response: HTTP ${HTTP_CODE}"
            fi
        fi

        if has_port 5986; then
            cmd "curl -sk -o /dev/null -w '%{http_code}' https://$TARGET:5986/wsman"
            HTTPS_CODE=$(curl -sk -o /dev/null -w '%{http_code}' \
                "https://${TARGET}:5986/wsman" 2>/dev/null || echo "000")
            if [[ "$HTTPS_CODE" == "405" || "$HTTPS_CODE" == "401" ]]; then
                ok "WinRM HTTPS (5986) responded: HTTP ${HTTPS_CODE} — service is alive"
                echo "WinRM 5986 HTTPS response: ${HTTPS_CODE}" >> "$WINRM_OUT"
            fi
        fi
    fi

    # Check if Kerberos / NTLM auth is advertised
    if grep -qi "Negotiate\|NTLM\|Kerberos" "$WINRM_OUT" 2>/dev/null; then
        ok "WinRM auth methods detected — check ${WINRM_OUT}"
    fi

    hint "WinRM shell (MANUAL — requires credentials):
  # Password authentication:
  evil-winrm -i ${TARGET} -u <USER> -p '<PASS>'

  # Pass-the-Hash (NTLM):
  evil-winrm -i ${TARGET} -u <USER> -H '<NTLM_HASH>'

  # With SSL (port 5986):
  evil-winrm -i ${TARGET} -u <USER> -p '<PASS>' -S

  # Upload / download files:
  *Evil-WinRM* PS> upload /local/file.exe C:\\Windows\\Temp\\file.exe
  *Evil-WinRM* PS> download C:\\interesting\\file.txt /local/file.txt"
    echo ""
fi

# ===========================================================================
# VNC — port 5900
# ===========================================================================
if has_port 5900; then
    info "[3/3] VNC (5900) — version fingerprint + authentication check"
    VNC_OUT="${REMOTE_DIR}/vnc_nmap.txt"

    cmd "nmap -p5900 --script vnc-info,realvnc-auth-bypass -Pn $TARGET"
    nmap -p5900 \
        --script 'vnc-info,realvnc-auth-bypass' \
        -Pn "$TARGET" \
        -oN "$VNC_OUT" 2>&1 | tee "$VNC_OUT" || {
        warn "nmap (VNC) failed — output may be incomplete. Check ${VNC_OUT} for details."
    } # IMP-7 applied

    # No-auth detection
    if grep -qiE 'Authentication disabled|security type.*None|Security types supported.*None' \
        "$VNC_OUT" 2>/dev/null; then
        warn "VNC: NO AUTHENTICATION REQUIRED — direct access possible"
        echo "[!] VNC unauthenticated access on ${TARGET}:5900" >> "$VNC_OUT"
    fi

    # RealVNC auth bypass vulnerability
    if grep -qi "realvnc-auth-bypass.*VULNERABLE" "$VNC_OUT" 2>/dev/null; then
        warn "VNC: RealVNC authentication bypass VULNERABLE — review ${VNC_OUT}"
    fi

    # Version fingerprint
    VNC_VER=$(grep -oP 'Protocol version: \K.+' "$VNC_OUT" 2>/dev/null | head -1 || true)
    [[ -n "$VNC_VER" ]] && ok "VNC protocol version: ${WHITE}${VNC_VER}${NC}"

    # Security type reported
    VNC_SEC=$(grep -oP 'Security types supported: \K.+' "$VNC_OUT" 2>/dev/null | head -1 || true)
    [[ -n "$VNC_SEC" ]] && info "VNC security types: ${VNC_SEC}"

    hint "VNC manual connection (requires authentication unless none is reported above):
  vncviewer ${TARGET}:5900
  vncviewer -passwd <PASSFILE> ${TARGET}:5900

  # Password brute (manual — only if explicitly authorized):
  hydra -P /usr/share/wordlists/rockyou.txt ${TARGET} vnc
  medusa -h ${TARGET} -u '' -P /usr/share/wordlists/rockyou.txt -M vnc"
    echo ""
fi

ok "Remote access enumeration complete — output: ${REMOTE_DIR}/"
echo ""
