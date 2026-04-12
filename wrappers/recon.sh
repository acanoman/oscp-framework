#!/usr/bin/env bash
# =============================================================================
#  wrappers/recon.sh — Initial Recon Wrapper
#  Stages: TTL OS detection → RustScan/Nmap (all ports) → UDP top-100 → Deep scan
#
#  Usage:
#    bash wrappers/recon.sh --target <IP> --output-dir <DIR> [--domain <DOMAIN>]
#
#  Output files written:
#    <DIR>/scans/allports.txt       — fast scan (all TCP)
#    <DIR>/scans/open_ports.txt     — comma-separated open ports
#    <DIR>/scans/udp.txt            — UDP top-100
#    <DIR>/scans/open_ports_udp.txt — comma-separated open UDP ports
#    <DIR>/scans/targeted.{nmap,xml,gnmap} — deep -sC -sV scan
#    <DIR>/scans/nmap_initial.xml   — symlink/copy used by parser
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Colours
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; WHITE='\033[1;37m'; NC='\033[0m'; BOLD='\033[1m'
# Disable ANSI colors when stdout is not a TTY (e.g. piped to Python)
[ -t 1 ] || { RED=""; GREEN=""; YELLOW=""; CYAN=""; WHITE=""; NC=""; BOLD=""; }

info()  { echo -e "  ${CYAN}[*]${NC} $*"; }
ok()    { echo -e "  ${GREEN}[+]${NC} $*"; }
warn()  { echo -e "  ${YELLOW}[!]${NC} $*"; }
err()   { echo -e "  ${RED}[-]${NC} $*"; }
cmd()   { echo -e "  ${YELLOW}[CMD]${NC} $*"; }
hint()  { echo -e "\n  ${YELLOW}[MANUAL]${NC} $*\n"; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
TARGET=""
OUTPUT_DIR=""
DOMAIN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)     TARGET="$2";     shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --domain)     DOMAIN="$2";     shift 2 ;;
        *) err "Unknown argument: $1"; exit 1 ;;
    esac
done

if [[ -z "$TARGET" || -z "$OUTPUT_DIR" ]]; then
    err "Usage: $0 --target <IP> --output-dir <DIR> [--domain <DOMAIN>]"
    exit 1
fi

SCANS_DIR="${OUTPUT_DIR}/scans"
mkdir -p "$SCANS_DIR"

# ---------------------------------------------------------------------------
# Helper: run a command and tee output
# ---------------------------------------------------------------------------
run() {
    local outfile="$1"; shift
    cmd "$*"
    "$@" 2>&1 | tee "$outfile"
    return "${PIPESTATUS[0]}"
}

echo ""
echo -e "  ${BOLD}============================================================${NC}"
echo -e "  ${BOLD}  RECON — ${TARGET}${NC}"
[[ -n "$DOMAIN" ]] && echo -e "  ${BOLD}  Domain: ${DOMAIN}${NC}"
echo -e "  ${BOLD}============================================================${NC}"
echo ""

# ===========================================================================
# STEP 1 — TTL OS Detection
# ===========================================================================
info "Step 1/4 — TTL OS Detection"

TTL_VAL=""
if command -v ping &>/dev/null; then
    TTL_VAL=$(ping -c 1 -W 2 "$TARGET" 2>/dev/null | grep -oP 'ttl=\K[0-9]+' | head -1)
fi

if [[ -n "$TTL_VAL" ]]; then
    ok "TTL received: ${WHITE}${TTL_VAL}${NC}"
    if   (( TTL_VAL <= 64 ));  then ok "OS Guess: ${GREEN}Linux${NC} (TTL ≤ 64)"
    elif (( TTL_VAL <= 128 )); then ok "OS Guess: ${CYAN}Windows${NC} (TTL ≤ 128)"
    elif (( TTL_VAL <= 255 )); then ok "OS Guess: ${YELLOW}Network Device / Cisco${NC} (TTL ≤ 255)"
    fi
    echo "$TTL_VAL" > "${SCANS_DIR}/ttl.txt"
else
    warn "No ping response — target may be blocking ICMP. Scans will use -Pn."
fi
echo ""

# ===========================================================================
# STEP 2 — Fast TCP Port Scan (all 65535 ports)
# ===========================================================================
info "Step 2/4 — Fast TCP Port Scan (all 65535 ports)"

FAST_OUT="${SCANS_DIR}/allports.txt"

# Skip if a valid previous result exists
if [[ -s "$FAST_OUT" ]] && grep -qP '^[0-9]+/tcp\s+open' "$FAST_OUT" 2>/dev/null; then
    ok "Existing scan found (${FAST_OUT}) — skipping re-scan."
elif command -v rustscan &>/dev/null; then
    info "RustScan detected — using for maximum speed."
    cmd "rustscan -a $TARGET --ulimit 5000 -- -sS -Pn -n -oN $FAST_OUT"
    rustscan -a "$TARGET" --ulimit 5000 -- -sS -Pn -n -oN "$FAST_OUT" 2>&1 || true
else
    info "RustScan not found — falling back to nmap --min-rate 5000."
    cmd "nmap -p- --open -sS --min-rate 5000 -n -Pn $TARGET -oN $FAST_OUT"
    nmap -p- --open -sS --min-rate 5000 -n -Pn "$TARGET" -oN "$FAST_OUT" 2>&1 || true
fi

# Extract open TCP ports
PORTS=""
if [[ -s "$FAST_OUT" ]]; then
    # Standard nmap format: "80/tcp   open  http"
    PORTS=$(awk -F/ '/^[0-9]+\/tcp[ \t]+open[ \t]+/ {print $1}' "$FAST_OUT" \
            | sort -un | paste -sd, -)

    # RustScan raw fallback: "Open 10.10.10.10:80"
    if [[ -z "$PORTS" ]]; then
        PORTS=$(grep -i "^Open " "$FAST_OUT" 2>/dev/null \
                | grep -oP ':\K\d+' | sort -un | paste -sd, -)
    fi
fi

if [[ -z "$PORTS" ]]; then
    warn "No open TCP ports found. Check target reachability."
    exit 0
fi

echo "$PORTS" > "${SCANS_DIR}/open_ports.txt"
ok "Open TCP ports: ${WHITE}${PORTS}${NC}"
echo ""

# ===========================================================================
# STEP 3 — UDP Top-100 Scan
# ===========================================================================
info "Step 3/4 — UDP Top-100 Port Scan (requires root/sudo)"

UDP_OUT="${SCANS_DIR}/udp.txt"
cmd "sudo nmap -sU --top-ports 100 --min-rate 1000 -Pn $TARGET -oN $UDP_OUT"
sudo nmap -sU --top-ports 100 --min-rate 1000 -Pn "$TARGET" -oN "$UDP_OUT" 2>&1 || \
    warn "UDP scan failed — try running as root."

PORTS_UDP=""
if [[ -s "$UDP_OUT" ]]; then
    PORTS_UDP=$(awk -F/ '/^[0-9]+\/udp[ \t]+open[ \t]+/ {print $1}' "$UDP_OUT" \
                | paste -sd, -)
fi

if [[ -n "$PORTS_UDP" ]]; then
    echo "$PORTS_UDP" > "${SCANS_DIR}/open_ports_udp.txt"
    ok "Open UDP ports: ${WHITE}${PORTS_UDP}${NC}"
else
    warn "No open UDP ports detected (or ICMP filtered)."
fi
echo ""

# ===========================================================================
# STEP 4 — Deep Service + Script Scan (targeted, foreground — results needed)
# ===========================================================================
info "Step 4/4 — Deep Service + Script Scan (-sC -sV -O)"

DEEP_BASE="${SCANS_DIR}/targeted"
cmd "sudo nmap -p${PORTS} -sC -sV -O --script-timeout 30s -Pn $TARGET -oA $DEEP_BASE"
sudo nmap -p"$PORTS" -sC -sV -O --script-timeout 30s -Pn "$TARGET" \
    -oA "$DEEP_BASE" 2>&1 | tee "${DEEP_BASE}.nmap" || \
    warn "Deep scan exited non-zero — partial results may still be available."

# Copy XML for the Python parser (guard: nmap may skip -O on hardened hosts)
if [[ -f "${DEEP_BASE}.xml" ]]; then
    cp "${DEEP_BASE}.xml" "${SCANS_DIR}/nmap_initial.xml" || \
        warn "Could not copy ${DEEP_BASE}.xml — check permissions."
    ok "Deep scan XML → ${WHITE}${SCANS_DIR}/nmap_initial.xml${NC}"
else
    warn "No XML output produced by deep scan — OS detection may be unavailable."
fi

# NSE vuln scan — run in background (slow, ~15 min)
# We launch it detached so the engine can proceed
VULN_OUT="${SCANS_DIR}/vulns.txt"
info "Launching NSE vuln scan in background (output: vulns.txt)..."
cmd "nmap -p${PORTS} -sV --script vuln,auth --script-timeout 60s -Pn $TARGET -oN $VULN_OUT"
nmap -p"$PORTS" -sV --script vuln,auth --script-timeout 60s -Pn "$TARGET" \
    -oN "$VULN_OUT" &>/dev/null &
VULN_PID=$!
echo "$VULN_PID" > "${SCANS_DIR}/vulns.pid"
ok "Vuln scan running in background — PID ${VULN_PID} saved to ${SCANS_DIR}/vulns.pid"
ok "Output when complete: ${VULN_OUT}"

# DNS recon if port 53 is open
if echo ",$PORTS," | grep -q ",53,"; then
    DNS_DIR="${OUTPUT_DIR}/dns"
    mkdir -p "$DNS_DIR"
    info "Port 53 open — running basic DNS recon..."
    cmd "nmap -p53 --script dns-nsid,dns-recursion -Pn $TARGET -oN $DNS_DIR/dns_nmap.txt"
    nmap -p53 --script dns-nsid,dns-recursion -Pn "$TARGET" \
        -oN "${DNS_DIR}/dns_nmap.txt" 2>&1 || true

    if [[ -n "$DOMAIN" ]]; then
        cmd "dig axfr $DOMAIN @$TARGET"
        dig axfr "$DOMAIN" @"$TARGET" 2>&1 | tee "${DNS_DIR}/zone_transfer.txt" || true
        if grep -q "XFR size" "${DNS_DIR}/zone_transfer.txt" 2>/dev/null; then
            ok "Zone transfer SUCCESSFUL — see ${DNS_DIR}/zone_transfer.txt"
        else
            info "Zone transfer denied (expected)."
        fi
    fi

    hint "Manual DNS steps:
    dig axfr <DOMAIN> @${TARGET}
    dnsrecon -d <DOMAIN> -a
    gobuster dns -d <DOMAIN> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 20"
fi

echo ""
ok "Recon complete for ${WHITE}${TARGET}${NC}"
echo "  Ports: ${PORTS}"
[[ -n "$PORTS_UDP" ]] && echo "  UDP:   ${PORTS_UDP}"
echo "  Files: ${SCANS_DIR}/"
echo ""
