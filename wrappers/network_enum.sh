#!/usr/bin/env bash
# =============================================================================
#  wrappers/network_enum.sh — Network Topology Discovery Wrapper
#
#  Covers: ICMP probing, traceroute, Nmap topology scan, ARP segment sweep,
#          reverse DNS / PTR lookup — feeds pivot planning in notes.md.
#
#  OSCP compliance:
#    - Passive/active topology discovery only (no exploitation)
#    - No SYN floods or mass targeting (ARP scan is /24 only, with timeout)
#    - All output feeds the pivot/dual-homed host analysis
#    - Prints every command before execution
#
#  Usage:
#    bash wrappers/network_enum.sh --target <IP> --output-dir <DIR> \
#         [--domain <DOMAIN>]
#
#  Output: <DIR>/network/
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; WHITE='\033[1;37m'; NC='\033[0m'; BOLD='\033[1m'

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
TARGET=""; OUTPUT_DIR=""; DOMAIN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)     TARGET="$2";     shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --domain)     DOMAIN="$2";     shift 2 ;;
        *) err "Unknown argument: $1"; exit 1 ;;
    esac
done

if [[ -z "$TARGET" || -z "$OUTPUT_DIR" ]]; then
    err "Usage: $0 --target <IP> --output-dir <DIR>"
    exit 1
fi

NET_DIR="${OUTPUT_DIR}/network"
mkdir -p "$NET_DIR"

echo ""
echo -e "  ${BOLD}============================================================${NC}"
echo -e "  ${BOLD}  NETWORK TOPOLOGY — ${TARGET}${NC}"
echo -e "  ${BOLD}============================================================${NC}"
echo ""

# ===========================================================================
# Step 1 — ICMP host probe + TTL fingerprint
# ===========================================================================
info "[1/5] ICMP host probe (TTL-based OS fingerprint)"
cmd "ping -c 4 -W 2 $TARGET"
PING_OUT=$(timeout 12 ping -c 4 -W 2 "$TARGET" 2>&1 || true)
echo "$PING_OUT" > "${NET_DIR}/ping.txt"

TTL=$(echo "$PING_OUT" | grep -oP 'ttl=\K\d+' | head -1 || true)
if [[ -n "$TTL" ]]; then
    if   [[ "$TTL" -le 64  ]]; then OS_GUESS="Linux/Unix (TTL=${TTL})"
    elif [[ "$TTL" -le 128 ]]; then OS_GUESS="Windows (TTL=${TTL})"
    else                             OS_GUESS="Network Device (TTL=${TTL})"
    fi
    ok "Ping response — ${WHITE}${OS_GUESS}${NC}"
else
    info "No ICMP echo response — target may block ICMP (use -Pn in Nmap scans)"
fi

# ===========================================================================
# Step 2 — Traceroute (network path discovery for pivot planning)
# ===========================================================================
info "[2/5] Traceroute — network path to target"
TRACEROUTE_OUT="${NET_DIR}/traceroute.txt"

if command -v traceroute &>/dev/null; then
    cmd "traceroute -n -m 20 $TARGET"
    timeout 40 traceroute -n -m 20 "$TARGET" 2>&1 | tee "$TRACEROUTE_OUT" || true

    HOP_COUNT=$(grep -cP '^\s*\d+\s' "$TRACEROUTE_OUT" 2>/dev/null || echo 0)
    ok "Traceroute: ${HOP_COUNT} hops to target → ${TRACEROUTE_OUT}"

    if [[ "$HOP_COUNT" -gt 1 ]]; then
        info "Multiple hops detected — check for internal subnets or router/firewall between attacker and target"
        grep -oP '^\s*\d+\s+\K[\d.]+' "$TRACEROUTE_OUT" 2>/dev/null | head -10 \
            > "${NET_DIR}/intermediate_hops.txt" || true
        [[ -s "${NET_DIR}/intermediate_hops.txt" ]] && \
            ok "Intermediate hop IPs → ${NET_DIR}/intermediate_hops.txt"
    fi

elif command -v tracepath &>/dev/null; then
    cmd "tracepath -n $TARGET"
    timeout 40 tracepath -n "$TARGET" 2>&1 | tee "$TRACEROUTE_OUT" || true
else
    skip "traceroute/tracepath"
    # Nmap --traceroute fallback
    cmd "nmap --traceroute -n -Pn -sn $TARGET"
    nmap --traceroute -n -Pn -sn "$TARGET" \
        -oN "${NET_DIR}/nmap_traceroute.txt" 2>&1 | tee "${NET_DIR}/nmap_traceroute.txt" || true
fi

# ===========================================================================
# Step 3 — Nmap OS fingerprint + traceroute
# ===========================================================================
info "[3/5] Nmap OS fingerprint + traceroute"
cmd "nmap --traceroute -O -Pn -n --top-ports 10 $TARGET"
nmap --traceroute -O -Pn -n --top-ports 10 "$TARGET" \
    -oN "${NET_DIR}/nmap_topology.txt" 2>&1 | tee "${NET_DIR}/nmap_topology.txt" || true

OS_MATCH=$(grep -iE "OS details:|Running:" "${NET_DIR}/nmap_topology.txt" 2>/dev/null | head -2 || true)
[[ -n "$OS_MATCH" ]] && ok "Nmap OS: ${WHITE}${OS_MATCH}${NC}"

# ===========================================================================
# Step 4 — ARP scan of local /24 segment
# ===========================================================================
info "[4/5] Local segment discovery (ARP)"
TARGET_SUBNET=$(echo "$TARGET" | grep -oP '^\d+\.\d+\.\d+\.' 2>/dev/null || true)

if command -v arp-scan &>/dev/null && [[ -n "$TARGET_SUBNET" ]]; then
    ARP_RANGE="${TARGET_SUBNET}0/24"
    cmd "arp-scan $ARP_RANGE"
    timeout 30 arp-scan "$ARP_RANGE" 2>&1 | tee "${NET_DIR}/arp_scan.txt" || true

    ARP_COUNT=$(grep -cP '^\d+\.\d+\.\d+\.\d+\s' "${NET_DIR}/arp_scan.txt" 2>/dev/null || echo 0)
    if [[ "$ARP_COUNT" -gt 1 ]]; then
        ok "ARP scan: ${ARP_COUNT} hosts on ${ARP_RANGE} → ${NET_DIR}/arp_scan.txt"
        warn "Multiple hosts on same /24 — check for dual-homed pivot candidates"
    fi
else
    info "arp-scan not available — skipping local ARP sweep"
    hint "Local segment discovery (manual):
  arp-scan ${TARGET_SUBNET:-<SUBNET>}0/24
  nmap -sn ${TARGET_SUBNET:-<SUBNET>}0/24 -Pn   ← ping sweep
  netdiscover -r ${TARGET_SUBNET:-<SUBNET>}0/24  ← passive ARP"
fi

# ===========================================================================
# Step 5 — Reverse DNS + PTR domain auto-detection
# ===========================================================================
info "[5/5] Reverse DNS + hostname resolution"
cmd "host $TARGET"
HOST_OUT=$(host "$TARGET" 2>&1 || true)
echo "$HOST_OUT" > "${NET_DIR}/reverse_dns.txt"

HOSTNAME=$(echo "$HOST_OUT" | grep -oP '\S+\.\S+\.\S+(?=\.$)' \
    | grep -v 'in-addr\|arpa' | head -1 || true)
if [[ -n "$HOSTNAME" ]]; then
    ok "Reverse DNS: ${WHITE}${HOSTNAME}${NC}"
    echo "$HOSTNAME" > "${NET_DIR}/hostname.txt"

    if [[ -z "$DOMAIN" ]]; then
        DETECTED_DOMAIN=$(echo "$HOSTNAME" | sed 's/^[^.]*\.//' | grep -P '\.' || true)
        if [[ -n "$DETECTED_DOMAIN" ]]; then
            ok "Domain auto-detected from PTR: ${WHITE}${DETECTED_DOMAIN}${NC}"
            echo "$DETECTED_DOMAIN" > "${NET_DIR}/domain_detected.txt"
            hint "Re-run with --domain ${DETECTED_DOMAIN} for full DNS/LDAP/SMB domain enumeration"
        fi
    fi
else
    info "No PTR record found for ${TARGET}"
fi

hint "Network topology manual steps:
  traceroute -n ${TARGET}
  nmap --traceroute -sn -Pn ${TARGET}
  arp-scan ${TARGET_SUBNET:-<SUBNET>}0/24

  # After getting a shell — pivot detection commands:
  ip a                       ← look for multiple interfaces
  ip route                   ← look for internal subnets
  netstat -rn                ← routing table (Linux)
  route print                ← routing table (Windows)
  arp -n                     ← ARP cache (known hosts on segment)"

echo ""
ok "Network topology enumeration complete → ${NET_DIR}/"
echo ""
