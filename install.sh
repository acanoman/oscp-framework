#!/usr/bin/env bash
# =============================================================================
#  install.sh — OSCP Framework Setup
#  Makes all wrappers executable and verifies required tools are present.
#
#  Usage: bash install.sh
# =============================================================================
set -uo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
CYAN='\033[0;36m';  WHITE='\033[1;37m';  NC='\033[0m'; BOLD='\033[1m'

ok()   { echo -e "  ${GREEN}[✓]${NC} $*"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $*"; }
err()  { echo -e "  ${RED}[✗]${NC} $*"; }
info() { echo -e "  ${CYAN}[*]${NC} $*"; }

# Resolve project root (directory containing this script)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo -e "  ${BOLD}============================================================${NC}"
echo -e "  ${BOLD}  OSCP ENUMERATION FRAMEWORK — INSTALLER${NC}"
echo -e "  ${BOLD}============================================================${NC}"
echo ""

# ===========================================================================
# 1 — Make all wrappers executable
# ===========================================================================
info "Setting execute permissions on wrappers..."

WRAPPERS_DIR="${SCRIPT_DIR}/wrappers"
if [[ ! -d "$WRAPPERS_DIR" ]]; then
    err "wrappers/ directory not found at ${WRAPPERS_DIR}"
    exit 1
fi

WRAPPER_COUNT=0
while IFS= read -r -d '' wrapper; do
    chmod +x "$wrapper"
    ok "chmod +x $(basename "$wrapper")"
    WRAPPER_COUNT=$(( WRAPPER_COUNT + 1 ))
done < <(find "$WRAPPERS_DIR" -maxdepth 1 -name "*.sh" -print0)

if [[ $WRAPPER_COUNT -eq 0 ]]; then
    warn "No .sh files found in wrappers/ — check your installation."
else
    ok "${WRAPPER_COUNT} wrapper(s) made executable."
fi
echo ""

# ===========================================================================
# 2 — Install system packages
# ===========================================================================
info "Installing apt packages (requires sudo)..."
echo ""

APT_PACKAGES=(
    # Python
    python3-rich
    python3-impacket
    # Database clients
    default-mysql-client
    postgresql-client
    redis-tools
    # Remote access
    freerdp2-x11
    # SNMP
    snmp
    snmp-mibs-downloader
    onesixtyone
    # NFS
    nfs-common
    # DNS
    dnsutils
    dnsrecon
    # Mail
    smtp-user-enum
    swaks
)

if sudo apt-get install -y "${APT_PACKAGES[@]}" &>/dev/null; then
    ok "apt packages installed successfully."
else
    warn "apt install encountered errors — some packages may be missing."
    warn "Run manually: sudo apt-get install -y ${APT_PACKAGES[*]}"
fi

# evil-winrm is a Ruby gem (not in apt)
info "Installing evil-winrm (Ruby gem)..."
if command -v gem &>/dev/null; then
    if sudo gem install evil-winrm &>/dev/null; then
        ok "evil-winrm installed."
    else
        warn "evil-winrm gem install failed — install manually: sudo gem install evil-winrm"
    fi
else
    warn "gem not found — install ruby first, then: sudo gem install evil-winrm"
fi
echo ""

# ===========================================================================
# 3 — Verify Python version
# ===========================================================================
info "Checking Python version..."
if command -v python3 &>/dev/null; then
    PY_VERSION=$(python3 --version 2>&1 | grep -oP '\d+\.\d+' | head -1)
    PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
    if (( PY_MAJOR >= 3 && PY_MINOR >= 8 )); then
        ok "Python ${PY_VERSION} (OK)"
    else
        warn "Python ${PY_VERSION} — recommend 3.8 or newer"
    fi
else
    err "python3 not found — install Python 3.8+"
fi
echo ""

# ===========================================================================
# 4 — Tool availability check (non-fatal — warns only)
# ===========================================================================
info "Checking tool availability..."
echo ""

check_tool() {
    local tool="$1"
    local desc="${2:-}"
    if command -v "$tool" &>/dev/null; then
        ok "${tool}${desc:+  (${desc})}"
    else
        warn "${tool} — not found${desc:+  (${desc})}"
    fi
}

echo -e "  ${BOLD}[ Recon ]${NC}"
check_tool "nmap"         "required"
check_tool "rustscan"     "optional — faster port scan"
echo ""

echo -e "  ${BOLD}[ SMB ]${NC}"
check_tool "smbclient"     "required for SMB"
check_tool "smbmap"        "required for SMB"
check_tool "rpcclient"     "required for SMB"
check_tool "enum4linux"    "optional"
check_tool "enum4linux-ng" "optional (preferred)"
check_tool "nxc"           "optional"
check_tool "netexec"       "optional"
check_tool "crackmapexec"  "optional (legacy)"
echo ""

echo -e "  ${BOLD}[ FTP ]${NC}"
check_tool "ftp"           "required for FTP"
check_tool "curl"          "required"
echo ""

echo -e "  ${BOLD}[ Web ]${NC}"
check_tool "curl"          "required"
check_tool "whatweb"       "required for web"
check_tool "gobuster"      "required for web"
check_tool "feroxbuster"   "optional (preferred for web)"
check_tool "nikto"         "required for web"
check_tool "wpscan"        "optional — WordPress only"
echo ""

echo -e "  ${BOLD}[ LDAP / AD ]${NC}"
check_tool "ldapsearch"    "required for LDAP"
echo ""

echo -e "  ${BOLD}[ DNS ]${NC}"
check_tool "dig"           "required — dnsutils"
check_tool "host"          "required — dnsutils"
check_tool "dnsrecon"      "required for DNS recon"
check_tool "gobuster"      "required for DNS brute-force"
echo ""

echo -e "  ${BOLD}[ SNMP ]${NC}"
check_tool "snmpwalk"      "required — snmp"
check_tool "onesixtyone"   "required — community string brute"
check_tool "snmp-check"    "optional"
echo ""

echo -e "  ${BOLD}[ NFS ]${NC}"
check_tool "showmount"     "required — nfs-common"
check_tool "rpcinfo"       "required — nfs-common"
echo ""

echo -e "  ${BOLD}[ Databases ]${NC}"
check_tool "mysql"         "required — default-mysql-client"
check_tool "psql"          "required — postgresql-client"
check_tool "redis-cli"     "required — redis-tools"
check_tool "mongosh"       "optional — MongoDB shell"
echo ""

echo -e "  ${BOLD}[ Remote Access ]${NC}"
check_tool "xfreerdp"      "required — freerdp2-x11"
check_tool "evil-winrm"    "required — gem install evil-winrm"
echo ""

echo -e "  ${BOLD}[ Mail ]${NC}"
check_tool "smtp-user-enum" "required — user enumeration via VRFY"
check_tool "swaks"          "required — SMTP testing"
check_tool "nc"             "required — manual banner grabs"
echo ""

echo -e "  ${BOLD}[ Post-Exploitation Helpers (not automated) ]${NC}"
check_tool "impacket-GetNPUsers"  "AS-REP Roasting"
check_tool "impacket-GetUserSPNs" "Kerberoasting"
check_tool "bloodhound-python"    "BloodHound"
echo ""

# ===========================================================================
# 5 — Create output directory skeleton
# ===========================================================================
info "Creating output/ directory skeleton..."
mkdir -p "${SCRIPT_DIR}/output/targets"
ok "output/targets/ ready"
echo ""

# ===========================================================================
# 6 — Quick smoke test (python import check)
# ===========================================================================
info "Running Python import check..."
if python3 -c "
import sys, pathlib
sys.path.insert(0, '${SCRIPT_DIR}')
from core.session import Session, TargetInfo
from core.engine import Engine
from core.parser import NmapParser
from core.recommender import Recommender
from core.advisor import generate_advisor_markdown
from core.arsenal_rules import WINDOWS_PRIVESC, LINUX_PRIVESC, AD_TOOLS
from core.runner import run_wrapper
import modules.network
import modules.smb
import modules.ftp
import modules.ldap
import modules.dns
import modules.snmp
import modules.nfs
import modules.services
import modules.databases
import modules.remote
import modules.mail
import modules.web
print('All imports OK')
" 2>&1; then
    ok "All Python modules import successfully."
else
    err "Python import check failed — check error above."
fi
echo ""

# ===========================================================================
# Done
# ===========================================================================
echo -e "  ${BOLD}============================================================${NC}"
echo -e "  ${BOLD}  Installation complete!${NC}"
echo -e "  ${BOLD}============================================================${NC}"
echo ""
echo -e "  Run the framework:"
echo -e "  ${WHITE}python3 main.py --target <IP>${NC}"
echo -e "  ${WHITE}python3 main.py --target <IP> --domain corp.local${NC}"
echo -e "  ${WHITE}python3 main.py --target <IP> --dry-run${NC}"
echo -e "  ${WHITE}python3 main.py --target <IP> --modules smb web${NC}"
echo ""
