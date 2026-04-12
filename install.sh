#!/usr/bin/env bash
# =============================================================================
#  install.sh — OSCP Framework Setup
#  Makes all wrappers executable, creates a Python venv, installs pip deps,
#  creates run.sh launcher, and verifies required tools are present.
#
#  Usage: sudo bash install.sh
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
# 3b — Create virtualenv and install pip dependencies
# ===========================================================================
info "Setting up Python virtual environment at .venv/ ..."

VENV_DIR="${SCRIPT_DIR}/.venv"
VENV_PYTHON="${VENV_DIR}/bin/python"
VENV_PIP="${VENV_DIR}/bin/pip"

# Ensure python3-venv is available
if ! python3 -m venv --help &>/dev/null; then
    info "Installing python3-venv via apt..."
    sudo apt-get install -y python3-venv &>/dev/null
fi

# Create the venv (idempotent — safe to re-run)
if python3 -m venv "${VENV_DIR}"; then
    ok "Virtual environment created at .venv/"
else
    err "Failed to create virtual environment — aborting pip install."
fi

# Install pip requirements into the venv
if [[ -f "${SCRIPT_DIR}/requirements.txt" ]]; then
    if "${VENV_PIP}" install -q -r "${SCRIPT_DIR}/requirements.txt"; then
        ok "pip requirements installed into .venv/"
    else
        err "pip install failed — check requirements.txt and try again."
    fi
else
    warn "requirements.txt not found — skipping pip install."
fi
echo ""

# ===========================================================================
# 3c — Write run.sh launcher
# ===========================================================================
info "Writing run.sh launcher..."
cat > "${SCRIPT_DIR}/run.sh" << 'RUNSCRIPT'
#!/usr/bin/env bash
# run.sh — Launch the OSCP framework using the project virtualenv.
# Usage: ./run.sh --target <IP> [options]
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${SCRIPT_DIR}/.venv/bin/python" "${SCRIPT_DIR}/main.py" "$@"
RUNSCRIPT
chmod +x "${SCRIPT_DIR}/run.sh"
ok "run.sh created — use ./run.sh --target <IP> from now on"
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
check_tool "ffuf"          "optional — vhost/parameter fuzzing"
check_tool "sslscan"       "optional — TLS enumeration"
echo ""

echo -e "  ${BOLD}[ CMS Scanners (auto-routed by web module) ]${NC}"
check_tool "wpscan"        "WordPress scanner — gem install wpscan"
check_tool "droopescan"    "Drupal/Joomla scanner — pip3 install droopescan"
check_tool "joomscan"      "Joomla scanner — apt install joomscan"
echo ""

echo -e "  ${BOLD}[ Active Directory ]${NC}"
check_tool "kerbrute"      "optional — Kerberos user enum / spray"
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
# 6 — Quick smoke test (python import check, using venv)
# ===========================================================================
info "Running Python import check..."
if "${VENV_PYTHON}" -c "
import sys
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
echo -e "  ${WHITE}./run.sh --target <IP>${NC}"
echo -e "  ${WHITE}./run.sh --target <IP> --domain corp.local --lhost <LHOST>${NC}"
echo -e "  ${WHITE}./run.sh --target <IP> --dry-run${NC}"
echo -e "  ${WHITE}./run.sh --target <IP> --modules smb web${NC}"
echo ""
echo -e "  Or activate the venv manually:"
echo -e "  ${WHITE}source .venv/bin/activate${NC}"
echo -e "  ${WHITE}python3 main.py --target <IP>${NC}"
echo ""
