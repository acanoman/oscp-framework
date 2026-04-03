#!/usr/bin/env bash
# =============================================================================
#  wrappers/ldap_enum.sh — LDAP / Active Directory Enumeration Wrapper
#  Tools: ldapsearch, nmap LDAP scripts
#
#  OSCP compliance:
#    - Anonymous bind enumeration only (no credentials required for null bind)
#    - AS-REP Roasting and Kerberoasting → manual hints only (impacket not run)
#    - No password attacks of any kind
#    - Prints every command before execution
#
#  Usage:
#    bash wrappers/ldap_enum.sh --target <IP> --output-dir <DIR> \
#         [--domain <DOMAIN>] [--user <USER>] [--pass <PASS>]
#
#  Output directory: <DIR>/ldap/
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
TARGET=""; OUTPUT_DIR=""; DOMAIN=""; LDAP_USER=""; LDAP_PASS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)     TARGET="$2";     shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --domain)     DOMAIN="$2";     shift 2 ;;
        --user)       LDAP_USER="$2";  shift 2 ;;
        --pass)       LDAP_PASS="$2";  shift 2 ;;
        *) err "Unknown argument: $1"; exit 1 ;;
    esac
done

if [[ -z "$TARGET" || -z "$OUTPUT_DIR" ]]; then
    err "Usage: $0 --target <IP> --output-dir <DIR> [--domain <DOMAIN>]"
    exit 1
fi

LDAP_DIR="${OUTPUT_DIR}/ldap"
mkdir -p "$LDAP_DIR"

echo ""
echo -e "  ${BOLD}============================================================${NC}"
echo -e "  ${BOLD}  LDAP / AD ENUM — ${TARGET}${NC}"
[[ -n "$DOMAIN" ]] && echo -e "  ${BOLD}  Domain : ${DOMAIN}${NC}"
[[ -n "$LDAP_USER" ]] && echo -e "  ${BOLD}  User   : ${LDAP_USER} (authenticated run)${NC}"
echo -e "  ${BOLD}============================================================${NC}"
echo ""

# ===========================================================================
# 1 — Nmap LDAP scripts
# ===========================================================================
info "[1/5] Nmap LDAP enumeration scripts"
NMAP_LDAP="${LDAP_DIR}/ldap_nmap.txt"
cmd "nmap -p389,636,3268,3269 --script ldap-search,ldap-rootdse,ldap-novell-getpass -Pn $TARGET"
nmap -p389,636,3268,3269 \
    --script 'ldap-search,ldap-rootdse' \
    -Pn "$TARGET" \
    -oN "$NMAP_LDAP" 2>&1 | tee "$NMAP_LDAP" || true
echo ""

# ===========================================================================
# 2 — ldapsearch: discover naming contexts (anonymous bind)
# ===========================================================================
info "[2/5] ldapsearch — discover naming contexts (anonymous bind)"
BASE_OUT="${LDAP_DIR}/ldapsearch_base.txt"

if command -v ldapsearch &>/dev/null; then
    cmd "ldapsearch -x -H ldap://$TARGET -b '' -s base namingcontexts"
    ldapsearch -x -H "ldap://$TARGET" -b '' -s base namingcontexts \
        2>&1 | tee "$BASE_OUT" || true

    # Extract base DN from output
    BASE_DN=$(grep -oP 'DC=\S+' "$BASE_OUT" 2>/dev/null \
        | head -1 \
        | sed 's/,$//' \
        || true)

    if [[ -n "$BASE_DN" ]]; then
        ok "Base DN discovered: ${WHITE}${BASE_DN}${NC}"
        echo "$BASE_DN" > "${LDAP_DIR}/base_dn.txt"

        # ===================================================================
        # 3 — Full anonymous LDAP dump
        # ===================================================================
        info "[3/5] ldapsearch — full anonymous dump (base: $BASE_DN)"
        FULL_OUT="${LDAP_DIR}/ldapsearch_full.txt"
        cmd "ldapsearch -x -H ldap://$TARGET -b '$BASE_DN'"
        ldapsearch -x -H "ldap://$TARGET" -b "$BASE_DN" \
            2>&1 | tee "$FULL_OUT" || true

        # Extract user accounts (sAMAccountName)
        USERS_OUT="${LDAP_DIR}/ldap_users.txt"
        grep -oP '(?<=sAMAccountName: )\S+' "$FULL_OUT" 2>/dev/null \
            | sort -u > "$USERS_OUT" || true
        USER_COUNT=$(wc -l < "$USERS_OUT" 2>/dev/null || echo 0)
        if [[ "$USER_COUNT" -gt 0 ]]; then
            ok "Users extracted from LDAP: ${WHITE}${USER_COUNT}${NC} accounts → ${USERS_OUT}"
        fi

        # Extract computer accounts
        grep -oP '(?<=sAMAccountName: )\S+\$' "$FULL_OUT" 2>/dev/null \
            | sort -u > "${LDAP_DIR}/ldap_computers.txt" || true

        # Extract group names
        grep -oP '(?<=cn: )\S.*' "$FULL_OUT" 2>/dev/null \
            | sort -u | head -50 > "${LDAP_DIR}/ldap_groups.txt" || true

    else
        info "Anonymous bind returned no naming contexts (anonymous bind may be disabled)."

        # ===================================================================
        # 3 — Try with domain if provided
        # ===================================================================
        if [[ -n "$DOMAIN" ]]; then
            # Convert domain to DN format: corp.local → DC=corp,DC=local
            DOMAIN_DN=$(echo "$DOMAIN" | sed 's/\./,DC=/g; s/^/DC=/')
            info "[3/5] Trying with domain DN: $DOMAIN_DN"
            cmd "ldapsearch -x -H ldap://$TARGET -b '$DOMAIN_DN'"
            ldapsearch -x -H "ldap://$TARGET" -b "$DOMAIN_DN" \
                2>&1 | tee "${LDAP_DIR}/ldapsearch_full.txt" || true
        else
            info "[3/5] No base DN and no domain — skipping full dump."
            touch "${LDAP_DIR}/ldapsearch_full.txt"
        fi
    fi

    # =====================================================================
    # 4 — Authenticated LDAP dump (if credentials provided)
    # =====================================================================
    if [[ -n "$LDAP_USER" && -n "$LDAP_PASS" && -n "$BASE_DN" ]]; then
        info "[4/5] Authenticated LDAP dump (${LDAP_USER})"
        AUTH_OUT="${LDAP_DIR}/ldapsearch_auth.txt"
        cmd "ldapsearch -x -H ldap://$TARGET -D '$LDAP_USER' -w '$LDAP_PASS' -b '$BASE_DN'"
        ldapsearch -x -H "ldap://$TARGET" \
            -D "$LDAP_USER" -w "$LDAP_PASS" \
            -b "$BASE_DN" \
            2>&1 | tee "$AUTH_OUT" || true

        # Re-extract users from authenticated dump (may find more)
        grep -oP '(?<=sAMAccountName: )\S+' "$AUTH_OUT" 2>/dev/null \
            | sort -u >> "${LDAP_DIR}/ldap_users.txt" || true
        sort -u "${LDAP_DIR}/ldap_users.txt" -o "${LDAP_DIR}/ldap_users.txt" 2>/dev/null || true
    else
        info "[4/5] No credentials — skipping authenticated LDAP dump."
    fi

else
    skip "ldapsearch"
    info "[3/5] Skipped — ldap-utils not installed."
    info "[4/5] Skipped — ldap-utils not installed."
    hint "Install: sudo apt-get install ldap-utils"
fi

# ===========================================================================
# 5 — windapsearch — deep AD object enumeration
#     Faster and more structured than raw ldapsearch for AD environments.
#     Falls back gracefully if not installed.
# ===========================================================================
info "[5/6] windapsearch — AD user + privileged account enumeration"

if command -v windapsearch &>/dev/null; then
    WIND_DIR="${LDAP_DIR}"

    # Full user dump with all attributes
    cmd "windapsearch -m users --full --dc-ip $TARGET"
    windapsearch -m users --full --dc-ip "$TARGET" \
        2>&1 | tee "${WIND_DIR}/windapsearch_users.txt" || true

    # Extract usernames from windapsearch output
    WIND_USERS=$(grep -oP '(?<=sAMAccountName: )\S+' \
        "${WIND_DIR}/windapsearch_users.txt" 2>/dev/null | sort -u || true)
    if [[ -n "$WIND_USERS" ]]; then
        echo "$WIND_USERS" >> "${LDAP_DIR}/ldap_users.txt"
        sort -u "${LDAP_DIR}/ldap_users.txt" -o "${LDAP_DIR}/ldap_users.txt" 2>/dev/null || true
        WIND_COUNT=$(echo "$WIND_USERS" | wc -l)
        ok "windapsearch found ${WHITE}${WIND_COUNT}${NC} users → ${WIND_DIR}/windapsearch_users.txt"
    fi

    # Privileged users (adminCount=1, Domain Admins, etc.)
    cmd "windapsearch -m privileged-users --dc-ip $TARGET"
    windapsearch -m privileged-users --dc-ip "$TARGET" \
        2>&1 | tee "${WIND_DIR}/windapsearch_privusers.txt" || true

    PRIV_USERS=$(grep -oP '(?<=sAMAccountName: )\S+' \
        "${WIND_DIR}/windapsearch_privusers.txt" 2>/dev/null | sort -u || true)
    if [[ -n "$PRIV_USERS" ]]; then
        warn "Privileged accounts found: ${WHITE}$(echo "$PRIV_USERS" | tr '\n' ' ')${NC}"
        echo "$PRIV_USERS" > "${WIND_DIR}/privileged_users.txt"
    fi

    # Groups enumeration
    cmd "windapsearch -m groups --dc-ip $TARGET"
    windapsearch -m groups --dc-ip "$TARGET" \
        2>&1 | tee "${WIND_DIR}/windapsearch_groups.txt" || true

    # Computers
    cmd "windapsearch -m computers --dc-ip $TARGET"
    windapsearch -m computers --dc-ip "$TARGET" \
        2>&1 | tee "${WIND_DIR}/windapsearch_computers.txt" || true

    # Accounts without pre-auth (AS-REP Roastable) — passive detection only
    cmd "windapsearch -m users --filter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' --dc-ip $TARGET"
    windapsearch \
        -m users \
        --filter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' \
        --dc-ip "$TARGET" \
        2>&1 | tee "${WIND_DIR}/windapsearch_asrep.txt" || true

    ASREP_USERS=$(grep -oP '(?<=sAMAccountName: )\S+' \
        "${WIND_DIR}/windapsearch_asrep.txt" 2>/dev/null | sort -u || true)
    if [[ -n "$ASREP_USERS" ]]; then
        warn "AS-REP Roastable users (no pre-auth): ${WHITE}$(echo "$ASREP_USERS" | tr '\n' ' ')${NC}"
        echo "$ASREP_USERS" > "${WIND_DIR}/asrep_candidates.txt"
        hint "AS-REP Roast (run manually):
    impacket-GetNPUsers <DOMAIN>/ -dc-ip ${TARGET} -no-pass \\
        -usersfile ${WIND_DIR}/asrep_candidates.txt \\
        -outputfile ${WIND_DIR}/asrep_hashes.txt"
    fi

else
    skip "windapsearch"
    hint "Install windapsearch for deeper AD enumeration:
    pip3 install windapsearch
    # Or: git clone https://github.com/ropnop/windapsearch && pip3 install -r requirements.txt"
fi
echo ""

# Targeted ldapsearch for high-value AD attributes
if command -v ldapsearch &>/dev/null && [[ -f "${LDAP_DIR}/base_dn.txt" ]]; then
    BASE_DN=$(cat "${LDAP_DIR}/base_dn.txt" 2>/dev/null || true)
    if [[ -n "$BASE_DN" ]]; then
        info "[5b/6] Targeted ldapsearch — password descriptions + SPNs"

        # Accounts with passwords in description field (very common on OSCP)
        cmd "ldapsearch -x -H ldap://$TARGET -b '$BASE_DN' '(description=*)' sAMAccountName description"
        ldapsearch -x -H "ldap://$TARGET" \
            -b "$BASE_DN" \
            '(description=*)' sAMAccountName description \
            2>&1 | tee "${LDAP_DIR}/ldap_descriptions.txt" || true

        DESC_COUNT=$(grep -c 'description:' "${LDAP_DIR}/ldap_descriptions.txt" 2>/dev/null || echo 0)
        [[ "$DESC_COUNT" -gt 0 ]] && \
            warn "LDAP: ${DESC_COUNT} accounts have Description fields — review for embedded passwords"

        # Kerberoastable accounts (have a ServicePrincipalName)
        cmd "ldapsearch -x -H ldap://$TARGET -b '$BASE_DN' '(servicePrincipalName=*)' sAMAccountName servicePrincipalName"
        ldapsearch -x -H "ldap://$TARGET" \
            -b "$BASE_DN" \
            '(servicePrincipalName=*)' sAMAccountName servicePrincipalName \
            2>&1 | tee "${LDAP_DIR}/ldap_spns.txt" || true

        SPN_COUNT=$(grep -c 'servicePrincipalName:' "${LDAP_DIR}/ldap_spns.txt" 2>/dev/null || echo 0)
        if [[ "$SPN_COUNT" -gt 0 ]]; then
            warn "Kerberoastable accounts (SPNs found): ${SPN_COUNT} — see ${LDAP_DIR}/ldap_spns.txt"
            hint "Kerberoast (run manually — requires valid credentials):
    impacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip ${TARGET} -request \\
        -outputfile ${LDAP_DIR}/kerberoast_hashes.txt
    hashcat -m 13100 ${LDAP_DIR}/kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt"
        fi
    fi
fi
echo ""

# ===========================================================================
# 6 — Kerberos pre-auth check (port 88) — detection only
# ===========================================================================
info "[6/6] Kerberos port check"
if nmap -p88 --open -Pn "$TARGET" 2>/dev/null | grep -q "88/tcp.*open"; then
    ok "Kerberos port 88 is open — this is likely a Domain Controller."
    session_add_note() { true; }  # notes go through Python layer

    hint "AS-REP Roasting (run manually — requires user list):
    impacket-GetNPUsers <DOMAIN>/ -dc-ip ${TARGET} -no-pass \\
        -usersfile ${LDAP_DIR}/ldap_users.txt \\
        -outputfile ${LDAP_DIR}/asrep_hashes.txt

    # Crack hashes:
    hashcat -m 18200 ${LDAP_DIR}/asrep_hashes.txt /usr/share/wordlists/rockyou.txt"

    hint "Kerberoasting (run manually — requires valid credentials):
    impacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip ${TARGET} -request \\
        -outputfile ${LDAP_DIR}/kerberoast_hashes.txt

    # Crack hashes:
    hashcat -m 13100 ${LDAP_DIR}/kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt"

    hint "BloodHound collection (run manually — requires credentials):
    bloodhound-python -u <USER> -p <PASS> -d <DOMAIN> -dc ${TARGET} -c All"
else
    info "Port 88 not open — target may not be a Domain Controller."
fi

echo ""
ok "LDAP enumeration complete — output: ${LDAP_DIR}/"
echo ""
