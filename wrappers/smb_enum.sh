#!/usr/bin/env bash
# =============================================================================
#  wrappers/smb_enum.sh — SMB Enumeration Wrapper
#  Tools: enum4linux-ng/enum4linux, smbmap, smbclient, rpcclient, nxc/cme
#
#  OSCP compliance: Read-only enumeration only. No brute-force. No exploitation.
#  All tools run with null/guest sessions. Authenticated runs require explicit creds.
#
#  Usage:
#    bash wrappers/smb_enum.sh --target <IP> --output-dir <DIR> \
#         [--user <USER>] [--pass <PASS>] [--domain <DOMAIN>]
#
#  Output directory: <DIR>/smb/
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
TARGET=""; OUTPUT_DIR=""; SMB_USER=""; SMB_PASS=""; DOMAIN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)     TARGET="$2";     shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --user)       SMB_USER="$2";   shift 2 ;;
        --pass)       SMB_PASS="$2";   shift 2 ;;
        --domain)     DOMAIN="$2";     shift 2 ;;
        *) err "Unknown argument: $1"; exit 1 ;;
    esac
done

if [[ -z "$TARGET" || -z "$OUTPUT_DIR" ]]; then
    err "Usage: $0 --target <IP> --output-dir <DIR> [--user U --pass P --domain D]"
    exit 1
fi

# ---------------------------------------------------------------------------
# Domain resolution — read domain.txt written by the Python engine if
# --domain was not supplied on the command line.
# ---------------------------------------------------------------------------
DOMAIN_FILE="${OUTPUT_DIR}/domain.txt"
if [[ -z "$DOMAIN" && -f "$DOMAIN_FILE" ]]; then
    DOMAIN=$(cat "$DOMAIN_FILE" | tr -d '[:space:]')
    [[ -n "$DOMAIN" ]] && ok "Domain read from domain.txt: ${WHITE}${DOMAIN}${NC}"
fi

SMB_DIR="${OUTPUT_DIR}/smb"
mkdir -p "$SMB_DIR"

# Detect preferred SMB tool (nxc > netexec > crackmapexec)
NXC=""
command -v nxc        &>/dev/null && NXC="nxc"
command -v netexec    &>/dev/null && NXC="netexec"
command -v crackmapexec &>/dev/null && [[ -z "$NXC" ]] && NXC="crackmapexec"

echo ""
echo -e "  ${BOLD}============================================================${NC}"
echo -e "  ${BOLD}  SMB ENUM — ${TARGET}${NC}"
[[ -n "$DOMAIN" ]] && echo -e "  ${BOLD}  Domain : ${DOMAIN}${NC}"
[[ -n "$SMB_USER" ]] && echo -e "  ${BOLD}  User   : ${SMB_USER} (authenticated run)${NC}"
echo -e "  ${BOLD}============================================================${NC}"
echo ""

# ===========================================================================
# 1 — Nmap SMB scripts (safe NSE only)
# ===========================================================================
info "[1/7] Nmap SMB enumeration scripts"
NMAP_SMB="${SMB_DIR}/nmap_smb.txt"
cmd "nmap -p445,139 --script smb-vuln*,smb-enum-shares,smb-enum-users,smb-os-discovery,smb2-security-mode,smb-protocols -Pn $TARGET -oN $NMAP_SMB"
nmap -p445,139 \
    --script 'smb-vuln*,smb-enum-shares,smb-enum-users,smb-os-discovery,smb2-security-mode,smb-protocols' \
    -Pn "$TARGET" -oN "$NMAP_SMB" 2>&1 | tee "$NMAP_SMB"

if grep -qi "CVE-" "$NMAP_SMB" 2>/dev/null; then
    warn "Potential CVE match in Nmap SMB output — review ${NMAP_SMB}"
fi
if grep -qi "VULNERABLE" "$NMAP_SMB" 2>/dev/null; then
    warn "VULNERABLE keyword found — review ${NMAP_SMB} manually"
fi
echo ""

# ===========================================================================
# 2 — enum4linux-ng / enum4linux (null session)
# ===========================================================================
info "[2/7] enum4linux (null session)"
E4L_OUT="${SMB_DIR}/enum4linux.txt"

if command -v enum4linux-ng &>/dev/null; then
    if [[ -n "$DOMAIN" ]]; then
        cmd "enum4linux-ng -A -d $DOMAIN $TARGET"
        enum4linux-ng -A -d "$DOMAIN" "$TARGET" 2>&1 | tee "$E4L_OUT" || true
    else
        cmd "enum4linux-ng -A $TARGET"
        enum4linux-ng -A "$TARGET" 2>&1 | tee "$E4L_OUT" || true
    fi
elif command -v enum4linux &>/dev/null; then
    cmd "enum4linux -a $TARGET"
    enum4linux -a "$TARGET" 2>&1 | tee "$E4L_OUT" || true
else
    skip "enum4linux-ng / enum4linux"
    echo "# Tool not installed" > "$E4L_OUT"
fi
echo ""

# ===========================================================================
# 3 — smbmap (null + guest sessions)
# ===========================================================================
info "[3/7] smbmap — null session"
SMBMAP_NULL="${SMB_DIR}/smbmap_null.txt"
cmd "smbmap -H $TARGET -u '' -p '' --no-banner"
smbmap -H "$TARGET" -u '' -p '' --no-banner 2>&1 | tee "$SMBMAP_NULL" || true

# Parse readable shares
READABLE_SHARES=$(grep -iE 'READ ONLY|READ, WRITE' "$SMBMAP_NULL" 2>/dev/null \
    | grep -ivE 'IPC\$|print\$' \
    | grep -oP '^\s*\K[A-Za-z0-9._$-]+' \
    | sort -u || true)

if [[ -n "$READABLE_SHARES" ]]; then
    ok "Readable shares (null): ${WHITE}${READABLE_SHARES//$'\n'/, }${NC}"
fi
echo ""

info "[3b/7] smbmap — null session recursive listing"
SMBMAP_NULL_R="${SMB_DIR}/smbmap_null_recursive.txt"
cmd "smbmap -H $TARGET -u '' -p '' -r --no-banner"
smbmap -H "$TARGET" -u '' -p '' -r --no-banner 2>&1 | tee "$SMBMAP_NULL_R" || true
echo ""

info "[3c/7] smbmap — guest session recursive listing"
SMBMAP_GUEST="${SMB_DIR}/smbmap_guest_recursive.txt"
cmd "smbmap -H $TARGET -u 'guest' -p '' -r --no-banner"
smbmap -H "$TARGET" -u 'guest' -p '' -r --no-banner 2>&1 | tee "$SMBMAP_GUEST" || true

# Flag interesting file types found in shares
INTERESTING=$(grep -iP '\.(ps1|bat|cmd|vbs|txt|xml|conf|config|ini|bak|old|zip|sql|key|pem|pfx|crt|log)$' \
    "$SMBMAP_GUEST" 2>/dev/null | head -10 || true)
if [[ -n "$INTERESTING" ]]; then
    ok "Potentially interesting files found in shares — review ${SMBMAP_GUEST}"
fi
echo ""

# ===========================================================================
# 4 — smbclient (null session share listing)
# ===========================================================================
info "[4/7] smbclient — null session share list"
SMBCLIENT_OUT="${SMB_DIR}/smbclient.txt"
cmd "smbclient -L //$TARGET -N"
smbclient -L "//${TARGET}" -N 2>&1 | tee "$SMBCLIENT_OUT" || true

# Print manual download hint for each readable share
if [[ -n "$READABLE_SHARES" ]]; then
    hint "Download share contents manually:
    while IFS= read -r share; do
        smbclient //${TARGET}/\$share -N -c 'prompt OFF; recurse ON; mget *'
    done <<< '$READABLE_SHARES'"
fi
echo ""

# ===========================================================================
# 5 — rpcclient (null session user/group enum)
# ===========================================================================
info "[5/7] rpcclient — null session"
RPC_OUT="${SMB_DIR}/rpcclient.txt"
cmd "rpcclient -U '' -N $TARGET -c 'enumdomusers; enumdomgroups; querydispinfo'"
rpcclient -U '' -N "$TARGET" \
    -c 'enumdomusers; enumdomgroups; querydispinfo' 2>&1 | tee "$RPC_OUT" || true

# Extract usernames from rpcclient output
USERS_FOUND=$(grep -oP 'user:\[\K[^\]]+' "$RPC_OUT" 2>/dev/null | sort -u || true)
if [[ -n "$USERS_FOUND" ]]; then
    echo "$USERS_FOUND" > "${SMB_DIR}/users_rpc.txt"
    ok "Users found via rpcclient: ${WHITE}$(echo "$USERS_FOUND" | tr '\n' ' ')${NC}"
fi
echo ""

# ===========================================================================
# 6 — nxc / netexec / crackmapexec (null + guest)
# ===========================================================================
if [[ -n "$NXC" ]]; then
    info "[6/7] ${NXC} — null + guest sessions"

    NXC_SHARES="${SMB_DIR}/nxc_shares.txt"
    NXC_USERS="${SMB_DIR}/nxc_users.txt"
    NXC_PASSPOL="${SMB_DIR}/nxc_passpol.txt"

    cmd "$NXC smb $TARGET --shares -u '' -p ''"
    $NXC smb "$TARGET" --shares -u '' -p '' 2>&1 | tee "$NXC_SHARES" || true

    cmd "$NXC smb $TARGET --shares -u 'guest' -p ''"
    $NXC smb "$TARGET" --shares -u 'guest' -p '' 2>&1 | tee -a "$NXC_SHARES" || true

    cmd "$NXC smb $TARGET --users -u '' -p ''"
    $NXC smb "$TARGET" --users -u '' -p '' 2>&1 | tee "$NXC_USERS" || true

    cmd "$NXC smb $TARGET --pass-pol -u '' -p ''"
    $NXC smb "$TARGET" --pass-pol -u '' -p '' 2>&1 | tee "$NXC_PASSPOL" || true

    # Check SMB signing
    if grep -qi "signing:False\|signing: False" "$NXC_SHARES" 2>/dev/null; then
        warn "SMB SIGNING DISABLED — target is potentially vulnerable to NTLM Relay."
        hint "Manual NTLM Relay (requires separate interface + authorization):
    Responder + ntlmrelayx must be run manually after reviewing scope.
    Do NOT automate relay attacks."
    fi
    echo ""
else
    info "[6/7] nxc/netexec/crackmapexec — not found, skipping."
    echo ""
fi

# ===========================================================================
# 6b — RID Cycling (nxc --rid-brute)
#      Enumerates ALL domain users by iterating SIDs from 500 to 10000.
#      Works even when enumdomusers / SAMR is blocked.
# ===========================================================================
if [[ -n "$NXC" ]]; then
    info "[6b/7] RID cycling — ${NXC} --rid-brute 10000"
    RID_OUT="${SMB_DIR}/nxc_rid_brute.txt"

    cmd "$NXC smb $TARGET --rid-brute 10000 -u '' -p ''"
    $NXC smb "$TARGET" --rid-brute 10000 -u '' -p '' \
        2>&1 | tee "$RID_OUT" || true

    # Extract usernames from RID output (format: DOMAIN\username (SidTypeUser))
    RID_USERS=$(grep -oP '\\\K\w+(?=\s+\(SidTypeUser\))' "$RID_OUT" 2>/dev/null \
        | sort -u || true)
    if [[ -n "$RID_USERS" ]]; then
        echo "$RID_USERS" >> "${SMB_DIR}/users_rpc.txt"
        sort -u "${SMB_DIR}/users_rpc.txt" -o "${SMB_DIR}/users_rpc.txt" 2>/dev/null || true
        ok "RID cycling found users: ${WHITE}$(echo "$RID_USERS" | tr '\n' ' ')${NC}"
    else
        info "RID cycling: no users returned (null session may be restricted)."

        # Fallback: try guest account for RID cycling
        cmd "$NXC smb $TARGET --rid-brute 10000 -u 'guest' -p ''"
        $NXC smb "$TARGET" --rid-brute 10000 -u 'guest' -p '' \
            2>&1 | tee -a "$RID_OUT" || true
        RID_USERS_GUEST=$(grep -oP '\\\K\w+(?=\s+\(SidTypeUser\))' "$RID_OUT" 2>/dev/null \
            | sort -u || true)
        if [[ -n "$RID_USERS_GUEST" ]]; then
            echo "$RID_USERS_GUEST" >> "${SMB_DIR}/users_rpc.txt"
            sort -u "${SMB_DIR}/users_rpc.txt" -o "${SMB_DIR}/users_rpc.txt" 2>/dev/null || true
            ok "RID cycling (guest session) found users: ${WHITE}$(echo "$RID_USERS_GUEST" | tr '\n' ' ')${NC}"
        fi
    fi
    echo ""
else
    info "[6b/7] nxc/netexec not found — attempting impacket-lookupsid instead."
    LSID_OUT="${SMB_DIR}/lookupsid_null.txt"

    if command -v impacket-lookupsid &>/dev/null; then
        # Try null session first
        cmd "impacket-lookupsid ''@$TARGET 10000"
        impacket-lookupsid "''@${TARGET}" 10000 \
            2>&1 | tee "$LSID_OUT" || true

        LSID_USERS=$(grep -oP 'SidTypeUser\)\s+\K\S+' "$LSID_OUT" 2>/dev/null \
            | grep -v '\\' | sort -u || true)
        if [[ -n "$LSID_USERS" ]]; then
            echo "$LSID_USERS" >> "${SMB_DIR}/users_rpc.txt"
            sort -u "${SMB_DIR}/users_rpc.txt" -o "${SMB_DIR}/users_rpc.txt" 2>/dev/null || true
            ok "lookupsid (null) found: ${WHITE}$(echo "$LSID_USERS" | tr '\n' ' ')${NC}"
        else
            info "lookupsid null session failed — trying guest session"
            cmd "impacket-lookupsid guest@$TARGET 10000"
            impacket-lookupsid "guest@${TARGET}" 10000 \
                2>&1 | tee "${SMB_DIR}/lookupsid_guest.txt" || true

            LSID_GUEST=$(grep -oP 'SidTypeUser\)\s+\K\S+' \
                "${SMB_DIR}/lookupsid_guest.txt" 2>/dev/null \
                | grep -v '\\' | sort -u || true)
            if [[ -n "$LSID_GUEST" ]]; then
                echo "$LSID_GUEST" >> "${SMB_DIR}/users_rpc.txt"
                sort -u "${SMB_DIR}/users_rpc.txt" -o "${SMB_DIR}/users_rpc.txt" 2>/dev/null || true
                ok "lookupsid (guest) found: ${WHITE}$(echo "$LSID_GUEST" | tr '\n' ' ')${NC}"
            fi
        fi
    else
        hint "Manual RID cycling (install impacket for automatic fallback):
    impacket-lookupsid ''@${TARGET} 10000
    impacket-lookupsid guest@${TARGET} 10000"
    fi
    echo ""
fi

# ===========================================================================
# 6d — impacket-lookupsid as secondary check after nxc RID cycling
#      Runs when nxc found nothing (null + guest both empty), ensuring
#      a second tool gets a chance before giving up on SID enumeration.
# ===========================================================================
if [[ -n "$NXC" ]] && command -v impacket-lookupsid &>/dev/null; then
    USERS_RPC="${SMB_DIR}/users_rpc.txt"
    EXISTING_COUNT=$(wc -l < "$USERS_RPC" 2>/dev/null || echo 0)
    if [[ "$EXISTING_COUNT" -eq 0 ]]; then
        info "[6d/7] nxc RID cycling found nothing — trying impacket-lookupsid as fallback"
        LSID_OUT="${SMB_DIR}/lookupsid_fallback.txt"

        cmd "impacket-lookupsid ''@$TARGET 10000"
        impacket-lookupsid "''@${TARGET}" 10000 \
            2>&1 | tee "$LSID_OUT" || true

        LSID_USERS=$(grep -oP 'SidTypeUser\)\s+\K\S+' "$LSID_OUT" 2>/dev/null \
            | grep -v '\\' | sort -u || true)
        if [[ -n "$LSID_USERS" ]]; then
            echo "$LSID_USERS" > "$USERS_RPC"
            ok "lookupsid fallback found: ${WHITE}$(echo "$LSID_USERS" | tr '\n' ' ')${NC}"
        else
            cmd "impacket-lookupsid guest@$TARGET 10000"
            impacket-lookupsid "guest@${TARGET}" 10000 \
                2>&1 | tee -a "$LSID_OUT" || true
            LSID_USERS=$(grep -oP 'SidTypeUser\)\s+\K\S+' "$LSID_OUT" 2>/dev/null \
                | grep -v '\\' | sort -u || true)
            [[ -n "$LSID_USERS" ]] && echo "$LSID_USERS" > "$USERS_RPC" && \
                ok "lookupsid (guest fallback) found: ${WHITE}$(echo "$LSID_USERS" | tr '\n' ' ')${NC}"
        fi
        echo ""
    fi
fi

# ===========================================================================
# 6c — Per-share deep recursive spider (nxc --spider)
#      Lists file tree of each readable share for targeted investigation.
# ===========================================================================
if [[ -n "$NXC" && -n "$READABLE_SHARES" ]]; then
    info "[6c/7] Per-share deep spider — readable shares: ${READABLE_SHARES//$'\n'/, }"

    while IFS= read -r SHARE; do
        [[ -z "$SHARE" ]] && continue
        SPIDER_OUT="${SMB_DIR}/spider_${SHARE}.txt"
        cmd "$NXC smb $TARGET -u '' -p '' --spider '$SHARE' --pattern ''"
        $NXC smb "$TARGET" -u '' -p '' \
            --spider "$SHARE" --pattern '' \
            2>&1 | tee "$SPIDER_OUT" || true

        # Highlight interesting extensions
        HITS=$(grep -iP '\.(ps1|bat|cmd|vbs|xml|conf|config|ini|bak|old|zip|sql|key|pem|pfx|crt|log|txt|xlsx|docx|db)$' \
            "$SPIDER_OUT" 2>/dev/null | head -20 || true)
        if [[ -n "$HITS" ]]; then
            ok "Interesting files in share '${SHARE}':"
            echo "$HITS"
            echo "--- spider hits: ${SHARE} ---" >> "${SMB_DIR}/interesting_files.txt"
            echo "$HITS" >> "${SMB_DIR}/interesting_files.txt"
        fi
    done <<< "$READABLE_SHARES"
    echo ""
fi

# ===========================================================================
# 7 — Authenticated enumeration (only if credentials provided)
# ===========================================================================
if [[ -n "$SMB_USER" && -n "$SMB_PASS" ]]; then
    info "[7/7] Authenticated SMB enumeration (${SMB_USER})"

    # smbmap authenticated
    SMBMAP_AUTH="${SMB_DIR}/smbmap_auth.txt"
    cmd "smbmap -H $TARGET -u '$SMB_USER' -p '$SMB_PASS' --no-banner"
    smbmap -H "$TARGET" -u "$SMB_USER" -p "$SMB_PASS" --no-banner \
        2>&1 | tee "$SMBMAP_AUTH" || true

    # nxc authenticated
    if [[ -n "$NXC" ]]; then
        cmd "$NXC smb $TARGET -u '$SMB_USER' -p '$SMB_PASS' --shares"
        $NXC smb "$TARGET" -u "$SMB_USER" -p "$SMB_PASS" --shares \
            2>&1 | tee "${SMB_DIR}/nxc_auth_shares.txt" || true

        cmd "$NXC smb $TARGET -u '$SMB_USER' -p '$SMB_PASS' --users"
        $NXC smb "$TARGET" -u "$SMB_USER" -p "$SMB_PASS" --users \
            2>&1 | tee "${SMB_DIR}/nxc_auth_users.txt" || true

        cmd "$NXC smb $TARGET -u '$SMB_USER' -p '$SMB_PASS' --groups"
        $NXC smb "$TARGET" -u "$SMB_USER" -p "$SMB_PASS" --groups \
            2>&1 | tee "${SMB_DIR}/nxc_auth_groups.txt" || true

        cmd "$NXC smb $TARGET -u '$SMB_USER' -p '$SMB_PASS' --loggedon-users"
        $NXC smb "$TARGET" -u "$SMB_USER" -p "$SMB_PASS" --loggedon-users \
            2>&1 | tee "${SMB_DIR}/nxc_auth_loggedon.txt" || true
    fi

    # enum4linux-ng authenticated
    if command -v enum4linux-ng &>/dev/null; then
        cmd "enum4linux-ng -A $TARGET -u '$SMB_USER' -p '$SMB_PASS'"
        enum4linux-ng -A "$TARGET" -u "$SMB_USER" -p "$SMB_PASS" \
            2>&1 | tee "${SMB_DIR}/enum4linux_auth.txt" || true
    fi
    echo ""
else
    info "[7/7] No credentials supplied — skipping authenticated enum."
    echo ""
fi

# ===========================================================================
# Manual steps hint (OSCP-style — user action required)
# ===========================================================================
hint "Manual SMB follow-up steps:

  # Explore a specific share interactively:
  smbclient //${TARGET}/<SHARE_NAME> -N

  # Download all files from a share:
  smbclient //${TARGET}/<SHARE_NAME> -N -c 'prompt OFF; recurse ON; mget *'

  # AS-REP Roasting (requires domain + user list — run manually):
  impacket-GetNPUsers <DOMAIN>/ -dc-ip ${TARGET} -no-pass -usersfile ${SMB_DIR}/users_rpc.txt

  # Kerberoasting (requires valid credentials — run manually):
  impacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip ${TARGET} -request

  # SMB brute force (only if explicitly in scope):
  ${NXC:-nxc} smb ${TARGET} -u <users.txt> -p <passwords.txt> --no-bruteforce"

ok "SMB enumeration complete — output: ${SMB_DIR}/"
echo ""
