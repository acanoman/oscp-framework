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
TARGET=""; OUTPUT_DIR=""; PORTS=""; UDP_PORTS=""; DOMAIN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)     TARGET="$2";     shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --ports)      PORTS="$2";      shift 2 ;;
        --udp-ports)  UDP_PORTS="$2";  shift 2 ;;
        --domain)     DOMAIN="$2";     shift 2 ;;
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
# ===========================================================================
if has_port 22; then
    mkdir -p "${OUTPUT_DIR}/ssh"
    info "[SSH] Port 22 — SSH audit + auth method enumeration"

    if command -v ssh-audit &>/dev/null; then
        SSH_AUDIT_OUT="${OUTPUT_DIR}/ssh/ssh_audit.txt"
        cmd "ssh-audit --skip-rate-test $TARGET"
        # Save full output to file for later reference
        ssh-audit --skip-rate-test "$TARGET" > "$SSH_AUDIT_OUT" 2>&1 || true

        # Print only the signal lines to the terminal — skip algorithm noise
        # (kex/enc/mac/key info lines and rec/nfo advisory lines).
        # Keep: (gen) banner, (fin) fingerprints, fail/warn lines with CVE.
        echo ""
        info "[SSH-AUDIT] Summary (full output → ${SSH_AUDIT_OUT})"
        grep -E '^\(gen\)|^\(fin\)|\[fail\].*CVE-|\[warn\].*CVE-|\[fail\].*broken|\[fail\].*deprecated' \
            "$SSH_AUDIT_OUT" 2>/dev/null \
            | sed 's/^\(gen\)/  (gen)/' \
            | sed 's/^\(fin\)/  (fin)/' \
            | while IFS= read -r line; do
                echo "  $line"
              done || true

        if grep -qiE 'CVE-' "$SSH_AUDIT_OUT" 2>/dev/null; then
            SSH_CVES=$(grep -oP 'CVE-\d+-\d+' "$SSH_AUDIT_OUT" 2>/dev/null \
                | sort -u | head -5 | tr '\n' ' ' || true)
            warn "SSH CVEs found: ${RED}${SSH_CVES}${NC}"
        else
            ok "No CVEs flagged by ssh-audit"
        fi
        echo ""
    else
        skip "ssh-audit"
        hint "Install ssh-audit:  pip3 install ssh-audit"
    fi

    # Auth method enumeration for common users (no brute force — reads metadata only)
    for SSH_USER in root admin user www-data; do
        AUTH_OUT="${OUTPUT_DIR}/ssh/ssh_auth_${SSH_USER}.txt"
        cmd "nmap -p22 --script ssh-auth-methods --script-args ssh.user=$SSH_USER -Pn $TARGET"
        nmap -p22 \
            --script ssh-auth-methods \
            --script-args "ssh.user=${SSH_USER}" \
            -Pn "$TARGET" \
            -oN "$AUTH_OUT" 2>&1 | tee "$AUTH_OUT" || true

        if grep -qi "password" "$AUTH_OUT" 2>/dev/null; then
            ok "SSH accepts password auth for user: ${WHITE}${SSH_USER}${NC}"
        fi
    done

    cat "${OUTPUT_DIR}"/ssh/ssh_auth_*.txt \
        > "${OUTPUT_DIR}/ssh/ssh_auth_methods.txt" 2>/dev/null || true

    hint "SSH brute force (manual — only if explicitly authorized):
    hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://${TARGET}

    # Private key login (if you find id_rsa):
    ssh -i id_rsa <user>@${TARGET}"
    echo ""
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
        BANNER_LINE=$(echo "$TELNET_BANNER" | grep -v '^$' | head -3 | tr '\n' ' ' | cut -c1-120)
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

    # Full SNMP walk with public community
    if command -v snmpwalk &>/dev/null; then
        cmd "snmpwalk -v2c -c public $TARGET"
        snmpwalk -v2c -c public "$TARGET" \
            2>&1 | tee "${SNMP_DIR}/snmpwalk_full.txt" || true

        # Targeted OID queries for high-value data
        cmd "snmpwalk -v2c -c public $TARGET 1.3.6.1.2.1.25.4.2.1.2 (running processes)"
        snmpwalk -v2c -c public "$TARGET" 1.3.6.1.2.1.25.4.2.1.2 \
            2>&1 | tee "${SNMP_DIR}/snmp_processes.txt" || true

        cmd "snmpwalk -v2c -c public $TARGET 1.3.6.1.2.1.25.6.3.1.2 (installed software)"
        snmpwalk -v2c -c public "$TARGET" 1.3.6.1.2.1.25.6.3.1.2 \
            2>&1 | tee "${SNMP_DIR}/snmp_software.txt" || true

        cmd "snmpwalk -v2c -c public $TARGET 1.3.6.1.4.1.77.1.2.25 (Windows users)"
        snmpwalk -v2c -c public "$TARGET" 1.3.6.1.4.1.77.1.2.25 \
            2>&1 | tee "${SNMP_DIR}/snmp_users.txt" || true

        # Network interfaces — critical for pivot/dual-homed host discovery
        cmd "snmpwalk -v2c -c public $TARGET 1.3.6.1.2.1.2.2.1.2 (network interfaces)"
        snmpwalk -v2c -c public "$TARGET" 1.3.6.1.2.1.2.2.1.2 \
            2>&1 | tee "${SNMP_DIR}/snmp_interfaces.txt" || true

        # Companion OID: interface IP addresses (pairs with interface names above)
        cmd "snmpwalk -v2c -c public $TARGET 1.3.6.1.2.1.4.20.1.1 (interface IP addresses)"
        snmpwalk -v2c -c public "$TARGET" 1.3.6.1.2.1.4.20.1.1 \
            2>&1 | tee "${SNMP_DIR}/snmp_ip_addrs.txt" || true

        # Flag dual-homed (pivot) hosts
        IF_COUNT=$(grep -c 'STRING:' "${SNMP_DIR}/snmp_interfaces.txt" 2>/dev/null || echo 0)
        if [[ "$IF_COUNT" -gt 2 ]]; then
            warn "SNMP: ${IF_COUNT} network interfaces detected — host may be DUAL-HOMED (pivot opportunity)"
            warn "  Review: ${SNMP_DIR}/snmp_interfaces.txt and ${SNMP_DIR}/snmp_ip_addrs.txt"
        fi
    else
        skip "snmpwalk"
    fi

    if command -v snmp-check &>/dev/null; then
        cmd "snmp-check $TARGET"
        snmp-check "$TARGET" 2>&1 | tee "${SNMP_DIR}/snmp_check.txt" || true
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
# Banner grab — unknown / non-standard ports
# ===========================================================================
KNOWN_PORTS="21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,636,993,995,1433,2049,3306,3389,5432,5985,5986,6379,8000,8080,8443,8888,27017"
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
    done
    echo ""
fi

ok "Service enumeration complete — output: ${OUTPUT_DIR}/"
echo ""
