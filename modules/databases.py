"""
modules/databases.py — Database enumeration module

Routes to wrappers/db_enum.sh for MSSQL, MySQL, PostgreSQL, Redis, and MongoDB.
After the wrapper runs, parses output files for key findings and injects
[MANUAL] hints directly into session notes so they appear in notes.md.

OSCP compliance:
  - Read-only NSE probes and redis-cli INFO only
  - NO brute force
  - Exploitation techniques (xp_cmdshell, Redis write-primitive) → hint only
"""

import re
import subprocess
from pathlib import Path

WRAPPERS_DIR = Path(__file__).resolve().parent.parent / "wrappers"

# Ports this module owns (taken out of services module)
_DB_PORTS = {
    1433,   # MSSQL
    3306,   # MySQL
    5432,   # PostgreSQL
    6379,   # Redis
    27017,  # MongoDB
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(target: str, session, dry_run: bool = False) -> None:
    log  = session.log
    ip   = session.info.ip

    open_db_ports = session.info.open_ports & _DB_PORTS
    if not open_db_ports:
        log.info("No database ports open — skipping databases module.")
        return

    log.info("Database ports to enumerate: %s", sorted(open_db_ports))

    # Inject MANUAL hints immediately — visible even if wrapper is interrupted
    _add_manual_hints(session, open_db_ports)

    script = WRAPPERS_DIR / "db_enum.sh"
    if not script.exists():
        log.error("Wrapper not found: %s", script)
        return

    ports_csv = ",".join(str(p) for p in sorted(open_db_ports))
    cmd = [
        "bash", str(script),
        "--target",     target,
        "--output-dir", str(session.target_dir),
        "--ports",      ports_csv,
    ]

    _exec(cmd, log, dry_run, label="db_enum.sh")

    if dry_run:
        return

    # Parse results
    _parse_mssql(session, log)
    _parse_mysql(session, log)
    _parse_pgsql(session, log)
    _parse_redis(session, log)
    _parse_mongodb(session, log)

    log.info("Databases module complete.")


# ---------------------------------------------------------------------------
# MANUAL hints — written to notes.md regardless of what the wrapper finds
# ---------------------------------------------------------------------------

def _add_manual_hints(session, open_db_ports: set) -> None:
    """
    Push actionable [MANUAL] hints into session.info.notes so they appear
    in the final notes.md report under the Session Notes section.
    """
    ip = session.info.ip

    if 1433 in open_db_ports:
        session.add_note(
            f"💡 [MANUAL] MSSQL login (blank password): "
            f"impacket-mssqlclient sa:''@{ip} -windows-auth"
        )
        session.add_note(
            f"💡 [MANUAL] MSSQL with creds: "
            f"impacket-mssqlclient DOMAIN/USER:PASS@{ip} -windows-auth"
        )

    if 3306 in open_db_ports:
        session.add_note(
            f"💡 [MANUAL] MySQL (blank password): mysql -h {ip} -u root --password=''"
        )

    if 5432 in open_db_ports:
        session.add_note(
            f"💡 [MANUAL] PostgreSQL: psql -h {ip} -U postgres"
        )

    if 6379 in open_db_ports:
        session.add_note(
            f"💡 [MANUAL] Redis enum: redis-cli -h {ip} ping && redis-cli -h {ip} keys '*'"
        )
        session.add_note(
            f"⚠️  [MANUAL / OSCP SCOPE CHECK] Redis write-primitive: "
            f"CONFIG SET dir + dbfilename — see db/redis.txt for technique"
        )

    if 27017 in open_db_ports:
        session.add_note(
            f"💡 [MANUAL] MongoDB: mongosh --host {ip} --port 27017"
        )


# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------

def _parse_mssql(session, log) -> None:
    db_dir  = session.target_dir / "db"
    mssql_f = db_dir / "mssql.txt"
    if not mssql_f.exists():
        return

    content = mssql_f.read_text(errors="ignore")

    if re.search(r"ms-sql-empty-password", content, re.IGNORECASE):
        log.warning("MSSQL: empty-password account detected")
        session.add_note(
            f"🚨 DATABASE FINDING: MSSQL empty-password SA account — {mssql_f}"
        )

    instances = re.findall(r"Instance Name:\s+(\S+)", content)
    if instances:
        log.info("MSSQL instances: %s", instances)
        session.add_note(f"MSSQL instances found: {instances}")

    version = re.search(r"Version:\s+(.+)", content)
    if version:
        log.info("MSSQL version: %s", version.group(1).strip())


def _parse_mysql(session, log) -> None:
    db_dir  = session.target_dir / "db"
    mysql_f = db_dir / "mysql.txt"
    if not mysql_f.exists():
        return

    content = mysql_f.read_text(errors="ignore")

    if re.search(r"mysql-empty-password|root.*empty password", content, re.IGNORECASE):
        log.warning("MySQL: root with empty password detected")
        session.add_note(
            f"🚨 DATABASE FINDING: MySQL root empty password — {mysql_f}"
        )

    version = re.search(r"MySQL.*?(\d+\.\d+\.\d+)", content)
    if version:
        log.info("MySQL version: %s", version.group(0))


def _parse_pgsql(session, log) -> None:
    db_dir  = session.target_dir / "db"
    pgsql_f = db_dir / "pgsql.txt"
    if not pgsql_f.exists():
        return

    content = pgsql_f.read_text(errors="ignore")

    if re.search(r"Valid credentials|postgres.*Valid", content, re.IGNORECASE):
        log.warning("PostgreSQL: valid credentials found in NSE output")
        creds = re.findall(r"(\S+:\S+)\s+-\s+Valid", content)
        if creds:
            session.add_note(f"🚨 PostgreSQL credentials: {creds}")
            session.info.users_found.extend(
                c.split(":")[0] for c in creds
                if c.split(":")[0] not in session.info.users_found
            )


def _parse_redis(session, log) -> None:
    db_dir    = session.target_dir / "db"
    redis_out = db_dir / "redis.txt"
    redis_inf = db_dir / "redis_info.txt"

    if redis_out.exists():
        content = redis_out.read_text(errors="ignore")
        if re.search(r"PING.*PONG|role:master", content, re.IGNORECASE):
            log.warning("Redis: unauthenticated access confirmed")
            session.add_note(
                f"🚨 DATABASE FINDING: Redis unauthenticated (no password required)"
            )

    if redis_inf.exists():
        content = redis_inf.read_text(errors="ignore")
        # Extract the data directory — useful for write-primitive assessment
        dir_match = re.search(r"^dir\s+(.+)$", content, re.MULTILINE)
        if dir_match:
            redis_dir = dir_match.group(1).strip()
            log.info("Redis data directory: %s", redis_dir)
            session.add_note(f"Redis data directory: {redis_dir}")


def _parse_mongodb(session, log) -> None:
    db_dir  = session.target_dir / "db"
    mongo_f = db_dir / "mongodb.txt"
    if not mongo_f.exists():
        return

    content = mongo_f.read_text(errors="ignore")
    if re.search(r"mongodb-databases|databases:", content, re.IGNORECASE):
        log.info("MongoDB: database listing retrieved — review %s", mongo_f)
        session.add_note(f"MongoDB database list available — review {mongo_f}")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _exec(cmd: list, log, dry_run: bool, label: str = "") -> int:
    display = " ".join(str(c) for c in cmd)
    prefix  = "[DRY-RUN]" if dry_run else "[CMD]"
    log.info("%s %s", prefix, display)

    if dry_run:
        return 0

    try:
        result = subprocess.run(cmd, text=True, check=False)
        if result.returncode != 0:
            log.warning("%s exited with code %d", label or cmd[0], result.returncode)
        return result.returncode
    except FileNotFoundError:
        log.error("Command not found: %s", cmd[0])
        return -1
