import sqlite3
import os
import json
from datetime import datetime
from collections import Counter
import config


def get_conn():
    db_path = config.DB_PATH
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def migrate_db() -> None:
    conn = get_conn()
    try:
        cur  = conn.cursor()
        existing = {row[1] for row in cur.execute("PRAGMA table_info(attacks)").fetchall()}
        additions = [
            ("mitre_tags",    "TEXT"),
            ("anomaly_score", "REAL DEFAULT 0.0"),
            ("threat_level",  "TEXT DEFAULT 'info'"),
        ]
        for col, col_type in additions:
            if col not in existing:
                cur.execute(f"ALTER TABLE attacks ADD COLUMN {col} {col_type}")
        conn.commit()
    finally:
        conn.close()

def init_db() -> None:
    conn = get_conn()
    try:
        cur = conn.cursor()

        cur.executescript("""
            CREATE TABLE IF NOT EXISTS attacks (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp     TEXT    NOT NULL DEFAULT (datetime('now')),
                service       TEXT    NOT NULL,
                src_ip        TEXT    NOT NULL,
                src_port      INTEGER,
                username      TEXT,
                password      TEXT,
                payload       TEXT,
                user_agent    TEXT,
                method        TEXT,
                path          TEXT,
                country       TEXT,
                city          TEXT,
                latitude      REAL,
                longitude     REAL,
                asn           TEXT,
                isp           TEXT,
                flagged       INTEGER DEFAULT 0,
                mitre_tags    TEXT,
                anomaly_score REAL    DEFAULT 0.0,
                threat_level  TEXT    DEFAULT 'info'
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_id   INTEGER REFERENCES attacks(id) ON DELETE CASCADE,
                started_at  TEXT    NOT NULL DEFAULT (datetime('now')),
                ended_at    TEXT,
                commands    TEXT
            );

            CREATE TABLE IF NOT EXISTS stats_hourly (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                hour        TEXT    NOT NULL UNIQUE,
                ssh_count   INTEGER DEFAULT 0,
                http_count  INTEGER DEFAULT 0,
                ftp_count   INTEGER DEFAULT 0,
                unique_ips  INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks(timestamp);
            CREATE INDEX IF NOT EXISTS idx_attacks_src_ip    ON attacks(src_ip);
            CREATE INDEX IF NOT EXISTS idx_attacks_service   ON attacks(service);
            CREATE INDEX IF NOT EXISTS idx_attacks_country   ON attacks(country);
        """)
        conn.commit()
    finally:
        conn.close()

def insert_attack(data: dict) -> int:
    conn = get_conn()
    try:
        cur = conn.cursor()
        cols = [
            "service", "src_ip", "src_port", "username", "password",
            "payload", "user_agent", "method", "path",
            "country", "city", "latitude", "longitude", "asn", "isp",
            "mitre_tags", "anomaly_score", "threat_level",
        ]
        placeholders = ", ".join(["?"] * len(cols))
        col_names    = ", ".join(cols)
        values = [data.get(c) for c in cols]
        cur.execute(
            f"INSERT INTO attacks ({col_names}) VALUES ({placeholders})",
            values,
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()

def get_intel_summary() -> dict:
    conn = get_conn()
    try:
        cur  = conn.cursor()

        threat_levels = cur.execute(
            "SELECT threat_level, COUNT(*) as cnt FROM attacks "
            "WHERE threat_level IS NOT NULL GROUP BY threat_level"
        ).fetchall()

        anomalies = cur.execute(
            "SELECT * FROM attacks WHERE anomaly_score < -0.1 "
            "ORDER BY anomaly_score ASC LIMIT 50"
        ).fetchall()

        mitre_raw = cur.execute(
            "SELECT mitre_tags FROM attacks WHERE mitre_tags IS NOT NULL AND mitre_tags != '[]'"
        ).fetchall()

        campaigns_data = cur.execute(
            "SELECT password, COUNT(DISTINCT src_ip) as ip_cnt, COUNT(*) as total "
            "FROM attacks WHERE password IS NOT NULL AND password != '' "
            "GROUP BY password HAVING ip_cnt >= 3 "
            "ORDER BY ip_cnt DESC LIMIT 10"
        ).fetchall()
    finally:
        conn.close()

    technique_counter: Counter = Counter()
    for row in mitre_raw:
        try:
            tags = json.loads(row[0])
            technique_counter.update(tags)
        except Exception:
            pass

    return {
        "threat_levels":  [dict(r) for r in threat_levels],
        "anomalies":      [dict(r) for r in anomalies],
        "top_techniques": [{"id": tid, "count": cnt}
                           for tid, cnt in technique_counter.most_common(15)],
        "campaigns":      [dict(r) for r in campaigns_data],
    }

def get_recent_attacks(limit: int = 100) -> list[dict]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM attacks ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]

def get_stats() -> dict:
    conn = get_conn()
    try:
        cur = conn.cursor()

        total      = cur.execute("SELECT COUNT(*) FROM attacks").fetchone()[0]
        unique_ips = cur.execute("SELECT COUNT(DISTINCT src_ip) FROM attacks").fetchone()[0]
        by_service = cur.execute(
            "SELECT service, COUNT(*) as cnt FROM attacks GROUP BY service"
        ).fetchall()
        top_ips = cur.execute(
            "SELECT src_ip, COUNT(*) as cnt FROM attacks GROUP BY src_ip ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        top_countries = cur.execute(
            "SELECT country, COUNT(*) as cnt FROM attacks WHERE country IS NOT NULL "
            "GROUP BY country ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        top_passwords = cur.execute(
            "SELECT password, COUNT(*) as cnt FROM attacks WHERE password IS NOT NULL "
            "GROUP BY password ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        top_usernames = cur.execute(
            "SELECT username, COUNT(*) as cnt FROM attacks WHERE username IS NOT NULL "
            "GROUP BY username ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        hourly = cur.execute(
            "SELECT strftime('%Y-%m-%d %H', timestamp) as hour, COUNT(*) as cnt "
            "FROM attacks GROUP BY hour ORDER BY hour DESC LIMIT 24"
        ).fetchall()
    finally:
        conn.close()
    return {
        "total":          total,
        "unique_ips":     unique_ips,
        "by_service":     [dict(r) for r in by_service],
        "top_ips":        [dict(r) for r in top_ips],
        "top_countries":  [dict(r) for r in top_countries],
        "top_passwords":  [dict(r) for r in top_passwords],
        "top_usernames":  [dict(r) for r in top_usernames],
        "hourly":         [dict(r) for r in hourly],
    }

def get_map_points() -> list[dict]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT src_ip, country, city, latitude, longitude, service, COUNT(*) as cnt "
            "FROM attacks WHERE latitude IS NOT NULL AND longitude IS NOT NULL "
            "GROUP BY src_ip"
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]
