import os
import sqlite3
import datetime
from typing import Optional, List, Dict, Any

class StorageEngine:
    def __init__(self, db_path: str = "/app/data/hunter_decisions.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self.init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 5000;")
        return conn

    def init_db(self):
        with self._get_connection() as conn:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_pattern TEXT NOT NULL,
                client_scope TEXT DEFAULT 'GLOBAL',
                action TEXT CHECK(action IN ('BLOCK', 'ALLOW', 'SNOOZE')) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NULL,
                notes TEXT
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_decisions_pattern_client 
            ON decisions(domain_pattern, client_scope);

            CREATE TABLE IF NOT EXISTS candidates_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                entropy_score REAL NOT NULL,
                query_count INTEGER DEFAULT 1,
                gemini_classification TEXT,
                gemini_summary TEXT,
                status TEXT CHECK(status IN ('PENDING', 'NOTIFIED', 'APPROVED', 'DISMISSED')) DEFAULT 'PENDING',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_candidates_domain ON candidates_log(domain);
            CREATE INDEX IF NOT EXISTS idx_candidates_status ON candidates_log(status);

            CREATE TABLE IF NOT EXISTS daemon_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS domain_cooldowns (
                domain TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                reason TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (domain, client_ip)
            );
            CREATE INDEX IF NOT EXISTS idx_cooldown_lookup ON domain_cooldowns(domain, client_ip, expires_at);
            """)

    def get_checkpoint(self, key: str = "last_query_time") -> Optional[str]:
        with self._get_connection() as conn:
            row = conn.execute("SELECT value FROM daemon_state WHERE key = ?", (key,)).fetchone()
            return row["value"] if row else None

    def set_checkpoint(self, key: str, value: str):
        with self._get_connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO daemon_state (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
                (key, value)
            )

    def match_decision(self, domain: str, client_ip: str) -> Optional[Dict[str, Any]]:
        """
        Matches domain and client against decisions using exact match and hierarchical wildcard patterns.
        E.g. for a.b.lge.com, checks:
        - exact 'a.b.lge.com'
        - '*.b.lge.com'
        - '*.lge.com'
        - '*.com'
        First checks client_scope == client_ip, then client_scope == 'GLOBAL'.
        Filters out expired decisions.
        """
        domain = domain.lower().strip(".")
        labels = domain.split(".")
        patterns = [domain]
        # Build wildcard patterns
        for i in range(1, len(labels)):
            patterns.append("*." + ".".join(labels[i:]))

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self._get_connection() as conn:
            # Check client-specific first, then global
            for scope in (client_ip, "GLOBAL"):
                placeholders = ",".join(["?"] * len(patterns))
                query = f"""
                SELECT domain_pattern, client_scope, action, expires_at 
                FROM decisions 
                WHERE client_scope = ? 
                  AND domain_pattern IN ({placeholders})
                  AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY length(domain_pattern) DESC
                LIMIT 1
                """
                params = [scope] + patterns + [now_iso]
                row = conn.execute(query, params).fetchone()
                if row:
                    return dict(row)
        return None

    def record_decision(self, domain_pattern: str, client_scope: str = "GLOBAL", 
                        action: str = "BLOCK", expires_at: Optional[str] = None, notes: str = ""):
        domain_pattern = domain_pattern.lower().strip()
        with self._get_connection() as conn:
            conn.execute("""
            INSERT OR REPLACE INTO decisions 
            (domain_pattern, client_scope, action, expires_at, notes, created_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (domain_pattern, client_scope, action, expires_at, notes))

    def record_candidate(self, domain: str, client_ip: str, entropy: float, 
                         classification: str = "", summary: str = "", status: str = "PENDING") -> int:
        with self._get_connection() as conn:
            cursor = conn.execute("""
            INSERT INTO candidates_log 
            (domain, client_ip, entropy_score, gemini_classification, gemini_summary, status)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (domain, client_ip, entropy, classification, summary, status))
            return cursor.lastrowid

    def update_candidate_status(self, candidate_id: int, status: str, classification: str = "", summary: str = ""):
        if classification or summary:
            with self._get_connection() as conn:
                conn.execute("UPDATE candidates_log SET status = ?, gemini_classification = ?, gemini_summary = ? WHERE id = ?", (status, classification, summary, candidate_id))
            return
        with self._get_connection() as conn:
            conn.execute("UPDATE candidates_log SET status = ? WHERE id = ?", (status, candidate_id))

    def cleanup_expired_decisions(self) -> int:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM decisions WHERE expires_at IS NOT NULL AND expires_at <= ?", (now_iso,))
            return cursor.rowcount

    def set_cooldown(self, domain: str, client_ip: str = "GLOBAL", duration_seconds: int = 86400, reason: str = "BENIGN"):
        domain = domain.lower().strip(".")
        expires_at = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=duration_seconds)).isoformat()
        with self._get_connection() as conn:
            conn.execute("""
            INSERT OR REPLACE INTO domain_cooldowns (domain, client_ip, expires_at, reason, created_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (domain, client_ip, expires_at, reason))

    def is_in_cooldown(self, domain: str, client_ip: str = "GLOBAL") -> bool:
        domain = domain.lower().strip(".")
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            row = conn.execute("""
            SELECT 1 FROM domain_cooldowns 
            WHERE domain = ? AND (client_ip = ? OR client_ip = 'GLOBAL') AND expires_at > ?
            LIMIT 1
            """, (domain, client_ip, now_iso)).fetchone()
            return row is not None

    def cleanup_expired_cooldowns(self) -> int:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM domain_cooldowns WHERE expires_at <= ?", (now_iso,))
            return cursor.rowcount
