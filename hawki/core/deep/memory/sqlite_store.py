# File: hawki/core/deep/memory/sqlite_store.py
"""
SQLite implementation of MemoryStore.
"""

import json
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import MemoryStore


class SQLiteStore(MemoryStore):
    """Persistent memory using SQLite."""

    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            db_path = Path.home() / ".hawki" / "deep_memory.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self.conn = sqlite3.connect(str(db_path))
        self._init_db()

    def _init_db(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS attempts (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                attack_type TEXT,
                rule_name TEXT,
                novel_description TEXT,
                parameters TEXT,
                success INTEGER,
                before_balance INTEGER,
                after_balance INTEGER,
                gas_used INTEGER,
                tx_hash TEXT,
                llm_reasoning TEXT,
                code_snippet TEXT,
                attack_signature TEXT UNIQUE
            )
        """)
        self.conn.commit()

    def record(self, attack_plan: Dict[str, Any], result: Dict[str, Any]) -> None:
        attack_signature = attack_plan.get("signature", str(uuid.uuid4()))
        self.conn.execute("""
            INSERT OR REPLACE INTO attempts (
                id, timestamp, attack_type, rule_name, novel_description,
                parameters, success, before_balance, after_balance,
                gas_used, tx_hash, llm_reasoning, code_snippet, attack_signature
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            str(uuid.uuid4()),
            datetime.utcnow().isoformat(),
            attack_plan.get("type", "rule"),
            attack_plan.get("rule_name"),
            attack_plan.get("novel_description"),
            json.dumps(attack_plan.get("parameters", {})),
            1 if result.get("success") else 0,
            result.get("before_balance", 0),
            result.get("after_balance", 0),
            result.get("gas_used", 0),
            result.get("transaction_hash", ""),
            result.get("llm_reasoning", ""),
            result.get("code_snippet", ""),
            attack_signature
        ))
        self.conn.commit()

    def has_attempted(self, attack_signature: str) -> bool:
        cur = self.conn.execute("SELECT 1 FROM attempts WHERE attack_signature = ?", (attack_signature,))
        return cur.fetchone() is not None

    def get_all(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        cur = self.conn.execute("SELECT * FROM attempts ORDER BY timestamp")
        rows = cur.fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get_recent(self, limit: int = 10) -> List[Dict[str, Any]]:
        cur = self.conn.execute("SELECT * FROM attempts ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get_stats(self) -> Dict[str, Any]:
        total = self.conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
        successful = self.conn.execute("SELECT COUNT(*) FROM attempts WHERE success = 1").fetchone()[0]
        rule_count = self.conn.execute("SELECT COUNT(*) FROM attempts WHERE attack_type = 'rule'").fetchone()[0]
        novel_count = self.conn.execute("SELECT COUNT(*) FROM attempts WHERE attack_type = 'novel'").fetchone()[0]
        return {
            "total_attempts": total,
            "successful": successful,
            "rule_attempts": rule_count,
            "novel_attempts": novel_count,
        }
    
    def clear_rule_attempts(self) -> None:
        """Delete all rows where attack_type = 'rule'."""
        self.conn.execute("DELETE FROM attempts WHERE attack_type = 'rule'")
        self.conn.commit()

    def _row_to_dict(self, row) -> Dict[str, Any]:
        return {
            "id": row[0],
            "timestamp": row[1],
            "attack_type": row[2],
            "rule_name": row[3],
            "novel_description": row[4],
            "parameters": json.loads(row[5]) if row[5] else {},
            "success": bool(row[6]),
            "before_balance": row[7],
            "after_balance": row[8],
            "gas_used": row[9],
            "tx_hash": row[10],
            "llm_reasoning": row[11],
            "code_snippet": row[12],
            "attack_signature": row[13],
        }

# EOF