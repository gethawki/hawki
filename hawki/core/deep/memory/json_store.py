# File: hawki/core/deep/memory/json_store.py
"""
JSON lines (JSONL) implementation of MemoryStore.
Each attempt is one line in the file.
"""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import MemoryStore


class JSONStore(MemoryStore):
    """Simple JSON lines storage (human-readable)."""

    def __init__(self, file_path: Optional[Path] = None):
        if file_path is None:
            file_path = Path.home() / ".hawki" / "deep_memory.jsonl"
        file_path.parent.mkdir(parents=True, exist_ok=True)
        self.file_path = file_path

    def _append_line(self, data: Dict[str, Any]) -> None:
        with open(self.file_path, "a") as f:
            f.write(json.dumps(data) + "\n")

    def _read_all_lines(self) -> List[Dict[str, Any]]:
        if not self.file_path.exists():
            return []
        with open(self.file_path) as f:
            lines = [json.loads(line) for line in f if line.strip()]
        return lines

    def record(self, attack_plan: Dict[str, Any], result: Dict[str, Any]) -> None:
        record = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "attack_type": attack_plan.get("type", "rule"),
            "rule_name": attack_plan.get("rule_name"),
            "novel_description": attack_plan.get("novel_description"),
            "parameters": attack_plan.get("parameters", {}),
            "success": result.get("success", False),
            "before_balance": result.get("before_balance", 0),
            "after_balance": result.get("after_balance", 0),
            "gas_used": result.get("gas_used", 0),
            "tx_hash": result.get("transaction_hash", ""),
            "llm_reasoning": result.get("llm_reasoning", ""),
            "code_snippet": result.get("code_snippet", ""),
            "attack_signature": attack_plan.get("signature", str(uuid.uuid4())),
        }
        self._append_line(record)

    def has_attempted(self, attack_signature: str) -> bool:
        for rec in self._read_all_lines():
            if rec.get("attack_signature") == attack_signature:
                return True
        return False

    def get_all(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        records = self._read_all_lines()
        if filters:
            filtered = []
            for r in records:
                match = True
                for k, v in filters.items():
                    if r.get(k) != v:
                        match = False
                        break
                if match:
                    filtered.append(r)
            return filtered
        return records

    def get_recent(self, limit: int = 10) -> List[Dict[str, Any]]:
        records = self._read_all_lines()
        return records[-limit:][::-1]  # most recent last in file, reverse
    
    def clear_rule_attempts(self) -> None:
        """Rewrite file, keeping only entries where attack_type != 'rule'."""
        records = self._read_all_lines()
        filtered = [r for r in records if r.get("attack_type") != "rule"]
        # Overwrite file
        with open(self.file_path, "w") as f:
            for rec in filtered:
                f.write(json.dumps(rec) + "\n")

    def get_stats(self) -> Dict[str, Any]:
        records = self._read_all_lines()
        total = len(records)
        successful = sum(1 for r in records if r.get("success"))
        rule_count = sum(1 for r in records if r.get("attack_type") == "rule")
        novel_count = sum(1 for r in records if r.get("attack_type") == "novel")
        return {
            "total_attempts": total,
            "successful": successful,
            "rule_attempts": rule_count,
            "novel_attempts": novel_count,
        }

# EOF