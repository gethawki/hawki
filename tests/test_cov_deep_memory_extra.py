# File: tests/deep/test_cov_deep_memory_extra.py
"""
Extra memory-store coverage not covered by tests/test_deep_memory.py:
JSONStore.get_all(filters=...), get_recent ordering, and the novel_description
round-trip. Temp paths only; no external services.
"""

import tempfile
import unittest
from pathlib import Path

from hawki.core.deep.memory.json_store import JSONStore
from hawki.core.deep.memory.sqlite_store import SQLiteStore


def _rule(sig="r.py", name="reentrancy"):
    return {"type": "rule", "rule_name": name, "signature": sig, "parameters": {"depth": 2}}


def _novel(sig="n1", desc="transient reentrancy"):
    return {"type": "novel", "novel_description": desc, "signature": sig, "parameters": {}}


def _result(success=True):
    return {"success": success, "before_balance": 5, "after_balance": 0,
            "gas_used": 100, "transaction_hash": "0xabc",
            "llm_reasoning": "why", "code_snippet": "code"}


class TestJSONStoreExtra(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = JSONStore(file_path=Path(self.tmp.name) / "mem.jsonl")

    def test_get_all_with_filters(self):
        self.store.record(_rule(sig="a.py", name="a"), _result(success=True))
        self.store.record(_rule(sig="b.py", name="b"), _result(success=False))
        matched = self.store.get_all(filters={"success": True})
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["rule_name"], "a")
        none_match = self.store.get_all(filters={"rule_name": "zzz"})
        self.assertEqual(none_match, [])

    def test_get_recent_returns_most_recent_first(self):
        for i in range(3):
            self.store.record(_rule(sig=f"s{i}.py", name=f"r{i}"), _result())
        recent = self.store.get_recent(limit=2)
        self.assertEqual(len(recent), 2)
        # File order is oldest->newest; get_recent reverses -> newest first.
        self.assertEqual(recent[0]["rule_name"], "r2")
        self.assertEqual(recent[1]["rule_name"], "r1")

    def test_novel_description_and_reasoning_persist(self):
        self.store.record(_novel(sig="n1", desc="storage reentrancy"), _result())
        rec = self.store.get_all()[0]
        self.assertEqual(rec["novel_description"], "storage reentrancy")
        self.assertEqual(rec["llm_reasoning"], "why")
        self.assertEqual(rec["tx_hash"], "0xabc")

    def test_get_all_empty_file(self):
        self.assertEqual(self.store.get_all(), [])
        self.assertFalse(self.store.has_attempted("anything"))


class TestSQLiteStoreExtra(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = SQLiteStore(db_path=Path(self.tmp.name) / "mem.db")

    def test_get_recent_desc_and_row_to_dict(self):
        self.store.record(_novel(sig="n1", desc="d1"), _result(success=True))
        recent = self.store.get_recent(limit=5)
        self.assertEqual(len(recent), 1)
        rec = recent[0]
        self.assertEqual(rec["novel_description"], "d1")
        self.assertEqual(rec["parameters"], {})
        self.assertTrue(rec["success"])
        self.assertEqual(rec["gas_used"], 100)

    def test_get_all_ordered(self):
        self.store.record(_rule(sig="a.py"), _result())
        self.store.record(_novel(sig="n1"), _result())
        rows = self.store.get_all()
        self.assertEqual(len(rows), 2)


if __name__ == "__main__":
    unittest.main()
