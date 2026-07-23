"""
Unit tests for the deep-agent memory backends (JSONStore + SQLiteStore).

Both are MemoryStore implementations; the tests exercise the documented
contract (record / get_all / has_attempted / get_recent / get_stats /
clear_rule_attempts) against a temp path so nothing touches ~/.hawki.
No external services are involved.
"""

import tempfile
import unittest
from pathlib import Path

from hawki.core.deep.memory.json_store import JSONStore
from hawki.core.deep.memory.sqlite_store import SQLiteStore


def _rule_plan(sig="reentrancy.py", name="reentrancy"):
    return {"type": "rule", "rule_name": name, "signature": sig, "parameters": {}}


def _novel_plan(sig="novel-1"):
    return {"type": "novel", "novel_description": "transient storage reentrancy", "signature": sig}


def _result(success=True, before=10, after=0):
    return {"success": success, "before_balance": before, "after_balance": after, "gas_used": 21000}


class _MemoryContractMixin:
    """Shared assertions run against whichever store `self.make_store` builds."""

    def make_store(self):
        raise NotImplementedError

    def test_record_and_get_all(self):
        store = self.make_store()
        store.record(_rule_plan(), _result())
        records = store.get_all()
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["attack_type"], "rule")
        self.assertEqual(rec["rule_name"], "reentrancy")
        self.assertTrue(rec["success"])
        self.assertEqual(rec["attack_signature"], "reentrancy.py")

    def test_has_attempted(self):
        store = self.make_store()
        self.assertFalse(store.has_attempted("reentrancy.py"))
        store.record(_rule_plan(), _result())
        self.assertTrue(store.has_attempted("reentrancy.py"))
        self.assertFalse(store.has_attempted("nonexistent.py"))

    def test_get_stats(self):
        store = self.make_store()
        store.record(_rule_plan(sig="a.py", name="a"), _result(success=True))
        store.record(_rule_plan(sig="b.py", name="b"), _result(success=False))
        store.record(_novel_plan(sig="n1"), _result(success=True))
        stats = store.get_stats()
        self.assertEqual(stats["total_attempts"], 3)
        self.assertEqual(stats["successful"], 2)
        self.assertEqual(stats["rule_attempts"], 2)
        self.assertEqual(stats["novel_attempts"], 1)

    def test_get_recent_limit(self):
        store = self.make_store()
        for i in range(5):
            store.record(_rule_plan(sig=f"s{i}.py", name=f"r{i}"), _result())
        recent = store.get_recent(limit=2)
        self.assertEqual(len(recent), 2)

    def test_clear_rule_attempts_keeps_novel(self):
        store = self.make_store()
        store.record(_rule_plan(sig="a.py", name="a"), _result())
        store.record(_novel_plan(sig="n1"), _result())
        store.clear_rule_attempts()
        remaining = store.get_all()
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]["attack_type"], "novel")


class TestJSONStore(_MemoryContractMixin, unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def make_store(self):
        return JSONStore(file_path=Path(self.tmp.name) / "mem.jsonl")


class TestSQLiteStore(_MemoryContractMixin, unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def make_store(self):
        return SQLiteStore(db_path=Path(self.tmp.name) / "mem.db")


class TestSQLiteDedupe(unittest.TestCase):
    def test_signature_is_unique(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = SQLiteStore(db_path=Path(tmp.name) / "mem.db")
        # Same signature recorded twice -> INSERT OR REPLACE keeps a single row.
        store.record(_rule_plan(sig="dup.py"), _result())
        store.record(_rule_plan(sig="dup.py"), _result())
        self.assertEqual(store.get_stats()["total_attempts"], 1)


if __name__ == "__main__":
    unittest.main()
