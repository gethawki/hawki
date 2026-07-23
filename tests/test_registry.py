"""
Unit tests for ContractRegistry: add/list/clear, case-insensitive address
dedupe (increments scan_count instead of duplicating), and the 30-day
is_scanned window. Uses a temp registry path so ~/.hawki is never touched.
No external services.
"""

import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from hawki.core.registry.contract_registry import ContractRegistry

ADDR = "0xABCdef0000000000000000000000000000000001"


class TestContractRegistry(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "scanned_registry.json"

    def tearDown(self):
        self.tmp.cleanup()

    def _reg(self):
        return ContractRegistry(registry_path=self.path)

    def test_add_creates_entry_with_schema(self):
        reg = self._reg()
        reg.add(ADDR, "ethereum", repo_hash="deadbeef", findings_count=3)
        entries = reg.list_entries()
        self.assertEqual(len(entries), 1)
        e = entries[0]
        for key in ("address", "chain", "first_scanned", "last_scanned",
                    "scan_count", "repo_hash", "findings_count"):
            self.assertIn(key, e)
        self.assertEqual(e["scan_count"], 1)
        self.assertEqual(e["findings_count"], 3)

    def test_dedupe_increments_scan_count(self):
        reg = self._reg()
        reg.add(ADDR, "ethereum", findings_count=1)
        # Same contract, different address casing -> matched, not duplicated.
        reg.add(ADDR.lower(), "ethereum", findings_count=5)
        entries = reg.list_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["scan_count"], 2)
        self.assertEqual(entries[0]["findings_count"], 5)

    def test_different_chain_is_separate_entry(self):
        reg = self._reg()
        reg.add(ADDR, "ethereum")
        reg.add(ADDR, "polygon")
        self.assertEqual(len(reg.list_entries()), 2)

    def test_is_scanned_within_window(self):
        reg = self._reg()
        reg.add(ADDR, "ethereum")
        self.assertTrue(reg.is_scanned(ADDR, "ethereum", days=30))
        self.assertTrue(reg.is_scanned(ADDR.lower(), "ethereum", days=30))
        self.assertFalse(reg.is_scanned("0xNOTthere", "ethereum", days=30))

    def test_is_scanned_expires_outside_window(self):
        reg = self._reg()
        reg.add(ADDR, "ethereum")
        # Backdate the entry 40 days and persist.
        old = (datetime.utcnow() - timedelta(days=40)).isoformat()
        reg.data["entries"][0]["last_scanned"] = old
        reg._save()
        reg2 = ContractRegistry(registry_path=self.path)  # reload from disk
        self.assertFalse(reg2.is_scanned(ADDR, "ethereum", days=30))

    def test_clear(self):
        reg = self._reg()
        reg.add(ADDR, "ethereum")
        reg.clear()
        self.assertEqual(reg.list_entries(), [])

    def test_persistence_across_instances(self):
        reg = self._reg()
        reg.add(ADDR, "ethereum", findings_count=7)
        reloaded = ContractRegistry(registry_path=self.path)
        entry = reloaded.get_entry(ADDR, "ethereum")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["findings_count"], 7)


if __name__ == "__main__":
    unittest.main()
