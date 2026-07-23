# File: tests/test_cov_telemetry_store.py
"""
Coverage tests for the telemetry MetricsStore. Pure local file I/O driven from
a tmp path (no network, no external deps). Round-trips append/get_all/clear and
exercises the corrupt-file and default-path branches.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hawki.core.telemetry.store import MetricsStore


class TestMetricsStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "sub" / "metrics.json"

    def test_constructor_creates_parent_dir(self):
        MetricsStore(self.path)
        self.assertTrue(self.path.parent.is_dir())

    def test_append_and_get_all_roundtrip(self):
        store = MetricsStore(self.path)
        store.append({"a": 1})
        store.append({"b": 2})
        data = store.get_all()
        self.assertEqual(data, [{"a": 1}, {"b": 2}])
        # File on disk is valid JSON list.
        self.assertEqual(json.loads(self.path.read_text()), data)

    def test_get_all_missing_file_returns_empty(self):
        store = MetricsStore(self.path)
        self.assertEqual(store.get_all(), [])

    def test_get_all_corrupt_file_returns_empty(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("{not json")
        store = MetricsStore(self.path)
        self.assertEqual(store.get_all(), [])

    def test_append_over_corrupt_file_resets(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("garbage")
        store = MetricsStore(self.path)
        store.append({"x": 9})
        self.assertEqual(store.get_all(), [{"x": 9}])

    def test_clear_removes_file(self):
        store = MetricsStore(self.path)
        store.append({"a": 1})
        self.assertTrue(self.path.exists())
        store.clear()
        self.assertFalse(self.path.exists())
        # Clearing again (missing file) is a no-op.
        store.clear()
        self.assertEqual(store.get_all(), [])

    def test_default_path_used_when_none(self):
        default = Path(self.tmp.name) / "home" / ".hawki" / "metrics.json"
        with mock.patch.object(MetricsStore, "DEFAULT_PATH", default):
            store = MetricsStore()
            self.assertEqual(store.path, default)
            store.append({"z": 1})
            self.assertEqual(store.get_all(), [{"z": 1}])


if __name__ == "__main__":
    unittest.main()
