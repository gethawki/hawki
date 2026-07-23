# --------------------
# File: tests/monitoring/test_state_manager.py
# --------------------
import tempfile
import unittest
from pathlib import Path

from hawki.core.monitoring.state_manager import StateManager


class TestStateManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temp_dir.name)
        self.sm = StateManager(state_dir=self.state_dir)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_set_get(self):
        self.sm.set("watcher1", {"key": "value"})
        self.assertEqual(self.sm.get("watcher1"), {"key": "value"})

    def test_persistence(self):
        self.sm.set("w1", {"a": 1})
        self.sm.save()
        sm2 = StateManager(state_dir=self.state_dir)
        self.assertEqual(sm2.get("w1"), {"a": 1})

if __name__ == "__main__":
    unittest.main()