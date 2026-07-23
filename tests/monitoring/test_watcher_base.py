# --------------------
# File: tests/monitoring/test_watcher_base.py
# --------------------
import unittest

from hawki.core.monitoring.watcher_base import Watcher


class DummyWatcher(Watcher):
    def check(self):
        return {"event": "dummy"}

class TestWatcherBase(unittest.TestCase):
    def test_get_id(self):
        w = DummyWatcher(name="test", config={})
        self.assertEqual(w.get_id(), "DummyWatcher:test")

    def test_state_management(self):
        w = DummyWatcher(name="test", config={})
        w.state = {"foo": "bar"}
        saved = w.save_state()
        self.assertEqual(saved, {"foo": "bar"})
        w.load_state({"new": "state"})
        self.assertEqual(w.state, {"new": "state"})

if __name__ == "__main__":
    unittest.main()