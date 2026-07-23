# --------------------
# File: tests/monitoring/test_cov_monitoring_monitor.py
# --------------------
"""
Coverage tests for the Monitor facade and WatcherRegistry.

The registry discovers the real watcher classes, but run cycles use
in-memory dummy watchers so no git/RPC is ever touched. State lives in
tmp dirs via tmp_path.
"""

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from hawki.core.monitoring import Monitor, WatcherRegistry
from hawki.core.monitoring.watcher_base import Watcher


class EventWatcher(Watcher):
    """Emits a fixed event (without a 'message' key) every check."""

    def check(self):
        return {"type": "boom"}


class QuietWatcher(Watcher):
    def check(self):
        return None


class TestWatcherRegistry(unittest.TestCase):
    def test_discovers_real_watchers(self):
        reg = WatcherRegistry()
        names = {c.__name__ for c in reg._watcher_classes}
        self.assertIn("CICDWatcher", names)
        self.assertIn("VulnerabilityEventWatcher", names)
        self.assertIn("RepoCommitWatcher", names)
        self.assertIn("DeployedContractWatcher", names)

    def test_missing_dir_yields_no_watchers(self):
        reg = WatcherRegistry(watchers_dir=Path("/nonexistent/watchers/dir"))
        self.assertEqual(reg._watcher_classes, [])

    def test_instantiate_all_skips_failing_watchers(self):
        reg = WatcherRegistry()
        # Empty configs -> DeployedContractWatcher raises (no contract_address)
        # and is skipped; the placeholder + repo watchers instantiate fine.
        instances = reg.instantiate_all({})
        names = {i.__class__.__name__ for i in instances}
        self.assertIn("CICDWatcher", names)
        self.assertIn("VulnerabilityEventWatcher", names)
        self.assertNotIn("DeployedContractWatcher", names)


class TestMonitor(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.state_dir = Path(self._tmp.name) / "state"
        self.alert_log = Path(self._tmp.name) / "alerts.log"

    def tearDown(self):
        self._tmp.cleanup()

    def _monitor(self):
        return Monitor(
            watcher_configs={},
            state_dir=self.state_dir,
            alert_log_file=self.alert_log,
        )

    def test_run_once_dispatches_and_persists(self):
        mon = self._monitor()
        ev = EventWatcher(name="ev", config={})
        quiet = QuietWatcher(name="quiet", config={})
        mon.watchers = [ev, quiet]

        mon.run_once()

        # Alert written for the event watcher, with injected message/watcher.
        lines = self.alert_log.read_text().strip().splitlines()
        self.assertEqual(len(lines), 1)
        record = json.loads(lines[0])
        self.assertEqual(record["type"], "boom")
        self.assertEqual(record["watcher"], "ev")
        self.assertEqual(record["message"], "Event from ev")
        self.assertIn("timestamp", record)

        # States persisted to disk under each watcher id.
        saved = json.loads((self.state_dir / "watcher_states.json").read_text())
        self.assertIn(ev.get_id(), saved)
        self.assertIn(quiet.get_id(), saved)

    def test_run_once_swallows_watcher_exception(self):
        mon = self._monitor()

        class Boom(Watcher):
            def check(self):
                raise RuntimeError("kaboom")

        mon.watchers = [Boom(name="boom", config={})]
        # Should not raise; error is logged and state still saved.
        mon.run_once()
        self.assertTrue((self.state_dir / "watcher_states.json").exists())

    def test_state_roundtrip_across_monitors(self):
        mon = self._monitor()
        w = QuietWatcher(name="quiet", config={})
        w.state = {"counter": 42}
        mon.watchers = [w]
        mon._save_states()

        # A fresh watcher loaded from a new StateManager sees persisted state.
        from hawki.core.monitoring.state_manager import StateManager
        sm = StateManager(state_dir=self.state_dir)
        self.assertEqual(sm.get(w.get_id()), {"counter": 42})

    def test_load_states_restores_watcher_state(self):
        # Seed state file, then build a monitor and confirm restoration.
        from hawki.core.monitoring.state_manager import StateManager
        w = QuietWatcher(name="quiet", config={})
        sm = StateManager(state_dir=self.state_dir)
        sm.set(w.get_id(), {"restored": True})
        sm.save()

        mon = self._monitor()
        mon.watchers = [w]
        mon._load_states()
        self.assertEqual(w.state, {"restored": True})

    def test_run_forever_stops_on_keyboard_interrupt(self):
        mon = self._monitor()
        mon.watchers = [QuietWatcher(name="quiet", config={})]
        with patch("hawki.core.monitoring.time.sleep", side_effect=KeyboardInterrupt):
            # Runs one cycle, then sleep raises KeyboardInterrupt -> clean exit.
            mon.run_forever(interval_seconds=0)
        self.assertTrue((self.state_dir / "watcher_states.json").exists())


if __name__ == "__main__":
    unittest.main()
