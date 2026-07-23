# --------------------
# File: tests/monitoring/test_alert_manager.py
# --------------------
import json
import tempfile
import unittest
from pathlib import Path

from hawki.core.monitoring.alert_manager import AlertManager


class TestAlertManager(unittest.TestCase):
    def test_alert_log_handler(self):
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".log") as tmp:
            am = AlertManager(alert_log_file=Path(tmp.name))
            event = {"message": "test alert", "foo": "bar"}
            am.alert(event)
            tmp.seek(0)
            line = tmp.readline()
            data = json.loads(line)
            self.assertEqual(data["message"], "test alert")
            self.assertEqual(data["foo"], "bar")
            self.assertIn("timestamp", data)

if __name__ == "__main__":
    unittest.main()