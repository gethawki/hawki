# File: tests/test_cov_telemetry_collector.py
"""
Coverage tests for the telemetry MetricsCollector. Drives collect/
collect_from_scan against a MetricsStore backed by a tmp path and asserts the
severity bucketing and simulation-success-rate computation.
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hawki.core.telemetry.collector import MetricsCollector
from hawki.core.telemetry.store import MetricsStore


class TestMetricsCollector(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "metrics.json"
        self.store = MetricsStore(self.path)
        self.collector = MetricsCollector(store=self.store)

    def test_collect_builds_and_persists_metrics(self):
        meta = {
            "version": "1.0.0",
            "mode": "full",
            "ai_enabled": True,
            "sandbox_enabled": False,
        }
        findings = {"Critical": 1, "High": 2}
        metrics = self.collector.collect(meta, findings, simulation_success_rate=0.5)
        self.assertEqual(metrics["version"], "1.0.0")
        self.assertEqual(metrics["mode"], "full")
        self.assertTrue(metrics["ai_enabled"])
        self.assertEqual(metrics["findings"], findings)
        self.assertEqual(metrics["simulation_success_rate"], 0.5)
        self.assertIn("platform", metrics)
        self.assertIn("timestamp", metrics)
        # Persisted to the store.
        self.assertEqual(self.store.get_all(), [metrics])

    def test_collect_defaults_for_missing_metadata(self):
        metrics = self.collector.collect({}, {})
        self.assertEqual(metrics["version"], "unknown")
        self.assertEqual(metrics["mode"], "minimal")
        self.assertFalse(metrics["ai_enabled"])
        self.assertFalse(metrics["sandbox_enabled"])

    def test_collect_from_scan_severity_counts(self):
        findings = [
            {"severity": "critical"},   # capitalize -> Critical
            {"severity": "HIGH"},       # capitalize -> High
            {"severity": "medium"},
            {"severity": "low"},
            {"severity": "weird"},      # unknown -> Low bucket
            {},                          # default Low
        ]
        meta = {"sandbox_enabled": False}
        metrics = self.collector.collect_from_scan(meta, {}, findings)
        counts = metrics["findings"]
        self.assertEqual(counts["Critical"], 1)
        self.assertEqual(counts["High"], 1)
        self.assertEqual(counts["Medium"], 1)
        self.assertEqual(counts["Low"], 3)  # low + weird + default
        self.assertIsNone(metrics["simulation_success_rate"])

    def test_collect_from_scan_simulation_rate(self):
        meta = {"sandbox_enabled": True}
        repo = {"sandbox_results": [{"success": True}, {"success": False}, {"success": True}]}
        metrics = self.collector.collect_from_scan(meta, repo, [])
        self.assertAlmostEqual(metrics["simulation_success_rate"], 2 / 3)

    def test_collect_from_scan_sandbox_enabled_but_no_results(self):
        meta = {"sandbox_enabled": True}
        repo = {"sandbox_results": []}
        metrics = self.collector.collect_from_scan(meta, repo, [])
        self.assertIsNone(metrics["simulation_success_rate"])

    def test_default_store_when_none(self):
        default = Path(self.tmp.name) / "default" / "metrics.json"
        with mock.patch.object(MetricsStore, "DEFAULT_PATH", default):
            collector = MetricsCollector()
            self.assertIsInstance(collector.store, MetricsStore)
            self.assertEqual(collector.store.path, default)


if __name__ == "__main__":
    unittest.main()
