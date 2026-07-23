"""
Unit tests for the exporters registry and the StructuredExporter envelope.

The structured JSON envelope is a frozen cloud contract, so these tests assert
the exact top-level field names (version/generated_at/metadata/findings/
exploits/score/dependencies) and per-finding field names. No external services.
"""

import json
import tempfile
import unittest
from pathlib import Path

from hawki.core.exporters.base import Exporter
from hawki.core.exporters.registry import get_exporter, list_exporters, register_exporter
from hawki.core.exporters.structured_exporter import StructuredExporter


def _context():
    return {
        "repo_data": {"type": "local", "path": "/tmp/repo"},
        "findings": [
            {
                "id": "F1",
                "title": "Reentrancy",
                "severity": "Critical",
                "file": "Vault.sol",
                "line": 42,
                "vulnerable_snippet": "call.value",
                "fix_snippet": "use checks-effects",
                "explanation": "why",
                "impact": "loss of funds",
                "exploit_steps": ["deploy", "reenter"],
                "ai_used": False,
            }
        ],
        "score": {"score": 85, "classification": "Minor Risk", "deductions": {"critical_findings": 1}},
        "scan_metadata": {"version": "1.0.0"},
        "dependency_findings": [{"package": "lodash", "severity": "High"}],
    }


class TestExporterRegistry(unittest.TestCase):
    def test_structured_registered(self):
        self.assertIn("structured", list_exporters())

    def test_get_structured(self):
        exp = get_exporter("structured")
        self.assertIsInstance(exp, StructuredExporter)
        self.assertEqual(exp.name, "structured")
        self.assertTrue(exp.description)

    def test_get_unknown_returns_none(self):
        self.assertIsNone(get_exporter("does-not-exist"))

    def test_register_custom(self):
        class Dummy(Exporter):
            def export(self, context, output_path):
                return output_path

            @property
            def name(self):
                return "dummy"

            @property
            def description(self):
                return "d"

        register_exporter("dummy_test_only", Dummy)
        self.assertIn("dummy_test_only", list_exporters())
        self.assertIsInstance(get_exporter("dummy_test_only"), Dummy)


class TestStructuredEnvelope(unittest.TestCase):
    def test_envelope_top_level_keys(self):
        data = StructuredExporter()._build_export_data(_context())
        for key in ("version", "generated_at", "metadata", "findings",
                    "exploits", "score", "dependencies"):
            self.assertIn(key, data)
        self.assertEqual(data["version"], "1.0.0")
        self.assertIn("scan_metadata", data["metadata"])
        self.assertIn("target", data["metadata"])

    def test_finding_field_names(self):
        data = StructuredExporter()._build_export_data(_context())
        self.assertEqual(len(data["findings"]), 1)
        f = data["findings"][0]
        for key in ("id", "title", "severity", "file", "line",
                    "vulnerable_snippet", "fix_snippet", "explanation",
                    "impact", "exploit_steps", "ai_used"):
            self.assertIn(key, f)
        self.assertEqual(f["severity"], "Critical")

    def test_exploits_extracted_from_findings(self):
        data = StructuredExporter()._build_export_data(_context())
        self.assertEqual(len(data["exploits"]), 1)
        self.assertEqual(data["exploits"][0]["finding_id"], "F1")
        self.assertEqual(data["exploits"][0]["poc_format"], "solidity")

    def test_deployed_target_shape(self):
        ctx = _context()
        ctx["repo_data"] = {
            "type": "deployed",
            "address": "0xabc",
            "chain": "ethereum",
            "chain_id": 1,
            "source_available": True,
        }
        data = StructuredExporter()._build_export_data(ctx)
        target = data["metadata"]["target"]
        self.assertEqual(target["type"], "deployed")
        self.assertEqual(target["address"], "0xabc")
        self.assertEqual(target["chain"], "ethereum")

    def test_export_writes_valid_json_file(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        out = Path(tmp.name) / "export.json"
        returned = StructuredExporter().export(_context(), out)
        self.assertEqual(returned, out)
        loaded = json.loads(out.read_text())
        self.assertEqual(loaded["score"]["score"], 85)
        self.assertEqual(loaded["dependencies"][0]["package"], "lodash")


if __name__ == "__main__":
    unittest.main()
