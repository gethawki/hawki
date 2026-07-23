"""
Unit tests for the dependency scanner's semver matching (VulnerableLibDB) and
the package.json / Cargo.toml parsers. Uses a temp vuln DB and temp repo files;
no network (the DB.update() HTTP path is not exercised).
"""

import json
import tempfile
import unittest
from pathlib import Path

from hawki.core.deps.parsers.base import clean_version
from hawki.core.deps.scanner import VulnerableLibDB, scan_dependencies


def _write_db(dir_path):
    db_path = Path(dir_path) / "vuln_libs.json"
    db_path.write_text(json.dumps({
        "lodash": [
            {"version_constraint": "<4.17.21", "severity": "High", "description": "proto pollution"},
        ],
        "openzeppelin": [
            {"version_constraint": ">=4.0.0,<4.4.1", "severity": "Critical", "description": "initializer bug"},
        ],
    }))
    return db_path


class TestCleanVersion(unittest.TestCase):
    def test_strips_range_prefixes(self):
        self.assertEqual(clean_version("^4.17.20"), "4.17.20")
        self.assertEqual(clean_version("~1.2.3"), "1.2.3")
        self.assertEqual(clean_version("v2.0.0"), "2.0.0")
        self.assertEqual(clean_version("=3.1.0"), "3.1.0")
        self.assertEqual(clean_version("1.0.0"), "1.0.0")


class TestVulnerableLibDB(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = VulnerableLibDB(db_path=_write_db(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_vulnerable_version_matches(self):
        vulns = self.db.check_package("lodash", "4.17.20")
        self.assertEqual(len(vulns), 1)
        v = vulns[0]
        self.assertEqual(v["package"], "lodash")
        self.assertEqual(v["installed_version"], "4.17.20")
        self.assertEqual(v["vulnerable_versions"], "<4.17.21")
        self.assertEqual(v["severity"], "High")

    def test_patched_version_not_flagged(self):
        self.assertEqual(self.db.check_package("lodash", "4.17.21"), [])

    def test_bounded_range(self):
        self.assertEqual(len(self.db.check_package("openzeppelin", "4.3.0")), 1)
        self.assertEqual(self.db.check_package("openzeppelin", "4.4.1"), [])
        self.assertEqual(self.db.check_package("openzeppelin", "3.9.0"), [])

    def test_unknown_package(self):
        self.assertEqual(self.db.check_package("not-a-package", "1.0.0"), [])

    def test_invalid_version_string(self):
        self.assertEqual(self.db.check_package("lodash", "not-a-version"), [])


class TestScanDependencies(unittest.TestCase):
    def test_package_json_flags_vulnerable_dep(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db_path = _write_db(tmp.name)
        repo = Path(tmp.name)
        (repo / "package.json").write_text(json.dumps({
            "dependencies": {"lodash": "^4.17.20"},
            "devDependencies": {"openzeppelin": "9.9.9"},
        }))
        findings = scan_dependencies(repo, db_path=db_path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["package"], "lodash")
        self.assertEqual(findings[0]["file"], "package.json")

    def test_cargo_toml_dict_version(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db_path = _write_db(tmp.name)
        # add a rust package to the db
        data = json.loads(db_path.read_text())
        data["serde"] = [{"version_constraint": "<1.0.100", "severity": "Medium", "description": "x"}]
        db_path.write_text(json.dumps(data))
        repo = Path(tmp.name)
        (repo / "Cargo.toml").write_text(
            '[dependencies]\nserde = { version = "1.0.99", features = ["derive"] }\n'
        )
        findings = scan_dependencies(repo, db_path=db_path)
        self.assertTrue(any(f["package"] == "serde" and f["file"] == "Cargo.toml" for f in findings))

    def test_no_lockfiles_no_findings(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db_path = _write_db(tmp.name)
        self.assertEqual(scan_dependencies(Path(tmp.name), db_path=db_path), [])


if __name__ == "__main__":
    unittest.main()
