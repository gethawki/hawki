# File: tests/test_cov_deps_extra.py
"""
Extra coverage for core.deps: the foundry.toml / hardhat.config / yarn.lock /
pnpm-lock parsers, the exact-pin ("=x.y.z") constraint normalization, the
unparseable-constraint and missing-DB branches, and the update() HTTP path
(mocked, no network).
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hawki.core.deps.scanner import (
    VulnerableLibDB,
    _normalize_constraint,
    scan_dependencies,
    update_db,
)


def _write_db(dir_path, extra=None):
    data = {
        "@openzeppelin/contracts": [
            {"version_constraint": "=4.7.0", "severity": "High", "description": "storage collision"},
        ],
        "forge-std": [
            {"version_constraint": "<=1.5.0", "severity": "Medium", "description": "console left in"},
        ],
        "hardhat": [
            {"version_constraint": "<2.5.0", "severity": "Critical", "description": "rce"},
        ],
        "solc": [
            {"version_constraint": "<0.8.4", "severity": "Medium", "description": "abi bug"},
        ],
        "lodash": [
            {"version_constraint": "<4.17.21", "severity": "High", "description": "proto"},
        ],
    }
    if extra:
        data.update(extra)
    db_path = Path(dir_path) / "vuln_libs.json"
    db_path.write_text(json.dumps(data))
    return db_path


class TestNormalizeConstraint(unittest.TestCase):
    def test_single_equals_becomes_double(self):
        self.assertEqual(_normalize_constraint("=4.7.0"), "==4.7.0")

    def test_double_equals_untouched(self):
        self.assertEqual(_normalize_constraint("==4.7.0"), "==4.7.0")

    def test_multi_clause_and_whitespace(self):
        self.assertEqual(
            _normalize_constraint(">=4.0.0, <4.4.1"), ">=4.0.0,<4.4.1"
        )

    def test_exact_pin_matches_via_db(self):
        with tempfile.TemporaryDirectory() as d:
            db = VulnerableLibDB(db_path=_write_db(d))
            self.assertEqual(len(db.check_package("@openzeppelin/contracts", "4.7.0")), 1)
            self.assertEqual(db.check_package("@openzeppelin/contracts", "4.7.1"), [])


class TestDBEdgeCases(unittest.TestCase):
    def test_missing_db_file_returns_empty(self):
        missing = Path(tempfile.gettempdir()) / "does-not-exist-hawki-vuln.json"
        if missing.exists():
            missing.unlink()
        db = VulnerableLibDB(db_path=missing)
        self.assertEqual(db.data, {})
        self.assertEqual(db.check_package("lodash", "1.0.0"), [])

    def test_unparseable_constraint_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            db_path = _write_db(d, extra={
                "weird": [{"version_constraint": "not-a-spec", "severity": "High", "description": "x"}],
            })
            db = VulnerableLibDB(db_path=db_path)
            # Should not raise; the bad clause is skipped and yields no findings.
            self.assertEqual(db.check_package("weird", "1.0.0"), [])


class TestUpdateHTTP(unittest.TestCase):
    def test_update_writes_fetched_body(self):
        with tempfile.TemporaryDirectory() as d:
            db_path = _write_db(d)
            new_body = json.dumps({"lodash": [
                {"version_constraint": "<5.0.0", "severity": "Low", "description": "fetched"}
            ]})
            fake_resp = mock.MagicMock()
            fake_resp.text = new_body
            fake_resp.raise_for_status.return_value = None
            # update() does `import requests` internally, so patch the module.
            with mock.patch("requests.get", return_value=fake_resp) as getter:
                db = VulnerableLibDB(db_path=db_path)
                db.update()
                getter.assert_called_once()
            self.assertIn("lodash", db.data)
            self.assertEqual(db.data["lodash"][0]["description"], "fetched")

    def test_update_uses_custom_url(self):
        with tempfile.TemporaryDirectory() as d:
            db_path = _write_db(d)
            fake_resp = mock.MagicMock()
            fake_resp.text = json.dumps({})
            fake_resp.raise_for_status.return_value = None
            with mock.patch("requests.get", return_value=fake_resp) as getter:
                update_db(db_path=db_path, url="https://example.test/db.json")
                args, kwargs = getter.call_args
                self.assertEqual(args[0], "https://example.test/db.json")


class TestFoundryParser(unittest.TestCase):
    def test_git_tag_dependency_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            db_path = _write_db(d)
            repo = Path(d)
            (repo / "foundry.toml").write_text(
                "[profile.default]\nsrc = 'src'\n\n"
                "[dependencies]\n"
                'forge-std = { git = "https://github.com/foundry-rs/forge-std", tag = "v1.4.0" }\n'
            )
            findings = scan_dependencies(repo, db_path=db_path)
            hits = [f for f in findings if f["file"] == "foundry.toml"]
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["package"], "forge-std")

    def test_no_dependencies_section(self):
        with tempfile.TemporaryDirectory() as d:
            db_path = _write_db(d)
            repo = Path(d)
            (repo / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n")
            self.assertEqual(scan_dependencies(repo, db_path=db_path), [])


class TestHardhatParser(unittest.TestCase):
    def test_solidity_version_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            db_path = _write_db(d)
            repo = Path(d)
            (repo / "hardhat.config.js").write_text(
                'module.exports = { solidity: "0.8.3" };\n'
            )
            findings = scan_dependencies(repo, db_path=db_path)
            hits = [f for f in findings if f["file"] == "hardhat.config.js"]
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["package"], "solc")

    def test_compilers_list_dedup(self):
        with tempfile.TemporaryDirectory() as d:
            db_path = _write_db(d)
            repo = Path(d)
            (repo / "hardhat.config.ts").write_text(
                'export default { solidity: { compilers: ['
                '{ version: "0.8.3" }, { version: "0.8.3" }, { version: "0.9.0" }'
                '] } };\n'
            )
            findings = scan_dependencies(repo, db_path=db_path)
            hits = [f for f in findings if f["file"] == "hardhat.config.ts"]
            # 0.8.3 flagged once (deduped); 0.9.0 not vulnerable.
            self.assertEqual(len(hits), 1)


class TestYarnLockParser(unittest.TestCase):
    def test_resolved_version_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            db_path = _write_db(d)
            repo = Path(d)
            (repo / "yarn.lock").write_text(
                "# yarn lockfile v1\n\n"
                '"@openzeppelin/contracts@^4.7.0":\n'
                '  version "4.7.0"\n'
                '  resolved "https://registry/x"\n\n'
                '"hardhat@^2.4.0", "hardhat@^2.6.0":\n'
                '  version "2.4.0"\n'
                '  resolved "https://registry/y"\n'
            )
            findings = scan_dependencies(repo, db_path=db_path)
            hits = {f["package"] for f in findings if f["file"] == "yarn.lock"}
            self.assertIn("@openzeppelin/contracts", hits)
            self.assertIn("hardhat", hits)

    def test_safe_versions_no_findings(self):
        with tempfile.TemporaryDirectory() as d:
            db_path = _write_db(d)
            repo = Path(d)
            (repo / "yarn.lock").write_text(
                '"lodash@^4.17.21":\n  version "4.17.21"\n'
            )
            self.assertEqual(
                [f for f in scan_dependencies(repo, db_path=db_path) if f["file"] == "yarn.lock"],
                [],
            )


class TestPnpmLockParser(unittest.TestCase):
    def test_v6_and_v9_key_shapes(self):
        with tempfile.TemporaryDirectory() as d:
            db_path = _write_db(d)
            repo = Path(d)
            (repo / "pnpm-lock.yaml").write_text(
                "lockfileVersion: '6.0'\n"
                "packages:\n"
                "  /lodash@4.17.20:\n"
                "    resolution: {integrity: sha512-x}\n"
                "  /@openzeppelin/contracts@4.7.0(react@18.0.0):\n"
                "    resolution: {integrity: sha512-y}\n"
            )
            findings = scan_dependencies(repo, db_path=db_path)
            hits = {f["package"] for f in findings if f["file"] == "pnpm-lock.yaml"}
            self.assertIn("lodash", hits)
            self.assertIn("@openzeppelin/contracts", hits)

    def test_malformed_yaml_is_swallowed(self):
        with tempfile.TemporaryDirectory() as d:
            db_path = _write_db(d)
            repo = Path(d)
            (repo / "pnpm-lock.yaml").write_text("packages:\n  - [unbalanced\n")
            # Should not raise; returns whatever (possibly empty).
            findings = scan_dependencies(repo, db_path=db_path)
            self.assertEqual([f for f in findings if f["file"] == "pnpm-lock.yaml"], [])


if __name__ == "__main__":
    unittest.main()
