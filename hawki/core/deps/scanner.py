# File: hawki/core/deps/scanner.py
"""
Complete dependency scanner with semver version comparison,
support for multiple lockfiles (package.json, foundry.toml, yarn.lock, pnpm-lock.yaml, Cargo.toml).
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from .parsers import (
    parse_cargo_toml,
    parse_foundry_toml,
    parse_hardhat_config,
    parse_package_json,
    parse_pnpm_lock,
    parse_yarn_lock,
)

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path(__file__).parent / "vuln_libs.json"


def _normalize_constraint(constraint: str) -> str:
    """
    Make a version constraint parseable by packaging.SpecifierSet.

    The vulnerability database uses a bare ``=`` operator (e.g. ``=4.7.0``) as
    shorthand for an exact pin, but SpecifierSet only accepts ``==``. Normalize
    each comma-separated clause so a single-equals prefix becomes double-equals.
    """
    parts = [p.strip() for p in constraint.split(",") if p.strip()]
    fixed = []
    for p in parts:
        if p.startswith("=") and not p.startswith("=="):
            p = "=" + p
        fixed.append(p)
    return ",".join(fixed)

class VulnerableLibDB:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self.data = self._load()

    def _load(self) -> Dict[str, Any]:
        if not self.db_path.exists():
            logger.warning(f"Vulnerability database not found: {self.db_path}")
            return {}
        with open(self.db_path) as f:
            return json.load(f)

    def update(self, url: str = None) -> None:
        import requests
        if url is None:
            url = "https://raw.githubusercontent.com/hawki/hawki-vuln-db/main/vuln_libs.json"
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        self.db_path.write_text(resp.text)
        self.data = self._load()
        logger.info(f"Vulnerability database updated from {url}")

    def check_package(self, name: str, version_str: str) -> List[Dict]:
        """Return list of vulnerabilities matching the version."""
        if name not in self.data:
            return []
        findings = []
        try:
            inst_version = Version(version_str)
        except InvalidVersion:
            # Try to clean further
            cleaned = version_str.strip()
            try:
                inst_version = Version(cleaned)
            except InvalidVersion:
                return findings
        for entry in self.data[name]:
            raw_constraint = entry["version_constraint"]
            try:
                spec = SpecifierSet(_normalize_constraint(raw_constraint))
            except InvalidSpecifier:
                logger.warning(
                    f"Skipping unparseable constraint '{raw_constraint}' for {name}"
                )
                continue
            if inst_version in spec:
                findings.append({
                    "package": name,
                    "installed_version": version_str,
                    "vulnerable_versions": entry["version_constraint"],
                    "severity": entry.get("severity", "High"),
                    "description": entry.get("description", ""),
                })
        return findings

def scan_dependencies(repo_path: Path, db_path: Optional[Path] = None) -> List[Dict]:
    db = VulnerableLibDB(db_path)
    findings = []
    # Run all parsers
    parsers = [
        parse_package_json,
        parse_foundry_toml,
        parse_hardhat_config,
        parse_yarn_lock,
        parse_pnpm_lock,
        parse_cargo_toml,
    ]
    for parser in parsers:
        findings.extend(parser(repo_path, db))
    return findings

def update_db(db_path: Optional[Path] = None, url: str = None):
    db = VulnerableLibDB(db_path)
    db.update(url)
# EOF
