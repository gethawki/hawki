# File: hawki/core/deps/parsers/cargo_toml.py
"""
Parse Cargo.toml for Rust dependencies (future-proofing).
"""
import logging
from pathlib import Path
from typing import Any, Dict, List

import toml

logger = logging.getLogger(__name__)

def parse_cargo_toml(repo_path: Path, db) -> List[Dict[str, Any]]:
    findings = []
    cargo_file = repo_path / "Cargo.toml"
    if not cargo_file.exists():
        return findings
    try:
        data = toml.load(cargo_file)
        deps = data.get("dependencies", {})
        for pkg, version in deps.items():
            if isinstance(version, dict):
                version = version.get("version", "")
            if version:
                vulns = db.check_package(pkg, version)
                for v in vulns:
                    v["file"] = "Cargo.toml"
                    findings.append(v)
    except Exception as e:
        logger.error(f"Failed to parse Cargo.toml: {e}")
    return findings
# EOF
