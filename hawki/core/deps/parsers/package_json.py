# File: hawki/core/deps/parsers/package_json.py
"""
Parse package.json for dependencies.
"""
import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from .base import clean_version

logger = logging.getLogger(__name__)

def parse_package_json(repo_path: Path, db) -> List[Dict[str, Any]]:
    findings = []
    pkg_file = repo_path / "package.json"
    if not pkg_file.exists():
        return findings
    try:
        data = json.loads(pkg_file.read_text())
        deps = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))
        for pkg, version in deps.items():
            version_clean = clean_version(version)
            if not version_clean:
                continue
            vulns = db.check_package(pkg, version_clean)
            for v in vulns:
                v["file"] = "package.json"
                findings.append(v)
    except Exception as e:
        logger.error(f"Failed to parse package.json: {e}")
    return findings
# EOF
