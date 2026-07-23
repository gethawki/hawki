# File: hawki/core/deps/parsers/foundry_toml.py
"""
Parse foundry.toml for git dependencies (forge-std, etc.).
"""
import logging
import re
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

def parse_foundry_toml(repo_path: Path, db) -> List[Dict[str, Any]]:
    findings = []
    foundry_file = repo_path / "foundry.toml"
    if not foundry_file.exists():
        return findings
    content = foundry_file.read_text()
    # Look for [dependencies] section
    dep_section = re.search(r'\[dependencies\](.*?)(?=\n\[|$)', content, re.DOTALL)
    if dep_section:
        lines = dep_section.group(1).split('\n')
        for line in lines:
            match = re.match(r'([\w@/-]+)\s*=\s*\{\s*git\s*=\s*"[^"]+",\s*tag\s*=\s*"v?([\d\.]+)"', line)
            if match:
                pkg = match.group(1)
                version = match.group(2)
                vulns = db.check_package(pkg, version)
                for v in vulns:
                    v["file"] = "foundry.toml"
                    findings.append(v)
    return findings
# EOF
