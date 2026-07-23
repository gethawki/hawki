# File: hawki/core/deps/parsers/hardhat_config.py
"""
Parse hardhat.config.{js,ts,cjs} for the pinned Solidity compiler version(s).

Hardhat pins the compiler in the `solidity` field, which can be a bare version
string, a single `{ version: "x.y.z" }` object, or a `{ compilers: [...] }`
list. Each discovered compiler version is checked against the vulnerability
database under the `solc` package key.
"""
import logging
import re
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_CONFIG_NAMES = ("hardhat.config.js", "hardhat.config.ts", "hardhat.config.cjs")
# Matches: solidity: "0.8.19"  and  version: "0.8.19"
_VERSION_RE = re.compile(r'(?:solidity|version)\s*:\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']')


def parse_hardhat_config(repo_path: Path, db) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    config_file = None
    for name in _CONFIG_NAMES:
        candidate = repo_path / name
        if candidate.exists():
            config_file = candidate
            break
    if config_file is None:
        return findings

    try:
        content = config_file.read_text(encoding="utf-8")
    except Exception as e:
        logger.error(f"Failed to read {config_file.name}: {e}")
        return findings

    seen = set()
    for version in _VERSION_RE.findall(content):
        if version in seen:
            continue
        seen.add(version)
        for vuln in db.check_package("solc", version):
            vuln["file"] = config_file.name
            findings.append(vuln)
    return findings
# EOF
