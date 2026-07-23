# File: hawki/core/deps/parsers/yarn_lock.py
"""
Parse yarn.lock for package versions.
"""
import logging
import re
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# A block header names one or more descriptors, e.g.
#   "hardhat@^2.4.0", "hardhat@^2.6.0":
#   @openzeppelin/contracts@4.7.0:
# The descriptor carries a semver *range*, not the resolved version; the actual
# installed version is on the indented `version "x.y.z"` line that follows.
_HEADER_RE = re.compile(r'^"?((?:@[^/@"]+/)?[^@"\s]+)@')
_VERSION_RE = re.compile(r'^\s+version\s+"?([^"\s]+)"?')


def parse_yarn_lock(repo_path: Path, db) -> List[Dict[str, Any]]:
    findings = []
    lock_file = repo_path / "yarn.lock"
    if not lock_file.exists():
        return findings
    content = lock_file.read_text()
    lines = content.split('\n')

    pkg_version = {}
    current_pkg = None
    for line in lines:
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        if not line[0].isspace():
            # Block header line; capture the package name (first descriptor).
            header = _HEADER_RE.match(line.strip())
            current_pkg = header.group(1) if header else None
        elif current_pkg is not None:
            vmatch = _VERSION_RE.match(line)
            if vmatch:
                # Resolved version wins; last one for a name stays.
                pkg_version[current_pkg] = vmatch.group(1)
                current_pkg = None

    for pkg, version in pkg_version.items():
        vulns = db.check_package(pkg, version)
        for v in vulns:
            v["file"] = "yarn.lock"
            findings.append(v)
    return findings
# EOF
