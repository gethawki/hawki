# File: hawki/core/deps/parsers/pnpm_lock.py
"""
Parse pnpm-lock.yaml for package versions.
"""
import logging
from pathlib import Path
from typing import Any, Dict, List

import yaml

logger = logging.getLogger(__name__)

def parse_pnpm_lock(repo_path: Path, db) -> List[Dict[str, Any]]:
    findings = []
    lock_file = repo_path / "pnpm-lock.yaml"
    if not lock_file.exists():
        return findings
    try:
        with open(lock_file) as f:
            data = yaml.safe_load(f) or {}
        # lockfileVersion 6.x keys look like '/pkg@version(peer)'; 9.x drops the
        # leading slash ('pkg@version'). 'snapshots' mirrors 'packages' in 9.x.
        entries = {}
        entries.update(data.get("packages", {}) or {})
        entries.update(data.get("snapshots", {}) or {})
        seen = set()
        for key in entries:
            pkg_version = key.lstrip('/')
            # Drop any peer-dependency suffix like '(react@18.0.0)'.
            pkg_version = pkg_version.split('(', 1)[0]
            if '@' not in pkg_version:
                continue
            pkg, version = pkg_version.rsplit('@', 1)
            if not pkg or not version:
                continue
            if (pkg, version) in seen:
                continue
            seen.add((pkg, version))
            vulns = db.check_package(pkg, version)
            for v in vulns:
                v["file"] = "pnpm-lock.yaml"
                findings.append(v)
    except Exception as e:
        logger.error(f"Failed to parse pnpm-lock.yaml: {e}")
    return findings
# EOF
