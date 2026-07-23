# File: hawki/core/registry/contract_registry.py
"""
Contract registry to track scanned contracts and avoid duplicates.
"""
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_REGISTRY_PATH = Path.home() / ".hawki" / "scanned_registry.json"

class ContractRegistry:
    def __init__(self, registry_path: Optional[Path] = None):
        self.registry_path = registry_path or DEFAULT_REGISTRY_PATH
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        self.data = self._load()

    def _load(self) -> Dict[str, Any]:
        if not self.registry_path.exists():
            return {"entries": []}
        try:
            with open(self.registry_path) as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load registry: {e}")
            return {"entries": []}

    def _save(self):
        with open(self.registry_path, "w") as f:
            json.dump(self.data, f, indent=2)

    def add(self, address: str, chain: str, repo_hash: Optional[str] = None,
            findings_count: int = 0) -> None:
        """Record a scanned contract."""
        entry = {
            "address": address,
            "chain": chain,
            "first_scanned": datetime.utcnow().isoformat(),
            "last_scanned": datetime.utcnow().isoformat(),
            "scan_count": 1,
            "repo_hash": repo_hash or "",
            "findings_count": findings_count,
        }
        for existing in self.data["entries"]:
            if existing["address"].lower() == address.lower() and existing["chain"] == chain:
                existing["last_scanned"] = datetime.utcnow().isoformat()
                existing["scan_count"] += 1
                existing["findings_count"] = findings_count
                self._save()
                return
        self.data["entries"].append(entry)
        self._save()

    def is_scanned(self, address: str, chain: str, days: int = 30) -> bool:
        """Check if contract was scanned within the given days."""
        for entry in self.data["entries"]:
            if entry["address"].lower() == address.lower() and entry["chain"] == chain:
                last = datetime.fromisoformat(entry["last_scanned"])
                if datetime.utcnow() - last < timedelta(days=days):
                    return True
        return False

    def list_entries(self) -> List[Dict]:
        return self.data["entries"]

    def clear(self):
        self.data = {"entries": []}
        self._save()

    def get_entry(self, address: str, chain: str) -> Optional[Dict]:
        for entry in self.data["entries"]:
            if entry["address"].lower() == address.lower() and entry["chain"] == chain:
                return entry
        return None
# EOF
