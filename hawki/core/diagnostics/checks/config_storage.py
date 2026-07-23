# File: hawki/core/diagnostics/checks/config_storage.py
"""
Check configuration and storage.
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from .base import CheckResult, DiagnosticCheck


class ConfigStorageCheck(DiagnosticCheck):
    """Validate config.yaml and check storage permissions."""

    @property
    def name(self) -> str:
        return "config_storage"

    @property
    def category(self) -> str:
        return "config"

    def run(self, config: Optional[Dict[str, Any]] = None) -> CheckResult:
        details = {}
        failures = []
        warnings = []

        # Check ~/.hawki directory
        hawki_dir = Path.home() / ".hawki"
        if not hawki_dir.exists():
            try:
                hawki_dir.mkdir(parents=True, exist_ok=True)
                details["hawki_dir"] = {"status": "ok", "message": "Created ~/.hawki directory"}
            except Exception as e:
                details["hawki_dir"] = {"status": "fail", "message": str(e)}
                failures.append("hawki_dir")
        else:
            # Check write permissions
            if os.access(hawki_dir, os.W_OK):
                details["hawki_dir"] = {"status": "ok", "message": "~/.hawki exists and is writable"}
            else:
                details["hawki_dir"] = {"status": "warn", "message": "~/.hawki exists but is not writable"}
                warnings.append("hawki_dir")

        # Check config.yaml
        config_path = hawki_dir / "config.yaml"
        if config_path.exists():
            try:
                with open(config_path) as f:
                    data = yaml.safe_load(f)
                if data is None:
                    data = {}
                details["config.yaml"] = {"status": "ok", "message": f"Valid YAML with {len(data)} top-level keys"}
            except yaml.YAMLError as e:
                details["config.yaml"] = {"status": "fail", "message": f"Invalid YAML: {e}"}
                failures.append("config.yaml")
            except Exception as e:
                details["config.yaml"] = {"status": "fail", "message": str(e)}
                failures.append("config.yaml")
        else:
            details["config.yaml"] = {"status": "ok", "message": "config.yaml not found (optional)"}

        # Check registry
        registry_path = hawki_dir / "scanned_registry.json"
        if registry_path.exists():
            import json
            try:
                with open(registry_path) as f:
                    data = json.load(f)
                entries = data.get("entries", [])
                details["registry"] = {"status": "ok", "message": f"Registry has {len(entries)} entries"}
            except Exception as e:
                details["registry"] = {"status": "warn", "message": f"Registry read error: {e}"}
                warnings.append("registry")

        if failures:
            return CheckResult(
                name=self.name,
                status="fail",
                message=f"Configuration issues: {', '.join(failures)}",
                fix="Check file permissions and YAML syntax.",
                details=details,
            )

        if warnings:
            return CheckResult(
                name=self.name,
                status="warn",
                message=f"Configuration warnings: {', '.join(warnings)}",
                details=details,
            )

        return CheckResult(
            name=self.name,
            status="pass",
            message="Configuration and storage are healthy.",
            details=details,
        )

    def is_critical(self) -> bool:
        return True
# EOF
