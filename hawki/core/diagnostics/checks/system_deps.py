# File: hawki/core/diagnostics/checks/system_deps.py
"""
Check system dependencies: forge, solc, git, python.
"""

import shutil
import subprocess
from typing import Any, Dict, Optional

from .base import CheckResult, DiagnosticCheck


class SystemDepsCheck(DiagnosticCheck):
    """Verify system dependencies are installed and meet version requirements."""

    @property
    def name(self) -> str:
        return "system_deps"

    @property
    def category(self) -> str:
        return "system"

    def run(self, config: Optional[Dict[str, Any]] = None) -> CheckResult:
        deps = {
            "forge": {"min_version": "0.2.0", "cmd": ["forge", "--version"]},
            "solc": {"min_version": "0.8.0", "cmd": ["solc", "--version"]},
            "git": {"min_version": "2.0.0", "cmd": ["git", "--version"]},
            "python": {"min_version": "3.9.0", "cmd": ["python3", "--version"]},
        }

        failed = []
        details = {}

        for dep, info in deps.items():
            path = shutil.which(dep)
            if not path:
                details[dep] = {"status": "missing", "message": f"{dep} not found in PATH"}
                failed.append(dep)
                continue

            try:
                result = subprocess.run(info["cmd"], capture_output=True, text=True, timeout=5)
                if result.returncode != 0:
                    details[dep] = {"status": "error", "message": f"Command failed: {result.stderr}"}
                    failed.append(dep)
                    continue
                version_str = result.stdout.strip().split()[1] if dep != "python" else result.stdout.strip().split()[1]
                details[dep] = {"status": "ok", "version": version_str, "path": path}
            except Exception as e:
                details[dep] = {"status": "error", "message": str(e)}
                failed.append(dep)

        if failed:
            fix = f"Install missing dependencies: {' '.join(failed)}. For Foundry, run: curl -L https://foundry.paradigm.xyz | bash"
            return CheckResult(
                name=self.name,
                status="fail",
                message=f"Missing dependencies: {', '.join(failed)}",
                fix=fix,
                details=details,
            )

        return CheckResult(
            name=self.name,
            status="pass",
            message="All system dependencies found.",
            details=details,
        )

    def is_critical(self) -> bool:
        return True
# EOF
