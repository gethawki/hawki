# File: hawki/core/diagnostics/checks/optional_tools.py
"""
Check for optional tools (slither, mythril).
"""

import shutil
from typing import Any, Dict, Optional

from .base import CheckResult, DiagnosticCheck


class OptionalToolsCheck(DiagnosticCheck):
    """Detect optional security tools."""

    @property
    def name(self) -> str:
        return "optional_tools"

    @property
    def category(self) -> str:
        return "tools"

    def run(self, config: Optional[Dict[str, Any]] = None) -> CheckResult:
        details = {}
        missing = []

        tools = {
            "slither": "pip install slither-analyzer",
            "mythril": "pip install mythril",
            "hevm": "https://github.com/ethereum/hevm",
        }

        for tool, install_cmd in tools.items():
            path = shutil.which(tool)
            if path:
                details[tool] = {"status": "ok", "path": path}
            else:
                details[tool] = {"status": "missing", "install": install_cmd}
                missing.append(tool)

        if missing:
            fix = f"Install optional tools: {', '.join(missing)}. {', '.join(tools[t] for t in missing)}"
            return CheckResult(
                name=self.name,
                status="warn",
                message=f"Optional tools missing: {', '.join(missing)}",
                fix=fix,
                details=details,
            )

        return CheckResult(
            name=self.name,
            status="pass",
            message="Optional tools found.",
            details=details,
        )
# EOF
