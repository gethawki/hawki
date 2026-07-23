# File: hawki/core/diagnostics/reporters/json_reporter.py
"""
JSON reporter for doctor output (CI/CD integration).
"""

import json
from typing import Any, Dict


class JSONReporter:
    """Render doctor results in JSON format."""

    def report(self, summary: Dict[str, Any]) -> str:
        return json.dumps(summary, indent=2)
# EOF
