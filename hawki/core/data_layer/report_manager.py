# File: hawki/core/data_layer/report_manager.py
"""
Handles persistence of scan results, including sandbox outcomes.
Now supports audit-grade reporting via ReportGeneratorV2 with all modules and styles.
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .reporting.report_generator_v2 import ReportGeneratorV2
from .reporting.scoring_engine import normalize_severity

logger = logging.getLogger(__name__)

class ReportManager:
    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = output_dir or Path.cwd() / "hawki_reports"
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            writable = os.access(self.output_dir, os.W_OK)
        except OSError:
            writable = False
        if not writable:
            # A common Docker footgun: the mounted output volume is owned by a
            # different uid than the container user, or mounted read-only. Fail
            # with an actionable message instead of an opaque traceback deep in
            # report rendering.
            raise RuntimeError(
                f"Cannot write reports to {self.output_dir}: permission denied. "
                "If running in Docker, mount a writable output directory and run as your "
                "own user, e.g. 'docker run --user $(id -u):$(id -g) -v $(pwd):/work -w /work ...', "
                "or choose a different --output-dir."
            )
        self.v2_generator = ReportGeneratorV2(self.output_dir)

    def save_findings(self, findings: List[Dict[str, Any]], repo_info: Dict[str, Any]) -> Path:
        """Legacy method: save findings as JSON only."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        report_file = self.output_dir / f"report_{timestamp}.json"

        report_data = {
            "scan_timestamp": timestamp,
            "repository": {k: v for k, v in repo_info.items() if k != "contracts"},
            "findings": findings,
            "summary": {
                "total_findings": len(findings),
                "severity_counts": self._count_severities(findings),
            }
        }

        if "sandbox_results" in repo_info:
            report_data["sandbox_results"] = repo_info["sandbox_results"]
            report_data["summary"]["sandbox_scripts_run"] = len(repo_info["sandbox_results"])
            report_data["summary"]["sandbox_successful"] = sum(
                1 for r in repo_info["sandbox_results"] if r.get("success")
            )

        with open(report_file, "w") as f:
            json.dump(report_data, f, indent=2)

        logger.info(f"Legacy report saved to {report_file}")
        return report_file

    def generate_report(
        self,
        findings: List[Dict[str, Any]],
        repo_data: Dict[str, Any],
        scan_metadata: Dict[str, Any],
        output_format: str = "md",
        style: str = "audit",  # NEW: 'audit' or 'immunefi'
        # Extra module results (forwarded to v2)
        bytecode_result: Optional[Dict[str, Any]] = None,
        dependency_findings: Optional[List[Dict[str, Any]]] = None,
        upgrade_findings: Optional[List[Dict[str, Any]]] = None,
        formal_findings: Optional[List[Dict[str, Any]]] = None,
        deep_agent_stats: Optional[Dict[str, Any]] = None,
        deep_agent_timeline: Optional[List[Dict[str, Any]]] = None,
    ) -> Path:
        """Generate an audit-grade report with full module support and style option."""
        return self.v2_generator.generate(
            repo_data=repo_data,
            findings=findings,
            scan_metadata=scan_metadata,
            output_format=output_format,
            style=style,  # NEW
            bytecode_result=bytecode_result,
            dependency_findings=dependency_findings,
            upgrade_findings=upgrade_findings,
            formal_findings=formal_findings,
            deep_agent_stats=deep_agent_stats,
            deep_agent_timeline=deep_agent_timeline,
        )

    def _count_severities(self, findings: List[Dict]) -> Dict[str, int]:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            sev = normalize_severity(f.get("severity"))
            counts[sev] = counts.get(sev, 0) + 1
        return counts

# EOF