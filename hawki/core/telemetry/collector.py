# --------------------
# File: hawki/core/telemetry/collector.py
# --------------------
"""
Metrics collector - gathers anonymous usage data after a scan.
"""

import logging
import platform
from datetime import datetime
from typing import Any, Dict, Optional

from .store import MetricsStore

logger = logging.getLogger(__name__)

class MetricsCollector:
    """Collects anonymous metrics from a scan."""

    def __init__(self, store: Optional[MetricsStore] = None):
        self.store = store or MetricsStore()

    def collect(
        self,
        scan_metadata: Dict[str, Any],
        findings: Dict[str, int],
        simulation_success_rate: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Gather metrics from a scan.

        Args:
            scan_metadata: Contains ai_enabled, sandbox_enabled, mode, version.
            findings: Dict with severity counts.
            simulation_success_rate: Optional float 0-1.

        Returns:
            A metrics dictionary (anonymous).
        """
        metrics = {
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d"),  # day only for privacy
            "version": scan_metadata.get("version", "unknown"),
            "mode": scan_metadata.get("mode", "minimal"),
            "ai_enabled": scan_metadata.get("ai_enabled", False),
            "sandbox_enabled": scan_metadata.get("sandbox_enabled", False),
            "findings": findings,
            "simulation_success_rate": simulation_success_rate,
            "platform": platform.system(),  # e.g., Linux, Windows, Darwin
        }
        # Store locally
        self.store.append(metrics)
        logger.debug("Collected telemetry metrics")
        return metrics

    def collect_from_scan(self, scan_metadata: Dict[str, Any], repo_data: Dict[str, Any], findings: list) -> Dict[str, Any]:
        """
        Convenience method to collect from scan outputs.
        """
        # Count findings by severity
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in findings:
            sev = f.get("severity", "Low").capitalize()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["Low"] += 1

        # Compute simulation success rate if applicable
        sim_rate = None
        if scan_metadata.get("sandbox_enabled") and "sandbox_results" in repo_data:
            results = repo_data["sandbox_results"]
            if results:
                successful = sum(1 for r in results if r.get("success"))
                sim_rate = successful / len(results)

        return self.collect(scan_metadata, severity_counts, sim_rate)
# EOF
