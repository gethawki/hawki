# File: hawki/core/diagnostics/doctor.py
"""
Doctor orchestrator - runs all diagnostic checks in parallel and aggregates results.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

from .checks.base import CheckResult, DiagnosticCheck
from .reporters.json_reporter import JSONReporter
from .reporters.terminal_reporter import TerminalReporter

logger = logging.getLogger(__name__)

class Doctor:
    """Orchestrates diagnostic checks and reporting."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.checks: List[DiagnosticCheck] = []
        self._discover_checks()

    def _discover_checks(self):
        """Discover and instantiate all check classes."""
        from .checks.ai_providers import AIProvidersCheck
        from .checks.budget_limits import BudgetLimitsCheck
        from .checks.config_storage import ConfigStorageCheck
        from .checks.optional_tools import OptionalToolsCheck
        from .checks.rpc_networks import RPCNetworksCheck
        from .checks.system_deps import SystemDepsCheck

        check_classes = [
            SystemDepsCheck,
            AIProvidersCheck,
            RPCNetworksCheck,
            ConfigStorageCheck,
            OptionalToolsCheck,
            BudgetLimitsCheck,
        ]

        for cls in check_classes:
            try:
                self.checks.append(cls())
            except Exception as e:
                logger.error(f"Failed to instantiate check {cls.__name__}: {e}")

    def run(self, skip_rpc: bool = False, skip_ai: bool = False,
            verbose: bool = False, fix: bool = False) -> Dict[str, Any]:
        """
        Run all checks and return aggregated results.
        """
        results = []
        critical_failures = 0
        warnings = 0
        passed = 0

        # Filter checks based on flags
        checks_to_run = self.checks
        if skip_rpc:
            checks_to_run = [c for c in checks_to_run if c.category != "network"]
        if skip_ai:
            checks_to_run = [c for c in checks_to_run if c.category != "ai"]

        # Checks are independent and mostly I/O bound (network RPC probes,
        # subprocess version calls), so run them concurrently in a thread pool.
        # Results are collected back into the original check order.
        def _run_one(check: DiagnosticCheck) -> CheckResult:
            try:
                start = time.time()
                result = check.run(self.config)
                result.duration_ms = (time.time() - start) * 1000
                return result
            except Exception as e:
                logger.error(f"Check {check.name} failed with exception: {e}")
                return CheckResult(
                    name=check.name,
                    status="fail",
                    message=f"Check crashed: {str(e)}",
                    fix="Report this issue to the Hawk-i developers.",
                )

        if checks_to_run:
            max_workers = min(len(checks_to_run), 8)
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                results = list(pool.map(_run_one, checks_to_run))

        for result in results:
            if result.status == "fail":
                critical_failures += 1
            elif result.status == "warn":
                warnings += 1
            else:
                passed += 1

        # Determine overall status
        status = "pass"
        if critical_failures > 0:
            status = "critical"
        elif warnings > 0:
            status = "warning"

        summary = {
            "status": status,
            "critical": critical_failures,
            "warnings": warnings,
            "passed": passed,
            "total": len(results),
            "checks": [r.to_dict() for r in results],
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        return summary

    def run_sync(self, skip_rpc: bool = False, skip_ai: bool = False,
                 verbose: bool = False, fix: bool = False) -> Dict[str, Any]:
        """Synchronous wrapper for run()."""
        return self.run(skip_rpc, skip_ai, verbose, fix)

    def report_terminal(self, summary: Dict[str, Any]) -> None:
        """Print a terminal report."""
        reporter = TerminalReporter()
        reporter.report(summary)

    def report_json(self, summary: Dict[str, Any]) -> str:
        """Generate a JSON report."""
        reporter = JSONReporter()
        return reporter.report(summary)
# EOF
