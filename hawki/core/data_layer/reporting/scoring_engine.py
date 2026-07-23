# File: hawki/core/data_layer/reporting/scoring_engine.py
"""
Security Score Engine - v1.0.0 with extended weights for all modules.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def normalize_severity(value: Any) -> str:
    """Canonical Title-case severity (Critical/High/Medium/Low/Info).

    Kept in sync with the rules layer so scoring, counting, and coloring all
    agree on one spelling regardless of what casing a finding arrived with.
    """
    key = str(value or "").strip().lower()
    aliases = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "moderate": "Medium",
        "low": "Low",
        "info": "Info",
        "informational": "Info",
        "note": "Info",
        "none": "Info",
        "": "Info",
    }
    return aliases.get(key, key.capitalize() if key else "Info")


class SecurityScoreEngine:
    """Computes security score from all available findings."""

    # Static rule severity weights (deductions from 100)
    SEVERITY_WEIGHTS = {
        "Critical": 15,
        "High": 8,
        "Medium": 4,
        "Low": 1,
        "Info": 0,
    }

    # Additional penalties
    SIMULATION_PENALTY = 5               # per successfully reproduced exploit
    BYTECODE_MISMATCH_PENALTY = 20       # one-time, if mismatch
    DEPENDENCY_VULN_PENALTY = 10         # per vulnerable library
    UPGRADE_COLLISION_PENALTY = 15       # per storage collision
    NOVEL_ATTACK_SUCCESS_PENALTY = 10    # per novel attack that succeeded

    CLASSIFICATION_BANDS = [
        (90, 100, "Secure"),
        (75, 89, "Minor Risk"),
        (50, 74, "Moderate Risk"),
        (25, 49, "High Risk"),
        (0, 24, "Critical Risk"),
    ]

    def calculate(
        self,
        findings: List[Dict[str, Any]],
        sandbox_results: Optional[List[Dict[str, Any]]] = None,
        ai_enabled: bool = False,
        # Additional module results
        bytecode_result: Optional[Dict[str, Any]] = None,
        dependency_findings: Optional[List[Dict[str, Any]]] = None,
        upgrade_findings: Optional[List[Dict[str, Any]]] = None,
        formal_findings: Optional[List[Dict[str, Any]]] = None,
        deep_agent_stats: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Calculate score based on all available information.

        Args:
            findings: Static/AI rule findings.
            sandbox_results: Results from exploit simulation.
            ai_enabled: Whether AI was used.
            bytecode_result: Dict from verify_bytecode().
            dependency_findings: List from scan_dependencies().
            upgrade_findings: List from check_upgrade_safety().
            formal_findings: List from formal verifier.
            deep_agent_stats: Stats from memory.get_stats() plus novel_successes.

        Returns:
            Score dict with breakdown.
        """
        base_score = 100
        deductions = {}

        # 1. Severity deductions
        severity_counts = {}
        for f in findings:
            sev = normalize_severity(f.get("severity"))
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        total_severity = 0
        for sev, count in severity_counts.items():
            weight = self.SEVERITY_WEIGHTS.get(sev, 1)
            total_severity += weight * count
            deductions[f"{sev.lower()}_findings"] = count

        # 2. Simulation penalty
        sim_penalty = 0
        if sandbox_results:
            successes = sum(1 for r in sandbox_results if r.get("success"))
            sim_penalty = successes * self.SIMULATION_PENALTY
            if successes:
                deductions["simulation_penalty"] = successes

        # 3. Bytecode mismatch
        bytecode_penalty = 0
        if bytecode_result and not bytecode_result.get("match", True):
            bytecode_penalty = self.BYTECODE_MISMATCH_PENALTY
            deductions["bytecode_mismatch"] = 1

        # 4. Dependency vulnerabilities
        dep_penalty = 0
        if dependency_findings:
            dep_penalty = len(dependency_findings) * self.DEPENDENCY_VULN_PENALTY
            deductions["dependency_vulns"] = len(dependency_findings)

        # 5. Upgrade collisions (only those with "collision" in title)
        upgrade_penalty = 0
        if upgrade_findings:
            collisions = [f for f in upgrade_findings if "collision" in f.get("title", "").lower()]
            upgrade_penalty = len(collisions) * self.UPGRADE_COLLISION_PENALTY
            if collisions:
                deductions["upgrade_collisions"] = len(collisions)

        # 6. Novel attack successes from deep agent
        novel_penalty = 0
        if deep_agent_stats:
            novel_successes = deep_agent_stats.get("novel_successes", 0)
            novel_penalty = novel_successes * self.NOVEL_ATTACK_SUCCESS_PENALTY
            if novel_successes:
                deductions["novel_attack_successes"] = novel_successes

        total_deduction = total_severity + sim_penalty + bytecode_penalty + dep_penalty + upgrade_penalty + novel_penalty
        final_score = max(0, min(100, base_score - total_deduction))

        # Classification
        classification = "Unknown"
        for low, high, label in self.CLASSIFICATION_BANDS:
            if low <= final_score <= high:
                classification = label
                break

        return {
            "score": final_score,
            "classification": classification,
            "deductions": deductions,
            "simulation_used": bool(sandbox_results),
            "ai_used": ai_enabled,
            "bytecode_checked": bytecode_result is not None,
            "deps_checked": dependency_findings is not None,
            "upgrade_checked": upgrade_findings is not None,
            "formal_checked": formal_findings is not None,
            "deep_agent_used": deep_agent_stats is not None,
        }
# EOF
