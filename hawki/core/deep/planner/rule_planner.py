# File: hawki/core/deep/planner/rule_planner.py
"""
Rule-based planner: iterates over attack scripts in the sandbox directory.
"""

import hashlib
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from .base import AttackPlan, Planner

logger = logging.getLogger(__name__)

class RulePlanner(Planner):
    """Planner that uses existing attack scripts from exploit_sandbox/attack_scripts/."""

    def __init__(self, attack_scripts_dir: Optional[Path] = None):
        if attack_scripts_dir is None:
            attack_scripts_dir = Path(__file__).parent.parent.parent / "exploit_sandbox" / "attack_scripts"
        self.scripts_dir = attack_scripts_dir
        self._script_paths: list[Path] = []
        self._refresh_scripts()

    def _refresh_scripts(self):
        """Discover all .py attack scripts (exclude __init__.py)."""
        if not self.scripts_dir.exists():
            logger.warning(f"Attack scripts directory not found: {self.scripts_dir}")
            self._script_paths = []
            return
        self._script_paths = [p for p in self.scripts_dir.glob("*.py") if p.name != "__init__.py"]
        logger.info(f"Discovered {len(self._script_paths)} attack scripts")

    def _generate_signature(self, script_path: Path, parameters: Dict[str, Any] = None) -> str:
        """Create a unique signature for an attack (script name + parameters)."""
        key = script_path.name
        if parameters:
            key += ":" + hashlib.md5(str(sorted(parameters.items())).encode()).hexdigest()
        return key

    def next_attack(self, memory, goal: str, force: bool = False) -> Optional[AttackPlan]:
        """Return the next rule-based attack that hasn't been attempted (unless force)."""
        for script in self._script_paths:
            sig = self._generate_signature(script)
            if not force and memory.has_attempted(sig):
                logger.debug(f"Skipping already attempted attack: {script.name}")
                continue
            plan = AttackPlan(
                plan_type="rule",
                rule_name=script.stem,
                signature=sig,
                parameters={},
                description=f"Rule-based attack: {script.name}"
            )
            logger.info(f"Selected rule attack: {script.name}")
            return plan
        return None

# EOF