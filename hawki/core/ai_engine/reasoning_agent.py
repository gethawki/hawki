# --------------------
# File: hawki/core/ai_engine/reasoning_agent.py
# --------------------
"""
AI reasoning agent that uses the orchestrator to analyse contracts.
Produces findings in the same format as static rules.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional

from .llm_orchestrator import LLMOrchestrator

logger = logging.getLogger(__name__)

class ReasoningAgent:
    """Applies AI analysis to contract data."""

    def __init__(self, orchestrator: Optional[LLMOrchestrator] = None):
        self.orchestrator = orchestrator or LLMOrchestrator()

    def analyse_contracts(
        self, contract_data: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Run AI analysis on each contract and collect findings.
        Uses the 'vuln_analysis_prompt' template.
        """
        findings = []
        for contract in contract_data:
            # Prepare context: contract name, source, functions, etc.
            context = {
                "contract_name": contract.get("name", "unknown"),
                "source_code": contract.get("source", ""),
                "functions": contract.get("functions", []),
                "state_variables": contract.get("state_variables", []),
            }
            result = self.orchestrator.analyze(
                template_name="vuln_analysis_prompt",
                **context,
            )
            if result:
                # Models are inconsistent: some return {"findings": [...]},
                # some {"vulnerabilities": [...]}, some a bare list, some a
                # single finding dict. Normalise all of these to a list.
                if isinstance(result, list):
                    ai_findings = result
                elif isinstance(result, dict):
                    ai_findings = (
                        result.get("findings")
                        or result.get("vulnerabilities")
                        or []
                    )
                    # A single finding returned as a bare dict.
                    if not ai_findings and ("title" in result or "severity" in result):
                        ai_findings = [result]
                else:
                    ai_findings = []

                for f in ai_findings:
                    if isinstance(f, str):
                        f = {"title": f}
                    if not isinstance(f, dict):
                        continue
                    # Models label fields inconsistently. Map common aliases to
                    # the standard finding schema before filling defaults.
                    if not f.get("title"):
                        for k in ("vulnerability", "name", "issue", "summary"):
                            if f.get(k):
                                f["title"] = f[k]
                                break
                    if not f.get("explanation") and f.get("description"):
                        f["explanation"] = f["description"]
                    if not f.get("impact"):
                        for k in ("impact", "consequence", "effect"):
                            if f.get(k):
                                f["impact"] = f[k]
                                break
                    if not f.get("file") or f.get("file") == "unknown":
                        for k in ("location", "contract", "contract_name"):
                            if f.get(k):
                                f["file"] = f[k]
                                break
                    if not f.get("fix_snippet"):
                        for k in ("fix_snippet", "fix", "recommendation", "remediation", "mitigation"):
                            if f.get(k):
                                f["fix_snippet"] = f[k]
                                break
                    # Coerce line to a usable int, accepting aliases and "L42".
                    if not isinstance(f.get("line"), int) or isinstance(f.get("line"), bool):
                        f["line"] = self._coerce_line(
                            f.get("line") or f.get("line_number") or f.get("lineNumber")
                        )
                    # Last resort: derive a title from the first sentence of the
                    # explanation (do not split on member access like tx.origin).
                    if not f.get("title") and f.get("explanation"):
                        expl = str(f["explanation"])
                        m = re.search(r"[.!?](?:\s|$)", expl)
                        first = (expl[: m.start()] if m else expl).strip()
                        f["title"] = (first or "AI-identified issue")[:120]
                    # Ensure the standard finding fields so AI findings flow
                    # through scoring and reporting like static ones.
                    f.setdefault("title", "AI-identified issue")
                    f.setdefault("severity", "Medium")
                    f.setdefault("file", context["contract_name"])
                    f.setdefault("line", 0)
                    f.setdefault("vulnerable_snippet", "")
                    f["rule"] = "AI_Reasoning"
                    f["source"] = "ai"
                    findings.append(f)
            else:
                logger.debug(f"No AI result for contract {contract.get('name')}")

        return findings

    @staticmethod
    def _coerce_line(value: Any) -> int:
        """Best-effort convert a model-supplied line value to a positive int."""
        if isinstance(value, bool):
            return 0
        if isinstance(value, int):
            return value if value > 0 else 0
        match = re.search(r"\d+", str(value or ""))
        if match:
            try:
                n = int(match.group())
                return n if n > 0 else 0
            except ValueError:
                return 0
        return 0

    def score_contract(self, contract: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Generate a risk score for a single contract.
        Uses 'risk_scoring_prompt' template.
        """
        context = {
            "contract_name": contract.get("name", "unknown"),
            "source_code": contract.get("source", ""),
        }
        return self.orchestrator.analyze(
            template_name="risk_scoring_prompt",
            **context,
        )

    def general_query(self, query: str, contract_context: Optional[Dict] = None) -> Optional[str]:
        """
        General purpose query using 'general_contract_prompt'.
        Returns raw text response.
        """
        context = {
            "user_query": query,
            "contract_context": json.dumps(contract_context) if contract_context else "None",
        }
        result = self.orchestrator.analyze(
            template_name="general_contract_prompt",
            **context,
        )
        if result and "raw_response" in result:
            return result["raw_response"]
        return None

# EOF: hawki/core/ai_engine/reasoning_agent.py