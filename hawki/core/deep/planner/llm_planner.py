# File: hawki/core/deep/planner/llm_planner.py
"""
LLM-based planner for novel attack generation.
Uses LiteLLM to generate attack plans based on repo context and memory.
"""

import json
import logging
from pathlib import Path
from typing import Optional

from ...ai_engine.lite_llm_adapter import LiteLLMAdapter
from .base import AttackPlan, Planner

logger = logging.getLogger(__name__)

class LLMPlanner(Planner):
    """Invent novel attacks using an LLM."""

    def __init__(self, model: str, api_key: Optional[str] = None,
                 prompts_dir: Optional[Path] = None):
        self.model = model
        self.api_key = api_key
        self.llm = LiteLLMAdapter(model=model, api_key=api_key)
        if prompts_dir is None:
            prompts_dir = Path(__file__).parent.parent / "prompts"
        self.novel_prompt_path = prompts_dir / "novel_attack.txt"
        self._load_prompt()

    def _load_prompt(self):
        if not self.novel_prompt_path.exists():
            raise FileNotFoundError(f"Prompt file not found: {self.novel_prompt_path}")
        with open(self.novel_prompt_path) as f:
            self.prompt_template = f.read()

    def _build_context(self, memory, goal: str, repo_summary: str) -> str:
        """Build the prompt context from memory and repo."""
        recent = memory.get_recent(limit=10)
        memory_summary = json.dumps(recent, indent=2) if recent else "No previous attempts."
        # Use targeted replacement rather than str.format: the prompt contains a
        # literal JSON schema whose braces would otherwise be parsed as fields.
        context = (
            self.prompt_template
            .replace("{repo_summary}", repo_summary)
            .replace("{goal}", goal)
            .replace("{memory_summary}", memory_summary)
        )
        return context

    def _parse_plan(self, llm_response: str) -> Optional[AttackPlan]:
        """Extract JSON from LLM response and create AttackPlan."""
        try:
            # Strip markdown fences if present
            cleaned = llm_response.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            if cleaned.startswith("```"):
                cleaned = cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            cleaned = cleaned.strip()
            data = json.loads(cleaned)
            # Validate required fields
            required = ["name", "description", "steps"]
            for field in required:
                if field not in data:
                    logger.error(f"Missing required field '{field}' in LLM response")
                    return None
            # Create a signature from the plan name
            signature = f"novel:{data['name']}"
            plan = AttackPlan(
                plan_type="novel",
                signature=signature,
                parameters={
                    "name": data["name"],
                    "description": data["description"],
                    "vulnerability_type": data.get("vulnerability_type", "unknown"),
                    "steps": data["steps"],
                    "expected_impact": data.get("expected_impact", "")
                },
                description=data["description"]
            )
            return plan
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM JSON: {e}\nResponse: {llm_response[:500]}")
            return None

    def next_attack(self, memory, goal: str, force: bool = False,
                    repo_summary: str = "") -> Optional[AttackPlan]:
        """Generate a novel attack plan using LLM."""
        if not self.llm:
            logger.warning("LLMPlanner has no LLM client configured")
            return None

        context = self._build_context(memory, goal, repo_summary)
        response = self.llm.complete(
            messages=[{"role": "user", "content": context}],
            temperature=0.7,
            max_tokens=2000
        )
        if not response:
            logger.error("LLM returned empty response")
            return None

        plan = self._parse_plan(response)
        if plan:
            # Estimate token usage (heuristic: 1 token ≈ 4 chars)
            estimated_tokens = (len(context) + len(response)) // 4
            plan.parameters["estimated_tokens"] = estimated_tokens
            logger.info(f"Generated novel attack: {plan.parameters['name']}")
        return plan

# EOF