# File: hawki/core/deep/executor/code_generator.py
"""
Generate exploit code from an attack plan using LLM.
Supports both Hardhat (JS) and Foundry (Solidity) formats.
"""

import json
import logging
from pathlib import Path
from typing import Optional

from ...ai_engine.lite_llm_adapter import LiteLLMAdapter

logger = logging.getLogger(__name__)

class CodeGenerator:
    def __init__(self, model: str, api_key: Optional[str] = None,
                 prompts_dir: Optional[Path] = None,
                 poc_format: str = "hardhat"):  # NEW: 'hardhat' or 'foundry'
        self.llm = LiteLLMAdapter(model=model, api_key=api_key)
        if prompts_dir is None:
            prompts_dir = Path(__file__).parent.parent / "prompts"
        self.poc_format = poc_format
        if poc_format == "foundry":
            self.prompt_path = prompts_dir / "exploit_code_foundry.txt"
        else:
            self.prompt_path = prompts_dir / "exploit_code.txt"
        self._load_prompt()

    def _load_prompt(self):
        if not self.prompt_path.exists():
            raise FileNotFoundError(f"Prompt file not found: {self.prompt_path}")
        with open(self.prompt_path) as f:
            self.prompt_template = f.read()

    def generate(self, plan, target_code_snippet: str) -> Optional[str]:
        """Generate exploit script in the configured format."""
        plan_json = json.dumps(plan.parameters, indent=2)
        # Targeted replacement, not str.format: the prompt and the injected
        # JSON/code contain literal braces that would break str.format.
        prompt = (
            self.prompt_template
            .replace("{plan_json}", plan_json)
            .replace("{target_code_snippet}", target_code_snippet)
        )
        response = self.llm.complete(
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=3000
        )
        if not response:
            return None
        # Clean up code fences
        code = response.strip()
        if code.startswith("```javascript") or code.startswith("```js"):
            code = code.split("\n", 1)[1]
        if code.startswith("```solidity") or code.startswith("```sol"):
            code = code.split("\n", 1)[1]
        if code.startswith("```"):
            code = code[3:]
        if code.endswith("```"):
            code = code[:-3]
        code = code.strip()
        return code

# EOF