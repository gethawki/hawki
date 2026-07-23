# --------------------
# File: hawki/core/ai_engine/prompt_manager.py
# --------------------
"""
Loads and manages prompt templates from the prompt_templates directory.
Supports dynamic discovery of new templates.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

class PromptManager:
    """Loads prompt templates from JSON files in the templates directory."""

    def __init__(self, templates_dir: Optional[Path] = None):
        if templates_dir is None:
            templates_dir = Path(__file__).parent / "prompt_templates"
        self.templates_dir = templates_dir
        self.templates: Dict[str, Dict[str, Any]] = {}
        self._load_templates()

    def _load_templates(self) -> None:
        """Scan the directory and load all .json files as templates."""
        if not self.templates_dir.exists():
            logger.warning(f"Prompt templates directory not found: {self.templates_dir}")
            return

        for json_file in self.templates_dir.glob("*.json"):
            try:
                with open(json_file, encoding="utf-8") as f:
                    template = json.load(f)
                # Validate minimal structure
                if "system" in template and "user" in template:
                    self.templates[json_file.stem] = template
                    logger.debug(f"Loaded prompt template: {json_file.stem}")
                else:
                    logger.error(f"Template {json_file.name} missing 'system' or 'user' field")
            except Exception as e:
                logger.error(f"Failed to load template {json_file}: {e}")

    def get_template(self, name: str) -> Optional[Dict[str, Any]]:
        """Retrieve a template by its base name (without .json)."""
        return self.templates.get(name)

    def render(self, name: str, **kwargs) -> Optional[Dict[str, str]]:
        """
        Render a template by replacing placeholders in system and user prompts.
        Placeholders are in {key} format.
        Returns a messages list ready for LitepytestLLM, or None if template not found.
        """
        template = self.get_template(name)
        if not template:
            logger.error(f"Template '{name}' not found")
            return None

        try:
            system = template["system"].format(**kwargs)
            user = template["user"].format(**kwargs)
        except KeyError as e:
            logger.error(f"Missing placeholder {e} in template '{name}'")
            return None
        except Exception as e:
            logger.error(f"Error rendering template '{name}': {e}")
            return None

        return [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]

# EOF: hawki/core/ai_engine/prompt_manager.py