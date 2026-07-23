# --------------------
# File: tests/ai/test_prompt_manager.py
# --------------------
import json
import tempfile
import unittest
from pathlib import Path

from hawki.core.ai_engine.prompt_manager import PromptManager


class TestPromptManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.templates_dir = Path(self.temp_dir.name)
        # Create a valid template
        valid = {"system": "test system {var}", "user": "test user {var}"}
        with open(self.templates_dir / "valid.json", "w") as f:
            json.dump(valid, f)
        # Create an invalid template (missing user)
        invalid = {"system": "only system"}
        with open(self.templates_dir / "invalid.json", "w") as f:
            json.dump(invalid, f)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_load_templates(self):
        pm = PromptManager(self.templates_dir)
        self.assertIn("valid", pm.templates)
        self.assertNotIn("invalid", pm.templates)

    def test_render_success(self):
        pm = PromptManager(self.templates_dir)
        messages = pm.render("valid", var="hello")
        self.assertIsNotNone(messages)
        self.assertEqual(len(messages), 2)
        self.assertIn("hello", messages[0]["content"])
        self.assertIn("hello", messages[1]["content"])

    def test_render_missing_placeholder(self):
        pm = PromptManager(self.templates_dir)
        messages = pm.render("valid", wrong="hello")  # missing var
        self.assertIsNone(messages)

if __name__ == "__main__":
    unittest.main()