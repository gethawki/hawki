# --------------------
# File: tests/sandbox/test_sandbox_manager.py
# --------------------
import unittest
from pathlib import Path
from unittest.mock import patch

from hawki.core.exploit_sandbox.sandbox_manager import SandboxManager


class TestSandboxManager(unittest.TestCase):
    @patch("hawki.core.exploit_sandbox.sandbox_manager.DockerConfig")
    @patch("hawki.core.exploit_sandbox.sandbox_manager.docker.from_env")
    def test_discover_scripts(self, mock_docker, mock_docker_cfg):
        # Create a temporary attack_scripts dir with a dummy script
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            scripts_dir = Path(tmpdir) / "attack_scripts"
            scripts_dir.mkdir()
            (scripts_dir / "test_script.py").touch()
            (scripts_dir / "__init__.py").touch()

            manager = SandboxManager(Path("/fake/repo"), attack_scripts_dir=scripts_dir)
            scripts = manager._discover_attack_scripts()
            self.assertEqual(len(scripts), 1)
            self.assertEqual(scripts[0].name, "test_script.py")

    # Additional tests would mock container interactions
    # For brevity, we'll skip heavy Docker mocking here.

if __name__ == "__main__":
    unittest.main()