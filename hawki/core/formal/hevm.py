# File: hawki/core/formal/hevm.py
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from .base import Verifier


def _find_solc():
    """Locate solc: PATH first, then next to the running interpreter."""
    found = shutil.which("solc")
    if found:
        return found
    candidate = Path(sys.executable).parent / "solc"
    if candidate.exists() and os.access(candidate, os.X_OK):
        return str(candidate)
    return None


class HevmVerifier(Verifier):
    def __init__(self):
        self.available = shutil.which("hevm") is not None

    def verify(self, source_path: Path, contract_name: str = None) -> List[Dict[str, Any]]:
        findings = []
        if not self.available:
            findings.append({
                "title": "hevm not installed",
                "severity": "Info",
                "description": "Install hevm from https://github.com/ethereum/hevm",
                "file": str(source_path),
                "line": 0,
            })
            return findings

        # Need to compile to bytecode. Use solc to get bytecode for the contract.
        if not contract_name:
            # Guess the first contract in the file
            # For simplicity, we'll compile all and pick first
            pass

        # Create a temp directory
        with tempfile.TemporaryDirectory():
            # Compile to bytecode
            solc = _find_solc() or "solc"
            compile_cmd = [solc, "--bin", str(source_path)]
            proc = subprocess.run(compile_cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                findings.append({
                    "title": "Compilation failed for hevm",
                    "severity": "Info",
                    "description": proc.stderr[:500],
                    "file": str(source_path),
                    "line": 0,
                })
                return findings
            # Extract bytecode (simplistic: look for hex after "Binary:")
            bytecode = None
            for line in proc.stdout.split('\n'):
                if "Binary:" in line:
                    parts = line.split("Binary:")
                    if len(parts) > 1:
                        bytecode = parts[1].strip()
                        break
            if not bytecode:
                findings.append({
                    "title": "No bytecode found",
                    "severity": "Info",
                    "description": "Could not extract bytecode from compilation output",
                    "file": str(source_path),
                    "line": 0,
                })
                return findings

            # Run hevm symbolic
            hevm_cmd = ["hevm", "symbolic", "--code", bytecode]
            proc = subprocess.run(hevm_cmd, capture_output=True, text=True, timeout=60)
            output = proc.stdout + proc.stderr
            if "counterexample" in output.lower():
                findings.append({
                    "title": "Hevm found counterexample",
                    "severity": "High",
                    "description": "Symbolic execution found a potential violation. Check output for details.",
                    "file": str(source_path),
                    "line": 0,
                })
            elif "all assertions proved" in output.lower():
                pass  # good
            else:
                findings.append({
                    "title": "Hevm analysis incomplete",
                    "severity": "Info",
                    "description": "Hevm did not complete full analysis. Check output.",
                    "file": str(source_path),
                    "line": 0,
                })
        return findings
# EOF
