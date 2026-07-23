# File: hawki/core/formal/smtchecker.py
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import Verifier

# solc's SMTChecker reports safety-property violations as warnings whose text
# names the target. Keys are matched case-insensitively against the warning
# body; values are the severity we assign.
_TARGET_SEVERITY = {
    "assertion": "High",
    "overflow": "Medium",
    "underflow": "Medium",
    "division by zero": "Medium",
    "out of bounds": "Medium",
    "insufficient funds": "Medium",
    "pop": "Low",
}

# Phrases solc emits when no SMT/Horn solver backend is available. Without a
# solver the checker can report nothing, so we surface that instead of silently
# returning zero findings.
_NO_SOLVER_MARKERS = (
    "but it is not available",
    "no horn solver was found",
    "no smt solver was found",
)


def _find_solc() -> Optional[str]:
    """Locate the solc binary. Prefer PATH, then fall back to a solc that lives
    next to the running interpreter (covers invoking the venv python by absolute
    path without activating it, which leaves the venv bin dir off PATH)."""
    found = shutil.which("solc")
    if found:
        return found
    candidate = Path(sys.executable).parent / "solc"
    if candidate.exists() and os.access(candidate, os.X_OK):
        return str(candidate)
    return None


def _z3_lib_dir() -> Optional[str]:
    """Locate the z3 shared library shipped with the z3-solver package, so the
    solc subprocess can load it even when the system has no system-wide z3.

    Resolve the package location without executing ``import z3``: the wheel's
    __init__ can fail to run for reasons unrelated to the shared library being
    present (for example a missing pkg_resources/setuptools), yet the libz3.so
    that solc dlopens sits right next to it and is all we need."""
    import importlib.util

    try:
        spec = importlib.util.find_spec("z3")
    except Exception:
        spec = None
    if spec is None or not spec.origin:
        return None
    lib_dir = os.path.join(os.path.dirname(spec.origin), "lib")
    if os.path.isdir(lib_dir):
        return lib_dir
    return None


class SMTCheckerVerifier(Verifier):
    def verify(self, source_path: Path, contract_name: str = None) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        solc = _find_solc()
        if solc is None:
            return [{
                "title": "solc not found",
                "severity": "Info",
                "description": "The Solidity compiler (solc) is required for SMTChecker. Install it via solc-select or your package manager.",
                "file": str(source_path),
                "line": 0,
            }]

        # Make the z3 backend discoverable if it was installed as a Python wheel.
        env = os.environ.copy()
        lib_dir = _z3_lib_dir()
        if lib_dir:
            existing = env.get("LD_LIBRARY_PATH", "")
            env["LD_LIBRARY_PATH"] = lib_dir + (os.pathsep + existing if existing else "")

        cmd = [
            solc,
            "--model-checker-engine", "all",
            "--model-checker-targets", "assert,underflow,overflow,divByZero,balance,outOfBounds",
            str(source_path),
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180, env=env)
        except subprocess.TimeoutExpired:
            return [{
                "title": "SMTChecker timeout",
                "severity": "Info",
                "description": "Analysis exceeded 180 seconds. Consider narrowing the targets or contract.",
                "file": str(source_path),
                "line": 0,
            }]
        except Exception as e:  # pragma: no cover - defensive
            return [{
                "title": "SMTChecker error",
                "severity": "Info",
                "description": str(e),
                "file": str(source_path),
                "line": 0,
            }]

        output = proc.stdout + proc.stderr
        lower_output = output.lower()

        if any(marker in lower_output for marker in _NO_SOLVER_MARKERS):
            return [{
                "title": "SMTChecker solver unavailable",
                "severity": "Info",
                "description": (
                    "No SMT solver backend was found, so no properties could be checked. "
                    "Install z3 (for example 'pip install z3-solver') and re-run."
                ),
                "file": str(source_path),
                "line": 0,
            }]

        # Split the compiler output into per-warning blocks. Each block runs from
        # a "Warning:" (or "Error:") header until the next header, capturing the
        # counterexample and the source-location pointer that follow.
        blocks = re.split(r'\n(?=Warning:|Error:)', output)
        for block in blocks:
            stripped = block.strip()
            if not (stripped.startswith("Warning:") or stripped.startswith("Error:")):
                continue
            lower_block = stripped.lower()

            severity = None
            for keyword, sev in _TARGET_SEVERITY.items():
                if keyword in lower_block:
                    severity = sev
                    break
            if severity is None:
                # Not a safety-property finding (e.g. license or pragma notices).
                continue

            # Pull the source line from solc's "--> file:line:col" pointer.
            line_no = 0
            loc = re.search(r'-->\s+\S+?:(\d+):\d+', stripped)
            if loc:
                line_no = int(loc.group(1))

            first_line = stripped.split('\n', 1)[0]
            first_line = re.sub(r'^(Warning|Error):\s*', '', first_line).strip()

            findings.append({
                "title": f"SMTChecker: {first_line[:120]}",
                "severity": severity,
                "description": stripped[:600],
                "file": str(source_path),
                "line": line_no,
            })

        return findings
# EOF
