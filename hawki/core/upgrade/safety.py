# File: hawki/core/upgrade/safety.py
"""
Upgrade safety checks: proxy-pattern detection, storage-layout collision
detection via solc --storage-layout, and initializer checks.
"""

import json
import logging
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


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

# Proxy fingerprints. Kept deliberately broad; a match only produces an
# informational finding plus a trigger for deeper storage analysis.
_PROXY_PATTERNS = {
    "UUPS": re.compile(r'function\s+upgradeTo(?:AndCall)?\s*\([^)]*\)[^{;]*onlyProxy', re.DOTALL),
    "Transparent": re.compile(r'function\s+upgradeTo(?:AndCall)?\s*\([^)]*\)\s*(?:public|external)'),
    "Beacon": re.compile(r'\bfunction\s+implementation\s*\(\s*\)\s*(?:public|external|view)|IBeacon'),
}

_DELEGATECALL_RE = re.compile(r'\bdelegatecall\s*\(', re.IGNORECASE)


def _run_storage_layout(sol_files: List[Path]) -> str:
    """Run solc --storage-layout over the given files, returning combined output."""
    solc = _find_solc()
    if not solc:
        logger.warning("solc not found on PATH; skipping storage-layout collision detection.")
        return ""
    cmd = [solc, "--storage-layout"] + [str(f) for f in sol_files]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except Exception as e:  # solc missing / timeout
        logger.warning(f"solc --storage-layout failed to run: {e}")
        return ""
    if result.returncode != 0:
        logger.warning(f"solc --storage-layout returned non-zero: {result.stderr[:300]}")
    # solc prints layouts to stdout even alongside warnings on stderr.
    return result.stdout


_SECTION_RE = re.compile(
    r'=======\s+(?P<file>\S+?):(?P<name>[A-Za-z0-9_$]+)\s+=======\s*\n'
    r'Contract Storage Layout:\s*\n(?P<json>\{.*)'
)


def _parse_storage_layouts(output: str) -> Dict[str, Dict[str, Any]]:
    """
    Parse solc --storage-layout text output into
    ``{contract_name: {"file": str, "slots": {slot_int: [(offset, type, label), ...]}}}``.
    """
    layouts: Dict[str, Dict[str, Any]] = {}
    for match in _SECTION_RE.finditer(output):
        name = match.group("name")
        file_path = match.group("file")
        try:
            data = json.loads(match.group("json"))
        except json.JSONDecodeError:
            continue
        slots: Dict[int, List[Tuple[int, str, str]]] = {}
        for entry in data.get("storage", []):
            try:
                slot = int(entry["slot"])
            except (KeyError, ValueError):
                continue
            offset = int(entry.get("offset", 0))
            var_type = entry.get("type", "")
            label = entry.get("label", "")
            slots.setdefault(slot, []).append((offset, var_type, label))
        for slot in slots:
            slots[slot].sort(key=lambda t: t[0])
        layouts[name] = {"file": file_path, "slots": slots}
    return layouts


def _base_name(name: str) -> str:
    """Normalize a contract name to a version-agnostic base (LogicV2 -> Logic)."""
    stripped = re.sub(r'(?:[_]?[vV])?\d+$', '', name)
    return stripped or name


def _slot_signature(entries: List[Tuple[int, str, str]]) -> List[Tuple[int, str]]:
    """Type signature of a slot, ignoring variable names (offset + type only)."""
    return [(offset, var_type) for offset, var_type, _label in entries]


def _compare_layouts(
    old_name: str,
    old: Dict[str, Any],
    new_name: str,
    new: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Detect storage collisions between two versions of the same contract."""
    findings: List[Dict[str, Any]] = []
    old_slots = old["slots"]
    new_slots = new["slots"]
    for slot in sorted(set(old_slots) & set(new_slots)):
        old_sig = _slot_signature(old_slots[slot])
        new_sig = _slot_signature(new_slots[slot])
        if old_sig != new_sig:
            old_desc = ", ".join(f"{t} {l}" for _o, t, l in old_slots[slot])
            new_desc = ", ".join(f"{t} {l}" for _o, t, l in new_slots[slot])
            findings.append({
                "title": f"Storage collision between {old_name} and {new_name}",
                "severity": "High",
                "description": (
                    f"Slot {slot} changed layout across versions: "
                    f"{old_name} holds [{old_desc}] but {new_name} holds [{new_desc}]. "
                    "Reordering or retyping an occupied storage slot corrupts existing state on upgrade."
                ),
                "file": new["file"],
                "line": 1,
            })
    return findings


def check_upgrade_safety(repo_path: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    sol_files = list(repo_path.rglob("*.sol"))
    if not sol_files:
        return findings

    proxy_contracts: List[str] = []

    for sol_file in sol_files:
        try:
            source = sol_file.read_text(encoding="utf-8")
        except Exception:
            continue
        lines = source.split('\n')

        detected = [label for label, pat in _PROXY_PATTERNS.items() if pat.search(source)]
        has_delegatecall = bool(_DELEGATECALL_RE.search(source))
        if detected or has_delegatecall:
            proxy_contracts.append(sol_file.name)
            label = ", ".join(detected) if detected else "delegatecall-based"
            findings.append({
                "title": f"Upgradeable proxy pattern: {label}",
                "severity": "Info",
                "description": f"Contract uses a {label} proxy pattern. Verify storage-layout compatibility before upgrading.",
                "file": str(sol_file),
                "line": 1,
            })

        # Missing initializer in an upgradeable contract.
        if "Initializable" in source or "UUPSUpgradeable" in source:
            if not re.search(r'function\s+initialize\w*\s*\(', source):
                for i, line in enumerate(lines):
                    if "is Initializable" in line or "is UUPSUpgradeable" in line or "Initializable" in line:
                        findings.append({
                            "title": "Missing initializer in upgradeable contract",
                            "severity": "Critical",
                            "description": "Upgradeable contract inherits Initializable/UUPSUpgradeable but declares no initialize function with the initializer modifier.",
                            "file": str(sol_file),
                            "line": i + 1,
                        })
                        break

        # __gap heuristic: state variables declared after the storage gap.
        gap_match = re.search(r'uint256\[(\d+)\]\s+private\s+__gap\s*;', source)
        if gap_match:
            gap_line = source[:gap_match.start()].count('\n') + 1
            after_gap = source[gap_match.end():]
            if re.search(r'^\s*(address|uint\d*|int\d*|bool|mapping|bytes\d*)\s+\w+\s*;', after_gap, re.MULTILINE):
                findings.append({
                    "title": "Storage collision risk: variables after __gap",
                    "severity": "High",
                    "description": "State variables declared after the __gap array can collide with future upgrades. Move new variables before __gap and shrink the gap accordingly.",
                    "file": str(sol_file),
                    "line": gap_line,
                })

    # Storage-layout based collision detection across the whole repo.
    layouts = _parse_storage_layouts(_run_storage_layout(sol_files))
    proxy_names_lower = {n.lower() for n in proxy_contracts}

    # 1) A proxy that occupies its own storage slots collides with the
    #    delegatecall target (safe proxies keep the implementation pointer at a
    #    pseudo-random EIP-1967 slot via assembly, so their layout is empty).
    for name, layout in layouts.items():
        if not layout["slots"]:
            continue
        file_stem = Path(layout["file"]).name.lower()
        looks_proxy = (
            f"{name.lower()}.sol" in proxy_names_lower
            or file_stem in proxy_names_lower
            or "proxy" in name.lower()
        )
        if looks_proxy:
            first_slot = sorted(layout["slots"])[0]
            var_desc = ", ".join(f"{t} {l}" for _o, t, l in layout["slots"][first_slot])
            findings.append({
                "title": f"Storage collision risk: proxy {name} declares state variables",
                "severity": "High",
                "description": (
                    f"Proxy contract {name} occupies storage slot {first_slot} ([{var_desc}]). "
                    "Under delegatecall the implementation writes the same slots, corrupting the proxy's state. "
                    "Store proxy metadata at EIP-1967 slots via assembly instead."
                ),
                "file": layout["file"],
                "line": 1,
            })

    # 2) Compare versioned implementations (LogicV1 vs LogicV2, ...) slot by slot.
    groups: Dict[str, List[str]] = {}
    for name in layouts:
        groups.setdefault(_base_name(name), []).append(name)
    for _base, names in groups.items():
        if len(names) < 2:
            continue
        ordered = sorted(names)
        first = ordered[0]
        for other in ordered[1:]:
            findings.extend(_compare_layouts(first, layouts[first], other, layouts[other]))

    return findings
# EOF
