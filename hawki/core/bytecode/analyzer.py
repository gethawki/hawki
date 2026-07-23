# File: hawki/core/bytecode/analyzer.py
"""
Basic bytecode analysis for deployed contracts without source code.
Detects dangerous opcodes and patterns.
"""

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Opcodes worth flagging when only bytecode is available, keyed by numeric value.
# Severity reflects how much power the opcode hands to a contract.
DANGEROUS_OPCODES = {
    0xF4: ("DELEGATECALL", "High"),
    0xF2: ("CALLCODE", "High"),
    0xFF: ("SELFDESTRUCT", "High"),
    0xF0: ("CREATE", "Medium"),
    0xF5: ("CREATE2", "Medium"),
    0xF1: ("CALL", "Medium"),
}

# PUSH1 (0x60) through PUSH32 (0x7f) carry inline immediate data that must be
# skipped so its bytes are not misread as opcodes.
_PUSH1 = 0x60
_PUSH32 = 0x7F

_OPCODE_IMPACT = {
    "DELEGATECALL": "Executes external code in this contract's storage context; a malicious or upgradeable target can take over state.",
    "CALLCODE": "Deprecated variant of DELEGATECALL with the same storage-hijack risk.",
    "SELFDESTRUCT": "Can remove the contract and forward its balance, potentially bricking dependent systems.",
    "CREATE": "Deploys new contracts at runtime, which can hide additional logic.",
    "CREATE2": "Deploys contracts at deterministic addresses, enabling address-reuse and metamorphic-contract tricks.",
    "CALL": "Makes external calls that may move value or trigger reentrancy.",
}


def _iter_opcodes(bytecode: bytes):
    """Yield (offset, opcode) pairs, skipping PUSH immediate data."""
    i = 0
    n = len(bytecode)
    while i < n:
        op = bytecode[i]
        if _PUSH1 <= op <= _PUSH32:
            # data length is opcode value minus (PUSH1 - 1)
            i += 1 + (op - _PUSH1 + 1)
            continue
        yield i, op
        i += 1


def analyze_bytecode(bytecode_hex: str) -> List[Dict[str, Any]]:
    """
    Analyze bytecode hex string for dangerous opcodes and patterns.
    Returns a list of findings.
    """
    findings = []
    if not bytecode_hex or len(bytecode_hex) < 2:
        return findings

    # Remove '0x' prefix if present
    if bytecode_hex.startswith("0x") or bytecode_hex.startswith("0X"):
        bytecode_hex = bytecode_hex[2:]

    # Convert to bytes
    try:
        bytecode = bytes.fromhex(bytecode_hex)
    except ValueError:
        logger.warning("Invalid bytecode hex")
        return findings

    # Collect real opcode positions, skipping PUSH immediates so we do not
    # count data bytes (a PUSH1 0xff is not a SELFDESTRUCT).
    opcode_positions: Dict[int, List[int]] = {}
    for offset, op in _iter_opcodes(bytecode):
        if op in DANGEROUS_OPCODES:
            opcode_positions.setdefault(op, []).append(offset)

    for op, positions in opcode_positions.items():
        name, severity = DANGEROUS_OPCODES[op]
        findings.append({
            "title": f"Dangerous opcode found: {name}",
            "severity": severity,
            "description": f"Bytecode contains {name} at byte offset(s): {positions[:5]}"
                           + (f" (+{len(positions) - 5} more)" if len(positions) > 5 else ""),
            "file": "bytecode",
            "line": positions[0] if positions else 0,
            "vulnerable_snippet": bytecode[:32].hex() + "...",
            "fix_snippet": "",
            "explanation": f"{name} can be used for malicious purposes. Review the contract's source code if available.",
            "impact": _OPCODE_IMPACT.get(name, "May allow unauthorized or unexpected behaviour."),
            "ai_used": False,
        })

    return findings
# EOF
