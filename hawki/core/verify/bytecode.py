# File: hawki/core/verify/bytecode.py
"""
Complete bytecode verification: compile source, fetch on-chain bytecode,
compare with optional metadata stripping, and return detailed diff.
"""

import json
import logging
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from web3 import Web3
from web3.middleware import geth_poa_middleware

logger = logging.getLogger(__name__)

def _normalize(bytecode_hex: str) -> str:
    """Strip a leading 0x prefix and lowercase, so on-chain and compiled hex
    (which solc emits without a prefix) compare on equal footing."""
    if not bytecode_hex:
        return ""
    h = bytecode_hex.strip()
    if h[:2] in ("0x", "0X"):
        h = h[2:]
    return h.lower()


def _strip_metadata(bytecode_hex: str) -> str:
    """
    Remove the trailing CBOR metadata block appended by solc.

    The last two bytes of the deployed bytecode encode the length (in bytes) of
    the CBOR metadata that precedes them, so the total block to strip is
    ``metadata_len + 2`` bytes. This is length aware rather than assuming a
    fixed 53-byte tail, since the block size varies with metadata options.
    """
    bc = _normalize(bytecode_hex)
    if len(bc) < 4:
        return bc
    try:
        meta_len = int(bc[-4:], 16)  # length in bytes, excluding the 2 length bytes
    except ValueError:
        meta_len = -1
    if meta_len > 0:
        total_hex = (meta_len + 2) * 2
        # The stripped region should begin with the CBOR map marker 0xa2.
        if 0 < total_hex < len(bc) and bc[-total_hex:-total_hex + 2] == "a2":
            return bc[:-total_hex]
    # Fallback for the common solc >=0.8 layout (53-byte block) if the length
    # bytes looked implausible.
    if len(bc) > 106 and bc[-106:].startswith("a264"):
        return bc[:-106]
    return bc


def compare_bytecode(onchain_hex: str, compiled_hex: str, ignore_metadata: bool = True) -> Dict[str, Any]:
    """
    Pure comparison of two runtime bytecode hex strings. Returns a dict with
    ``match`` (bool) and ``diff_summary`` (str). Exposed separately so the
    compare logic can be exercised without a live RPC connection.
    """
    onchain_compare = _normalize(onchain_hex)
    compiled_compare = _normalize(compiled_hex)
    if ignore_metadata:
        onchain_compare = _strip_metadata(onchain_compare)
        compiled_compare = _strip_metadata(compiled_compare)

    if onchain_compare == compiled_compare:
        summary = "Bytecode matches (metadata ignored)" if ignore_metadata else "Bytecode matches exactly"
        return {"match": True, "diff_summary": summary}

    min_len = min(len(onchain_compare), len(compiled_compare))
    diff_byte = min_len // 2
    for i in range(0, min_len, 2):
        if onchain_compare[i:i + 2] != compiled_compare[i:i + 2]:
            diff_byte = i // 2
            break
    summary = (
        f"Mismatch at byte offset {diff_byte}. "
        f"Onchain length {len(onchain_compare) // 2}, compiled {len(compiled_compare) // 2}"
    )
    return {"match": False, "diff_summary": summary}

def _compile_source(source_path: Path) -> Dict[str, str]:
    """
    Compile all Solidity files in source_path using solc.
    Returns a dict mapping contract name (fully qualified) to runtime bytecode hex.
    """
    sol_files = list(source_path.rglob("*.sol"))
    if not sol_files:
        raise ValueError(f"No .sol files found in {source_path}")

    # Use solc with combined-json output
    cmd = [
        "solc",
        "--combined-json", "bin-runtime",
        "--base-path", str(source_path),
        "--include-path", str(source_path),
    ] + [str(f) for f in sol_files]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(f"Compilation failed: {result.stderr}")

    data = json.loads(result.stdout)
    contracts = {}
    for contract_name, contract_data in data.get("contracts", {}).items():
        if "bin-runtime" in contract_data:
            contracts[contract_name] = contract_data["bin-runtime"]
    return contracts

def verify_bytecode(
    address: str,
    rpc_url: str,
    source_path: Path,
    ignore_metadata: bool = True,
    contract_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Verify deployed bytecode matches compiled source.

    Returns:
        {
            "success": bool,
            "match": bool,
            "onchain": {"hash": str, "length": int, "hex": str (truncated)},
            "compiled": {"name": str, "hash": str, "length": int, "hex": str (truncated)},
            "diff_summary": str,
            "error": str or None,
        }
    """
    result = {
        "success": False,
        "match": False,
        "onchain": {},
        "compiled": {},
        "diff_summary": "",
        "error": None,
    }

    try:
        # Connect to RPC
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        # Inject POA middleware if needed (for chains like BSC, Polygon)
        try:
            w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        except Exception:
            pass
        if not w3.is_connected():
            result["error"] = f"Cannot connect to RPC: {rpc_url}"
            return result

        # Fetch on-chain bytecode
        checksum_addr = Web3.to_checksum_address(address)
        onchain_bytes = w3.eth.get_code(checksum_addr)
        onchain_hex = _normalize(onchain_bytes.hex())
        if not onchain_hex:
            result["error"] = "No bytecode found at address (contract not deployed?)"
            return result
        result["onchain"] = {
            "hash": onchain_hex[:12] + "...",
            "length": len(onchain_hex) // 2,
            "hex": onchain_hex[:256] + ("..." if len(onchain_hex) > 256 else ""),
        }

        # Compile source
        compiled_contracts = _compile_source(source_path)
        if not compiled_contracts:
            result["error"] = "No runtime bytecode found in compiled output"
            return result

        # If contract_name not provided, try to find the best match
        target_bytecode = None
        target_name = None
        if contract_name:
            # Find exact or partial match
            for name, bc in compiled_contracts.items():
                if name.endswith(f":{contract_name}") or name == contract_name:
                    target_bytecode = bc
                    target_name = name
                    break
        else:
            # If only one contract, use it; otherwise pick first
            if len(compiled_contracts) == 1:
                target_name, target_bytecode = next(iter(compiled_contracts.items()))
            else:
                # Try to find a contract matching the address's metadata? Not possible.
                # Fallback: ask user to specify contract name.
                result["error"] = "Multiple contracts found. Specify --contract-name"
                return result

        if not target_bytecode:
            result["error"] = f"Contract '{contract_name}' not found in compiled output"
            return result

        target_bytecode = _normalize(target_bytecode)
        result["compiled"] = {
            "name": target_name,
            "hash": target_bytecode[:12] + "...",
            "length": len(target_bytecode) // 2,
            "hex": target_bytecode[:256] + ("..." if len(target_bytecode) > 256 else ""),
        }

        # Compare (normalization and metadata stripping handled in the helper).
        comparison = compare_bytecode(onchain_hex, target_bytecode, ignore_metadata=ignore_metadata)
        result["match"] = comparison["match"]
        result["diff_summary"] = comparison["diff_summary"]
        result["success"] = True
        return result

    except Exception as e:
        logger.exception("Bytecode verification failed")
        result["error"] = str(e)
        return result
# EOF
