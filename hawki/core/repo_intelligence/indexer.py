# File: hawki/core/repo_intelligence/indexer.py
"""
Repository indexer: handles local directories, remote Git repos, and deployed contracts.
For deployed contracts, fetches bytecode, attempts to fetch verified source, and performs bytecode analysis.
"""

import json
import logging
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import git
from web3 import Web3
from web3.middleware import geth_poa_middleware

from ..bytecode.analyzer import analyze_bytecode
from ..chain_config import get_chain_config
from ..explorer.client import ExplorerClient
from .parser import SolidityParser

logger = logging.getLogger(__name__)

class RepositoryIndexer:
    def __init__(self, parser: Optional[SolidityParser] = None):
        self.parser = parser or SolidityParser()
        self._temp_dir: Optional[Path] = None

    def index(self, path_or_url: str) -> Dict[str, Any]:
        parsed = urlparse(path_or_url)
        is_remote = parsed.scheme in ("http", "https", "git", "ssh")
        if is_remote:
            return self._index_remote(path_or_url)
        else:
            return self._index_local(Path(path_or_url))

    def from_contract(
        self,
        address: str,
        rpc_url: Optional[str] = None,
        source_path: Optional[Path] = None,
        chain: str = "ethereum",
        explorer_api_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a virtual repository from a deployed contract address.
        Fetches bytecode, tries to get source from explorer, and performs bytecode analysis.
        """
        if not Web3.is_address(address):
            raise ValueError(f"Invalid address: {address}")
        checksum_addr = Web3.to_checksum_address(address)

        chain_config = get_chain_config(chain)
        rpc_url = rpc_url or chain_config["default_rpc"]

        # Connect to RPC
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        try:
            w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        except Exception:
            pass
        if not w3.is_connected():
            raise ConnectionError(f"Cannot connect to RPC: {rpc_url}")

        # Fetch bytecode
        bytecode = w3.eth.get_code(checksum_addr)
        if not bytecode or bytecode == b'':
            raise ValueError(f"Contract at {address} has no bytecode")
        bytecode_hex = bytecode.hex()

        repo_data = {
            "type": "deployed",
            "address": checksum_addr,
            "chain": chain,
            "chain_id": chain_config["chain_id"],
            "rpc_url": rpc_url,
            "bytecode": bytecode_hex,
            "bytecode_length": len(bytecode),
            "contracts": [],
            "source_available": False,
            "verified_source": False,
            "etherscan_url": None,
            "bytecode_findings": [],
        }

        # Attempt to fetch verified source from explorer
        try:
            explorer = ExplorerClient(chain, api_key=explorer_api_key)
            source_data = explorer.get_contract_source(address)
            if source_data:
                repo_data["verified_source"] = True
                repo_data["etherscan_url"] = f"https://{chain}.etherscan.io/address/{checksum_addr}#code"
                # Parse and create virtual repo
                source_code = source_data.get("SourceCode", "")
                if source_code.startswith("{"):
                    try:
                        parsed_source = json.loads(source_code)
                        if "sources" in parsed_source:
                            files = {}
                            for file_path, file_data in parsed_source["sources"].items():
                                files[file_path] = file_data.get("content", "")
                            virtual_repo = self._create_virtual_repo_from_files(files)
                            repo_data["contracts"] = virtual_repo["contracts"]
                            repo_data["source_available"] = True
                            repo_data["source_type"] = "verified_multifile"
                        else:
                            contract_name = source_data.get("ContractName", "Contract")
                            virtual_repo = self._create_virtual_repo_from_single_file(
                                source_code, f"{contract_name}.sol"
                            )
                            repo_data["contracts"] = virtual_repo["contracts"]
                            repo_data["source_available"] = True
                            repo_data["source_type"] = "verified_single"
                    except json.JSONDecodeError:
                        contract_name = source_data.get("ContractName", "Contract")
                        virtual_repo = self._create_virtual_repo_from_single_file(
                            source_code, f"{contract_name}.sol"
                        )
                        repo_data["contracts"] = virtual_repo["contracts"]
                        repo_data["source_available"] = True
                        repo_data["source_type"] = "verified_single"
                else:
                    contract_name = source_data.get("ContractName", "Contract")
                    virtual_repo = self._create_virtual_repo_from_single_file(
                        source_code, f"{contract_name}.sol"
                    )
                    repo_data["contracts"] = virtual_repo["contracts"]
                    repo_data["source_available"] = True
                    repo_data["source_type"] = "verified_single"
                logger.info(f"Fetched verified source for {address}")
        except Exception as e:
            logger.warning(f"Failed to fetch verified source: {e}")

        # If source provided by user, use it (overrides verified source? We'll merge)
        if source_path and source_path.exists():
            logger.info(f"Using user-provided source from {source_path}")
            user_contracts = self._scan_directory(source_path)
            # Merge or replace? We'll replace if we have user source.
            repo_data["contracts"] = user_contracts
            repo_data["source_available"] = True
            repo_data["source_type"] = "user_provided"
            repo_data["path"] = str(source_path)

        # If no source available, perform bytecode analysis
        if not repo_data.get("source_available"):
            logger.warning(f"No source available for {address}; performing bytecode analysis only")
            repo_data["bytecode_findings"] = analyze_bytecode(bytecode_hex)

        return repo_data

    def _create_virtual_repo_from_single_file(self, source_code: str, filename: str) -> Dict[str, Any]:
        import tempfile
        temp_dir = Path(tempfile.mkdtemp(prefix="hawki_contract_"))
        file_path = temp_dir / filename
        file_path.write_text(source_code)
        contracts = self._scan_directory(temp_dir)
        return {"type": "virtual", "path": str(temp_dir), "contracts": contracts}

    def _create_virtual_repo_from_files(self, files: Dict[str, str]) -> Dict[str, Any]:
        import tempfile
        temp_dir = Path(tempfile.mkdtemp(prefix="hawki_contract_"))
        for file_path, content in files.items():
            full_path = temp_dir / file_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content)
        contracts = self._scan_directory(temp_dir)
        return {"type": "virtual", "path": str(temp_dir), "contracts": contracts}

    def _index_local(self, path: Path) -> Dict[str, Any]:
        if not path.is_dir():
            raise ValueError(f"Not a directory: {path}")
        contracts = self._scan_directory(path)
        return {"type": "local", "path": str(path), "contracts": contracts}

    def _index_remote(self, url: str) -> Dict[str, Any]:
        self._temp_dir = Path(tempfile.mkdtemp(prefix="hawki_"))
        logger.info(f"Cloning {url} into {self._temp_dir}")
        try:
            git.Repo.clone_from(url, self._temp_dir)
        except Exception as e:
            raise RuntimeError(f"Failed to clone repository: {e}") from e
        contracts = self._scan_directory(self._temp_dir)
        return {"type": "remote", "url": url, "path": str(self._temp_dir), "contracts": contracts}

    def _scan_directory(self, directory: Path) -> List[Dict[str, Any]]:
        contracts = []
        for sol_file in directory.rglob("*.sol"):
            parsed = self.parser.parse_file(sol_file)
            if parsed:
                contracts.append(parsed)
        return contracts

    def cleanup(self):
        if self._temp_dir and self._temp_dir.exists():
            import shutil
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None

# EOF: hawki/core/repo_intelligence/indexer.py