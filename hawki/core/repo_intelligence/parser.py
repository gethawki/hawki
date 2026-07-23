# --------------------
# File: hawki/core/repo_intelligence/parser.py
# --------------------
"""
Solidity parser using tree-sitter.
Extracts contracts, functions, state variables, modifiers, and inheritance.
Produces a structured representation for further analysis.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import tree_sitter
import tree_sitter_solidity

logger = logging.getLogger(__name__)

class SolidityParser:
    """Parses Solidity source files and builds an AST index."""

    def __init__(self):
        """
        Tree-sitter initialization with cross-version compatibility.
        """

        solidity_lang = tree_sitter_solidity.language()

        if isinstance(solidity_lang, tree_sitter.Language):
            self._language = solidity_lang
        else:
            self._language = tree_sitter.Language(solidity_lang)

        try:
            self._parser = tree_sitter.Parser(self._language)
        except TypeError:
            self._parser = tree_sitter.Parser()
            if hasattr(self._parser, "set_language"):
                self._parser.set_language(self._language)
            else:
                self._parser.language = self._language

    def parse_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse a single Solidity file and return a structured representation.
        Returns None if parsing fails.
        """
        try:
            with open(file_path, encoding='utf-8') as f:
                source_code = f.read()
        except Exception as e:
            logger.error(f"Failed to read {file_path}: {e}")
            return None

        tree = self._parser.parse(bytes(source_code, "utf8"))
        if not tree:
            logger.error(f"Failed to parse {file_path}")
            return None

        contracts = self._extract_contracts(tree.root_node, source_code)

        return {
            "path": str(file_path),
            "source": source_code,
            "contracts": contracts,
        }

    def _extract_contracts(self, node: tree_sitter.Node, source: str) -> List[Dict]:
        """Recursively extract contract definitions."""
        contracts = []

        if node.type == "contract_declaration":
            name_node = node.child_by_field_name("name")
            name = self._node_text(name_node, source) if name_node else "<anonymous>"

            functions = self._extract_functions(node, source)
            state_vars = self._extract_state_variables(node, source)
            modifiers = self._extract_modifiers(node, source)
            inheritance = self._extract_inheritance(node, source)

            contracts.append({
                "name": name,
                "functions": functions,
                "state_variables": state_vars,
                "modifiers": modifiers,
                "inheritance": inheritance,
            })

        for child in node.children:
            contracts.extend(self._extract_contracts(child, source))

        return contracts

    # ✅ FIXED - recursive search
    def _extract_functions(self, contract_node: tree_sitter.Node, source: str) -> List[Dict]:
        """Extract function definitions inside a contract."""
        functions = []

        def walk(node):
            if node.type == "function_definition":
                name_node = node.child_by_field_name("name")
                name = self._node_text(name_node, source) if name_node else "fallback"

                params = self._extract_parameters(node, source)
                modifiers = self._extract_modifier_names(node, source)
                visibility = self._extract_visibility(node, source)
                state_mutability = self._extract_state_mutability(node, source)
                returns = self._extract_returns(node, source)

                functions.append({
                    "name": name,
                    "parameters": params,
                    "modifiers": modifiers,
                    "visibility": visibility,
                    "state_mutability": state_mutability,
                    "returns": returns,
                })

            for child in node.children:
                walk(child)

        walk(contract_node)
        return functions

    def _extract_state_variables(self, contract_node: tree_sitter.Node, source: str) -> List[Dict]:
        """Extract state variable declarations."""
        variables = []

        def walk(node):
            if node.type == "state_variable_declaration":
                name_node = node.child_by_field_name("name")
                name = self._node_text(name_node, source) if name_node else "unknown"

                type_node = node.child_by_field_name("type")
                var_type = self._node_text(type_node, source) if type_node else "unknown"

                visibility = self._extract_visibility(node, source)

                variables.append({
                    "name": name,
                    "type": var_type,
                    "visibility": visibility,
                })

            for child in node.children:
                walk(child)

        walk(contract_node)
        return variables

    def _extract_modifiers(self, contract_node: tree_sitter.Node, source: str) -> List[Dict]:
        """Extract modifier definitions."""
        modifiers = []

        def walk(node):
            if node.type == "modifier_declaration":
                name_node = node.child_by_field_name("name")
                name = self._node_text(name_node, source) if name_node else "unknown"

                params = self._extract_parameters(node, source)

                modifiers.append({
                    "name": name,
                    "parameters": params,
                })

            for child in node.children:
                walk(child)

        walk(contract_node)
        return modifiers

    def _extract_inheritance(self, contract_node: tree_sitter.Node, source: str) -> List[str]:
        """Extract base contracts."""
        bases = []

        def walk(node):
            if node.type == "inheritance_specifier":
                name_node = node.child_by_field_name("name")
                if name_node:
                    bases.append(self._node_text(name_node, source))

            for child in node.children:
                walk(child)

        walk(contract_node)
        return bases

    def _extract_parameters(self, node: tree_sitter.Node, source: str) -> List[Dict]:
        """Extract parameters."""
        params = []

        for child in node.children:
            if child.type == "parameter":
                name_node = child.child_by_field_name("name")
                type_node = child.child_by_field_name("type")

                name = self._node_text(name_node, source) if name_node else ""
                param_type = self._node_text(type_node, source) if type_node else ""

                params.append({"name": name, "type": param_type})

        return params

    def _extract_modifier_names(self, node: tree_sitter.Node, source: str) -> List[str]:
        """Extract modifier invocations."""
        modifiers = []

        for child in node.children:
            if child.type == "modifier_invocation":
                name_node = child.child_by_field_name("name")
                if name_node:
                    modifiers.append(self._node_text(name_node, source))

        return modifiers

    def _extract_visibility(self, node: tree_sitter.Node, source: str) -> str:
        """
        Extract visibility modifier from a node.
        Searches recursively because visibility is nested
        inside function_header in Tree-sitter Solidity grammar.
        """

        VISIBILITY_TYPES = {"public", "internal", "external", "private"}

        def walk(n):
            if n.type in VISIBILITY_TYPES:
                return n.type

            for child in n.children:
                result = walk(child)
                if result:
                    return result

            return None

        found = walk(node)
        return found if found else "internal"


    def _extract_state_mutability(self, node: tree_sitter.Node, source: str) -> str:
        """Extract mutability."""
        for child in node.children:
            if child.type in ["pure", "view", "payable"]:
                return child.type
        return "nonpayable"

    def _extract_returns(self, node: tree_sitter.Node, source: str) -> List[Dict]:
        """Extract returns."""
        returns = []

        for child in node.children:
            if child.type == "returns":
                for param in child.children:
                    if param.type == "parameter":
                        name_node = param.child_by_field_name("name")
                        type_node = param.child_by_field_name("type")

                        name = self._node_text(name_node, source) if name_node else ""
                        param_type = self._node_text(type_node, source) if type_node else ""

                        returns.append({"name": name, "type": param_type})

        return returns

    def _node_text(self, node: Optional[tree_sitter.Node], source: str) -> str:
        """Safely extract text from a node."""
        if not node:
            return ""
        return source[node.start_byte:node.end_byte]

# EOF: hawki/core/repo_intelligence/parser.py
