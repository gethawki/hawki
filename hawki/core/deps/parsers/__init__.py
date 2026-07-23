# File: hawki/core/deps/parsers/__init__.py
"""
Lockfile parsers for dependency scanning.
"""
from .cargo_toml import parse_cargo_toml
from .foundry_toml import parse_foundry_toml
from .hardhat_config import parse_hardhat_config
from .package_json import parse_package_json
from .pnpm_lock import parse_pnpm_lock
from .yarn_lock import parse_yarn_lock

__all__ = [
    "parse_package_json",
    "parse_foundry_toml",
    "parse_hardhat_config",
    "parse_yarn_lock",
    "parse_pnpm_lock",
    "parse_cargo_toml",
]
# EOF
