# File: hawki/core/deps/__init__.py
from .scanner import VulnerableLibDB, scan_dependencies, update_db

__all__ = ["scan_dependencies", "update_db", "VulnerableLibDB"]
# EOF
