# File: hawki/core/exporters/registry.py
"""
Registry for discovering and retrieving exporters.
"""

from typing import Dict, Optional, Type

from .base import Exporter
from .structured_exporter import StructuredExporter

_EXPORTERS: Dict[str, Type[Exporter]] = {
    "structured": StructuredExporter,
}

def register_exporter(name: str, exporter_class: Type[Exporter]) -> None:
    """Register a new exporter."""
    _EXPORTERS[name] = exporter_class

def get_exporter(name: str) -> Optional[Exporter]:
    """Instantiate and return an exporter by name."""
    if name not in _EXPORTERS:
        return None
    return _EXPORTERS[name]()

def list_exporters() -> list:
    """Return list of available exporter names."""
    return list(_EXPORTERS.keys())
# EOF
