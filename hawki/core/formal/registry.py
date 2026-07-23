# File: hawki/core/formal/registry.py
import importlib
import pkgutil
from pathlib import Path
from typing import Dict, List, Type

from .base import Verifier

_VERIFIERS: Dict[str, Type[Verifier]] = {}

def _discover():
    """Auto-discover all verifier classes in this package."""
    package_dir = Path(__file__).parent
    for module_info in pkgutil.iter_modules([str(package_dir)]):
        if module_info.name.startswith('_'):
            continue
        module = importlib.import_module(f"hawki.core.formal.{module_info.name}")
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and issubclass(attr, Verifier) and attr is not Verifier:
                name = module_info.name.lower().replace('_', '')
                _VERIFIERS[name] = attr

def get_verifier(name: str) -> Verifier:
    """Instantiate verifier by name."""
    if not _VERIFIERS:
        _discover()
    if name not in _VERIFIERS:
        raise ValueError(f"Unknown verifier: {name}. Available: {list(_VERIFIERS.keys())}")
    return _VERIFIERS[name]()

def list_verifiers() -> List[str]:
    if not _VERIFIERS:
        _discover()
    return list(_VERIFIERS.keys())
# EOF
