# --------------------
# File: hawki/core/__init__.py
# --------------------
"""
Core subsystems for Hawk-i.

The deep-agent classes are imported lazily so that lightweight commands
(doctor, metrics, version) do not pay the cost of importing litellm on
every invocation. Access them normally, e.g. `from hawki.core import
DeepOrchestrator`; the import happens on first attribute access.
"""

__all__ = ["DeepOrchestrator", "BudgetManager", "SQLiteStore", "JSONStore"]

_DEEP_EXPORTS = {"DeepOrchestrator", "BudgetManager", "SQLiteStore", "JSONStore"}


def __getattr__(name):
    if name in _DEEP_EXPORTS:
        from . import deep

        return getattr(deep, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
# EOF
