# File: hawki/core/telemetry/__init__.py
"""
Telemetry module for local anonymous usage metrics (no network export).
"""

from .collector import MetricsCollector
from .store import MetricsStore

__all__ = ["MetricsCollector", "MetricsStore"]
# EOF
