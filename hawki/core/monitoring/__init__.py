# --------------------
# File: hawki/core/monitoring/__init__.py
# --------------------
"""
Monitoring subsystem: auto-discovers watchers and runs continuous checks.
"""

import importlib
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from .alert_manager import AlertManager
from .state_manager import StateManager
from .watcher_base import Watcher

logger = logging.getLogger(__name__)

class WatcherRegistry:
    """Discovers and instantiates watcher classes."""

    def __init__(self, watchers_dir: Optional[Path] = None):
        if watchers_dir is None:
            watchers_dir = Path(__file__).parent / "watchers"
        self.watchers_dir = watchers_dir
        self._watcher_classes: List[Type[Watcher]] = []
        self._discover()

    def _discover(self) -> None:
        """Dynamically import all modules in watchers directory and collect Watcher subclasses."""
        if not self.watchers_dir.exists():
            logger.warning(f"Watchers directory not found: {self.watchers_dir}")
            return

        # Import all .py files except __init__
        for py_file in self.watchers_dir.glob("*.py"):
            if py_file.name == "__init__.py":
                continue
            module_name = f"hawki.core.monitoring.watchers.{py_file.stem}"
            try:
                module = importlib.import_module(module_name)
                # Find all classes that are subclasses of Watcher (excluding Watcher itself)
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if isinstance(attr, type) and issubclass(attr, Watcher) and attr is not Watcher:
                        self._watcher_classes.append(attr)
                        logger.debug(f"Discovered watcher: {attr.__name__}")
            except Exception as e:
                logger.error(f"Failed to load watcher module {module_name}: {e}")

    def instantiate_all(self, configs: Dict[str, Dict[str, Any]]) -> List[Watcher]:
        """
        Create instances of all discovered watcher classes.
        configs is a dict mapping watcher name (or class name) to configuration.
        """
        watchers = []
        for cls in self._watcher_classes:
            # Default config key: class name lowercase
            name = cls.__name__.lower()
            config = configs.get(name, {})
            try:
                instance = cls(name=name, config=config)
                watchers.append(instance)
            except Exception as e:
                logger.error(f"Failed to instantiate watcher {cls.__name__}: {e}")
        return watchers


class Monitor:
    """Runs watchers continuously, manages state and alerts."""

    def __init__(
        self,
        watcher_configs: Dict[str, Dict[str, Any]],
        state_dir: Optional[Path] = None,
        alert_log_file: Optional[Path] = None,
    ):
        self.registry = WatcherRegistry()
        self.watchers = self.registry.instantiate_all(watcher_configs)
        self.state_manager = StateManager(state_dir)
        self.alert_manager = AlertManager(alert_log_file)
        self._load_states()

    def _load_states(self) -> None:
        """Restore persisted state for each watcher."""
        for watcher in self.watchers:
            state = self.state_manager.get(watcher.get_id())
            watcher.load_state(state)

    def _save_states(self) -> None:
        """Persist current state of all watchers."""
        for watcher in self.watchers:
            self.state_manager.set(watcher.get_id(), watcher.save_state())
        self.state_manager.save()

    def run_once(self) -> None:
        """Run a single check cycle on all watchers."""
        for watcher in self.watchers:
            try:
                event = watcher.check()
                if event:
                    # Ensure event has required fields
                    if "message" not in event:
                        event["message"] = f"Event from {watcher.name}"
                    event["watcher"] = watcher.name
                    self.alert_manager.alert(event)
            except Exception as e:
                logger.error(f"Watcher {watcher.name} check failed: {e}")
        self._save_states()

    def run_forever(self, interval_seconds: int = 60) -> None:
        """Run continuous monitoring with given interval."""
        logger.info(f"Starting monitor with {len(self.watchers)} watchers, interval={interval_seconds}s")
        try:
            while True:
                self.run_once()
                time.sleep(interval_seconds)
        except KeyboardInterrupt:
            logger.info("Monitor stopped by user")
            self._save_states()

# EOF: hawki/core/monitoring/__init__.py