# File: hawki/core/formal/base.py
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List


class Verifier(ABC):
    @abstractmethod
    def verify(self, source_path: Path, contract_name: str = None) -> List[Dict[str, Any]]:
        pass
# EOF
