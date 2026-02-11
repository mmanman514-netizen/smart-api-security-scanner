"""Base scanner interface."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List


class BaseScanner(ABC):
    @abstractmethod
    async def scan(
        self,
        resources: List[Dict[str, Any]],
        auth_contexts: Dict[str, Dict[str, Any]],
        dry_run: bool = False,
    ) -> List[Dict[str, Any]]:
        """Run scanner and return findings."""
        raise NotImplementedError
