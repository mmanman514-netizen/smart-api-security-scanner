"""Base scanner interface."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
from models.api_resource import ApiResource
from models.auth_context import AuthContext


class BaseScanner(ABC):
    @abstractmethod
    async def scan(
        self,
        resources: List[ApiResource],
        auth_contexts: Dict[str, AuthContext],
        dry_run: bool = False
    ) -> List[Dict[str, Any]]:
        """Run scanner and return findings."""
        raise NotImplementedError
