# إنشاء scanners/base.py
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
        pass

# ثم في bola_scanner.py:
from scanners.base import BaseScanner
class BOLAScanner(BaseScanner):
    # ... التنفيذ
