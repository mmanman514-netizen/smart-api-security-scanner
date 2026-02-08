from typing import List, Dict, Any
from scanners.base import BaseScanner
from models.api_resource import ApiResource
from auth.context import AuthContext
from core.errors import ScannerError
import logging

logger = logging.getLogger("scanner-orchestrator")

class ScanOrchestrator:
    def __init__(
        self,
        scanner: BaseScanner,
        resources: List[ApiResource],
        auth_contexts: Dict[str, AuthContext],
        dry_run: bool = False
    ):
        self.scanner = scanner
        self.resources = resources
        self.auth_contexts = auth_contexts
        self.dry_run = dry_run

    async def run(self) -> List[Dict[str, Any]]:
        if not self.resources:
            raise ScannerError("No resources to scan")

        logger.info(f"Starting scan with {len(self.resources)} resources")
        findings = await self.scanner.scan(
            self.resources,
            auth_contexts=self.auth_contexts,
            dry_run=self.dry_run
        )
        logger.info(f"Scan finished. Findings: {len(findings)}")
        return findings
