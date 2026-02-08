# scanners/bola_scanner.py - الإصدار المصحح
import asyncio
import aiohttp
import json
import logging
import time
import hashlib
from typing import Dict, Any, Optional, List
from models.api_resource import ApiResource
from models.auth_context import AuthContext

logger = logging.getLogger(__name__)

class BOLAScanner:
    """BOLA (Broken Object Level Authorization) Scanner"""
    
    def __init__(
        self,
        base_url: str = "",
        rate_limit: float = 1.0,
        max_concurrent: int = 5,
        timeout: int = 30,
        strict_owner: bool = False
    ):
        self.base_url = base_url
        self.rate_limit = rate_limit
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.timeout = timeout
        self.strict_owner = strict_owner
        self.session = None
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout))
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def scan(
        self,
        resources: List[ApiResource],
        auth_contexts: Dict[str, AuthContext],
        dry_run: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Scan for BOLA vulnerabilities
        
        Args:
            resources: List of ApiResource to scan
            auth_contexts: Dict with 'user_a' and 'user_b' AuthContext
            dry_run: If True, don't make actual requests
            
        Returns:
            List of findings
        """
        findings = []
        
        if not auth_contexts or len(auth_contexts) < 2:
            raise ValueError("BOLA scan requires at least 2 auth contexts")
        
        user_a = auth_contexts.get("user_a")
        user_b = auth_contexts.get("user_b")
        
        if not user_a or not user_b:
            raise ValueError("Missing user_a or user_b in auth_contexts")
        
        for resource in resources:
            # Skip non-user-owned resources
            if not self._is_user_owned(resource):
                continue
            
            # Get object IDs to test
            object_ids = await self._get_object_ids(resource, user_a)
            
            for object_id in object_ids[:5]:  # Limit to 5 IDs
                for method in resource.methods:
                    if method in ["POST", "PUT", "DELETE"]:
                        continue  # Skip destructive methods in basic scan
                    
                    if dry_run:
                        logger.info(f"Dry run: {method} {resource.endpoint} id={object_id}")
                        continue
                    
                    try:
                        # Make requests
                        response_a = await self._make_request(
                            resource, user_a, object_id, method
                        )
                        response_b = await self._make_request(
                            resource, user_b, object_id, method
                        )
                        
                        # Compare responses
                        if self._is_vulnerable(response_a, response_b, resource):
                            finding = self._create_finding(
                                resource, object_id, method, response_a, response_b
                            )
                            findings.append(finding)
                            
                    except Exception as e:
                        logger.warning(f"Error scanning {resource.name}: {e}")
        
        return findings
    
    def _is_user_owned(self, resource: ApiResource) -> bool:
        """Check if resource is user-owned"""
        return "{id}" in resource.endpoint and resource.owner_field
    
    async def _get_object_ids(self, resource: ApiResource, auth_context: AuthContext) -> List[str]:
        """Get object IDs to test"""
        ids = set()
        
        # Try to get IDs from list endpoint
        list_endpoint = resource.endpoint.replace("{id}", "")
        try:
            response = await self._make_request(resource, auth_context, "", "GET")
            if response["status"] == 200:
                ids.update(self._extract_ids_from_response(response["body"]))
        except:
            pass
        
        # Add some default IDs
        ids.update(["1", "2", "100", "999"])
        
        return list(ids)
    
    async def _make_request(
        self,
        resource: ApiResource,
        auth_context: AuthContext,
        object_id: str,
        method: str
    ) -> Dict[str, Any]:
        """Make HTTP request"""
        async with self.semaphore:
            await asyncio.sleep(self.rate_limit)
            
            url = resource.build_url(self.base_url, object_id)
            headers = auth_context.all_headers()
            
            try:
                if method == "GET":
                    async with self.session.get(url, headers=headers) as resp:
                        body = await resp.json() if resp.content_type == 'application/json' else {}
                        return {
                            "status": resp.status,
                            "body": body,
                            "headers": dict(resp.headers)
                        }
                # Add other methods as needed
                else:
                    async with self.session.get(url, headers=headers) as resp:
                        body = await resp.json() if resp.content_type == 'application/json' else {}
                        return {
                            "status": resp.status,
                            "body": body,
                            "headers": dict(resp.headers)
                        }
            except Exception as e:
                return {
                    "status": 0,
                    "body": {},
                    "error": str(e)
                }
    
    def _is_vulnerable(
        self,
        response_a: Dict[str, Any],
        response_b: Dict[str, Any],
        resource: ApiResource
    ) -> bool:
        """Check if BOLA vulnerability exists"""
        
        # If status codes are different, might be OK
        if response_a.get("status") != response_b.get("status"):
            return False
        
        # If both returned success (2xx)
        if 200 <= response_a.get("status", 0) < 300:
            # Check if responses are similar
            return self._responses_similar(response_a.get("body", {}), response_b.get("body", {}))
        
        return False
    
    def _responses_similar(self, body_a: Dict, body_b: Dict, threshold: float = 0.8) -> bool:
        """Check if two responses are similar"""
        # Simple implementation - compare JSON strings
        import difflib
        str_a = json.dumps(body_a, sort_keys=True)
        str_b = json.dumps(body_b, sort_keys=True)
        similarity = difflib.SequenceMatcher(None, str_a, str_b).ratio()
        return similarity >= threshold
    
    def _extract_ids_from_response(self, body: Any) -> List[str]:
        """Extract IDs from response body"""
        ids = []
        
        if isinstance(body, list):
            for item in body[:10]:  # Limit
                if isinstance(item, dict) and "id" in item:
                    ids.append(str(item["id"]))
        elif isinstance(body, dict) and "data" in body and isinstance(body["data"], list):
            for item in body["data"][:10]:
                if isinstance(item, dict) and "id" in item:
                    ids.append(str(item["id"]))
        
        return ids
    
    def _create_finding(
        self,
        resource: ApiResource,
        object_id: str,
        method: str,
        response_a: Dict[str, Any],
        response_b: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create finding dictionary"""
        return {
            "resource": resource.name,
            "endpoint": resource.endpoint,
            "object_id": object_id,
            "method": method,
            "issue": "cross_user_access",
            "severity": "critical",
            "confidence": 80,
            "details": {
                "response_a_status": response_a.get("status"),
                "response_b_status": response_b.get("status"),
                "similarity": self._responses_similar(response_a.get("body", {}), response_b.get("body", {}))
            }
                            }
