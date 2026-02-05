import asyncio
import aiohttp
import requests
import jwt
import json
import logging
import time
import xml.etree.ElementTree as ET
import csv
import io
import re
from typing import Dict, Any, Optional, List, Set, TypedDict, Literal
from aiohttp import ClientError
from functools import lru_cache
from cryptography.fernet import Fernet

try:
    import nest_asyncio
    nest_asyncio.apply()
except ImportError:
    pass

# ... (imports الأخرى كما في النسخة السابقة)

class ScanResult(TypedDict):
    resource: str
    object_id: str
    method: str
    status: str
    severity: str
    confidence: float
    risk_score: float
    authorization_verdict: Literal["ALLOW", "DENY", "INCONCLUSIVE"]
    details: List[str]
    evidence: Dict[str, Any]
    statistics: Dict[str, Any]

class BaseScanner:
    def __init__(
        self,
        base_url: str,
        timeout: int = 10,
        proxies: Optional[Dict[str, str]] = None,
        max_retries: int = 3,
        rate_limit: float = 1.0,
        ignored_fields: Set[str] = {"created_at", "updated_at", "timestamp"},
        risk_factors: Optional[Dict[str, float]] = None,
        nested_ownership_paths: List[str] = ["owner_id", "user_id", "account_id", "creator_id", "author_id", "user.id", "owner.id", "account.owner_id"],
        encryption_key: str,
        jwt_public_key: Optional[str] = None,
        jwt_algorithms: List[str] = ["RS256", "HS256"],  # configurable
        revoked_tokens_cache: Optional[Set[str]] = None,  # للـ revoked tokens
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.proxies = proxies
        self.max_retries = max_retries
        self.rate_limit = rate_limit
        self.last_request_time = 0.0
        self.ignored_fields = ignored_fields
        self.risk_factors = risk_factors or {
            "method_delete": 1.5,
            "status_diff": 1.2,
            "role_diff": 1.3,
            "data_type_plain": 1.1,
        }
        self.nested_ownership_paths = nested_ownership_paths
        self.encryption_key = encryption_key
        self.fernet = Fernet(encryption_key.encode())
        self.jwt_public_key = jwt_public_key
        self.jwt_algorithms = jwt_algorithms
        self.revoked_tokens_cache = revoked_tokens_cache or set()

    def _extract_jwt_info(self, auth: AuthContext, resource_algorithms: Optional[List[str]] = None) -> Dict[str, Any]:
        """Extract and verify JWT with configurable algorithms and revoked check."""
        token = auth.jwt_token
        if not token or token in self.revoked_tokens_cache:
            return {}
        
        algorithms = resource_algorithms or self.jwt_algorithms
        try:
            if self.jwt_public_key:
                payload = jwt.decode(token, self.jwt_public_key, algorithms=algorithms, options={"verify_exp": True})
            else:
                payload = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
            return {
                "subject": payload.get("sub"),
                "roles": payload.get("roles", []),
                "exp": payload.get("exp"),
            }
        except jwt.ExpiredSignatureError:
            logger.warning("JWT expired")
        except jwt.InvalidTokenError:
            logger.warning("Invalid JWT")
        except Exception as e:
            logger.warning(f"JWT extraction failed: {e}")
        return {}

    def _get_data_size(self, response) -> int:
        """Get data size using Content-Length to avoid memory consumption."""
        content_length = response.headers.get("Content-Length")
        if content_length:
            try:
                return int(content_length)
            except ValueError:
                pass
        # Fallback: chunked reading without full load
        size = 0
        try:
            async for chunk in response.content.iter_chunked(8192):  # 8KB chunks
                size += len(chunk)
                if size > 10**6:  # Cap at 1MB to avoid excessive reading
                    break
        except Exception:
            pass
        return size

    def _categorize_error(self, exception: Optional[Exception] = None, status_code: Optional[int] = None) -> str:
        """Categorize errors for detailed logging."""
        if isinstance(exception, aiohttp.ClientConnectorError):
            return "network_error"
        if status_code:
            if 400 <= status_code < 500:
                return "client_error"
            if 500 <= status_code < 600:
                return "server_error"
        return "unknown_error"

    def _normalize_id(self, value: Any) -> str:
        """Normalize IDs for ownership check (e.g., lower case emails, strip spaces)."""
        if isinstance(value, str):
            return value.lower().strip()
        return str(value).strip()

    def _evaluate_ownership(self, data: Dict[str, Any], user_id: Optional[str], jwt_subject: Optional[str], jwt_roles: Optional[List[str]]) -> bool:
        """Evaluate ownership with normalization."""
        for path in self.nested_ownership_paths:
            value = self._get_nested_value(data, path)
            if value and self._normalize_id(value) == self._normalize_id(user_id):
                return True
        if jwt_subject and self._normalize_id(jwt_subject) == self._normalize_id(user_id):
            return True
        if jwt_roles and "admin" in jwt_roles:
            return True
        return False

    def _calculate_risk_score(
        self, method: str, status_a: int, status_b: int, role_a: Optional[str], role_b: Optional[str], 
        content_type: str, data_size: int = 0, criticality: str = "low", impact: str = "low", 
        exploitability: str = "medium", exposed_fields: int = 0, endpoint_sensitivity: str = "public"
    ) -> float:
        """Enhanced OWASP-compliant risk score."""
        base_score = 1.0
        # Data size
        if data_size > 1000:
            base_score *= 1.5
        # Exposed fields
        if exposed_fields > 10:
            base_score *= 1.2
        # Endpoint sensitivity
        if endpoint_sensitivity == "admin":
            base_score *= 2.0
        # Type of data (impact)
        if "pii" in impact.lower():
            base_score *= 2.0
        if "financial" in impact.lower():
            base_score *= 2.5
        if "api_keys" in impact.lower():
            base_score *= 3.0
        # Exploitability
        if exploitability == "high":
            base_score *= 1.5
        # Auth strength
        if not role_a or not role_b:
            base_score *= 1.3
        # Method and status
        if method.upper() == "DELETE":
            base_score *= 1.5
        if status_a != status_b:
            base_score *= 1.2
        return min(base_score, 10.0)

    # ... (باقي الطرق كما في النسخة السابقة، مع التحسينات)

class BOLAScanner(BaseScanner):
    async def scan(
        self,
        resource: ApiResource,
        user_a: AuthContext,
        user_b: AuthContext,
        object_id: str | int,
        method: str = "GET",
        request_body: Optional[Dict[str, Any]] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        custom_risk_factors: Optional[Dict[str, float]] = None,
        custom_ignored_fields: Optional[Set[str]] = None,
        custom_nested_paths: Optional[List[str]] = None,
        criticality: str = "low",
        impact: str = "low",
        exploitability: str = "medium",
        jwt_algorithms: Optional[List[str]] = None,  # per resource
        endpoint_sensitivity: str = "public",
    ) -> ScanResult:
        result: ScanResult = {
            "resource": resource.endpoint,
            "object_id": str(object_id),
            "method": method.upper(),
            "status": "UNKNOWN",
            "severity": "INFO",
            "confidence": 0.0,
            "risk_score": 0.0,
            "authorization_verdict": "INCONCLUSIVE",
            "details": [],
            "evidence": {},
            "statistics": {
                "vulnerabilities_found": 0,
                "responses_analyzed": 0,
                "response_details": [],
                "scan_summary": "",
                "total_time": 0.0,
                "avg_response_time": 0.0,
                "failed_requests": 0,
            },
        }

        start_time = time.time()
        response_times = []

        # التحقق من صحة المدخلات
        if "{id}" not in resource.endpoint:
            return self._fail(result, "INVALID_INPUT", "Endpoint must contain '{id}' placeholder")
        if not str(object_id).strip():
            return self._fail(result, "INVALID_INPUT", "Object ID cannot be empty")
        if method.upper() in ["DELETE", "PUT"] and not request_body:
            result["details"].append("Warning: Destructive method used without body.")

        url = self._build_url(resource.endpoint, object_id)
        logger.info(f"Scanning URL: {url} with method: {method.upper()}")

        if custom_risk_factors:
            self.risk_factors.update(custom_risk_factors)
        if custom_nested_paths:
            self.nested_ownership_paths.extend(custom_nested_paths)

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            # 1️⃣ Baseline – User A (owner)
            resp_a = await self._send_request(session, url, method, user_a, request_body, custom_headers, result)
            if not resp_a:
                error_cat = self._categorize_error(None, None)
                result["details"].append(f"Baseline failed: {error_cat}")
                result["statistics"]["failed_requests"] += 1
                result["statistics"]["scan_summary"] = "Failed to get baseline response."
                result["statistics"]["total_time"] = time.time() - start_time
                return result

            result["statistics"]["responses_analyzed"] += 1
            result["statistics"]["response_details"].append({
                "user": "user_a",
                "status_code": resp_a.status,
                "content_length": self._get_data_size(resp_a),
                "content_type": resp_a.headers.get("content-type", "unknown"),
            })

            # Handle 401, 403, 404 errors
            if resp_a.status == 401:
                return self._fail(result, "INVALID_AUTH", "User A authentication failed")
            if resp_a.status in (403, 404):
                return self._fail(result, "OBJECT_PROTECTED", f"Owner access blocked ({resp_a.status})")
            if resp_a.status not in (200, 201, 202):
                return self._fail(result, "UNKNOWN_BASELINE", f"Unexpected baseline status {resp_a.status}")

            # 2️⃣ Ownership auto-detection
            resp_a_data = await resp_a.json() if "json" in resp_a.headers.get("content-type", "") else {}
            owner_id = self._detect_owner(resp_a_data)
            result["evidence"]["detected_owner_id"] = owner_id

            if owner_id and user_a.user_id and owner_id != user_a.user_id:
                return self._fail(result, "OWNER_MISMATCH", "Object does not belong to baseline user")

            # 3️⃣ JWT decoding with per-resource algorithms
            jwt_info_a = self._extract_jwt_info(user_a, jwt_algorithms)
            jwt_info_b = self._extract_jwt_info(user_b, jwt_algorithms)

            # 4️⃣ Attack simulation – User B
            resp_b = await self._send_request(session, url, method, user_b, request_body, custom_headers, result)
            if not resp_b:
                error_cat = self._categorize_error(None, resp_b.status if resp_b else None)
                result["details"].append(f"User B request failed: {error_cat}")
                result["statistics"]["failed_requests"] += 1
                result["statistics"]["scan_summary"] = "Failed to get attacker response."
                result["statistics"]["total_time"] = time.time() - start_time
                return result

            result["statistics"]["responses_analyzed"] += 1
            result["statistics"]["response_details"].append({
                "user": "user_b",
                "status_code": resp_b.status,
                "content_length": self._get_data_size(resp_b),
                "content_type": resp_b.headers.get("content-type", "unknown"),
            })

            # 5️⃣ Decision logic with enhanced analysis
            resp_b_data = await resp_b.json() if "json" in resp_b.headers.get("content-type", "") else {}
            is_owner_a = self._evaluate_ownership(resp_a_data, user_a.user_id, jwt_info_a.get("subject"), jwt_info_a.get("roles"))
            is_owner_b = self._evaluate_ownership(resp_b_data, user_b.user_id, jwt_info_b.get("subject"), jwt_info_b.get("roles"))

            verdict = await self._responses_identical(resp_a, resp_b, custom_ignored, is_owner_a, is_owner_b)
            result["authorization_verdict"] = verdict

            # Risk score with all factors
            data_size = self._get_data_size(resp_a)
            exposed_fields = len(resp_a_data) if isinstance(resp_a_data, dict) else 0
            risk_score = self._calculate_risk_score(
                method, resp_a.status, resp_b.status, user_a.role, user_b.role, 
                resp_a.headers.get("content-type", ""), data_size, criticality, impact, 
                exploitability, exposed_fields, endpoint_sensitivity
            )
            result["risk_score"] = risk_score

            if verdict == "DENY" and not is_owner_b:
                result["status"] = "CONFIRMED_BOLA"
                result["severity"] = "CRITICAL"
                result["confidence"] = min(0.95 * risk_score / 10, 1.0)
                result["details"].append("User B accessed identical resource owned by
