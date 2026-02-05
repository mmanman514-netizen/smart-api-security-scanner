import requests
import jwt
from typing import Dict, Any, Optional

from models.api_resource import ApiResource
from models.auth_context import AuthContext


class BOLAScanner:
    """
    Production-grade BOLA (IDOR) Scanner

    Features:
    - Ownership auto-detection
    - JWT decoding (optional)
    - Role-based BOLA detection
    - Response diffing
    - Confidence scoring
    - GET-only, non-destructive
    """

    def __init__(
        self,
        base_url: str,
        timeout: int = 5,
        enable_jwt_decoding: bool = True,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.enable_jwt_decoding = enable_jwt_decoding

    # ==========================================================
    # Public API
    # ==========================================================

    def scan(
        self,
        resource: ApiResource,
        user_a: AuthContext,
        user_b: AuthContext,
        object_id: str | int,
    ) -> Dict[str, Any]:

        result = {
            "resource": resource.endpoint,
            "object_id": object_id,
            "status": "UNKNOWN",
            "severity": "INFO",
            "confidence": 0.0,
            "details": [],
            "evidence": {},
        }

        url = self._build_url(resource.endpoint, object_id)

        # 1️⃣ Baseline — User A (owner)
        resp_a = self._send_get(url, user_a)
        if not resp_a:
            return self._fail(result, "ERROR", "Baseline request failed")

        if resp_a.status_code == 401:
            return self._fail(result, "INVALID_AUTH", "User A authentication failed")

        if resp_a.status_code in (403, 404):
            return self._fail(
                result,
                "OBJECT_PROTECTED",
                f"Owner access blocked ({resp_a.status_code})",
            )

        if resp_a.status_code != 200:
            return self._fail(
                result,
                "UNKNOWN_BASELINE",
                f"Unexpected baseline status {resp_a.status_code}",
            )

        # 2️⃣ Ownership auto-detection
        owner_id = self._detect_owner(resp_a.json())
        result["evidence"]["detected_owner_id"] = owner_id

        if owner_id and user_a.user_id and owner_id != user_a.user_id:
            return self._fail(
                result,
                "OWNER_MISMATCH",
                "Object does not belong to baseline user",
            )

        # 3️⃣ JWT decoding (optional)
        if self.enable_jwt_decoding:
            self._decode_and_attach_identity(user_a, result, "user_a")
            self._decode_and_attach_identity(user_b, result, "user_b")

        # 4️⃣ Attack simulation — User B
        resp_b = self._send_get(url, user_b)
        if not resp_b:
            return self._fail(result, "ERROR", "User B request failed")

        # 5️⃣ Decision logic
        if resp_b.status_code == 200:
            # Response diffing
            identical = self._responses_identical(resp_a, resp_b)

            if identical:
                result["status"] = "CONFIRMED_BOLA"
                result["severity"] = "CRITICAL"
                result["confidence"] = 0.95
                result["details"].append(
                    "User B accessed identical resource owned by User A"
                )
            else:
                result["status"] = "POTENTIAL_BOLA"
                result["severity"] = "HIGH"
                result["confidence"] = 0.75
                result["details"].append(
                    "User B accessed resource with partial data exposure"
                )

        elif resp_b.status_code in (401, 403, 404):
            result["status"] = "SECURE"
            result["severity"] = "LOW"
            result["confidence"] = 0.9
            result["details"].append(
                f"Access correctly denied ({resp_b.status_code})"
            )

        else:
            result["status"] = "UNKNOWN"
            result["details"].append(
                f"Unexpected status code {resp_b.status_code}"
            )

        # 6️⃣ Role-based BOLA check
        self._analyze_roles(user_a, user_b, result)

        return result

    # ==========================================================
    # Helpers
    # ==========================================================

    def _build_url(self, endpoint: str, object_id: str | int) -> str:
        endpoint = endpoint.replace("{id}", str(object_id))
        return f"{self.base_url}{endpoint}"

    def _send_get(self, url: str, auth: AuthContext):
        try:
            return requests.get(
                url,
                headers=auth.headers,
                cookies=auth.cookies,
                timeout=self.timeout,
            )
        except requests.RequestException:
            return None

    def _detect_owner(self, data: Dict[str, Any]) -> Optional[str]:
        """
        Attempts to auto-detect ownership fields
        """
        for key in ("owner_id", "user_id", "account_id"):
            if key in data:
                return str(data[key])
        return None

    def _decode_and_attach_identity(
        self,
        auth: AuthContext,
        result: Dict[str, Any],
        label: str,
    ):
        token = auth.jwt_token
        if not token:
            return

        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            result["evidence"][f"{label}_jwt"] = {
                "sub": payload.get("sub"),
                "role": payload.get("role"),
                "scope": payload.get("scope"),
            }
        except Exception:
            result["details"].append(f"Failed to decode JWT for {label}")

    def _responses_identical(self, r1, r2) -> bool:
        return r1.text == r2.text

    def _analyze_roles(
        self,
        user_a: AuthContext,
        user_b: AuthContext,
        result: Dict[str, Any],
    ):
        if not user_a.role or not user_b.role:
            return

        if user_b.role != user_a.role and result["status"] in (
            "CONFIRMED_BOLA",
            "POTENTIAL_BOLA",
        ):
            result["details"].append(
                f"Role-based access violation: {user_b.role} accessed {user_a.role} resource"
            )
            result["status"] = "ROLE_BASED_BOLA"
            result["severity"] = "CRITICAL"
            result["confidence"] = max(result["confidence"], 0.9)

    def _fail(self, result, status, message):
        result["status"] = status
        result["details"].append(message)
        result["confidence"] = 0.0
        return result
