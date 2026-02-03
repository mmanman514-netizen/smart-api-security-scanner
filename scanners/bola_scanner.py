# scanners/bola_scanner.py

import requests
from typing import Dict

from models.api_resource import ApiResource
from models.auth_context import AuthContext


class BOLAScanner:
    """
    Professional BOLA (IDOR) Scanner
    GET-only, non-destructive, user-vs-user testing
    """

    def __init__(self, base_url: str, timeout: int = 5):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def scan(
        self,
        resource: ApiResource,
        user_a: AuthContext,
        user_b: AuthContext,
        object_id: str | int,
    ) -> Dict:
        """
        Scan a single ApiResource for BOLA vulnerability
        """

        result = {
            "resource": resource.endpoint,
            "object_id": object_id,
            "status": "UNKNOWN",
            "details": [],
        }

        # 1️⃣ Build target URL
        url = self._build_url(resource.endpoint, object_id)

        # 2️⃣ User A request (baseline)
        resp_a = self._send_get(url, user_a)

        if resp_a is None or resp_a.status_code != 200:
            result["status"] = "CANNOT_BASELINE"
            result["details"].append(
                "User A could not access own resource"
            )
            return result

        # 3️⃣ User B request (attack simulation)
        resp_b = self._send_get(url, user_b)

        if resp_b is None:
            result["status"] = "ERROR"
            return result

        # 4️⃣ Analyze result
        if resp_b.status_code == 200:
            result["status"] = "CONFIRMED_BOLA"
            result["details"].append(
                "User B accessed resource owned by User A"
            )
        elif resp_b.status_code in (403, 404):
            result["status"] = "SECURE"
            result["details"].append(
                "Access correctly denied for User B"
            )
        else:
            result["status"] = "POTENTIAL_BOLA"
            result["details"].append(
                f"Unexpected status code: {resp_b.status_code}"
            )

        return result

    # -------------------- helpers --------------------

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
