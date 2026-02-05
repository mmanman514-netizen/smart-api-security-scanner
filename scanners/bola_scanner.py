import requests
import jwt
import json
import logging
import time
import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional, List
from requests.exceptions import RequestException

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False
    logging.warning("BeautifulSoup not installed. HTML parsing will be limited.")

from models.api_resource import ApiResource
from models.auth_context import AuthContext

# إعداد Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BOLAScanner:
    """
    Elite-grade BOLA (IDOR) Scanner

    Features:
    - Ownership auto-detection
    - JWT decoding with signature validation (optional)
    - Role-based BOLA detection
    - Response diffing (content, headers, cookies) for all HTTP methods
    - Support for non-JSON data (XML, HTML, plain text)
    - Detailed reporting with statistics
    - Non-destructive by default (GET), but supports other methods

    تحذير: هذه الأداة مخصصة للاختبار الأمني المصرح به فقط. الاستخدام غير القانوني قد ينتهك القوانين.
    """

    def __init__(
        self,
        base_url: str,
        timeout: int = 10,
        enable_jwt_decoding: bool = True,
        jwt_secret_or_key: Optional[str] = None,
        proxies: Optional[Dict[str, str]] = None,
        max_retries: int = 3,
    ):
        """
        Initialize the BOLA Scanner.
        
        :param base_url: The base URL for the target API.
        :param timeout: Timeout for each request (in seconds).
        :param enable_jwt_decoding: Whether to enable JWT decoding and validation.
        :param jwt_secret_or_key: Secret or public key for JWT validation (optional).
        :param proxies: Proxies for requests (optional).
        :param max_retries: Maximum number of retries for failed requests.
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.enable_jwt_decoding = enable_jwt_decoding
        self.jwt_secret_or_key = jwt_secret_or_key
        self.proxies = proxies
        self.max_retries = max_retries

    def scan(
        self,
        resource: ApiResource,
        user_a: AuthContext,
        user_b: AuthContext,
        object_id: str | int,
        method: str = "GET",  # دعم جميع طرق HTTP
        request_body: Optional[Dict[str, Any]] = None,  # لـ POST/PUT
    ) -> Dict[str, Any]:
        """
        Scan a single API resource for BOLA vulnerability using any HTTP method.
        
        :param resource: The resource to be scanned.
        :param user_a: The first user (owner).
        :param user_b: The second user (attacker).
        :param object_id: The ID of the object being tested.
        :param method: HTTP method (GET, POST, PUT, DELETE, etc.).
        :param request_body: Request body for methods like POST/PUT (optional).
        :return: A dictionary containing the scan results with detailed statistics.
        """
        result = {
            "resource": resource.endpoint,
            "object_id": object_id,
            "method": method.upper(),
            "status": "UNKNOWN",
            "severity": "INFO",
            "confidence": 0.0,
            "details": [],
            "evidence": {},
            "statistics": {  # تقارير تفصيلية
                "vulnerabilities_found": 0,
                "responses_analyzed": 0,
                "response_details": [],
                "scan_summary": "",
            },
        }

        # التحقق من صحة المدخلات
        if "{id}" not in resource.endpoint:
            return self._fail(result, "INVALID_INPUT", "Endpoint must contain '{id}' placeholder")
        if not str(object_id).strip():
            return self._fail(result, "INVALID_INPUT", "Object ID cannot be empty")
        if method.upper() not in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]:
            return self._fail(result, "INVALID_INPUT", f"Unsupported HTTP method: {method}")

        url = self._build_url(resource.endpoint, object_id)
        logger.info(f"Scanning URL: {url} with method: {method.upper()}")

        # 1️⃣ Baseline – User A (owner)
        resp_a = self._send_request(url, method, user_a, request_body, result)
        if not resp_a:
            result["statistics"]["scan_summary"] = "Failed to get baseline response."
            return result

        result["statistics"]["responses_analyzed"] += 1
        result["statistics"]["response_details"].append({
            "user": "user_a",
            "status_code": resp_a.status_code,
            "content_length": len(resp_a.content),
            "content_type": resp_a.headers.get("content-type", "unknown"),
        })

        # Handle 401, 403, 404 errors
        if resp_a.status_code == 401:
            return self._fail(result, "INVALID_AUTH", "User A authentication failed")
        
        if resp_a.status_code in (403, 404):
            return self._fail(result, "OBJECT_PROTECTED", f"Owner access blocked ({resp_a.status_code})")
        
        if resp_a.status_code not in (200, 201, 202):  # قبول رموز نجاح شائعة
            return self._fail(result, "UNKNOWN_BASELINE", f"Unexpected baseline status {resp_a.status_code}")

        # 2️⃣ Ownership auto-detection
        owner_id = self._detect_owner(resp_a)
        result["evidence"]["detected_owner_id"] = owner_id

        if owner_id and user_a.user_id and owner_id != user_a.user_id:
            return self._fail(result, "OWNER_MISMATCH", "Object does not belong to baseline user")

        # 3️⃣ JWT decoding (optional)
        if self.enable_jwt_decoding:
            self._decode_and_attach_identity(user_a, result, "user_a")
            self._decode_and_attach_identity(user_b, result, "user_b")

        # 4️⃣ Attack simulation – User B
        resp_b = self._send_request(url, method, user_b, request_body, result)
        if not resp_b:
            result["statistics"]["scan_summary"] = "Failed to get attacker response."
            return result

        result["statistics"]["responses_analyzed"] += 1
        result["statistics"]["response_details"].append({
            "user": "user_b",
            "status_code": resp_b.status_code,
            "content_length": len(resp_b.content),
            "content_type": resp_b.headers.get("content-type", "unknown"),
        })

        # 5️⃣ Decision logic with deep analysis
        if resp_b.status_code in (200, 201, 202):
            identical = self._responses_identical(resp_a, resp_b)

            if identical:
                result["status"] = "CONFIRMED_BOLA"
                result["severity"] = "CRITICAL"
                result["confidence"] = 0.95
                result["details"].append("User B accessed identical resource owned by User A")
                result["statistics"]["vulnerabilities_found"] += 1
            else:
                result["status"] = "POTENTIAL_BOLA"
                result["severity"] = "HIGH"
                result["confidence"] = 0.75
                result["details"].append("User B accessed resource with partial data exposure")
                result["statistics"]["vulnerabilities_found"] += 1

        elif resp_b.status_code in (401, 403, 404):
            result["status"] = "SECURE"
            result["severity"] = "LOW"
            result["confidence"] = 0.9
            result["details"].append(f"Access correctly denied ({resp_b.status_code})")
        else:
            result["status"] = "UNKNOWN"
            result["details"].append(f"Unexpected status code {resp_b.status_code}")

        # 6️⃣ Role-based BOLA check
        self._analyze_roles(user_a, user_b, result)

        # إنهاء الإحصائيات
        result["statistics"]["scan_summary"] = f"Scan completed. Vulnerabilities: {result['statistics']['vulnerabilities_found']}, Responses analyzed: {result['statistics']['responses_analyzed']}."

        logger.info(f"Scan completed for {url}: Status={result['status']}, Confidence={result['confidence']}")
        return result

    # ==========================================================
    # Helpers
    # ==========================================================

    def _build_url(self, endpoint: str, object_id: str | int) -> str:
        """Construct the full URL by replacing object_id placeholder."""
        endpoint = endpoint.replace("{id}", str(object_id))
        return f"{self.base_url}{endpoint}"

    def _send_request(self, url: str, method: str, auth: AuthContext, body: Optional[Dict[str, Any]], result: Dict[str, Any]):
        """Send HTTP request with proper authentication and retries."""
        for attempt in range(self.max_retries):
            try:
                response = requests.request(
                    method.upper(),
                    url,
                    headers=auth.headers,
                    cookies=auth.cookies,
                    json=body if body else None,  # افتراض JSON للـ body
                    timeout=self.timeout,
                    proxies=self.proxies,
                )
                response.raise_for_status()
                logger.info(f"Request successful for {url} with {method.upper()}")
                return response
            except RequestException as e:
                error_msg = f"Request failed (attempt {attempt+1}/{self.max_retries}): {str(e)}"
                logger.warning(error_msg)
                result["details"].append(error_msg)
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
        return None

    def _detect_owner(self, response) -> Optional[str]:
        """Attempt to auto-detect the owner from response content."""
        content_type = response.headers.get("content-type", "").lower()
        if "application/json" in content_type:
            try:
                data = response.json()
                for key in ("owner_id", "user_id", "account_id", "creator_id", "author_id"):
                    if key in data:
                        return str(data[key])
            except ValueError:
                pass
        return None

    def _decode_and_attach_identity(self, auth: AuthContext, result: Dict[str, Any], label: str):
        """Decode the JWT and attach identity information to the result."""
        token = auth.jwt_token
        if not token:
            return
        
        try:
            if self.jwt_secret_or_key:
                payload = jwt.decode(
                    token,
                    self.jwt_secret_or_key,
                    algorithms=["HS256", "RS256", "ES256"],
                    options={"verify_exp": True}
                )
            else:
                payload = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
            
            result["evidence"][f"{label}_jwt"] = {
                "sub": payload.get("sub"),
                "role": payload.get("role"),
                "scope": payload.get("scope"),
            }
            logger.info(f"JWT decoded successfully for {label}")
        except jwt.ExpiredSignatureError:
            result["details"].append(f"JWT expired for {label}")
        except jwt.InvalidTokenError:
            result["details"].append(f"Invalid JWT for {label}")
        except Exception as e:
            result["details"].append(f"Failed to decode JWT for {label}: {str(e)}")

    def _responses_identical(self, r1, r2) -> bool:
        """Compare responses deeply: content, headers, and cookies."""
        # مقارنة الـ headers (تجاهل headers غير حساسة)
        ignored_headers = {"date", "server", "x-powered-by", "connection", "keep-alive"}
        headers1 = {k.lower(): v for k, v in r1.headers.items() if k.lower() not in ignored_headers}
        headers2 = {k.lower(): v for k, v in r2.headers.items() if k.lower() not in ignored_headers}
        if headers1 != headers2:
            return False
        
        # مقارنة الـ cookies
        if dict(r1.cookies) != dict(r2.cookies):
            return False
        
        # مقارنة المحتوى بناءً على نوعه
        content_type = r1.headers.get("content-type", "").lower()
        if "application/json" in content_type:
            try:
                json_r1 = r1.json()
                json_r2 = r2.json()
                return json.dumps(json_r1, sort_keys=True) == json.dumps(json_r2, sort_keys=True)
            except ValueError:
                return False
        elif "application/xml" in content_type or "text/xml" in content_type:
            try:
                root1 = ET.fromstring(r1.text)
                root2 = ET.fromstring(r2.text)
                return ET.tostring(root1, encoding='unicode') == ET.tostring(root2, encoding='unicode')
            except ET.ParseError:
                return r1.text.strip() == r2.text.strip()
        elif "text/html" in content_type:
            if HAS_BS4:
                soup1 = BeautifulSoup(r1.text, 'html.parser')
                soup2 = BeautifulSoup(r2.text, 'html.parser')
                return soup1.get_text().strip() == soup2.get_text().strip()
            else:
                return r1.text.strip() == r2.text.strip()
        else:  # نصوص عادية أو غير معروفة
            return r1.text.strip() == r2.text.strip()

    def _analyze_roles(self, user_a: AuthContext, user_b: AuthContext, result: Dict[str, Any]):
        """Analyze the roles of users to detect any role-based BOLA."""
        if user_a.role and user_b.role:
            if user_b.role != user_a.role and result["status"] in ("CONFIRMED_BOLA", "POTENTIAL_BOLA"):
                result["details"].append(f"Role-based access violation: {user_b.role} accessed {user_a.role} resource")
                result["status"] = "ROLE_BASED_BOLA"
                result["severity"] = "CRITICAL"
                result["confidence"] = max(result["confidence"], 0.9)
                result["statistics"]["vulnerabilities_found"] += 1

    def _fail(self, result, status, message):
        """Helper to finalize the result in case of failure."""
        result["status"] = status
        result["details"].append(message)
        result["confidence"] = 0.0
        return result
