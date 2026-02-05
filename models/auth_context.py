from typing import Optional, Dict, Any, List
import re
import base64
import json
import uuid
from functools import lru_cache
import binascii

try:
    import jwt as jwt_lib
    from jwt.exceptions import InvalidTokenError, ExpiredSignatureError, InvalidSignatureError
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    jwt_lib = None
    InvalidTokenError = Exception
    ExpiredSignatureError = Exception
    InvalidSignatureError = Exception


class AuthContext:
    """
    Represents authentication context for a user.
    Supports header-based, cookie-based, API key, and token-based authentication.
    Designed for extensibility to support OAuth or other auth methods.

    Security Notes:
    - JWT signature verification is optional and skipped if no public_key is provided. For sensitive projects, always provide public_key and use force_signature_verification=True in is_token_expired().
    - API key permissive mode allows any alphanumeric string >=10; this is convenient for testing but poses a security risk in sensitive projects. Use strict_api_key_validation=True or force_strict_api_key=True for UUID/Base64 only.

    Example usage with ApiResource:
        from models.api_resource import ApiResource
        from models.auth_context import AuthContext

        resource = ApiResource(name="User Profile", endpoint="/users/{id}", methods=["GET"])
        auth = AuthContext(headers={"Authorization": "Bearer eyJ..."}, label="user_a")
        # Use auth in BOLA scanner
    """

    def __init__(
        self,
        headers: Optional[Dict[str, str]] = None,  # HTTP headers like {'Authorization': 'Bearer <token>'} or {'X-API-Key': '<key>'}
        cookies: Optional[Dict[str, str]] = None,  # Session or JWT cookies like {'session_id': '<id>'}
        label: str = "unknown",  # Identifier for the user context, e.g., 'user_a' or 'user_b'
        api_key: Optional[str] = None,  # API key string for key-based auth
        token: Optional[str] = None,  # Direct token string for token-based auth
        validate_values: bool = False,  # Optional validation for headers, cookies, token, and api_key values
        jwt_public_key: Optional[str] = None,  # Public key for JWT signature verification (optional)
        jwt_algorithms: Optional[List[str]] = None,  # Dynamic list of JWT algorithms (default: ["RS256", "HS256"])
        mask_sensitive: bool = True,  # Mask sensitive data in to_dict and __repr__
        strict_api_key_validation: bool = False,  # If True, restrict API key to UUID or Base64 only
        force_strict_api_key: bool = False,  # Force strict API key validation for sensitive projects
    ):
        """
        Initialize AuthContext.

        :param headers: HTTP headers dictionary. Example: {'Authorization': 'Bearer eyJ...'}.
        :param cookies: Cookies dictionary. Example: {'session_id': 'abc123'}.
        :param label: Label for the context, e.g., 'user_a'.
        :param api_key: API key string for key-based authentication.
        :param token: Token string for token-based authentication.
        :param validate_values: If True, validate that all values in headers and cookies are strings, and check token/api_key formats.
        :param jwt_public_key: Public key for JWT signature verification (optional, for full security).
        :param jwt_algorithms: List of JWT algorithms to support (default: ["RS256", "HS256"]).
        :param mask_sensitive: If True, mask sensitive data in to_dict and __repr__.
        :param strict_api_key_validation: If True, restrict API key validation to UUID or Base64 only.
        :param force_strict_api_key: Force strict API key validation for sensitive projects.
        """
        if validate_values:
            if headers:
                for k, v in headers.items():
                    if not isinstance(v, str):
                        raise ValueError(f"Header value for '{k}' must be a string")
            if cookies:
                for k, v in cookies.items():
                    if not isinstance(v, str):
                        raise ValueError(f"Cookie value for '{k}' must be a string")
            if token and not self._is_valid_jwt(token, jwt_public_key, jwt_algorithms):
                raise ValueError("Token must be a valid JWT format")
            if api_key and not self._is_valid_api_key(api_key, strict_api_key_validation or force_strict_api_key):
                raise ValueError("API key must be a valid format")

        self.headers = headers or {}
        self.cookies = cookies or {}
        self.label = label
        self.api_key = api_key
        self.token = token
        self.jwt_public_key = jwt_public_key
        self.jwt_algorithms = jwt_algorithms or ["RS256", "HS256"]
        self.mask_sensitive = mask_sensitive
        self.strict_api_key_validation = strict_api_key_validation
        self.force_strict_api_key = force_strict_api_key

    def is_authenticated(self) -> bool:
        """Check if the context has any authentication data."""
        return bool(self.headers or self.cookies or self.api_key or self.token)

    def get_auth_header(self) -> Optional[str]:
        """Get the 'Authorization' header if present. This returns only the Authorization header, not other auth types."""
        return self.headers.get('Authorization')

    def get_header(self, name: str) -> Optional[str]:
        """Get a specific header by name."""
        return self.headers.get(name)

    def get_cookie(self, name: str) -> Optional[str]:
        """Get a specific cookie by name."""
        return self.cookies.get(name)

    def all_headers(self) -> Dict[str, str]:
        """Return all headers as a dictionary."""
        return self.headers.copy()

    def all_cookies(self) -> Dict[str, str]:
        """Return all cookies as a dictionary."""
        return self.cookies.copy()

    def to_dict(self) -> Dict[str, Any]:
        """Convert the entire context to a dictionary for JSON serialization or testing."""
        data = {
            "headers": self.headers,
            "cookies": self.cookies,
            "label": self.label,
            "api_key": self.api_key,
            "token": self.token,
        }
        if self.mask_sensitive:
            if data["api_key"]:
                data["api_key"] = self._mask_string(data["api_key"])
            if data["token"]:
                data["token"] = self._mask_string(data["token"])
        return data

    def is_token_expired(self, verify_signature: bool = False, force_signature_verification: bool = False) -> bool:
        """Check if the token is expired, with optional signature verification. For sensitive projects, set force_signature_verification=True and provide jwt_public_key."""
        if not self.token or not JWT_AVAILABLE:
            return False
        try:
            options = {"verify_exp": True}
            if (verify_signature or force_signature_verification) and self.jwt_public_key:
                jwt_lib.decode(self.token, self.jwt_public_key, algorithms=self.jwt_algorithms, options=options)
            else:
                jwt_lib.decode(self.token, options={"verify_signature": False, "verify_exp": True})
            return False  # If no exception, not expired
        except ExpiredSignatureError:
            return True
        except InvalidTokenError:
            return False  # Invalid, but not necessarily expired

    def _mask_string(self, s: str) -> str:
        """Mask sensitive string for logging."""
        if len(s) <= 4:
            return "***"
        return s[:2] + "*" * (len(s) - 4) + s[-2:]

    @lru_cache(maxsize=128)
    def _is_valid_jwt(self, token: str, public_key: Optional[str] = None, algorithms: Optional[List[str]] = None) -> bool:
        """Check if token is a valid JWT format with Base64 decode and optional signature verification."""
        if not JWT_AVAILABLE:
            return False
        parts = token.split('.')
        if len(parts) != 3:
            return False
        try:
            # Decode header and payload
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '==').decode('utf-8'))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '==').decode('utf-8'))
            if not (isinstance(header, dict) and isinstance(payload, dict)):
                return False
            # Optional signature verification with sorted algorithms and public_key hash to avoid cache collision
            if public_key and algorithms:
                jwt_lib.decode(token, public_key, algorithms=sorted(algorithms))
            return True
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError, InvalidTokenError, InvalidSignatureError):
            return False

    def _is_valid_api_key(self, key: str, strict: bool = False) -> bool:
        """Check if key is a valid API key format."""
        if strict:
            # UUID or Base64 only
            if self._is_valid_uuid(key):
                return True
            try:
                base64.b64decode(key, validate=True)
                return True
            except binascii.Error:  # Specific exception for better performance
                return False
        else:
            # Permissive: UUID, Base64, or alphanumeric >=10
            if self._is_valid_uuid(key):
                return True
            try:
                base64.b64decode(key, validate=True)
                return True
            except binascii.Error:
                pass
            return bool(re.match(r'^[a-zA-Z0-9]{10,}$', key))

    def _is_valid_uuid(self, key: str) -> bool:
        """Check if key is a valid UUID format using uuid library."""
        try:
            uuid.UUID(key)
            return True
        except ValueError:
            return False

    def __repr__(self):
        auth_status = self.is_authenticated()
        if self.mask_sensitive:
            masked_token = self._mask_string(self.token) if self.token else None
            masked_key = self._mask_string(self.api_key) if self.api_key else None
            return f"<AuthContext {self.label} authenticated={auth_status} token={masked_token} api_key={masked_key}>"
        return f"<AuthContext {self.label} authenticated={auth_status}>"
