from typing import List, Optional, Dict, Any, Callable
import re
import json
from functools import lru_cache
from urllib.parse import urlparse
import weakref

class ApiResource:
    def __init__(
        self,
        name: str,
        endpoint: str,
        methods: List[str],
        owner_field: Optional[str] = None,
        sensitive_fields: Optional[List[str]] = None,
        writable_fields: Optional[List[str]] = None,
        multi_tenant: bool = True,
        admin_only: bool = False,
        criticality: str = "low",  # low / medium / high
        default_jwt_algorithms: Optional[List[str]] = None,
        jwt_algorithm_validator: Optional[Callable[[str], bool]] = None,  # ديناميكي
        object_id_regex: Optional[str] = r'^[a-zA-Z0-9\-_.{}%@\+\=]+$',  # مرن لـ UUIDs وغيرها
    ):
        # Input validation (محسنة)
        if not name or not isinstance(name, str) or len(name.strip()) == 0:
            raise ValueError("Name must be a non-empty string")
        if not endpoint or "{id}" not in endpoint:
            raise ValueError("Endpoint must be a non-empty string containing '{id}' placeholder")
        if criticality not in ["low", "medium", "high"]:
            raise ValueError("Criticality must be 'low', 'medium', or 'high'")
        valid_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
        methods = [m.upper() for m in methods if m.upper() in valid_methods]
        if not methods:
            raise ValueError("At least one valid HTTP method must be provided")
        if owner_field and not re.match(r'^[a-zA-Z0-9_.]+$', owner_field):  # تحقق من سلامة المسار
            raise ValueError("Owner field must be a valid dot-separated path")

        self.name = name
        self.endpoint = endpoint
        self.methods = methods
        self.owner_field = owner_field
        self.sensitive_fields = sensitive_fields or []
        self.writable_fields = writable_fields or []
        self.multi_tenant = multi_tenant
        self.admin_only = admin_only
        self.criticality = criticality.lower()
        self.default_jwt_algorithms = default_jwt_algorithms or ["RS256", "HS256"]
        self.jwt_algorithm_validator = jwt_algorithm_validator or (lambda alg: alg in self.default_jwt_algorithms)  # ديناميكي
        self.object_id_regex = object_id_regex

    def build_url(self, base_url: str, object_id: Any) -> str:
        """Construct full URL with base_url and object_id validation to prevent injection."""
        parsed = urlparse(base_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid base_url: must be a valid URL with scheme and netloc")
        if not re.match(self.object_id_regex, str(object_id)):
            raise ValueError("Invalid object_id: does not match allowed pattern")
        return f"{base_url.rstrip('/')}{self.endpoint.replace('{id}', str(object_id))}"

    def get_owner_value(self, data: Dict[str, Any]) -> Optional[str]:
        """Extract owner value from nested data with caching for performance."""
        data_hash = hash(json.dumps(data, sort_keys=True))
        return self._get_owner_value_cached(data_hash, data)

    @lru_cache(maxsize=128)
    def _get_owner_value_cached(self, data_hash: int, data: Dict[str, Any]) -> Optional[str]:
        """Cached internal implementation."""
        return self._get_owner_value_impl(data)

    def _get_owner_value_impl(self, data: Dict[str, Any]) -> Optional[str]:
        """Internal implementation for owner extraction."""
        if not self.owner_field or not data:
            return None
        return self._navigate_path(data, self.owner_field.split("."), 0, 10)

    def _navigate_path(self, data: Any, keys: List[str], depth: int = 0, max_depth: int = 10) -> Optional[str]:
        """Navigate path with wildcard support and depth limit for deep search."""
        if depth > max_depth:
            return None
        if not keys:
            return str(data) if data is not None else None
        k = keys[0]
        if k == "*":  # بحث عميق في القائمة
            if isinstance(data, list):
                for item in data:
                    result = self._navigate_path(item, keys[1:], depth + 1, max_depth)
                    if result is not None:
                        return result
            return None
        elif isinstance(data, dict):
            return self._navigate_path(data.get(k), keys[1:], depth + 1, max_depth)
        elif isinstance(data, list) and k.isdigit():
            index = int(k)
            if 0 <= index < len(data):
                return self._navigate_path(data[index], keys[1:], depth + 1, max_depth)
        return None

    def exposed_fields_count(self, data: Dict[str, Any]) -> int:
        """Count sensitive fields present in the response with nested support."""
        if not data:
            return 0
        count = 0
        for f in self.sensitive_fields:
            if self._field_exists(data, f):
                count += 1
        return count

    def _field_exists(self, data: Dict[str, Any], field: str, max_depth: int = 10) -> bool:
        """Check if nested field exists with improved list handling, wildcard, and depth limit."""
        keys = field.split(".")
        return self._navigate_exists(data, keys, 0, max_depth)

    def _navigate_exists(self, data: Any, keys: List[str], depth: int, max_depth: int) -> bool:
        """Navigate for existence with wildcard deep search and depth limit, supporting multiple wildcards in different levels."""
        if depth > max_depth:
            return False
        if not keys:
            return data is not None
        k = keys[0]
        if k == "*":  # بحث عميق في القائمة، مع دعم multiple wildcards
            if isinstance(data, list):
                return any(self._navigate_exists(item, keys[1:], depth + 1, max_depth) for item in data)
            return False
        elif isinstance(data, dict):
            return self._navigate_exists(data.get(k), keys[1:], depth + 1, max_depth)
        elif isinstance(data, list) and k.isdigit():
            index = int(k)
            if 0 <= index < len(data):
                return self._navigate_exists(data[index], keys[1:], depth + 1, max_depth)
        return False

    def is_sensitive(self, field_name: str) -> bool:
        """Check if a field is sensitive."""
        return field_name in self.sensitive_fields

    def validate_jwt_algorithm(self, algorithm: str) -> bool:
        """Validate JWT algorithm dynamically."""
        return self.jwt_algorithm_validator(algorithm)

    def __repr__(self):
        return (
            f"<ApiResource name={self.name} endpoint={self.endpoint} "
            f"methods={self.methods} owner_field={self.owner_field} "
            f"sensitive_fields={self.sensitive_fields} "
            f"multi_tenant={self.multi_tenant} admin_only={self.admin_only} "
            f"criticality={self.criticality} jwt_validator={self.jwt_algorithm_validator.__name__ if callable(self.jwt_algorithm_validator) else 'default'} "
            f"object_id_regex={self.object_id_regex}>"
                               )
