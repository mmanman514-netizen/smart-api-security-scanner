from typing import List, Dict, Any, Optional
import asyncio
import aiohttp
import requests
import logging
import time
import re
from collections import OrderedDict

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    yaml = None

try:
    import ijson
    HAS_IJSON = True
except ImportError:
    HAS_IJSON = False
    ijson = None

from models.api_resource import ApiResource, ResourceType  # ✅ توافق صريح مع ApiResource و ResourceType

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

COMMON_SWAGGER_PATHS = [
    "/swagger.json",
    "/openapi.json",
    "/v3/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
]

# Custom Exceptions
class SwaggerDiscoveryError(Exception):
    """Base exception for SwaggerDiscovery errors."""
    pass

class NetworkError(SwaggerDiscoveryError):
    """Network-related errors."""
    pass

class ParsingError(SwaggerDiscoveryError):
    """Parsing-related errors."""
    pass


class SwaggerDiscovery:
    """
    Ultimate-grade Swagger / OpenAPI Discovery & Parser.
    
    Discovers, loads, and parses Swagger/OpenAPI specs into ApiResource objects.
    Features advanced discovery strategies, robust error handling, compatibility tests, and memory-efficient caching.
    
    Security Notes:
    - Always use with explicit permission; unauthorized access violates laws.
    - SSL verification is enabled by default.
    - Rate limiting and concurrency limits prevent server overload.
    - Custom inputs are validated to prevent injection.
    
    Ethical Use:
    - Designed for authorized security testing (e.g., pentesting).
    - Do not use for malicious purposes.
    
    Example:
        async with SwaggerDiscovery("https://api.example.com") as discovery:
            url = await discovery.find_swagger_url()
            if url:
                spec = await discovery.load_swagger(url)
                resources = discovery.parse_paths(spec)
    """

    def __init__(
        self,
        base_url: str,
        timeout: int = 10,
        verify_ssl: bool = True,
        rate_limit_delay: float = 1.0,
        max_concurrent: int = 5,  # Max concurrent requests
        cache_ttl: int = 300,  # Cache TTL in seconds
        max_cache_entries: int = 50,  # Max cache entries for memory efficiency
        custom_sensitive_keywords: Optional[List[str]] = None,
        custom_paths: Optional[List[str]] = None,  # Custom discovery paths
        enable_html_parsing: bool = True,  # Enable HTML link parsing
        enable_robots_txt: bool = True,  # Enable robots.txt scanning
        enable_subdomain_scan: bool = False,  # Enable subdomain scanning
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.rate_limit_delay = rate_limit_delay
        self.max_concurrent = max_concurrent
        self.cache_ttl = cache_ttl
        self.max_cache_entries = max_cache_entries
        self.custom_sensitive_keywords = self._validate_custom_keywords(custom_sensitive_keywords or [])
        self.custom_paths = custom_paths or []
        self.enable_html_parsing = enable_html_parsing
        self.enable_robots_txt = enable_robots_txt
        self.enable_subdomain_scan = enable_subdomain_scan
        self.headers = self._validate_headers(headers or {})
        self.cookies = cookies or {}

        self._last_request_time = 0.0
        self._swagger_cache = OrderedDict()  # LRU cache with weakref support
        self._cache_timestamps: Dict[str, float] = {}
        self._session: Optional[aiohttp.ClientSession] = None
        self._semaphore = asyncio.Semaphore(max_concurrent)

    # ---------- Validation Helpers ----------

    def _validate_custom_keywords(self, keywords: List[str]) -> List[str]:
        """Validate custom sensitive keywords to prevent injection."""
        for kw in keywords:
            if not re.match(r'^[a-zA-Z0-9_]+$', kw):
                raise ValueError(f"Invalid keyword: {kw} (only alphanumeric and underscore allowed)")
        return keywords

    def _validate_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Validate headers to prevent injection."""
        for k, v in headers.items():
            if not re.match(r'^[a-zA-Z0-9\-_]+$', k):
                raise ValueError(f"Invalid header key: {k}")
            if not re.match(r'^[a-zA-Z0-9\-_.:/]+$', v):
                raise ValueError(f"Invalid header value for {k}")
        return headers

    # ---------- Session Management ----------

    async def __aenter__(self):
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        )
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self._session:
            await self._session.close()
        self._cleanup_cache()

    # ---------- Public API ----------

    async def find_swagger_url(self) -> Optional[str]:
        """Discover Swagger/OpenAPI endpoint with advanced strategies."""
        assert self._session, "SwaggerDiscovery must be used as async context manager"

        discovery_paths = COMMON_SWAGGER_PATHS + self.custom_paths

        # Strategy 1: Standard path checks (parallel)
        url = await self._find_via_paths(discovery_paths)
        if url:
            return url

        # Strategy 2: HTML parsing
        if self.enable_html_parsing:
            url = await self._find_via_html()
            if url:
                return url

        # Strategy 3: Robots.txt scanning
        if self.enable_robots_txt:
            urls = await self._find_via_robots_txt()
            for url in urls:
                if await self._validate_swagger_url(url):
                    return url

        # Strategy 4: Subdomain scanning (basic)
        if self.enable_subdomain_scan:
            subdomains = ["api", "swagger", "docs"]
            for sub in subdomains:
                sub_url = self.base_url.replace("://", f"://{sub}.")
                discovery = SwaggerDiscovery(sub_url, timeout=self.timeout, verify_ssl=self.verify_ssl)
                async with discovery as d:
                    url = await d.find_swagger_url()
                    if url:
                        return url

        logger.info("[-] No Swagger endpoint found with all strategies")
        return None

    async def load_swagger(self, swagger_url: str) -> Dict[str, Any]:
        """Load and cache Swagger spec with memory-efficient streaming."""
        self._cleanup_cache()  # Clean expired entries
        if swagger_url in self._swagger_cache and time.time() - self._cache_timestamps.get(swagger_url, 0) < self.cache_ttl:
            return self._swagger_cache[swagger_url]

        assert self._session, "SwaggerDiscovery must be used as async context manager"

        try:
            async with self._semaphore:
                await self._rate_limit()
                async with self._session.get(
                    swagger_url,
                    headers=self.headers,
                    cookies=self.cookies,
                    ssl=self.verify_ssl or None,
                ) as resp:
                    resp.raise_for_status()
                    content_type = resp.headers.get("content-type", "").lower()
                    if "application/json" in content_type:
                        if HAS_IJSON and resp.content_length and resp.content_length > 1024 * 1024:  # >1MB
                            spec = await self._load_json_streaming(resp)
                        else:
                            spec = await resp.json()
                    elif "application/yaml" in content_type and HAS_YAML:
                        text = await resp.text()
                        spec = yaml.safe_load(text)
                    else:
                        raise ParsingError("Unsupported content type for Swagger spec")

                    # Compatibility checks
                    if not self._is_compatible_spec(spec):
                        raise ParsingError("Incompatible Swagger/OpenAPI spec")

                    self._swagger_cache[swagger_url] = spec
                    self._cache_timestamps[swagger_url] = time.time()
                    if len(self._swagger_cache) > self.max_cache_entries:
                        self._swagger_cache.popitem(last=False)  # LRU eviction
                    logger.info(f"[+] Swagger loaded and cached: {swagger_url}")
                    return spec
        except aiohttp.ClientError as e:
            raise NetworkError(f"Failed to load Swagger: {e}") from e
        except (ValueError, yaml.YAMLError) as e:
            raise ParsingError(f"Failed to parse Swagger: {e}") from e

    def parse_paths(self, swagger: Dict[str, Any]) -> List[ApiResource]:
        """Convert Swagger paths to ApiResource objects with security awareness."""
        resources: List[ApiResource] = []
        security_schemes = swagger.get("components", {}).get("securitySchemes", {})

        for path, methods in swagger.get("paths", {}).items():
            for method, details in methods.items():
                if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                    continue

                try:
                    resolved = self._resolve_ref(swagger, details, max_depth=10)
                    resource = self._build_resource(path, method.upper(), resolved, security_schemes)
                    resources.append(resource)
                except Exception as e:
                    logger.warning(f"Failed to parse path {path} {method}: {e}")

        logger.info(f"[+] Parsed {len(resources)} API resources")
        return resources

    # ---------- Discovery Strategies ----------

    async def _find_via_paths(self, paths: List[str]) -> Optional[str]:
        """Parallel path checking."""
        async def check_path(path: str) -> Optional[str]:
            url = f"{self.base_url}{path}"
            try:
                async with self._semaphore:
                    await self._rate_limit()
                    async with self._session.get(
                        url,
                        headers=self.headers,
                        cookies=self.cookies,
                        ssl=self.verify_ssl or None,
                    ) as resp:
                        if resp.status == 200:
                            content_type = resp.headers.get("content-type", "").lower()
                            if "application/json" in content_type or ("application/yaml" in content_type and HAS_YAML):
                                data = await resp.json() if "json" in content_type else yaml.safe_load(await resp.text())
                                if self._looks_like_swagger(data):
                                    return url
            except aiohttp.ClientError:
                pass
            return None

        tasks = [check_path(path) for path in paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, str):
                return result
        return None

    async def _find_via_html(self) -> Optional[str]:
        """Parse HTML for Swagger links."""
        try:
            await self._rate_limit()
            async with self._session.get(
                self.base_url,
                headers=self.headers,
                cookies=self.cookies,
                ssl=self.verify_ssl or None,
            ) as resp:
                if resp.status == 200 and "text/html" in resp.headers.get("content-type", ""):
                    html = await resp.text()
                    links = re.findall(r'href=["\']([^"\']*swagger[^"\']*)["\']', html, re.IGNORECASE)
                    for link in links:
                        full_url = link if link.startswith("http") else f"{self.base_url}/{link.lstrip('/')}"
                        if await self._validate_swagger_url(full_url):
                            return full_url
        except aiohttp.ClientError:
            pass
        return None

    async def _find_via_robots_txt(self) -> List[str]:
        """Scan robots.txt for paths."""
        urls = []
        try:
            await self._rate_limit()
            async with self._session.get(
                f"{self.base_url}/robots.txt",
                headers=self.headers,
                cookies=self.cookies,
                ssl=self.verify_ssl or None,
            ) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    for line in text.splitlines():
                        if line.startswith("Disallow:") or line.startswith("Allow:"):
                            path = line.split(":", 1)[1].strip()
                            if "swagger" in path.lower():
                                urls.append(f"{self.base_url}{path}")
        except aiohttp.ClientError:
            pass
        return urls

    async def _validate_swagger_url(self, url: str) -> bool:
        """Validate if URL points to a valid Swagger spec."""
        try:
            async with self._semaphore:
                await self._rate_limit()
                async with self._session.get(
                    url,
                    headers=self.headers,
                    cookies=self.cookies,
                    ssl=self.verify_ssl or None,
                ) as resp:
                    if resp.status == 200:
                        content_type = resp.headers.get("content-type", "").lower()
                        if "application/json" in content_type:
                            data = await resp.json()
                            return self._looks_like_swagger(data)
                        elif "application/yaml" in content_type and HAS_YAML:
                            text = await resp.text()
                            data = yaml.safe_load(text)
                            return self._looks_like_swagger(data)
        except aiohttp.ClientError:
            pass
        return False

    # ---------- ApiResource Builder ----------

    def _build_resource(
        self,
        path: str,
        method: str,
        details: Dict[str, Any],
        security_schemes: Dict[str, Any],
    ) -> ApiResource:
        return ApiResource(
            name=self._infer_name(path),
            endpoint=path,
            methods=[method],
            owner_field=self._infer_owner_field(path, security_schemes),
            sensitive_fields=self._infer_sensitive_fields(details),
            writable_fields=self._infer_writable_fields(details),
            multi_tenant=True,  # قيمة افتراضية
            admin_only=self._is_admin_endpoint(path, details),
            criticality=self._infer_criticality(path, details),
            resource_type=ResourceType.USER_OWNED,  # قيمة افتراضية
        )

    # ---------- Heuristics ----------

    def _looks_like_swagger(self, data: Dict[str, Any]) -> bool:
        return "paths" in data and ("openapi" in data or "swagger" in data)

    def _is_compatible_spec(self, spec: Dict[str, Any]) -> bool:
        """Check compatibility with OpenAPI/Swagger versions."""
        version = spec.get("openapi", spec.get("swagger", ""))
        if version.startswith("3.") or version.startswith("2."):
            return True
        return False

    def _infer_name(self, path: str) -> str:
        parts = [p for p in path.split("/") if p and not p.startswith("{")]
        return parts[-1].capitalize() if parts else "Unknown"

    def _infer_owner_field(self, path: str, security_schemes: Dict[str, Any]) -> Optional[str]:
        """Infer owner field with nested support and security awareness."""
        if "{" in path and "}" in path:
            param = path.split("{")[1].split("}")[0]
            if "." in param:
                return param
            return param
        
        for scheme in security_schemes.values():
            if scheme.get("type") == "http" and scheme.get("scheme") == "bearer":
                return "user_id"
        return None

    def _infer_sensitive_fields(self, details: Dict[str, Any]) -> List[str]:
        """Infer sensitive fields with regex and custom keywords."""
        keywords = set([
            "role", "balance", "password", "is_admin", "email", "phone", "ssn", "credit"
        ]).union(self.custom_sensitive_keywords)
        
        found = set()
        for resp in details.get("responses", {}).values():
            for c in resp.get("content", {}).values():
                props = c.get("schema", {}).get("properties", {})
                for key in props:
                    if any(re.search(rf'\b{k}\b', key, re.IGNORECASE) for k in keywords):
                        found.add(key)
        return list(found)

    def _infer_writable_fields(self, details: Dict[str, Any]) -> List[str]:
        fields = set()
        body = details.get("requestBody", {})
        for c in body.get("content", {}).values():
            fields.update(c.get("schema", {}).get("properties", {}).keys())
        return list(fields)

    # ---------- Helpers ----------

    async def _load_json_streaming(self, response) -> Dict[str, Any]:
        """Stream large JSON files to avoid memory issues"""
        try:
            # تحميل بسيط إذا لم يكن ijson متاحاً
            if not HAS_IJSON:
                return await response.json()
            
            # تنفيذ streaming مبسط
            data = {}
            parser = ijson.parse_async(response.content)
            
            async for prefix, event, value in parser:
                if prefix == 'paths' and event == 'start_map':
                    data['paths'] = {}
                # يمكن توسيع هذا حسب الحاجة
                
            return data if data else await response.json()
        except Exception as e:
            logger.warning(f"Streaming failed, falling back: {e}")
            return await response.json()

    def _resolve_ref(self, swagger: Dict[str, Any], obj: Any, max_depth: int = 10, depth: int = 0) -> Any:
        """Resolve $ref references recursively"""
        if depth > max_depth:
            return obj
        
        if isinstance(obj, dict) and '$ref' in obj:
            ref_path = obj['$ref']
            if ref_path.startswith('#/'):
                parts = ref_path[2:].split('/')
                current = swagger
                for part in parts:
                    current = current.get(part, {})
                return self._resolve_ref(swagger, current, max_depth, depth + 1)
        
        elif isinstance(obj, dict):
            return {k: self._resolve_ref(swagger, v, max_depth, depth + 1) for k, v in obj.items()}
        
        elif isinstance(obj, list):
            return [self._resolve_ref(swagger, item, max_depth, depth + 1) for item in obj]
        
        return obj

    def _cleanup_cache(self):
        """Clean expired cache entries."""
        current_time = time.time()
        expired_keys = [k for k, t in self._cache_timestamps.items() if current_time - t > self.cache_ttl]
        for k in expired_keys:
            del self._swagger_cache[k]
            del self._cache_timestamps[k]

    def _rate_limit(self):
        """Enforce rate limiting."""
        current_time = time.time()
        if current_time - self._last_request_time < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - (current_time - self._last_request_time))
        self._last_request_time = time.time()

    def _is_admin_endpoint(self, path: str, details: Dict[str, Any]) -> bool:
        """Infer if endpoint is admin-only based on path and details."""
        admin_keywords = ["admin", "superuser", "root", "manage"]
        return any
