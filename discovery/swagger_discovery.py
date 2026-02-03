# discovery/swagger_discovery.py

import requests
from typing import List, Dict, Any, Optional

from models.api_resource import ApiResource


COMMON_SWAGGER_PATHS = [
    "/swagger.json",
    "/openapi.json",
    "/v3/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
]


class SwaggerDiscovery:
    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    # 1️⃣ البحث عن Swagger
    def find_swagger_url(self) -> Optional[str]:
        for path in COMMON_SWAGGER_PATHS:
            url = f"{self.base_url}{path}"
            try:
                resp = requests.get(url, timeout=self.timeout)
                if resp.status_code == 200 and self._looks_like_swagger(resp.json()):
                    return url
            except Exception:
                continue
        return None

    # 2️⃣ تحميل Swagger
    def load_swagger(self, swagger_url: str) -> Dict[str, Any]:
        resp = requests.get(swagger_url, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    # 3️⃣ تحليل paths
    def parse_paths(self, swagger: Dict[str, Any]) -> List[ApiResource]:
        resources: List[ApiResource] = []
        paths = swagger.get("paths", {})

        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                    continue

                resource = self._build_resource(path, method.upper(), details)
                resources.append(resource)

        return resources

    # 4️⃣ بناء ApiResource
    def _build_resource(
        self,
        path: str,
        method: str,
        details: Dict[str, Any],
    ) -> ApiResource:
        name = self._infer_name(path)
        owner_field = self._infer_owner_field(path)
        sensitive_fields = self._infer_sensitive_fields(details)
        writable_fields = self._infer_writable_fields(details)

        return ApiResource(
            name=name,
            endpoint=path,
            methods=[method],
            owner_field=owner_field,
            sensitive_fields=sensitive_fields,
            writable_fields=writable_fields,
        )

    # ---------- Heuristics (ذكاء خفيف) ----------

    def _looks_like_swagger(self, data: Dict[str, Any]) -> bool:
        return "paths" in data and (
            "openapi" in data or "swagger" in data
        )

    def _infer_name(self, path: str) -> str:
        parts = [p for p in path.split("/") if p and not p.startswith("{")]
        return parts[-1].capitalize() if parts else "Unknown"

    def _infer_owner_field(self, path: str) -> Optional[str]:
        # مثال: /users/{id}
        if "{" in path and "}" in path:
            return path.split("{")[1].split("}")[0]
        return None

    def _infer_sensitive_fields(self, details: Dict[str, Any]) -> List[str]:
        fields = []
        responses = details.get("responses", {})
        for resp in responses.values():
            content = resp.get("content", {})
            for c in content.values():
                schema = c.get("schema", {})
                props = schema.get("properties", {})
                for key in props.keys():
                    if key.lower() in {"role", "balance", "password", "is_admin"}:
                        fields.append(key)
        return list(set(fields))

    def _infer_writable_fields(self, details: Dict[str, Any]) -> List[str]:
        fields = []
        body = details.get("requestBody", {})
        content = body.get("content", {})
        for c in content.values():
            schema = c.get("schema", {})
            props = schema.get("properties", {})
            fields.extend(props.keys())
        return list(set(fields))
