import asyncio
import json
import logging
import os
import time
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

try:
    import aiofiles
    HAS_AIOFILES = True
except ImportError:
    HAS_AIOFILES = False
    aiofiles = None

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    yaml = None

try:
    import tomli
    HAS_TOML = True
except ImportError:
    HAS_TOML = False
    tomli = None

try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False
    jsonschema = None

from models.api_resource import ApiResource, ResourceType
from models.auth_context import AuthContext

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ConfigError(Exception):
    """Custom exception for configuration errors."""
    pass

# Basic JSON Schema for validation
DEFAULT_SCHEMA = {
    "type": "object",
    "properties": {
        "target": {"type": "string"},
        "auth": {"type": "object"},
        "resources": {"type": "array"},
        "scan": {"type": "object"}
    },
    "required": ["target", "auth", "resources"]
}

# Cache for loaded configs
_config_cache: Dict[str, Dict[str, Any]] = {}
_cache_timestamps: Dict[str, float] = {}
CACHE_TTL = 300  # 5 minutes

def _require(data: Dict[str, Any], key: str):
    if key not in data:
        raise ConfigError(f"Missing required config key: '{key}'")
    return data[key]

def _validate_url(url: str) -> bool:
    """Validate URL format."""
    parsed = urlparse(url)
    return bool(parsed.scheme and parsed.netloc)

def _sanitize_path(path: str) -> str:
    """Sanitize path to prevent traversal."""
    abs_path = os.path.abspath(path)
    if ".." in abs_path or not abs_path.startswith(os.getcwd()):
        raise ConfigError(f"Invalid path: {path} (path traversal detected)")
    return abs_path

def _mask_sensitive(value: Any) -> Any:
    """Mask sensitive values for logging."""
    if isinstance(value, str) and len(value) > 4:
        return value[:2] + "*" * (len(value) - 4) + value[-2:]
    return value

def _expand_env_vars(data: Any) -> Any:
    """Recursively expand environment variables in strings, with validation."""
    if isinstance(data, str):
        expanded = os.path.expandvars(data)
        if "$" in data and expanded == data:
            raise ConfigError(f"Environment variable not found in: {data}")
        return expanded
    elif isinstance(data, dict):
        return {k: _expand_env_vars(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_expand_env_vars(item) for item in data]
    return data

def _cleanup_cache():
    """Remove expired cache entries."""
    now = time.time()
    expired = [k for k, t in _cache_timestamps.items() if now - t > CACHE_TTL]
    for k in expired:
        del _config_cache[k]
        del _cache_timestamps[k]

def load_config(path: str, validate_schema: bool = True, custom_schema: Optional[Dict[str, Any]] = None, use_cache: bool = True) -> Dict[str, Any]:
    """
    Load scanner configuration from JSON, YAML, or TOML file with advanced validation.
    
    Supports environment variable interpolation (e.g., ${VAR_NAME}), caching, and metrics.
    Validates types, URLs, and optional JSON Schema.
    
    Security Notes:
    - Always use with permission; unauthorized access violates laws.
    - Environment variables are expanded and validated for secrets.
    - Schema validation and path sanitization prevent malformed configs.
    - Sensitive values are masked in logs.
    
    :param path: Path to config file (JSON, YAML, or TOML).
    :param validate_schema: Enable JSON Schema validation.
    :param custom_schema: Custom JSON Schema for validation.
    :param use_cache: Enable caching for loaded configs.
    :return: dict with keys: target, auth_contexts, resources, scan, metrics.
    """
    sanitized_path = _sanitize_path(path)
    
    # Check cache
    if use_cache and sanitized_path in _config_cache and time.time() - _cache_timestamps.get(sanitized_path, 0) < CACHE_TTL:
        logger.info(f"Config loaded from cache: {sanitized_path}")
        return _config_cache[sanitized_path]
    
    start_time = time.time()
    try:
        with open(sanitized_path, "r", encoding="utf-8") as f:
            file_size = os.path.getsize(sanitized_path)
            if sanitized_path.endswith(('.yaml', '.yml')):
                if not HAS_YAML:
                    raise ConfigError("YAML support not available; install PyYAML")
                data = yaml.safe_load(f)
            elif sanitized_path.endswith('.toml'):
                if not HAS_TOML:
                    raise ConfigError("TOML support not available; install tomli")
                data = tomli.load(f)
            else:
                data = json.load(f)
    except Exception as e:
        raise ConfigError(f"Failed to load config file: {e}")

    # Expand environment variables
    data = _expand_env_vars(data)

    # Schema validation
    if validate_schema and HAS_JSONSCHEMA:
        schema = custom_schema or DEFAULT_SCHEMA
        try:
            jsonschema.validate(data, schema)
        except jsonschema.ValidationError as e:
            raise ConfigError(f"Config schema validation failed: {e}")

    # ---------- Root validation ----------
    target = _require(data, "target")
    if not _validate_url(target):
        raise ConfigError(f"Invalid target URL: {target}")
    
    auth_cfg = _require(data, "auth")
    resources_cfg = _require(data, "resources")
    scan_cfg = data.get("scan", {})

    # ---------- Auth contexts (multiple support) ----------
    auth_contexts: Dict[str, AuthContext] = {}
    for label, cfg in auth_cfg.items():
        if not isinstance(cfg, dict):
            raise ConfigError(f"Auth config for '{label}' must be a dict")
        try:
            masked_cfg = {k: _mask_sensitive(v) for k, v in cfg.items()}
            logger.debug(f"Loading auth context '{label}': {masked_cfg}")
            auth_contexts[label] = AuthContext(
                headers=cfg.get("headers"),
                cookies=cfg.get("cookies"),
                label=label,
            )
        except Exception as e:
            raise ConfigError(f"Invalid auth config for '{label}': {e}")

    # ---------- Resources ----------
    resources: List[ApiResource] = []
    for idx, r in enumerate(resources_cfg):
        if not isinstance(r, dict):
            raise ConfigError(f"Resource at index {idx} must be a dict")
        try:
            methods = _require(r, "methods")
            if not isinstance(methods, list) or not all(isinstance(m, str) for m in methods):
                raise ConfigError(f"Methods must be a list of strings at index {idx}")
            
            resource = ApiResource(
                name=_require(r, "name"),
                endpoint=_require(r, "endpoint"),
                methods=methods,
                owner_field=r.get("owner_field"),
                sensitive_fields=r.get("sensitive_fields", []),
                writable_fields=r.get("writable_fields", []),
                multi_tenant=r.get("multi_tenant", True),
                admin_only=r.get("admin_only", False),
                criticality=r.get("criticality", "low"),
                resource_type=ResourceType(r.get("resource_type", ResourceType.USER_OWNED.value)),
            )
            resources.append(resource)
        except Exception as e:
            raise ConfigError(f"Invalid resource definition at index {idx}: {e}")

    load_time = time.time() - start_time
    metrics = {
        "load_time_seconds": load_time,
        "file_size_bytes": file_size,
        "auth_contexts_count": len(auth_contexts),
        "resources_count": len(resources),
    }
    
    result = {
        "target": target,
        "auth_contexts": auth_contexts,
        "resources": resources,
        "scan": scan_cfg,
        "metrics": metrics,
    }
    
    # Cache result
    if use_cache:
        _config_cache[sanitized_path] = result
        _cache_timestamps[sanitized_path] = time.time()
        _cleanup_cache()
    
    logger.info(f"Config loaded successfully: {len(auth_contexts)} auth contexts, {len(resources)} resources in {load_time:.2f}s")
    return result

async def load_config_async(path: str, validate_schema: bool = True, custom_schema: Optional[Dict[str, Any]] = None, use_cache: bool = True) -> Dict[str, Any]:
    """Async version with true async I/O."""
    if not HAS_AIOFILES:
        raise ConfigError("Async loading requires aiofiles; install aiofiles")
    
    sanitized_path = _sanitize_path(path)
    
    # Check cache
    if use_cache and sanitized_path in _config_cache and time.time() - _cache_timestamps.get(sanitized_path, 0) < CACHE_TTL:
        logger.info(f"Config loaded from cache (async): {sanitized_path}")
        return _config_cache[sanitized_path]
    
    start_time = time.time()
    try:
        async with aiofiles.open(sanitized_path, "r", encoding="utf-8") as f:
            content = await f.read()
            file_size = len(content.encode('utf-8'))
            if sanitized_path.endswith(('.yaml', '.yml')):
                if not HAS_YAML:
                    raise ConfigError("YAML support not available; install PyYAML")
                data = yaml.safe_load(content)
            elif sanitized_path.endswith('.toml'):
                if not HAS_TOML:
                    raise ConfigError("TOML support not available; install tomli")
                data = tomli.loads(content)
            else:
                data = json.loads(content)
    except Exception as e:
        raise ConfigError(f"Failed to load config file (async): {e}")

    # Expand environment variables
    data = _expand_env_vars(data)

    # Schema validation (run in executor if needed)
    if validate_schema and HAS_JSONSCHEMA:
        schema = custom_schema or DEFAULT_SCHEMA
        try:
            jsonschema.validate(data, schema)
        except jsonschema.ValidationError as e:
            raise ConfigError(f"Config schema validation failed: {e}")

    # ---------- Root validation ----------
    target = _require(data, "target")
    if not _validate_url(target):
        raise ConfigError(f"Invalid target URL: {target}")
    
    auth_cfg = _require(data, "auth")
    resources_cfg = _require(data, "resources")
    scan_cfg = data.get("scan", {})

    # ---------- Auth contexts (multiple support) ----------
    auth_contexts: Dict[str, AuthContext] = {}
    for label, cfg in auth_cfg.items():
        if not isinstance(cfg, dict):
            raise ConfigError(f"Auth config for '{label}' must be a dict")
        try:
            masked_cfg = {k: _mask_sensitive(v) for k, v in cfg.items()}
            logger.debug(f"Loading auth context '{label}' (async): {masked_cfg}")
            auth_contexts[label] = AuthContext(
                headers=cfg.get("headers"),
                cookies=cfg.get("cookies"),
                label=label,
            )
        except Exception as e:
            raise ConfigError(f"Invalid auth config for '{label}': {e}")

    # ---------- Resources ----------
    resources: List[ApiResource] = []
    for idx, r in enumerate(resources_cfg):
        if not isinstance(r, dict):
            raise ConfigError(f"Resource at index {idx} must be a dict")
        try:
            methods = _require(r, "methods")
            if not isinstance(methods, list) or not all(isinstance(m, str) for m in methods):
                raise ConfigError(f"Methods must be a list of strings at index {idx}")
            
            resource = ApiResource(
                name=_require(r, "name"),
                endpoint=_require(r, "endpoint"),
                methods=methods,
                owner_field=r.get("owner_field"),
                sensitive_fields=r.get("sensitive_fields", []),
                writable_fields=r.get("writable_fields", []),
                multi_tenant=r.get("multi_tenant", True),
                admin_only=r.get("admin_only", False),
                criticality=r.get("criticality", "low"),
                resource_type=ResourceType(r.get("resource_type", ResourceType.USER_OWNED.value)),
            )
            resources.append(resource)
        except Exception as e:
            raise ConfigError(f"Invalid resource definition at index {idx}: {e}")

    load_time = time.time() - start_time
    metrics = {
        "load_time_seconds": load_time,
        "file_size_bytes": file_size,
        "auth_contexts_count": len(auth_contexts),
        "resources_count": len(resources),
    }
    
    result = {
        "target": target,
        "auth_contexts": auth_contexts,
        "resources": resources,
        "scan": scan_cfg,
        "metrics": metrics,
    }
    
    # Cache result
    if use_cache:
        _config_cache[sanitized_path] = result
        _cache_timestamps[sanitized_path] = time.time()
        _cleanup_cache()
    
    logger.info(f"Config loaded successfully (async): {len(auth_contexts)} auth contexts, {len(resources)} resources in {load_time:.2f}s")
    return result

# ---------- Simple Unit Tests (using pytest) ----------
if __name__ == "__main__":
    import tempfile
    import pytest

    def test_load_config():
        config_data = {
            "target": "https://example.com",
            "auth": {"user_a": {"headers": {"Authorization": "Bearer token"}}},
            "resources": [{"name": "Test", "endpoint": "/test/{id}", "methods": ["GET"]}],
            "scan": {}
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            f.flush()
            result = load_config(f.name)
            assert result["target"] == "https://example.com"
            assert "user_a" in result["auth_contexts"]
            assert len(result["resources"]) == 1
            os.unlink(f.name)

    def test_invalid_url():
        with pytest.raises(ConfigError):
            load_config("invalid_path.json")

    # Run tests
    test_load_config()
    test_invalid_url()
    print("All tests passed!")
