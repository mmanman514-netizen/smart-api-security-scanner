"""
محمل تكوين API Security Scanner مع دعم كامل لـ v2.1
"""

import json
import yaml
import os
import re
import sys
from typing import Dict, Any, List, Optional
from pathlib import Path
import uuid
import random
import string

class ConfigLoader:
    """محمل التكوين المحسن مع دعم v2.1"""
    
    @staticmethod
    def load(file_path: str, validate: bool = True) -> Dict[str, Any]:
        """
        تحميل ملف التكوين بدعم الإصدارات المختلفة
        
        Args:
            file_path: مسار ملف التكوين
            validate: إذا كان True، يتحقق من صحة التكوين
            
        Returns:
            التكوين المحمل والمحوّل
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {file_path}")
        
        config = ConfigLoader._load_raw_config(file_path)
        
        # التحقق من الإصدار
        version = config.get("version", "1.0")
        
        if version.startswith("2."):
            print(f"📦 Loading v{version} configuration...")
            config = ConfigLoader._convert_v2_to_v1(config)
        
        if validate:
            ConfigLoader._validate_config(config)
        
        return config

    @staticmethod
    def _load_raw_config(file_path: str) -> Dict[str, Any]:
        """قراءة ملف التكوين بشكل مباشر وبصيغة صارمة."""
        path = Path(file_path)

        if path.suffix.lower() in ['.json']:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Strict JSON only (comments are not supported)
                return json.load(f)

        if path.suffix.lower() in ['.yaml', '.yml']:
            with open(file_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)

        raise ValueError("Unsupported config format. Use JSON or YAML.")
    
    @staticmethod
    def _convert_v2_to_v1(config_v2: Dict[str, Any]) -> Dict[str, Any]:
        """تحويل تكوين v2.1 إلى صيغة متوافقة مع النظام"""
        
        # التكوين الأساسي v1
        config_v1 = {
            "api": {
                "base_url": config_v2.get("target", {}).get("base_url", ""),
                "validate_ssl": config_v2.get("target", {}).get("validate_ssl", True),
                "default_headers": config_v2.get("target", {}).get("default_headers", {})
            },
            "auth": {
                "strategy": config_v2.get("authentication", {}).get("strategy", "env_variables")
            },
            "scanners": {
                "bola": {
                    "rate_limit": config_v2.get("scan_configuration", {})
                                   .get("performance", {})
                                   .get("requests_per_second", 2.0),
                    "max_concurrent": config_v2.get("scan_configuration", {})
                                      .get("performance", {})
                                      .get("max_concurrent", 5),
                    "timeout": config_v2.get("scan_configuration", {})
                                   .get("performance", {})
                                   .get("timeout_seconds", 30),
                    "strict_owner": True,
                    "id_patterns": ConfigLoader._extract_id_patterns(config_v2),
                    "user_pairs": ConfigLoader._extract_user_pairs(config_v2)
                },
                "rate_limit": {
                    "max_concurrent": 10,
                    "threshold_requests": 100,
                    "time_window": 60
                },
                "injection": {
                    "payloads_file": "payloads/sqli.txt",
                    "max_concurrent": 3
                }
            },
            "logging": {
                "level": "INFO",
                "file": "scanner.log",
                "console": True
            },
            "report": {
                "default_format": "json",
                "output_dir": "reports",
                "include_evidence": config_v2.get("scan_configuration", {})
                                     .get("reporting", {})
                                     .get("include_evidence", True),
                "mask_sensitive_data": config_v2.get("scan_configuration", {})
                                         .get("reporting", {})
                                         .get("mask_sensitive_data", True)
            },
            "safety": {
                "max_requests_total": config_v2.get("safety_controls", {})
                                       .get("rate_limiting", {})
                                       .get("max_requests_total", 1000),
                "auto_stop_on_error_rate": config_v2.get("safety_controls", {})
                                             .get("rate_limiting", {})
                                             .get("auto_stop_on_error_rate", 0.1),
                "disallowed_domains": config_v2.get("safety_controls", {})
                                        .get("target_validation", {})
                                        .get("disallowed_domains", []),
                "allowed_environments": config_v2.get("safety_controls", {})
                                          .get("target_validation", {})
                                          .get("allowed_environments", [])
            }
        }
        
        return config_v1
    
    @staticmethod
    def _extract_id_patterns(config_v2: Dict[str, Any]) -> List[Dict[str, Any]]:
        """استخراج أنماط ID من تكوين v2.1"""
        patterns = []
        
        phases = config_v2.get("scan_configuration", {}).get("phases", [])
        for phase in phases:
            if phase.get("name") == "id_enumeration":
                id_patterns = phase.get("id_patterns", [])
                for pattern in id_patterns:
                    patterns.append({
                        "type": pattern.get("type", "numeric"),
                        "range": pattern.get("range", [1, 100]),
                        "step": pattern.get("step", 1),
                        "pattern": pattern.get("pattern", "")
                    })
                break
        
        return patterns or [
            {"type": "numeric", "range": [1, 100], "step": 1},
            {"type": "uuid", "version": 4}
        ]
    
    @staticmethod
    def _extract_user_pairs(config_v2: Dict[str, Any]) -> List[List[str]]:
        """استخراج أزواج المستخدمين من تكوين v2.1"""
        user_pairs = []
        
        phases = config_v2.get("scan_configuration", {}).get("phases", [])
        for phase in phases:
            if phase.get("name") == "cross_user_testing":
                user_pairs = phase.get("user_pairs", [])
                break
        
        # إذا لم توجد أزواج، نستخدم الافتراضي
        if not user_pairs and "authentication" in config_v2:
            contexts = list(config_v2["authentication"].get("contexts", {}).keys())
            if len(contexts) >= 2:
                user_pairs = [[contexts[0], contexts[1]]]
        
        return user_pairs
    
    @staticmethod
    def _validate_config(config: Dict[str, Any]):
        """التحقق من صحة التكوين"""
        errors = []
        
        # التحقق من API base_url
        if not config.get("api", {}).get("base_url"):
            errors.append("Missing required field: api.base_url")
        
        # التحقق من وجود ماسحات
        if not config.get("scanners"):
            errors.append("Missing required section: scanners")
        
        if errors:
            raise ValueError(f"Config validation failed: {'; '.join(errors)}")
        
        print("✅ Configuration validated successfully")

    @staticmethod
    def _validate_resources(resources: Any):
        """التحقق من صحة قسم الموارد."""
        if not isinstance(resources, list):
            raise ValueError("'resources' must be a list")

        for resource in resources:
            if not isinstance(resource, dict):
                raise ValueError("Each resource must be an object")

            resource_path = resource.get("path") or resource.get("endpoint")
            if resource_path is None:
                raise ValueError("Each resource must define 'path' or 'endpoint'")

            if not isinstance(resource_path, str):
                raise ValueError("Resource 'path' must be a string")

            placeholders = re.findall(r"\{([^}]+)\}", resource_path)
            if not placeholders:
                raise ValueError(
                    f"Resource path must contain at least one placeholder: {resource_path}"
                )

            object_id_regex = resource.get("object_id_regex")
            if object_id_regex is not None:
                try:
                    re.compile(object_id_regex)
                except re.error as exc:
                    raise ValueError(
                        f"Invalid object_id_regex in resource {resource_path}"
                    ) from exc
    
    @staticmethod
    def load_resources(file_path: str) -> List[Dict[str, Any]]:
        """تحميل الموارد من ملف التكوين v2.1"""
        config = ConfigLoader._load_raw_config(file_path)

        if "resources" not in config:
            raise ValueError("Missing 'resources' section in config")

        resources = config.get("resources", [])
        ConfigLoader._validate_resources(resources)
        converted_resources = []
        
        for resource in resources:
            # تخطي الموارد التي ليست USER_OWNED (لـ BOLA)
            if resource.get("resource_type") != "USER_OWNED":
                continue
            
            converted = {
                "name": resource.get("name", ""),
                "endpoint": resource.get("endpoint", "").replace("{user_id}", "{id}"),
                "methods": resource.get("methods", []),
                "owner_field": resource.get("owner_field")
            }
            
            # إضافة الحقول الحساسة
            if "sensitivity" in resource:
                converted["sensitive_fields"] = resource["sensitivity"].get("fields", [])
            
            # إضافة قواعد التحقق
            if "validation_rules" in resource:
                converted["validation_rules"] = resource["validation_rules"]
            
            converted_resources.append(converted)
        
        return converted_resources
    
    @staticmethod
    def load_auth_contexts(file_path: str) -> Dict[str, Dict[str, Any]]:
        """تحميل سياقات المصادقة من ملف التكوين v2.1"""
        config = ConfigLoader.load(file_path, validate=False)
        
        auth_contexts_v2 = config.get("authentication", {}).get("contexts", {})
        auth_contexts_v1 = {}
        
        for user_id, user_config in auth_contexts_v2.items():
            # استخراج التوكن من المتغير البيئي
            token_env_var = user_config.get("token_env_var") or user_config.get("key_env_var")
            token = os.getenv(token_env_var, "") if token_env_var else ""
            
            # إذا كان التوكن فارغاً، نستخدم قيمة وهمية للاختبار
            if not token and "test" in config.get("metadata", {}).get("environment", "").lower():
                token = f"test_token_{user_id}"
                print(f"⚠️  Using test token for {user_id}")
            
            auth_contexts_v1[user_id] = {
                "token": token,
                "token_type": "Bearer" if user_config.get("type") == "bearer_token" else "APIKey",
                "headers": {
                    "Authorization": f"Bearer {token}" if user_config.get("type") == "bearer_token"
                                    else f"ApiKey {token}"
                },
                "role": user_config.get("role", "user"),
                "expected_scopes": user_config.get("expected_scopes", [])
            }
        
        return auth_contexts_v1
    
    @staticmethod
    def generate_id_from_pattern(pattern: Dict[str, Any]) -> str:
        """توليد ID بناءً على النمط"""
        pattern_type = pattern.get("type", "numeric")
        
        if pattern_type == "numeric":
            start, end = pattern.get("range", [1, 100])
            step = pattern.get("step", 1)
            return str(random.randrange(start, end, step))
        
        elif pattern_type == "uuid":
            version = pattern.get("version", 4)
            if version == 4:
                return str(uuid.uuid4())
            elif version == 1:
                return str(uuid.uuid1())
        
        elif pattern_type == "regex":
            regex_pattern = pattern.get("pattern", "^[a-zA-Z0-9]{8}$")
            # توليد سلسلة عشوائية تطابق النمط (تبسيط)
            length = 8
            if match := re.search(r'\{(\d+),?(\d*)\}', regex_pattern):
                length = int(match.group(1))
            return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        
        return str(random.randint(1, 1000))
