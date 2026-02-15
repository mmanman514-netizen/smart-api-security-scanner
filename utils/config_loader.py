diff --git a/utils/config_loader.py b/utils/config_loader.py
index a0b7b5d..8abe438 100644
--- a/utils/config_loader.py
+++ b/utils/config_loader.py
@@ -3,7 +3,6 @@
 """
 
 import json
-import yaml
 import os
 import re
 import sys
@@ -54,10 +53,21 @@ class ConfigLoader:
 
         if path.suffix.lower() in ['.json']:
             with open(file_path, 'r', encoding='utf-8') as f:
-                # Strict JSON only (comments are not supported)
-                return json.load(f)
+                # يدعم JSON مع تعليقات // و /* */ شائعة في ملفات الإعداد
+                content = f.read()
+                try:
+                    return json.loads(content)
+                except json.JSONDecodeError:
+                    sanitized = ConfigLoader._strip_json_comments(content)
+                    return json.loads(sanitized)
 
         if path.suffix.lower() in ['.yaml', '.yml']:
+            try:
+                import yaml
+            except ModuleNotFoundError as exc:
+                raise ModuleNotFoundError(
+                    "PyYAML is required to load YAML config files. Install with: pip install pyyaml"
+                ) from exc
             with open(file_path, 'r', encoding='utf-8') as f:
                 return yaml.safe_load(f)
 
@@ -213,7 +223,9 @@ class ConfigLoader:
                 raise ValueError("Resource 'path' must be a string")
 
             placeholders = re.findall(r"\{([^}]+)\}", resource_path)
-            if not placeholders:
+            resource_type = str(resource.get("resource_type", "")).upper()
+            is_user_owned = resource_type in {"USER_OWNED", ""} or bool(resource.get("owner_field"))
+            if is_user_owned and not placeholders:
                 raise ValueError(
                     f"Resource path must contain at least one placeholder: {resource_path}"
                 )
@@ -266,7 +278,11 @@ class ConfigLoader:
     @staticmethod
     def load_auth_contexts(file_path: str) -> Dict[str, Dict[str, Any]]:
         """تحميل سياقات المصادقة من ملف التكوين v2.1"""
-        config = ConfigLoader.load(file_path, validate=False)
+        config = ConfigLoader._load_raw_config(file_path)
+
+        # دعم ملفات v1 التي تستخدم auth_contexts مباشرة
+        if isinstance(config.get("auth_contexts"), dict):
+            return config["auth_contexts"]
         
         auth_contexts_v2 = config.get("authentication", {}).get("contexts", {})
         auth_contexts_v1 = {}
@@ -293,6 +309,54 @@ class ConfigLoader:
             }
         
         return auth_contexts_v1
+
+    @staticmethod
+    def _strip_json_comments(content: str) -> str:
+        """إزالة تعليقات // و /* */ من JSON مع احترام النصوص."""
+        result = []
+        in_string = False
+        escaped = False
+        i = 0
+        length = len(content)
+
+        while i < length:
+            ch = content[i]
+            nxt = content[i + 1] if i + 1 < length else ""
+
+            if in_string:
+                result.append(ch)
+                if escaped:
+                    escaped = False
+                elif ch == "\\":
+                    escaped = True
+                elif ch == '"':
+                    in_string = False
+                i += 1
+                continue
+
+            if ch == '"':
+                in_string = True
+                result.append(ch)
+                i += 1
+                continue
+
+            if ch == "/" and nxt == "/":
+                i += 2
+                while i < length and content[i] not in "\r\n":
+                    i += 1
+                continue
+
+            if ch == "/" and nxt == "*":
+                i += 2
+                while i + 1 < length and not (content[i] == "*" and content[i + 1] == "/"):
+                    i += 1
+                i += 2
+                continue
+
+            result.append(ch)
+            i += 1
+
+        return "".join(result)
