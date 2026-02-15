diff --git a/utils/logging_setup.py b/utils/logging_setup.py
new file mode 100644
index 0000000..770cc15
--- /dev/null
+++ b/utils/logging_setup.py
@@ -0,0 +1,25 @@
+"""Logging bootstrap utilities for scanner entrypoint."""
+
+import logging
+from pathlib import Path
+
+
+def setup_logging(log_level: str = "INFO", log_file: str = "scanner.log") -> None:
+    """Configure root logging handlers safely for CLI execution."""
+    level = getattr(logging, str(log_level).upper(), logging.INFO)
+
+    root_logger = logging.getLogger()
+    for handler in list(root_logger.handlers):
+        root_logger.removeHandler(handler)
+
+    handlers = [logging.StreamHandler()]
+
+    if log_file:
+        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
+        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
+
+    logging.basicConfig(
+        level=level,
+        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
+        handlers=handlers,
+    )

