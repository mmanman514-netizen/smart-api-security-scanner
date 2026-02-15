diff --git a/utils/report_generator.py b/utils/report_generator.py
new file mode 100644
index 0000000..e2924c7
--- /dev/null
+++ b/utils/report_generator.py
@@ -0,0 +1,48 @@
+"""Minimal report generation helpers used by main.py."""
+
+import json
+from datetime import datetime
+from pathlib import Path
+from typing import Any, Dict
+
+
+class ReportGenerator:
+    """Generate JSON/HTML/console reports for scan results."""
+
+    def generate_json_report(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
+        return {
+            "generated_at": datetime.utcnow().isoformat() + "Z",
+            "report_type": "api_security_scan",
+            "results": scan_results,
+        }
+
+    def generate_html_report(self, scan_results: Dict[str, Any]) -> str:
+        report_dir = Path("reports")
+        report_dir.mkdir(parents=True, exist_ok=True)
+        output_file = report_dir / f"{scan_results.get('scan_id', 'scan_report')}.html"
+
+        findings = scan_results.get("findings", [])
+        html = f"""<!doctype html>
+<html lang='en'>
+<head><meta charset='utf-8'><title>API Security Scan Report</title></head>
+<body>
+  <h1>API Security Scan Report</h1>
+  <p>Scan ID: {scan_results.get('scan_id', 'N/A')}</p>
+  <p>Total Findings: {len(findings)}</p>
+  <pre>{json.dumps(scan_results, indent=2, ensure_ascii=False)}</pre>
+</body>
+</html>"""
+
+        output_file.write_text(html, encoding="utf-8")
+        return str(output_file)
+
+    def print_console_report(self, scan_results: Dict[str, Any]) -> None:
+        findings = scan_results.get("findings", [])
+        print("\n=== API Security Scan Report ===")
+        print(f"Scan ID: {scan_results.get('scan_id', 'N/A')}")
+        print(f"Total Findings: {len(findings)}")
+        for idx, finding in enumerate(findings, start=1):
+            issue = finding.get("issue", "unknown")
+            severity = finding.get("severity", "info")
+            endpoint = finding.get("endpoint", "")
+            print(f"{idx}. [{severity}] {issue} {endpoint}")

