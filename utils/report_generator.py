"""Report generation helpers used by main.py."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict


class ReportGenerator:
    def generate_json_report(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Return the serializable report payload."""
        return scan_results

    def generate_html_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate a lightweight HTML report and return its path."""
        report_dir = Path("reports")
        report_dir.mkdir(exist_ok=True)
        report_file = report_dir / f"{scan_results.get('scan_id', 'scan_report')}.html"

        findings_html = "".join(
            f"<li><strong>{finding.get('resource', 'Unknown')}</strong> - "
            f"{finding.get('issue', 'unknown_issue')} "
            f"({finding.get('severity', 'info')})</li>"
            for finding in scan_results.get("findings", [])
        )

        html = f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <title>API Security Scan Report</title>
</head>
<body>
  <h1>API Security Scan Report</h1>
  <p><strong>Scan ID:</strong> {scan_results.get('scan_id', 'N/A')}</p>
  <p><strong>Generated:</strong> {datetime.utcnow().isoformat()}Z</p>
  <h2>Summary</h2>
  <pre>{json.dumps(scan_results.get('findings_by_severity', {}), indent=2)}</pre>
  <h2>Findings</h2>
  <ul>{findings_html or '<li>No findings</li>'}</ul>
</body>
</html>
"""

        report_file.write_text(html, encoding="utf-8")
        return str(report_file)

    def print_console_report(self, scan_results: Dict[str, Any]) -> None:
        """Print a concise console summary."""
        print("\n=== API Security Scan Report ===")
        print(f"Scan ID: {scan_results.get('scan_id', 'N/A')}")
        print(f"Total Findings: {scan_results.get('total_findings', len(scan_results.get('findings', [])))}")
        for finding in scan_results.get("findings", []):
            print(
                f"- [{finding.get('severity', 'info').upper()}] "
                f"{finding.get('resource', 'Unknown')} :: {finding.get('issue', 'unknown_issue')}"
            )
