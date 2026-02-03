# reporting/markdown_report.py

from datetime import datetime
from typing import List, Dict


class MarkdownReport:
    """
    Generates professional Markdown reports for API security findings
    """

    def __init__(self, target: str):
        self.target = target
        self.findings: List[Dict] = []
        self.generated_at = datetime.utcnow().isoformat()

    def add_finding(self, finding: Dict):
        self.findings.append(finding)

    def generate(self) -> str:
        lines = []

        # Header
        lines.append(f"# 🛡️ API Security Scan Report")
        lines.append("")
        lines.append(f"**Target:** `{self.target}`")
        lines.append(f"**Generated at:** `{self.generated_at} UTC`")
        lines.append("")
        lines.append("---")

        if not self.findings:
            lines.append("✅ No security issues detected.")
            return "\n".join(lines)

        # Findings
        for idx, finding in enumerate(self.findings, start=1):
            lines.extend(self._format_finding(idx, finding))
            lines.append("---")

        return "\n".join(lines)

    # -------------------- helpers --------------------

    def _format_finding(self, idx: int, finding: Dict) -> List[str]:
        status = finding.get("status", "UNKNOWN")
        resource = finding.get("resource", "N/A")
        object_id = finding.get("object_id", "N/A")
        details = finding.get("details", [])

        severity = self._map_severity(status)

        lines = []
        lines.append(f"## 🔍 Finding #{idx}")
        lines.append("")
        lines.append(f"- **Resource:** `{resource}`")
        lines.append(f"- **Object ID Tested:** `{object_id}`")
        lines.append(f"- **Status:** `{status}`")
        lines.append(f"- **Severity:** **{severity}**")
        lines.append("")

        lines.append("### 🧪 Evidence")
        for d in details:
            lines.append(f"- {d}")

        lines.append("")
        lines.append("### 📌 Explanation")
        lines.append(self._explain_status(status))

        lines.append("")
        lines.append("### 🛠️ Recommended Mitigation")
        lines.append(self._mitigation(status))

        return lines

    def _map_severity(self, status: str) -> str:
        mapping = {
            "CONFIRMED_BOLA": "🔴 Critical",
            "POTENTIAL_BOLA": "🟠 High",
            "SECURE": "🟢 None",
            "CANNOT_BASELINE": "⚪ Informational",
        }
        return mapping.get(status, "⚪ Informational")

    def _explain_status(self, status: str) -> str:
        explanations = {
            "CONFIRMED_BOLA": (
                "The API does not properly enforce object-level authorization. "
                "A user was able to access a resource owned by another user."
            ),
            "POTENTIAL_BOLA": (
                "The API response was unexpected and may indicate improper "
                "authorization checks."
            ),
            "SECURE": (
                "The API correctly denied access to resources owned by other users."
            ),
            "CANNOT_BASELINE": (
                "The scanner could not establish a valid baseline using the owner's account."
            ),
        }
        return explanations.get(status, "No explanation available.")

    def _mitigation(self, status: str) -> str:
        if status in ("CONFIRMED_BOLA", "POTENTIAL_BOLA"):
            return (
                "- Enforce object ownership checks on the server side.\n"
                "- Never rely on client-supplied object identifiers.\n"
                "- Bind resource access to the authenticated user identity.\n"
                "- Add centralized authorization middleware."
            )
        return "No action required."
