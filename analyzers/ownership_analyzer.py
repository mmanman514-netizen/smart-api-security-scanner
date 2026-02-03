# analyzers/ownership_analyzer.py

from typing import List
from models.api_resource import ApiResource


class OwnershipAnalyzer:
    """
    Analyze API resources to determine object ownership risks (BOLA / IDOR)
    """

    def analyze(self, resources: List[ApiResource]) -> None:
        for resource in resources:
            self._analyze_resource(resource)

    def _analyze_resource(self, resource: ApiResource) -> None:
        # 1️⃣ هل يوجد Object Identifier؟
        if not resource.owner_field:
            resource.risk_flags.append("NO_OBJECT_IDENTIFIER")
            return

        # 2️⃣ هل العملية حساسة؟
        sensitive_methods = {"GET", "PUT", "PATCH", "DELETE"}
        if not any(m in sensitive_methods for m in resource.methods):
            return

        # 3️⃣ هل endpoint يبدو user-owned؟
        if self._looks_user_owned(resource):
            resource.risk_flags.append("POTENTIAL_BOLA")

        # 4️⃣ هل يوجد تعديل على مورد مملوك؟
        if any(m in {"PUT", "PATCH", "DELETE"} for m in resource.methods):
            resource.risk_flags.append("OBJECT_MODIFICATION")

    def _looks_user_owned(self, resource: ApiResource) -> bool:
        keywords = {"user", "account", "profile", "order"}
        return any(k in resource.endpoint.lower() for k in keywords)
