import asyncio
import logging
from typing import List, Optional, Dict, Any
from models.api_resource import ApiResource, ResourceType

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OwnershipAnalyzer:
    """
    Analyze API resources to detect BOLA / IDOR risks.
    
    This analyzer focuses on user-owned resources, checks for object identifiers,
    sensitive operations, and adds risk flags accordingly. Designed for authorized
    security testing only; unauthorized use violates laws.
    
    Example:
        analyzer = OwnershipAnalyzer()
        analyzer.analyze(resources)
        # Check resource.risk_flags for added flags
    """

    def __init__(
        self,
        custom_risk_thresholds: Optional[Dict[str, int]] = None,  # Custom thresholds for risks
        enable_detailed_logging: bool = True,  # Enable detailed logging
    ):
        self.custom_risk_thresholds = custom_risk_thresholds or {}
        self.enable_detailed_logging = enable_detailed_logging

    def analyze(self, resources: List[ApiResource]) -> Dict[str, Any]:
        """
        Analyze a list of API resources for BOLA/IDOR risks.
        
        :param resources: List of ApiResource objects to analyze.
        :return: Metrics dictionary with analysis results.
        """
        if not isinstance(resources, list) or not all(isinstance(r, ApiResource) for r in resources):
            raise ValueError("Resources must be a list of ApiResource objects")
        
        metrics = {
            "total_resources": len(resources),
            "analyzed_resources": 0,
            "risk_flags_added": 0,
            "bola_risks": 0,
        }
        
        for resource in resources:
            self._analyze_resource(resource, metrics)
        
        logger.info(f"Analysis complete: {metrics}")
        return metrics

    async def analyze_async(self, resources: List[ApiResource]) -> Dict[str, Any]:
        """Async version for large lists."""
        # Simple async wrapper; can be enhanced with parallel processing
        return await asyncio.get_event_loop().run_in_executor(None, self.analyze, resources)

    def _analyze_resource(self, resource: ApiResource, metrics: Dict[str, Any]) -> None:
        """Analyze a single resource."""
        metrics["analyzed_resources"] += 1
        
        # 🔒 Analyze only user-owned resources
        if resource.resource_type != ResourceType.USER_OWNED:
            if self.enable_detailed_logging:
                logger.debug(f"Skipping non-user-owned resource: {resource.name}")
            return

        # 1️⃣ Check for Object Identifier
        if not resource.owner_field:
            resource.add_risk_flag("NO_OBJECT_IDENTIFIER")
            metrics["risk_flags_added"] += 1
            if self.enable_detailed_logging:
                logger.warning(f"No object identifier for {resource.name}")
            return

        # 2️⃣ Check for sensitive methods
        sensitive_methods = {"GET", "PUT", "PATCH", "DELETE"}
        if not any(m in sensitive_methods for m in resource.methods):
            return

        # 3️⃣ Potential BOLA risk
        resource.add_risk_flag("POTENTIAL_BOLA")
        metrics["risk_flags_added"] += 1
        metrics["bola_risks"] += 1
        if self.enable_detailed_logging:
            logger.info(f"Potential BOLA detected for {resource.name}")

        # 4️⃣ Object modification risk
        if any(m in {"PUT", "PATCH", "DELETE"} for m in resource.methods):
            resource.add_risk_flag("OBJECT_MODIFICATION")
            metrics["risk_flags_added"] += 1

        # 5️⃣ Additional checks based on resource properties
        if resource.multi_tenant:
            resource.add_risk_flag("MULTI_TENANT_RISK")
            metrics["risk_flags_added"] += 1
        if resource.admin_only:
            resource.add_risk_flag("ADMIN_ONLY_RISK")
            metrics["risk_flags_added"] += 1
        # تحسين: استخدم بيانات حقيقية إذا متوفرة، أو افترض 0 للبيانات الفارغة
        exposed_count = resource.exposed_fields_count({})  # يمكن تمرير بيانات حقيقية هنا
        if exposed_count > self.custom_risk_thresholds.get("exposed_fields", 0):
            resource.add_risk_flag("HIGH_EXPOSURE")
            metrics["risk_flags_added"] += 1
