import asyncio
import logging
from typing import List, Optional, Dict, Any
from models.api_resource import ApiResource, ResourceType

logger = logging.getLogger(__name__)

class OwnershipAnalyzer:
    """
    Analyze API resources to detect BOLA / IDOR risks with enhanced features.
    
    Features:
    - Automatic risk flagging for user-owned resources
    - Customizable risk thresholds
    - Async support for large datasets
    - Integration with scanning workflows
    
    Example:
        # After Swagger discovery
        resources = discovery.parse_paths(spec)
        
        # Analyze for risks
        analyzer = OwnershipAnalyzer()
        metrics = analyzer.analyze(resources)
        
        # Use results for targeted scanning
        high_risk = [r for r in resources if r.has_risk_flag("POTENTIAL_BOLA")]
    """

    def __init__(
        self,
        custom_risk_thresholds: Optional[Dict[str, Any]] = None,
        enable_detailed_logging: bool = True,
        default_sample_data: Optional[Dict[str, Any]] = None,
    ):
        self.custom_risk_thresholds = custom_risk_thresholds or {
            "exposed_fields": 3,
            "sensitive_methods": 2,
        }
        self.enable_detailed_logging = enable_detailed_logging
        self.default_sample_data = default_sample_data or {}
        
        # تعريف risk flags مع وصف
        self.risk_flag_descriptions = {
            "NO_OBJECT_IDENTIFIER": "Resource lacks owner_field for BOLA detection",
            "POTENTIAL_BOLA": "User-owned resource with sensitive methods",
            "OBJECT_MODIFICATION": "Resource supports PUT/PATCH/DELETE methods",
            "MULTI_TENANT_RISK": "Multi-tenant resource may have isolation issues",
            "ADMIN_ONLY_RISK": "Admin-only endpoint privilege escalation risk",
            "HIGH_EXPOSURE": "Exposes many sensitive fields",
        }

    def analyze(self, resources: List[ApiResource]) -> Dict[str, Any]:
        """
        Analyze API resources for security risks.
        
        Args:
            resources: List of ApiResource objects
            
        Returns:
            Dictionary with analysis metrics
            
        Raises:
            ValueError: If resources is not a list of ApiResource
        """
        if not isinstance(resources, list):
            raise ValueError("Resources must be a list")
        
        if not all(isinstance(r, ApiResource) for r in resources):
            raise ValueError("All items must be ApiResource instances")
        
        metrics = {
            "total_resources": len(resources),
            "user_owned_resources": 0,
            "public_resources": 0,
            "admin_resources": 0,
            "risk_flags_added": 0,
            "bola_risks": 0,
            "modification_risks": 0,
            "resource_types": {},
        }
        
        for resource in resources:
            self._analyze_resource(resource, metrics)
        
        # تحليل إحصائي
        self._calculate_statistics(metrics)
        
        if self.enable_detailed_logging:
            logger.info(f"📊 Analysis complete: {metrics}")
        
        return metrics

    def _analyze_resource(self, resource: ApiResource, metrics: Dict[str, Any]) -> None:
        """Analyze a single resource with comprehensive checks."""
        
        # تحديث إحصائيات أنواع الموارد
        resource_type = resource.resource_type.value
        metrics["resource_types"][resource_type] = metrics["resource_types"].get(resource_type, 0) + 1
        
        # 🔒 التركيز على موارد user-owned فقط لـBOLA
        if resource.resource_type != ResourceType.USER_OWNED:
            if resource.resource_type == ResourceType.PUBLIC:
                metrics["public_resources"] += 1
            elif resource.resource_type == ResourceType.ADMIN_ONLY:
                metrics["admin_resources"] += 1
            return
        
        metrics["user_owned_resources"] += 1
        
        # 1️⃣ تحقق من معرّف المالك (أساسي لـBOLA)
        if not resource.owner_field:
            self._add_risk_flag(resource, "NO_OBJECT_IDENTIFIER", metrics)
            return

        # 2️⃣ تحقق من الطرق الحساسة
        sensitive_methods = {"GET", "PUT", "PATCH", "DELETE"}
        resource_methods = {m.upper() for m in resource.methods}
        sensitive_found = resource_methods.intersection(sensitive_methods)
        
        if not sensitive_found:
            return  # لا طرق حساسة، لا خطر BOLA

        # 3️⃣ خطر BOLA محتمل
        self._add_risk_flag(resource, "POTENTIAL_BOLA", metrics)
        metrics["bola_risks"] += 1
        
        if self.enable_detailed_logging:
            logger.info(f"⚠️  Potential BOLA: {resource.name} ({resource.endpoint})")

        # 4️⃣ خطر تعديل الكائن
        modification_methods = {"PUT", "PATCH", "DELETE"}
        if any(m in modification_methods for m in resource_methods):
            self._add_risk_flag(resource, "OBJECT_MODIFICATION", metrics)
            metrics["modification_risks"] += 1

        # 5️⃣ مخاطر إضافية بناءً على خصائص المورد
        self._check_additional_risks(resource, metrics)

    def _check_additional_risks(self, resource: ApiResource, metrics: Dict[str, Any]) -> None:
        """Check for additional risk factors."""
        try:
            # استخدام الحقول الإضافية إذا كانت موجودة
            if hasattr(resource, 'multi_tenant') and resource.multi_tenant:
                self._add_risk_flag(resource, "MULTI_TENANT_RISK", metrics)
            
            if hasattr(resource, 'admin_only') and resource.admin_only:
                self._add_risk_flag(resource, "ADMIN_ONLY_RISK", metrics)
            
            # حساب الحقول الحساسة المكشوفة
            exposed_count = 0
            if hasattr(resource, 'exposed_fields_count'):
                # استخدام بيانات افتراضية أو حقيقية
                sample_data = self.default_sample_data or {
                    "dummy": "data",
                    "email": "test@example.com" if "email" in resource.sensitive_fields else None
                }
                exposed_count = resource.exposed_fields_count(sample_data)
            
            threshold = self.custom_risk_thresholds.get("exposed_fields", 3)
            if exposed_count > threshold:
                self._add_risk_flag(resource, "HIGH_EXPOSURE", metrics)
                
        except AttributeError:
            # إذا كانت الخصائص غير موجودة، تخطيها
            pass

    def _add_risk_flag(self, resource: ApiResource, flag: str, metrics: Dict[str, Any]) -> None:
        """Add risk flag with description."""
        resource.add_risk_flag(flag)
        metrics["risk_flags_added"] += 1
        
        if self.enable_detailed_logging:
            description = self.risk_flag_descriptions.get(flag, "Unknown risk")
            logger.debug(f"  Added flag '{flag}': {description}")

    def _calculate_statistics(self, metrics: Dict[str, Any]) -> None:
        """Calculate additional statistics."""
        total = metrics["total_resources"]
        if total > 0:
            metrics["bola_risk_percentage"] = (metrics["bola_risks"] / total) * 100
            metrics["modification_risk_percentage"] = (metrics["modification_risks"] / total) * 100
            metrics["avg_flags_per_resource"] = metrics["risk_flags_added"] / total

    async def analyze_async(self, resources: List[ApiResource]) -> Dict[str, Any]:
        """Async analysis with potential for parallel processing."""
        # يمكن تحسين هذا لمعالجة الموازية للمجموعات الكبيرة
        return await asyncio.to_thread(self.analyze, resources)
    
    def get_high_risk_resources(self, resources: List[ApiResource]) -> List[ApiResource]:
        """Filter and return high-risk resources."""
        high_risk = []
        critical_flags = {"POTENTIAL_BOLA", "OBJECT_MODIFICATION"}
        
        for resource in resources:
            if any(resource.has_risk_flag(flag) for flag in critical_flags):
                high_risk.append(resource)
        
        return high_risk
