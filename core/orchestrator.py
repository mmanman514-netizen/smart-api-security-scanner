# core/orchestrator.py - الإصدار المصحح
from typing import List, Dict, Any
import logging
import time

# استيرادات آمنة مع fallback
try:
    from scanners.bola_scanner import BOLAScanner
    SCANNER_AVAILABLE = True
except ImportError:
    SCANNER_AVAILABLE = False
    BOLAScanner = None

try:
    from models.api_resource import ApiResource
    API_RESOURCE_AVAILABLE = True
except ImportError:
    API_RESOURCE_AVAILABLE = False
    ApiResource = None

try:
    from models.auth_context import AuthContext
    AUTH_CONTEXT_AVAILABLE = True
except ImportError:
    AUTH_CONTEXT_AVAILABLE = False
    AuthContext = None

logger = logging.getLogger("scanner-orchestrator")

# استثناء محلي إذا لم يكن موجوداً
class ScannerError(Exception):
    """Custom exception for scanner errors"""
    pass

class ScanOrchestrator:
    def __init__(
        self,
        scanner: Any,  # ⚠️ تغيير من BaseScanner إلى Any للمرونة
        resources: List[ApiResource],
        auth_contexts: Dict[str, AuthContext],
        dry_run: bool = False
    ):
        # التحقق من التوفر
        if not SCANNER_AVAILABLE:
            raise ImportError("BOLAScanner not available")
        if not API_RESOURCE_AVAILABLE:
            raise ImportError("ApiResource not available")
        if not AUTH_CONTEXT_AVAILABLE:
            raise ImportError("AuthContext not available")
        
        # التحقق من الأنواع
        if scanner is None:
            raise ValueError("Scanner cannot be None")
        if not resources:
            raise ValueError("Resources list cannot be empty")
        if not auth_contexts:
            raise ValueError("Auth contexts cannot be empty")
        
        self.scanner = scanner
        self.resources = resources
        self.auth_contexts = auth_contexts
        self.dry_run = dry_run
        
        logger.debug(f"Orchestrator initialized with {len(resources)} resources")

    async def run(self) -> List[Dict[str, Any]]:
        """
        Execute the scan and return findings
        
        Returns:
            List of vulnerability findings
            
        Raises:
            ScannerError: If scan fails
            ValueError: If inputs are invalid
        """
        # التحقق المسبق
        if not self.resources:
            raise ScannerError("No resources to scan")
        
        if len(self.auth_contexts) < 2:
            raise ScannerError("BOLA scan requires at least 2 auth contexts")
        
        logger.info(f"🚀 Starting scan with {len(self.resources)} resources")
        logger.info(f"   Dry run mode: {self.dry_run}")
        logger.info(f"   Auth contexts: {list(self.auth_contexts.keys())}")
        
        try:
            # تنفيذ المسح
            start_time = time.time()
            
            findings = await self.scanner.scan(
                resources=self.resources,
                auth_contexts=self.auth_contexts,
                dry_run=self.dry_run
            )
            
            # حساب الإحصائيات
            duration = time.time() - start_time
            logger.info(f"⏱️  Scan completed in {duration:.2f} seconds")
            
            # تسجيل النتائج
            if not findings:
                logger.info("✅ No vulnerabilities found")
            else:
                logger.info(f"🚨 Found {len(findings)} potential vulnerabilities")
                
                # تسجيل ملخص للنتائج
                severities = {}
                for finding in findings:
                    severity = finding.get('severity', 'unknown')
                    severities[severity] = severities.get(severity, 0) + 1
                
                for severity, count in severities.items():
                    logger.info(f"   {severity.upper()}: {count}")
            
            logger.info(f"📊 Scan finished. Total findings: {len(findings)}")
            return findings
            
        except Exception as e:
            logger.error(f"❌ Scan failed: {e}")
            raise ScannerError(f"Scan execution failed: {e}")

# دالة مساعدة لإنشاء orchestrator بسهولة
async def create_and_run_scan(
    scanner_config: Dict[str, Any],
    resources: List[ApiResource],
    auth_contexts: Dict[str, AuthContext],
    dry_run: bool = False
) -> List[Dict[str, Any]]:
    """
    Helper function to create scanner and run scan in one call
    
    Args:
        scanner_config: Configuration for BOLAScanner
        resources: List of resources to scan
        auth_contexts: Authentication contexts
        dry_run: Whether to run in dry mode
        
    Returns:
        List of findings
    """
    if not SCANNER_AVAILABLE:
        raise ImportError("BOLAScanner not available")
    
    # إنشاء الماسح
    scanner = BOLAScanner(**scanner_config)
    
    # إنشاء وتشغيل المنظم
    orchestrator = ScanOrchestrator(
        scanner=scanner,
        resources=resources,
        auth_contexts=auth_contexts,
        dry_run=dry_run
    )
    
    return await orchestrator.run()
