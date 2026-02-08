
"""
مسح ثغرات Rate Limiting
"""

import asyncio
import aiohttp
import logging
import time
from typing import Dict, Any, List, Optional
from models.api_resource import ApiResource

logger = logging.getLogger(__name__)

class RateLimitScanner:
    """مسح اختبار Rate Limiting"""
    
    def __init__(
        self,
        base_url: str = "",
        max_concurrent: int = 10,
        threshold_requests: int = 100,
        time_window: int = 60
    ):
        self.base_url = base_url
        self.max_concurrent = max_concurrent
        self.threshold_requests = threshold_requests
        self.time_window = time_window
        self.session = None
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def scan(self, resources: List[ApiResource]) -> List[Dict[str, Any]]:
        """مسح ثغرات Rate Limiting"""
        findings = []
        
        for resource in resources:
            # اختبار نقاط النهاية الحساسة فقط
            if not self._is_rate_limit_sensitive(resource):
                continue
                
            logger.info(f"Testing rate limit for: {resource.name}")
            
            try:
                result = await self._test_rate_limit(resource)
                if result["vulnerable"]:
                    findings.append({
                        "resource": resource.name,
                        "endpoint": resource.endpoint,
                        "issue": "rate_limit_missing",
                        "severity": "medium",
                        "confidence": result["confidence"],
                        "details": result
                    })
            except Exception as e:
                logger.error(f"Rate limit test failed for {resource.name}: {e}")
        
        return findings
    
    def _is_rate_limit_sensitive(self, resource: ApiResource) -> bool:
        """تحديد إذا كان المورد حساسًا لـ Rate Limiting"""
        sensitive_methods = ["POST", "PUT", "DELETE", "LOGIN", "REGISTER"]
        sensitive_paths = ["/login", "/register", "/password", "/reset", "/otp"]
        
        # التحقق من المسار
        endpoint_lower = resource.endpoint.lower()
        if any(path in endpoint_lower for path in sensitive_paths):
            return True
        
        # التحقق من الطرق الحساسة
        if any(method in resource.methods for method in sensitive_methods):
            return True
            
        return False
    
    async def _test_rate_limit(self, resource: ApiResource) -> Dict[str, Any]:
        """اختبار Rate Limiting لنقطة نهاية محددة"""
        url = f"{self.base_url}{resource.endpoint.replace('{id}', 'test')}"
        
        # إرسال طلبات متتالية سريعة
        requests_sent = self.threshold_requests
        successful_responses = 0
        limited_responses = 0
        
        tasks = []
        for i in range(requests_sent):
            task = self._make_rapid_request(url, resource.methods[0] if resource.methods else "GET")
            tasks.append(task)
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # تحليل الاستجابات
        for response in responses:
            if isinstance(response, dict):
                status = response.get("status", 0)
                
                if 200 <= status < 300:
                    successful_responses += 1
                elif status == 429:  # Too Many Requests
                    limited_responses += 1
        
        # حساب الثقة
        if limited_responses > 0:
            vulnerable = False
            confidence = 100 if limited_responses > 10 else limited_responses * 10
        else:
            vulnerable = successful_responses >= self.threshold_requests * 0.8
            confidence = min(100, (successful_responses / self.threshold_requests) * 100)
        
        return {
            "vulnerable": vulnerable,
            "confidence": confidence,
            "requests_sent": requests_sent,
            "successful_responses": successful_responses,
            "limited_responses": limited_responses,
            "url": url
        }
    
    async def _make_rapid_request(self, url: str, method: str) -> Dict[str, Any]:
        """إرسال طلب سريع"""
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()
            
            if method == "GET":
                async with self.session.get(url) as resp:
                    return {
                        "status": resp.status,
                        "headers": dict(resp.headers)
                    }
            elif method == "POST":
                async with self.session.post(url, json={}) as resp:
                    return {
                        "status": resp.status,
                        "headers": dict(resp.headers)
                    }
            else:
                async with self.session.get(url) as resp:
                    return {
                        "status": resp.status,
                        "headers": dict(resp.headers)
                    }
        except Exception as e:
            return {
                "status": 0,
                "error": str(e)
              }
