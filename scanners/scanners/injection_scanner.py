
"""
مسح ثغرات الحقن (SQLi, XSS, Command Injection)
"""

import asyncio
import aiohttp
import logging
import os
from typing import Dict, Any, List, Optional
from models.api_resource import ApiResource
from models.auth_context import AuthContext

logger = logging.getLogger(__name__)

class InjectionScanner:
    """مسح ثغرات الحقن"""
    
    def __init__(
        self,
        base_url: str = "",
        payloads_file: str = "payloads/sqli.txt",
        max_concurrent: int = 3
    ):
        self.base_url = base_url
        self.payloads_file = payloads_file
        self.max_concurrent = max_concurrent
        self.payloads = []
        self.session = None
        self.semaphore = asyncio.Semaphore(max_concurrent)
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        self._load_payloads()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def _load_payloads(self):
        """تحميل حمولات الاختبار"""
        default_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL, NULL--",
            "1; DROP TABLE users",
            "<script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "${@system('whoami')}",
            "| ls -la",
            "; ls -la",
            "`whoami`",
            "$(whoami)"
        ]
        
        try:
            if os.path.exists(self.payloads_file):
                with open(self.payloads_file, 'r', encoding='utf-8') as f:
                    self.payloads = [line.strip() for line in f if line.strip()]
            else:
                self.payloads = default_payloads
                logger.warning(f"Payloads file not found, using default payloads")
        except Exception as e:
            logger.error(f"Error loading payloads: {e}")
            self.payloads = default_payloads
        
        logger.info(f"Loaded {len(self.payloads)} injection payloads")
    
    async def scan(
        self,
        resources: List[ApiResource],
        auth_contexts: Dict[str, AuthContext]
    ) -> List[Dict[str, Any]]:
        """مسح ثغرات الحقن"""
        findings = []
        
        if not auth_contexts:
            logger.warning("No auth contexts provided for injection scan")
            return findings
        
        # استخدام أول سياق مصادقة
        auth_context = next(iter(auth_contexts.values()))
        
        for resource in resources:
            # التركيز على نقاط النهاية التي تقبل مدخلات
            if not self._accepts_input(resource):
                continue
            
            logger.info(f"Testing injection on: {resource.name}")
            
            try:
                resource_findings = await self._test_resource_injections(resource, auth_context)
                findings.extend(resource_findings)
            except Exception as e:
                logger.error(f"Injection test failed for {resource.name}: {e}")
        
        return findings
    
    def _accepts_input(self, resource: ApiResource) -> bool:
        """التحقق إذا كان المورد يقبل مدخلات"""
        # نقاط النهاية التي تحتوي على معلمات
        if "{" in resource.endpoint and "}" in resource.endpoint:
            return True
        
        # الطرق التي ترسل بيانات
        input_methods = ["POST", "PUT", "PATCH"]
        if any(method in resource.methods for method in input_methods):
            return True
            
        return False
    
    async def _test_resource_injections(
        self,
        resource: ApiResource,
        auth_context: AuthContext
    ) -> List[Dict[str, Any]]:
        """اختبار ثغرات الحقن لمورد معين"""
        findings = []
        
        # اختبار حقن في URL parameters
        if "{" in resource.endpoint:
            url_findings = await self._test_url_injections(resource, auth_context)
            findings.extend(url_findings)
        
        # اختبار حقن في body parameters
        if any(method in ["POST", "PUT", "PATCH"] for method in resource.methods):
            body_findings = await self._test_body_injections(resource, auth_context)
            findings.extend(body_findings)
        
        return findings
    
    async def _test_url_injections(
        self,
        resource: ApiResource,
        auth_context: AuthContext
    ) -> List[Dict[str, Any]]:
        """اختبار حقن في معلمات URL"""
        findings = []
        
        # استبدال {id} في المسار
        base_url = resource.build_url(self.base_url, "1")
        
        for payload in self.payloads[:10]:  # اختصار لأغراض الاختبار
            try:
                # اختبار payload في المسار
                test_url = base_url.replace("1", payload)
                
                response = await self._make_request(
                    test_url, "GET", auth_context.all_headers()
                )
                
                if self._is_injection_detected(response, payload):
                    findings.append({
                        "resource": resource.name,
                        "endpoint": resource.endpoint,
                        "issue": "path_traversal_or_injection",
                        "severity": "high",
                        "confidence": 70,
                        "details": {
                            "payload": payload,
                            "response_status": response.get("status"),
                            "response_body_sample": str(response.get("body", ""))[:200]
                        }
                    })
                    
            except Exception as e:
                logger.debug(f"URL injection test failed: {e}")
        
        return findings
    
    async def _test_body_injections(
        self,
        resource: ApiResource,
        auth_context: AuthContext
    ) -> List[Dict[str, Any]]:
        """اختبار حقن في body"""
        findings = []
        
        url = resource.build_url(self.base_url, "test")
        headers = auth_context.all_headers()
        
        for payload in self.payloads[:5]:  # اختصار
            try:
                # اختبار حقن في JSON body
                test_data = {
                    "username": payload,
                    "password": payload,
                    "email": f"{payload}@test.com",
                    "search": payload
                }
                
                response = await self._make_request(
                    url, "POST", headers, test_data
                )
                
                if self._is_injection_detected(response, payload):
                    findings.append({
                        "resource": resource.name,
                        "endpoint": resource.endpoint,
                        "issue": "sql_or_command_injection",
                        "severity": "critical",
                        "confidence": 80,
                        "details": {
                            "payload": payload,
                            "response_status": response.get("status"),
                            "error_detected": self._extract_error_indicator(response)
                        }
                    })
                    
            except Exception as e:
                logger.debug(f"Body injection test failed: {e}")
        
        return findings
    
    async def _make_request(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        data: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """إرسال طلب HTTP"""
        async with self.semaphore:
            try:
                if not self.session:
                    self.session = aiohttp.ClientSession()
                
                if method == "GET":
                    async with self.session.get(url, headers=headers) as resp:
                        body = await resp.text() if resp.content_length else ""
                        return {
                            "status": resp.status,
                            "body": body,
                            "headers": dict(resp.headers)
                        }
                elif method == "POST":
                    async with self.session.post(url, json=data, headers=headers) as resp:
                        body = await resp.text() if resp.content_length else ""
                        return {
                            "status": resp.status,
                            "body": body,
                            "headers": dict(resp.headers)
                        }
                else:
                    async with self.session.get(url, headers=headers) as resp:
                        body = await resp.text() if resp.content_length else ""
                        return {
                            "status": resp.status,
                            "body": body,
                            "headers": dict(resp.headers)
                        }
                        
            except Exception as e:
                return {
                    "status": 0,
                    "error": str(e),
                    "body": ""
                }
    
    def _is_injection_detected(self, response: Dict[str, Any], payload: str) -> bool:
        """التحقق إذا تم اكتشاف حقن"""
        status = response.get("status", 0)
        body = str(response.get("body", "")).lower()
        
        # مؤشرات الحقن
        sql_errors = [
            "sql", "syntax", "database", "mysql", "postgresql",
            "oracle", "sqlite", "query failed", "union",
            "you have an error in your sql syntax"
        ]
        
        xss_indicators = [
            "<script>", "alert(", "onerror=", "onload=",
            "javascript:", "eval(", "document.cookie"
        ]
        
        # مؤشرات الاستجابة غير الطبيعية
        if status >= 500:  # أخطاء سيرفر
            return True
        
        if any(error in body for error in sql_errors):
            return True
            
        if payload in ["<script>alert('XSS')</script>", "\"><script>alert('XSS')</script>"]:
            if "<script>" in body and "alert" in body:
                return True
        
        # تحقق من أخطاء تنفيذ الأوامر
        command_errors = [
            "sh:", "bash:", "permission denied",
            "command not found", "segmentation fault"
        ]
        
        if any(cmd_error in body for cmd_error in command_errors):
            return True
        
        return False
    
    def _extract_error_indicator(self, response: Dict[str, Any]) -> str:
        """استخراج مؤشر الخطأ"""
        body = str(response.get("body", "")).lower()
        
        indicators = {
            "sql": ["sql", "syntax", "database", "query failed"],
            "xss": ["<script>", "alert(", "onerror="],
            "command": ["sh:", "bash:", "permission denied"],
            "generic": ["error", "exception", "failed"]
        }
        
        for error_type, patterns in indicators.items():
            for pattern in patterns:
                if pattern in body:
                    return f"{error_type}_error_detected"
        
        return "suspicious_response"
