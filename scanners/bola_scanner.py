import asyncio
import aiohttp
import json
import logging
import time
import hashlib
import random
import re
import uuid
from typing import Dict, Any, Optional, List
from utils.config_loader import ConfigLoader

logger = logging.getLogger(__name__)

class BOLAScanner:
    """BOLA Scanner with v2.1 configuration support"""
    
    def __init__(
        self,
        base_url: str = "",
        rate_limit: float = 1.0,
        requests_per_second: Optional[float] = None,
        max_concurrent: int = 5,
        timeout: int = 30,
        strict_owner: bool = False,
        id_patterns: List[Dict[str, Any]] = None,
        user_pairs: List[List[str]] = None,
        safety_config: Dict[str, Any] = None
    ):
        self.base_url = base_url
        # NOTE: v2.1 config exposes requests_per_second while older code used
        # `rate_limit`. Normalize both to an inter-request delay in seconds.
        effective_rps = requests_per_second if requests_per_second is not None else rate_limit
        self.request_delay = 0.0
        try:
            if effective_rps and float(effective_rps) > 0:
                self.request_delay = 1.0 / float(effective_rps)
        except (TypeError, ValueError):
            logger.warning("Invalid rate limit value. Falling back to no delay.")
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.timeout = timeout
        self.strict_owner = strict_owner
        self.id_patterns = id_patterns or []
        self.user_pairs = user_pairs or []
        self.safety_config = safety_config or {}
        self.session = None
        self.default_headers = {}
        
        # إحصائيات السلامة
        self.total_requests = 0
        self.error_count = 0
        self.start_time = None
        
    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(ssl=False)  # أو True إذا كنت تريد SSL
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=self.default_headers
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def scan(
        self,
        resources: List[Dict[str, Any]],
        auth_contexts: Dict[str, Dict[str, Any]],
        dry_run: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Scan for BOLA vulnerabilities with v2.1 configuration
        
        Returns:
            List of findings
        """
        self.start_time = time.time()
        findings = []
        
        if not auth_contexts or len(auth_contexts) < 2:
            raise ValueError("BOLA scan requires at least 2 auth contexts")
        
        logger.info(f"Starting BOLA scan with {len(resources)} resources")
        
        for resource in resources:
            if dry_run:
                logger.info(f"Dry run: {resource.get('name')} - {resource.get('endpoint')}")
                continue
            
            # التحقق من حدود السلامة
            if self._safety_check_failed():
                logger.warning("Safety check failed, stopping scan")
                break
            
            try:
                resource_findings = await self._scan_resource(resource, auth_contexts)
                findings.extend(resource_findings)
                
            except Exception as e:
                logger.error(f"Error scanning {resource.get('name')}: {e}")
                self.error_count += 1
        
        logger.info(f"BOLA scan completed. Findings: {len(findings)}")
        return findings
    
    async def _scan_resource(
        self,
        resource: Dict[str, Any],
        auth_contexts: Dict[str, Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """مسح مورد معين"""
        findings = []
        
        # الحصول على IDs للاختبار
        object_ids = await self._get_object_ids(resource, auth_contexts)
        
        if not object_ids:
            logger.warning(f"No object IDs found for {resource.get('name')}")
            return findings
        
        logger.info(f"Testing {len(object_ids)} IDs for {resource.get('name')}")
        
        # استخدام أزواج المستخدمين من التكوين أو إنشاء أزواج افتراضية
        user_pairs = self.user_pairs or self._generate_user_pairs(list(auth_contexts.keys()))
        
        for object_id in object_ids[:10]:  # تحديد للسلامة
            for method in resource.get("methods", []):
                if method in ["POST", "PUT", "DELETE"] and self.strict_owner:
                    continue  # تخطي الطرق التغييرية في المسح الأساسي
                
                for user_a_id, user_b_id in user_pairs:
                    if self._safety_check_failed():
                        return findings
                    
                    try:
                        finding = await self._test_access(
                            resource, object_id, method,
                            auth_contexts[user_a_id], auth_contexts[user_b_id],
                            user_a_id, user_b_id
                        )
                        
                        if finding:
                            findings.append(finding)
                            
                    except Exception as e:
                        logger.debug(f"Test failed for {object_id}: {e}")
                        self.error_count += 1
        
        return findings
    
    async def _get_object_ids(
        self,
        resource: Dict[str, Any],
        auth_contexts: Dict[str, Dict[str, Any]]
    ) -> List[str]:
        """الحصول على Object IDs للاختبار"""
        ids = set()
        
        # 1. محاولة الحصول من نقطة list endpoint
        list_endpoint = resource.get("endpoint", "").replace("{id}", "")
        if list_endpoint and list_endpoint != resource.get("endpoint", ""):
            try:
                # استخدام أول مستخدم
                first_user = next(iter(auth_contexts.values()))
                response = await self._make_request(
                    list_endpoint, "GET", first_user.get("headers", {})
                )
                
                if response.get("status") == 200:
                    extracted_ids = self._extract_ids_from_response(
                        response.get("body", {}),
                        resource.get("validation_rules", {})
                    )
                    ids.update(extracted_ids)
                    
            except Exception as e:
                logger.debug(f"Failed to get IDs from list endpoint: {e}")
        
        # 2. استخدام أنماط ID من التكوين v2.1
        for pattern in self.id_patterns:
            generated_id = ConfigLoader.generate_id_from_pattern(pattern)
            
            # التحقق من صحة ID بناءً على regex إذا وجد
            if "validation_rules" in resource:
                regex = resource["validation_rules"].get("owner_field_regex")
                if regex and not re.match(regex, generated_id):
                    continue
            
            ids.add(generated_id)
        
        # 3. إضافة IDs افتراضية
        default_ids = ["1", "100", "999", "test_user", str(uuid.uuid4())]
        ids.update(default_ids)
        
        return list(ids)[:20]  # تحديد العدد للسلامة
    
    async def _test_access(
        self,
        resource: Dict[str, Any],
        object_id: str,
        method: str,
        auth_a: Dict[str, Any],
        auth_b: Dict[str, Any],
        user_a_id: str,
        user_b_id: str
    ) -> Optional[Dict[str, Any]]:
        """اختبار الوصول بين مستخدمين"""
        
        # بناء URL
        url = self._build_url(resource.get("endpoint", ""), object_id)
        
        # إرسال الطلبات
        response_a = await self._make_request(url, method, auth_a.get("headers", {}))
        response_b = await self._make_request(url, method, auth_b.get("headers", {}))
        
        self.total_requests += 2
        
        # التحقق من الثغرة
        if self._is_vulnerable(response_a, response_b, auth_a, auth_b):
            return self._create_finding(
                resource, object_id, method,
                user_a_id, user_b_id,
                response_a, response_b
            )
        
        return None
    
    async def _make_request(
        self,
        url: str,
        method: str,
        headers: Dict[str, str]
    ) -> Dict[str, Any]:
        """إرسال طلب HTTP"""
        async with self.semaphore:
            if self.request_delay > 0:
                await asyncio.sleep(self.request_delay)
            
            full_url = f"{self.base_url}{url}" if not url.startswith("http") else url
            
            try:
                if method == "GET":
                    async with self.session.get(full_url, headers=headers) as resp:
                        return await self._process_response(resp)
                elif method == "POST":
                    async with self.session.post(full_url, headers=headers, json={}) as resp:
                        return await self._process_response(resp)
                elif method == "PUT":
                    async with self.session.put(full_url, headers=headers, json={}) as resp:
                        return await self._process_response(resp)
                elif method == "DELETE":
                    async with self.session.delete(full_url, headers=headers) as resp:
                        return await self._process_response(resp)
                else:
                    async with self.session.get(full_url, headers=headers) as resp:
                        return await self._process_response(resp)
                        
            except Exception as e:
                self.error_count += 1
                return {
                    "status": 0,
                    "error": str(e),
                    "body": {}
                }
    
    async def _process_response(self, response) -> Dict[str, Any]:
        """معالجة الاستجابة"""
        try:
            content_type = response.headers.get('Content-Type', '')
            if 'application/json' in content_type:
                body = await response.json()
            else:
                body = await response.text()
                
            return {
                "status": response.status,
                "body": body,
                "headers": dict(response.headers)
            }
        except:
            return {
                "status": response.status,
                "body": {},
                "headers": dict(response.headers)
            }
    
    def _is_vulnerable(
        self,
        response_a: Dict[str, Any],
        response_b: Dict[str, Any],
        auth_a: Dict[str, Any],
        auth_b: Dict[str, Any]
    ) -> Optional[bool]:
        """التحقق من وجود ثغرة BOLA

        Returns:
            True  -> confirmed BOLA
            False -> not vulnerable
            None  -> inconclusive
        """
        
        # إذا كان المستخدم الثاني له صلاحيات أعلى، قد يكون طبيعياً
        if self._is_higher_privilege(auth_b, auth_a):
            return False

        # إذا فشل أي طلب
        if response_a is None or response_b is None:
            logger.warning("Inconclusive: request failure.")
            return None

        status_a = response_a.get("status", 0)
        status_b = response_b.get("status", 0)

        # baseline (user_a) يجب أن ينجح
        if not (200 <= status_a < 300):
            logger.warning("Baseline user does not successfully access object. Inconclusive.")
            return None

        # challenger (user_b) لم ينجح => ليست BOLA
        if not (200 <= status_b < 300):
            return False

        # إذا كان الردان متطابقين أو متشابهين جداً
        if self._responses_similar(response_a, response_b):
            return True
        
        return False
    
    def _is_higher_privilege(self, auth1: Dict[str, Any], auth2: Dict[str, Any]) -> bool:
        """التحقق إذا كانت صلاحيات auth1 أعلى من auth2"""
        roles_hierarchy = ["admin", "support", "customer", "user"]
        
        role1 = auth1.get("role", "user")
        role2 = auth2.get("role", "user")
        
        try:
            idx1 = roles_hierarchy.index(role1.lower())
            idx2 = roles_hierarchy.index(role2.lower())
            return idx1 < idx2  # أصغر index = صلاحيات أعلى
        except:
            return False
    
    def _responses_similar(
        self,
        response_a: Dict[str, Any],
        response_b: Dict[str, Any],
        threshold: float = 0.7
    ) -> bool:
        """التحقق من تشابه الردود"""
        import difflib
        
        # معالجة خاصة للـ JSON
        body_a = response_a.get("body", {})
        body_b = response_b.get("body", {})
        
        # تحويل إلى نص للمقارنة
        str_a = json.dumps(body_a, sort_keys=True) if isinstance(body_a, dict) else str(body_a)
        str_b = json.dumps(body_b, sort_keys=True) if isinstance(body_b, dict) else str(body_b)
        
        similarity = difflib.SequenceMatcher(None, str_a, str_b).ratio()
        return similarity >= threshold
    
    def _extract_ids_from_response(
        self,
        body: Any,
        validation_rules: Dict[str, Any]
    ) -> List[str]:
        """استخراج IDs من الاستجابة"""
        ids = []
        
        def extract_from_dict(d: dict, path=""):
            for key, value in d.items():
                current_path = f"{path}.{key}" if path else key
                
                if key in ["id", "user_id", "userId", "uuid"] and isinstance(value, (str, int)):
                    ids.append(str(value))
                elif isinstance(value, dict):
                    extract_from_dict(value, current_path)
                elif isinstance(value, list):
                    for item in value[:5]:  # تحديد
                        if isinstance(item, dict):
                            extract_from_dict(item, f"{current_path}[]")
        
        if isinstance(body, dict):
            extract_from_dict(body)
        elif isinstance(body, list):
            for item in body[:5]:
                if isinstance(item, dict):
                    extract_from_dict(item)
        
        # تصفية بناءً على regex إذا وجد
        regex = validation_rules.get("owner_field_regex")
        if regex:
            ids = [id_str for id_str in ids if re.match(regex, id_str)]
        
        return list(set(ids))  # إزالة التكرارات
    
    def _build_url(self, endpoint: str, object_id: str) -> str:
        """بناء URL"""
        return endpoint.replace("{id}", object_id).replace("{user_id}", object_id)
    
    def _generate_user_pairs(self, user_ids: List[str]) -> List[List[str]]:
        """توليد أزواج المستخدمين"""
        pairs = []
        if len(user_ids) >= 2:
            # أول مستخدمين
            pairs.append([user_ids[0], user_ids[1]])
            
            # إذا كان هناك أكثر من مستخدمين، إنشاء أزواج إضافية
            if len(user_ids) > 2:
                for i in range(2, len(user_ids)):
                    pairs.append([user_ids[0], user_ids[i]])
        
        return pairs
    
    def _safety_check_failed(self) -> bool:
        """التحقق من حدود السلامة"""
        if not self.safety_config:
            return False
        
        # التحقق من الحد الأقصى للطلبات
        max_requests = self.safety_config.get("max_requests_total", 1000)
        if self.total_requests >= max_requests:
            logger.warning(f"Max requests limit reached: {max_requests}")
            return True
        
        # التحقق من معدل الأخطاء
        error_rate_limit = self.safety_config.get("auto_stop_on_error_rate", 0.1)
        if self.total_requests > 10:
            error_rate = self.error_count / self.total_requests
            if error_rate > error_rate_limit:
                logger.warning(f"Error rate too high: {error_rate:.2f} > {error_rate_limit}")
                return True
        
        # التحقق من الوقت
        if self.start_time:
            elapsed = time.time() - self.start_time
            if elapsed > 3600:  # ساعة واحدة
                logger.warning("Scan time exceeded 1 hour")
                return True
        
        return False
    
    def _create_finding(
        self,
        resource: Dict[str, Any],
        object_id: str,
        method: str,
        user_a_id: str,
        user_b_id: str,
        response_a: Dict[str, Any],
        response_b: Dict[str, Any]
    ) -> Dict[str, Any]:
        """إنشاء نتيجة اكتشاف"""
        
        # حساب الشدة
        severity = self._calculate_severity(resource, method, response_a, response_b)
        
        return {
            "resource": resource.get("name", "Unknown"),
            "endpoint": resource.get("endpoint", ""),
            "object_id": object_id,
            "method": method,
            "issue": "broken_object_level_authorization",
            "severity": severity,
            "confidence": 85,
            "details": {
                "user_a": user_a_id,
                "user_b": user_b_id,
                "response_a_status": response_a.get("status"),
                "response_b_status": response_b.get("status"),
                "similarity_score": self._responses_similar(response_a, response_b),
                "resource_sensitivity": resource.get("sensitivity", {}).get("level", "MEDIUM"),
                "owner_field": resource.get("owner_field", "unknown")
            },
            "remediation": "Implement proper authorization checks that verify the requesting user owns the requested resource.",
            "cvss_score": 8.1 if severity == "critical" else 6.5
        }
    
    def _calculate_severity(
        self,
        resource: Dict[str, Any],
        method: str,
        response_a: Dict[str, Any],
        response_b: Dict[str, Any]
    ) -> str:
        """حساب شدة الثغرة"""
        
        # الطرق التغييرية أكثر خطورة
        if method in ["DELETE", "PUT", "POST"]:
            base_severity = "critical"
        else:
            base_severity = "high"
        
        # حساسية البيانات
        sensitivity = resource.get("sensitivity", {}).get("level", "MEDIUM")
        if sensitivity == "HIGH":
            if base_severity == "high":
                base_severity = "critical"
        
        # حالة الرد
        if response_a.get("status", 0) == 200 and response_b.get("status", 0) == 200:
            base_severity = "critical" if base_severity != "critical" else base_severity
        
        return base_severity
