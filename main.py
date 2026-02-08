#!/usr/bin/env python3
"""
Security API Scanner - Main Application
أداة متكاملة لفحص الثغرات الأمنية في واجهات برمجة التطبيقات
"""

import asyncio
import logging
import argparse
import sys
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from scanners.bola_scanner import BOLAScanner
from scanners.rate_limit_scanner import RateLimitScanner
from scanners.injection_scanner import InjectionScanner
from models.api_resource import ApiResource
from models.auth_context import AuthContext
from utils.config_loader import ConfigLoader
from utils.report_generator import ReportGenerator
from utils.logging_setup import setup_logging

logger = logging.getLogger(__name__)

class SecurityAPIScanner:
    """الفئة الرئيسية لإدارة عمليات المسح الأمني"""
    
    def __init__(self, config_path: str = "config.yaml"):
        """
        تهيئة الماسح الأمني
        
        Args:
            config_path: مسار ملف الإعدادات
        """
        self.config = ConfigLoader.load(config_path)
        self.resources: List[ApiResource] = []
        self.auth_contexts: Dict[str, AuthContext] = {}
        self.findings: List[Dict[str, Any]] = []
        
        # إعداد التسجيل
        setup_logging(
            log_level=self.config.get("logging", {}).get("level", "INFO"),
            log_file=self.config.get("logging", {}).get("file", "scanner.log")
        )
        
        # تهيئة الماسحات
        self.scanners = self._initialize_scanners()
        
    def _initialize_scanners(self) -> Dict[str, Any]:
        """تهيئة جميع الماسحات"""
        scanners_config = self.config.get("scanners", {})
        
        scanners = {
            "bola": BOLAScanner(
                base_url=self.config.get("api", {}).get("base_url", ""),
                rate_limit=scanners_config.get("bola", {}).get("rate_limit", 1.0),
                max_concurrent=scanners_config.get("bola", {}).get("max_concurrent", 5),
                timeout=scanners_config.get("bola", {}).get("timeout", 30),
                strict_owner=scanners_config.get("bola", {}).get("strict_owner", False)
            ),
            "rate_limit": RateLimitScanner(
                base_url=self.config.get("api", {}).get("base_url", ""),
                max_concurrent=scanners_config.get("rate_limit", {}).get("max_concurrent", 10)
            ),
            "injection": InjectionScanner(
                base_url=self.config.get("api", {}).get("base_url", ""),
                payloads_file=scanners_config.get("injection", {}).get("payloads_file", "payloads/sqli.txt")
            )
        }
        
        logger.info(f"Initialized {len(scanners)} scanners")
        return scanners
    
    def load_resources(self, resources_file: Optional[str] = None):
        """تحميل مصادر API"""
        resources_file = resources_file or self.config.get("api", {}).get("resources_file", "resources.json")
        
        try:
            with open(resources_file, 'r', encoding='utf-8') as f:
                resources_data = json.load(f)
            
            self.resources = [
                ApiResource.from_dict(resource) 
                for resource in resources_data.get("resources", [])
            ]
            
            logger.info(f"Loaded {len(self.resources)} API resources from {resources_file}")
            
        except FileNotFoundError:
            logger.error(f"Resources file not found: {resources_file}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in resources file: {e}")
            sys.exit(1)
    
    def load_auth_contexts(self, auth_file: Optional[str] = None):
        """تحميل سياقات المصادقة"""
        auth_file = auth_file or self.config.get("auth", {}).get("auth_file", "auth.json")
        
        try:
            with open(auth_file, 'r', encoding='utf-8') as f:
                auth_data = json.load(f)
            
            for user_id, auth_info in auth_data.get("users", {}).items():
                self.auth_contexts[user_id] = AuthContext(
                    user_id=user_id,
                    token=auth_info.get("token"),
                    headers=auth_info.get("headers", {}),
                    cookies=auth_info.get("cookies", {}),
                    token_type=auth_info.get("token_type", "Bearer"),
                    token_refresh_url=auth_info.get("token_refresh_url")
                )
            
            logger.info(f"Loaded {len(self.auth_contexts)} authentication contexts")
            
        except FileNotFoundError:
            logger.error(f"Auth file not found: {auth_file}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in auth file: {e}")
            sys.exit(1)
    
    async def run_scan(self, scanner_types: List[str], dry_run: bool = False) -> Dict[str, Any]:
        """
        تشغيل عملية المسح
        
        Args:
            scanner_types: أنواع الماسحات المراد تشغيلها
            dry_run: إذا كان True، يعرض فقط ما سيتم تنفيذه
        
        Returns:
            نتائج المسح
        """
        start_time = datetime.now()
        logger.info(f"Starting security scan at {start_time}")
        logger.info(f"Scanners to run: {', '.join(scanner_types)}")
        logger.info(f"Dry run mode: {dry_run}")
        
        if dry_run:
            self._dry_run_analysis(scanner_types)
            return {"status": "dry_run_completed"}
        
        # تشغيل الماسحات المحددة
        all_findings = []
        
        for scanner_name in scanner_types:
            if scanner_name in self.scanners:
                logger.info(f"Running {scanner_name} scanner...")
                
                try:
                    scanner = self.scanners[scanner_name]
                    
                    if scanner_name == "bola":
                        findings = await scanner.scan(
                            resources=self.resources,
                            auth_contexts=self.auth_contexts,
                            dry_run=False
                        )
                    elif scanner_name == "rate_limit":
                        findings = await scanner.scan(
                            resources=self.resources
                        )
                    elif scanner_name == "injection":
                        findings = await scanner.scan(
                            resources=self.resources,
                            auth_contexts=self.auth_contexts
                        )
                    else:
                        logger.warning(f"Unknown scanner: {scanner_name}")
                        continue
                    
                    all_findings.extend(findings)
                    logger.info(f"{scanner_name} scanner found {len(findings)} issues")
                    
                except Exception as e:
                    logger.error(f"Scanner {scanner_name} failed: {e}")
            else:
                logger.warning(f"Scanner {scanner_name} not available")
        
        # تخزين النتائج
        self.findings = all_findings
        
        # حساب الوقت المستغرق
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # إعداد النتائج
        results = {
            "scan_id": f"scan_{start_time.strftime('%Y%m%d_%H%M%S')}",
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": duration,
            "scanners_executed": scanner_types,
            "resources_scanned": len(self.resources),
            "total_findings": len(all_findings),
            "findings_by_severity": self._categorize_findings(all_findings),
            "findings": all_findings
        }
        
        logger.info(f"Scan completed in {duration:.2f} seconds")
        logger.info(f"Total findings: {len(all_findings)}")
        
        return results
    
    def _dry_run_analysis(self, scanner_types: List[str]):
        """تحليل ما سيتم تنفيذه في وضع dry run"""
        logger.info("=== DRY RUN ANALYSIS ===")
        logger.info(f"Resources to scan: {len(self.resources)}")
        
        for resource in self.resources:
            logger.info(f"  - {resource.name}: {resource.endpoint} ({', '.join(resource.methods)})")
        
        logger.info(f"\nAuthentication contexts: {len(self.auth_contexts)}")
        for user_id, ctx in self.auth_contexts.items():
            logger.info(f"  - {user_id}: {ctx.token_type} token")
        
        logger.info(f"\nScanners to execute: {', '.join(scanner_types)}")
        
        # تحليل BOLA خاص
        if "bola" in scanner_types:
            bola_resources = [r for r in self.resources if self._is_bola_target(r)]
            logger.info(f"\nBOLA targets: {len(bola_resources)}")
            for resource in bola_resources:
                logger.info(f"  - {resource.name} (owner_field: {resource.owner_field})")
    
    def _is_bola_target(self, resource: ApiResource) -> bool:
        """تحقق إذا كان المورد هدفًا محتملاً لـ BOLA"""
        return "{id}" in resource.endpoint and resource.owner_field
    
    def _categorize_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """تصنيف النتائج حسب الشدة"""
        categories = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            categories[severity] = categories.get(severity, 0) + 1
        
        return categories
    
    def generate_report(self, scan_results: Dict[str, Any], output_format: str = "json"):
        """إنشاء تقرير عن النتائج"""
        report_generator = ReportGenerator()
        
        if output_format == "json":
            report = report_generator.generate_json_report(scan_results)
            output_file = f"reports/{scan_results['scan_id']}.json"
            
            # إنشاء مجلد reports إذا لم يكن موجودًا
            Path("reports").mkdir(exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            logger.info(f"JSON report saved to: {output_file}")
            
        elif output_format == "html":
            report_file = report_generator.generate_html_report(scan_results)
            logger.info(f"HTML report saved to: {report_file}")
            
        elif output_format == "console":
            report_generator.print_console_report(scan_results)
            
        else:
            logger.error(f"Unsupported report format: {output_format}")
    
    async def interactive_mode(self):
        """الوضع التفاعلي للماسح"""
        print("\n" + "="*50)
        print("  API Security Scanner - Interactive Mode")
        print("="*50)
        
        while True:
            print("\nAvailable commands:")
            print("  1. List resources")
            print("  2. List auth contexts")
            print("  3. Run BOLA scan")
            print("  4. Run Rate Limit scan")
            print("  5. Run Injection scan")
            print("  6. Run comprehensive scan")
            print("  7. Generate report")
            print("  8. Exit")
            
            try:
                choice = input("\nSelect option (1-8): ").strip()
                
                if choice == "1":
                    self._print_resources()
                elif choice == "2":
                    self._print_auth_contexts()
                elif choice == "3":
                    await self._run_single_scanner("bola")
                elif choice == "4":
                    await self._run_single_scanner("rate_limit")
                elif choice == "5":
                    await self._run_single_scanner("injection")
                elif choice == "6":
                    await self._run_comprehensive_scan()
                elif choice == "7":
                    if self.findings:
                        self.generate_report({
                            "scan_id": f"interactive_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                            "findings": self.findings
                        }, "console")
                    else:
                        print("No findings to report. Run a scan first.")
                elif choice == "8":
                    print("Exiting...")
                    break
                else:
                    print("Invalid choice. Please try again.")
                    
            except KeyboardInterrupt:
                print("\nInterrupted by user")
                break
            except Exception as e:
                print(f"Error: {e}")
    
    def _print_resources(self):
        """عرض قائمة الموارد"""
        print(f"\nLoaded {len(self.resources)} resources:")
        for i, resource in enumerate(self.resources, 1):
            print(f"{i}. {resource.name}")
            print(f"   Endpoint: {resource.endpoint}")
            print(f"   Methods: {', '.join(resource.methods)}")
            if resource.owner_field:
                print(f"   Owner field: {resource.owner_field}")
            print()
    
    def _print_auth_contexts(self):
        """عرض سياقات المصادقة"""
        print(f"\nLoaded {len(self.auth_contexts)} auth contexts:")
        for user_id, ctx in self.auth_contexts.items():
            print(f"  {user_id}:")
            print(f"    Token type: {ctx.token_type}")
            print(f"    Headers: {len(ctx.headers)}")
            print(f"    Cookies: {len(ctx.cookies)}")
            if ctx.token_refresh_url:
                print(f"    Token refresh: {ctx.token_refresh_url}")
    
    async def _run_single_scanner(self, scanner_name: str):
        """تشغيل ماسح واحد"""
        print(f"\nRunning {scanner_name} scanner...")
        
        results = await self.run_scan([scanner_name])
        
        if scanner_name == "bola" and "user_a" not in self.auth_contexts:
            print("Warning: BOLA scan requires at least 2 users (user_a and user_b)")
            return
        
        print(f"Scan completed. Found {results.get('total_findings', 0)} issues.")
        
        if results.get('findings'):
            self.findings.extend(results['findings'])
            self._print_findings_summary(results['findings'])
    
    async def _run_comprehensive_scan(self):
        """تشغيل جميع الماسحات"""
        print("\nRunning comprehensive security scan...")
        
        all_scanners = list(self.scanners.keys())
        results = await self.run_scan(all_scanners)
        
        print(f"\nComprehensive scan completed.")
        print(f"Duration: {results.get('duration_seconds', 0):.2f} seconds")
        print(f"Total findings: {results.get('total_findings', 0)}")
        
        severity_counts = results.get('findings_by_severity', {})
        for severity, count in severity_counts.items():
            if count > 0:
                print(f"  {severity.upper()}: {count}")
        
        if results.get('findings'):
            self.findings = results['findings']
    
    def _print_findings_summary(self, findings: List[Dict[str, Any]]):
        """عرض ملخص النتائج"""
        if not findings:
            print("No security issues found.")
            return
        
        print(f"\nFound {len(findings)} security issues:")
        
        for i, finding in enumerate(findings, 1):
            print(f"{i}. [{finding.get('severity', 'unknown').upper()}] {finding.get('resource', 'Unknown')}")
            print(f"   Endpoint: {finding.get('method', 'GET')} {finding.get('endpoint', 'Unknown')}")
            print(f"   Issue: {finding.get('issue', 'Unknown')}")
            print()

def main():
    """الدالة الرئيسية للتشغيل"""
    parser = argparse.ArgumentParser(
        description="API Security Scanner - Comprehensive API vulnerability assessment tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --config config.yaml --scan bola
  %(prog)s --interactive
  %(prog)s --dry-run --scan all
  %(prog)s --resources my_resources.json --auth my_auth.json
        """
    )
    
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to configuration file (default: config.yaml)"
    )
    
    parser.add_argument(
        "--resources",
        help="Path to API resources file (overrides config)"
    )
    
    parser.add_argument(
        "--auth",
        help="Path to authentication file (overrides config)"
    )
    
    parser.add_argument(
        "--scan",
        choices=["bola", "rate_limit", "injection", "all"],
        nargs="+",
        default=["all"],
        help="Scanners to run (default: all)"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be scanned without making requests"
    )
    
    parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="Run in interactive mode"
    )
    
    parser.add_argument(
        "--report-format",
        choices=["json", "html", "console"],
        default="json",
        help="Output report format (default: json)"
    )
    
    parser.add_argument(
        "--output",
        "-o",
        help="Output file for report (default: auto-generated)"
    )
    
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # إنشاء الماسح
    scanner = SecurityAPIScanner(args.config)
    
    # تحميل الموارد وسياقات المصادقة
    scanner.load_resources(args.resources)
    scanner.load_auth_contexts(args.auth)
    
    # تحديد الماسحات المراد تشغيلها
    if "all" in args.scan:
        scanner_types = list(scanner.scanners.keys())
    else:
        scanner_types = args.scan
    
    # الوضع التفاعلي
    if args.interactive:
        asyncio.run(scanner.interactive_mode())
        return
    
    # الوضع العادي
    try:
        # تشغيل المسح
        results = asyncio.run(scanner.run_scan(scanner_types, args.dry_run))
        
        # إنشاء التقرير إذا لم يكن dry run
        if not args.dry_run and results.get("status") != "dry_run_completed":
            scanner.generate_report(results, args.report_format)
            
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error during scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
