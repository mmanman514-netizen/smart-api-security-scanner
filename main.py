#!/usr/bin/env python3
"""
Security API Scanner - Main Application with v2.1 config support
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
from utils.config_loader import ConfigLoader
from utils.report_generator import ReportGenerator
from utils.logging_setup import setup_logging

logger = logging.getLogger(__name__)

class SecurityAPIScanner:
    """الفئة الرئيسية مع دعم v2.1"""
    
    def __init__(self, config_path: str = "config.json"):
        """
        تهيئة الماسح الأمني
        
        Args:
            config_path: مسار ملف الإعدادات (JSON v2.1 أو YAML v1)
        """
        # تحميل التكوين
        self.config = ConfigLoader.load(config_path)
        
        # تحميل الموارد وسياقات المصادقة من نفس الملف
        self.resources = ConfigLoader.load_resources(config_path)
        self.auth_contexts = ConfigLoader.load_auth_contexts(config_path)
        
        # إعداد التسجيل
        setup_logging(
            log_level=self.config.get("logging", {}).get("level", "INFO"),
            log_file=self.config.get("logging", {}).get("file", "scanner.log")
        )
        
        # تحميل إعدادات السلامة
        self.safety_config = self.config.get("safety", {})
        
        # التحقق من البيئة
        self._validate_environment()
        
        # تهيئة الماسحات
        self.scanners = self._initialize_scanners()
        
        self.findings: List[Dict[str, Any]] = []
        
    def _validate_environment(self):
        """التحقق من البيئة قبل المسح"""
        base_url = self.config.get("api", {}).get("base_url", "")
        
        # التحقق من النطاقات غير المسموحة
        disallowed_domains = self.safety_config.get("disallowed_domains", [])
        for domain in disallowed_domains:
            if domain in base_url:
                raise ValueError(f"Scanning disallowed domain: {domain}")
        
        # التحقق من البيئات المسموحة
        allowed_envs = self.safety_config.get("allowed_environments", [])
        if allowed_envs:
            env_allowed = False
            for env in allowed_envs:
                if env.lower() in base_url.lower():
                    env_allowed = True
                    break
            
            if not env_allowed and "production" not in base_url.lower():
                logger.warning(f"Target environment may not be in allowed list: {allowed_envs}")
        
        logger.info(f"Environment validation passed for: {base_url}")
    
    def _initialize_scanners(self) -> Dict[str, BOLAScanner]:
        """تهيئة الماسحات مع إعدادات v2.1"""
        scanners_config = self.config.get("scanners", {})
        bola_config = scanners_config.get("bola", {})
        
        # إعدادات متقدمة من v2.1
        scanner = BOLAScanner(
            base_url=self.config.get("api", {}).get("base_url", ""),
            rate_limit=bola_config.get("rate_limit", 2.0),
            max_concurrent=bola_config.get("max_concurrent", 5),
            timeout=bola_config.get("timeout", 30),
            strict_owner=bola_config.get("strict_owner", True),
            # إعدادات متقدمة
            id_patterns=bola_config.get("id_patterns", []),
            user_pairs=bola_config.get("user_pairs", []),
            safety_config=self.safety_config
        )
        
        # إضافة الـ headers الافتراضية
        default_headers = self.config.get("api", {}).get("default_headers", {})
        scanner.default_headers = default_headers
        
        return {"bola": scanner}
    
    async def run_bola_scan(self, dry_run: bool = False) -> Dict[str, Any]:
        """تشغيل مسح BOLA مع إعدادات v2.1"""
        start_time = datetime.now()
        logger.info(f"🚀 Starting BOLA scan with v2.1 configuration")
        
        if dry_run:
            return self._dry_run_analysis()
        
        try:
            scanner = self.scanners["bola"]
            
            # تشغيل المسح
            async with scanner:
                findings = await scanner.scan(
                    resources=self.resources,
                    auth_contexts=self.auth_contexts,
                    dry_run=False
                )
            
            self.findings = findings
            
            # إعداد النتائج
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            results = {
                "scan_id": f"bola_scan_{start_time.strftime('%Y%m%d_%H%M%S')}",
                "config_version": "2.1",
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration_seconds": duration,
                "resources_scanned": len(self.resources),
                "users_tested": len(self.auth_contexts),
                "total_findings": len(findings),
                "findings_by_severity": self._categorize_findings(findings),
                "safety_checks": {
                    "max_requests": self.safety_config.get("max_requests_total", 1000),
                    "error_rate_limit": self.safety_config.get("auto_stop_on_error_rate", 0.1),
                    "environment_validated": True
                },
                "findings": findings
            }
            
            logger.info(f"✅ BOLA scan completed in {duration:.2f} seconds")
            logger.info(f"📊 Findings: {len(findings)} total")
            
            return results
            
        except Exception as e:
            logger.error(f"❌ BOLA scan failed: {e}")
            raise
    
    def _dry_run_analysis(self) -> Dict[str, Any]:
        """تحليل ما سيتم تنفيذه"""
        logger.info("🔍 DRY RUN ANALYSIS (v2.1 Config)")
        logger.info(f"Base URL: {self.config.get('api', {}).get('base_url', '')}")
        logger.info(f"Resources to scan: {len(self.resources)}")
        
        for resource in self.resources:
            logger.info(f"  • {resource['name']}: {resource['endpoint']}")
        
        logger.info(f"\nAuthentication contexts: {len(self.auth_contexts)}")
        for user_id, ctx in self.auth_contexts.items():
            logger.info(f"  • {user_id} ({ctx.get('role', 'user')})")
        
        # عرض أنماط ID
        bola_config = self.config.get("scanners", {}).get("bola", {})
        id_patterns = bola_config.get("id_patterns", [])
        if id_patterns:
            logger.info(f"\nID Patterns to test:")
            for pattern in id_patterns:
                logger.info(f"  • {pattern.get('type', 'numeric')}: {pattern.get('range', 'N/A')}")
        
        return {
            "status": "dry_run_completed",
            "resources_count": len(self.resources),
            "users_count": len(self.auth_contexts),
            "config_version": "2.1"
        }
    
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
        from utils.report_generator import ReportGenerator
        report_generator = ReportGenerator()
        
        # إضافة معلومات التكوين
        scan_results["config_metadata"] = {
            "version": "2.1",
            "environment": self.config.get("metadata", {}).get("environment", "unknown"),
            "safety_controls_applied": True
        }
        
        if output_format == "json":
            report = report_generator.generate_json_report(scan_results)
            output_file = f"reports/{scan_results['scan_id']}.json"
            
            Path("reports").mkdir(exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            logger.info(f"📄 JSON report saved to: {output_file}")
            
        elif output_format == "html":
            report_file = report_generator.generate_html_report(scan_results)
            logger.info(f"📄 HTML report saved to: {report_file}")
            
        elif output_format == "console":
            report_generator.print_console_report(scan_results)
            
        else:
            logger.error(f"Unsupported report format: {output_format}")
    
    async def interactive_mode(self):
        """الوضع التفاعلي للماسح"""
        print("\n" + "="*50)
        print("  API Security Scanner v2.1 - Interactive Mode")
        print("="*50)
        
        while True:
            print("\nAvailable commands:")
            print("  1. Show configuration summary")
            print("  2. List resources")
            print("  3. List auth contexts")
            print("  4. Run BOLA scan")
            print("  5. Run BOLA scan (dry run)")
            print("  6. Generate report")
            print("  7. Exit")
            
            try:
                choice = input("\nSelect option (1-7): ").strip()
                
                if choice == "1":
                    self._show_config_summary()
                elif choice == "2":
                    self._print_resources()
                elif choice == "3":
                    self._print_auth_contexts()
                elif choice == "4":
                    await self._run_bola_scan_ui()
                elif choice == "5":
                    await self._run_bola_dry_run_ui()
                elif choice == "6":
                    if self.findings:
                        self.generate_report({
                            "scan_id": f"interactive_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                            "findings": self.findings
                        }, "console")
                    else:
                        print("No findings to report. Run a scan first.")
                elif choice == "7":
                    print("Exiting...")
                    break
                else:
                    print("Invalid choice. Please try again.")
                    
            except KeyboardInterrupt:
                print("\nInterrupted by user")
                break
            except Exception as e:
                print(f"Error: {e}")
    
    def _show_config_summary(self):
        """عرض ملخص التكوين"""
        print("\n📋 CONFIGURATION SUMMARY (v2.1)")
        print("-" * 40)
        print(f"Base URL: {self.config.get('api', {}).get('base_url', 'N/A')}")
        print(f"Environment: {self.config.get('metadata', {}).get('environment', 'N/A')}")
        print(f"Resources: {len(self.resources)}")
        print(f"Auth Contexts: {len(self.auth_contexts)}")
        
        # عرض إعدادات السلامة
        safety = self.safety_config
        print(f"\n🔒 SAFETY CONTROLS:")
        print(f"  Max Requests: {safety.get('max_requests_total', 'N/A')}")
        print(f"  Error Rate Limit: {safety.get('auto_stop_on_error_rate', 'N/A')}")
        print(f"  Disallowed Domains: {len(safety.get('disallowed_domains', []))}")
    
    def _print_resources(self):
        """عرض قائمة الموارد"""
        print(f"\n📁 Loaded {len(self.resources)} resources:")
        for i, resource in enumerate(self.resources, 1):
            print(f"{i}. {resource['name']}")
            print(f"   Endpoint: {resource['endpoint']}")
            print(f"   Methods: {', '.join(resource.get('methods', []))}")
            if 'owner_field' in resource:
                print(f"   Owner field: {resource['owner_field']}")
            print()
    
    def _print_auth_contexts(self):
        """عرض سياقات المصادقة"""
        print(f"\n👤 Loaded {len(self.auth_contexts)} auth contexts:")
        for user_id, ctx in self.auth_contexts.items():
            print(f"  {user_id}:")
            print(f"    Role: {ctx.get('role', 'N/A')}")
            print(f"    Token type: {ctx.get('token_type', 'N/A')}")
            print(f"    Expected scopes: {', '.join(ctx.get('expected_scopes', []))}")
    
    async def _run_bola_scan_ui(self):
        """تشغيل BOLA scan من الواجهة"""
        print("\n🚀 Running BOLA scan...")
        
        try:
            results = await self.run_bola_scan(dry_run=False)
            
            print(f"\n✅ Scan completed!")
            print(f"Duration: {results.get('duration_seconds', 0):.2f} seconds")
            print(f"Total findings: {results.get('total_findings', 0)}")
            
            severity_counts = results.get('findings_by_severity', {})
            for severity, count in severity_counts.items():
                if count > 0:
                    print(f"  {severity.upper()}: {count}")
            
            if results.get('findings'):
                self.findings = results['findings']
                print("\n📋 Generate report with option 6")
        
        except Exception as e:
            print(f"❌ Scan failed: {e}")
    
    async def _run_bola_dry_run_ui(self):
        """تشغيل dry run من الواجهة"""
        print("\n🔍 Running BOLA scan (dry run)...")
        
        results = await self.run_bola_scan(dry_run=True)
        print(f"\n✅ Dry run completed. Would scan:")
        print(f"   Resources: {results.get('resources_count', 0)}")
        print(f"   Users: {results.get('users_count', 0)}")

def main():
    """الدالة الرئيسية للتشغيل"""
    parser = argparse.ArgumentParser(
        description="API Security Scanner v2.1 - Comprehensive API vulnerability assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples with v2.1 config:
  %(prog)s --config config.json                    # Scan with v2.1 config
  %(prog)s --config config.json --dry-run         # Dry run analysis
  %(prog)s --interactive                          # Interactive mode
  %(prog)s --config config.json --report html     # Generate HTML report

Environment variables required:
  USER_A_TOKEN, USER_B_TOKEN, ADMIN_API_KEY (as defined in config)
        """
    )
    
    parser.add_argument(
        "--config",
        default="config.json",
        help="Path to configuration file (v2.1 JSON or v1 YAML)"
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
        "--report",
        choices=["json", "html", "console"],
        default="json",
        help="Output report format"
    )
    
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # التحقق من وجود الملف
    if not Path(args.config).exists():
        print(f"Error: Config file not found: {args.config}")
        sys.exit(1)
    
    # إنشاء الماسح
    try:
        scanner = SecurityAPIScanner(args.config)
    except Exception as e:
        print(f"Error initializing scanner: {e}")
        sys.exit(1)
    
    # الوضع التفاعلي
    if args.interactive:
        asyncio.run(scanner.interactive_mode())
        return
    
    # الوضع العادي
    try:
        # تشغيل المسح
        results = asyncio.run(scanner.run_bola_scan(args.dry_run))
        
        # إنشاء التقرير إذا لم يكن dry run
        if not args.dry_run and results.get("status") != "dry_run_completed":
            scanner.generate_report(results, args.report)
            
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error during scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
