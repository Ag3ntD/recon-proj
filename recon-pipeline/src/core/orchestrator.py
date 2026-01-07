#!/usr/bin/env python3
"""
Main Orchestrator for Recon Pipeline
Coordinates all scanning phases with error handling and database storage
"""

import sys
import os
import yaml
import time
from datetime import datetime
from typing import Dict, Any, List, Optional

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from database.models import (
    DatabaseManager, Target, Scan, Subdomain, URL, 
    Finding, Secret, JavaScript, Notification
)
from utils.helpers import (
    RateLimiter, ScopeValidator, URLNormalizer, 
    Deduplicator, BatchProcessor, Logger, ToolValidator
)
from scanners.subdomain_enum import SubdomainEnumerator, LiveHostDetector, DNSAnalyzer
from scanners.vuln_scan import VulnerabilityScanner, CORSChecker
from scanners.javascript import JavaScriptAnalyzer
from core.notifications import NotificationManager


class ReconPipeline:
    """
    Main orchestrator for reconnaissance and vulnerability scanning
    """
    
    def __init__(self, config_path: str):
        """
        Initialize the recon pipeline
        
        Args:
            config_path: Path to configuration file
        """
        # Load configuration
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Initialize logger
        log_level = self.config.get('output', {}).get('log_level', 'INFO')
        self.logger = Logger("recon-pipeline", log_level)
        log_file = self.config.get('output', {}).get('log_file', 'logs/recon-pipeline.log')
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        self.logger.set_log_file(log_file)
        
        # Initialize database
        self.db_manager = DatabaseManager(self.config)
        try:
            self.db_manager.initialize()
            self.logger.info("Database initialized successfully")
        except Exception as e:
            self.logger.critical(f"Failed to initialize database: {str(e)}")
            raise
        
        # Initialize utilities
        rate_limit = self.config.get('scan', {}).get('rate_limits', {}).get('default', 10)
        self.rate_limiter = RateLimiter(rate=rate_limit)
        
        inscope = self.config.get('target', {}).get('scope', [])
        exclude = self.config.get('target', {}).get('exclude', [])
        self.scope_validator = ScopeValidator(inscope, exclude)
        
        batch_size = self.config.get('scan', {}).get('batch_size', 25)
        batch_delay = self.config.get('scan', {}).get('batch_delay', 5)
        self.batch_processor = BatchProcessor(batch_size, batch_delay)
        
        self.deduplicator = Deduplicator()
        
        # Initialize notification manager
        self.notifier = NotificationManager(self.config, self.logger)
        
        # Target domain
        self.target_domain = self.config.get('target', {}).get('domain', '')
        
        # Scan results
        self.results = {
            'subdomains': [],
            'live_hosts': [],
            'urls': [],
            'findings': [],
            'secrets': [],
            'js_files': []
        }
    
    def validate_tools(self) -> bool:
        """
        Validate that required tools are installed
        
        Returns:
            True if all required tools are available
        """
        self.logger.info("Validating required tools...")
        
        required_tools = []
        
        # Subdomain enumeration tools
        if self.config.get('scan', {}).get('passive_recon', True):
            required_tools.extend(
                self.config.get('tools', {}).get('subdomain_enum', [])
            )
            required_tools.append('httpx')
        
        # Vulnerability scanning tools
        if self.config.get('scan', {}).get('vulnerability_scanning', True):
            required_tools.extend(['nuclei', 'dalfox', 'subzy'])
        
        # JavaScript analysis tools
        if self.config.get('scan', {}).get('javascript_analysis', True):
            required_tools.extend(['getJS', 'trufflehog'])
        
        # Validate
        validation_results = ToolValidator.validate_tools(list(set(required_tools)))
        all_available = ToolValidator.print_validation_report(validation_results)
        
        if not all_available:
            self.logger.warning("Some tools are missing. Scan will continue with available tools.")
        
        return True  # Continue even if some tools are missing
    
    def run(self):
        """
        Execute the complete reconnaissance and scanning pipeline
        """
        self.logger.info("=" * 70)
        self.logger.info("Starting Recon Pipeline")
        self.logger.info(f"Target: {self.target_domain}")
        self.logger.info("=" * 70)
        
        # Validate tools
        self.validate_tools()
        
        # Create/get target in database
        session = self.db_manager.get_session()
        target = session.query(Target).filter_by(domain=self.target_domain).first()
        if not target:
            target = Target(domain=self.target_domain)
            session.add(target)
            session.commit()
        
        start_time = time.time()
        
        try:
            # Phase 1: Passive Reconnaissance
            if self.config.get('scan', {}).get('passive_recon', True):
                self.phase_passive_recon(session, target)
            
            # Phase 2: Vulnerability Scanning
            if self.config.get('scan', {}).get('vulnerability_scanning', True):
                self.phase_vulnerability_scan(session, target)
            
            # Phase 3: JavaScript Analysis
            if self.config.get('scan', {}).get('javascript_analysis', True):
                self.phase_javascript_analysis(session, target)
            
            # Phase 4: Generate Reports
            self.generate_reports()
            
            # Send batch notification
            if self.results['findings']:
                self.notifier.notify_batch(self.results['findings'])
            
        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
        finally:
            session.close()
        
        elapsed = time.time() - start_time
        self.logger.info("=" * 70)
        self.logger.info(f"Scan completed in {elapsed:.2f} seconds")
        self.logger.info("=" * 70)
        self.print_summary()
    
    def phase_passive_recon(self, session, target):
        """
        Phase 1: Passive Reconnaissance
        
        Args:
            session: Database session
            target: Target database object
        """
        self.logger.info("\n" + "=" * 70)
        self.logger.info("PHASE 1: Passive Reconnaissance")
        self.logger.info("=" * 70)
        
        # Create scan record
        scan = Scan(
            target_id=target.id,
            scan_type='passive',
            status='running'
        )
        session.add(scan)
        session.commit()
        
        try:
            # Subdomain enumeration
            self.logger.info("\n[Step 1.1] Subdomain Enumeration")
            enumerator = SubdomainEnumerator(self.target_domain, self.config, self.logger)
            subdomains = enumerator.enumerate_all()
            
            # Filter by scope
            self.logger.info(f"\n[Step 1.2] Scope Validation")
            inscope_subdomains = self.scope_validator.filter_domains(subdomains)
            self.logger.info(
                f"Filtered to {len(inscope_subdomains)} in-scope subdomains "
                f"(removed {len(subdomains) - len(inscope_subdomains)} out-of-scope)"
            )
            
            # Save subdomains to database
            for subdomain in inscope_subdomains:
                if not session.query(Subdomain).filter_by(
                    target_id=target.id,
                    subdomain=subdomain
                ).first():
                    db_subdomain = Subdomain(
                        target_id=target.id,
                        subdomain=subdomain,
                        source='multiple'
                    )
                    session.add(db_subdomain)
            session.commit()
            
            self.results['subdomains'] = inscope_subdomains
            
            # Live host detection
            if inscope_subdomains:
                self.logger.info(f"\n[Step 1.3] Live Host Detection")
                detector = LiveHostDetector(self.config, self.logger, self.rate_limiter)
                live_hosts = detector.check_hosts(inscope_subdomains)
                
                # Update database
                for host_data in live_hosts:
                    subdomain_obj = session.query(Subdomain).filter_by(
                        target_id=target.id,
                        subdomain=host_data['host']
                    ).first()
                    
                    if subdomain_obj:
                        subdomain_obj.is_live = True
                        subdomain_obj.http_status = host_data.get('status_code')
                        subdomain_obj.http_title = host_data.get('title')
                        subdomain_obj.technologies = host_data.get('technologies')
                        subdomain_obj.ip_address = host_data.get('ip')
                
                session.commit()
                self.results['live_hosts'] = live_hosts
            
            # Mark scan as completed
            scan.status = 'completed'
            scan.completed_at = datetime.utcnow()
            session.commit()
            
        except Exception as e:
            self.logger.error(f"Passive recon failed: {str(e)}")
            scan.status = 'failed'
            scan.error_message = str(e)
            session.commit()
    
    def phase_vulnerability_scan(self, session, target):
        """
        Phase 2: Vulnerability Scanning
        
        Args:
            session: Database session
            target: Target database object
        """
        self.logger.info("\n" + "=" * 70)
        self.logger.info("PHASE 2: Vulnerability Scanning")
        self.logger.info("=" * 70)
        
        # Create scan record
        scan = Scan(
            target_id=target.id,
            scan_type='vuln',
            status='running'
        )
        session.add(scan)
        session.commit()
        
        try:
            # Get live host URLs
            urls = [host['url'] for host in self.results.get('live_hosts', [])]
            
            if not urls:
                self.logger.warning("No live hosts to scan")
                scan.status = 'completed'
                scan.completed_at = datetime.utcnow()
                session.commit()
                return
            
            self.logger.info(f"Scanning {len(urls)} live hosts")
            
            # Initialize scanner
            vuln_scanner = VulnerabilityScanner(
                self.config, self.logger, 
                self.rate_limiter, self.batch_processor
            )
            
            # Run vulnerability scans
            findings = vuln_scanner.scan_all(urls)
            
            # Check CORS misconfigurations
            self.logger.info("\n[Step 2.1] Checking CORS misconfigurations")
            cors_checker = CORSChecker(self.logger)
            cors_findings = cors_checker.check(urls[:10])  # Check first 10
            findings.extend(cors_findings)
            
            # Save findings to database
            for finding_data in findings:
                finding = Finding(
                    scan_id=scan.id,
                    finding_type=finding_data.get('finding_type'),
                    severity=finding_data.get('severity'),
                    title=finding_data.get('title'),
                    description=finding_data.get('description'),
                    host=finding_data.get('host'),
                    url=finding_data.get('url'),
                    matched_at=finding_data.get('matched_at'),
                    tool=finding_data.get('tool'),
                    template_id=finding_data.get('template_id'),
                    cve_id=finding_data.get('cve_id'),
                    cwe_id=finding_data.get('cwe_id'),
                    evidence=finding_data.get('evidence'),
                    raw_output=finding_data.get('raw_output')
                )
                session.add(finding)
                
                # Send notification for high/critical findings
                if finding_data.get('severity') in ['high', 'critical']:
                    self.notifier.notify_finding(finding_data)
            
            session.commit()
            self.results['findings'] = findings
            
            # Mark scan as completed
            scan.status = 'completed'
            scan.completed_at = datetime.utcnow()
            session.commit()
            
        except Exception as e:
            self.logger.error(f"Vulnerability scan failed: {str(e)}")
            scan.status = 'failed'
            scan.error_message = str(e)
            session.commit()
    
    def phase_javascript_analysis(self, session, target):
        """
        Phase 3: JavaScript Analysis
        
        Args:
            session: Database session
            target: Target database object
        """
        self.logger.info("\n" + "=" * 70)
        self.logger.info("PHASE 3: JavaScript Analysis")
        self.logger.info("=" * 70)
        
        try:
            # Get URLs to analyze
            urls = [host['url'] for host in self.results.get('live_hosts', [])]
            
            if not urls:
                self.logger.warning("No URLs to analyze")
                return
            
            # Initialize analyzer
            js_analyzer = JavaScriptAnalyzer(
                self.config, self.logger, self.rate_limiter
            )
            
            # Discover JS files
            self.logger.info("[Step 3.1] Discovering JavaScript files")
            js_files = js_analyzer.discover_js_files(urls[:10])  # Limit to first 10 URLs
            
            # Save JS files to database
            for js_url in js_files:
                if not session.query(JavaScript).filter_by(url=js_url).first():
                    js_obj = JavaScript(
                        url=js_url,
                        subdomain=URLNormalizer.extract_domain(js_url)
                    )
                    session.add(js_obj)
            session.commit()
            
            # Analyze JS files
            self.logger.info("[Step 3.2] Analyzing JavaScript files")
            analysis_results = js_analyzer.analyze_all(js_files)
            
            # Save secrets to database
            for secret_data in analysis_results.get('secrets', []):
                secret = Secret(
                    secret_type=secret_data.get('secret_type'),
                    detector=secret_data.get('detector'),
                    source_url=secret_data.get('source_url'),
                    secret_value=secret_data.get('secret_value'),
                    verified=secret_data.get('verified', False),
                    confidence=secret_data.get('confidence', 0.5)
                )
                session.add(secret)
            
            session.commit()
            self.results['secrets'] = analysis_results.get('secrets', [])
            self.results['js_files'] = js_files
            
        except Exception as e:
            self.logger.error(f"JavaScript analysis failed: {str(e)}")
    
    def generate_reports(self):
        """
        Generate output reports
        """
        self.logger.info("\n" + "=" * 70)
        self.logger.info("Generating Reports")
        self.logger.info("=" * 70)
        
        output_dir = self.config.get('output', {}).get('directory', 'reports')
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        base_filename = f"{self.target_domain}_{timestamp}"
        
        # JSON report
        import json
        json_file = os.path.join(output_dir, f"{base_filename}.json")
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        self.logger.info(f"JSON report saved: {json_file}")
        
        # Markdown report (basic)
        md_file = os.path.join(output_dir, f"{base_filename}.md")
        with open(md_file, 'w') as f:
            f.write(f"# Recon Report: {self.target_domain}\n\n")
            f.write(f"Generated: {datetime.utcnow().isoformat()}\n\n")
            f.write(f"## Summary\n\n")
            f.write(f"- Subdomains: {len(self.results['subdomains'])}\n")
            f.write(f"- Live Hosts: {len(self.results['live_hosts'])}\n")
            f.write(f"- Findings: {len(self.results['findings'])}\n")
            f.write(f"- Secrets: {len(self.results['secrets'])}\n")
        self.logger.info(f"Markdown report saved: {md_file}")
    
    def print_summary(self):
        """
        Print scan summary
        """
        print("\n" + "=" * 70)
        print("SCAN SUMMARY")
        print("=" * 70)
        print(f"Target: {self.target_domain}")
        print(f"\nSubdomains found: {len(self.results['subdomains'])}")
        print(f"Live hosts: {len(self.results['live_hosts'])}")
        print(f"Vulnerabilities found: {len(self.results['findings'])}")
        print(f"Secrets discovered: {len(self.results['secrets'])}")
        
        # Findings by severity
        if self.results['findings']:
            print("\nFindings by Severity:")
            by_severity = {}
            for finding in self.results['findings']:
                sev = finding.get('severity', 'unknown')
                by_severity[sev] = by_severity.get(sev, 0) + 1
            
            for sev in ['critical', 'high', 'medium', 'low', 'info']:
                if sev in by_severity:
                    print(f"  {sev.upper()}: {by_severity[sev]}")
        
        print("=" * 70)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Automated Bug Bounty Reconnaissance Pipeline"
    )
    parser.add_argument(
        '-c', '--config',
        default='config/config.yaml',
        help='Path to configuration file'
    )
    
    args = parser.parse_args()
    
    # Check if config exists
    if not os.path.exists(args.config):
        print(f"Error: Configuration file not found: {args.config}")
        sys.exit(1)
    
    # Run pipeline
    pipeline = ReconPipeline(args.config)
    pipeline.run()


if __name__ == "__main__":
    main()
