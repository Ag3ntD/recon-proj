#!/usr/bin/env python3
"""
Vulnerability Scanning Module
"""

import subprocess
import json
import time
from typing import List, Dict, Any, Optional
from datetime import datetime


class VulnerabilityScanner:
    """
    Orchestrate vulnerability scanning tools
    """
    
    def __init__(self, config: Dict[str, Any], logger, rate_limiter, batch_processor):
        self.config = config
        self.logger = logger
        self.rate_limiter = rate_limiter
        self.batch_processor = batch_processor
        self.findings: List[Dict[str, Any]] = []
    
    def scan_all(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Run all enabled vulnerability scanners
        
        Args:
            urls: List of URLs to scan
            
        Returns:
            List of findings
        """
        if not urls:
            return []
        
        self.logger.info(f"Starting vulnerability scans on {len(urls)} URLs")
        
        # Run scanners in batches
        def scan_batch(batch_urls):
            batch_findings = []
            
            for url in batch_urls:
                # Rate limit each request
                self.rate_limiter.wait()
                
                # Run nuclei
                nuclei_findings = self.nuclei_scan([url])
                batch_findings.extend(nuclei_findings)
                
                # Run dalfox
                dalfox_findings = self.dalfox_scan(url)
                batch_findings.extend(dalfox_findings)
                
                # Run subzy
                subzy_findings = self.subzy_scan(url)
                batch_findings.extend(subzy_findings)
            
            return batch_findings
        
        # Process in batches
        all_findings = self.batch_processor.process(
            urls,
            scan_batch,
            progress_callback=lambda curr, total: self.logger.info(
                f"Processing batch {curr}/{total}"
            )
        )
        
        self.findings.extend(all_findings)
        self.logger.info(f"Total findings: {len(all_findings)}")
        
        return all_findings
    
    def nuclei_scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Run nuclei scanner
        
        Args:
            urls: List of URLs to scan
            
        Returns:
            List of findings
        """
        if not urls:
            return []
        
        nuclei_config = self.config.get('tools', {}).get('vuln_scan', {}).get('nuclei', {})
        severity = nuclei_config.get('severity', 'high,critical')
        rate_limit = nuclei_config.get('rate_limit', 150)
        bulk_size = nuclei_config.get('bulk_size', 25)
        templates = nuclei_config.get('templates', '')
        
        # Create temp file with URLs
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for url in urls:
                f.write(f"{url}\n")
            temp_file = f.name
        
        try:
            command = [
                'nuclei',
                '-l', temp_file,
                '-silent',
                '-json',
                '-severity', severity,
                '-rate-limit', str(rate_limit),
                '-bulk-size', str(bulk_size),
                '-retries', '1'
            ]
            
            # Add templates if specified
            if templates:
                command.extend(['-t', templates])
            
            # Add interactsh for OOB detection (SSRF, XXE, etc.)
            command.extend(['-interactsh'])
            
            self.logger.info(f"Running nuclei on {len(urls)} URLs")
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.config.get('scan', {}).get('timeouts', {}).get('tool_execution', 300)
            )
            
            # Parse findings
            findings = []
            for line in result.stdout.split('\n'):
                if not line.strip() or not line.strip().startswith('{'):
                    continue
                
                try:
                    finding = json.loads(line)
                    
                    # Extract and structure finding
                    structured_finding = {
                        'tool': 'nuclei',
                        'finding_type': finding.get('info', {}).get('name', 'unknown'),
                        'severity': finding.get('info', {}).get('severity', 'unknown').lower(),
                        'title': finding.get('info', {}).get('name', ''),
                        'description': finding.get('info', {}).get('description', ''),
                        'host': finding.get('host', ''),
                        'url': finding.get('matched-at', ''),
                        'matched_at': finding.get('matched-at', ''),
                        'template_id': finding.get('template-id', ''),
                        'template': finding.get('template', ''),
                        'cve_id': self._extract_cve(finding),
                        'cwe_id': self._extract_cwe(finding),
                        'evidence': {
                            'matcher_name': finding.get('matcher-name', ''),
                            'type': finding.get('type', ''),
                            'curl_command': finding.get('curl-command', '')
                        },
                        'raw_output': json.dumps(finding),
                        'discovered_at': datetime.utcnow().isoformat()
                    }
                    
                    findings.append(structured_finding)
                    
                except json.JSONDecodeError:
                    continue
            
            self.logger.info(f"Nuclei found {len(findings)} vulnerabilities")
            return findings
            
        except subprocess.TimeoutExpired:
            self.logger.error("Nuclei timed out")
            return []
        except FileNotFoundError:
            self.logger.warning("Nuclei not found - skipping")
            return []
        except Exception as e:
            self.logger.error(f"Nuclei error: {str(e)}")
            return []
        finally:
            import os
            try:
                os.unlink(temp_file)
            except:
                pass
    
    def dalfox_scan(self, url: str) -> List[Dict[str, Any]]:
        """
        Run dalfox XSS scanner
        
        Args:
            url: URL to scan
            
        Returns:
            List of XSS findings
        """
        try:
            command = [
                'dalfox',
                'url', url,
                '--format', 'json',
                '--silence',
                '--skip-bav',  # Skip BAV (Boring Alert Validation)
                '--only-poc', 'g'  # Only grep POC
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if not result.stdout.strip():
                return []
            
            # Parse dalfox JSON output
            findings = []
            try:
                dalfox_results = json.loads(result.stdout)
                
                for vuln in dalfox_results.get('results', []):
                    finding = {
                        'tool': 'dalfox',
                        'finding_type': 'xss',
                        'severity': 'high',
                        'title': 'Cross-Site Scripting (XSS)',
                        'description': f"XSS vulnerability found via {vuln.get('type', 'unknown')}",
                        'host': vuln.get('data', {}).get('url', url),
                        'url': vuln.get('data', {}).get('url', url),
                        'matched_at': vuln.get('param', ''),
                        'evidence': {
                            'payload': vuln.get('payload', ''),
                            'poc': vuln.get('poc', ''),
                            'param': vuln.get('param', ''),
                            'type': vuln.get('type', '')
                        },
                        'raw_output': json.dumps(vuln),
                        'discovered_at': datetime.utcnow().isoformat()
                    }
                    findings.append(finding)
                
                if findings:
                    self.logger.info(f"Dalfox found {len(findings)} XSS vulnerabilities at {url}")
                
                return findings
                
            except json.JSONDecodeError:
                return []
            
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Dalfox timed out on {url}")
            return []
        except FileNotFoundError:
            self.logger.warning("Dalfox not found - skipping XSS scanning")
            return []
        except Exception as e:
            self.logger.error(f"Dalfox error on {url}: {str(e)}")
            return []
    
    def subzy_scan(self, url: str) -> List[Dict[str, Any]]:
        """
        Check for subdomain takeover vulnerabilities
        
        Args:
            url: URL to check
            
        Returns:
            List of takeover findings
        """
        try:
            command = [
                'subzy',
                'run',
                '--target', url,
                '--hide_fails'
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            findings = []
            
            # Parse output (subzy outputs vulnerable findings)
            if result.stdout and 'vulnerable' in result.stdout.lower():
                finding = {
                    'tool': 'subzy',
                    'finding_type': 'subdomain_takeover',
                    'severity': 'critical',
                    'title': 'Subdomain Takeover Vulnerability',
                    'description': 'Subdomain is vulnerable to takeover',
                    'host': url,
                    'url': url,
                    'evidence': {
                        'output': result.stdout
                    },
                    'raw_output': result.stdout,
                    'discovered_at': datetime.utcnow().isoformat()
                }
                findings.append(finding)
                self.logger.info(f"Subzy found takeover vulnerability: {url}")
            
            return findings
            
        except subprocess.TimeoutExpired:
            return []
        except FileNotFoundError:
            self.logger.warning("Subzy not found - skipping takeover checks")
            return []
        except Exception as e:
            self.logger.error(f"Subzy error: {str(e)}")
            return []
    
    def _extract_cve(self, finding: Dict[str, Any]) -> Optional[str]:
        """Extract CVE ID from nuclei finding"""
        info = finding.get('info', {})
        classification = info.get('classification', {})
        cve_id = classification.get('cve-id')
        
        if cve_id:
            if isinstance(cve_id, list):
                return cve_id[0] if cve_id else None
            return str(cve_id)
        
        return None
    
    def _extract_cwe(self, finding: Dict[str, Any]) -> Optional[str]:
        """Extract CWE ID from nuclei finding"""
        info = finding.get('info', {})
        classification = info.get('classification', {})
        cwe_id = classification.get('cwe-id')
        
        if cwe_id:
            if isinstance(cwe_id, list):
                return cwe_id[0] if cwe_id else None
            return str(cwe_id)
        
        return None


class CORSChecker:
    """
    Check for CORS misconfigurations
    """
    
    def __init__(self, logger):
        self.logger = logger
    
    def check(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Check URLs for CORS misconfigurations
        
        Args:
            urls: List of URLs to check
            
        Returns:
            List of CORS findings
        """
        import requests
        findings = []
        
        for url in urls:
            try:
                # Test with evil.com origin
                headers = {'Origin': 'https://evil.com'}
                response = requests.get(url, headers=headers, timeout=10, verify=False)
                
                # Check for dangerous CORS headers
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == '*' or acao == 'https://evil.com':
                    severity = 'high' if acac == 'true' else 'medium'
                    
                    finding = {
                        'tool': 'cors_checker',
                        'finding_type': 'cors_misconfiguration',
                        'severity': severity,
                        'title': 'CORS Misconfiguration',
                        'description': f"Dangerous CORS policy: ACAO={acao}, ACAC={acac}",
                        'host': url,
                        'url': url,
                        'evidence': {
                            'acao': acao,
                            'acac': acac,
                            'headers': dict(response.headers)
                        },
                        'discovered_at': datetime.utcnow().isoformat()
                    }
                    findings.append(finding)
                    self.logger.info(f"CORS misconfiguration found: {url}")
            
            except Exception as e:
                continue
        
        return findings
