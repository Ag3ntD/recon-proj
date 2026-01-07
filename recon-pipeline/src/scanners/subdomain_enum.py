#!/usr/bin/env python3
"""
Subdomain Enumeration Module
"""

import subprocess
import requests
import time
from typing import List, Set, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


class SubdomainEnumerator:
    """
    Subdomain enumeration using multiple tools
    """
    
    def __init__(self, domain: str, config: Dict[str, Any], logger):
        self.domain = domain.strip().lower()
        self.config = config
        self.logger = logger
        self.subdomains: Set[str] = set()
        
    def _run_tool(
        self, 
        command: List[str], 
        tool_name: str, 
        timeout: int = 120
    ) -> List[str]:
        """
        Run a subdomain enumeration tool
        
        Args:
            command: Command to execute
            tool_name: Name of the tool for logging
            timeout: Timeout in seconds
            
        Returns:
            List of discovered subdomains
        """
        self.logger.info(f"Running {tool_name} for {self.domain}")
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0:
                subdomains = [
                    line.strip().lower() 
                    for line in result.stdout.split('\n') 
                    if line.strip() and self.domain in line.strip().lower()
                ]
                self.logger.info(f"{tool_name} found {len(subdomains)} subdomains")
                return subdomains
            else:
                self.logger.warning(f"{tool_name} failed: {result.stderr[:200]}")
                return []
                
        except FileNotFoundError:
            self.logger.warning(f"{tool_name} not found - skipping")
            return []
        except subprocess.TimeoutExpired:
            self.logger.warning(f"{tool_name} timed out")
            return []
        except Exception as e:
            self.logger.error(f"{tool_name} error: {str(e)}")
            return []
    
    def subfinder(self) -> List[str]:
        """Run subfinder"""
        command = ['subfinder', '-d', self.domain, '-silent', '-all']
        return self._run_tool(command, 'subfinder', timeout=120)
    
    def amass(self) -> List[str]:
        """Run amass"""
        # Use passive mode only for bug bounty safety
        command = ['amass', 'enum', '-passive', '-d', self.domain, '-timeout', '5']
        return self._run_tool(command, 'amass', timeout=300)
    
    def assetfinder(self) -> List[str]:
        """Run assetfinder"""
        command = ['assetfinder', '--subs-only', self.domain]
        return self._run_tool(command, 'assetfinder', timeout=60)
    
    def findomain(self) -> List[str]:
        """Run findomain"""
        command = ['findomain', '-t', self.domain, '-q']
        return self._run_tool(command, 'findomain', timeout=60)
    
    def crtsh(self) -> List[str]:
        """
        Query Certificate Transparency logs via crt.sh
        """
        self.logger.info(f"Querying crt.sh for {self.domain}")
        subdomains = []
        
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            certs = response.json()
            for cert in certs:
                name = cert.get('common_name', '').strip().lower()
                if name and self.domain in name:
                    subdomains.append(name)
                
                # Also check name_value field
                name_value = cert.get('name_value', '').strip().lower()
                for entry in name_value.split('\n'):
                    entry = entry.strip()
                    if entry and self.domain in entry:
                        subdomains.append(entry)
            
            # Remove wildcards and deduplicate
            subdomains = [
                s.replace('*.', '') 
                for s in subdomains 
                if not s.startswith('*.')
            ]
            subdomains = list(set(subdomains))
            
            self.logger.info(f"crt.sh found {len(subdomains)} subdomains")
            return subdomains
            
        except Exception as e:
            self.logger.error(f"crt.sh error: {str(e)}")
            return []
    
    def enumerate_all(self) -> List[str]:
        """
        Run all enabled subdomain enumeration tools
        
        Returns:
            List of unique subdomains
        """
        enabled_tools = self.config.get('tools', {}).get('subdomain_enum', [])
        
        self.logger.info(f"Starting subdomain enumeration for {self.domain}")
        self.logger.info(f"Enabled tools: {', '.join(enabled_tools)}")
        
        # Map tool names to methods
        tool_methods = {
            'subfinder': self.subfinder,
            'amass': self.amass,
            'assetfinder': self.assetfinder,
            'findomain': self.findomain,
            'crtsh': self.crtsh
        }
        
        # Run each enabled tool
        for tool_name in enabled_tools:
            if tool_name in tool_methods:
                subdomains = tool_methods[tool_name]()
                self.subdomains.update(subdomains)
                time.sleep(1)  # Small delay between tools
        
        unique_subdomains = sorted(list(self.subdomains))
        self.logger.info(
            f"Total unique subdomains found: {len(unique_subdomains)}"
        )
        
        return unique_subdomains


class LiveHostDetector:
    """
    Detect live hosts using httpx
    """
    
    def __init__(self, config: Dict[str, Any], logger, rate_limiter):
        self.config = config
        self.logger = logger
        self.rate_limiter = rate_limiter
    
    def check_hosts(self, subdomains: List[str]) -> List[Dict[str, Any]]:
        """
        Check which subdomains are live using httpx
        
        Args:
            subdomains: List of subdomains to check
            
        Returns:
            List of live host information
        """
        if not subdomains:
            return []
        
        self.logger.info(f"Checking {len(subdomains)} hosts with httpx")
        
        # Get httpx configuration
        httpx_config = self.config.get('tools', {}).get('live_hosts', {})
        httpx_args = httpx_config.get('args', '-silent -json')
        
        # Create temporary file with subdomains
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for subdomain in subdomains:
                f.write(f"{subdomain}\n")
            temp_file = f.name
        
        try:
            # Add rate limiting
            rate_limit = self.config.get('scan', {}).get(
                'rate_limits', {}
            ).get('web_scan', 10)
            
            command = [
                'httpx',
                '-l', temp_file,
                '-rate-limit', str(rate_limit),
                '-timeout', '10',
                '-silent',
                '-json',
                '-follow-redirects',
                '-status-code',
                '-title',
                '-tech-detect'
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # Parse JSON output
            live_hosts = []
            for line in result.stdout.split('\n'):
                if not line.strip():
                    continue
                
                try:
                    host_data = eval(line)  # Replace with json.loads
                    
                    live_hosts.append({
                        'url': host_data.get('url', ''),
                        'host': host_data.get('host', ''),
                        'status_code': host_data.get('status_code', 0),
                        'title': host_data.get('title', ''),
                        'technologies': host_data.get('tech', []),
                        'content_length': host_data.get('content_length', 0),
                        'ip': host_data.get('ip', '')
                    })
                except:
                    continue
            
            self.logger.info(f"Found {len(live_hosts)} live hosts")
            return live_hosts
            
        except subprocess.TimeoutExpired:
            self.logger.error("httpx timed out")
            return []
        except Exception as e:
            self.logger.error(f"httpx error: {str(e)}")
            return []
        finally:
            # Clean up temp file
            import os
            try:
                os.unlink(temp_file)
            except:
                pass


class DNSAnalyzer:
    """
    DNS analysis using dnsx
    """
    
    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
    
    def analyze(self, subdomains: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Perform DNS analysis on subdomains
        
        Args:
            subdomains: List of subdomains
            
        Returns:
            Dict mapping subdomain to DNS records
        """
        if not subdomains:
            return {}
        
        self.logger.info(f"Running DNS analysis on {len(subdomains)} subdomains")
        
        # Create temporary file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for subdomain in subdomains:
                f.write(f"{subdomain}\n")
            temp_file = f.name
        
        try:
            command = [
                'dnsx',
                '-l', temp_file,
                '-json',
                '-a',        # A records
                '-aaaa',     # AAAA records
                '-cname',    # CNAME records
                '-mx',       # MX records
                '-ns',       # NS records
                '-txt',      # TXT records
                '-silent'
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Parse results
            dns_records = {}
            for line in result.stdout.split('\n'):
                if not line.strip():
                    continue
                
                try:
                    record = eval(line)  # Replace with json.loads
                    host = record.get('host', '')
                    if host:
                        dns_records[host] = record
                except:
                    continue
            
            self.logger.info(f"DNS analysis completed for {len(dns_records)} hosts")
            return dns_records
            
        except FileNotFoundError:
            self.logger.warning("dnsx not found - skipping DNS analysis")
            return {}
        except subprocess.TimeoutExpired:
            self.logger.error("dnsx timed out")
            return {}
        except Exception as e:
            self.logger.error(f"dnsx error: {str(e)}")
            return {}
        finally:
            import os
            try:
                os.unlink(temp_file)
            except:
                pass
