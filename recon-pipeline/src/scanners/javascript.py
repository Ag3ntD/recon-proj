#!/usr/bin/env python3
"""
JavaScript Analysis and Secret Detection Module
"""

import subprocess
import json
import hashlib
from typing import List, Dict, Any, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


class JavaScriptAnalyzer:
    """
    Analyze JavaScript files for secrets and endpoints
    """
    
    def __init__(self, config: Dict[str, Any], logger, rate_limiter):
        self.config = config
        self.logger = logger
        self.rate_limiter = rate_limiter
        self.js_files: List[str] = []
        self.secrets: List[Dict[str, Any]] = []
        self.endpoints: List[str] = []
    
    def discover_js_files(self, urls: List[str]) -> List[str]:
        """
        Discover JavaScript files using getJS
        
        Args:
            urls: List of URLs to analyze
            
        Returns:
            List of JavaScript file URLs
        """
        all_js_files = []
        
        for url in urls:
            try:
                command = ['getJS', '-url', url, '-complete']
                
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if result.returncode == 0:
                    js_files = [
                        line.strip() 
                        for line in result.stdout.split('\n') 
                        if line.strip() and line.strip().startswith('http')
                    ]
                    all_js_files.extend(js_files)
                    self.logger.info(f"Found {len(js_files)} JS files from {url}")
            
            except subprocess.TimeoutExpired:
                self.logger.warning(f"getJS timed out on {url}")
            except FileNotFoundError:
                self.logger.warning("getJS not found - skipping JS discovery")
                break
            except Exception as e:
                self.logger.error(f"getJS error on {url}: {str(e)}")
        
        # Deduplicate
        unique_js_files = list(set(all_js_files))
        self.js_files = unique_js_files
        
        # Apply max files limit from config (removed arbitrary 5 limit)
        max_files = self.config.get('tools', {}).get('javascript', {}).get(
            'max_files_per_host', 50
        )
        
        if len(unique_js_files) > max_files:
            self.logger.warning(
                f"Found {len(unique_js_files)} JS files, "
                f"limiting to {max_files} for performance"
            )
            unique_js_files = unique_js_files[:max_files]
        
        self.logger.info(f"Total unique JS files: {len(unique_js_files)}")
        return unique_js_files
    
    def analyze_js_file(self, js_url: str) -> Dict[str, Any]:
        """
        Analyze a single JavaScript file
        
        Args:
            js_url: URL of JavaScript file
            
        Returns:
            Dict with analysis results
        """
        results = {
            'url': js_url,
            'endpoints': [],
            'secrets': [],
            'urls': []
        }
        
        # Extract endpoints with LinkFinder
        results['endpoints'] = self.linkfinder_analysis(js_url)
        
        # Extract URLs with jsluice
        results['urls'] = self.jsluice_analysis(js_url)
        
        # Scan for secrets with trufflehog
        results['secrets'] = self.trufflehog_scan(js_url)
        
        return results
    
    def analyze_all(self, js_files: List[str]) -> Dict[str, Any]:
        """
        Analyze all JavaScript files in parallel
        
        Args:
            js_files: List of JS file URLs
            
        Returns:
            Combined analysis results
        """
        if not js_files:
            return {
                'js_files_analyzed': 0,
                'endpoints': [],
                'secrets': [],
                'urls': []
            }
        
        self.logger.info(f"Analyzing {len(js_files)} JavaScript files")
        
        all_endpoints = []
        all_secrets = []
        all_urls = []
        
        # Use ThreadPoolExecutor for parallel analysis
        max_workers = min(10, len(js_files))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {
                executor.submit(self.analyze_js_file, js_url): js_url 
                for js_url in js_files
            }
            
            for future in as_completed(future_to_url):
                js_url = future_to_url[future]
                try:
                    result = future.result(timeout=120)
                    all_endpoints.extend(result['endpoints'])
                    all_secrets.extend(result['secrets'])
                    all_urls.extend(result['urls'])
                except Exception as e:
                    self.logger.error(f"Error analyzing {js_url}: {str(e)}")
        
        # Deduplicate
        all_endpoints = list(set(all_endpoints))
        all_urls = list(set(all_urls))
        
        self.endpoints = all_endpoints
        self.secrets = all_secrets
        
        self.logger.info(
            f"JS Analysis complete: {len(all_endpoints)} endpoints, "
            f"{len(all_secrets)} secrets, {len(all_urls)} URLs"
        )
        
        return {
            'js_files_analyzed': len(js_files),
            'endpoints': all_endpoints,
            'secrets': all_secrets,
            'urls': all_urls
        }
    
    def linkfinder_analysis(self, js_url: str) -> List[str]:
        """
        Extract endpoints using LinkFinder
        
        Args:
            js_url: URL of JavaScript file
            
        Returns:
            List of discovered endpoints
        """
        try:
            command = [
                'linkfinder',
                '-i', js_url,
                '-o', 'cli'
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                endpoints = [
                    line.strip() 
                    for line in result.stdout.split('\n') 
                    if line.strip() and not line.startswith('[')
                ]
                return endpoints
            
            return []
            
        except subprocess.TimeoutExpired:
            return []
        except FileNotFoundError:
            # Try Python version
            return self.linkfinder_python(js_url)
        except Exception as e:
            return []
    
    def linkfinder_python(self, js_url: str) -> List[str]:
        """
        Run LinkFinder Python version
        
        Args:
            js_url: URL of JavaScript file
            
        Returns:
            List of endpoints
        """
        try:
            command = [
                'python3',
                '-m', 'linkfinder',
                '-i', js_url,
                '-o', 'cli'
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return [
                    line.strip() 
                    for line in result.stdout.split('\n') 
                    if line.strip()
                ]
            
            return []
            
        except:
            return []
    
    def jsluice_analysis(self, js_url: str) -> List[str]:
        """
        Extract URLs using jsluice
        
        Args:
            js_url: URL of JavaScript file
            
        Returns:
            List of extracted URLs
        """
        try:
            command = ['jsluice', 'urls', js_url]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                urls = [
                    line.strip() 
                    for line in result.stdout.split('\n') 
                    if line.strip()
                ]
                return urls
            
            return []
            
        except subprocess.TimeoutExpired:
            return []
        except FileNotFoundError:
            return []
        except Exception as e:
            return []
    
    def trufflehog_scan(self, js_url: str) -> List[Dict[str, Any]]:
        """
        Scan JavaScript file for secrets using trufflehog
        
        Args:
            js_url: URL of JavaScript file
            
        Returns:
            List of secret findings
        """
        try:
            # Curl the JS file and pipe to trufflehog
            curl_process = subprocess.Popen(
                ['curl', '-s', js_url],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            trufflehog_process = subprocess.Popen(
                ['trufflehog', 'stdin', '--json', '--no-update'],
                stdin=curl_process.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            curl_process.stdout.close()
            stdout, stderr = trufflehog_process.communicate(timeout=60)
            
            secrets = []
            
            if stdout:
                for line in stdout.split('\n'):
                    if not line.strip() or not line.strip().startswith('{'):
                        continue
                    
                    try:
                        secret_data = json.loads(line)
                        
                        # Only process actual secrets (has DetectorName)
                        if 'DetectorName' in secret_data:
                            secret = {
                                'secret_type': secret_data.get('DetectorName', 'unknown'),
                                'detector': 'trufflehog',
                                'source_url': js_url,
                                'secret_value': secret_data.get('Raw', ''),
                                'verified': secret_data.get('Verified', False),
                                'confidence': 0.9 if secret_data.get('Verified') else 0.5,
                                'raw_output': json.dumps(secret_data),
                                'discovered_at': datetime.utcnow().isoformat()
                            }
                            secrets.append(secret)
                    
                    except json.JSONDecodeError:
                        continue
            
            return secrets
            
        except subprocess.TimeoutExpired:
            return []
        except FileNotFoundError:
            return []
        except Exception as e:
            return []
    
    def secretfinder_scan(self, url: str) -> List[Dict[str, Any]]:
        """
        Scan for secrets using SecretFinder
        
        Args:
            url: URL to scan
            
        Returns:
            List of potential secrets
        """
        # Make path configurable via environment variable or config
        secretfinder_path = self.config.get('tools', {}).get('javascript', {}).get(
            'secretfinder_path', 
            '/opt/SecretFinder/SecretFinder.py'
        )
        
        try:
            command = [
                'python3',
                secretfinder_path,
                '-i', url,
                '-o', 'cli'
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            secrets = []
            
            if result.stdout:
                for line in result.stdout.split('\n'):
                    if line.strip() and not line.startswith('['):
                        secret = {
                            'secret_type': 'potential_secret',
                            'detector': 'secretfinder',
                            'source_url': url,
                            'secret_value': line.strip(),
                            'verified': False,
                            'confidence': 0.3,  # Low confidence for SecretFinder
                            'discovered_at': datetime.utcnow().isoformat()
                        }
                        secrets.append(secret)
            
            return secrets
            
        except subprocess.TimeoutExpired:
            return []
        except FileNotFoundError:
            self.logger.warning(
                f"SecretFinder not found at {secretfinder_path} - skipping"
            )
            return []
        except Exception as e:
            return []
    
    def calculate_file_hash(self, js_url: str) -> Optional[str]:
        """
        Calculate hash of JS file for change detection
        
        Args:
            js_url: URL of JavaScript file
            
        Returns:
            SHA256 hash or None
        """
        try:
            import requests
            response = requests.get(js_url, timeout=10)
            content = response.content
            return hashlib.sha256(content).hexdigest()
        except:
            return None
