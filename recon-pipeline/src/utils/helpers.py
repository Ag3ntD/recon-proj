#!/usr/bin/env python3
"""
Utility functions for the recon pipeline
"""

import time
import hashlib
import re
from typing import List, Set, Dict, Any, Optional, Callable
from urllib.parse import urlparse, urldefrag, parse_qs
from datetime import datetime
import threading
from collections import deque


class RateLimiter:
    """
    Thread-safe rate limiter using token bucket algorithm
    """
    
    def __init__(self, rate: int = 10):
        """
        Initialize rate limiter
        
        Args:
            rate: Maximum requests per second
        """
        self.rate = rate
        self.tokens = rate
        self.max_tokens = rate
        self.last_update = time.time()
        self.lock = threading.Lock()
        
    def acquire(self, tokens: int = 1) -> bool:
        """
        Acquire tokens for a request
        
        Args:
            tokens: Number of tokens to acquire
            
        Returns:
            True if tokens acquired, False otherwise
        """
        with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            
            # Add tokens based on elapsed time
            self.tokens = min(self.max_tokens, self.tokens + elapsed * self.rate)
            self.last_update = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False
    
    def wait(self, tokens: int = 1):
        """
        Wait until tokens are available
        
        Args:
            tokens: Number of tokens needed
        """
        while not self.acquire(tokens):
            time.sleep(0.1)


class ScopeValidator:
    """
    Validate domains and URLs against defined scope
    """
    
    def __init__(self, inscope_domains: List[str], exclude_domains: List[str] = None):
        """
        Initialize scope validator
        
        Args:
            inscope_domains: List of in-scope domain patterns (e.g., ['.example.com'])
            exclude_domains: List of domains to exclude
        """
        self.inscope_domains = [d.lower() for d in inscope_domains]
        self.exclude_domains = [d.lower() for d in (exclude_domains or [])]
        
    def is_in_scope(self, domain: str) -> bool:
        """
        Check if a domain is in scope
        
        Args:
            domain: Domain to check
            
        Returns:
            True if in scope, False otherwise
        """
        domain = domain.lower().strip()
        
        # Check exclusions first
        for exclude in self.exclude_domains:
            if exclude in domain or domain.endswith(exclude):
                return False
        
        # Check inscope patterns
        for inscope in self.inscope_domains:
            if inscope in domain or domain.endswith(inscope):
                return True
        
        return False
    
    def filter_domains(self, domains: List[str]) -> List[str]:
        """
        Filter a list of domains by scope
        
        Args:
            domains: List of domains to filter
            
        Returns:
            List of in-scope domains
        """
        return [d for d in domains if self.is_in_scope(d)]
    
    def filter_urls(self, urls: List[str]) -> List[str]:
        """
        Filter a list of URLs by scope
        
        Args:
            urls: List of URLs to filter
            
        Returns:
            List of in-scope URLs
        """
        filtered = []
        for url in urls:
            try:
                parsed = urlparse(url)
                if self.is_in_scope(parsed.netloc):
                    filtered.append(url)
            except:
                continue
        return filtered


class URLNormalizer:
    """
    Normalize URLs for deduplication
    """
    
    @staticmethod
    def normalize(url: str) -> str:
        """
        Normalize a URL for deduplication
        
        Args:
            url: URL to normalize
            
        Returns:
            Normalized URL
        """
        try:
            url = url.strip()
            if not url:
                return ""
            
            # Remove fragments
            url_without_fragment, _ = urldefrag(url)
            
            # Parse URL
            parsed = urlparse(url_without_fragment)
            
            # Reconstruct normalized URL
            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Sort query parameters
            if parsed.query:
                params = parse_qs(parsed.query, keep_blank_values=True)
                sorted_params = "&".join(
                    f"{k}={v[0]}" for k, v in sorted(params.items())
                )
                normalized += f"?{sorted_params}"
            
            return normalized.lower()
        except:
            return url.lower()
    
    @staticmethod
    def get_hash(url: str) -> str:
        """
        Get hash of normalized URL
        
        Args:
            url: URL to hash
            
        Returns:
            SHA256 hash
        """
        normalized = URLNormalizer.normalize(url)
        return hashlib.sha256(normalized.encode()).hexdigest()
    
    @staticmethod
    def has_parameters(url: str) -> bool:
        """
        Check if URL has query parameters
        
        Args:
            url: URL to check
            
        Returns:
            True if URL has parameters
        """
        try:
            parsed = urlparse(url)
            return bool(parsed.query)
        except:
            return False
    
    @staticmethod
    def is_javascript(url: str) -> bool:
        """
        Check if URL points to a JavaScript file
        
        Args:
            url: URL to check
            
        Returns:
            True if URL is JavaScript
        """
        return url.lower().endswith('.js') or '/js/' in url.lower()
    
    @staticmethod
    def extract_domain(url: str) -> Optional[str]:
        """
        Extract domain from URL
        
        Args:
            url: URL to extract from
            
        Returns:
            Domain or None
        """
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except:
            return None


class Deduplicator:
    """
    Deduplicate items using sets
    """
    
    def __init__(self):
        self.seen: Set[str] = set()
    
    def add(self, item: str) -> bool:
        """
        Add item to deduplicator
        
        Args:
            item: Item to add
            
        Returns:
            True if item was new, False if duplicate
        """
        if item in self.seen:
            return False
        self.seen.add(item)
        return True
    
    def filter(self, items: List[str]) -> List[str]:
        """
        Filter list to remove duplicates
        
        Args:
            items: List of items
            
        Returns:
            List of unique items
        """
        unique = []
        for item in items:
            if self.add(item):
                unique.append(item)
        return unique
    
    def clear(self):
        """Clear deduplicator"""
        self.seen.clear()


class BatchProcessor:
    """
    Process items in batches with delays
    """
    
    def __init__(self, batch_size: int = 25, batch_delay: float = 5.0):
        """
        Initialize batch processor
        
        Args:
            batch_size: Number of items per batch
            batch_delay: Delay between batches in seconds
        """
        self.batch_size = batch_size
        self.batch_delay = batch_delay
    
    def process(
        self, 
        items: List[Any], 
        callback: Callable[[List[Any]], Any],
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> List[Any]:
        """
        Process items in batches
        
        Args:
            items: List of items to process
            callback: Function to call for each batch
            progress_callback: Optional callback for progress (current, total)
            
        Returns:
            List of results from all batches
        """
        results = []
        total_batches = (len(items) + self.batch_size - 1) // self.batch_size
        
        for i in range(0, len(items), self.batch_size):
            batch = items[i:i + self.batch_size]
            batch_num = i // self.batch_size + 1
            
            if progress_callback:
                progress_callback(batch_num, total_batches)
            
            # Process batch
            batch_results = callback(batch)
            if batch_results:
                results.extend(batch_results)
            
            # Delay between batches (except for last batch)
            if i + self.batch_size < len(items):
                time.sleep(self.batch_delay)
        
        return results


class Logger:
    """
    Simple logger with levels
    """
    
    LEVELS = {
        'DEBUG': 0,
        'INFO': 1,
        'WARNING': 2,
        'ERROR': 3,
        'CRITICAL': 4
    }
    
    def __init__(self, name: str = "recon-pipeline", level: str = "INFO"):
        self.name = name
        self.level = self.LEVELS.get(level.upper(), 1)
        self.log_file = None
    
    def set_log_file(self, filepath: str):
        """Set log file path"""
        self.log_file = filepath
    
    def _log(self, level: str, message: str):
        """Internal log method"""
        if self.LEVELS.get(level, 0) >= self.level:
            timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            log_msg = f"[{timestamp}] [{level}] {message}"
            print(log_msg)
            
            if self.log_file:
                try:
                    with open(self.log_file, 'a') as f:
                        f.write(log_msg + '\n')
                except:
                    pass
    
    def debug(self, message: str):
        self._log('DEBUG', message)
    
    def info(self, message: str):
        self._log('INFO', message)
    
    def warning(self, message: str):
        self._log('WARNING', message)
    
    def error(self, message: str):
        self._log('ERROR', message)
    
    def critical(self, message: str):
        self._log('CRITICAL', message)


class ToolValidator:
    """
    Validate that required tools are installed
    """
    
    @staticmethod
    def check_tool(tool_name: str) -> bool:
        """
        Check if a tool is available in PATH
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            True if tool is available
        """
        import subprocess
        try:
            subprocess.run(
                [tool_name, '--help'],
                capture_output=True,
                timeout=5
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    @staticmethod
    def validate_tools(required_tools: List[str]) -> Dict[str, bool]:
        """
        Validate multiple tools
        
        Args:
            required_tools: List of tool names
            
        Returns:
            Dict mapping tool name to availability
        """
        results = {}
        for tool in required_tools:
            results[tool] = ToolValidator.check_tool(tool)
        return results
    
    @staticmethod
    def print_validation_report(validation_results: Dict[str, bool]) -> bool:
        """
        Print validation report
        
        Args:
            validation_results: Dict from validate_tools()
            
        Returns:
            True if all tools available
        """
        all_available = True
        print("\n" + "="*60)
        print("Tool Validation Report")
        print("="*60)
        
        for tool, available in sorted(validation_results.items()):
            status = "✓ Available" if available else "✗ Missing"
            print(f"{tool:20s} : {status}")
            if not available:
                all_available = False
        
        print("="*60 + "\n")
        return all_available


def extract_severity_from_nuclei(finding: Dict[str, Any]) -> str:
    """
    Extract severity from nuclei finding
    
    Args:
        finding: Nuclei finding dict
        
    Returns:
        Severity string (info, low, medium, high, critical)
    """
    try:
        return finding.get('info', {}).get('severity', 'unknown').lower()
    except:
        return 'unknown'


def parse_nuclei_json(raw_output: str) -> List[Dict[str, Any]]:
    """
    Parse nuclei JSON output
    
    Args:
        raw_output: Raw stdout from nuclei
        
    Returns:
        List of parsed findings
    """
    findings = []
    
    # Find start of JSON output (skip table)
    first_brace = raw_output.find('{')
    if first_brace == -1:
        return findings
    
    json_section = raw_output[first_brace:]
    
    # Parse line by line
    for line in json_section.split('\n'):
        line = line.strip()
        if not line or not line.startswith('{'):
            continue
        
        try:
            finding = eval(line)  # Using eval for now, replace with json.loads
            
            # Validate required fields
            if 'template-id' in finding and 'info' in finding:
                findings.append(finding)
        except:
            continue
    
    return findings


def calculate_confidence(finding: Dict[str, Any]) -> float:
    """
    Calculate confidence score for a finding
    
    Args:
        finding: Finding dictionary
        
    Returns:
        Confidence score between 0.0 and 1.0
    """
    confidence = 0.5  # Base confidence
    
    # Increase confidence for verified findings
    if finding.get('verified', False):
        confidence += 0.3
    
    # Increase confidence for findings with CVE
    if finding.get('cve_id'):
        confidence += 0.2
    
    # Increase confidence for high severity
    severity = finding.get('severity', '').lower()
    if severity in ['high', 'critical']:
        confidence += 0.1
    
    return min(1.0, confidence)
