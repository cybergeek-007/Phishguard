"""
Threat Intelligence Broker Module
==================================
Integrates external threat intelligence APIs with caching.
"""

import json
import time
import os
import requests
from typing import Dict, Optional, List
from urllib.parse import urlparse
import tldextract


class ThreatIntelligenceBroker:
    """Manages threat intelligence lookups with caching"""
    
    def __init__(self, cache_file: str = None, api_keys: Dict = None):
        """
        Initialize threat intelligence broker
        
        Args:
            cache_file: Path to cache file
            api_keys: Dictionary of API keys
        """
        self.cache_file = cache_file or 'threat_cache.json'
        self.api_keys = api_keys or {}
        self.cache = self._load_cache()
        self.demo_mode = not any(self.api_keys.values())
        
        if self.demo_mode:
            print("🎭 Threat Intelligence: Running in DEMO mode with simulated data")
    
    def _load_cache(self) -> Dict:
        """Load cache from disk"""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading cache: {e}")
        return {}
    
    def _save_cache(self):
        """Save cache to disk"""
        try:
            os.makedirs(os.path.dirname(self.cache_file) or '.', exist_ok=True)
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            print(f"Error saving cache: {e}")
    
    def _get_cached(self, key: str, ttl: int = 86400) -> Optional[Dict]:
        """Get cached result if not expired"""
        if key in self.cache:
            cached_data = self.cache[key]
            if time.time() - cached_data.get('cached_at', 0) < ttl:
                return cached_data.get('result')
        return None
    
    def _set_cached(self, key: str, result: Dict):
        """Store result in cache"""
        self.cache[key] = {
            'result': result,
            'cached_at': time.time()
        }
        self._save_cache()
    
    def check_ip_reputation(self, ip_address: str) -> Dict:
        """
        Check IP reputation against threat intelligence sources
        
        Args:
            ip_address: IP address to check
            
        Returns:
            dict: {'score': 0-100, 'is_whitelisted': bool, 'sources': []}
        """
        if not ip_address:
            return {'score': 0, 'is_whitelisted': False, 'sources': []}
        
        cache_key = f'ip:{ip_address}'
        cached = self._get_cached(cache_key)
        if cached:
            return cached
        
        if self.demo_mode:
            result = self._simulate_ip_reputation(ip_address)
        else:
            result = self._query_abuseipdb(ip_address)
        
        self._set_cached(cache_key, result)
        return result
    
    def _query_abuseipdb(self, ip_address: str) -> Dict:
        """Query AbuseIPDB API"""
        api_key = self.api_keys.get('abuseipdb')
        if not api_key:
            return {'score': 0, 'is_whitelisted': False, 'sources': ['No API key']}
        
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Key': api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                
                # Abuse Confidence Score is 0-100
                confidence = data.get('abuseConfidencePercentage', 0)
                
                result = {
                    'score': confidence,
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'country': data.get('countryCode', ''),
                    'isp': data.get('isp', ''),
                    'domain': data.get('domain', ''),
                    'total_reports': data.get('totalReports', 0),
                    'last_reported': data.get('lastReportedAt', ''),
                    'sources': ['AbuseIPDB']
                }
                
                return result
            
            elif response.status_code == 429:
                print(f"AbuseIPDB rate limit hit for {ip_address}")
                return {'score': 0, 'is_whitelisted': False, 'sources': ['Rate limited']}
            
        except Exception as e:
            print(f"AbuseIPDB error for {ip_address}: {e}")
        
        return {'score': 0, 'is_whitelisted': False, 'sources': ['Error']}
    
    def _simulate_ip_reputation(self, ip_address: str) -> Dict:
        """Simulate IP reputation for demo mode"""
        # Known safe IPs
        safe_ips = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
        
        # Known suspicious IP patterns (for demo)
        suspicious_octets = ['45.33', '185.220', '192.42']
        
        if ip_address in safe_ips:
            return {
                'score': 0,
                'is_whitelisted': True,
                'country': 'US',
                'isp': 'Trusted DNS Provider',
                'sources': ['DEMO'],
                'note': 'Known safe IP (demo mode)'
            }
        
        # Check if IP starts with suspicious octets
        for octet in suspicious_octets:
            if ip_address.startswith(octet):
                return {
                    'score': 85,
                    'is_whitelisted': False,
                    'country': 'RU',
                    'isp': 'Suspicious Network',
                    'sources': ['DEMO'],
                    'note': 'Suspicious IP pattern (demo mode)'
                }
        
        # Default: low risk
        return {
            'score': 5,
            'is_whitelisted': False,
            'country': 'US',
            'isp': 'Unknown',
            'sources': ['DEMO'],
            'note': 'Simulated data (demo mode)'
        }
    
    def check_url_reputation(self, url: str) -> Dict:
        """
        Check URL reputation
        
        Args:
            url: URL to check
            
        Returns:
            dict: {'is_malicious': bool, 'threat_types': [], 'sources': []}
        """
        if not url:
            return {'is_malicious': False, 'threat_types': [], 'sources': []}
        
        cache_key = f'url:{url}'
        cached = self._get_cached(cache_key)
        if cached:
            return cached
        
        if self.demo_mode:
            result = self._simulate_url_reputation(url)
        else:
            result = self._check_safe_browsing(url)
        
        self._set_cached(cache_key, result)
        return result
    
    def _check_safe_browsing(self, url: str) -> Dict:
        """Check URL against Google Safe Browsing"""
        api_key = self.api_keys.get('safe_browsing')
        if not api_key:
            return {'is_malicious': False, 'threat_types': [], 'sources': ['No API key']}
        
        try:
            api_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}'
            
            payload = {
                'client': {
                    'clientId': 'phishguard',
                    'clientVersion': '1.0'
                },
                'threatInfo': {
                    'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
                    'platformTypes': ['ANY_PLATFORM'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries': [{'url': url}]
                }
            }
            
            response = requests.post(api_url, json=payload, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                matches = data.get('matches', [])
                
                if matches:
                    threat_types = [m.get('threatType') for m in matches]
                    return {
                        'is_malicious': True,
                        'threat_types': threat_types,
                        'sources': ['Google Safe Browsing']
                    }
                
                return {
                    'is_malicious': False,
                    'threat_types': [],
                    'sources': ['Google Safe Browsing']
                }
            
        except Exception as e:
            print(f"Safe Browsing error for {url}: {e}")
        
        return {'is_malicious': False, 'threat_types': [], 'sources': ['Error']}
    
    def _simulate_url_reputation(self, url: str) -> Dict:
        """Simulate URL reputation for demo mode"""
        suspicious_patterns = ['phish', 'evil', 'malware', 'fake', 'scam', 'verify-now']
        
        url_lower = url.lower()
        for pattern in suspicious_patterns:
            if pattern in url_lower:
                return {
                    'is_malicious': True,
                    'threat_types': ['SOCIAL_ENGINEERING'],
                    'sources': ['DEMO'],
                    'note': 'Suspicious pattern detected (demo mode)'
                }
        
        return {
            'is_malicious': False,
            'threat_types': [],
            'sources': ['DEMO'],
            'note': 'Simulated data (demo mode)'
        }
    
    def check_domain_age(self, domain: str) -> Dict:
        """
        Query domain registration information
        
        Args:
            domain: Domain to check
            
        Returns:
            dict: {'age_days': int, 'is_new': bool, 'registrar': str}
        """
        if not domain:
            return {'age_days': -1, 'is_new': False, 'registrar': 'Unknown'}
        
        cache_key = f'domain:{domain}'
        cached = self._get_cached(cache_key)
        if cached:
            return cached
        
        if self.demo_mode:
            result = self._simulate_domain_age(domain)
        else:
            result = self._query_whois(domain)
        
        self._set_cached(cache_key, result)
        return result
    
    def _query_whois(self, domain: str) -> Dict:
        """Query WHOIS for domain information"""
        try:
            import whois
            
            w = whois.whois(domain)
            
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                age_days = (time.time() - creation_date.timestamp()) / 86400
                
                return {
                    'age_days': int(age_days),
                    'is_new': age_days < 30,
                    'registrar': w.registrar or 'Unknown',
                    'creation_date': creation_date.strftime('%Y-%m-%d') if creation_date else 'Unknown',
                    'expiration_date': w.expiration_date.strftime('%Y-%m-%d') if w.expiration_date else 'Unknown'
                }
        
        except Exception as e:
            print(f"WHOIS error for {domain}: {e}")
        
        return {'age_days': -1, 'is_new': False, 'registrar': 'Unknown'}
    
    def _simulate_domain_age(self, domain: str) -> Dict:
        """Simulate domain age for demo mode"""
        # Simulate some domains as new
        new_domains = ['paypa1-verify.com', 'amaz0n-security.net', 'micros0ft-login.xyz']
        
        if domain in new_domains:
            return {
                'age_days': 12,
                'is_new': True,
                'registrar': 'Suspicious Registrar',
                'creation_date': '2026-01-15',
                'note': 'Simulated data (demo mode)'
            }
        
        # Well-known domains
        old_domains = ['google.com', 'microsoft.com', 'amazon.com', 'paypal.com']
        
        if domain in old_domains:
            return {
                'age_days': 9000,
                'is_new': False,
                'registrar': 'MarkMonitor Inc.',
                'creation_date': '1998-09-15',
                'note': 'Simulated data (demo mode)'
            }
        
        # Default
        return {
            'age_days': 365,
            'is_new': False,
            'registrar': 'Unknown',
            'creation_date': '2025-01-01',
            'note': 'Simulated data (demo mode)'
        }
    
    def batch_check_ips(self, ip_addresses: List[str]) -> Dict[str, Dict]:
        """Check multiple IPs in batch"""
        results = {}
        for ip in ip_addresses:
            if ip:
                results[ip] = self.check_ip_reputation(ip)
        return results
