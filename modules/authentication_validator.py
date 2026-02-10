"""
Authentication Validator Module
===============================
Validates SPF, DKIM, and DMARC authentication for emails.
"""

import spf
import dkim
import dns.resolver
import re
from typing import Dict, Optional, Tuple


class AuthenticationValidator:
    """Validates email authentication mechanisms"""
    
    def __init__(self):
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 5
    
    def validate_all(self, email_data: Dict) -> Dict:
        """
        Run all authentication checks
        
        Args:
            email_data: Parsed email data from EmailFetcher
            
        Returns:
            Dictionary with SPF, DKIM, DMARC results
        """
        # Extract sender information
        sender_ip = self._extract_sender_ip(email_data.get('received_headers', []))
        envelope_from = self._extract_envelope_from(email_data.get('from_envelope', ''))
        header_from = self._extract_domain_from_email(email_data.get('from_header', ''))
        
        # Run checks
        spf_result = self.check_spf(sender_ip, envelope_from, '')
        dkim_result = self.verify_dkim(email_data.get('raw_bytes', b''))
        dmarc_result = self.check_dmarc(header_from)
        
        return {
            'spf': spf_result,
            'dkim': dkim_result,
            'dmarc': dmarc_result,
            'arc': {'result': 'none', 'reason': 'ARC not implemented'}
        }
    
    def check_spf(self, sender_ip: str, envelope_from: str, helo_domain: str) -> Dict:
        """
        Query SPF record and validate sending IP (simplified for Streamlit Cloud)
        
        Args:
            sender_ip: IP of sending server (from first Received header)
            envelope_from: MAIL FROM address (envelope sender)
            helo_domain: HELO/EHLO identity
            
        Returns:
            dict: {'result': 'pass|fail|softfail|neutral|none|error', 
                   'reason': 'explanation'}
        """
        if not sender_ip or not envelope_from:
            return {'result': 'none', 'reason': 'Missing sender IP or envelope address'}
        
        # Simplified SPF check for Streamlit Cloud (DNS queries may timeout)
        # In production, you can enable full SPF validation using pyspf
        return {
            'result': 'none',
            'reason': 'SPF check skipped (Streamlit Cloud)',
            'sender_ip': sender_ip,
            'envelope_from': envelope_from
        }
    
    def verify_dkim(self, raw_email: bytes) -> Dict:
        """
        Verify DKIM signature (simplified for Streamlit Cloud)
        
        Args:
            raw_email: Raw email bytes
            
        Returns:
            dict: {'result': 'pass|fail|none|error', 'details': {...}}
        """
        if not raw_email:
            return {'result': 'none', 'reason': 'No email data provided'}
        
        # Check if DKIM signature exists
        if b'DKIM-Signature:' not in raw_email and b'dkim-signature:' not in raw_email:
            return {'result': 'none', 'reason': 'No DKIM signature found'}
        
        # Simplified DKIM check for Streamlit Cloud
        # Extract selector and domain for info
        selector, domain = self._extract_dkim_info(raw_email)
        
        return {
            'result': 'none',
            'reason': 'DKIM verification skipped (Streamlit Cloud)',
            'selector': selector,
            'domain': domain
        }
    
    def check_dmarc(self, domain: str) -> Dict:
        """
        Query DMARC policy record (simplified for Streamlit Cloud)
        
        Args:
            domain: Domain to check DMARC for
            
        Returns:
            dict: {'policy': 'reject|quarantine|none', 
                   'percentage': int,
                   'reporting_address': str}
        """
        if not domain:
            return {'policy': 'none', 'reason': 'No domain provided'}
        
        # Simplified DMARC check for Streamlit Cloud (DNS queries may timeout)
        # In production, you can enable full DNS queries
        return {'policy': 'none', 'reason': 'DNS check skipped (Streamlit Cloud)'}
    
    def _parse_dmarc_record(self, record: str) -> Dict:
        """Parse DMARC TXT record"""
        result = {
            'policy': 'none',
            'percentage': 100,
            'reporting_address': None,
            'raw_record': record
        }
        
        # Parse key-value pairs
        parts = record.split(';')
        for part in parts:
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if key == 'p':
                    result['policy'] = value.lower()
                elif key == 'pct':
                    try:
                        result['percentage'] = int(value)
                    except:
                        pass
                elif key == 'rua':
                    result['reporting_address'] = value
        
        result['reason'] = f"Policy: {result['policy']}, Percentage: {result['percentage']}%"
        return result
    
    def _extract_sender_ip(self, received_headers: list) -> str:
        """Extract sender IP from Received headers"""
        if not received_headers:
            return ''
        
        # Get the last (oldest) Received header - this is the first hop
        last_header = received_headers[-1] if received_headers else ''
        
        # Extract IP address using regex
        ip_pattern = r'[\[\(]([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})[\]\)]'
        match = re.search(ip_pattern, last_header)
        
        if match:
            return match.group(1)
        
        # Try alternative pattern
        alt_pattern = r'from\s+\S+\s+\(?\s*\[?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]?\s*\)?'
        match = re.search(alt_pattern, last_header)
        
        return match.group(1) if match else ''
    
    def _extract_envelope_from(self, return_path: str) -> str:
        """Extract email address from Return-Path or similar"""
        if not return_path:
            return ''
        
        # Extract email from <address> format
        match = re.search(r'<([^>]+)>', return_path)
        if match:
            return match.group(1)
        
        # If no brackets, assume it's the email itself
        if '@' in return_path:
            return return_path.strip()
        
        return ''
    
    def _extract_domain_from_email(self, email_address: str) -> str:
        """Extract domain from email address"""
        if not email_address:
            return ''
        
        # Extract email from "Name <email>" format
        match = re.search(r'<([^>]+)>', email_address)
        if match:
            email_address = match.group(1)
        
        # Extract domain
        if '@' in email_address:
            return email_address.split('@')[1].strip()
        
        return ''
    
    def _extract_dkim_info(self, raw_email: bytes) -> Tuple[Optional[str], Optional[str]]:
        """Extract DKIM selector and domain from signature"""
        try:
            email_str = raw_email.decode('utf-8', errors='ignore')
            
            # Find DKIM-Signature header
            dkim_match = re.search(r'DKIM-Signature:[^\n]+', email_str, re.IGNORECASE)
            if dkim_match:
                header = dkim_match.group(0)
                
                # Extract selector (s=)
                selector_match = re.search(r'\bs=([^;\s]+)', header)
                selector = selector_match.group(1) if selector_match else None
                
                # Extract domain (d=)
                domain_match = re.search(r'\bd=([^;\s]+)', header)
                domain = domain_match.group(1) if domain_match else None
                
                return selector, domain
        except:
            pass
        
        return None, None


def get_authentication_summary(auth_results: Dict) -> str:
    """Get a human-readable summary of authentication results"""
    spf = auth_results.get('spf', {}).get('result', 'none')
    dkim = auth_results.get('dkim', {}).get('result', 'none')
    dmarc = auth_results.get('dmarc', {}).get('policy', 'none')
    
    spf_icon = '✅' if spf == 'pass' else '❌' if spf in ['fail', 'softfail'] else '⚪'
    dkim_icon = '✅' if dkim == 'pass' else '❌' if dkim == 'fail' else '⚪'
    dmarc_icon = '✅' if dmarc in ['reject', 'quarantine'] else '⚪' if dmarc == 'none' else '❌'
    
    return f"SPF: {spf_icon} {spf.upper()} | DKIM: {dkim_icon} {dkim.upper()} | DMARC: {dmarc_icon} {dmarc.upper()}"
