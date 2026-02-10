"""
Phishing Heuristics Engine Module
==================================
Detects phishing patterns and calculates threat scores.
"""

import re
import difflib
from typing import Dict, List, Optional, Tuple
import tldextract
from bs4 import BeautifulSoup
from urllib.parse import urlparse


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance using difflib (Python standard library)"""
    seq_matcher = difflib.SequenceMatcher(None, s1, s2)
    similarity = seq_matcher.ratio()
    # Convert similarity to approximate edit distance
    max_len = max(len(s1), len(s2))
    return int((1 - similarity) * max_len)


class PhishingHeuristics:
    """Analyzes emails for phishing indicators"""
    
    # Legitimate brands for lookalike detection
    LEGITIMATE_BRANDS = [
        'paypal.com', 'amazon.com', 'microsoft.com', 'apple.com',
        'google.com', 'facebook.com', 'bankofamerica.com', 'chase.com',
        'wellsfargo.com', 'citibank.com', 'usbank.com', 'netflix.com',
        'linkedin.com', 'twitter.com', 'instagram.com', 'github.com',
        'dropbox.com', 'adobe.com', 'salesforce.com', 'stripe.com',
        'square.com', 'shopify.com', 'ebay.com', 'etsy.com',
        'spotify.com', 'hulu.com', 'disney.com', 'appleid.apple.com'
    ]
    
    # Suspicious TLDs
    SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.link']
    
    # High-risk country TLDs
    RISKY_COUNTRY_TLDS = ['.ru', '.cn', '.kp', '.ir', '.by']
    
    # Urgency keywords
    URGENCY_KEYWORDS = [
        r'\burgent\b', r'\bimmediate action required\b', r'\bsuspended\b',
        r'\bverify now\b', r'\bunusual activity\b', r'\bsecurity alert\b',
        r'\bconfirm your identity\b', r'\baccount locked\b',
        r'\bexpires today\b', r'\bfinal notice\b', r'\bclick here immediately\b',
        r'\bwithin 24 hours\b', r'\bact now\b', r'\blimited time\b',
        r'\baccount will be closed\b', r'\bunauthorized access\b',
        r'\bsuspicious activity\b', r'\bupdate required\b',
        r'\bverify your account\b', r'\bconfirm your details\b',
        r'\bpassword expired\b', r'\bpayment failed\b',
        r'\baccount compromised\b', r'\bimmediate verification\b'
    ]
    
    # Trusted senders (whitelist)
    TRUSTED_SENDERS = [
        'amazon.com', 'google.com', 'microsoft.com', 'apple.com',
        'github.com', 'linkedin.com', 'salesforce.com'
    ]
    
    def __init__(self):
        self.url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
    
    def analyze(self, email_data: Dict) -> Dict:
        """
        Run all phishing heuristics analysis
        
        Args:
            email_data: Parsed email data
            
        Returns:
            Dictionary with all threat indicators
        """
        subject = email_data.get('subject', '')
        body_text = email_data.get('body_text', '')
        body_html = email_data.get('body_html', '')
        from_header = email_data.get('from_header', '')
        from_envelope = email_data.get('from_envelope', '')
        
        # Run all checks
        lookalike = self.check_lookalike_domain(from_header)
        urgency = self.scan_urgency_keywords(subject, body_text)
        link_mismatches = self.check_link_mismatches(body_html)
        suspicious_urls = self.find_suspicious_urls(body_text + ' ' + body_html)
        sender_mismatch = self.check_sender_mismatch(from_header, from_envelope)
        
        return {
            'lookalike_domain': lookalike,
            'urgency_keywords': urgency,
            'link_mismatches': link_mismatches,
            'suspicious_urls': suspicious_urls,
            'sender_mismatch': sender_mismatch,
            'suspicious_url_count': len(suspicious_urls),
            'link_mismatch_count': len(link_mismatches)
        }
    
    def check_lookalike_domain(self, sender_email: str) -> Dict:
        """
        Detect domain spoofing using Levenshtein distance
        
        Args:
            sender_email: Sender's email address
            
        Returns:
            dict: {'is_lookalike': bool, 'target_brand': str, 'similarity_score': int}
        """
        if not sender_email:
            return {'is_lookalike': False}
        
        # Extract domain from email
        domain = self._extract_domain(sender_email)
        if not domain:
            return {'is_lookalike': False}
        
        extracted = tldextract.extract(domain)
        sender_root = f'{extracted.domain}.{extracted.suffix}'
        
        for brand in self.LEGITIMATE_BRANDS:
            edit_distance = _levenshtein_distance(sender_root.lower(), brand.lower())
            
            # Threshold: 1-5 character difference (adjusted for difflib-based distance)
            if 1 <= edit_distance <= 5:
                return {
                    'is_lookalike': True,
                    'target_brand': brand,
                    'similarity_score': edit_distance,
                    'detected_domain': sender_root,
                    'example': f'{sender_root} vs {brand}'
                }
        
        # Check for suspicious TLD
        for tld in self.SUSPICIOUS_TLDS + self.RISKY_COUNTRY_TLDS:
            if sender_root.endswith(tld):
                return {
                    'is_lookalike': False,
                    'suspicious_tld': True,
                    'tld': tld,
                    'reason': f'Suspicious TLD: {tld}'
                }
        
        return {'is_lookalike': False}
    
    def scan_urgency_keywords(self, subject: str, body: str) -> List[str]:
        """
        Detect urgency/pressure tactics
        
        Args:
            subject: Email subject
            body: Email body text
            
        Returns:
            list: Matched keywords
        """
        text = f'{subject} {body}'.lower()
        matches = []
        
        for pattern in self.URGENCY_KEYWORDS:
            if re.search(pattern, text, re.IGNORECASE):
                # Clean up the pattern for display
                clean_pattern = pattern.strip(r'\b').replace(r'\b', '')
                if clean_pattern not in matches:
                    matches.append(clean_pattern)
        
        return matches
    
    def check_link_mismatches(self, html_body: str) -> List[Dict]:
        """
        Compare visible link text vs actual href
        
        Args:
            html_body: HTML body content
            
        Returns:
            list: Mismatched links with severity
        """
        if not html_body:
            return []
        
        mismatches = []
        
        try:
            soup = BeautifulSoup(html_body, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                visible_text = link.get_text().strip()
                actual_url = link['href']
                
                # Skip non-HTTP links
                if not actual_url.startswith('http'):
                    continue
                
                # Extract domain from visible text if it looks like URL
                if 'http' in visible_text or ('.' in visible_text and ' ' not in visible_text):
                    visible_domain = self._extract_domain(visible_text)
                    actual_domain = self._extract_domain(actual_url)
                    
                    if visible_domain and actual_domain and visible_domain != actual_domain:
                        mismatches.append({
                            'visible_text': visible_text[:50],
                            'visible_domain': visible_domain,
                            'actual_url': actual_url[:100],
                            'actual_domain': actual_domain,
                            'severity': 'high'
                        })
                
                # Check for IP-based URLs (suspicious)
                if self._contains_ip_url(actual_url):
                    mismatches.append({
                        'visible_text': visible_text[:50],
                        'actual_url': actual_url[:100],
                        'severity': 'medium',
                        'reason': 'IP-based URL detected'
                    })
        
        except Exception as e:
            print(f"Error parsing HTML: {e}")
        
        return mismatches
    
    def find_suspicious_urls(self, text: str) -> List[Dict]:
        """Find suspicious URLs in text"""
        if not text:
            return []
        
        suspicious = []
        urls = self.url_pattern.findall(text)
        
        for url in urls:
            reasons = []
            
            # Check for IP-based URLs
            if self._contains_ip_url(url):
                reasons.append('IP-based URL')
            
            # Check for suspicious TLDs
            domain = self._extract_domain(url)
            for tld in self.SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    reasons.append(f'Suspicious TLD: {tld}')
            
            # Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'buff.ly']
            for shortener in shorteners:
                if shortener in url.lower():
                    reasons.append(f'URL shortener: {shortener}')
            
            # Check for lookalike domains in URL
            extracted = tldextract.extract(domain)
            url_root = f'{extracted.domain}.{extracted.suffix}'
            
            for brand in self.LEGITIMATE_BRANDS:
                edit_distance = _levenshtein_distance(url_root.lower(), brand.lower())
                if 1 <= edit_distance <= 5:
                    reasons.append(f'Lookalike domain: {url_root} vs {brand}')
            
            if reasons:
                suspicious.append({
                    'url': url[:100],
                    'domain': domain,
                    'reasons': reasons
                })
        
        return suspicious
    
    def check_sender_mismatch(self, from_header: str, from_envelope: str) -> Dict:
        """
        Check if envelope sender differs from header sender
        
        Args:
            from_header: From header value
            from_envelope: Return-Path or envelope sender
            
        Returns:
            dict: Mismatch information
        """
        header_domain = self._extract_domain(from_header)
        envelope_domain = self._extract_domain(from_envelope)
        
        if not header_domain or not envelope_domain:
            return {'mismatch': False}
        
        if header_domain.lower() != envelope_domain.lower():
            return {
                'mismatch': True,
                'header_domain': header_domain,
                'envelope_domain': envelope_domain,
                'severity': 'high'
            }
        
        return {'mismatch': False}
    
    def calculate_threat_score(self, analysis_data: Dict, heuristics: Dict) -> Dict:
        """
        Calculate weighted composite threat score
        
        Args:
            analysis_data: Full analysis data including authentication
            heuristics: Phishing heuristics results
            
        Returns:
            dict: {'score': int, 'classification': str}
        """
        score = 0
        reasons = []
        
        # Authentication failures
        auth = analysis_data.get('authentication', {})
        
        if auth.get('spf', {}).get('result') == 'fail':
            score += 30
            reasons.append('SPF fail (+30)')
        elif auth.get('spf', {}).get('result') == 'softfail':
            score += 15
            reasons.append('SPF softfail (+15)')
        
        if auth.get('dkim', {}).get('result') == 'fail':
            score += 20
            reasons.append('DKIM fail (+20)')
        
        if auth.get('dmarc', {}).get('result') == 'fail':
            score += 25
            reasons.append('DMARC fail (+25)')
        
        # Sender mismatch
        if heuristics.get('sender_mismatch', {}).get('mismatch'):
            score += 15
            reasons.append('Sender mismatch (+15)')
        
        # Lookalike domain
        if heuristics.get('lookalike_domain', {}).get('is_lookalike'):
            score += 40
            reasons.append('Lookalike domain (+40)')
        
        # Suspicious TLD
        if heuristics.get('lookalike_domain', {}).get('suspicious_tld'):
            score += 15
            reasons.append('Suspicious TLD (+15)')
        
        # New domain (from threat intel)
        threat_indicators = analysis_data.get('threat_indicators', {})
        if threat_indicators.get('new_domain'):
            score += 25
            reasons.append('New domain (+25)')
        
        # Urgency keywords (max 20 points)
        keyword_count = len(heuristics.get('urgency_keywords', []))
        keyword_score = min(keyword_count * 5, 20)
        if keyword_score > 0:
            score += keyword_score
            reasons.append(f'Urgency keywords ({keyword_count}) (+{keyword_score})')
        
        # Link mismatches
        link_mismatches = heuristics.get('link_mismatch_count', 0)
        if link_mismatches > 0:
            score += min(link_mismatches * 15, 30)
            reasons.append(f'Link mismatches ({link_mismatches}) (+{min(link_mismatches * 15, 30)})')
        
        # Suspicious URLs
        suspicious_urls = heuristics.get('suspicious_url_count', 0)
        if suspicious_urls > 0:
            score += min(suspicious_urls * 10, 20)
            reasons.append(f'Suspicious URLs ({suspicious_urls}) (+{min(suspicious_urls * 10, 20)})')
        
        # IP reputation (take max from relay path)
        relay_path = analysis_data.get('relay_path', [])
        if relay_path:
            max_ip_score = max([hop.get('reputation_score', 0) for hop in relay_path])
            if max_ip_score > 0:
                score += min(max_ip_score, 50)
                reasons.append(f'IP reputation (+{min(max_ip_score, 50)})')
        
        # Cap at 100
        score = min(score, 100)
        
        # Apply whitelist reduction
        from_domain = self._extract_domain(analysis_data.get('from_header', ''))
        if from_domain in self.TRUSTED_SENDERS:
            score = int(score * 0.5)
            reasons.append('Trusted sender discount (x0.5)')
        
        # Classify
        if score >= 71:
            classification = 'HIGH_RISK_PHISHING'
        elif score >= 31:
            classification = 'MEDIUM_RISK'
        else:
            classification = 'LOW_RISK'
        
        return {
            'score': score,
            'classification': classification,
            'reasons': reasons
        }
    
    def _extract_domain(self, email_or_url: str) -> str:
        """Extract domain from email address or URL"""
        if not email_or_url:
            return ''
        
        # Remove mailto: prefix
        if email_or_url.startswith('mailto:'):
            email_or_url = email_or_url[7:]
        
        # Extract email from "Name <email>" format
        import re
        match = re.search(r'<([^>]+)>', email_or_url)
        if match:
            email_or_url = match.group(1)
        
        # Extract domain from email
        if '@' in email_or_url:
            return email_or_url.split('@')[1].strip().lower()
        
        # Extract domain from URL
        try:
            parsed = urlparse(email_or_url if '://' in email_or_url else f'http://{email_or_url}')
            domain = parsed.netloc.lower()
            # Remove www. prefix
            if domain.startswith('www.'):
                domain = domain[4:]
            return domain
        except:
            pass
        
        return email_or_url.lower()
    
    def _contains_ip_url(self, url: str) -> bool:
        """Check if URL contains an IP address instead of domain"""
        ip_pattern = r'https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        return bool(re.search(ip_pattern, url))


def get_threat_summary(heuristics: Dict) -> str:
    """Get a human-readable summary of threat indicators"""
    indicators = []
    
    if heuristics.get('lookalike_domain', {}).get('is_lookalike'):
        indicators.append(f"⚠️ Lookalike: {heuristics['lookalike_domain'].get('example', '')}")
    
    if heuristics.get('sender_mismatch', {}).get('mismatch'):
        indicators.append("⚠️ Sender mismatch detected")
    
    urgency_count = len(heuristics.get('urgency_keywords', []))
    if urgency_count > 0:
        indicators.append(f"⚠️ {urgency_count} urgency keywords found")
    
    link_mismatch_count = heuristics.get('link_mismatch_count', 0)
    if link_mismatch_count > 0:
        indicators.append(f"⚠️ {link_mismatch_count} link mismatches")
    
    suspicious_url_count = heuristics.get('suspicious_url_count', 0)
    if suspicious_url_count > 0:
        indicators.append(f"⚠️ {suspicious_url_count} suspicious URLs")
    
    return ' | '.join(indicators) if indicators else 'No major indicators'
