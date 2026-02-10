"""
PhishGuard Configuration
========================
Configuration settings for API keys, caching, and analysis parameters.
"""

import os
from dataclasses import dataclass
from typing import Dict, List, Optional

# API Keys (Load from environment variables or use demo mode)
API_KEYS = {
    'abuseipdb': os.getenv('ABUSEIPDB_API_KEY', ''),
    'virustotal': os.getenv('VIRUSTOTAL_API_KEY', ''),
    'safe_browsing': os.getenv('SAFE_BROWSING_API_KEY', ''),
    'ipapi': os.getenv('IPAPI_KEY', ''),  # Optional, free tier doesn't require key
}

# Cache Configuration
CACHE_CONFIG = {
    'ttl': 86400,  # 24 hours
    'storage': os.path.join(os.path.dirname(__file__), 'cache', 'threat_cache.json'),
    'enabled': True
}

# Analysis Settings
@dataclass
class AnalysisConfig:
    """Configuration for email analysis"""
    # Threat Score Weights
    SPF_FAIL_WEIGHT: int = 30
    DKIM_FAIL_WEIGHT: int = 20
    DMARC_FAIL_WEIGHT: int = 25
    SENDER_MISMATCH_WEIGHT: int = 15
    LOOKALIKE_DOMAIN_WEIGHT: int = 40
    NEW_DOMAIN_WEIGHT: int = 25
    SUSPICIOUS_TLD_WEIGHT: int = 15
    LINK_MISMATCH_WEIGHT: int = 30
    URGENCY_KEYWORD_WEIGHT: int = 5  # Per keyword, max 20
    
    # Thresholds
    HIGH_RISK_THRESHOLD: int = 71
    MEDIUM_RISK_THRESHOLD: int = 31
    
    # Domain Age
    NEW_DOMAIN_DAYS: int = 30
    
    # Relay Path
    MAX_NORMAL_HOPS: int = 10
    SUSPICIOUS_HOP_COUNT: int = 10

# Legitimate Brands for Lookalike Detection
LEGITIMATE_BRANDS = [
    'paypal.com', 'amazon.com', 'microsoft.com', 'apple.com',
    'google.com', 'facebook.com', 'bankofamerica.com', 'chase.com',
    'wellsfargo.com', 'citibank.com', 'usbank.com', 'netflix.com',
    'linkedin.com', 'twitter.com', 'instagram.com', 'github.com',
    'dropbox.com', 'adobe.com', 'salesforce.com', 'stripe.com'
]

# Suspicious TLDs
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.ru', '.cn', '.xyz', '.top', '.click']

# Urgency Keywords for Phishing Detection
URGENCY_KEYWORDS = [
    r'\burgent\b', r'\bimmediate action required\b', r'\bsuspended\b',
    r'\bverify now\b', r'\bunusual activity\b', r'\bsecurity alert\b',
    r'\bconfirm your identity\b', r'\baccount locked\b',
    r'\bexpires today\b', r'\bfinal notice\b', r'\bclick here immediately\b',
    r'\bwithin 24 hours\b', r'\bact now\b', r'\blimited time\b',
    r'\baccount will be closed\b', r'\bunauthorized access\b',
    r'\bsuspicious activity\b', r'\bupdate required\b',
    r'\bverify your account\b', r'\bconfirm your details\b'
]

# Trusted Senders (Whitelist)
TRUSTED_SENDERS = [
    'amazon.com', 'google.com', 'microsoft.com', 'apple.com',
    'github.com', 'linkedin.com', 'salesforce.com'
]

# IMAP Settings
IMAP_CONFIG = {
    'gmail': {
        'server': 'imap.gmail.com',
        'port': 993,
        'use_ssl': True
    },
    'outlook': {
        'server': 'outlook.office365.com',
        'port': 993,
        'use_ssl': True
    },
    'yahoo': {
        'server': 'imap.mail.yahoo.com',
        'port': 993,
        'use_ssl': True
    }
}

# Demo Mode (when no API keys are available)
DEMO_MODE = not any(API_KEYS.values())

if DEMO_MODE:
    print("⚠️  Running in DEMO MODE - No API keys configured. Threat intelligence will use simulated data.")
