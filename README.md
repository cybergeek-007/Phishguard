# PhishGuard - Email Security Analysis Platform

🛡️ **PhishGuard** is a production-ready email security analysis platform that automates the forensic investigation process typically performed manually by SOC analysts.

## 🎯 Mission

Reduce manual email analysis from **10 minutes to 10 seconds** while maintaining SOC-level accuracy.

## 🔍 What PhishGuard Analyzes

| Analysis Module | Description |
|----------------|-------------|
| **SPF Validation** | Verify if sending IP is authorized for the domain |
| **DKIM Verification** | Check cryptographic email signatures |
| **DMARC Policy** | Validate domain authentication policies |
| **Relay Path** | Trace email's journey through mail servers |
| **IP Reputation** | Check against abuse databases (AbuseIPDB) |
| **URL Analysis** | Detect malicious and suspicious links |
| **Phishing Heuristics** | Lookalike domains, urgency keywords, link mismatches |
| **Domain Age** | Identify newly registered domains |

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- pip

### Installation

```bash
# Clone or download the project
cd phishguard

# Install dependencies
pip install -r requirements.txt
```

### Launch Dashboard

```bash
# Run the Streamlit dashboard
streamlit run dashboard.py

# Or use the launcher
python run.py dashboard
```

The dashboard will be available at `http://localhost:8501`

### CLI Analysis

```bash
# Analyze a single email file
python run.py analyze path/to/email.eml

# Run tests on sample files
python run.py test
```

## 📊 Threat Scoring

PhishGuard calculates a composite threat score (0-100):

| Score | Classification | Action |
|-------|---------------|--------|
| 0-30 | LOW_RISK | Likely legitimate |
| 31-70 | MEDIUM_RISK | Review required |
| 71-100 | HIGH_RISK_PHISHING | Likely phishing - Block |

### Scoring Factors

- SPF Fail: +30 points
- DKIM Fail: +20 points
- DMARC Fail: +25 points
- Lookalike Domain: +40 points
- Sender Mismatch: +15 points
- New Domain (<30 days): +25 points
- Suspicious TLD: +15 points
- Link Mismatches: +30 points
- Urgency Keywords: +5 each (max 20)
- IP Reputation: Direct addition

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        INPUT LAYER                          │
│              (IMAP, Gmail API, .eml Upload)                 │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                      PARSER LAYER                           │
│         (Header Extraction, MIME Decoding, Body Parse)      │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                     ANALYSIS LAYER                          │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐        │
│  │  Auth        │ │  Relay Path  │ │  Threat      │        │
│  │  Validator   │ │  Analyzer    │ │  Intel       │        │
│  │  (SPF/DKIM)  │ │              │ │  Broker      │        │
│  └──────────────┘ └──────────────┘ └──────────────┘        │
│  ┌────────────────────────────────────────────────────┐    │
│  │         Phishing Heuristics Engine                 │    │
│  └────────────────────────────────────────────────────┘    │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                   PRESENTATION LAYER                        │
│              (Streamlit Dashboard / CLI)                    │
└─────────────────────────────────────────────────────────────┘
```

## 📁 Project Structure

```
phishguard/
├── modules/
│   ├── __init__.py
│   ├── email_fetcher.py          # IMAP/email parsing
│   ├── authentication_validator.py # SPF/DKIM/DMARC
│   ├── relay_path_analyzer.py    # Received header analysis
│   ├── threat_intelligence.py    # IP/URL reputation
│   ├── phishing_heuristics.py    # Phishing detection
│   └── analyzer_engine.py        # Main orchestration
├── test_data/
│   ├── sample_phishing.eml       # Sample phishing email
│   └── sample_legitimate.eml     # Sample legitimate email
├── cache/                        # Threat intel cache
├── config.py                     # Configuration
├── dashboard.py                  # Streamlit UI
├── run.py                        # CLI entry point
└── requirements.txt              # Dependencies
```

## 🔑 API Keys (Optional)

PhishGuard works in demo mode without API keys. For production use, configure:

```python
# config.py or environment variables
export ABUSEIPDB_API_KEY="your_key"
export VIRUSTOTAL_API_KEY="your_key"
export SAFE_BROWSING_API_KEY="your_key"
```

### Free Tier Limits

| Service | Free Tier | Rate Limit |
|---------|-----------|------------|
| AbuseIPDB | 1,000 checks/day | 1 req/sec |
| Google Safe Browsing | 10,000 queries/day | No strict limit |
| ipapi.co | 1,000 requests/day | No key required |

## 🧪 Testing

```bash
# Run all tests
python run.py test

# Analyze sample phishing email
python run.py analyze test_data/sample_phishing.eml

# Analyze sample legitimate email
python run.py analyze test_data/sample_legitimate.eml
```

## 📈 Sample Output

### Phishing Email Detection

```
Threat Score: 92/100
Classification: HIGH_RISK_PHISHING
Recommendation: BLOCK

Authentication:
  SPF: FAIL
  DKIM: NONE
  DMARC: FAIL

Threat Indicators:
  ✅ Lookalike Domain: paypa1.com vs paypal.com
  ✅ Sender Mismatch: envelope ≠ header
  ✅ Urgency Keywords: urgent, suspended, verify now
  ✅ Suspicious URLs: 2 detected
  ✅ New Domain: Registered 12 days ago

Relay Path:
  Hop 1: 45.33.22.11 (RU) - Reputation: 85/100
  Hop 2: 142.250.1.1 (US) - Reputation: 0/100
```

## 🛡️ Security Considerations

- API keys should be stored as environment variables
- Cache files may contain sensitive IP/domain data
- Email content is processed locally - no data leaves your system
- Use HTTPS when deploying in production

## 🔮 Future Enhancements

- [ ] YARA rules for attachment scanning
- [ ] Machine learning classification
- [ ] Database storage (PostgreSQL)
- [ ] REST API
- [ ] Slack/Teams integration
- [ ] SIEM integration (Splunk, ELK)

## 📄 License

MIT License - See LICENSE file for details

## 🤝 Contributing

Contributions welcome! Please submit pull requests or open issues.

## 📧 Support

For questions or support, please open an issue on GitHub.

---

**Built with Python, Streamlit, and ❤️ for email security.**
