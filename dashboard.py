"""
PhishGuard Streamlit Dashboard
==============================
Interactive web interface for email security analysis.
"""

import streamlit as st
import pandas as pd
import json
import os
import sys
from datetime import datetime

# Add modules to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.email_fetcher import EmailFetcher
from modules.analyzer_engine import PhishGuardAnalyzer
from config import API_KEYS, CACHE_CONFIG, DEMO_MODE

# Page configuration
st.set_page_config(
    page_title="PhishGuard - Email Security Analysis",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
    }
    .threat-high {
        color: #ff4b4b;
        font-weight: bold;
    }
    .threat-medium {
        color: #ffa500;
        font-weight: bold;
    }
    .threat-low {
        color: #2ecc71;
        font-weight: bold;
    }
    .metric-card {
        background-color: rgba(240, 242, 246, 0.1);
        border: 1px solid rgba(49, 51, 63, 0.2);
        border-radius: 10px;
        padding: 20px;
        text-align: center;
    }
    .indicator-found {
        color: #ff4b4b;
    }
    .indicator-clear {
        color: #2ecc71;
    }
    
    /* Dark mode specific styles */
    @media (prefers-color-scheme: dark) {
        .metric-card {
            background-color: rgba(38, 39, 48, 0.4);
            border: 1px solid rgba(250, 250, 250, 0.1);
        }
    }
    
    /* Streamlit dark theme detection */
    [data-theme="dark"] .metric-card {
        background-color: rgba(38, 39, 48, 0.4);
        border: 1px solid rgba(250, 250, 250, 0.1);
    }
    
    /* Streamlit light theme detection */
    [data-theme="light"] .metric-card {
        background-color: rgba(240, 242, 246, 0.8);
        border: 1px solid rgba(49, 51, 63, 0.1);
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'analyzer' not in st.session_state:
    st.session_state.analyzer = PhishGuardAnalyzer(
        api_keys=API_KEYS,
        cache_file=CACHE_CONFIG['storage']
    )

if 'analysis_result' not in st.session_state:
    st.session_state.analysis_result = None

if 'analysis_history' not in st.session_state:
    st.session_state.analysis_history = []


def get_threat_color(score):
    """Get color based on threat score"""
    if score >= 71:
        return "🔴"
    elif score >= 31:
        return "🟠"
    return "🟢"


def get_threat_class(score):
    """Get CSS class based on threat score"""
    if score >= 71:
        return "threat-high"
    elif score >= 31:
        return "threat-medium"
    return "threat-low"


def render_header():
    """Render the main header"""
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.markdown('<p class="main-header">🛡️ PhishGuard</p>', unsafe_allow_html=True)
        st.markdown("**Email Header Forensics & Threat Analysis Platform**")
    
    with col2:
        if DEMO_MODE:
            st.warning("⚠️ DEMO MODE\nUsing simulated threat data", icon="⚠️")
        else:
            st.success("✅ API Connected", icon="✅")


def render_sidebar():
    """Render the sidebar with input options"""
    st.sidebar.header("📧 Email Input")
    
    input_method = st.sidebar.radio(
        "Choose Input Method:",
        ["Upload .eml File", "Paste Email Headers", "Sample Analysis"]
    )
    
    email_data = None
    
    if input_method == "Upload .eml File":
        uploaded_file = st.sidebar.file_uploader(
            "Upload .eml file",
            type=['eml'],
            help="Upload an email file exported from your email client"
        )
        
        if uploaded_file:
            email_data = uploaded_file.read()
            st.sidebar.success(f"✅ Loaded: {uploaded_file.name}")
    
    elif input_method == "Paste Email Headers":
        st.sidebar.info("Paste raw email headers including Received, From, To, etc.")
        pasted_headers = st.sidebar.text_area(
            "Email Headers:",
            height=200,
            placeholder="Received: from mail.example.com...\nFrom: sender@example.com..."
        )
        
        if pasted_headers:
            # Create a minimal email structure
            email_data = f"""Subject: Pasted Email
From: unknown@example.com
To: recipient@example.com

{pasted_headers}""".encode('utf-8')
    
    else:  # Sample Analysis
        st.sidebar.info("Analyze a sample phishing email for demonstration")
        if st.sidebar.button("Load Sample"):
            # Create a sample phishing email
            email_data = create_sample_email()
    
    # Analyze button
    if email_data and st.sidebar.button("🚀 Analyze Email", type="primary", use_container_width=True):
        with st.spinner("Analyzing email..."):
            result = st.session_state.analyzer.analyze_eml_bytes(email_data)
            if result:
                st.session_state.analysis_result = result
                st.session_state.analysis_history.append({
                    'timestamp': datetime.now().strftime('%H:%M:%S'),
                    'subject': result.get('subject', 'Unknown')[:30],
                    'score': result.get('threat_score', 0),
                    'classification': result.get('classification', 'UNKNOWN')
                })
                st.rerun()
            else:
                st.sidebar.error("❌ Failed to parse email")
    
    # Clear button
    if st.session_state.analysis_result and st.sidebar.button("🗑️ Clear Results"):
        st.session_state.analysis_result = None
        st.rerun()
    
    # History
    if st.session_state.analysis_history:
        st.sidebar.markdown("---")
        st.sidebar.subheader("📊 Analysis History")
        for item in st.session_state.analysis_history[-5:]:
            color = "🔴" if item['score'] >= 71 else "🟠" if item['score'] >= 31 else "🟢"
            st.sidebar.text(f"{item['timestamp']} - {color} {item['score']}")


def create_sample_email() -> bytes:
    """Create a sample phishing email for demo"""
    sample = b"""Message-ID: <phish-sample-123@evil.com>
Date: Fri, 07 Feb 2026 14:22:58 +0000
From: PayPal Security <security@paypa1-verify.com>
To: victim@company.com
Subject: Urgent: Your Account Has Been Suspended
Return-Path: <bounce@evil-server.ru>
Received: from mail.evil-server.ru (unknown [45.33.22.11])
    by mx.google.com with ESMTP id abc123
    for <victim@company.com>; Fri, 07 Feb 2026 14:22:58 +0000
Received: from localhost (localhost [127.0.0.1])
    by mail.evil-server.ru with ESMTPS id xyz789;
    Fri, 07 Feb 2026 14:22:55 +0000
DKIM-Signature: v=1; a=rsa-sha256; d=paypa1-verify.com; s=default;
Authentication-Results: mx.google.com;
    spf=fail smtp.mailfrom=evil-server.ru;
    dkim=none;
    dmarc=fail (p=REJECT) header.from=paypa1-verify.com
Content-Type: text/html; charset="utf-8"

<html>
<body>
<h1>PayPal Security Alert</h1>
<p>Dear Customer,</p>
<p>We detected unusual activity on your account. Your account has been <b>suspended</b>.</p>
<p><a href="http://paypa1-verify.com/login">Click here immediately to verify your account</a></p>
<p>You must act within 24 hours or your account will be permanently closed.</p>
<p>Visible text: https://www.paypal.com/signin<br>
Actual link: http://paypa1-verify.com/login</p>
</body>
</html>
"""
    return sample


def render_threat_score(result):
    """Render the threat score section"""
    score = result.get('threat_score', 0)
    classification = result.get('classification', 'UNKNOWN')
    
    st.subheader("🎯 Threat Assessment")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        color = get_threat_color(score)
        st.metric(
            label="Threat Score",
            value=f"{color} {score}/100"
        )
    
    with col2:
        threat_class = get_threat_class(score)
        st.markdown(f"""
        <div class="metric-card">
            <h4>Classification</h4>
            <p class="{threat_class}">{classification}</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        recommendation = "BLOCK" if score >= 71 else "REVIEW" if score >= 31 else "ACCEPT"
        rec_color = "🔴" if recommendation == "BLOCK" else "🟠" if recommendation == "REVIEW" else "🟢"
        st.metric(
            label="Recommendation",
            value=f"{rec_color} {recommendation}"
        )
    
    with col4:
        st.metric(
            label="Analysis Time",
            value=f"{result.get('analysis_time_seconds', 0)}s"
        )
    
    # Progress bar
    st.progress(score / 100, text=f"Risk Level: {score}%")


def render_email_metadata(result):
    """Render email metadata section"""
    st.subheader("📨 Email Metadata")
    
    col1, col2 = st.columns(2)
    
    with col1:
        metadata = {
            "Message ID": result.get('message_id', 'N/A')[:50] + '...' if len(result.get('message_id', '')) > 50 else result.get('message_id', 'N/A'),
            "From (Display)": result.get('from_header', 'N/A'),
            "To": result.get('to', 'N/A')[:50] + '...' if len(result.get('to', '')) > 50 else result.get('to', 'N/A'),
        }
        
        for key, value in metadata.items():
            st.text(f"**{key}:** {value}")
    
    with col2:
        envelope = result.get('from_envelope', '')
        header = result.get('from_header', '')
        
        # Check for mismatch
        if envelope and header and envelope not in header:
            st.error(f"**From (Envelope):** {envelope} ⚠️ MISMATCH DETECTED")
        else:
            st.text(f"**From (Envelope):** {envelope or 'N/A'}")
        
        st.text(f"**Subject:** {result.get('subject', 'N/A')}")
        st.text(f"**Timestamp:** {result.get('timestamp', 'N/A')}")


def render_authentication_results(result):
    """Render authentication results section"""
    st.subheader("🔐 Authentication Status")
    
    auth = result.get('authentication', {})
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        spf = auth.get('spf', {})
        spf_result = spf.get('result', 'none')
        if spf_result == 'pass':
            st.success(f"**SPF:** ✅ PASS")
        elif spf_result in ['fail', 'softfail']:
            st.error(f"**SPF:** ❌ {spf_result.upper()}")
        else:
            st.info(f"**SPF:** ⚪ {spf_result.upper()}")
        
        if spf.get('reason'):
            st.caption(spf.get('reason'))
    
    with col2:
        dkim = auth.get('dkim', {})
        dkim_result = dkim.get('result', 'none')
        if dkim_result == 'pass':
            st.success(f"**DKIM:** ✅ PASS")
        elif dkim_result == 'fail':
            st.error(f"**DKIM:** ❌ FAIL")
        else:
            st.info(f"**DKIM:** ⚪ {dkim_result.upper()}")
        
        if dkim.get('selector'):
            st.caption(f"Selector: {dkim.get('selector')}")
    
    with col3:
        dmarc = auth.get('dmarc', {})
        dmarc_result = dmarc.get('policy', 'none')
        if dmarc_result in ['reject', 'quarantine']:
            st.success(f"**DMARC:** ✅ {dmarc_result.upper()}")
        elif dmarc_result == 'none':
            st.info(f"**DMARC:** ⚪ NONE")
        else:
            st.error(f"**DMARC:** ❌ {dmarc_result.upper()}")
        
        if dmarc.get('percentage'):
            st.caption(f"Pct: {dmarc.get('percentage')}%")


def render_relay_path(result):
    """Render relay path analysis"""
    st.subheader("🌍 Relay Path Analysis")
    
    relay_path = result.get('relay_path', [])
    
    if not relay_path:
        st.info("No relay path information available")
        return
    
    # Summary
    st.caption(result.get('relay_summary', ''))
    
    # Create DataFrame
    df_data = []
    for hop in relay_path:
        df_data.append({
            'Hop': hop.get('hop', ''),
            'IP': hop.get('ip', 'N/A'),
            'Hostname': hop.get('hostname', 'N/A')[:40] if hop.get('hostname') else 'N/A',
            'Country': f"{hop.get('country', 'Unknown')} {get_country_flag(hop.get('country', ''))}",
            'ISP': hop.get('isp', 'Unknown')[:30] if hop.get('isp') else 'Unknown',
            'Reputation': f"{hop.get('reputation_score', 0)}/100"
        })
    
    df = pd.DataFrame(df_data)
    st.dataframe(df, use_container_width=True, hide_index=True)
    
    # Anomalies
    anomalies = result.get('relay_anomalies', [])
    if anomalies:
        st.warning("⚠️ Relay Anomalies Detected:")
        for anomaly in anomalies:
            severity_emoji = "🔴" if anomaly.get('severity') == 'high' else "🟠"
            st.text(f"{severity_emoji} {anomaly.get('message', '')}")


def get_country_flag(country_code):
    """Get flag emoji for country code"""
    flags = {
        'US': '🇺🇸', 'RU': '🇷🇺', 'CN': '🇨🇳', 'GB': '🇬🇧', 'DE': '🇩🇪',
        'FR': '🇫🇷', 'JP': '🇯🇵', 'IN': '🇮🇳', 'BR': '🇧🇷', 'CA': '🇨🇦',
        'AU': '🇦🇺', 'KR': '🇰🇷', 'NL': '🇳🇱', 'SG': '🇸🇬', 'Private': '🏠',
        'Unknown': '❓'
    }
    return flags.get(country_code, '🌐')


def render_threat_indicators(result):
    """Render threat indicators section"""
    st.subheader("🚨 Threat Indicators")
    
    indicators = result.get('threat_indicators', {})
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Lookalike domain
        lookalike = indicators.get('lookalike_domain', {})
        if lookalike.get('is_lookalike'):
            st.error(f"✅ **Lookalike Domain Detected**\n\n{lookalike.get('example', '')}")
        elif lookalike.get('suspicious_tld'):
            st.warning(f"⚠️ **Suspicious TLD:** {lookalike.get('tld', '')}")
        else:
            st.success("❌ No lookalike domain detected")
        
        # Sender mismatch
        sender_mismatch = indicators.get('sender_mismatch', {})
        if sender_mismatch.get('mismatch'):
            st.error(f"✅ **Sender Mismatch**\n\nHeader: {sender_mismatch.get('header_domain')}\nEnvelope: {sender_mismatch.get('envelope_domain')}")
        else:
            st.success("❌ No sender mismatch")
        
        # Urgency keywords
        urgency = indicators.get('urgency_keywords', [])
        if urgency:
            st.error(f"✅ **Urgency Keywords ({len(urgency)})**\n\n{', '.join(urgency[:5])}")
        else:
            st.success("❌ No urgency keywords")
    
    with col2:
        # Link mismatches
        link_mismatches = indicators.get('link_mismatches', [])
        if link_mismatches:
            st.error(f"✅ **Link Mismatches ({len(link_mismatches)})**")
            for mismatch in link_mismatches[:3]:
                st.text(f"• {mismatch.get('visible_text', 'N/A')[:30]} → {mismatch.get('actual_domain', 'N/A')}")
        else:
            st.success("❌ No link mismatches")
        
        # Suspicious URLs
        suspicious_urls = indicators.get('suspicious_urls', [])
        if suspicious_urls:
            st.error(f"✅ **Suspicious URLs ({len(suspicious_urls)})**")
            for url_info in suspicious_urls[:3]:
                st.text(f"• {url_info.get('domain', 'N/A')}")
                st.caption(f"  Reasons: {', '.join(url_info.get('reasons', [])[:2])}")
        else:
            st.success("❌ No suspicious URLs")
        
        # Domain age
        domain_info = result.get('domain_info', {})
        if domain_info.get('is_new'):
            st.error(f"✅ **New Domain** ({domain_info.get('age_days', 0)} days old)")
        else:
            st.success(f"❌ Domain age OK ({domain_info.get('age_days', 'Unknown')} days)")


def render_scoring_breakdown(result):
    """Render scoring breakdown"""
    st.subheader("📊 Scoring Breakdown")
    
    reasons = result.get('scoring_reasons', [])
    
    if reasons:
        for reason in reasons:
            if '+' in reason:
                st.text(f"🔴 {reason}")
            elif 'discount' in reason.lower():
                st.text(f"🟢 {reason}")
            else:
                st.text(f"⚪ {reason}")
    else:
        st.info("No scoring details available")


def render_export_options(result):
    """Render export options"""
    st.subheader("📄 Export Report")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # JSON export
        json_report = json.dumps(result, indent=2, default=str)
        st.download_button(
            label="📥 Download JSON Report",
            data=json_report,
            file_name=f"phishguard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True
        )
    
    with col2:
        # Text report
        text_report = st.session_state.analyzer.generate_report(result, format='text')
        st.download_button(
            label="📥 Download Text Report",
            data=text_report,
            file_name=f"phishguard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
            use_container_width=True
        )


def main():
    """Main dashboard function"""
    render_header()
    render_sidebar()
    
    # Main content area
    if st.session_state.analysis_result:
        result = st.session_state.analysis_result
        
        # Threat Score
        render_threat_score(result)
        
        st.divider()
        
        # Email Metadata
        render_email_metadata(result)
        
        st.divider()
        
        # Authentication
        render_authentication_results(result)
        
        st.divider()
        
        # Relay Path
        render_relay_path(result)
        
        st.divider()
        
        # Threat Indicators
        render_threat_indicators(result)
        
        st.divider()
        
        # Scoring Breakdown
        render_scoring_breakdown(result)
        
        st.divider()
        
        # Export Options
        render_export_options(result)
    
    else:
        # Welcome screen
        st.markdown("""
        ## Welcome to PhishGuard! 🛡️
        
        PhishGuard is an advanced email security analysis platform that helps you:
        
        ### 🔍 **What We Analyze**
        
        | Feature | Description |
        |---------|-------------|
        | **SPF Validation** | Verify if the sending IP is authorized |
        | **DKIM Verification** | Check cryptographic email signatures |
        | **DMARC Policy** | Validate domain authentication policies |
        | **Relay Path** | Trace email's journey through mail servers |
        | **IP Reputation** | Check against threat intelligence databases |
        | **Phishing Heuristics** | Detect lookalike domains, urgency keywords |
        | **Link Analysis** | Identify mismatched and suspicious URLs |
        
        ### 🚀 **Get Started**
        
        1. **Upload an .eml file** from your email client, or
        2. **Paste email headers** directly, or
        3. **Try the sample** to see how it works
        
        Use the sidebar on the left to begin! 👈
        """)
        
        # Stats
        if st.session_state.analysis_history:
            st.divider()
            st.subheader("📈 Session Statistics")
            
            stats = st.session_state.analyzer.get_statistics()
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Analyzed", stats['total_analyzed'])
            with col2:
                st.metric("High Risk", stats['high_risk'], delta_color="inverse")
            with col3:
                st.metric("Medium Risk", stats['medium_risk'])
            with col4:
                st.metric("Avg Time", f"{stats['avg_time']}s")


if __name__ == "__main__":
    main()
