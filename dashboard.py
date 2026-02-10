"""
PhishGuard Streamlit Dashboard
==============================
Interactive web interface for email security analysis.
Enhanced with modern UI and improved UX.
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

# Enhanced Custom CSS with modern styling
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    * {
        font-family: 'Inter', sans-serif;
    }
    
    .main-header {
        font-size: 2.8rem;
        font-weight: 700;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        margin-bottom: 0.5rem;
    }
    
    .subheader {
        font-size: 1.1rem;
        color: #6b7280;
        font-weight: 400;
    }
    
    .threat-high {
        color: #dc2626;
        font-weight: 700;
    }
    
    .threat-medium {
        color: #ea580c;
        font-weight: 700;
    }
    
    .threat-low {
        color: #16a34a;
        font-weight: 700;
    }
    
    .metric-card {
        background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
        border-radius: 16px;
        padding: 24px;
        text-align: center;
        border: 1px solid #e2e8f0;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    
    .metric-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
    }
    
    .indicator-found {
        color: #dc2626;
    }
    
    .indicator-clear {
        color: #16a34a;
    }
    
    .stButton>button {
        border-radius: 12px;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    
    .stButton>button:hover {
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    }
    
    .score-circle {
        width: 120px;
        height: 120px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 2rem;
        font-weight: 700;
        margin: 0 auto;
        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.1);
    }
    
    .score-high {
        background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%);
        color: #dc2626;
        border: 4px solid #dc2626;
    }
    
    .score-medium {
        background: linear-gradient(135deg, #ffedd5 0%, #fed7aa 100%);
        color: #ea580c;
        border: 4px solid #ea580c;
    }
    
    .score-low {
        background: linear-gradient(135deg, #dcfce7 0%, #bbf7d0 100%);
        color: #16a34a;
        border: 4px solid #16a34a;
    }
    
    .feature-card {
        background: white;
        border-radius: 12px;
        padding: 20px;
        border: 1px solid #e5e7eb;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        transition: all 0.3s ease;
    }
    
    .feature-card:hover {
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        border-color: #667eea;
    }
    
    .auth-pass {
        background: linear-gradient(135deg, #dcfce7 0%, #bbf7d0 100%);
        color: #166534;
        padding: 12px 16px;
        border-radius: 10px;
        font-weight: 600;
        text-align: center;
    }
    
    .auth-fail {
        background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%);
        color: #991b1b;
        padding: 12px 16px;
        border-radius: 10px;
        font-weight: 600;
        text-align: center;
    }
    
    .auth-neutral {
        background: linear-gradient(135deg, #f3f4f6 0%, #e5e7eb 100%);
        color: #4b5563;
        padding: 12px 16px;
        border-radius: 10px;
        font-weight: 600;
        text-align: center;
    }
    
    .threat-badge {
        display: inline-block;
        padding: 6px 14px;
        border-radius: 20px;
        font-size: 0.85rem;
        font-weight: 600;
    }
    
    .badge-high {
        background: #fee2e2;
        color: #dc2626;
    }
    
    .badge-medium {
        background: #ffedd5;
        color: #ea580c;
    }
    
    .badge-low {
        background: #dcfce7;
        color: #16a34a;
    }
    
    .sidebar-section {
        background: #f8fafc;
        border-radius: 12px;
        padding: 16px;
        margin-bottom: 16px;
    }
    
    .history-item {
        background: white;
        border-radius: 8px;
        padding: 10px 12px;
        margin-bottom: 8px;
        border-left: 4px solid #e5e7eb;
        font-size: 0.9rem;
    }
    
    .history-high {
        border-left-color: #dc2626;
    }
    
    .history-medium {
        border-left-color: #ea580c;
    }
    
    .history-low {
        border-left-color: #16a34a;
    }
    
    .welcome-hero {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 40px;
        border-radius: 20px;
        text-align: center;
        margin-bottom: 30px;
    }
    
    .welcome-hero h1 {
        color: white;
        margin-bottom: 10px;
    }
    
    .welcome-hero p {
        color: rgba(255, 255, 255, 0.9);
        font-size: 1.1rem;
    }
    
    .feature-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 20px;
        margin-top: 20px;
    }
    
    .stProgress > div > div {
        border-radius: 10px;
    }
    
    .stDataFrame {
        border-radius: 12px;
        overflow: hidden;
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


def get_score_circle_class(score):
    """Get score circle CSS class"""
    if score >= 71:
        return "score-high"
    elif score >= 31:
        return "score-medium"
    return "score-low"


def get_badge_class(score):
    """Get badge CSS class"""
    if score >= 71:
        return "badge-high"
    elif score >= 31:
        return "badge-medium"
    return "badge-low"


def render_header():
    """Render the main header"""
    col1, col2 = st.columns([4, 1])
    
    with col1:
        st.markdown('<p class="main-header">🛡️ PhishGuard</p>', unsafe_allow_html=True)
        st.markdown('<p class="subheader">Advanced Email Security & Phishing Detection Platform</p>', unsafe_allow_html=True)
    
    with col2:
        if DEMO_MODE:
            st.warning("⚠️ DEMO MODE", icon="⚠️")
            st.caption("Using simulated threat data")
        else:
            st.success("✅ API Connected", icon="✅")
            st.caption("Live threat intelligence")


def render_sidebar():
    """Render the sidebar with input options"""
    st.sidebar.markdown("<div class='sidebar-section'>", unsafe_allow_html=True)
    st.sidebar.header("📧 Email Input")
    
    input_method = st.sidebar.radio(
        "Choose Input Method:",
        ["📁 Upload .eml File", "📋 Paste Email Headers", "🎯 Sample Analysis"],
        label_visibility="collapsed"
    )
    
    email_data = None
    
    if input_method == "📁 Upload .eml File":
        uploaded_file = st.sidebar.file_uploader(
            "Upload .eml file",
            type=['eml'],
            help="Upload an email file exported from your email client",
            label_visibility="collapsed"
        )
        
        if uploaded_file:
            email_data = uploaded_file.read()
            st.sidebar.success(f"✅ Loaded: {uploaded_file.name}")
    
    elif input_method == "📋 Paste Email Headers":
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
        if st.sidebar.button("🎯 Load Sample Phishing Email", use_container_width=True):
            email_data = create_sample_email()
            st.sidebar.success("✅ Sample loaded!")
    
    st.sidebar.markdown("</div>", unsafe_allow_html=True)
    
    # Analyze button
    st.sidebar.markdown("<div class='sidebar-section'>", unsafe_allow_html=True)
    if email_data and st.sidebar.button("🚀 Analyze Email", type="primary", use_container_width=True):
        with st.spinner("🔍 Analyzing email security..."):
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
    if st.session_state.analysis_result and st.sidebar.button("🗑️ Clear Results", use_container_width=True):
        st.session_state.analysis_result = None
        st.rerun()
    st.sidebar.markdown("</div>", unsafe_allow_html=True)
    
    # History
    if st.session_state.analysis_history:
        st.sidebar.markdown("---")
        st.sidebar.subheader("📊 Analysis History")
        for item in st.session_state.analysis_history[-5:]:
            score = item['score']
            history_class = "history-high" if score >= 71 else "history-medium" if score >= 31 else "history-low"
            st.sidebar.markdown(
                f"<div class='history-item {history_class}'>"
                f"<small>{item['timestamp']}</small><br>"
                f"<strong>{item['subject']}</strong><br>"
                f"Score: <b>{score}</b> - {item['classification'][:10]}"
                f"</div>",
                unsafe_allow_html=True
            )


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
    """Render the threat score section with enhanced visuals"""
    score = result.get('threat_score', 0)
    classification = result.get('classification', 'UNKNOWN')
    
    st.subheader("🎯 Threat Assessment")
    
    col1, col2, col3, col4 = st.columns([1.5, 1, 1, 1])
    
    with col1:
        # Score circle
        circle_class = get_score_circle_class(score)
        st.markdown(f"""
        <div class="score-circle {circle_class}">
            {score}
        </div>
        <p style="text-align: center; margin-top: 10px; font-weight: 600;">Threat Score</p>
        """, unsafe_allow_html=True)
    
    with col2:
        threat_class = get_threat_class(score)
        badge_class = get_badge_class(score)
        st.markdown(f"""
        <div class="metric-card">
            <h4>Classification</h4>
            <span class="threat-badge {badge_class}">{classification.replace('_', ' ')}</span>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        recommendation = "BLOCK" if score >= 71 else "REVIEW" if score >= 31 else "ACCEPT"
        rec_color = "🔴" if recommendation == "BLOCK" else "🟠" if recommendation == "REVIEW" else "🟢"
        st.markdown(f"""
        <div class="metric-card">
            <h4>Recommendation</h4>
            <p style="font-size: 1.2rem; font-weight: 700;">{rec_color} {recommendation}</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <h4>Analysis Time</h4>
            <p style="font-size: 1.2rem; font-weight: 700;">⚡ {result.get('analysis_time_seconds', 0)}s</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Progress bar with color coding
    progress_color = "red" if score >= 71 else "orange" if score >= 31 else "green"
    st.progress(score / 100, text=f"Risk Level: {score}%")


def render_email_metadata(result):
    """Render email metadata section"""
    st.subheader("📨 Email Metadata")
    
    col1, col2 = st.columns(2)
    
    with col1:
        with st.container():
            st.markdown("**Message ID:**")
            msg_id = result.get('message_id', 'N/A')
            st.code(msg_id[:60] + '...' if len(msg_id) > 60 else msg_id, language=None)
            
            st.markdown("**From (Display):**")
            st.info(result.get('from_header', 'N/A'))
            
            st.markdown("**To:**")
            to_addr = result.get('to', 'N/A')
            st.info(to_addr[:50] + '...' if len(to_addr) > 50 else to_addr)
    
    with col2:
        envelope = result.get('from_envelope', '')
        header = result.get('from_header', '')
        
        # Check for mismatch
        if envelope and header and envelope not in header:
            st.markdown("**From (Envelope):**")
            st.error(f"{envelope} ⚠️ MISMATCH DETECTED")
        else:
            st.markdown("**From (Envelope):**")
            st.info(envelope or 'N/A')
        
        st.markdown("**Subject:**")
        st.info(result.get('subject', 'N/A'))
        
        st.markdown("**Timestamp:**")
        st.info(result.get('timestamp', 'N/A'))


def render_authentication_results(result):
    """Render authentication results section with enhanced visuals"""
    st.subheader("🔐 Authentication Status")
    
    auth = result.get('authentication', {})
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        spf = auth.get('spf', {})
        spf_result = spf.get('result', 'none')
        if spf_result == 'pass':
            st.markdown('<div class="auth-pass">✅ SPF PASS</div>', unsafe_allow_html=True)
        elif spf_result in ['fail', 'softfail']:
            st.markdown(f'<div class="auth-fail">❌ SPF {spf_result.upper()}</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="auth-neutral">⚪ SPF {spf_result.upper()}</div>', unsafe_allow_html=True)
        
        if spf.get('reason'):
            st.caption(spf.get('reason'))
    
    with col2:
        dkim = auth.get('dkim', {})
        dkim_result = dkim.get('result', 'none')
        if dkim_result == 'pass':
            st.markdown('<div class="auth-pass">✅ DKIM PASS</div>', unsafe_allow_html=True)
        elif dkim_result == 'fail':
            st.markdown('<div class="auth-fail">❌ DKIM FAIL</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="auth-neutral">⚪ DKIM {dkim_result.upper()}</div>', unsafe_allow_html=True)
        
        if dkim.get('selector'):
            st.caption(f"Selector: {dkim.get('selector')}")
    
    with col3:
        dmarc = auth.get('dmarc', {})
        dmarc_result = dmarc.get('policy', 'none')
        if dmarc_result in ['reject', 'quarantine']:
            st.markdown(f'<div class="auth-pass">✅ DMARC {dmarc_result.upper()}</div>', unsafe_allow_html=True)
        elif dmarc_result == 'none':
            st.markdown('<div class="auth-neutral">⚪ DMARC NONE</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="auth-fail">❌ DMARC {dmarc_result.upper()}</div>', unsafe_allow_html=True)
        
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
    
    # Create DataFrame with enhanced styling
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
    """Render threat indicators section with enhanced visuals"""
    st.subheader("🚨 Threat Indicators")
    
    indicators = result.get('threat_indicators', {})
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Lookalike domain
        lookalike = indicators.get('lookalike_domain', {})
        if lookalike.get('is_lookalike'):
            st.error(f"🚨 **Lookalike Domain Detected**\n\n{lookalike.get('example', '')}")
        elif lookalike.get('suspicious_tld'):
            st.warning(f"⚠️ **Suspicious TLD:** {lookalike.get('tld', '')}")
        else:
            st.success("✅ No lookalike domain detected")
        
        # Sender mismatch
        sender_mismatch = indicators.get('sender_mismatch', {})
        if sender_mismatch.get('mismatch'):
            st.error(f"🚨 **Sender Mismatch**\n\nHeader: {sender_mismatch.get('header_domain')}\nEnvelope: {sender_mismatch.get('envelope_domain')}")
        else:
            st.success("✅ No sender mismatch")
        
        # Urgency keywords
        urgency = indicators.get('urgency_keywords', [])
        if urgency:
            st.error(f"🚨 **Urgency Keywords ({len(urgency)})**\n\n{', '.join(urgency[:5])}")
        else:
            st.success("✅ No urgency keywords")
    
    with col2:
        # Link mismatches
        link_mismatches = indicators.get('link_mismatches', [])
        if link_mismatches:
            st.error(f"🚨 **Link Mismatches ({len(link_mismatches)})**")
            for mismatch in link_mismatches[:3]:
                st.text(f"• {mismatch.get('visible_text', 'N/A')[:30]} → {mismatch.get('actual_domain', 'N/A')}")
        else:
            st.success("✅ No link mismatches")
        
        # Suspicious URLs
        suspicious_urls = indicators.get('suspicious_urls', [])
        if suspicious_urls:
            st.error(f"🚨 **Suspicious URLs ({len(suspicious_urls)})**")
            for url_info in suspicious_urls[:3]:
                st.text(f"• {url_info.get('domain', 'N/A')}")
                st.caption(f"  Reasons: {', '.join(url_info.get('reasons', [])[:2])}")
        else:
            st.success("✅ No suspicious URLs")
        
        # Domain age
        domain_info = result.get('domain_info', {})
        if domain_info.get('is_new'):
            st.error(f"🚨 **New Domain** ({domain_info.get('age_days', 0)} days old)")
        else:
            st.success(f"✅ Domain age OK ({domain_info.get('age_days', 'Unknown')} days)")


def render_scoring_breakdown(result):
    """Render scoring breakdown"""
    st.subheader("📊 Scoring Breakdown")
    
    reasons = result.get('scoring_reasons', [])
    
    if reasons:
        cols = st.columns(2)
        for i, reason in enumerate(reasons):
            col = cols[i % 2]
            if '+' in reason:
                col.markdown(f"🔴 {reason}")
            elif 'discount' in reason.lower():
                col.markdown(f"🟢 {reason}")
            else:
                col.markdown(f"⚪ {reason}")
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


def render_welcome_screen():
    """Render enhanced welcome screen"""
    st.markdown("""
    <div class="welcome-hero">
        <h1>🛡️ Welcome to PhishGuard</h1>
        <p>Advanced Email Security & Phishing Detection Platform</p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### 🔍 **What We Analyze**
        
        <div class="feature-card">
            <h4>🔐 Authentication</h4>
            <p>SPF, DKIM, and DMARC validation to verify email authenticity</p>
        </div>
        
        <div class="feature-card">
            <h4>🌍 Relay Path</h4>
            <p>Trace email's journey through mail servers with geolocation</p>
        </div>
        
        <div class="feature-card">
            <h4>🧠 Threat Intelligence</h4>
            <p>IP reputation, domain age, and URL analysis</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        ### 🚨 **Phishing Detection**
        
        <div class="feature-card">
            <h4>👤 Lookalike Domains</h4>
            <p>Detect domain spoofing using Levenshtein distance</p>
        </div>
        
        <div class="feature-card">
            <h4>⏰ Urgency Keywords</h4>
            <p>Identify pressure tactics commonly used in phishing</p>
        </div>
        
        <div class="feature-card">
            <h4>🔗 Link Analysis</h4>
            <p>Find mismatched and suspicious URLs</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("""
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
        render_welcome_screen()


if __name__ == "__main__":
    main()
