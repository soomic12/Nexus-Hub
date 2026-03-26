import streamlit as st
import requests
import re
from urllib.parse import urlparse
from security_utils import check_authenticity, apply_cyber_styling

# 1. Page Configuration
st.set_page_config(page_title="Site Checker", page_icon="🌐", layout="wide")

# 2. Security & Unified Styling
check_authenticity()
apply_cyber_styling("Site Checker")

# --- CORE ENGINES ---

@st.cache_data(ttl=600, show_spinner=False)
def get_latest_malware_url():
    """Fetches a live, real-world malware payload URL from the Abuse.ch Honeypot."""
    try:
        res = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/", timeout=5)
        if res.status_code == 200:
            lines = res.text.split('\n')
            for line in lines:
                if not line.startswith('#') and 'http' in line:
                    parts = line.split('","')
                    if len(parts) > 2:
                        return parts[2].strip('"')
    except:
        pass
    # Fallback highly suspicious URL if the live API is unreachable
    return "http://verify-account-update.securesite.login.com"

def query_urlhaus(target_url):
    """Queries the live URLhaus database."""
    try:
        response = requests.post('https://urlhaus-api.abuse.ch/v1/url/', data={'url': target_url}, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('query_status') == 'ok':
                return True, data
        return False, None
    except Exception as e:
        return None, str(e)

def calculate_trust_score(url, domain, is_blacklisted):
    """Dynamic Heuristic Engine to calculate realistic Trust Scores."""
    if is_blacklisted:
        return 0, "MALWARE", ["Actively listed in Abuse.ch Threat Database"]
    
    score = 100
    penalties = []
    
    if not url.startswith("https"):
        score -= 20
        penalties.append("Unencrypted HTTP traffic (No SSL/TLS)")
        
    if re.match(r"^[0-9\.]+$", domain):
        score -= 30
        penalties.append("Domain is a raw IP address (Highly Suspicious)")
        
    suspicious_keywords = ['login', 'verify', 'update', 'secure', 'account', 'bank', 'paypal', 'free', 'gift', 'prize', 'admin']
    for kw in suspicious_keywords:
        if kw in url.lower():
            score -= 15
            penalties.append(f"Deceptive keyword detected: '{kw}'")
            
    suspicious_tlds = ['.xyz', '.top', '.pw', '.cc', '.ru', '.click', '.tk']
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        score -= 20
        penalties.append("High-risk Top Level Domain (TLD)")
        
    if len(url) > 85:
        score -= 10
        penalties.append("Excessive URL length (Potential Obfuscation)")
        
    score = max(5, min(100, score))
    
    if score < 40:
        status = "HIGH RISK"
    elif score < 80:
        status = "SUSPICIOUS"
    else:
        status = "CLEAN"
        
    return score, status, penalties

# 3. Sidebar Intelligence
with st.sidebar:
    st.markdown("### 🛡️ Dual-Threat Engine")
    st.info("Layer 1: URLhaus OSINT API\nLayer 2: Lexical Heuristics")
    st.divider()
    st.markdown("### 🧠 Live Honeypot Sync")
    st.caption("This tool automatically fetches the latest malware payload from global honeypots every 10 minutes to test the engine.")

# 4. Main UI
st.title("🛡️ Web Threat & Scam Scanner")
st.write("Analyze URLs against live threat databases and dynamic heuristic models.")
st.divider()

# Grab a real, live malware URL to use as the default!
default_url = get_latest_malware_url()

st.caption("💡 Try analyzing the live threat below, or test a safe site like `https://google.com`")
target_url = st.text_input("Enter Target URL:", default_url)

if st.button("EXECUTE LIVE REPUTATION AUDIT", use_container_width=True):
    if target_url:
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = "http://" + target_url
            
        domain = urlparse(target_url).netloc

        with st.spinner(f"Running Multi-Layer Threat Analysis on {domain}..."):
            is_malicious, threat_data = query_urlhaus(target_url)
            
            # Run the heuristic engine to generate a unique score
            score, status, penalties = calculate_trust_score(target_url, domain, is_malicious)
            
            # Dynamic Styling Based on the Score
            color = "#ff4b4b" if score < 50 else ("#ffc107" if score < 80 else "#00ffcc")
            
            if is_malicious is None:
                st.error("🚨 Uplink Timeout: Could not reach Threat API. Check network connection.")
            else:
                if is_malicious:
                    st.error(f"🚨 CRITICAL WARNING: `{domain}` is actively distributing malware.")
                elif score < 80:
                    st.warning(f"⚠️ CAUTION: `{domain}` displays suspicious heuristic patterns.")
                else:
                    st.success(f"✅ STATUS CLEAN: `{domain}` passed all security checks.")

                # --- DYNAMIC TELEMETRY CARDS ---
                c1, c2, c3 = st.columns(3)
                with c1:
                    threat_type = threat_data.get('threat', 'HEURISTIC').upper() if is_malicious else status
                    st.markdown(f'''<div style="background-color: #1e122b; border: 1px solid {color}; border-radius: 8px; padding: 15px; text-align: center;">
                        <div style="color: #e0d4f5; font-size: 0.8rem;"><b>Threat Signature</b></div>
                        <div style="color: {color}; font-size: 1.1rem; font-weight: bold;">{threat_type}</div>
                    </div>''', unsafe_allow_html=True)
                with c2:
                    osint_status = threat_data.get('url_status', 'offline').upper() if is_malicious else "NOT LISTED"
                    st.markdown(f'''<div style="background-color: #1e122b; border: 1px solid {color}; border-radius: 8px; padding: 15px; text-align: center;">
                        <div style="color: #e0d4f5; font-size: 0.8rem;"><b>OSINT Status</b></div>
                        <div style="color: {color}; font-size: 1.1rem; font-weight: bold;">{osint_status}</div>
                    </div>''', unsafe_allow_html=True)
                with c3:
                    st.markdown(f'''<div style="background-color: #1e122b; border: 1px solid {color}; border-radius: 8px; padding: 15px; text-align: center;">
                        <div style="color: #e0d4f5; font-size: 0.8rem;"><b>Dynamic Trust Score</b></div>
                        <div style="color: {color}; font-size: 1.1rem; font-weight: bold;">{score} / 100</div>
                    </div>''', unsafe_allow_html=True)

                st.divider()
                
                # --- HEURISTIC BREAKDOWN EXPLANATION ---
                st.markdown("### 🧬 Lexical & Heuristic Breakdown")
                if not penalties:
                    st.info("✅ No deceptive patterns or malicious signatures detected in URL structure.")
                else:
                    for penalty in penalties:
                        st.markdown(f"- 🚩 **{penalty}**")
                        
                if is_malicious:
                    date_added = threat_data.get('date_added', 'Recent')
                    st.error(f"**Database Match:** Flagged by Abuse.ch on {date_added}. Immediate containment recommended.")

# Footer
st.markdown("---")
st.caption("NEXUS DUAL-ENGINE REPUTATION SYSTEM // v4.0")