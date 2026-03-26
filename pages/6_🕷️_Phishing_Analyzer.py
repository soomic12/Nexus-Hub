import streamlit as st
import re
import math
from collections import Counter
from urllib.parse import urlparse
from security_utils import check_authenticity, apply_cyber_styling

# 1. Page Configuration
st.set_page_config(page_title="Phishing Analyzer", page_icon="🕷️", layout="wide")

# 2. Security & Unified Styling
check_authenticity()
apply_cyber_styling("Phishing Analyzer")

# 3. Sidebar Intelligence
with st.sidebar:
    st.markdown("### 🔍 Heuristic Parameters")
    st.info("Method: Shannon Entropy + Pattern Matching\nDetection: DGA, Typosquatting, Credential Hijacking")
    st.divider()
    st.markdown("### 🧠 DGA Detection")
    st.caption("Domain Generation Algorithms (DGA) create high-entropy random strings. A score > 4.0 often indicates botnet command-and-control communication.")

# 4. Logic Functions
def calculate_entropy(string):
    if not string: return 0
    p, lns = Counter(string), float(len(string))
    return -sum(count/lns * math.log2(count/lns) for count in p.values())

# 5. Main UI
st.write("Analyze URLs for deceptive topologies, malicious redirects, and Domain Generation Algorithm (DGA) entropy.")
st.divider()

url = st.text_input("Enter Suspicious URL to Analyze:", "http://secure-login-update-account.com@192.168.1.1/login")

if st.button("RUN THREAT ANALYSIS", use_container_width=True):
    if url:
        with st.spinner("Executing bit-level pattern matching..."):
            threat_score = 0
            flags = []
            
            # Parse URL
            parsed_url = urlparse(url if "://" in url else f"http://{url}")
            domain = parsed_url.netloc
            
            # --- HEURISTIC ENGINE ---
            # 1. Entropy Check
            domain_entropy = calculate_entropy(domain)
            if domain_entropy > 4.0:
                threat_score += 3
                flags.append("High Domain Entropy: Potential DGA detected.")
                
            # 2. IP in Domain Check
            if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
                threat_score += 3
                flags.append("IP-Based Hosting: Bypassing DNS reputation filters.")
                
            # 3. SSL Check
            if parsed_url.scheme != "https":
                threat_score += 2
                flags.append("Insecure Protocol: Missing SSL/TLS encryption.")
                
            # 4. Obfuscation (@ symbol)
            if "@" in domain or "@" in parsed_url.path:
                threat_score += 3
                flags.append("Credential Masking: '@' symbol used to hide malicious server.")
                
            # 5. Length Check
            if len(url) > 75:
                threat_score += 1
                flags.append("Payload Length: Unusual length used for obfuscation.")

            st.success("✅ Heuristic Analysis Complete.")
            
            # --- CORE TELEMETRY CARDS ---
            c1, c2, c3, c4 = st.columns(4)
            with c1:
                st.markdown(f'<div class="cyber-card"><div class="card-title">Protocol</div><div class="card-value">{parsed_url.scheme.upper()}</div></div>', unsafe_allow_html=True)
            with c2:
                st.markdown(f'<div class="cyber-card"><div class="card-title">Payload Size</div><div class="card-value">{len(url)} bytes</div></div>', unsafe_allow_html=True)
            with c3:
                st.markdown(f'<div class="cyber-card"><div class="card-title">Entropy Bits</div><div class="card-value">{round(domain_entropy, 2)}</div></div>', unsafe_allow_html=True)
            with c4:
                status_color = "#ff4b4b" if threat_score > 4 else ("#ffa500" if threat_score > 0 else "#00ffcc")
                st.markdown(f'<div class="cyber-card" style="border-color:{status_color};"><div class="card-title">Threat Score</div><div class="card-value" style="color:{status_color};">{threat_score}/10</div></div>', unsafe_allow_html=True)

            st.divider()

            # --- REPORT SECTION ---
            col_rep, col_anat = st.columns([1, 1])
            
            with col_rep:
                st.markdown("### 🛠️ Intelligence Report")
                if flags:
                    flags_html = "".join([f"<li style='color: #ff4b4b; margin-bottom: 8px;'>{f}</li>" for f in flags])
                    st.markdown(f"""
                    <div class="cyber-card" style="border-color: #ff4b4b; text-align: left; padding: 25px;">
                        <div style="color: #ff4b4b; font-weight: bold; margin-bottom: 15px;">⚠️ MALICIOUS INDICATORS FOUND</div>
                        <ul style="font-family: monospace;">{flags_html}</ul>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown("""
                    <div class="cyber-card" style="border-color: #00ffcc; text-align: left; padding: 25px;">
                        <div style="color: #00ffcc; font-weight: bold;">✅ LINK VERIFIED CLEAN</div>
                        <div style="font-family: monospace;">No heuristic phishing or DGA patterns detected.</div>
                    </div>
                    """, unsafe_allow_html=True)

            with col_anat:
                st.markdown("### 🔍 URL Anatomy Analysis")
                
                st.caption("Attackers use subdomains and the '@' symbol to trick the human eye while the browser routes to a different IP.")

# Footer
st.markdown("---")
st.caption("NEXUS PHISHING & DGA ANALYZER // v3.0")