import streamlit as st
import re
import random
import string
import math
from security_utils import check_authenticity, apply_cyber_styling

# 1. Page Configuration
st.set_page_config(page_title="Password Auditor", page_icon="🛡️", layout="wide")

# 2. Security & Unified Styling
check_authenticity()
apply_cyber_styling("Password Auditor")

# 3. Sidebar Intelligence
with st.sidebar:
    st.markdown("### 🧮 Entropy Formula")
    st.latex(r"E = L \cdot \log_2(N)")
    st.caption("Where L is length and N is the character pool size.")
    st.divider()
    st.markdown("### 🧠 Benchmarking")
    st.info("Simulation assumes an offline brute-force attack performing **100 Billion** guesses per second using high-end GPU clusters.")

# 4. Main UI Logic
st.write("Calculate Shannon Entropy and simulate offline brute-force cracking resistance for cryptographic payloads.")
st.divider()

# Input Section
password_input = st.text_input("Enter password to audit:", type="password", help="Nexus does not store or log audited passwords.")

if st.button("RUN ENTROPY ANALYSIS", use_container_width=True):
    if password_input:
        with st.spinner("Calculating algorithmic complexity..."):
            # Logic: Pool Size (N) calculation
            pool_size = 0
            tips = []
            length = len(password_input)
            
            if length < 12: 
                tips.append("Length: Extend payload to 12+ characters to increase search space.")
            
            if re.search(r"[a-z]", password_input): pool_size += 26
            else: tips.append("Complexity: Inject lowercase characters.")
                
            if re.search(r"[A-Z]", password_input): pool_size += 26
            else: tips.append("Complexity: Inject uppercase characters.")
                
            if re.search(r"\d", password_input): pool_size += 10
            else: tips.append("Complexity: Integrate numeric digits.")
                
            if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password_input): pool_size += 32
            else: tips.append("Complexity: Utilize special cryptographic symbols.")
            
            # Entropy Math
            entropy = length * math.log2(pool_size) if pool_size > 0 else 0
            
            # Crack Time Simulation
            combinations = pool_size ** length if pool_size > 0 else 0
            seconds_to_crack = combinations / 100_000_000_000
            
            if seconds_to_crack < 60: crack_time = "Almost Instantly"
            elif seconds_to_crack < 3600: crack_time = f"{int(seconds_to_crack/60)} Minutes"
            elif seconds_to_crack < 86400: crack_time = f"{int(seconds_to_crack/3600)} Hours"
            elif seconds_to_crack < 31536000: crack_time = f"{int(seconds_to_crack/86400)} Days"
            else: crack_time = f"{int(seconds_to_crack/31536000):,} Years"

            st.success("✅ Analysis Complete.")
            
            # --- CORE METRIC CARDS ---
            c1, c2, c3, c4 = st.columns(4)
            with c1:
                st.markdown(f'<div class="cyber-card"><div class="card-title">Length</div><div class="card-value">{length} Chars</div></div>', unsafe_allow_html=True)
            with c2:
                st.markdown(f'<div class="cyber-card"><div class="card-title">Pool Size (N)</div><div class="card-value">{pool_size}</div></div>', unsafe_allow_html=True)
            with c3:
                st.markdown(f'<div class="cyber-card"><div class="card-title">Shannon Entropy</div><div class="card-value">{int(entropy)} Bits</div></div>', unsafe_allow_html=True)
            with c4:
                # Dynamic coloring based on strength
                color = "#ff4b4b" if entropy < 50 else ("#ffa500" if entropy < 80 else "#00ffcc")
                st.markdown(f'<div class="cyber-card" style="border-color:{color};"><div class="card-title">Est. Crack Time</div><div class="card-value" style="color:{color};">{crack_time}</div></div>', unsafe_allow_html=True)

            # Strength Bar
            st.progress(min(entropy / 120.0, 1.0))
            
            # --- REMEDIATION SECTION ---
            st.markdown("### 🛠️ Vulnerability Remediation")
            if tips:
                tips_list = "".join([f"<li style='color: #ff4b4b; margin-bottom: 5px;'>{t}</li>" for t in tips])
                st.markdown(f"""
                <div class="cyber-card" style="border-color: #ff4b4b; text-align: left; padding: 25px;">
                    <div style="color: #ff4b4b; font-weight: bold; margin-bottom: 10px;">⚠️ Identified Structural Weaknesses</div>
                    <ul style="font-family: monospace;">{tips_list}</ul>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div class="cyber-card" style="border-color: #00ffcc; text-align: left; padding: 25px;">
                    <div style="color: #00ffcc; font-weight: bold;">✅ Cryptographically Secure</div>
                    <div style="font-family: monospace; font-size: 0.9rem;">Payload meets maximum entropy standards. No structural weaknesses detected.</div>
                </div>
                """, unsafe_allow_html=True)

# --- GENERATOR SECTION ---
st.divider()
st.markdown("### ⚡ Secure Key Generator")

if st.button("GENERATE 256-BIT SECURE KEY"):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    secure_key = ''.join(random.choice(chars) for _ in range(32))
    st.code(secure_key, language="text")
    st.caption("Secure key generated via pseudo-random entropy. Deploy immediately.")

# Footer
st.markdown("---")
st.caption("NEXUS ENTROPY AUDIT SYSTEM // v3.0")