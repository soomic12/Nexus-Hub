import streamlit as st
import requests
import time
from security_utils import check_authenticity, apply_cyber_styling

# 1. Page Configuration
st.set_page_config(page_title="Breach Monitor", page_icon="📧", layout="wide")

# 2. Security & Unified Styling
check_authenticity()
apply_cyber_styling("Breach Monitor")

# --- CACHED API CALL FOR BREACH DICTIONARY ---
# We fetch the master list of all global breaches to get details on what was leaked.
@st.cache_data(ttl=3600, show_spinner=False)
def fetch_global_breach_dictionary():
    try:
        req = requests.get("https://api.xposedornot.com/v1/breaches")
        if req.status_code == 200:
            breaches = req.json().get('exposedBreaches', [])
            # Convert list to a dictionary for fast lookups
            return {b['breachID']: b for b in breaches}
        return {}
    except:
        return {}

# 3. Sidebar Intelligence
with st.sidebar:
    st.markdown("### 🔍 Live API Connection")
    st.info("Source: XposedOrNot API\nStatus: Online\nType: Real-Time OSINT")
    st.divider()
    st.markdown("### 🧠 Threat Logic")
    st.caption("This tool queries live, encrypted endpoints to cross-reference the target email against thousands of known database dumps.")

# 4. Main UI
st.title("📧 Global Data Breach Monitor (Live API)")
st.write("Query real-world deep web database dumps and compromised networks.")
st.divider()

email = st.text_input("Enter Target Email Address:", "test@example.com")

if st.button("INITIATE LIVE DEEP-WEB SCAN", use_container_width=True):
    if "@" in email:
        with st.spinner(f"Querying global intelligence nodes for {email}..."):
            # 1. Fetch the master breach details list
            breach_dict = fetch_global_breach_dictionary()
            
            # 2. Query the specific email
            target_url = f"https://api.xposedornot.com/v1/check-email/{email}"
            try:
                response = requests.get(target_url, timeout=10)
                
                # HTTP 404 from this specific API means "Not Found" (Safe)
                if response.status_code == 404:
                    st.success("✅ **STATUS SECURE:** No leaks detected in the current index for this identity.")
                    st.balloons()
                
                # HTTP 200 means the email was found in breaches
                elif response.status_code == 200:
                    data = response.json()
                    breached_sites = data.get("breaches", [[]])[0]
                    
                    if breached_sites:
                        # --- HIGH DANGER ALERT ---
                        st.markdown(f'''
                            <div style="background-color: #4a0000; border: 4px solid #ff4b4b; padding: 40px; border-radius: 15px; text-align: center; margin-bottom: 30px; box-shadow: 0 0 50px rgba(255, 75, 75, 0.4);">
                                <h1 style="color: #ff4b4b; font-size: 3.5rem; margin: 0; font-family: monospace;">⚠️ BREACH DETECTED ⚠️</h1>
                                <p style="color: #ffffff; font-size: 1.2rem; margin-top: 10px; font-weight: bold;">LIVE EXPOSURE FOUND: {len(breached_sites)} DATABASES</p>
                            </div>
                        ''', unsafe_allow_html=True)

                        st.markdown("### 🧬 Live Forensic Breakdown")
                        st.caption(f"Cross-referenced `{email}` against XposedOrNot threat intelligence.")
                        
                        # Render results dynamically based on API data
                        for site_name in breached_sites:
                            # Pull detailed info if available in our dictionary
                            site_info = breach_dict.get(site_name, {})
                            exposed_data = site_info.get("exposedData", "Emails, Passwords (Unverified)")
                            domain = site_info.get("domain", "Unknown")
                            
                            st.markdown(f'''
                                <div style="background-color: #1a1a2e; border-left: 5px solid #ff4b4b; padding: 15px; margin-bottom: 10px; border-radius: 5px;">
                                    <div style="display: flex; justify-content: space-between;">
                                        <span style="color: #ff4b4b; font-weight: bold; font-size: 1.1rem;">{site_name}</span>
                                        <span style="color: #888; font-size: 0.8rem; font-family: monospace;">DOMAIN: {domain}</span>
                                    </div>
                                    <div style="color: #e0d4f5; font-size: 0.9rem; margin-top: 5px;"><b>Compromised Metadata:</b> {exposed_data}</div>
                                </div>
                            ''', unsafe_allow_html=True)

                        st.divider()
                        st.markdown("### 🛡️ Recommended Mitigation Strategy")
                        st.error("**1. Immediate Password Rotation:** Change passwords for all accounts sharing these credentials.\n\n"
                                 "**2. Active MFA Enforcement:** Use hardware keys or TOTP apps (Google Authenticator).\n\n"
                                 "**3. Password Manager:** Never reuse the same password across multiple domains.")
                    else:
                        st.success("✅ **STATUS SECURE:** Data structure returned empty.")
                else:
                    st.error(f"🚨 API Error: Received HTTP {response.status_code}. Endpoint may be rate-limited.")
                    
            except requests.exceptions.RequestException as e:
                st.error(f"🚨 Uplink Timeout: Could not reach Threat API. ({e})")
    else:
        st.error("Invalid email format.")

# Footer
st.markdown("---")
st.caption("NEXUS LIVE BREACH INTELLIGENCE // v4.0")