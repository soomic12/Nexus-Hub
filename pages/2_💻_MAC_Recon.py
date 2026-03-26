import streamlit as st
import requests
import re
from security_utils import check_authenticity, apply_cyber_styling

# 1. Page Configuration
st.set_page_config(page_title="MAC Recon", page_icon="💻", layout="wide")

# 2. Security & Unified Styling
check_authenticity()
apply_cyber_styling("MAC Recon")

# 3. Sidebar Intelligence
with st.sidebar:
    st.markdown("### 🔍 Hardware Analysis")
    st.info("Registry: IEEE OUI\nMethod: Bit-level Header Inspection")
    st.divider()
    st.markdown("### 🧠 Forensic Insight")
    st.caption("Device classification is determined by cross-referencing the OUI against known mobile-only vs. desktop-component manufacturer databases.")

# 4. Main UI Logic
st.write("Decode OUI signatures, detect hardware spoofing, and identify device categories (Mobile vs. Desktop).")
st.divider()

col_input, col_info = st.columns([1, 2])

# --- LOGIC: DEVICE CLASSIFICATION ENGINE ---
def get_device_class(vendor):
    vendor_lower = vendor.lower()
    mobile_indicators = ["samsung", "apple", "huawei", "xiaomi", "oppo", "vivo", "google", "motorola", "hmd", "zte"]
    pc_indicators = ["intel", "dell", "hp inc", "lenovo", "asus", "gigabyte", "realtek", "tp-link", "cisco", "msi"]
    
    if any(m in vendor_lower for m in mobile_indicators):
        return "📱 Mobile / Android"
    elif any(p in vendor_lower for p in pc_indicators):
        return "💻 Desktop / Laptop"
    else:
        return "🛡️ Generic Hardware"

with col_input:
    st.markdown("### 🔌 Hardware Input")
    mac_input = st.text_input("Enter MAC Address:", "BC:D1:1F:B1:10:02")
    clean_mac = re.sub(r'[^a-fA-F0-9]', '', mac_input)
    
    if st.button("INITIATE HARDWARE TRACE", use_container_width=True):
        if len(clean_mac) >= 6:
            with st.spinner("Analyzing bit-level headers..."):
                second_char = clean_mac[1].upper() if len(clean_mac) > 1 else ""
                is_random = second_char in ['2', '6', 'A', 'E']
                st.session_state['mac_is_random'] = is_random
                
                try:
                    res = requests.get(f"https://api.macvendors.com/{mac_input}")
                    vendor_name = res.text if res.status_code == 200 else "Unknown / Private"
                    st.session_state['mac_vendor'] = vendor_name
                    st.session_state['mac_device_class'] = get_device_class(vendor_name)
                except:
                    st.session_state['mac_vendor'] = "Lookup Error"
                    st.session_state['mac_device_class'] = "Unknown"
        else:
            st.error("Invalid MAC Format.")

with col_info:
    vendor = st.session_state.get('mac_vendor', "Awaiting Trace...")
    is_random = st.session_state.get('mac_is_random', False)
    device_class = st.session_state.get('mac_device_class', "Unknown")
    
    # --- STEP 1: RENDER CARDS (Pure HTML) ---
    st.markdown(f'''
    <div style="display: flex; gap: 10px; margin-bottom: 20px;">
        <div style="flex: 1; background-color: #1e122b; border: 1px solid #b24bf3; border-radius: 8px; padding: 15px; text-align: center;">
            <div style="color: #e0d4f5; font-size: 0.9rem; opacity: 0.8;"><b>Manufacturer</b></div>
            <div style="color: #b24bf3; font-size: 1.2rem; font-weight: bold;">{vendor}</div>
        </div>
        <div style="flex: 1; background-color: #1e122b; border: 1px solid #b24bf3; border-radius: 8px; padding: 15px; text-align: center;">
            <div style="color: #e0d4f5; font-size: 0.9rem; opacity: 0.8;"><b>Device Class</b></div>
            <div style="color: #b24bf3; font-size: 1.2rem; font-weight: bold;">{device_class}</div>
        </div>
        <div style="flex: 1; background-color: #1e122b; border: 1px solid #b24bf3; border-radius: 8px; padding: 15px; text-align: center;">
            <div style="color: #e0d4f5; font-size: 0.9rem; opacity: 0.8;"><b>Address Type</b></div>
            <div style="color: #b24bf3; font-size: 1.2rem; font-weight: bold;">{"Randomized" if is_random else "Hardware-Locked"}</div>
        </div>
    </div>
    ''', unsafe_allow_html=True)

    # --- STEP 2: ALERTS ---
    if is_random:
        st.warning("⚠️ **DETECTION: Locally Administered Address (LAA).** Privacy Mode Active.")
    else:
        st.success("✅ **DETECTION: Universally Administered Address (UAA).** Hardware Signature Verified.")

    # --- STEP 3: ANATOMY & BREAKDOWN (Separate from HTML) ---
    st.markdown("### 🧠 Hardware Anatomy")
    
    
    
    st.write(f"**Forensic Breakdown for node `{mac_input}`:**")
    st.write(f"* **OUI Identifier:** The first 24 bits belong to **{vendor}**.")
    st.write(f"* **Machine Context:** The hardware footprint matches a **{device_class}** profile.")

st.markdown("---")
st.caption("NEXUS HARDWARE INTELLIGENCE SYSTEM // v3.0")