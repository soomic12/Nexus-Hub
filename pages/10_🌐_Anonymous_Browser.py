import streamlit as st
import requests
import folium
from streamlit_folium import folium_static
from security_utils import check_authenticity, apply_cyber_styling

# 1. Page Configuration
st.set_page_config(page_title="IP Tracker", page_icon="📍", layout="wide")
check_authenticity()
apply_cyber_styling("IP Tracker")

# 2. Session State Initialization
if 'last_query' not in st.session_state:
    st.session_state['last_query'] = ""

# 3. Main UI
st.title("📍 Geospatial IP Reconnaissance")
st.write("Enter any **Public IPv4** address to perform a global node trace.")

# --- THE FIX: Input & Logical Trigger ---
# We use a unique key to ensure Streamlit tracks the input correctly
target_ip = st.text_input("Target IPv4 Address:", placeholder="e.g. 1.1.1.1 or 8.8.8.8", key="ip_input_field")

col_trace, col_reset = st.columns([1, 1])

with col_trace:
    if st.button("🔍 INITIATE TACTICAL TRACE", use_container_width=True):
        if not target_ip:
            st.warning("Digital footprint required. Please enter an IPv4 address.")
        else:
            with st.spinner(f"Querying global registries for {target_ip}..."):
                try:
                    # CRITICAL FIX: Explicitly passing the target_ip to the API
                    # Using a 5-second timeout to prevent the app from hanging
                    url = f"http://ip-api.com/json/{target_ip}?fields=status,message,country,regionName,city,lat,lon,timezone,isp,org,as"
                    response = requests.get(url, timeout=5).json()

                    if response.get('status') == 'success':
                        st.success(f"✅ Trace Complete: {response['city']}, {response['country']}")
                        
                        # Data Cards
                        c1, c2, c3 = st.columns(3)
                        # This will now correctly show "Cloudflare" for 1.1.1.1
                        c1.metric("Network Provider (ISP)", response.get('isp')) 
                        c2.metric("Organization", response.get('org'))
                        c3.metric("Routing Node (AS)", response.get('as'))

                        # Map Rendering
                        lat, lon = response['lat'], response['lon']
                        m = folium.Map(location=[lat, lon], zoom_start=12, tiles='CartoDB dark_matter')
                        folium.Marker(
                            [lat, lon], 
                            popup=f"Target: {target_ip}",
                            icon=folium.Icon(color='red', icon='crosshairs', prefix='fa')
                        ).add_to(m)
                        
                        folium_static(m, width=1100)
                        
                        st.info(f"📍 Forensic Note: Signal localized to {response['city']} Gateway node.")
                    else:
                        st.error(f"🚨 Trace Error: {response.get('message', 'Invalid Node Address')}")
                        st.caption("Note: Private IPs (192.168.x.x) cannot be traced on the public web.")
                
                except Exception as e:
                    st.error(f"🛰️ Uplink Lost: {str(e)}")

with col_reset:
    if st.button("🗑️ CLEAR SCAN DATA", use_container_width=True):
        # Clears the input and reruns the app for a fresh state
        st.session_state['ip_input_field'] = ""
        st.rerun()

# Sidebar Info
with st.sidebar:
    st.markdown("### 🛰️ Trace Methodology")
    st.caption("This module queries the IP-API global database. It bypasses local server headers to ensure the target's actual registration data is displayed.")

st.markdown("---")
st.caption("NEXUS IP RECONNAISSANCE SYSTEM // v3.0")