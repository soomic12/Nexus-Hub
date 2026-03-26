import streamlit as st
import requests
import folium
from streamlit_folium import folium_static
from security_utils import check_authenticity, apply_cyber_styling

# 1. Page Configuration
st.set_page_config(page_title="Nexus Hub | IP Tracker", page_icon="📍", layout="wide")
check_authenticity()
apply_cyber_styling("IP Tracker")

# 2. Session State Initialization (The Fix for the "Refresh" Bug)
if 'search_result' not in st.session_state:
    st.session_state['search_result'] = None

st.title("📍 Geospatial IP Reconnaissance")
st.write("Enter a **Public IPv4** to triangulate its physical routing node.")
st.divider()

# --- THE INPUT ---
# We use a unique key to ensure the value is captured correctly
query_ip = st.text_input("Target IPv4 Address:", placeholder="e.g. 1.1.1.1 or 8.8.8.8", key="main_ip_input")

col_btn1, col_btn2 = st.columns([1, 1])

with col_btn1:
    if st.button("🔍 INITIATE TACTICAL TRACE", use_container_width=True):
        if query_ip:
            with st.spinner(f"Querying registries for {query_ip}..."):
                try:
                    # THE FIX: Explicitly appending the query_ip to the URL
                    # We add 'fields' to ensure we get ISP and ORG data specifically
                    api_url = f"http://ip-api.com/json/{query_ip}?fields=status,message,country,regionName,city,lat,lon,timezone,isp,org,as"
                    response = requests.get(api_url, timeout=5).json()
                    
                    if response.get('status') == 'success':
                        st.session_state['search_result'] = response
                    else:
                        st.error(f"Trace Failed: {response.get('message', 'Invalid IP')}")
                except Exception as e:
                    st.error(f"Uplink Error: {e}")
        else:
            st.warning("Please enter an IP address first.")

with col_btn2:
    if st.button("🗑️ CLEAR SYSTEM CACHE", use_container_width=True):
        st.session_state['search_result'] = None
        st.rerun()

# --- DISPLAY LOGIC (Only shows if a search was successful) ---
if st.session_state['search_result']:
    res = st.session_state['search_result']
    
    st.success(f"✅ Trace Complete: {res['city']}, {res['country']}")
    
    # These metrics will now correctly show Cloudflare for 1.1.1.1
    c1, c2, c3 = st.columns(3)
    c1.metric("ISP / Provider", res.get('isp'))
    c2.metric("Organization", res.get('org'))
    c3.metric("AS Number", res.get('as'))

    # Map Rendering
    lat, lon = res['lat'], res['lon']
    m = folium.Map(location=[lat, lon], zoom_start=12, tiles='CartoDB dark_matter')
    folium.Marker([lat, lon], popup=f"IP: {query_ip}").add_to(m)
    folium_static(m, width=1100)
    
    st.info(f"📍 Forensic Note: Coordinate ({lat}, {lon}) identifies the ISP Gateway node.")

st.markdown("---")
st.caption("NEXUS IP RECONNAISSANCE SYSTEM // v3.0")