import streamlit as st
import requests
import folium
from streamlit_folium import folium_static
from security_utils import check_authenticity, apply_cyber_styling

st.set_page_config(page_title="IP Tracker", page_icon="📍", layout="wide")
check_authenticity()
apply_cyber_styling("IP Tracker")

# --- SESSION STATE MANAGEMENT ---
if 'display_ip' not in st.session_state:
    st.session_state['display_ip'] = ""

# --- MAIN UI ---
st.title("📍 Geospatial IP Tracker")
st.write("Enter a Public IPv4 address to triangulate its physical routing node.")
st.divider()

# Input field is linked to session state
target_ip = st.text_input("Target IPv4 Address:", value=st.session_state['display_ip'], placeholder="Enter Public IP (e.g. 1.1.1.1)")

# Button Layout
col1, col2 = st.columns([1, 1])

with col1:
    if st.button("🔍 INITIATE TACTICAL TRACE", use_container_width=True):
        if not target_ip:
            st.warning("Please enter an IP address.")
        else:
            with st.spinner("Triangulating..."):
                try:
                    # Clear previous results by refreshing query
                    response = requests.get(f"http://ip-api.com/json/{target_ip}").json()
                    
                    if response['status'] == 'success':
                        st.success(f"✅ Trace Complete: {response['city']}, {response['country']}")
                        
                        # Metrics
                        c1, c2, c3 = st.columns(3)
                        c1.metric("ISP", response.get('isp'))
                        c2.metric("Organization", response.get('org'))
                        c3.metric("Timezone", response.get('timezone'))

                        # Map
                        lat, lon = response['lat'], response['lon']
                        m = folium.Map(location=[lat, lon], zoom_start=12, tiles='CartoDB dark_matter')
                        folium.Marker([lat, lon], popup=target_ip, icon=folium.Icon(color='red', icon='crosshairs', prefix='fa')).add_to(m)
                        folium_static(m, width=1100)
                        
                        st.info(f"📍 Forensic Note: Coordinate ({lat}, {lon}) identifies the ISP Gateway.")
                    else:
                        st.error("🚨 Trace Failed: Private or Invalid IP address.")
                except Exception as e:
                    st.error(f"🛰️ Uplink Lost: {e}")

with col2:
    # This button now just clears the state so you can type fresh
    if st.button("🗑️ CLEAR SEARCH", use_container_width=True):
        st.session_state['display_ip'] = ""
        st.rerun()

st.markdown("---")
st.caption("NEXUS IP RECONNAISSANCE SYSTEM // v3.0")