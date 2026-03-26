import streamlit as st
import requests
import folium
from streamlit_folium import folium_static
from security_utils import check_authenticity, apply_cyber_styling

# 1. Page Configuration
st.set_page_config(page_title="IP Tracker", page_icon="📍", layout="wide")

# 2. Security & Unified Styling
check_authenticity()
apply_cyber_styling("IP Tracker")

# 3. Sidebar Intelligence
with st.sidebar:
    st.markdown("### 🛰️ Orbital Parameters")
    st.info("Source: IP-API / Esri World Imagery\nAccuracy: City-Level (Node PoP)")
    st.divider()
    st.markdown("### 🧠 Forensic Insight")
    st.caption("Automated self-tracing demonstrates how a web server captures 'Egress Traffic' data the moment a handshake is established.")

# 4. Main UI Logic
st.title("📍 Geospatial IP Tracker (Satellite Link)")
st.write("Perform a self-trace to identify your footprint or query a target IPv4 to map its physical routing node.")
st.divider()

# --- INITIALIZE SESSION STATES ---
if 'target_ip' not in st.session_state:
    st.session_state['target_ip'] = "8.8.8.8"
if 'trigger_trace' not in st.session_state:
    st.session_state['trigger_trace'] = False

# --- ALIGNED INPUT SECTION ---
col_input, col_button = st.columns([4, 1], vertical_alignment="bottom")

with col_input:
    target_ip = st.text_input(
        "Target IPv4 Address:", 
        value=st.session_state['target_ip']
    )

with col_button:
    if st.button("🔍 Find My IP", use_container_width=True):
        with st.spinner("Fetching..."):
            services = ['https://api.ipify.org', 'https://ifconfig.me/ip', 'https://ident.me']
            for service in services:
                try:
                    current_ip = requests.get(service, timeout=3).text.strip()
                    if current_ip:
                        st.session_state['target_ip'] = current_ip
                        st.session_state['trigger_trace'] = True 
                        st.rerun()
                        break
                except:
                    continue

# --- THE TRACE ENGINE ---
if st.button("INITIATE TACTICAL TRACE", use_container_width=True) or st.session_state['trigger_trace']:
    st.session_state['trigger_trace'] = False
    
    with st.spinner("Triangulating node location via satellite..."):
        try:
            query_ip = st.session_state['target_ip']
            response = requests.get(f"http://ip-api.com/json/{query_ip}").json()
            
            if response['status'] == 'success':
                st.success(f"✅ Trace Complete: {response['city']}, {response.get('regionName')}, {response.get('country')}")
                st.divider()
                
                # --- TELEMETRY CARDS (FIXED HTML BLOCKS) ---
                st.markdown("### 📡 Core Routing Telemetry")
                
                # Row 1
                st.markdown(f'''
                <div style="display: flex; gap: 10px; margin-bottom: 10px;">
                    <div style="flex: 1; background-color: #1e122b; border: 1px solid #b24bf3; border-radius: 8px; padding: 15px; text-align: center;">
                        <div style="color: #e0d4f5; font-size: 0.8rem;"><b>ISP</b></div>
                        <div style="color: #b24bf3; font-size: 1.1rem; font-weight: bold;">{response.get('isp')}</div>
                    </div>
                    <div style="flex: 1; background-color: #1e122b; border: 1px solid #b24bf3; border-radius: 8px; padding: 15px; text-align: center;">
                        <div style="color: #e0d4f5; font-size: 0.8rem;"><b>Latitude</b></div>
                        <div style="color: #b24bf3; font-size: 1.1rem; font-weight: bold;">{response.get('lat')}</div>
                    </div>
                    <div style="flex: 1; background-color: #1e122b; border: 1px solid #b24bf3; border-radius: 8px; padding: 15px; text-align: center;">
                        <div style="color: #e0d4f5; font-size: 0.8rem;"><b>Longitude</b></div>
                        <div style="color: #b24bf3; font-size: 1.1rem; font-weight: bold;">{response.get('lon')}</div>
                    </div>
                </div>
                ''', unsafe_allow_html=True)

                # Row 2
                st.markdown(f'''
                <div style="display: flex; gap: 10px; margin-bottom: 20px;">
                    <div style="flex: 1; background-color: #1e122b; border: 1px solid #b24bf3; border-radius: 8px; padding: 15px; text-align: center;">
                        <div style="color: #e0d4f5; font-size: 0.8rem;"><b>Organization</b></div>
                        <div style="color: #b24bf3; font-size: 1.1rem; font-weight: bold;">{response.get('org')}</div>
                    </div>
                    <div style="flex: 1; background-color: #1e122b; border: 1px solid #b24bf3; border-radius: 8px; padding: 15px; text-align: center;">
                        <div style="color: #e0d4f5; font-size: 0.8rem;"><b>Timezone</b></div>
                        <div style="color: #b24bf3; font-size: 1.1rem; font-weight: bold;">{response.get('timezone')}</div>
                    </div>
                    <div style="flex: 1; background-color: #1e122b; border: 1px solid #b24bf3; border-radius: 8px; padding: 15px; text-align: center;">
                        <div style="color: #e0d4f5; font-size: 0.8rem;"><b>AS Number</b></div>
                        <div style="color: #b24bf3; font-size: 1.1rem; font-weight: bold;">{response.get('as')}</div>
                    </div>
                </div>
                ''', unsafe_allow_html=True)

                st.divider()
                st.markdown("### 🛰️ Tactical Satellite View (High Precision)")
                
                lat, lon = response['lat'], response['lon']
                accuracy_radius = 5000 
                
                # Image Tag Refined
                st.image("https://img.icons8.com/clouds/100/satellite.png", width=50)
                st.caption("Forensic Analysis: IP Geolocation Map with Signal Margin of Error")
                

                m = folium.Map(
                    location=[lat, lon],
                    zoom_start=15, 
                    tiles='https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
                    attr='Esri World Imagery'
                )
                
                folium.Circle(
                    radius=accuracy_radius,
                    location=[lat, lon],
                    color="#ff4b4b",
                    fill=True,
                    fill_opacity=0.15,
                    popup="Probable Signal Radius"
                ).add_to(m)

                folium.Marker(
                    [lat, lon],
                    popup=f"Target: {query_ip}",
                    icon=folium.Icon(color="red", icon="crosshairs", prefix="fa")
                ).add_to(m)
                
                folium_static(m, width=1100, height=500)
                
                st.divider()
                st.markdown("### 🧠 OSINT Methodology")
                
                st.caption("Infrastructure: Network routing from client device to ISP neighborhood hub")
                

                st.warning(f"📍 Forensic Note: Coordinate ({lat}, {lon}) identifies the ISP Gateway. Target is triangulated within a {accuracy_radius/1000}km radius.")
                
            else:
                st.error("🚨 Trace Failed: Private IP or invalid node configuration.")
        except Exception as e:
            st.error(f"🛰️ Uplink Lost: {e}")

# Footer
st.markdown("---")
st.caption("NEXUS IP RECONNAISSANCE SYSTEM // v3.0")