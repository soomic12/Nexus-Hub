import streamlit as st
import ipapi
import folium
import requests
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
    st.info("Engine: IPAPI Core Bindings / MaxMind\nAccuracy: Hardware Node Resolution")
    st.divider()
    st.markdown("### 🧠 Forensic Insight")
    st.caption("Automated self-tracing demonstrates how a web server captures 'Egress Traffic' data the moment a handshake is established.")

# 4. Main UI Logic
st.title("📍 Geospatial IP Tracker (Satellite Link)")
st.write("Perform a self-trace to identify your footprint or query a target IPv4 to map its physical routing node.")
st.divider()

# --- INITIALIZE SESSION STATES (The Refresh Logic) ---
if 'current_ip_val' not in st.session_state:
    st.session_state['current_ip_val'] = "8.8.8.8"
if 'widget_key_suffix' not in st.session_state:
    st.session_state['widget_key_suffix'] = 0

# --- ALIGNED INPUT SECTION ---
col_input, col_button = st.columns([4, 1], vertical_alignment="bottom")

with col_input:
    # We use a dynamic key (suffix) to force Streamlit to redraw the widget 
    # when the 'Find My IP' button is clicked.
    target_ip_input = st.text_input(
        "Target IPv4 Address:", 
        value=st.session_state['current_ip_val'],
        key=f"ip_input_widget_{st.session_state['widget_key_suffix']}"
    )

# --- FIND MY IP (Using native ipapi self-lookup) ---
with col_button:
    if st.button("🔍 Find My IP", use_container_width=True):
        with st.spinner("Fetching local footprint..."):
            try:
                # Removed the 'timeout' argument that caused the Uplink Error
                self_data = ipapi.location() 
                if self_data and 'ip' in self_data:
                    # 1. Update the value
                    st.session_state['current_ip_val'] = self_data['ip']
                    # 2. Increment suffix to force-refresh the text box
                    st.session_state['widget_key_suffix'] += 1
                    st.rerun()
                else:
                    st.error("Failed to retrieve local routing data.")
            except Exception as e:
                st.error(f"Uplink Error: {e}")

# --- THE TRACE ENGINE (Powered by IPAPI) ---
if st.button("INITIATE TACTICAL TRACE", use_container_width=True):
    # Read the current content of the refreshed text box
    query_ip = target_ip_input.strip()
    
    with st.spinner("Triangulating node location via satellite..."):
        try:
            # Utilizing the official python bindings for the lookup
            raw_data = ipapi.location(ip=query_ip)
            
            if raw_data and "error" not in raw_data:
                # Map ipapi dictionary keys to your UI variables
                response = {
                    'status': 'success',
                    'city': raw_data.get('city') or 'Data Center',
                    'regionName': raw_data.get('region') or 'Global',
                    'country': raw_data.get('country_name') or 'Global Node',
                    'isp': raw_data.get('org', 'Unknown Provider'),
                    'lat': raw_data.get('latitude', 0.0),
                    'lon': raw_data.get('longitude', 0.0),
                    'org': raw_data.get('org', 'Unknown Organization'),
                    'timezone': raw_data.get('timezone', 'UTC'),
                    'as': raw_data.get('asn', 'Unknown ASN')
                }
                
                if ":" in query_ip:
                    st.info("📡 **Protocol Detected:** IPv6 (Next-Gen Stack). Trace identifies the Regional Peering Point.")
                else:
                    st.info("📡 **Protocol Detected:** IPv4 (Legacy Stack). Trace identifies the CGNAT Gateway.")
                st.success(f"✅ Trace Complete: {response['city']}, {response['country']}")
                st.divider()
                
                # --- TELEMETRY CARDS (YOUR CUSTOM HTML BLOCKS) ---
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
                accuracy_radius = 5000 if response['city'] != "Data Center" else 50000 
                
                st.image("https://img.icons8.com/clouds/100/satellite.png", width=50)
                st.caption("Forensic Analysis: IP Geolocation Map with Signal Margin of Error")
                
                m = folium.Map(
                    location=[lat, lon],
                    zoom_start=15 if response['city'] != "Data Center" else 5, 
                    tiles='https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
                    attr='Esri World Imagery'
                )
                
                folium.Circle(
                    radius=accuracy_radius,
                    location=[lat, lon],
                    color="#ff4b4b",
                    fill=True,
                    fill_opacity=0.15,
                    popup="Probable Signal Area"
                ).add_to(m)

                folium.Marker(
                    [lat, lon],
                    popup=f"Target: {query_ip}",
                    icon=folium.Icon(color="red", icon="crosshairs", prefix="fa")
                ).add_to(m)
                
                folium_static(m, width=1100, height=500)
                
                st.divider()
                st.markdown("### 🧠 OSINT Methodology")
                
                if response['city'] == "Data Center":
                    st.warning("📍 Forensic Note: Target is utilizing Global Anycast routing. Coordinates reflect the administrative headquarters.")
                else:
                    st.warning(f"📍 Forensic Note: Coordinate ({lat}, {lon}) identifies the ISP Gateway. Target is triangulated within a {accuracy_radius/1000}km radius.")
                
            else:
                st.error(f"🚨 Trace Failed: {raw_data.get('reason', 'Private IP or invalid node configuration.')}")
        except Exception as e:
            st.error(f"🛰️ Uplink Lost: Check API connection. Details: {e}")

# Footer
st.markdown("---")
st.caption("NEXUS IP RECONNAISSANCE SYSTEM // v4.0")