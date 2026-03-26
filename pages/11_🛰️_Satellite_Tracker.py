import streamlit as st
import requests
import pandas as pd
import pydeck as pdk
from security_utils import check_authenticity, apply_cyber_styling

# 1. Page Setup
st.set_page_config(page_title="Satellite SIGINT", page_icon="🛰️", layout="wide")
check_authenticity()
apply_cyber_styling("Satellite Tracker")

# 2. API Key
API_KEY = "8GLWER-8KWBDU-XN2BLF-5OKO"

# --- CUSTOM CSS FOR TABLE GLOW ---
st.markdown("""
<style>
    /* Add a neon border and shadow to the dataframe container */
    [data-testid="stDataFrame"] {
        border: 1px solid #00ffcc !important;
        border-radius: 5px;
        box-shadow: 0 0 10px rgba(0, 255, 204, 0.2);
    }
</style>
""", unsafe_allow_html=True)

def get_satellite_data(lat, lon):
    url = f"https://api.n2yo.com/rest/v1/satellite/above/{lat}/{lon}/0/70/0/&apiKey={API_KEY}"
    try:
        r = requests.get(url, timeout=10)
        return r.json()
    except: return None

# --- UI LAYOUT ---
col_map, col_data = st.columns([1.5, 1])

with col_map:
    st.markdown("### 🛰️ Orbital Intercept Map")
    lat = st.number_input("Station Lat:", value=9.9312, format="%.4f")
    lon = st.number_input("Station Lon:", value=76.2673, format="%.4f")
    scan_btn = st.button("INITIATE SCAN", use_container_width=True)

    if scan_btn:
        with st.spinner("Decoding TLE Data..."):
            data = get_satellite_data(lat, lon)
            if data and "above" in data:
                raw_df = pd.DataFrame(data['above'])
                
                # Setup Map Data
                map_df = raw_df.rename(columns={'satlat': 'lat', 'satlng': 'lon'})
                
                st.pydeck_chart(pdk.Deck(
                    map_style='mapbox://styles/mapbox/dark-v10',
                    initial_view_state=pdk.ViewState(latitude=lat, longitude=lon, zoom=2.5, pitch=45),
                    layers=[
                        pdk.Layer('ScatterplotLayer', data=map_df, get_position='[lon, lat]',
                                  get_color='[0, 255, 204, 200]', get_radius=150000),
                    ],
                ))
            else:
                st.error("Scan Failed: Zero Nodes.")

with col_data:
    st.markdown("### 📋 Tactical Telemetry")
    if scan_btn and 'raw_df' in locals():
        # Prepping data for the "Designed" view
        display_df = raw_df[['satname', 'launchDate', 'satalt']].copy()
        display_df.columns = ['ID', 'Launched', 'Altitude']
        
        # Adding a "Status" column for visual flair
        display_df['Status'] = "ACTIVE"
        
        # RENDER THE DESIGNED DATAFRAME
        st.dataframe(
            display_df,
            column_config={
                "ID": st.column_config.TextColumn("📡 SATELLITE NAME", width="medium"),
                "Launched": st.column_config.TextColumn("📅 DATE"),
                "Altitude": st.column_config.ProgressColumn(
                    "📏 ALTITUDE (km)",
                    help="Orbital Height in Kilometers",
                    format="%d km",
                    min_value=0,
                    max_value=40000, # Covers GEO orbit
                ),
                "Status": st.column_config.SelectboxColumn(
                    "⚡ STATUS",
                    options=["ACTIVE", "STANDBY", "LOCKED"],
                    default="ACTIVE",
                )
            },
            hide_index=True,
            use_container_width=True,
            height=500
        )
    else:
        st.info("Awaiting scan initiation...")