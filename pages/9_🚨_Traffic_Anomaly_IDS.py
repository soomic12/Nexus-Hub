import streamlit as st
import pandas as pd
import numpy as np
import time
import zipfile
import io
import dpkt
import socket
from security_utils import check_authenticity, apply_cyber_styling

st.set_page_config(page_title="Traffic Anomaly", page_icon="🕵️", layout="wide")
check_authenticity()
apply_cyber_styling("Traffic Anomaly")
st.write("Ingest raw PCAP binaries or Kaggle ZIP archives. Utilizes Z-Score statistical modeling to identify volumetric anomalies.")

st.divider()



col1, col2 = st.columns([1, 2])



with col1:

    st.markdown("### 📥 Ingest Kaggle Dataset")

    st.write("Upload a `.csv`, `.pcap`, or a compressed `.zip` containing raw network traffic.")

   

    # Upgraded Uploader to accept PCAP files

    uploaded_file = st.file_uploader("Upload Network Logs", type=['csv', 'zip', 'pcap'])

   

    st.divider()

    st.markdown("### ⚙️ Statistical Parameters")

    z_threshold = st.slider("Anomaly Z-Score Threshold:", min_value=2.0, max_value=5.0, value=3.0, step=0.1)

    st.caption("A Z-Score > 3 indicates statistical anomalies (99.7% confidence interval).")

   

    st.divider()

    st.markdown("### 🧪 Simulation Mode")

    if st.button("Generate Synthetic Traffic (5,000 Nodes)"):

        with st.spinner("Compiling synthetic network swarm..."):

            time.sleep(1)

            np.random.seed(42)

            normal_ips = [f"192.168.1.{i}" for i in range(1, 100)]

            malicious_ips = ["45.33.22.11", "104.22.8.99", "185.11.2.5"]

           

            data = {'Source_IP': np.random.choice(normal_ips, 4800), 'Packet_Size': np.random.normal(500, 100, 4800)}

            ddos_data = {'Source_IP': np.random.choice(malicious_ips, 200), 'Packet_Size': np.random.normal(5000, 500, 200)}

           

            df_normal = pd.DataFrame(data)

            df_ddos = pd.DataFrame(ddos_data)

            st.session_state['traffic_data'] = pd.concat([df_normal, df_ddos]).sample(frac=1).reset_index(drop=True)

            st.success("Synthetic Kaggle dataset generated and loaded into memory.")



# --- THE NATIVE PACKET DISSECTOR FUNCTION ---

def parse_pcap_to_df(file_bytes):

    """Optimized high-speed dissector for large datasets."""

    records = []

    try:

        # We wrap the bytes in a buffer to handle large file seeking

        pcap = dpkt.pcap.Reader(file_bytes)

    except Exception:

        file_bytes.seek(0)

        try:

            pcap = dpkt.pcapng.Reader(file_bytes)

        except Exception:

            st.error("🚨 Unrecognized Packet Format.")

            return pd.DataFrame()

           

    packet_count = 0

    # Increase limit to 200k packets for a 1GB file (balance between depth and speed)

    MAX_PACKETS = 200000

   

    for timestamp, buf in pcap:

        if packet_count >= MAX_PACKETS:

            break

           

        try:

            # We use 'dpkt' to only unpack the header, not the full payload

            # This is 10x faster and uses way less RAM

            eth = dpkt.ethernet.Ethernet(buf)

            if isinstance(eth.data, dpkt.ip.IP):

                ip_layer = eth.data

                src_ip = socket.inet_ntoa(ip_layer.src)

                pkt_size = len(buf)

                records.append({'Source_IP': src_ip, 'Packet_Size': pkt_size})

                packet_count += 1

        except:

            continue

           

    # Explicitly clear file_bytes from memory after reading

    file_bytes.close()

    return pd.DataFrame(records)



with col2:

    st.markdown("### 📈 Volumetric Threat Analysis")

   

    df = None

    if uploaded_file is not None:

        file_name = uploaded_file.name.lower()

        try:

            # 1. Handle standard CSV

            if file_name.endswith('.csv'):

                df = pd.read_csv(uploaded_file)

                st.success(f"✅ Extracted payload: `{uploaded_file.name}`")

               

            # 2. Handle raw PCAP (Wireshark) files natively

            elif file_name.endswith('.pcap'):

                with st.spinner("Executing native packet dissection on binary capture..."):

                    df = parse_pcap_to_df(uploaded_file)

                    st.success(f"✅ Successfully dissected `{uploaded_file.name}` directly into memory.")

                   

            # 3. Handle ZIP archives

            elif file_name.endswith('.zip'):

                with st.spinner("Unpacking ZIP archive in memory..."):

                    with zipfile.ZipFile(uploaded_file, 'r') as z:

                        file_list = z.namelist()

                       

                        # Find CSV or PCAP inside the zip

                        csv_files = [f for f in file_list if f.endswith('.csv')]

                        pcap_files = [f for f in file_list if f.endswith('.pcap') or '.' not in f] # Kaggle sometimes leaves extensions off PCAPs

                       

                        if csv_files:

                            with z.open(csv_files[0]) as f:

                                df = pd.read_csv(f)

                            st.success(f"✅ Extracted CSV payload: `{csv_files[0]}`")

                        elif pcap_files:

                            with z.open(pcap_files[0]) as f:

                                file_bytes = io.BytesIO(f.read())

                                df = parse_pcap_to_df(file_bytes)

                            st.success(f"✅ Dissected binary PCAP payload: `{pcap_files[0]}`")

                        else:

                            st.error("🚨 Extractor failed: No recognizable traffic logs found inside the ZIP.")

        except Exception as e:

             st.error(f"🚨 Data Ingestion Error: {e}")

             

    elif 'traffic_data' in st.session_state:

        df = st.session_state['traffic_data']

       

    if df is not None and not df.empty:

        try:

            traffic_summary = df.groupby('Source_IP').agg(

                Request_Count=('Source_IP', 'count'), Avg_Payload=('Packet_Size', 'mean')

            ).reset_index()

           

            mean_requests = traffic_summary['Request_Count'].mean()

            std_requests = traffic_summary['Request_Count'].std()

            traffic_summary['Z_Score'] = (traffic_summary['Request_Count'] - mean_requests) / std_requests

           

            anomalies = traffic_summary[traffic_summary['Z_Score'] > z_threshold].sort_values(by='Z_Score', ascending=False)

           

            c1, c2, c3 = st.columns(3)

            with c1: st.markdown(f'<div class="cyber-card"><div class="card-title">Total Packets Analyzed</div><div class="card-value">{len(df):,}</div></div>', unsafe_allow_html=True)

            with c2: st.markdown(f'<div class="cyber-card"><div class="card-title">Unique Origin Nodes</div><div class="card-value">{len(traffic_summary):,}</div></div>', unsafe_allow_html=True)

            with c3:

                color = "#ff4b4b" if len(anomalies) > 0 else "#00ffcc"

                st.markdown(f'<div class="cyber-card" style="border-color:{color};"><div class="card-title">Anomalies Detected</div><div class="card-value" style="color:{color};">{len(anomalies)}</div></div>', unsafe_allow_html=True)



            st.divider()

           

            if not anomalies.empty:

                st.error("🚨 **CRITICAL: Asymmetric Traffic Spikes Detected.** Potential Botnet/DDoS signatures isolated.")

                st.dataframe(

                    anomalies.style.format({'Avg_Payload': '{:.2f} bytes', 'Z_Score': '{:.2f}'}),

                    column_config={"Source_IP": "Malicious Origin", "Request_Count": "Packet Volume", "Avg_Payload": "Avg Payload Size", "Z_Score": "Statistical Z-Score"},

                    hide_index=True, use_container_width=True

                )

               

                # --- EXPORT TO CSV FEATURE ---

                st.markdown("### 💾 Export Threat Intelligence")

                st.write("Export the dissected anomalies as a clean CSV for firewall blacklisting.")

                csv_export = anomalies.to_csv(index=False).encode('utf-8')

                st.download_button(

                    label="⬇️ Download Dissected CSV",

                    data=csv_export,

                    file_name="nids_anomalies_detected.csv",

                    mime="text/csv",

                )

            else:

                st.success("✅ Baseline traffic is normal. No statistical deviations detected.")

               

        except KeyError:

            st.error("🚨 Dataset format error. Ensure the data contains `Source_IP` and `Packet_Size`.")

    else:

        st.info("Awaiting raw traffic logs. Upload a CSV/ZIP/PCAP or generate a synthetic baseline.")



