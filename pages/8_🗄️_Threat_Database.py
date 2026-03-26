import streamlit as st
import sqlite3
import pandas as pd
from security_utils import check_authenticity, apply_cyber_styling

# 1. Page Configuration
st.set_page_config(page_title="Threat Intelligence DB", page_icon="🗄️", layout="wide")

# 2. Security & Unified Styling
check_authenticity()
apply_cyber_styling("Threat Intelligence DB")

# 3. Sidebar Intelligence
with st.sidebar:
    st.markdown("### 🗄️ Storage Engine")
    st.info("Engine: SQLite3\nArchitecture: Relational (SQL)\nEncryption: Local-Node Only")
    st.divider()
    st.markdown("### 🧠 Analyst Tip")
    st.caption("Centralizing threat logs allows for trend analysis. Identifying repeated 'Primary Vectors' helps in prioritizing firewall rules and patch management.")

# 4. Database Initialization
DB_FILE = 'threat_intelligence.db'

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS threat_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL, 
            threat_type TEXT NOT NULL,
            severity TEXT NOT NULL, 
            notes TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

init_db()

# 5. Data Retrieval & Analytics
conn = sqlite3.connect(DB_FILE)
df = pd.read_sql_query("SELECT * FROM threat_logs ORDER BY timestamp DESC", conn)
conn.close()

st.write("Persistent SQL logging and live analytics for identified network threats.")
st.divider()

# --- ANALYTICS DASHBOARD ---
st.markdown("### 📈 Real-Time Intelligence Analytics")


c1, c2, c3, c4 = st.columns(4)

total_logs = len(df)
critical_count = len(df[df['severity'] == 'Critical']) if total_logs > 0 else 0
most_common = df['threat_type'].mode()[0] if total_logs > 0 else "N/A"

with c1:
    st.markdown(f'<div class="cyber-card"><div class="card-title">Total Intelligence Logs</div><div class="card-value">{total_logs}</div></div>', unsafe_allow_html=True)
with c2:
    st.markdown(f'<div class="cyber-card" style="border-color:#ff4b4b;"><div class="card-title">Critical Escalations</div><div class="card-value" style="color:#ff4b4b;">{critical_count}</div></div>', unsafe_allow_html=True)
with c3:
    st.markdown(f'<div class="cyber-card"><div class="card-title">Primary Threat Vector</div><div class="card-value" style="font-size:1rem;">{most_common}</div></div>', unsafe_allow_html=True)
with c4:
    st.markdown(f'<div class="cyber-card"><div class="card-title">SQL Node Status</div><div class="card-value" style="color:#00ffcc;">CONNECTED</div></div>', unsafe_allow_html=True)

st.divider()

# --- ENTRY AND REGISTRY ---
col_form, col_reg = st.columns([1, 2])

with col_form:
    st.markdown("### 📝 Log New Intelligence")
    with st.form("threat_form", clear_on_submit=True):
        target_input = st.text_input("Target Node / Payload Indicator:")
        type_input = st.selectbox("Classification:", ["Malware Node", "Phishing Link", "Botnet Command", "Vulnerable Port", "Suspicious DNS", "DGA Pattern"])
        severity_input = st.select_slider("Severity Level:", options=["Low", "Medium", "High", "Critical"])
        notes_input = st.text_area("Forensic Analyst Notes:")
        
        if st.form_submit_button("💾 COMMIT TO SQL SERVER", use_container_width=True):
            if target_input:
                conn = sqlite3.connect(DB_FILE)
                cursor = conn.cursor()
                cursor.execute('''INSERT INTO threat_logs (target, threat_type, severity, notes) VALUES (?, ?, ?, ?)''', 
                             (target_input, type_input, severity_input, notes_input))
                conn.commit()
                conn.close()
                st.success("Target successfully committed to encrypted registry.")
                st.rerun()
            else:
                st.error("Target identification field is required.")

with col_reg:
    st.markdown("### 🗃️ Active Threat Registry")
    if not df.empty:
        st.dataframe(df, column_config={
            "id": "ID", 
            "target": "Indicator", 
            "threat_type": "Classification", 
            "severity": "Risk", 
            "notes": "Analyst Observations", 
            "timestamp": "Timestamp (UTC)"
        }, hide_index=True, use_container_width=True)
        
        if st.button("⚠️ PURGE INTELLIGENCE DATABASE", use_container_width=True):
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM threat_logs")
            conn.commit()
            conn.close()
            st.rerun()
    else:
        st.info("The SQL Intelligence Node is currently empty. Awaiting analyst input.")

# --- EXPORT SECTION ---
st.divider()
try:
    with open(DB_FILE, 'rb') as db_file:
        st.download_button(
            label="⬇️ DOWNLOAD RAW SQLITE DATABASE (.DB)", 
            data=db_file, 
            file_name="nexus_threat_intel.db", 
            mime="application/octet-stream",
            use_container_width=True
        )
except FileNotFoundError:
    st.caption("Database file awaiting initialization.")

# Footer
st.markdown("---")
st.caption("NEXUS THREAT INTELLIGENCE SYSTEM // v3.0")