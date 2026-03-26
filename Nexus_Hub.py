import streamlit as st
import sqlite3
import hashlib
import os

# 1. Page Configuration
st.set_page_config(page_title="NEXUS COMMAND", page_icon="👁️", layout="wide")

# 2. Constants & Database Setup
SESSION_FILE = ".nexus_session"
USER_DB = "auth_system.db"
LOGO_PATH = "logo.png"

# --- CUSTOM CYBER CSS ---
st.markdown("""
<style>

    /* 1. Global Dark Theme */
    /* Stop the sidebar buttons from ever rendering space */
    [data-testid="stSidebarHeader"], 
    [data-testid="stSidebarCollapseButton"],
    button[aria-label="Close sidebar"],
    button[aria-label="Open sidebar"] {
        display: none !important;
        height: 0px !important;
        margin: 0px !important;
        padding: 0px !important;
    }

    /* Force the content container to start at 0px immediately */
    [data-testid="stSidebarContent"] {
        padding-top: 20px !important;
    }

    /* Ensure the nav list doesn't jump */
    [data-testid="stSidebarNav"] {
        padding-top: 0px !important;
    }

    [data-testid="stSidebarNavHeader"] {
        margin-top: 0px !important;
        padding-top: 15px !important;
    }


    .cyber-header {
        background: linear-gradient(90deg, #240b36 0%, #c31432 100%);
        padding: 20px; border-radius: 10px; border-bottom: 2px solid #ff4b4b;
        text-align: center; margin-bottom: 30px; box-shadow: 0 0 20px rgba(255, 75, 75, 0.3);
    }

    .logo-text {
        font-family: 'Courier New', monospace; font-size: 3rem; font-weight: bold;
        letter-spacing: 5px; color: #ffffff; text-shadow: 2px 2px #ff4b4b, -2px -2px #00ffcc;
    }

    .module-card {
        background-color: #1a1a2e; border-left: 5px solid #ff4b4b;
        padding: 15px; margin-bottom: 10px; border-radius: 5px; transition: 0.3s;
    }

    .module-card:hover {
        background-color: #16213e; border-left: 5px solid #00ffcc; transform: translateX(10px);
    }

    .cyber-footer {
        margin-top: 50px; padding: 20px; text-align: center; border-top: 1px solid #333;
        font-size: 0.8rem; color: #666;
    }
</style>
""", unsafe_allow_html=True)

# --- LOGIC FUNCTIONS ---
def init_user_db():
    conn = sqlite3.connect(USER_DB)
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT NOT NULL)')
    conn.commit()
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

init_user_db()

# --- SESSION RECOVERY ---
if 'authenticated' not in st.session_state:
    if os.path.exists(SESSION_FILE):
        with open(SESSION_FILE, "r") as f:
            saved_user = f.read().strip()
            if saved_user:
                st.session_state['authenticated'] = True
                st.session_state['username'] = saved_user
    else:
        st.session_state['authenticated'] = False

# Header Section
st.markdown('<div class="cyber-header"><div class="logo-text">NEXUS // HUB</div><div style="color: #00ffcc; font-family: monospace;">CENTRAL OSINT COMMAND & CONTROL v3.0</div></div>', unsafe_allow_html=True)

# --- SIDEBAR LOGO INJECTION ---

if not st.session_state['authenticated']:
    st.markdown("<style>[data-testid='stSidebarNav'] ul li:nth-child(n+2) {display: none;}</style>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 1.5, 1])
    with col2:
        tab1, tab2 = st.tabs(["🔑 ACCESS TERMINAL", "📝 RECRUIT OPERATOR"])
        with tab1:
            user = st.text_input("Operator ID:")
            pw = st.text_input("Access Key:", type="password")
            remember = st.checkbox("Keep Connection Alive")
            if st.button("INITIATE LOGIN", use_container_width=True):
                conn = sqlite3.connect(USER_DB)
                cursor = conn.cursor()
                cursor.execute("SELECT password FROM users WHERE username=?", (user,))
                result = cursor.fetchone()
                conn.close()
                if result and result[0] == hash_password(pw):
                    st.session_state['authenticated'] = True
                    st.session_state['username'] = user
                    if remember:
                        with open(SESSION_FILE, "w") as f: f.write(user)
                    st.rerun()
                else: st.error("🚨 INVALID CREDENTIALS.")
        with tab2:
            new_user = st.text_input("New ID:")
            new_pw = st.text_input("New Key:", type="password")
            if st.button("REGISTER", use_container_width=True):
                if new_user and new_pw:
                    try:
                        conn = sqlite3.connect(USER_DB)
                        cursor = conn.cursor()
                        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (new_user, hash_password(new_pw)))
                        conn.commit()
                        conn.close()
                        st.success("Registration complete.")
                    except: st.error("ID Taken.")
else:
    with st.sidebar:
        st.markdown(f"### 👤 ACTIVE: `{st.session_state['username']}`")
        if st.button("🔴 EMERGENCY LOGOUT"):
            st.session_state['authenticated'] = False
            if os.path.exists(SESSION_FILE): os.remove(SESSION_FILE)
            st.rerun()

    col_left, col_right = st.columns([1.6, 1])
    with col_left:
        st.markdown("### 🛰️ Global Threat Intelligence (Live)")
        st.components.v1.iframe("https://cybermap.kaspersky.com/en/widget/dynamic/dark", height=450)
        st.info("**ENCRYPTION:** AES-256 Enabled | **THREAT LEVEL:** High | **VPN TUNNEL:** Secure")
        st.markdown("---")
        st.write("Centralized OSINT intelligence is logged to the persistent SQL database.")

    with col_right:
        st.markdown("### 🛠️ Active Deployment Modules")
        modules = [
            ("📍 IP Tracker", "Geospatial node mapping & ISP telemetry."),
            ("💻 MAC Recon", "OUI decoding & Device Class detection."),
            ("🛡️ Password Auditor", "Shannon entropy & brute-force simulation."),
            ("🌐 DNS Recon", "Subdomain mapping & zone extraction."),
            ("🔌 Vulnerability Scanner", "Port audit, banner grabbing, and CVE lookup."),
            ("🕷️ Phishing Analyzer", "DGA detection & heuristic analysis."),
            ("🧮 Subnet Calc", "IPv4 architecture & CIDR boundaries."),
            ("🗄️ Threat DB", "Persistent SQL intelligence logging."),
            ("🚨 Traffic NIDS", "Z-Score statistical anomaly detection."),
            ("🌐 Anonymous Browser", "Interactive SSR sandboxed navigation."),
            ("🔐 Crypto Vault", "AES-128 Encryption & File Sealing."),
            ("🛰️ Satellite Tracker", "Track satellites in real-time."),
            ("📧 Breach Monitor", "Deep web leak & credential audit."),
            ("🌐 Site Checker", "Real-time URL reputation & scam analysis."),
            ("🛡️ File Integrity Monitor", "SHA-256 recursive baseline directory hashing."),
            ("📝 WAF Log Analyzer", "Access log heuristics for SQLi & XSS detection.")
        ]
        for name, desc in modules:
            st.markdown(f'<div class="module-card"><span style="color:#00ffcc; font-weight:bold;">{name}</span><br><span style="font-size:0.85rem; color:#aaa;">{desc}</span></div>', unsafe_allow_html=True)

st.markdown('<div class="cyber-footer">NEXUS COMMAND SYSTEM | INNOVX 2026 OFFICIAL SUBMISSION</div>', unsafe_allow_html=True)