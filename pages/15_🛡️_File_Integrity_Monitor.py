import streamlit as st
import os
import hashlib
import sqlite3
import time
from datetime import datetime
from security_utils import check_authenticity, apply_cyber_styling

# 1. Page Configuration
st.set_page_config(page_title="File Integrity Monitor", page_icon="🛡️", layout="wide")

# 2. Security & Unified Styling
check_authenticity()
apply_cyber_styling("File Integrity Monitor (FIM)")

# --- DATABASE INITIALIZATION ---
def init_fim_db():
    conn = sqlite3.connect('auth_system.db')
    c = conn.cursor()
    # Table to store directory baselines
    c.execute('''CREATE TABLE IF NOT EXISTS fim_baselines 
                 (target_dir TEXT PRIMARY KEY, timestamp TEXT, hash_data TEXT)''')
    conn.commit()
    conn.close()

init_fim_db()

# --- PERSISTENT STATE ---
if 'scan_active' not in st.session_state:
    st.session_state['scan_active'] = False
if 'current_hashes' not in st.session_state:
    st.session_state['current_hashes'] = {}
if 'scan_target' not in st.session_state:
    st.session_state['scan_target'] = ""

# 3. Sidebar Intelligence & Simulator
with st.sidebar:
    st.markdown("### 🛡️ Defense Engine")
    st.info("Algorithm: SHA-256\nStorage: SQLite (Persistent)\nScope: Recursive Hash Audit")
    
    st.divider()
    st.markdown("### ☣️ Red-Team Simulator")
    st.caption("Use this to simulate a breach during your presentation.")
    
    if st.button("⚠️ SIMULATE FILE INJECTION", use_container_width=True):
        # Creates a file in the current working directory
        with open("unauthorized_backdoor.txt", "w") as f:
            f.write(f"Malicious payload injected at {datetime.now()}")
        st.sidebar.warning("Malicious file injected!")

# --- Core FIM Functions (SQLite Backend) ---
def get_file_hash(filepath):
    hasher = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except:
        return None

def scan_directory(directory_path):
    file_hashes = {}
    if not os.path.isdir(directory_path):
        return None, 0
    for root, _, files in os.walk(directory_path):
        for file in files:
            # Skip the database file itself to avoid self-referencing errors
            if file.endswith(".db"): continue 
            filepath = os.path.join(root, file)
            f_hash = get_file_hash(filepath)
            if f_hash:
                file_hashes[filepath] = f_hash
    return file_hashes, len(file_hashes)

def save_baseline_db(target_dir, hash_dict):
    conn = sqlite3.connect('auth_system.db')
    c = conn.cursor()
    # Convert dict to string for storage
    hash_string = str(hash_dict)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT OR REPLACE INTO fim_baselines VALUES (?, ?, ?)", 
              (target_dir, timestamp, hash_string))
    conn.commit()
    conn.close()

def load_baseline_db(target_dir):
    conn = sqlite3.connect('auth_system.db')
    c = conn.cursor()
    c.execute("SELECT hash_data FROM fim_baselines WHERE target_dir=?", (target_dir,))
    result = c.fetchone()
    conn.close()
    if result:
        # Evaluate string back into dictionary
        return eval(result[0])
    return None

def delete_baseline_db(target_dir):
    conn = sqlite3.connect('auth_system.db')
    c = conn.cursor()
    c.execute("DELETE FROM fim_baselines WHERE target_dir=?", (target_dir,))
    conn.commit()
    conn.close()
    st.session_state['scan_active'] = False

# 4. Main UI Logic
st.title("🛡️ File Integrity Monitor")
st.write("Monitor system integrity using SHA-256 cryptographic handshakes stored in the NEXUS Vault.")
st.divider()

# --- COMMAND BAR ---
c_input, c_base, c_scan = st.columns([2, 1, 1])
with c_input:
    target_path = st.text_input("Target Directory:", value=os.getcwd())
with c_base:
    st.markdown("<div style='margin-top:28px'></div>", unsafe_allow_html=True)
    if st.button("CALCULATE BASELINE", use_container_width=True):
        res, count = scan_directory(target_path)
        if res:
            save_baseline_db(target_path, res)
            st.success(f"Baseline Secure: {count} files mapped.")
            time.sleep(1)
            st.rerun()
with c_scan:
    st.markdown("<div style='margin-top:28px'></div>", unsafe_allow_html=True)
    if st.button("START DEEP SCAN NOW", type="primary", use_container_width=True):
        baseline = load_baseline_db(target_path)
        if not baseline:
            st.error("No baseline found in SQLite Vault.")
        else:
            current, _ = scan_directory(target_path)
            st.session_state['current_hashes'] = current
            st.session_state['scan_target'] = target_path
            st.session_state['scan_active'] = True

st.divider()

# --- DISPLAY LOGIC ---
col_zones, col_audit = st.columns([1, 1.2])

with col_zones:
    st.markdown("### 📋 Monitored Zones")
    conn = sqlite3.connect('auth_system.db')
    c = conn.cursor()
    c.execute("SELECT target_dir, timestamp FROM fim_baselines")
    zones = c.fetchall()
    conn.close()
    
    if zones:
        for z_path, z_time in zones:
            with st.container(border=True):
                st.markdown(f"**Zone:** `{z_path}`")
                st.caption(f"Baseline: {z_time}")
                if st.button("Purge Baseline", key=f"del_{z_path}", use_container_width=True):
                    delete_baseline_db(z_path)
                    st.rerun()
    else:
        st.info("Vault empty. Establish a baseline.")

with col_audit:
    st.markdown("### 🔍 Integrity Audit")
    if st.session_state['scan_active']:
        target = st.session_state['scan_target']
        original = load_baseline_db(target)
        current = st.session_state['current_hashes']
        
        if original:
            new = [f for f in current if f not in original]
            deleted = [f for f in original if f not in current]
            modified = [f for f, h in current.items() if f in original and original[f] != h]
            
            if not new and not deleted and not modified:
                st.success("✅ SYSTEM SECURE: All signatures match.")
            else:
                st.error("🚨 INTEGRITY BREACH: Unauthorized changes detected.")
                st.write(f"Modified: {len(modified)} | Deleted: {len(deleted)} | New: {len(new)}")
                
                if modified: st.error(f"**Modified:** {', '.join([os.path.basename(x) for x in modified])}")
                if new: st.info(f"**New Files:** {', '.join([os.path.basename(x) for x in new])}")
                
                if st.button("ACKNOWLEDGE & UPDATE", type="primary", use_container_width=True):
                    save_baseline_db(target, current)
                    st.session_state['scan_active'] = False
                    st.rerun()
    else:
        st.info("Execute scan to begin forensic analysis.")

# Footer
st.markdown("---")
st.caption("NEXUS FILE INTEGRITY MONITOR // v4.0")