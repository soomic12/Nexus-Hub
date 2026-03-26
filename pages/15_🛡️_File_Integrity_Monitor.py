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

# --- DATABASE INITIALIZATION (Persistent Vault) ---
def init_fim_db():
    conn = sqlite3.connect('auth_system.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS fim_baselines 
                 (target_dir TEXT PRIMARY KEY, timestamp TEXT, hash_data TEXT)''')
    conn.commit()
    conn.close()

init_fim_db()

# --- PERSISTENT SESSION STATE ---
if 'scan_active' not in st.session_state:
    st.session_state['scan_active'] = False
if 'current_hashes' not in st.session_state:
    st.session_state['current_hashes'] = {}
if 'scan_target' not in st.session_state:
    st.session_state['scan_target'] = ""

# 3. Sidebar Intelligence & Red-Team Simulator
with st.sidebar:
    st.markdown("### 🛡️ Defense Engine")
    st.info("Algorithm: SHA-256\nStorage: SQLite Vault\nEnvironment: Streamlit Cloud (Ephemeral)")
    
    st.divider()
    st.markdown("### ☣️ Red-Team Simulator")
    st.caption("Inject a real file into the cloud server to test detection.")
    
    if st.button("⚠️ SIMULATE FILE INJECTION", use_container_width=True):
        # This physically creates a file on the Streamlit Cloud disk
        with open("unauthorized_backdoor.txt", "w") as f:
            f.write(f"--- MALICIOUS PAYLOAD DETECTED ---\nOrigin: Simulated Breach\nTimestamp: {datetime.now()}\nStatus: Active Persistence")
        st.sidebar.warning("Backdoor 'unauthorized_backdoor.txt' injected into root!")

# --- Core FIM Functions ---
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
            # Skip DB files to avoid locking issues during scans
            if file.endswith(".db"): continue 
            filepath = os.path.join(root, file)
            f_hash = get_file_hash(filepath)
            if f_hash:
                file_hashes[filepath] = f_hash
    return file_hashes, len(file_hashes)

def save_baseline_db(target_dir, hash_dict):
    conn = sqlite3.connect('auth_system.db')
    c = conn.cursor()
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
    # On Streamlit Cloud, this defaults to /mount/src/nexus-hub
    target_path = st.text_input("Target Directory:", value=os.getcwd())

with c_base:
    st.markdown("<div style='margin-top:28px'></div>", unsafe_allow_html=True)
    if st.button("CALCULATE BASELINE", use_container_width=True):
        # 1. AUTO-CLEAN: If the simulation file exists, delete it immediately
        if os.path.exists("unauthorized_backdoor.txt"):
            try:
                os.remove("unauthorized_backdoor.txt")
                st.toast("🧹 Auto-Clean: Backdoor file removed from baseline.")
            except:
                st.error("🚨 Clean-Room Error: Could not remove backdoor file.")
        
        # 2. PROCEED TO HASHING
        with st.spinner("Establishing secure baseline..."):
            res, count = scan_directory(target_path)
            if res:
                save_baseline_db(target_path, res)
                st.success(f"✅ Baseline Secure: {count} files mapped.")
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
    
    # --- FORENSIC EVIDENCE VIEWER (PROVES THE FILE IS REAL) ---
    if st.session_state['scan_active']:
        target = st.session_state['scan_target']
        original = load_baseline_db(target)
        current = st.session_state['current_hashes']
        
        # --- FORENSIC EVIDENCE VIEWER (Now inside the scan logic) ---
        if os.path.exists("unauthorized_backdoor.txt"):
            st.warning("⚠️ **EVIDENCE LOCATED:** `unauthorized_backdoor.txt` detected on disk.")
            with open("unauthorized_backdoor.txt", "r") as f:
                st.code(f.read(), language="text")
        
        if original:
            new = [f for f in current if f not in original]
            new = [f for f in current if f not in original]
            deleted = [f for f in original if f not in current]
            modified = [f for f, h in current.items() if f in original and original[f] != h]
            
            if not new and not deleted and not modified:
                st.success("✅ SYSTEM SECURE: Integrity Verified.")
            else:
                st.error("🚨 INTEGRITY BREACH: Unauthorized modifications found.")
                
                ca, cb = st.columns(2)
                with ca:
                    if st.button("ACKNOWLEDGE & UPDATE", type="primary", use_container_width=True):
                        save_baseline_db(target, current)
                        st.session_state['scan_active'] = False
                        st.rerun()
                with cb:
                    if st.button("🧨 PURGE IDENTIFIED THREATS"):
                        if os.path.exists("unauthorized_backdoor.txt"):
                            os.remove("unauthorized_backdoor.txt")
                        st.session_state['scan_active'] = False # This hides the audit results
                        st.rerun()

                st.write(f"Modified: {len(modified)} | Deleted: {len(deleted)} | New: {len(new)}")
                if modified: st.error(f"**Modified:** {', '.join([os.path.basename(x) for x in modified])}")
                if new: st.info(f"**New Files:** {', '.join([os.path.basename(x) for x in new])}")
    else:
        st.info("Execute scan to begin forensic analysis.")

# Footer
st.markdown("---")
st.caption("NEXUS FILE INTEGRITY MONITOR // v4.0")