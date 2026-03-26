import streamlit as st
import os
import hashlib
import json
import time
from datetime import datetime
from security_utils import check_authenticity, apply_cyber_styling

# 1. Page Configuration
st.set_page_config(page_title="File Integrity Monitor", page_icon="🛡️", layout="wide")

# 2. Security & Unified Styling
check_authenticity()
apply_cyber_styling("File Integrity Monitor (FIM)")

# Constants
FIM_STATE_FILE = "fim_baselines.json"

# --- PERSISTENT STATE INITIALIZATION ---
if 'scan_active' not in st.session_state:
    st.session_state['scan_active'] = False
if 'current_hashes' not in st.session_state:
    st.session_state['current_hashes'] = {}
if 'scan_target' not in st.session_state:
    st.session_state['scan_target'] = ""

# 3. Sidebar Intelligence
with st.sidebar:
    st.markdown("### 🛡️ Defense Engine")
    st.info("Algorithm: SHA-256\nMode: Recursive Directory Scanning\nStorage: Local Baseline JSON")
    st.divider()
    st.markdown("### 🧠 Forensic Insight")
    st.caption("A File Integrity Monitor (FIM) is the last line of defense against Ransomware and stealthy rootkits. By establishing a cryptographic baseline, any unauthorized modification (even a single byte change) will trigger a critical alert.")

# --- Core FIM Functions ---
def get_file_hash(filepath):
    hasher = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None

def scan_directory(directory_path):
    file_hashes = {}
    total_files = 0
    if not os.path.isdir(directory_path):
        return None, 0
    for root, _, files in os.walk(directory_path):
        for file in files:
            filepath = os.path.join(root, file)
            file_hash = get_file_hash(filepath)
            if file_hash:
                file_hashes[filepath] = file_hash
                total_files += 1
    return file_hashes, total_files

def save_baseline(baseline_data, target_dir):
    state = {}
    if os.path.exists(FIM_STATE_FILE):
        with open(FIM_STATE_FILE, 'r') as f:
            try: state = json.load(f)
            except: state = {}
    
    state[target_dir] = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'hashes': baseline_data
    }
    with open(FIM_STATE_FILE, 'w') as f:
        json.dump(state, f, indent=4)

def load_baseline(target_dir):
    if os.path.exists(FIM_STATE_FILE):
        with open(FIM_STATE_FILE, 'r') as f:
            try: return json.load(f).get(target_dir)
            except: return None
    return None

def get_all_baselines():
    if os.path.exists(FIM_STATE_FILE):
        with open(FIM_STATE_FILE, 'r') as f:
            try: return json.load(f)
            except: return {}
    return {}

def delete_baseline(target_dir):
    if os.path.exists(FIM_STATE_FILE):
        with open(FIM_STATE_FILE, 'r') as f:
            try: state = json.load(f)
            except: state = {}
        if target_dir in state:
            del state[target_dir]
            with open(FIM_STATE_FILE, 'w') as f:
                json.dump(state, f, indent=4)

# 4. Main UI Logic
st.title("🛡️ File Integrity Monitor")
st.write("Establish cryptographic baselines for critical directories and monitor them for unauthorized modifications.")
st.divider()

st.markdown("### 🎯 Target Assignment")

# --- THE UNIFIED COMMAND BAR ---
c_input, c_base, c_scan = st.columns([2, 1, 1])

with c_input:
    target_dir = st.text_input("Target Directory Path (Absolute):", value=os.getcwd())

with c_base:
    st.markdown("<div style='margin-top: 28px;'></div>", unsafe_allow_html=True)
    calc_btn = st.button("CALCULATE BASELINE", use_container_width=True)

with c_scan:
    st.markdown("<div style='margin-top: 28px;'></div>", unsafe_allow_html=True)
    scan_btn = st.button("START DEEP SCAN NOW", use_container_width=True, type="primary")

st.divider()

# --- TOP BAR LOGIC CONTROLLERS ---
if calc_btn:
    if target_dir and os.path.isdir(target_dir):
        with st.spinner(f"Recursively hashing files in {target_dir}..."):
            hashes_dict, file_count = scan_directory(target_dir)
            if hashes_dict is not None:
                save_baseline(hashes_dict, target_dir)
                st.session_state['scan_active'] = False # Reset scan view
                st.success(f"✅ Baseline established! Successfully calculated SHA-256 hashes for {file_count} files.")
    else:
        st.error("🚨 Invalid Directory Path.")

if scan_btn:
    if target_dir and os.path.isdir(target_dir):
        baseline_data = load_baseline(target_dir)
        if not baseline_data:
            st.error(f"🚨 No baseline found for `{target_dir}`. Please click **Calculate Baseline** first.")
        else:
            with st.spinner("Executing deep cryptographic scan..."):
                current_hashes, _ = scan_directory(target_dir)
                if current_hashes is not None:
                    st.session_state['current_hashes'] = current_hashes
                    st.session_state['scan_target'] = target_dir
                    st.session_state['scan_active'] = True
                else:
                    st.error("🚨 Directory is inaccessible!")
    else:
        st.error("🚨 Invalid Directory Path.")


# --- TWO-COLUMN RESULTS DISPLAY ---
col1, col2 = st.columns([1, 1.2])

with col1:
    st.markdown("### 📋 Active Monitored Zones")
    saved_baselines = get_all_baselines()
    
    if saved_baselines:
        for b_dir, b_data in saved_baselines.items():
            num_files = len(b_data.get('hashes', {}))
            timestamp = b_data.get('timestamp', 'Unknown')
            
            with st.container(border=True):
                st.markdown(f"**Zone:** `{b_dir}`")
                st.caption(f"Last Baseline: {timestamp} | Files: {num_files}")
                if st.button("Delete Baseline", key=f"del_{b_dir}", use_container_width=True):
                    delete_baseline(b_dir)
                    st.rerun()
    else:
        st.info("No active baselines found. Establish a baseline to begin monitoring.")

with col2:
    st.markdown("### 🔍 Integrity Audit Run")
    
    if st.session_state['scan_active']:
        audit_target = st.session_state['scan_target']
        baseline_data = load_baseline(audit_target)
        original_hashes = baseline_data.get('hashes', {})
        current_hashes = st.session_state['current_hashes']
        
        new_files = []
        deleted_files = []
        modified_files = []
        
        # Compare logic
        for filepath, current_hash in current_hashes.items():
            if filepath not in original_hashes:
                new_files.append(filepath)
            elif original_hashes[filepath] != current_hash:
                modified_files.append(filepath)
                
        for filepath in original_hashes:
            if filepath not in current_hashes:
                deleted_files.append(filepath)

        # --- RENDER RESULTS ---
        st.markdown("### 📊 Audit Results")
        
        if not new_files and not deleted_files and not modified_files:
            st.success("✅ SYSTEM SECURE: Cryptographic signatures match the baseline perfectly.")
        else:
            st.error("🚨 BREACH DETECTED: System integrity compromised.")
            
            r1, r2, r3 = st.columns(3)
            with r1:
                st.markdown(f'''<div style="background-color: #1e122b; border: 1px solid #ff4b4b; border-radius: 8px; padding: 15px; text-align: center;">
                    <div style="color: #e0d4f5; font-size: 0.8rem;"><b>Modified</b></div>
                    <div style="color: #ff4b4b; font-size: 1.5rem; font-weight: bold;">{len(modified_files)}</div>
                </div>''', unsafe_allow_html=True)
            with r2:
                st.markdown(f'''<div style="background-color: #1e122b; border: 1px solid #ffa500; border-radius: 8px; padding: 15px; text-align: center;">
                    <div style="color: #e0d4f5; font-size: 0.8rem;"><b>Deleted</b></div>
                    <div style="color: #ffa500; font-size: 1.5rem; font-weight: bold;">{len(deleted_files)}</div>
                </div>''', unsafe_allow_html=True)
            with r3:
                st.markdown(f'''<div style="background-color: #1e122b; border: 1px solid #00ffcc; border-radius: 8px; padding: 15px; text-align: center;">
                    <div style="color: #e0d4f5; font-size: 0.8rem;"><b>New Files</b></div>
                    <div style="color: #00ffcc; font-size: 1.5rem; font-weight: bold;">{len(new_files)}</div>
                </div>''', unsafe_allow_html=True)
            
            st.write("") 
            
            if modified_files:
                st.error(f"**MODIFIED ({len(modified_files)}):**\n" + "\n".join([f"- `{os.path.basename(f)}`" for f in modified_files]))
            if deleted_files:
                st.warning(f"**DELETED ({len(deleted_files)}):**\n" + "\n".join([f"- `{os.path.basename(f)}`" for f in deleted_files]))
            if new_files:
                st.info(f"**NEW ({len(new_files)}):**\n" + "\n".join([f"- `{os.path.basename(f)}`" for f in new_files]))
            
            st.divider()
            
            # --- THE DEDICATED ACKNOWLEDGE BUTTON ---
            if st.button("ACKNOWLEDGE & UPDATE BASELINE", type="primary", use_container_width=True):
                save_baseline(current_hashes, audit_target)
                st.session_state['scan_active'] = False
                st.success("✅ Baseline updated! The new file signatures have been stored.")
                time.sleep(1.5)
                st.rerun()

    else:
        st.info("Assign a Target Directory above and execute a Deep Scan to analyze system integrity.")

# Footer
st.markdown("---")
st.caption("NEXUS FILE INTEGRITY MONITOR // v4.0")