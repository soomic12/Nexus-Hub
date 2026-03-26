import streamlit as st
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from security_utils import check_authenticity, apply_cyber_styling

# 1. Page Configuration
st.set_page_config(page_title="Anonymous Browser", page_icon="🌐", layout="wide")

# 2. Security & Unified Styling
check_authenticity()
apply_cyber_styling("Anonymous Browser")

# --- INITIALIZE SESSION STATE FOR NAVIGATION ---
if 'history' not in st.session_state:
    st.session_state['history'] = ["https://www.wikipedia.org"]
if 'history_index' not in st.session_state:
    st.session_state['history_index'] = 0

# 3. Sidebar Intelligence
with st.sidebar:
    st.markdown("### 🛰️ Proxy Telemetry")
    st.info("Mode: Interactive Link Rewriting\nNode: Nexus-Edge-India")
    st.divider()
    st.markdown("### 🧠 Technical Warning")
    st.caption("SSR Mode: Navigation history is tracked server-side. JavaScript-based redirects might not be captured.")

# 4. Proxy Engine
def fetch_and_proxy(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'}
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Link & Form Rewriting
        for a in soup.find_all(['a', 'form']):
            if a.name == 'a' and a.has_attr('href'):
                a['href'] = urljoin(url, a['href'])
                a['target'] = '_self' 
            if a.name == 'form' and a.has_attr('action'):
                a['action'] = urljoin(url, a['action'])
                a['target'] = '_self'

        # Asset Reconstruction
        for tag in soup.find_all(['img', 'link', 'script'], src=True):
            tag['src'] = urljoin(url, tag['src'])
        
        # Inject Base Tag
        if soup.head:
            base_tag = soup.new_tag('base', target='_self')
            soup.head.insert(0, base_tag)

        return soup.prettify()
    except Exception as e:
        return f'<div style="color:red; font-family:monospace;">🚨 Tunnel Error: {e}</div>'

# 5. UI Logic
st.write("Navigate the web through a hardened, proxied layer.")

# --- NAVIGATION CONTROLS ---
col_back, col_fwd, col_url, col_btn = st.columns([0.5, 0.5, 4, 1])

with col_back:
    if st.button("⬅️", use_container_width=True, disabled=st.session_state['history_index'] == 0):
        st.session_state['history_index'] -= 1
        st.rerun()

with col_fwd:
    if st.button("➡️", use_container_width=True, disabled=st.session_state['history_index'] >= len(st.session_state['history']) - 1):
        st.session_state['history_index'] += 1
        st.rerun()

current_url = st.session_state['history'][st.session_state['history_index']]

with col_url:
    new_url = st.text_input("📍 Destination URL:", value=current_url, label_visibility="collapsed")

with col_btn:
    if st.button("EXECUTE TUNNEL", use_container_width=True):
        if new_url != current_url:
            # If we were in the middle of history and type a new URL, clear forward history
            st.session_state['history'] = st.session_state['history'][:st.session_state['history_index'] + 1]
            st.session_state['history'].append(new_url)
            st.session_state['history_index'] += 1
            st.rerun()

# 6. The Virtual Display
st.markdown(f"**Browsing History:** `{st.session_state['history_index'] + 1} / {len(st.session_state['history'])}` | **Node:** `{current_url}`")

with st.spinner("Establishing secure tunnel..."):
    raw_html = fetch_and_proxy(current_url)
    st.components.v1.html(raw_html, height=800, scrolling=True)

# Footer
st.markdown("---")
st.caption("NEXUS ANONYMOUS BROWSING SYSTEM // v3.0")