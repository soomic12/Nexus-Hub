import streamlit as st
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlencode, parse_qs
from security_utils import check_authenticity, apply_cyber_styling

# 1. Page Configuration
st.set_page_config(page_title="Anonymous Browser", page_icon="🌐", layout="wide")
check_authenticity()
apply_cyber_styling("Anonymous Browser")

# --- NAVIGATION ENGINE ---
# We use query parameters so the URL changes in the REAL browser too
query_params = st.query_params
current_url = query_params.get("url", "https://www.wikipedia.org")

if 'history' not in st.session_state:
    st.session_state['history'] = [current_url]
if 'history_index' not in st.session_state:
    st.session_state['history_index'] = 0

# Function to update history and move forward
def navigate_to(new_url):
    if new_url != st.session_state['history'][st.session_state['history_index']]:
        # Clear forward history if we are in the middle of the stack
        st.session_state['history'] = st.session_state['history'][:st.session_state['history_index'] + 1]
        st.session_state['history'].append(new_url)
        st.session_state['history_index'] += 1
        st.query_params["url"] = new_url
        st.rerun()

# 2. Proxy Engine
def fetch_and_proxy(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'}
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')

        # REWRITING LINKS TO POINT BACK TO STREAMLIT
        # This is the "Magic": it rewrites <a> tags to reload the app with the new URL
        for a in soup.find_all('a', href=True):
            original_href = urljoin(url, a['href'])
            # We point the link back to our own Streamlit app with a URL parameter
            a['href'] = f"?url={original_href}"
            a['target'] = '_self' 

        # Asset Reconstruction (Images/CSS) - Keep these pointing to original source
        for tag in soup.find_all(['img', 'link', 'script'], src=True):
            tag['src'] = urljoin(url, tag['src'])
        for tag in soup.find_all(['link'], href=True):
            if not tag.has_attr('target'): # Don't overwrite our navigation
                tag['href'] = urljoin(url, tag['href'])

        return soup.prettify()
    except Exception as e:
        return f'<div style="color:red; font-family:monospace;">🚨 Tunnel Error: {e}</div>'

# 3. UI Layout
st.write("Full-Stack Anonymous Proxy with Navigation History.")

# --- NAVIGATION BAR ---
col_back, col_fwd, col_url, col_btn = st.columns([0.5, 0.5, 4, 1])

with col_back:
    if st.button("⬅️", use_container_width=True, disabled=st.session_state['history_index'] == 0):
        st.session_state['history_index'] -= 1
        new_url = st.session_state['history'][st.session_state['history_index']]
        st.query_params["url"] = new_url
        st.rerun()

with col_fwd:
    if st.button("➡️", use_container_width=True, disabled=st.session_state['history_index'] >= len(st.session_state['history']) - 1):
        st.session_state['history_index'] += 1
        new_url = st.session_state['history'][st.session_state['history_index']]
        st.query_params["url"] = new_url
        st.rerun()

with col_url:
    input_url = st.text_input("📍 URL:", value=current_url, label_visibility="collapsed")

with col_btn:
    if st.button("GO", use_container_width=True):
        navigate_to(input_url)

# 4. Display
st.caption(f"Step {st.session_state['history_index'] + 1} of {len(st.session_state['history'])} | Current: {current_url}")

with st.spinner("Rendering..."):
    html_content = fetch_and_proxy(current_url)
    st.components.v1.html(html_content, height=800, scrolling=True)

st.markdown("---")
st.caption("NEXUS ANONYMOUS BROWSING SYSTEM // v3.0")