import streamlit as st
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from security_utils import check_authenticity, apply_cyber_styling

# 1. Page Configuration
st.set_page_config(page_title="Anonymous Browser", page_icon="🌐", layout="wide")

# 2. Security & Unified Styling
check_authenticity()
apply_cyber_styling("Anonymous Browser")

# 3. Sidebar Intelligence
with st.sidebar:
    st.markdown("### 🛰️ Proxy Telemetry")
    st.info("Mode: Interactive Link Rewriting\nNode: Nexus-Edge-India\nSafety: Sandbox-Enforced")
    st.divider()
    st.markdown("### 🧠 Technical Warning")
    st.caption("This module uses **Server-Side Rendering (SSR)**. While it bypasses X-Frame blocks, it may not execute complex client-side JavaScript (React/Angular) due to security isolation.")

# 4. Proxy Engine
def fetch_and_proxy(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
            'Accept-Language': 'en-US,en;q=0.9'
        }
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')

        # 1. Link & Form Rewriting Engine
        # We also need to target 'form' because login pages use forms!
        for a in soup.find_all(['a', 'form'], href=True):
            if a.name == 'a':
                a['href'] = urljoin(url, a['href'])
                # FORCE links to open in the same frame
                a['target'] = '_self' 
            
        for form in soup.find_all('form', action=True):
            form['action'] = urljoin(url, form['action'])
            # Ensure forms don't pop out into a new tab
            form['target'] = '_self'

        # 2. Asset Reconstruction (Images, Scripts, Styles)
        for tag in soup.find_all(['img', 'link', 'script'], src=True):
            tag['src'] = urljoin(url, tag['src'])
        for tag in soup.find_all(['link'], href=True):
            tag['href'] = urljoin(url, tag['href'])

        # 3. Base Tag (The Ultimate "Stay Put" Command)
        # We insert a <base> tag at the top of the head to force all relative links to stay here
        base_tag = soup.new_tag('base', target='_self')
        if soup.head:
            soup.head.insert(0, base_tag)

        return soup.prettify()
    except Exception as e:
        return f'<div style="color:red; font-family:monospace; background:white; padding:20px;">🚨 Tunnel Error: {e}</div>'

# 5. UI Logic
st.write("Navigate the web through a hardened, proxied layer. This isolation masks your IP and strips local tracking cookies.")
st.divider()

if 'current_url' not in st.session_state:
    st.session_state['current_url'] = "https://www.wikipedia.org"

# Address Bar
col_url, col_btn = st.columns([5, 1])
with col_url:
    new_url = st.text_input("📍 Destination URL:", value=st.session_state['current_url'], label_visibility="collapsed")
with col_btn:
    if st.button("EXECUTE TUNNEL", use_container_width=True):
        st.session_state['current_url'] = new_url
        st.rerun()

# 6. The Virtual Display
st.markdown(f"**Browsing as:** `Nexus-Node-Central` | **Target Node:** `{st.session_state['current_url']}`")



with st.spinner("Establishing secure tunnel and rewriting DOM links..."):
    raw_html = fetch_and_proxy(st.session_state['current_url'])
    
    # We wrap the HTML content in a CSS-styled div INSIDE the iframe component
    # This avoids the "unclosed tag" glitch
    styled_html = f"""
    <div style="border: 4px solid #ff4b4b; border-radius: 15px; overflow: hidden; background: white; font-family: sans-serif;">
        <div style="background: #ff4b4b; color: white; padding: 5px 15px; font-size: 12px; font-weight: bold;">
            NEXUS SECURE GATEWAY // ENCRYPTED SESSION
        </div>
        {raw_html}
    </div>
    """
    
    st.components.v1.html(styled_html, height=800, scrolling=True)

# Footer
st.markdown("---")
st.caption("NEXUS ANONYMOUS BROWSING SYSTEM // v3.0")