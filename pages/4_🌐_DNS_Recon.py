import streamlit as st
import socket
import requests
from security_utils import check_authenticity, apply_cyber_styling

# 1. Page Configuration
st.set_page_config(page_title="DNS Recon", page_icon="🌐", layout="wide")

# 2. Security & Unified Styling
check_authenticity()
apply_cyber_styling("DNS Recon")

# 3. Sidebar Intelligence
with st.sidebar:
    st.markdown("### 🔍 Scan Parameters")
    st.info("Protocol: DNS-over-HTTPS (DoH)\nAPI: Google DNS Public Resolver")
    st.divider()
    st.markdown("### 🧠 Record Glossary")
    st.caption("**A:** Maps domain to IPv4\n**MX:** Mail routing server\n**NS:** Authoritative nameserver\n**TXT:** Verification & SPF/DKIM data")

# 4. Main UI Logic
st.write("Extract Domain Name System records, SOA metrics, and map server topology for the target domain.")
st.divider()

domain = st.text_input("Enter Target Domain (e.g., github.com):", "github.com")

if st.button("INITIATE DEEP SCAN", use_container_width=True):
    # Clean domain string
    clean_domain = domain.replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0]
    
    if clean_domain:
        with st.spinner(f"Querying global DNS servers for {clean_domain}..."):
            try:
                # 1. Basic A Record
                ip_address = socket.gethostbyname(clean_domain)
                
                # 2. Fetch Advanced Records via Google DNS API
                records = {"MX": [], "NS": [], "TXT": [], "SOA": []}
                for r_type in records.keys():
                    response = requests.get(f"https://dns.google/resolve?name={clean_domain}&type={r_type}").json()
                    if "Answer" in response:
                        records[r_type] = [ans["data"] for ans in response["Answer"]]

                st.success("✅ Topology Mapping Complete.")
                
                # --- CORE TELEMETRY CARDS ---
                st.markdown("### 📡 Core Routing Telemetry")
                c1, c2, c3, c4 = st.columns(4)
                with c1:
                    st.markdown(f'<div class="cyber-card"><div class="card-title">Target Node</div><div class="card-value">{clean_domain}</div></div>', unsafe_allow_html=True)
                with c2:
                    st.markdown(f'<div class="cyber-card"><div class="card-title">Primary IPv4 (A)</div><div class="card-value">{ip_address}</div></div>', unsafe_allow_html=True)
                with c3:
                    st.markdown(f'<div class="cyber-card"><div class="card-title">Mail Servers (MX)</div><div class="card-value">{len(records["MX"])} Found</div></div>', unsafe_allow_html=True)
                with c4:
                    st.markdown(f'<div class="cyber-card"><div class="card-title">Security Records (TXT)</div><div class="card-value">{len(records["TXT"])} Found</div></div>', unsafe_allow_html=True)

                st.divider()
                
                # --- RAW DATA DUMP ---
                st.markdown("### 🗃️ Raw Zone File Extraction")
                
                
                
                col_left, col_right = st.columns(2)
                
                with col_left:
                    st.markdown("**Start of Authority (SOA)**")
                    if records["SOA"]: 
                        st.code(records["SOA"][0], language="text")
                    else: 
                        st.caption("No SOA record detected.")
                    
                    st.markdown("**Nameservers (NS)**")
                    if records["NS"]:
                        for ns in records["NS"]: st.code(ns, language="text")
                    else:
                        st.caption("No NS records found.")
                        
                with col_right:
                    st.markdown("**Mail Exchange (MX)**")
                    if records["MX"]:
                        for mx in records["MX"]: st.code(mx, language="text")
                    else:
                        st.caption("No MX records found.")
                    
                    st.markdown("**Security & Verification (TXT)**")
                    if records["TXT"]:
                        for txt in records["TXT"]: st.code(txt, language="text")
                    else:
                        st.caption("No TXT records found.")

                st.info("💡 **Operational Insight:** Multiple NS records indicate high availability. TXT records containing 'v=spf1' are critical for email spoofing prevention.")

            except socket.gaierror:
                st.error("🚨 Scan failed. Domain not found or target server is offline.")

# Footer
st.markdown("---")
st.caption("NEXUS DNS RECONNAISSANCE SYSTEM // v3.0")