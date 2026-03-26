import streamlit as st
import ipaddress
from security_utils import check_authenticity, apply_cyber_styling

# 1. Page Configuration
st.set_page_config(page_title="Subnet Calculator", page_icon="🧮", layout="wide")

# 2. Security & Unified Styling
check_authenticity()
apply_cyber_styling("Subnet Calculator")

# 3. Sidebar Intelligence
with st.sidebar:
    st.markdown("### 🔍 Network Logic")
    st.info("Standard: IPv4 (RFC 791)\nMath: Bitwise AND Operations")
    st.divider()
    st.markdown("### 🧠 CIDR Table")
    st.caption("**/24:** 256 IPs (Class C)\n**/16:** 65,536 IPs (Class B)\n**/8:** 16.7M IPs (Class A)")

# 4. Main UI Logic
st.write("Calculate network boundaries, broadcast addresses, and usable host ranges for enterprise IT planning.")
st.divider()

col_input, col_cidr = st.columns([2, 1])
with col_input:
    ip_input = st.text_input("Enter Target IP Address (e.g., 192.168.1.0):", "192.168.1.0")
with col_cidr:
    cidr_input = st.number_input("CIDR Notation (0-32):", min_value=0, max_value=32, value=24)

if st.button("CALCULATE NETWORK ARCHITECTURE", use_container_width=True):
    try:
        network_string = f"{ip_input}/{cidr_input}"
        network = ipaddress.IPv4Network(network_string, strict=False)
        
        st.success("✅ Network Topology Calculated.")
        
        # --- CORE METRIC CARDS ---
        st.markdown("### 📊 Core Network Metrics")
        
        r1c1, r1c2 = st.columns(2)
        with r1c1:
            st.markdown(f'<div class="cyber-card"><div class="card-title">Network ID</div><div class="card-value">{network.network_address}</div></div>', unsafe_allow_html=True)
        with r1c2:
            st.markdown(f'<div class="cyber-card"><div class="card-title">Broadcast Address</div><div class="card-value">{network.broadcast_address}</div></div>', unsafe_allow_html=True)
            
        r2c1, r2c2 = st.columns(2)
        with r2c1:
            st.markdown(f'<div class="cyber-card"><div class="card-title">Subnet Mask</div><div class="card-value">{network.netmask}</div></div>', unsafe_allow_html=True)
        with r2c2:
            usable_hosts = max(0, network.num_addresses - 2)
            st.markdown(f'<div class="cyber-card"><div class="card-title">Usable Hosts</div><div class="card-value">{usable_hosts:,}</div></div>', unsafe_allow_html=True)
            
        # --- USABLE IP RANGE ---
        hosts = list(network.hosts())
        start_ip = hosts[0] if hosts else "N/A"
        end_ip = hosts[-1] if hosts else "N/A"
        
        st.markdown(f"""
        <div class="cyber-card" style="text-align: left; border-left: 5px solid #00ffcc;">
            <div class="card-title">🖥️ Usable Host IP Range</div>
            <div class="card-value" style="font-size: 1.4rem; color: #ffffff;">
                {start_ip} <span style="color: #00ffcc;">&rarr;</span> {end_ip}
            </div>
        </div>
        """, unsafe_allow_html=True)

        # --- DEEP INSPECTION DATA ---
        st.divider()
        col_map, col_details = st.columns([1, 1])

        with col_map:
            st.markdown("### 🗺️ Subnetting Visualization")
            
            st.caption("Subnetting divides a large network into smaller, manageable segments to reduce broadcast traffic and improve security.")

        with col_details:
            st.markdown("### 🔍 Technical Specifications")
            
            # Determine IP Class
            first_oct = int(str(network.network_address).split('.')[0])
            if 1 <= first_oct <= 126: ip_class = "Class A (Enterprise)"
            elif 128 <= first_oct <= 191: ip_class = "Class B (Campus)"
            elif 192 <= first_oct <= 223: ip_class = "Class C (SOHO)"
            else: ip_class = "Multicast/Experimental"
            
            # Routing Type
            route_type = "Private (Internal)" if network.is_private else "Public (Internet)"
            binary_mask = '.'.join([bin(int(x)+256)[3:] for x in str(network.netmask).split('.')])

            st.write(f"**Network Class:** `{ip_class}`")
            st.write(f"**Routing Type:** `{route_type}`")
            st.write(f"**Wildcard Mask:** `{network.hostmask}`")
            st.write("**Binary Representation:**")
            st.code(binary_mask, language="text")

    except ValueError:
        st.error("🚨 Invalid IP/CIDR configuration. Please check your notation.")

# Footer
st.markdown("---")
st.caption("NEXUS IPv4 ARCHITECTURE ENGINE // v3.0")