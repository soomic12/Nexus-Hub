import streamlit as st
import ipaddress
from security_utils import check_authenticity, apply_cyber_styling

# 1. Page Configuration
st.set_page_config(page_title="Nexus Hub | Subnet Calculator", page_icon="🧮", layout="wide")

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
st.title("🧮 IPv4 Subnet Architecture Engine")
st.write("Calculate network boundaries, broadcast addresses, and usable host ranges for enterprise IT planning.")
st.divider()

col_input, col_cidr = st.columns([2, 1])
with col_input:
    # Placeholder for input
    ip_input = st.text_input("Enter Target IP Address:", placeholder="e.g., 192.168.1.0", value="192.168.1.0")
with col_cidr:
    cidr_input = st.number_input("CIDR Notation (0-32):", min_value=0, max_value=32, value=24)

if st.button("CALCULATE NETWORK ARCHITECTURE", use_container_width=True):
    try:
        network_string = f"{ip_input}/{cidr_input}"
        # strict=False allows users to enter an IP that isn't the base network address
        network = ipaddress.IPv4Network(network_string, strict=False)
        
        st.success(f"✅ Network Topology Calculated for {network_string}")
        
        # --- CORE METRIC CARDS (Sleek Professional Version) ---
        st.markdown("### 📊 Core Network Metrics")
        
        # We use a custom style block to ensure the text isn't "Giant"
        st.markdown(f'''
        <div style="display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 20px;">
            <div style="flex: 1; min-width: 200px; background-color: #0e1117; border: 1px solid #00ffcc; border-radius: 5px; padding: 10px; text-align: center;">
                <div style="color: #00ffcc; font-size: 0.8rem; text-transform: uppercase;">Network ID</div>
                <div style="color: #ffffff; font-size: 1.1rem; font-family: monospace;">{network.network_address}</div>
            </div>
            <div style="flex: 1; min-width: 200px; background-color: #0e1117; border: 1px solid #00ffcc; border-radius: 5px; padding: 10px; text-align: center;">
                <div style="color: #00ffcc; font-size: 0.8rem; text-transform: uppercase;">Broadcast</div>
                <div style="color: #ffffff; font-size: 1.1rem; font-family: monospace;">{network.broadcast_address}</div>
            </div>
            <div style="flex: 1; min-width: 200px; background-color: #0e1117; border: 1px solid #00ffcc; border-radius: 5px; padding: 10px; text-align: center;">
                <div style="color: #00ffcc; font-size: 0.8rem; text-transform: uppercase;">Subnet Mask</div>
                <div style="color: #ffffff; font-size: 1.1rem; font-family: monospace;">{network.netmask}</div>
            </div>
            <div style="flex: 1; min-width: 200px; background-color: #0e1117; border: 1px solid #00ffcc; border-radius: 5px; padding: 10px; text-align: center;">
                <div style="color: #00ffcc; font-size: 0.8rem; text-transform: uppercase;">Usable Hosts</div>
                <div style="color: #ffffff; font-size: 1.1rem; font-family: monospace;">{usable_count:,}</div>
            </div>
        </div>
        ''', unsafe_allow_html=True)
            
        # --- SAFE USABLE IP RANGE (Memory Efficient) ---
        if network.prefixlen <= 30:
            start_ip = network.network_address + 1
            end_ip = network.broadcast_address - 1
            st.info(f"🖥️ **Usable Host IP Range:** `{start_ip}` → `{end_ip}`")
        else:
            st.warning("⚠️ This subnet size (P2P/Loopback) does not support a standard usable host range.")

        # --- DEEP INSPECTION DATA ---
        st.divider()
        col_map, col_details = st.columns([1, 1])

        with col_map:
            st.markdown("### 🗺️ Binary Logic Visualization")
            binary_mask = '.'.join([bin(int(x)+256)[3:] for x in str(network.netmask).split('.')])
            st.write("**Netmask Binary:**")
            st.code(binary_mask, language="text")
            st.caption("The mask determines which bits represent the Network ID vs the Host ID.")

        with col_details:
            st.markdown("### 🔍 Technical Specifications")
            
            # Determine IP Class
            first_oct = int(str(network.network_address).split('.')[0])
            if 1 <= first_oct <= 126: ip_class = "Class A (Enterprise)"
            elif 128 <= first_oct <= 191: ip_class = "Class B (Campus)"
            elif 192 <= first_oct <= 223: ip_class = "Class C (SOHO)"
            else: ip_class = "Multicast/Experimental"
            
            # Routing Type
            route_type = "Private (Internal RFC 1918)" if network.is_private else "Public (Internet Routable)"

            st.write(f"**Network Class:** `{ip_class}`")
            st.write(f"**Routing Type:** `{route_type}`")
            st.write(f"**Wildcard Mask:** `{network.hostmask}`")

    except ValueError:
        st.error("🚨 Invalid IP/CIDR configuration. Please check your notation.")

# Footer
st.markdown("---")
st.caption("NEXUS IPv4 ARCHITECTURE ENGINE // v3.0")