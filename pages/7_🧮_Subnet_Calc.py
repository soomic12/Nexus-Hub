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
        
        # --- CORE METRIC CARDS ---
        st.markdown("### 📊 Core Network Metrics")
        
        r1c1, r1c2, r1c3, r1c4 = st.columns(4)
        with r1c1:
            st.metric("Network ID", str(network.network_address))
        with r1c2:
            st.metric("Broadcast", str(network.broadcast_address))
        with r1c3:
            st.metric("Subnet Mask", str(network.netmask))
        with r1c4:
            usable_count = max(0, network.num_addresses - 2) if network.prefixlen < 31 else 0
            st.metric("Usable Hosts", f"{usable_count:,}")
            
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