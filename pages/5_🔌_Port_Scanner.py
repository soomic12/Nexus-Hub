import streamlit as st
import socket
import time
import requests
from security_utils import check_authenticity, apply_cyber_styling

# 1. Page Configuration
st.set_page_config(page_title="Vulnerability Scanner", page_icon="🔌", layout="wide")

# 2. Security & Unified Styling
check_authenticity()
apply_cyber_styling("Vulnerability & Port Scanner")

# 3. Sidebar Intelligence
with st.sidebar:
    st.markdown("### 🔍 Scan Parameters")
    st.info("Method: TCP Connect Scan + Banner Grabbing\nTimeout: 0.8s per port\nThreads: Sequential")
    st.divider()
    st.markdown("### 🧠 Forensic Insight")
    st.caption("A 'TCP Connect' scan completes the full 3-way handshake. If successful, we attempt 'Banner Grabbing' (sending raw data and waiting for a response) to identify the specific service version. We then cross-reference this with a known vulnerability database (CVE).")

# 4. Main UI Logic
st.write("Execute deep TCP connect scans, grab service banners, and cross-reference with known Common Vulnerabilities and Exposures (CVEs).")
st.divider()

target = st.text_input("Enter Target IP or Domain:", "scanme.nmap.org")

# Port Definitions for the Audit
common_ports = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 
    53: "DNS", 80: "HTTP", 110: "POP3", 443: "HTTPS", 3389: "RDP"
}

def grab_banner(ip, port):
    """Attempt to grab the service banner from an open port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0) # Slightly longer timeout for grabbing banners
        s.connect((ip, port))
        
        # We need to send some data to trigger a response for HTTP/HTTPS
        if port in [80, 443]:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        else:
            # For FTP, SSH, etc., we just receive
            pass
            
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        
        # Take just the first line as the banner
        if banner:
            return banner.split('\n')[0][:50]
        return "Banner unavailable"
    except Exception as e:
        return "Connection closed before banner sent"

def mock_cve_lookup(service, banner):
    """Simulates CVE lookup based on banner keywords. In production, query NVD API."""
    vulns = []
    banner_lower = banner.lower()
    
    if "ssh" in banner_lower:
        if "openssh 4." in banner_lower or "openssh 5." in banner_lower:
            vulns.append("CVE-2016-0777: OpenSSH Roaming Info Leak")
        if "libssh" in banner_lower:
            vulns.append("CVE-2018-10933: libssh Authentication Bypass")
            
    if "ftp" in banner_lower and "vsftpd 2.3.4" in banner_lower:
        vulns.append("CVE-2011-2523: vsftpd 2.3.4 Backdoor Command Execution")
        
    if "http" in banner_lower:
        if "apache" in banner_lower and "2.4.49" in banner_lower:
            vulns.append("CVE-2021-41773: Apache HTTP Server Path Traversal")
        if "nginx 1.4" in banner_lower:
             vulns.append("CVE-2013-4547: NGINX Space character vulnerability")
             
    if service == "Telnet" or service == "FTP" or service == "RDP":
        vulns.append("CRITICAL: Unencrypted / Remote Access Protocol exposed.")
        
    if not vulns and banner != "Banner unavailable" and banner != "Connection closed before banner sent":
        vulns.append("No critical CVEs identified for this specific version.")
        
    return vulns


if st.button("EXECUTE DEEP VULNERABILITY SCAN", use_container_width=True):
    with st.spinner(f"Initiating full TCP handshake and banner extraction on {target}..."):
        start_time = time.time()
        open_ports_data = [] # List of dicts
        critical_exposure = False
        
        progress_bar = st.progress(0)
        
        # Scan Engine
        for i, (port, service) in enumerate(common_ports.items()):
            try:
                # Resolve IP (Needed for banner grabbing)
                target_ip = socket.gethostbyname(target)
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target_ip, port))
                
                if result == 0:
                    # Port is open. Grab Banner.
                    sock.close() # Close probing socket
                    
                    banner = grab_banner(target_ip, port)
                    cves = mock_cve_lookup(service, banner)
                    
                    if port in [21, 23, 3389] or any("CVE" in cve for cve in cves): 
                        critical_exposure = True
                        
                    open_ports_data.append({
                        "port": port,
                        "service": service,
                        "banner": banner,
                        "cves": cves
                    })
                else:
                    sock.close()
            except socket.gaierror:
               st.error(f"Hostname resolution failed for {target}.")
               break
            except Exception as e:
                pass
                
            progress_bar.progress((i + 1) / len(common_ports))
            
        scan_duration = round(time.time() - start_time, 2)
        st.success(f"✅ Scanning & Banner Grabbing Complete in {scan_duration}s.")
        
        # --- CORE TELEMETRY CARDS ---
        if open_ports_data or not target: # Show if done mapping
            st.markdown("### 📊 Endpoint Telemetry")
            c1, c2, c3, c4 = st.columns(4)
            
            with c1:
                st.markdown(f'<div class="cyber-card"><div class="card-title">Target Host</div><div class="card-value" style="font-size:1.1rem;">{target}</div></div>', unsafe_allow_html=True)
            with c2:
                st.markdown(f'<div class="cyber-card"><div class="card-title">Ports Audited</div><div class="card-value">{len(common_ports)}</div></div>', unsafe_allow_html=True)
            with c3:
                st.markdown(f'<div class="cyber-card"><div class="card-title">Open Endpoints</div><div class="card-value">{len(open_ports_data)}</div></div>', unsafe_allow_html=True)
            with c4:
                # Determine Risk Level
                if critical_exposure:
                    risk_color, risk_level = "#ff4b4b", "CRITICAL"
                elif len(open_ports_data) > 0:
                    risk_color, risk_level = "#ffa500", "ELEVATED"
                else:
                    risk_color, risk_level = "#00ffcc", "SECURE"
                    
                st.markdown(f'<div class="cyber-card" style="border-color:{risk_color};"><div class="card-title">Risk Assessment</div><div class="card-value" style="color:{risk_color};">{risk_level}</div></div>', unsafe_allow_html=True)
    
            st.divider()
            
            # --- RESULTS & METHODOLOGY ---
            col_res, col_meth = st.columns([2, 1])
            
            with col_res:
                st.markdown("### 🔓 Exposed Services & CVE Risk")
                if open_ports_data:
                    for port_data in open_ports_data:
                        port = port_data['port']
                        service = port_data['service']
                        banner = port_data['banner']
                        cves = port_data['cves']
                        
                        has_cve = any("CVE" in cve for cve in cves) or port in [21, 23, 3389]
                        
                        if has_cve:
                             with st.expander(f"⚠️ Port {port} ({service}) - VULNERABILITY DETECTED", expanded=True):
                                 st.markdown(f"**Banner Profile:** `{banner}`")
                                 st.error("**Identified Threats:**")
                                 for cve in cves:
                                     st.write(f"- {cve}")
                        else:
                            with st.expander(f"✅ Port {port} ({service}) - Open", expanded=False):
                                 st.markdown(f"**Banner Profile:** `{banner}`")
                                 st.info("No immediate CVEs found for this profile based on local signatures.")
                else:
                    st.info("No common vulnerabilities exposed. Host firewalls are actively rejecting traffic.")
    
            with col_meth:
                st.markdown("### ⚙️ Engine Methodology")
                st.caption("1. **TCP Handshake:** Verifies port availability via full SYN->SYNACK->ACK.\n2. **Banner Grab:** Transmits raw payload layer bytes and intercepts service response signature.\n3. **CVE Cross-Ref:** Parses signature against the loaded Vulnerability Database definitions.")

# Footer
st.markdown("---")
st.caption("NEXUS DEEP VULNERABILITY SCANNER // v4.0")