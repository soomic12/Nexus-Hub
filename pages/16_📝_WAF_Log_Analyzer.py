import streamlit as st
import pandas as pd
import re
import io
from security_utils import check_authenticity, apply_cyber_styling

# 1. Page Configuration
st.set_page_config(page_title="WAF Log Analyzer", page_icon="📝", layout="wide")

# 2. Security & Unified Styling
check_authenticity()
apply_cyber_styling("WAF Log Analyzer")

# 3. Sidebar Intelligence
with st.sidebar:
    st.markdown("### 📝 Parsing Engine")
    st.info("Log Type: Nginx / Apache Access\nEngine: RegEx Heuristics\nContext: Web Application Firewall")
    st.divider()
    st.markdown("### 🧠 Forensic Insight")
    st.caption("Attackers rely on malicious payloads embedded in HTTP GET/POST requests. By parsing access logs against known attack signatures (SQLi, XSS, LFI), we can reconstruct the attack timeline.")

# 4. Main UI Logic
st.write("Ingest standard web server access logs to proactively detect SQL Injection, Cross-Site Scripting (XSS), and Path Traversal attempts.")
st.divider()

# Attack Signatures (Regex)
SIGNATURES = {
    "SQL Injection (SQLi)": r"(?i)(union(.|\n)*?select|select(.|\n)*?from|insert(.|\n)*?into|drop(.|\n)*?table|%27|%22|--|%23|\bOR\b|\bAND\b\s+[\d\w]+\s*=\s*[\d\w]+)",
    "Cross-Site Scripting (XSS)": r"(?i)(<script>|%3Cscript%3E|javascript:|onmouseover=|onerror=|onload=|eval\()",
    "Path Traversal (LFI)": r"(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|etc/passwd|boot\.ini|windows/win\.ini)",
    "Command Injection": r"(?i)(;|\||`|\$|\n|\r)(cat|ls|pwd|whoami|id|wget|curl|bash|nc|ping)"
}

def parse_log_line(line):
    """Parses a standard Apache/Nginx combined log line format."""
    pattern = r'^(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+.*?\[(?P<time>.*?)\].*?"(?P<request>.*?)"\s+(?P<status>\d{3})\s+.*$'
    match = re.match(pattern, line)
    if match:
        return match.groupdict()
    return None

col1, col2 = st.columns([1, 2])

with col1:
    st.markdown("### 📤 Ingest Access Log")
    uploaded_file = st.file_uploader("Upload Apache/Nginx access.log:", type=["log", "txt"])
    
    st.divider()
    st.markdown("### 🧪 Simulation Mode")
    if st.button("Load Simulated Attack Log"):
        simulated_log = """
            192.168.1.10 - - [11/Mar/2026:10:00:01 +0000] "GET /index.php HTTP/1.1" 200 1024
            10.0.0.5 - - [11/Mar/2026:10:01:23 +0000] "GET /login.php?user=admin' OR '1'='1 HTTP/1.1" 403 512
            172.16.0.4 - - [11/Mar/2026:10:05:12 +0000] "GET /admin/config.php HTTP/1.1" 404 256
            10.0.0.5 - - [11/Mar/2026:10:06:55 +0000] "POST /comment.php?msg=<script>alert('XSS')</script> HTTP/1.1" 200 401
            192.168.1.50 - - [11/Mar/2026:10:10:00 +0000] "GET /style.css HTTP/1.1" 200 3040
            192.168.1.10 - - [11/Mar/2026:10:15:22 +0000] "GET /download.php?file=../../../../etc/passwd HTTP/1.1" 200 819
            10.0.0.8 - - [11/Mar/2026:10:20:11 +0000] "GET /ping.php?ip=127.0.0.1;cat /etc/shadow HTTP/1.1" 500 0
        """
        st.session_state['simulated_log'] = io.StringIO(simulated_log.strip())
        st.success("Loaded synthetic threat logs.")


with col2:
    st.markdown("### 🚨 Threat Analysis")
    
    log_file_to_process = None
    
    if uploaded_file is not None:
        log_file_to_process = io.StringIO(uploaded_file.getvalue().decode("utf-8"))
    elif 'simulated_log' in st.session_state:
        log_file_to_process = st.session_state['simulated_log']
        st.session_state['simulated_log'].seek(0)
        
    if log_file_to_process:
        with st.spinner("Parsing logs against threat signatures..."):
            parsed_data = []
            total_lines = 0
            
            for line in log_file_to_process:
                total_lines += 1
                parsed = parse_log_line(line.strip())
                if parsed:
                    request_uri = parsed['request']
                    detected_threats = []
                    
                    for threat_name, threat_regex in SIGNATURES.items():
                        if re.search(threat_regex, request_uri):
                            detected_threats.append(threat_name)
                            
                    parsed['threats'] = ", ".join(detected_threats) if detected_threats else "None"
                    parsed['is_malicious'] = len(detected_threats) > 0
                    parsed_data.append(parsed)

            if parsed_data:
                df = pd.DataFrame(parsed_data)
                
                total_malicious = len(df[df['is_malicious'] == True])
                unique_ips = df[df['is_malicious'] == True]['ip'].nunique()
                
                c_t1, c_t2, c_t3 = st.columns(3)
                with c_t1:
                    st.markdown(f'<div style="background-color: #1e122b; border: 1px solid #b24bf3; border-radius: 8px; padding: 15px; text-align: center;"><div style="color: #e0d4f5; font-size: 0.8rem;"><b>Total Log Entries</b></div><div style="color: #b24bf3; font-size: 1.2rem; font-weight: bold;">{total_lines}</div></div>', unsafe_allow_html=True)
                with c_t2:
                    color = "#ff4b4b" if total_malicious > 0 else "#00ffcc"
                    st.markdown(f'<div style="background-color: #1e122b; border: 1px solid {color}; border-radius: 8px; padding: 15px; text-align: center;"><div style="color: #e0d4f5; font-size: 0.8rem;"><b>Malicious Requests</b></div><div style="color: {color}; font-size: 1.2rem; font-weight: bold;">{total_malicious}</div></div>', unsafe_allow_html=True)
                with c_t3:
                    st.markdown(f'<div style="background-color: #1e122b; border: 1px solid #b24bf3; border-radius: 8px; padding: 15px; text-align: center;"><div style="color: #e0d4f5; font-size: 0.8rem;"><b>Unique Attacker IPs</b></div><div style="color: #b24bf3; font-size: 1.2rem; font-weight: bold;">{unique_ips}</div></div>', unsafe_allow_html=True)
                
                st.divider()
                
                if total_malicious > 0:
                    st.error("⚠️ **WAF Alerts Triggered:** Malicious payloads identified in the access logs.")
                    
                    malicious_df = df[df['is_malicious'] == True][['time', 'ip', 'request', 'status', 'threats']]
                    
                    st.dataframe(
                        malicious_df.style.applymap(lambda _: 'color: #ff4b4b;', subset=['threats']),
                        column_config={
                            "time": "Timestamp",
                            "ip": "Source IP",
                            "request": "HTTP Request (Payload)",
                            "status": "Response Code",
                            "threats": "Signature Match"
                        },
                        hide_index=True,
                        use_container_width=True
                    )
                    
                    st.markdown("### 💾 Export Forensic Report")
                    csv_export = malicious_df.to_csv(index=False).encode('utf-8')
                    st.download_button(
                        label="⬇️ Download Threat Report (CSV)",
                        data=csv_export,
                        file_name="waf_threat_report.csv",
                        mime="text/csv",
                    )
                else:
                    st.success("✅ Log analysis complete. No known attack signatures detected.")
            else:
                 st.error("Could not parse log format. Ensure standard Apache/Nginx combined format.")
                 
    else:
        # Pushes the info box down to align exactly with the Drag and Drop area
        st.markdown("<div style='margin-top: 35px;'></div>", unsafe_allow_html=True)
        st.info("Awaiting log file ingestion for WAF analysis.")

# Footer
st.markdown("---")
st.caption("NEXUS WAF LOG HEURISTICS ENGINE // v3.0")