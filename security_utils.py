import streamlit as st
import os

SESSION_FILE = ".nexus_session"

def apply_cyber_styling(page_name):
    """Applies the core Nexus CSS and the red module header without logo injection."""
    
    st.markdown(f"""
    <style>
    /* Stop the sidebar buttons from ever rendering space */
    .st-emotion-cache-16ids9e, 
    .st-emotion-cache-z5fcl4,
    [data-testid="stSidebarHeader"], 
    [data-testid="stSidebarCollapseButton"],
    button[aria-label="Close sidebar"],
    button[aria-label="Open sidebar"] {{
        display: none !important;
        height: 0px !important;
        width: 0px !important;
        margin: 0px !important;
        padding: 0px !important;
        overflow: hidden !important;
    }}

    /* Force the content container to start at 0px immediately */
    [data-testid="stSidebarContent"] {{
        padding-top: 20px !important;
    }}

    /* Ensure the nav list doesn't jump */
    [data-testid="stSidebarNav"] {{
        padding-top: 0px !important;
    }}

    [data-testid="stSidebarNavHeader"] {{
        margin-top: 0px !important;
        padding-top: 15px !important;
    }}

        /* 3. Module Page Header Styling */
        .cyber-page-header {{
            background: linear-gradient(90deg, #240b36 0%, #c31432 100%);
            padding: 15px;
            border-radius: 8px;
            border-bottom: 2px solid #ff4b4b;
            text-align: center;
            margin-bottom: 0px;
            box-shadow: 0 0 15px rgba(255, 75, 75, 0.2);
        }}
        
        .header-title {{
            font-family: 'Courier New', monospace;
            font-size: 1.8rem;
            font-weight: bold;
            color: white;
            letter-spacing: 2px;
            text-shadow: 1px 1px #ff4b4b;
        }}
    </style>
    """, unsafe_allow_html=True)

    # Inject the Red Cyber Header at the top of the page
    st.markdown(f"""
    <div class="cyber-page-header">
        <div class="header-title">NEXUS // {page_name.upper()}</div>
        <div style="color: #00ffcc; font-size: 0.8rem; font-family: monospace;">MODULE STATUS: ACTIVE | ENCRYPTION: AES-256</div>
    </div>
    """, unsafe_allow_html=True)

def check_authenticity():
    """Gatekeeper function to ensure only logged-in operators access the modules."""
    if 'authenticated' not in st.session_state or not st.session_state['authenticated']:
        # Try to recover session from file
        if os.path.exists(SESSION_FILE):
            with open(SESSION_FILE, "r") as f:
                saved_user = f.read().strip()
                if saved_user:
                    st.session_state['authenticated'] = True
                    st.session_state['username'] = saved_user
                    return True
        
        # If no session, block access
        st.error("🚨 UNAUTHORIZED INTERCEPT. Access Denied. Please login at NEXUS // HUB.")
        st.stop()
    return True