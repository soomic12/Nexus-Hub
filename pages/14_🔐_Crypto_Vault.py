import streamlit as st
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from security_utils import check_authenticity, apply_cyber_styling
import io
import os

# 1. Page Configuration
st.set_page_config(page_title="Crypto Vault", page_icon="🔐", layout="wide")

# 2. Security & Unified Styling
check_authenticity()
apply_cyber_styling("Crypto Vault")

# 3. Sidebar Intelligence
with st.sidebar:
    st.markdown("### 🔐 Cryptographic Engine")
    st.info("Algorithm: AES-128 (Fernet)\nKDF: PBKDF2HMAC\nIterations: 480,000")
    st.divider()
    st.markdown("### 🧠 Forensic Insight")
    st.caption("Military-grade symmetric encryption. Without the exact passphrase and salt, deciphering the ciphertext is statistically impossible.")

# 4. Main UI Logic
st.write("Secure your intel. Encrypt and decrypt text or files using state-of-the-art AES encryption.")
st.divider()

def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


tab1, tab2 = st.tabs(["📝 Text Encryption", "📄 File Encryption"])

with tab1:
    col_text1, col_text2 = st.columns(2)
    with col_text1:
        st.markdown("### 🔒 Encrypt Message")
        master_pass_enc = st.text_input("Master Passphrase (Encryption):", type="password", key="pass_enc1")
        plain_text = st.text_area("Input sensitive intel:")
        
        if st.button("ENCRYPT INTEL", use_container_width=True):
            if master_pass_enc and plain_text:
                salt = os.urandom(16)
                key = generate_key(master_pass_enc, salt)
                f = Fernet(key)
                token = f.encrypt(plain_text.encode())
                
                # Prepend salt to the token so it can be extracted during decryption
                final_payload = base64.b64encode(salt + token).decode()
                
                st.success("Ciphertext generated successfully.")
                st.code(final_payload, language="text")
            else:
                st.error("Passphrase and intel are required.")

    with col_text2:
        st.markdown("### 🔓 Decrypt Message")
        master_pass_dec = st.text_input("Master Passphrase (Decryption):", type="password", key="pass_dec1")
        cipher_text = st.text_area("Input Ciphertext:")
        
        if st.button("DECRYPT INTEL", use_container_width=True):
            if master_pass_dec and cipher_text:
                try:
                    raw_data = base64.b64decode(cipher_text.encode())
                    salt = raw_data[:16]
                    token = raw_data[16:]
                    
                    key = generate_key(master_pass_dec, salt)
                    f = Fernet(key)
                    decrypted = f.decrypt(token).decode()
                    
                    st.success("Decryption successful.")
                    st.code(decrypted, language="text")
                except Exception as e:
                    st.error("🚨 Decryption Failed: Invalid passphrase or corrupted ciphertext.")
            else:
                st.error("Passphrase and ciphertext are required.")

with tab2:
    col_file1, col_file2 = st.columns(2)
    
    with col_file1:
        st.markdown("### 📜 Encrypt File")
        master_pass_file_enc = st.text_input("Master Passphrase (Encryption):", type="password", key="pass_enc2")
        uploaded_file_enc = st.file_uploader("Upload file to encrypt:")
        
        if st.button("ENCRYPT SYSTEM FILE", use_container_width=True):
            if master_pass_file_enc and uploaded_file_enc:
                file_bytes = uploaded_file_enc.read()
                salt = os.urandom(16)
                key = generate_key(master_pass_file_enc, salt)
                f = Fernet(key)
                token = f.encrypt(file_bytes)
                final_payload = salt + token
                
                st.success("File encrypted successfully.")
                st.download_button(
                    label="⬇️ DOWNLOAD ENCRYPTED FILE",
                    data=final_payload,
                    file_name=uploaded_file_enc.name + ".enc",
                    mime="application/octet-stream"
                )
            else:
                st.error("Passphrase and file are required.")

    with col_file2:
        st.markdown("### 🧩 Decrypt File")
        master_pass_file_dec = st.text_input("Master Passphrase (Decryption):", type="password", key="pass_dec2")
        uploaded_file_dec = st.file_uploader("Upload .enc file to decrypt:")
        
        if st.button("DECRYPT SYSTEM FILE", use_container_width=True):
            if master_pass_file_dec and uploaded_file_dec:
                try:
                    raw_data = uploaded_file_dec.read()
                    salt = raw_data[:16]
                    token = raw_data[16:]
                    
                    key = generate_key(master_pass_file_dec, salt)
                    f = Fernet(key)
                    decrypted_bytes = f.decrypt(token)
                    
                    original_name = uploaded_file_dec.name.replace(".enc", "")
                    if not original_name: original_name = "decrypted_file.bin"
                    
                    st.success("File decrypted successfully.")
                    st.download_button(
                        label="⬇️ DOWNLOAD DECRYPTED FILE",
                        data=decrypted_bytes,
                        file_name=original_name,
                        mime="application/octet-stream"
                    )
                except Exception as e:
                    st.error("🚨 Decryption Failed: Invalid passphrase or corrupted file.")
            else:
                st.error("Passphrase and file are required.")

# Footer
st.markdown("---")
st.caption("NEXUS CRYPTOGRAPHY & DATA VAULT // v3.0")
