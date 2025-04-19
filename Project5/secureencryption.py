# secure_encryption_app

import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# --- Security Setup ---
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# --- Data Storage ---
stored_data = {}  # { encrypted_text: { "encrypted_text": ..., "passkey": hashed_passkey } }
failed_attempts = 0

# --- Helper Functions ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    for value in stored_data.values():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    failed_attempts += 1
    return None

# --- UI Setup ---
st.set_page_config(page_title="Secure Vault", page_icon="🔐")
st.title("🔐 Secure Data Vault")
st.markdown("Keep your **data safe and private** using encryption & unique passkeys.")

menu = ["🏠 Home", "🗄️ Store Data", "🔍 Retrieve Data", "🔑 Admin Login"]
choice = st.sidebar.radio("📁 Navigation", menu)

# --- Home ---
if choice == "🏠 Home":
    st.subheader("Welcome!")
    st.markdown("This app lets you securely **store** and **retrieve** encrypted data using a passkey. "
                "🔑 Everything stays private and protected.")

# --- Store Data ---
elif choice == "🗄️ Store Data":
    st.subheader("📂 Store Data Securely")

    with st.form("store_form"):
        user_data = st.text_area("📝 Enter the data you want to secure:")
        passkey = st.text_input("🔑 Create a Passkey", type="password", help="This passkey will be required to decrypt your data.")
        submitted = st.form_submit_button("🔒 Encrypt & Save")

        if submitted:
            if user_data and passkey:
                hashed_passkey = hash_passkey(passkey)
                encrypted_text = encrypt_data(user_data, passkey)
                stored_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
                st.success("✅ Data has been encrypted and stored securely!")
                st.code(encrypted_text, language="text")
            else:
                st.error("⚠️ Please fill in both fields.")

# --- Retrieve Data ---
elif choice == "🔍 Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")

    with st.form("retrieve_form"):
        encrypted_text = st.text_area("🔐 Enter your encrypted data:")
        passkey = st.text_input("🔑 Enter your passkey", type="password")
        decrypt_btn = st.form_submit_button("🔓 Decrypt")

        if decrypt_btn:
            if encrypted_text and passkey:
                decrypted_text = decrypt_data(encrypted_text, passkey)
                if decrypted_text:
                    st.success("✅ Successfully decrypted your data:")
                    st.text_area("📄 Your Data", decrypted_text, height=150)
                else:
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - failed_attempts}")
                    if failed_attempts >= 3:
                        st.warning("🔒 Too many failed attempts. Redirecting to Login...")
                        st.experimental_rerun()
            else:
                st.error("⚠️ Please fill in both fields.")

# --- Login ---
elif choice == "🔑 Admin Login":
    # global failed_attempts
    st.subheader("🔐 Reauthorize Access")

    with st.form("login_form"):
        login_pass = st.text_input("Master Password", type="password")
        login_btn = st.form_submit_button("🔑 Login")

        if login_btn:
            if login_pass == "admin123":
                failed_attempts = 0
                st.success("✅ Login successful! Redirecting...")
                st.experimental_rerun()
            else:
                st.error("❌ Incorrect master password!")
