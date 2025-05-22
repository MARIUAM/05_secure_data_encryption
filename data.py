

import streamlit as st
import hashlib
import sqlite3
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
# Theme Selection
theme = st.selectbox("Choose Theme", ["Light", "Dark"])

# Apply Theme CSS
if theme == "Light":
    st.markdown("""
    <style>
    body {
        background-color: #ffffff;
        color: #000;
        font-family: 'Segoe UI', sans-serif;
    }
    .stApp {
        background: #e5fafd;
    }
    h1, h2, h3 {
        color: #4ED7F1;
        text-shadow: 0 0 10px #6FE6FC;
    }
    .stButton>button {
        background-color: #4ED7F1;
        color: black;
        border-radius: 10px;
        border: none;
        font-weight: bold;
        box-shadow: 0 0 10px #6FE6FC;
    }
    .stTextInput>div>div>input, .stTextArea>div>div>textarea {
        border: 1px solid #4ED7F1;
        background-color: #fff;
    }
    .card {
        border: 1px solid #4ED7F1;
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 0 15px #6FE6FC;
        margin-top: 20px;
    }
    </style>
    """, unsafe_allow_html=True)
else:
    st.markdown("""
    <style>
    body {
        background-color: #0e1117;
        color: #fff;
        font-family: 'Segoe UI', sans-serif;
    }
    .stApp {
        background: #0e1117;
    }
    h1, h2, h3 {
        color: #58a6ff;
        text-shadow: 0 0 10px #58a6ff;
    }
    .stButton>button {
        background-color: #58a6ff;
        color: white;
        border-radius: 10px;
        border: none;
        font-weight: bold;
        box-shadow: 0 0 10px #58a6ff;
    }
    .stTextInput>div>div>input, .stTextArea>div>div>textarea {
        border: 1px solid #58a6ff;
        background-color: #1c1f26;
        color: white;
    }
    .card {
        border: 1px solid #58a6ff;
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 0 15px #58a6ff;
        margin-top: 20px;
    }
    </style>
    """, unsafe_allow_html=True)


# Database Setup
DB_NAME = 'neon_secure_vault.db'

def create_connection():
    return sqlite3.connect(DB_NAME)

def create_tables():
    conn = create_connection()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS encrypted_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    encrypted_text TEXT,
                    passkey_hash TEXT,
                    owner TEXT,
                    timestamp TEXT)''')
    conn.commit()
    conn.close()

create_tables()

# Session State Initialization
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "current_user" not in st.session_state:
    st.session_state.current_user = ""
if "start_time" not in st.session_state:
    st.session_state.start_time = datetime.now()

# Styling: Aqua & White Theme with Light/Dark Toggle
st.markdown("""
    <style>
    body { background-color: #ffffff; color: #000; font-family: 'Segoe UI', sans-serif; }
    .stApp { background: #e5fafd; }
    h1, h2, h3 { color: #4ED7F1; text-shadow: 0 0 10px #6FE6FC; }
    .stButton>button {
        background-color: #4ED7F1;
        color: black;
        border-radius: 10px;
        border: none;
        font-weight: bold;
        box-shadow: 0 0 10px #6FE6FC;
    }
    .stTextInput>div>div>input, .stTextArea>div>div>textarea {
        border: 1px solid #4ED7F1;
        background-color: #fff;
    }
    .card {
        border: 1px solid #4ED7F1;
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 0 15px #6FE6FC;
        margin-top: 20px;
    }
    </style>
""", unsafe_allow_html=True)

# Encryption Setup
key = Fernet.generate_key()
cipher = Fernet(key)

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

def auto_logout():
    if datetime.now() - st.session_state.start_time > timedelta(minutes=5):
        st.session_state.authenticated = False
        st.warning("Session expired due to inactivity.")

def login_user(username, password):
    conn = create_connection()
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()
    if user and user[0] == hash_passkey(password):
        st.session_state.authenticated = True
        st.session_state.current_user = username
        st.session_state.start_time = datetime.now()
        return True
    return False

def register_user(username, password):
    conn = create_connection()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                  (username, hash_passkey(password)))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False

def store_encrypted_data(user, encrypted, passkey_hash):
    conn = create_connection()
    c = conn.cursor()
    c.execute("INSERT INTO encrypted_data (encrypted_text, passkey_hash, owner, timestamp) VALUES (?, ?, ?, ?)",
              (encrypted, passkey_hash, user, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

def get_user_data(user):
    conn = create_connection()
    c = conn.cursor()
    c.execute("SELECT encrypted_text, timestamp FROM encrypted_data WHERE owner=?", (user,))
    data = c.fetchall()
    conn.close()
    return data

# Password Strength Checker
import re
def check_password_strength(password):
    if len(password) < 8:
        return "Weak: Minimum 8 characters required"
    if not re.search(r"[A-Z]", password):
        return "Weak: Add at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return "Weak: Add at least one lowercase letter"
    if not re.search(r"[0-9]", password):
        return "Weak: Add at least one number"
    if not re.search(r"[@$!%*#?&]", password):
        return "Weak: Add a special character"
    return "Strong Password ✅"

# UI
st.title("📚  Secure DATA Encryption")
action = st.radio("Choose an action", ["Login", "Register"])
username = st.text_input("Username")
password = st.text_input("Password", type="password")

if password:
    strength = check_password_strength(password)
    st.caption(strength)

if action == "Login":
    if st.button("Login"):
        if login_user(username, password):
            st.success(f"Welcome back, {username}")
        else:
            st.error("Invalid credentials")
elif action == "Register":
    if st.button("Register"):
        if register_user(username, password):
            st.success("User registered successfully")
        else:
            st.warning("Username already exists")

# Secure Area
auto_logout()

if st.session_state.authenticated:
    st.subheader("🔏 Encrypt and Store Your Data")
    text_to_encrypt = st.text_area("Enter your data")
    passkey = st.text_input("Enter your encryption key", type="password")

    if st.button("Encrypt & Store"):
        if text_to_encrypt and passkey:
            encrypted = encrypt_data(text_to_encrypt)
            store_encrypted_data(st.session_state.current_user, encrypted, hash_passkey(passkey))
            st.success("Data encrypted and stored successfully")
        else:
            st.error("Please provide both data and passkey")

    if st.button("Show My Encrypted Data"):
        data = get_user_data(st.session_state.current_user)
        for enc, timestamp in data:
            st.markdown(f"**Encrypted:** `{enc}`\n\n📅 {timestamp}", unsafe_allow_html=True)

    if st.button("Logout"):
        st.session_state.authenticated = False
        st.success("Logged out successfully")

