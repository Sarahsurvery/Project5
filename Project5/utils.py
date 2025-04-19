# encryptor.py
import hashlib
from cryptography.fernet import Fernet

# Key for Fernet encryption (normally should be securely stored)
fernet_key = Fernet.generate_key()
cipher = Fernet(fernet_key)

# Hash a passkey using SHA-256
def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt text
def encrypt_text(text: str) -> str:
    return cipher.encrypt(text.encode()).decode()

# Decrypt text
def decrypt_text(encrypted_text: str) -> str:
    return cipher.decrypt(encrypted_text.encode()).decode()
