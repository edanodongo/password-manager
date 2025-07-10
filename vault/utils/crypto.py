import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# 32-byte key (AES-256)
# KEY = os.environ.get('ENCRYPTION_KEY', 'fallback-key-must-be-32-bytes!').encode('utf-8')
KEY = base64.b64decode(os.environ.get('ENCRYPTION_KEY'))

def get_cipher(iv):
    return Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())

def encrypt(plaintext):
    iv = os.urandom(16)  # AES block size is 16 bytes
    cipher = get_cipher(iv)
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode('utf-8')  # store IV + encrypted together

def decrypt(ciphertext_b64):
    data = base64.b64decode(ciphertext_b64)
    iv, encrypted = data[:16], data[16:]
    cipher = get_cipher(iv)
    decryptor = cipher.decryptor()
    
    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(decrypted_padded) + unpadder.finalize()).decode()
