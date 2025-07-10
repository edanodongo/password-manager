# vault/utils/crypto.py
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from django.conf import settings

# Decode the base64 key from settings
KEY = base64.b64decode(settings.ENCRYPTION_KEY)  # this will be exactly 32 bytes

def get_cipher(iv):
    return Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())

def encrypt(plaintext):
    iv = os.urandom(16)
    cipher = get_cipher(iv)
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()

    encrypted = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode()

def decrypt(ciphertext_b64):
    data = base64.b64decode(ciphertext_b64)
    iv, encrypted = data[:16], data[16:]
    cipher = get_cipher(iv)
    decryptor = cipher.decryptor()

    padded = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()
