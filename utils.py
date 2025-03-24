import base64
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(nonce + tag + ciphertext).decode()

def decrypt_message(encrypted_message, key):
    data = base64.b64decode(encrypted_message)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def generate_mac(message, mac_key):
    hmac = HMAC.new(mac_key, message.encode(), SHA256)
    return base64.b64encode(hmac.digest()).decode()

def verify_mac(message, mac, mac_key):
    hmac = HMAC.new(mac_key, message.encode(), SHA256)
    return base64.b64encode(hmac.digest()).decode() == mac
