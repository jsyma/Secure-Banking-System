import socket
import threading
import bcrypt
import json
import os
import base64
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

# Store User Accounts
accounts = {}

# Master Secret Key
master_secret_key = os.urandom(32)

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

def handle_client(client_socket):
    try:
        data = client_socket.recv(1024).decode()
        request = json.loads(data)
        action = request.get("action")

        if action == "register":
            username = request["username"]
            password = request["password"]
            if username in accounts:
                response = {"status": "error", "message": "Username already exists"}
            else:
                hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                accounts[username] = {"password": hashed_password, "balance": 0}
                response = {"status": "success", "message": "Account created"}

        elif action == "authenticate":
            username = request["username"]
            password = request["password"]
            if username in accounts and bcrypt.checkpw(password.encode(), accounts[username]["password"]):
                response = {"status": "success", "master_secret": base64.b64encode(master_secret_key).decode()}
            else:
                response = {"status": "error", "message": "Invalid credentials"}

        elif action in ["deposit", "withdraw", "balance"]:
            username = request["username"]
            encrypted_data = request["data"]
            mac = request["mac"]

            key = SHA256.new(master_secret_key).digest()
            encryption_key = key[:16]
            mac_key = key[16:]

            decrypted_data = decrypt_message(encrypted_data, encryption_key)
            if not verify_mac(decrypted_data, mac, mac_key):
                response = {"status": "error", "message": "MAC verification failed"}
            else:
                amount = int(decrypted_data.split(":")[-1])
                if action == "deposit":
                    accounts[username]["balance"] += amount
                    response = {"status": "success", "message": "Deposit successful"}
                elif action == "withdraw":
                    if accounts[username]["balance"] >= amount:
                        accounts[username]["balance"] -= amount
                        response = {"status": "success", "message": "Withdrawal successful"}
                    else:
                        response = {"status": "error", "message": "Insufficient funds"}
                elif action == "balance":
                    response = {"status": "success", "balance": accounts[username]["balance"]}

        else:
            response = {"status": "error", "message": "Invalid action"}

        client_socket.sendall(json.dumps(response).encode())

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

def start_bank_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 8000))
    server.listen(5)
    print("Bank Server Running...")

    while True:
        client_socket, _ = server.accept()
        threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == "__main__":
    start_bank_server()
