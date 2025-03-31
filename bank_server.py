import socket
import threading
import bcrypt
import json
import os
import base64
import datetime
from Crypto.Hash import SHA256
from utils import encrypt_message, decrypt_message, generate_mac, verify_mac
from dotenv import load_dotenv

LOG_FILE = "audit_transactions.txt"

load_dotenv()

# Store User Accounts
accounts = {}

# Master Secret Key
master_secret_key = base64.b64decode(os.getenv("MASTER_SECRET_KEY"))

def audit_transaction(username, action, encryption_key, mac_key):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    audit_message = f"{username}: {action} at {timestamp}"

    encrypted_audit_message = encrypt_message(audit_message, encryption_key)
    audit_mac = generate_mac(audit_message, mac_key)

    if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, "w") as log_file:
                log_file.write("")

    with open(LOG_FILE, "a") as log_file:
        log_file.write(json.dumps({"Transaction": encrypted_audit_message, "MAC": audit_mac}) + "\n")

def handle_client(client_socket):
    try:
        data = client_socket.recv(1024).decode()
        request = json.loads(data)
        action = request.get("action")

        if action == "register":
            username = request["username"]
            password = request["password"]
            if username in accounts:
                response = {"status": "error", "message": "Username Already Exists"}
            else:
                hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                accounts[username] = {"password": hashed_password, "balance": 0}
                response = {"status": "success", "message": "Account Created"}

        elif action == "authenticate":
            username = request["username"]
            password = request["password"]
            if username in accounts and bcrypt.checkpw(password.encode(), accounts[username]["password"]):
                response = {"status": "success", "master_secret": base64.b64encode(master_secret_key).decode()}
            else:
                response = {"status": "error", "message": "Invalid Credentials"}

        elif action in ["deposit", "withdraw", "balance"]:
            username = request["username"]
            if action in ["deposit", "withdraw"]:
                encrypted_data = request["data"]
                mac = request["mac"]

                key = SHA256.new(master_secret_key).digest()
                encryption_key = key[:16]
                mac_key = key[16:]

                decrypted_data = decrypt_message(encrypted_data, encryption_key)
                if not verify_mac(decrypted_data, mac, mac_key):
                    response = {"status": "error", "message": "MAC Verification Failed"}
                else:
                    amount = int(decrypted_data.split(":")[-1])
                    if action == "deposit":
                        accounts[username]["balance"] += amount
                        response = {"status": "success", "message": "Deposit Successful"}
                    elif action == "withdraw":
                        if accounts[username]["balance"] >= amount:
                            accounts[username]["balance"] -= amount
                            response = {"status": "success", "message": "Withdrawal Successful"}
                        else:
                            response = {"status": "error", "message": "Insufficient Funds!"}
               
                audit_transaction(username, action, encryption_key, mac_key)

            elif action == "balance":
                balance_request = request["data"]
                mac = request["mac"]

                key = SHA256.new(master_secret_key).digest()
                encryption_key = key[:16]
                mac_key = key[16:]

                decrypted_balance_request = decrypt_message(balance_request, encryption_key)

                if not verify_mac(decrypted_balance_request, mac, mac_key):
                    response = {"status": "error", "message": "MAC Verification Failed"}
                else:
                    balance_message = f"{username}: {accounts[username]["balance"]}"
                    encrypted_balance = encrypt_message(balance_message, encryption_key)
                    mac_balance = generate_mac(balance_message, mac_key)
                    response = {"status": "success", "encrypted_balance": encrypted_balance, "mac": mac_balance}

                audit_transaction(username, action, encryption_key, mac_key)

        else:
            response = {"status": "error", "message": "Invalid Action!"}

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
