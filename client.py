import socket
import json
import base64
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(nonce + tag + ciphertext).decode()

def generate_mac(message, mac_key):
    hmac = HMAC.new(mac_key, message.encode(), SHA256)
    return base64.b64encode(hmac.digest()).decode()

def communicate_with_bank(request):
    bank_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bank_socket.connect(("127.0.0.1", 8000))
    bank_socket.sendall(json.dumps(request).encode())
    response = json.loads(bank_socket.recv(1024).decode())
    bank_socket.close()
    return response

def register():
    username = input("Enter a New Username: ")
    password = input("Enter a New Password: ")
    
    response = communicate_with_bank({"action": "register", "username": username, "password": password})
    print(response["message"])

def authenticate():
    username = input("Enter Username: ")
    password = input("Enter Password: ")

    response = communicate_with_bank({"action": "authenticate", "username": username, "password": password})
    if response["status"] == "success":
        print("Authentication Successful!")
        return username, base64.b64decode(response["master_secret"])
    else:
        print("Authentication Failed.")
        return None, None

def main():
    print("\n1. Register\n2. Login")
    choice = input("New User/Existing User: ")

    if choice == "1":
        register()
        return

    username, master_secret = authenticate()
    if not username:
        return

    key = SHA256.new(master_secret).digest()
    encryption_key = key[:16]
    mac_key = key[16:]

    while True:
        print("\n1. Deposit\n2. Withdraw\n3. Check Balance\n4. Exit")
        choice = input("How Many We Help You Today!")

        if choice in ["1", "2"]:
            amount = input("Enter Amount: ")
            message = f"{username}: {amount}"
            encrypted_data = encrypt_message(message, encryption_key)
            mac = generate_mac(message, mac_key)
            action = "deposit" if choice == "1" else "withdraw"

            transaction_response = communicate_with_bank({
                "action": action,
                "username": username,
                "data": encrypted_data,
                "mac": mac
            })
            print(transaction_response["message"])

        elif choice == "3":
            transaction_response = communicate_with_bank({"action": "balance", "username": username})
            print(f"Balance: {transaction_response['balance']}")

        elif choice == "4":
            print("Exiting ATM...")
            break

if __name__ == "__main__":
    main()
