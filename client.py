import socket
import json
import base64
from Crypto.Hash import SHA256
from utils import encrypt_message, decrypt_message, generate_mac, verify_mac

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
    
    # Send the registration request to the bank server
    response = communicate_with_bank({"action": "register", "username": username, "password": password})
    print(response["message"] + "\nProceeding to Log In...")
    
    if response["status"] == "success":
        # Automatically log the user in after successful registration
        username, master_secret = authenticate()
        return username, master_secret

    return None, None  # Return None if registration fails

def authenticate():
    username = input("Enter Username: ")
    password = input("Enter Password: ")

    # Send authentication request to bank server
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
        username, master_secret = register()
        if not username: 
            return 
        
    if choice == "2":
        username, master_secret = authenticate()
        if not username:
            return

    key = SHA256.new(master_secret).digest()
    encryption_key = key[:16]
    mac_key = key[16:]

    while True:
        print("\n1. Deposit\n2. Withdraw\n3. Check Balance\n4. Exit")
        choice = input("How Many We Help You Today! ")

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
            message = f"{username}: balance inquiry"
            encrypted_data = encrypt_message(message, encryption_key)
            mac = generate_mac(message, mac_key)
            transaction_response = communicate_with_bank({
                "action": "balance", 
                "username": username,
                "data": encrypted_data,
                "mac": mac
            })
            if transaction_response["status"] == "success":
                encrypted_balance = transaction_response["encrypted_balance"]
                balance_mac = transaction_response["mac"]
                decrypted_balance = decrypt_message(encrypted_balance, encryption_key)
                _, balance = decrypted_balance.split(": ")                
                if not verify_mac(decrypted_balance, balance_mac, mac_key):
                    print("Integrity check failed!")
                else:
                    print(f"Balance: {balance}")
            else:
                print(transaction_response["message"])

        elif choice == "4":
            print("Exiting ATM...")
            break

if __name__ == "__main__":
    main()