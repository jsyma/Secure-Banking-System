import socket
import json
import os
import base64
import tkinter as tk
from tkinter import messagebox, simpledialog
from Crypto.Hash import SHA256
from utils import encrypt_message, decrypt_message, generate_mac, verify_mac
from dotenv import load_dotenv

class BankApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ATM Client")
        self.root.geometry("500x400")
        
        self.username = None
        self.master_secret = None
        self.encryption_key = None
        self.mac_key = None
        load_dotenv()

        self.master_secret_key = base64.b64decode(os.getenv("MASTER_SECRET_KEY"))

        self.main_frame = tk.Frame(self.root, bg="#f0f0f0")
        self.main_frame.pack(padx=40, pady=40, expand=True)

        self.username_label = tk.Label(self.main_frame, text="Username:", font=("Courier", 14), bg="#f0f0f0")
        self.username_label.grid(row=0, column=0, pady=20, sticky="w")
        self.username_entry = tk.Entry(self.main_frame, font=("Courier", 12))
        self.username_entry.grid(row=0, column=1, pady=20, sticky="w")

        self.password_label = tk.Label(self.main_frame, text="Password:", font=("Courier", 14), bg="#f0f0f0")
        self.password_label.grid(row=1, column=0, pady=20, sticky="w" )
        self.password_entry = tk.Entry(self.main_frame, font=("Courier", 12), show="*")
        self.password_entry.grid(row=1, column=1, pady=20, sticky="w")

        self.register_button = tk.Button(self.main_frame, text="Register", command=self.register, font=("Courier", 12), bg="#0049B7", fg="white", relief="raised", padx=20, pady=10)
        self.register_button.grid(row=2, column=0, pady=20, sticky="w")

        self.login_button = tk.Button(self.main_frame, text="Login", command=self.login, font=("Courier", 12), bg="#4681f4", fg="white", relief="raised", padx=20, pady=10)
        self.login_button.grid(row=2, column=1, pady=20, sticky="e")

        self.transaction_frame = tk.Frame(self.root, bg="#f0f0f0")
        self.welcome_label = tk.Label(self.transaction_frame, text="", font=("Courier", 14), bg="#f0f0f0", fg="#333333")
        self.welcome_label.grid(row=0, column=0, pady=20)

        self.deposit_button = tk.Button(self.transaction_frame, text="Deposit", command=self.deposit, font=("Courier", 12), bg="#14A073", fg="white", relief="raised", padx=20, pady=10)
        self.deposit_button.grid(row=1, column=0, pady=10, sticky="nsew")

        self.withdraw_button = tk.Button(self.transaction_frame, text="Withdraw", command=self.withdraw, font=("Courier", 12), bg="#C1121F", fg="white", relief="raised", padx=20, pady=10)
        self.withdraw_button.grid(row=2, column=0, pady=10, sticky="nsew")

        self.check_balance_button = tk.Button(self.transaction_frame, text="Check Balance", command=self.check_balance, font=("Courier", 12), bg="#4871e9", fg="white", relief="raised", padx=20, pady=10)
        self.check_balance_button.grid(row=3, column=0, pady=10, sticky="nsew")
  
        self.transaction_frame.pack_forget()

    def communicate_with_bank(self, request):
        bank_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bank_socket.connect(("127.0.0.1", 8000))
        bank_socket.sendall(json.dumps(request).encode())
        response = json.loads(bank_socket.recv(1024).decode())
        bank_socket.close()
        return response

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        response = self.communicate_with_bank({"action": "register", "username": username, "password": password})
        messagebox.showinfo("Register", response["message"])

        if response["status"] == "success":
            self.username = username
            messagebox.showinfo("Register", "Registration Successful. Please Login.")
        else:
            messagebox.showerror("Register", "Registration Failed.")

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        response = self.communicate_with_bank({"action": "authenticate", "username": username, "password": password})
        if response["status"] == "success":
            messagebox.showinfo("Login", "Authentication Successful!")
            self.username = username
            self.master_secret = base64.b64decode(response["master_secret"])
            key = SHA256.new(self.master_secret).digest()
            self.encryption_key = key[:16]
            self.mac_key = key[16:]
            self.main_frame.pack_forget()
            self.transaction_frame.pack(padx=20, pady=20)            
            self.welcome_label.config(text=f"Welcome, {self.username}!\n\nHow can we help you today?")
        else:
            messagebox.showerror("Login", "Authentication Failed.")

    def check_balance(self):
        message = f"{self.username}: Balance Inquiry"
        encrypted_data = encrypt_message(message, self.encryption_key)
        mac = generate_mac(message, self.mac_key)
        response = self.communicate_with_bank({
            "action": "balance", 
            "username": self.username,
            "data": encrypted_data,
            "mac": mac
        })

        if response["status"] == "success":
            encrypted_balance = response["encrypted_balance"]
            balance_mac = response["mac"]
            decrypted_balance = decrypt_message(encrypted_balance, self.encryption_key)
            _, balance = decrypted_balance.split(": ")                
            if verify_mac(decrypted_balance, balance_mac, self.mac_key):
                messagebox.showinfo("Balance", f"Your Balance is: {balance}")
            else:
                messagebox.showerror("Balance", "Integrity check failed!")
        else:
            messagebox.showerror("Balance", response["message"])

    def deposit(self):
        amount = simpledialog.askinteger("Amount", "Enter Amount:")
        if amount:
            message = f"{self.username}: {amount}"
            encrypted_data = encrypt_message(message, self.encryption_key)
            mac = generate_mac(message, self.mac_key)
            response = self.communicate_with_bank({
                "action": "deposit",
                "username": self.username,
                "data": encrypted_data,
                "mac": mac
            })
            messagebox.showinfo("Deposit", response["message"])

    def withdraw(self):
        amount = simpledialog.askinteger("Amount", "Enter Amount:")
        if amount:
            message = f"{self.username}: {amount}"
            encrypted_data = encrypt_message(message, self.encryption_key)
            mac = generate_mac(message, self.mac_key)
            response = self.communicate_with_bank({
                "action": "withdraw",
                "username": self.username,
                "data": encrypted_data,
                "mac": mac
            })
            messagebox.showinfo("Withdraw", response["message"])

if __name__ == "__main__":
    root = tk.Tk()
    app = BankApp(root)
    root.mainloop()
