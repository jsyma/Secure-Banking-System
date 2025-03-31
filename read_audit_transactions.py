import os
import json
import base64
from Crypto.Hash import SHA256
from dotenv import load_dotenv
from utils import decrypt_message, verify_mac

load_dotenv()

LOG_FILE = "audit_transactions.txt"

def read_audit_log():
    if not os.path.exists(LOG_FILE):
        print("Audit Log File Not Found")
        return
    
    master_secret_key = base64.b64decode(os.getenv("MASTER_SECRET_KEY"))
    key = SHA256.new(master_secret_key).digest()
    encryption_key = key[:16]
    mac_key = key[16:]
    
    with open(LOG_FILE, "r") as log_file:
        for line in log_file:
            try:
                transcation = json.loads(line.strip())
                encrypted_audit_message = transcation["Transaction"]
                audit_mac = transcation["MAC"]

                decrypted_log = decrypt_message(encrypted_audit_message, encryption_key)

                if verify_mac(decrypted_log, audit_mac, mac_key):
                    print(f"Valid Log: {decrypted_log}")
                else:
                    print("Integrity Check Failed for Log Entry")
            except Exception as e:
                print(f"Error: {e}")

if __name__ == "__main__":
    read_audit_log()
