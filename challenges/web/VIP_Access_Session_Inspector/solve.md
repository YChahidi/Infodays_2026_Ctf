📖 Description
The Stadium's VIP management portal uses a specific cookie to track your status. You've found the portal, but as a guest, the doors are locked. Can you inspect your credentials and elevate your access?

Target Address: http://localhost:8003

🕵️ Discovery
Analyze the Headers: Open the Browser Developer Tools (F12) and check the Storage or Application tab under Cookies.

Locate the Target: Instead of the standard session name, you find a cookie specifically named session_data.

Decode the Value: The value of session_data appears to be a Base64 encoded string (e.g., eyJ1c2VyIjogImd1ZXN0IiwgImlzX2FkbWluIjogZmFsc2V9).

Base64 Decode: Using a tool like CyberChef or a terminal, decoding reveals a JSON object:

{"user": "guest", "is_admin": false}

🛠️ Exploitation:

Tamper with the JSON: Change the values to gain privilege:

{"user": "admin", "is_admin": true}

Base64 Re-encode: Take that modified JSON string and encode it back to Base64.

Cookie Injection:

Double-click the value of the session_data cookie in your browser's inspector.

Paste your new Base64 string.

Capture: Refresh the page. The server reads the modified session_data, sees is_admin: true, and displays the VIP flag.

🏁 Flag:

Flag: flag{infodays_b64_d3c0d3_f0und}
