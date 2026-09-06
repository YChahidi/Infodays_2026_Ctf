from flask import Flask, request, render_template_string
import subprocess
import re
import urllib.parse

app = Flask(__name__)

# Whitelist: only valid IPv4 or simple hostnames
IPV4_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

# Internal-only flag service (simulated — in Docker this would be a real second container)
INTERNAL_FLAG_HOST = "172.20.0.99"  # Only reachable from within Docker network

def waf_check(raw_input):
    # Normalize first — catches %0a, %09, unicode tricks, etc.
    decoded = urllib.parse.unquote(raw_input)
    decoded = urllib.parse.unquote(decoded)  # double decode

    # Strict: must be a valid IPv4
    if not IPV4_RE.match(decoded.strip()):
        return False, "Only IPv4 addresses accepted."

    octets = decoded.strip().split('.')
    for o in octets:
        if not (0 <= int(o) <= 255):
            return False, "Invalid IP range."

    # Block RFC-1918 ranges except the one we want to demo SSRF on
    first = int(octets[0])
    if first == 127 or (first == 10) or (first == 192 and int(octets[1]) == 168):
        return False, "Private ranges blocked."

    return True, decoded.strip()

HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Ping-o-Matic v2 - Stadium Network Monitor</title>
    <style>
        body { font-family: monospace; background: #0a0a0a; color: #0f0; padding: 20px; }
        input { background: #1a1a1a; color: #0f0; border: 1px solid #0f0; padding: 5px; width: 300px; }
        button { background: #0a0a0a; color: #0f0; border: 1px solid #0f0; padding: 5px 10px; cursor: pointer; }
        pre { background: #1a1a1a; padding: 10px; border-left: 3px solid #0f0; white-space: pre-wrap; }
        .hint { color: #555; font-size: 0.8em; margin-top: 30px; border-top: 1px solid #222; padding-top: 10px; }
    </style>
</head>
<body>
    <h1>🏟️ Agadir 2030 - Network Diagnostics</h1>
    <p>Stadium infrastructure ping utility. Enter a target IPv4:</p>
    <form method="GET">
        <input type="text" name="ip" placeholder="e.g. 8.8.8.8" size="40">
        <button type="submit">Ping</button>
    </form>
    {% if result %}
    <h3>Result:</h3>
    <pre>{{ result }}</pre>
    {% endif %}
    <div class="hint">
        <p>Internal monitoring dashboard: <code>http://monitor.stadium.internal/status</code></p>
        <p>Firewall enforces strict IPv4 whitelist. No funny business.</p>
    </div>
</body>
</html>
'''

SPLASH = '''<!doctype html>
<html><head><meta charset="utf-8"><title>Ping-o-Matic</title>
<style>*{margin:0;padding:0}body{background:#050a12;overflow:hidden}
.s{width:100vw;height:100vh}
.s img{width:100%;height:100%;object-fit:cover}
.o{position:fixed;inset:0;background:linear-gradient(to bottom,rgba(5,10,18,.1),rgba(5,10,18,.05) 40%,rgba(5,10,18,.5) 80%,rgba(5,10,18,.95));pointer-events:none}
.t{position:fixed;bottom:60px;width:100%;text-align:center;z-index:2;font-family:Inter,system-ui,sans-serif}
.t h1{font-size:48px;font-weight:800;color:#fff;text-shadow:0 2px 40px rgba(0,0,0,.8)}
.t h1 span{color:#5e9fff}
.t p{color:#8899b5;font-size:14px;letter-spacing:2px;text-transform:uppercase;margin-top:8px}
</style></head><body>
<div class="s"><img src="/static/asshole.jpeg" alt=""></div>
<div class="o"></div>
<div class="t"><h1>&#x1F3D3; <span>Ping-o-Matic</span></h1>
<p>Stadium Network Monitor</p></div>
</body></html>'''

@app.route('/')
def splash():
    return SPLASH

@app.route('/ping')
def index():
    ip = request.args.get('ip', '')
    result = ""

    if ip:
        ok, val = waf_check(ip)
        if not ok:
            result = f"⛔ Blocked: {val}"
        else:
            # Check for SSRF target first
            internal = query_internal(val)
            if internal:
                result = internal
            else:
                try:
                    cmd = ["ping", "-c", "1", "-W", "2", val]
                    out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    result = out.stdout + out.stderr or "No response"
                except Exception as e:
                    result = f"Error: {e}"

    return render_template_string(HTML, result=result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
