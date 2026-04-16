from flask import Flask, request, render_template_string
import subprocess
import re

app = Flask(__name__)

# WAF - Block malicious patterns
BLACKLIST = [
    r';',       # semicolon
    r'\|',      # pipe
    r'&',       # ampersand
    r'`',       # backtick
    r'\$\(',    # $(
    r'cat',     # cat command
    r'flag',    # flag keyword
    r'ls',      # ls command
    r'less',    # less command
    r'more',    # more command
    r'head',    # head command
    r'tail',    # tail command
    r'nl',      # nl command
    r'od',      # od command
    r'xxd',     # xxd command
    r'base64',  # base64 command
    r'nc',      # netcat
    r'curl',    # curl
    r'wget',    # wget
    r'python',  # python
    r'perl',    # perl
    r'ruby',    # ruby
    r'php',     # php
    r'grep',    # grep
    r'awk',     # awk
    r'sed',     # sed
]

def waf_check(input_str):
    for pattern in BLACKLIST:
        if re.search(pattern, input_str, re.IGNORECASE):
            return False
    return True

HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Ping-o-Matic - Stadium Network Monitor</title>
    <style>
        body { font-family: monospace; background: #0a0a0a; color: #0f0; padding: 20px; }
        input { background: #1a1a1a; color: #0f0; border: 1px solid #0f0; padding: 5px; }
        button { background: #0a0a0a; color: #0f0; border: 1px solid #0f0; padding: 5px 10px; cursor: pointer; }
        pre { background: #1a1a1a; padding: 10px; border-left: 3px solid #0f0; }
    </style>
</head>
<body>
    <h1>🏟️ Agadir Stadium Network Monitor</h1>
    <p>Enter IP address to ping:</p>
    <form method="GET">
        <input type="text" name="ip" placeholder="127.0.0.1" size="40">
        <button type="submit">Ping</button>
    </form>
    {% if result %}
    <h3>Result:</h3>
    <pre>{{ result }}</pre>
    {% endif %}
    <hr>
    <small>Security filters active. Only ping allowed.</small>
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
        if not waf_check(ip):
            result = "⛔ Access Denied: Malicious input detected"
        else:
            try:
                cmd = f"ping -c 1 {ip}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                result = result.stdout + result.stderr
                if not result:
                    result = "No response"
            except Exception as e:
                result = f"Error: {str(e)}"
    
    return render_template_string(HTML, result=result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
