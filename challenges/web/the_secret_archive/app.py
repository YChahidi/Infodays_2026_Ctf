from flask import Flask, request, render_template_string, send_file, make_response, redirect
import os, base64, hashlib
from functools import wraps

app = Flask(__name__)

# Security configuration
SECRET_KEY = "SECRET_ARCHIVE_ISOLATED_KEY_2026"
XOR_KEY = 0x42

def xor_crypt(data):
    return ''.join([chr(ord(c) ^ XOR_KEY) for c in data])

def session_check(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_token = request.cookies.get('session')
        # Simple session validation based on secret key
        expected = hashlib.md5((SECRET_KEY + "admin").encode()).hexdigest()
        if session_token != expected:
            return redirect('/login_page')
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return '''<!doctype html>
<html><head><meta charset="utf-8"><title>Secret Archive</title>
<style>*{margin:0;padding:0}body{background:#050a12;overflow:hidden}
.s{width:100vw;height:100vh}
.s img{width:100%;height:100%;object-fit:cover}
.o{position:fixed;inset:0;background:linear-gradient(to bottom,rgba(5,10,18,.1),rgba(5,10,18,.05) 40%,rgba(5,10,18,.5) 80%,rgba(5,10,18,.95));pointer-events:none}
.t{position:fixed;bottom:60px;width:100%;text-align:center;z-index:2;font-family:Inter,system-ui,sans-serif}
.t h1{font-size:48px;font-weight:800;color:#fff;text-shadow:0 2px 40px rgba(0,0,0,.8)}
.t h1 span{color:#5e9fff}
.t p{color:#8899b5;font-size:14px;letter-spacing:2px;text-transform:uppercase;margin-top:8px}
</style></head><body>
<div class="s"><img src="/static/0iq.jpeg" alt=""></div>
<div class="o"></div>
<div class="t"><h1>&#x1F512; <span>Secret</span> Archive</h1>
<p>Restricted Management Interface</p></div>
</body></html>'''

@app.route('/login_page')
def login_page():
    return render_template_string('''
    <body style="background:#000;color:#0f0;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;">
        <form method="POST" action="/login" style="border:1px solid #0f0;padding:30px;">
            <h3 style="color:#ff0;">SYSTEM AUTHENTICATION</h3>
            <input type="text" name="username" placeholder="Username" required><br>
            <input type="password" name="password" placeholder="Password" required><br><br>
            <button type="submit">AUTHENTICATE</button>
        </form>
    </body>
    ''')

@app.route('/login', methods=['POST'])
def login():
    if request.form.get('username') == "admin" and request.form.get('password') == "Arch1ve_Adm1n_P4ss!":
        session_token = hashlib.md5((SECRET_KEY + "admin").encode()).hexdigest()
        resp = make_response(redirect('/dashboard'))
        resp.set_cookie('session', session_token, httponly=True)
        return resp
    return "Invalid Credentials", 403

@app.route('/dashboard')
@session_check
def dashboard():
    return render_template_string('''
    <body style="background:#0a0a0a;color:#0f0;font-family:monospace;padding:20px;">
        <h1>📁 Administrative Dashboard</h1>
        <hr style="border:0.5px solid #333;">
        <h3>Available Records:</h3>
        <ul>
            <li><a href="/view?file=news.txt" style="color:#0f0;">system_news_2026.log</a></li>
        </ul>
        </body>
    ''')

@app.route('/view')
@session_check
def view():
    raw_input = request.args.get('file')
    if not raw_input:
        return "Missing parameter: file", 400

    # WAF Check: Filters common traversal patterns in plaintext
    blocked_patterns = ['..', 'flag', '/etc/', '/proc/']
    for pattern in blocked_patterns:
        if pattern in raw_input.lower():
            return "WAF: Malicious Path Traversal Detected!", 403

    # Bypassable Logic: The app decodes AFTER the security check
    try:
        # Step 1: Base64 Decode
        decoded_b64 = base64.b64decode(raw_input).decode()
        # Step 2: XOR Decrypt
        filename = xor_crypt(decoded_b64)
    except:
        # Fallback for standard files like news.txt
        filename = raw_input

    try:
        return send_file(filename)
    except:
        return f"File Not Found: {filename}", 404

@app.route('/robots.txt')
def robots():
    return (
        "User-agent: *\n"
        "Disallow: /debug\n\n"
        "# --- EMERGENCY ACCESS ---\n"
        "# User: admin / Arch1ve_Adm1n_P4ss!\n"
        "# XOR Key: 0x42"
    )

@app.route('/debug')
@session_check # Optional: Keep it protected to force login first
def debug():
    return render_template_string('''
    <body style="background:#000;color:#f00;font-family:monospace;padding:50px;">
        <h3>[SYSTEM DEBUG LOG]</h3>
        <p>Current Working Directory: <b>/home/ctfuser/</b></p>
        <p>Flag Backup Path: <b>/tmp/the_real_flag.txt</b></p>
        <hr style="border:0.5px solid #400;">
        <p style="color:#444;">Note: Debug interface for internal path verification only.</p>
    </body>
    ''')

if __name__ == "__main__":
    # Running on 0.0.0.0 to allow Docker port mapping
    app.run(host='0.0.0.0', port=8080)
