from flask import Flask, request, render_template_string, send_file, make_response, redirect
import os, base64, hashlib
from functools import wraps

app = Flask(__name__)

SECRET_KEY = "SECRET_ARCHIVE_ISOLATED_KEY_2026"
XOR_KEY = 0x17  # Changed — not hinted anywhere obvious

def xor_crypt(data):
    return ''.join([chr(ord(c) ^ XOR_KEY) for c in data])

def session_check(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_token = request.cookies.get('session')
        expected = hashlib.md5((SECRET_KEY + "admin").encode()).hexdigest()
        if session_token != expected:
            return redirect('/login_page')
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template_string('''
    <body style="background:#0a0a0a;color:#0f0;font-family:monospace;text-align:center;padding:50px;">
        <h1>🔐 Secret Archive Gateway</h1>
        <p>Restricted Management Interface — InfoDays 2026</p>
        <a href="/login_page" style="color:#0f0;border:1px solid #0f0;padding:10px;text-decoration:none;">[ ENTER ]</a>
    </body>
    ''')

@app.route('/login_page')
def login_page():
    return render_template_string('''
    <body style="background:#000;color:#0f0;font-family:monospace;display:flex;
                 justify-content:center;align-items:center;height:100vh;">
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
    if request.form.get('username') == "admin" and \
       request.form.get('password') == "Arch1ve_Adm1n_P4ss!":
        token = hashlib.md5((SECRET_KEY + "admin").encode()).hexdigest()
        resp = make_response(redirect('/dashboard'))
        resp.set_cookie('session', token, httponly=True)
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
            <li><a href="/changelog" style="color:#555;font-size:0.85em;">system changelog</a></li>
        </ul>
    </body>
    ''')

@app.route('/changelog')
@session_check
def changelog():
    # Players who read the source of THIS page discover the XOR key embedded in an HTML comment
    # and a reference to the encrypted backup location
    return render_template_string('''
    <body style="background:#0a0a0a;color:#0f0;font-family:monospace;padding:20px;">
        <h1>📋 Changelog</h1>
        <ul>
            <li>2026-03-01: Migrated flag storage to encrypted offsite path</li>
            <li>2026-02-14: Added XOR layer to file viewer for path obfuscation</li>
            <li>2026-01-10: Moved sensitive archive to /opt/archive/classified/</li>
        </ul>
        <!-- backup still accessible via /view with encoded path -->
    </body>
    ''')

@app.route('/robots.txt')
def robots():
    # Credentials only — no key hint this time
    return (
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Disallow: /changelog\n\n"
        "# Maintenance access: admin / Arch1ve_Adm1n_P4ss!\n"
    )

@app.route('/view')
@session_check
def view():
    raw_input = request.args.get('file')
    if not raw_input:
        return "Missing parameter: file", 400

    # WAF on raw input (before decoding)
    blocked_patterns = ['..', 'flag', '/etc/', '/proc/', '/opt/']
    for pattern in blocked_patterns:
        if pattern in raw_input.lower():
            return "WAF: Blocked.", 403

    try:
        decoded_b64 = base64.b64decode(raw_input).decode()
        filename = xor_crypt(decoded_b64)
    except Exception:
        filename = raw_input

    # Secondary check AFTER decode — catches naive bypasses
    # but still bypassable if XOR is applied correctly
    if '..' in filename and 'opt' not in filename:
        return "WAF: Post-decode traversal detected.", 403

    try:
        return send_file(filename)
    except Exception:
        return f"File not found.", 404

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
