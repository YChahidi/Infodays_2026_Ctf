from flask import Flask, request, make_response, render_template_string, redirect
import jwt
import datetime
import json

app = Flask(__name__)

# Weak secret — crackable with rockyou.txt: "football"
JWT_SECRET = "football"

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>VIP Access Portal</title>
    <style>
        body { background:#0a0a0a; color:#0f0; font-family:monospace; padding:40px; text-align:center; }
        .box { display:inline-block; border:2px solid #0f0; padding:30px; border-radius:8px; }
        .denied { color:#f00; border-color:#f00; }
        .granted { color:#0f0; background:#001a00; }
        code { background:#111; padding:3px 6px; border-radius:3px; }
    </style>
</head>
<body>
<div class="box {% if is_vip %}granted{% else %}denied{% endif %}">
    {% if is_vip %}
        <h2>✅ VIP ACCESS GRANTED</h2>
        <p>Welcome, <b>{{ username }}</b></p>
        <p>🏟️ Flag: <b>INFODAYS{JWT_W34K_S3CR3T_CR4CK3D_2030}</b></p>
    {% else %}
        <h2>❌ ACCESS DENIED</h2>
        <p>Welcome, <b>{{ username }}</b>. Your clearance level is insufficient.</p>
        <p>VIP access requires <code>role: vip</code> in your session token.</p>
        <br>
        <small style="color:#555">Token accepted. Signature verified. Role insufficient.</small>
    {% endif %}
</div>
</body>
</html>
"""

def make_guest_token():
    payload = {
        "username": "guest",
        "role": "viewer",
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=6)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

@app.route('/')
def index():
    token = request.cookies.get('vip_token')

    if not token:
        token = make_guest_token()
        resp = make_response(render_template_string(HTML, username="guest", is_vip=False))
        resp.set_cookie('vip_token', token, httponly=False)  # intentionally readable
        return resp

    # VULNERABILITY: weak secret + only checks role field
    try:
        # Strictly require HS256 — no algorithm confusion here
        # The weakness is purely the crackable secret
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        is_vip = data.get("role") == "vip"
        username = data.get("username", "unknown")
        return render_template_string(HTML, username=username, is_vip=is_vip)
    except jwt.ExpiredSignatureError:
        resp = make_response(redirect('/'))
        resp.delete_cookie('vip_token')
        return resp
    except jwt.InvalidTokenError as e:
        return render_template_string(HTML, username="invalid", is_vip=False), 401

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
