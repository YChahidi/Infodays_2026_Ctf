from flask import Flask, request, make_response, render_template_string
import base64
import json
import os

app = Flask(__name__)

FLAG = os.environ.get("FLAG", "INFODAYS{b64_d3c0d3_f0und}")

HTML = """
<!DOCTYPE html>
<html>
<head><title>Secure Admin Panel</title></head>
<body>
    <h1>System Dashboard</h1>
    {% if is_admin %}
        <div style="background: #e1ffdc; padding: 20px; border: 2px solid green;">
            <h3>Access Granted: Administrator</h3>
            <p>Flag: <b>{{ flag }}</b></p>
        </div>
    {% else %}
        <div style="background: #ffdbdb; padding: 20px; border: 2px solid red;">
            <h3>Access Denied</h3>
            <p>Welcome, <b>{{ user }}</b>. Only the system 'admin' can view the flag.</p>
        </div>
    {% endif %}
    </body>
</html>
"""

SPLASH = '''<!doctype html>
<html><head><meta charset="utf-8"><title>VIP Access</title>
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
<div class="t"><h1>&#x1F451; <span>VIP Access</span></h1>
<p>Session Inspector</p></div>
</body></html>'''

@app.route('/')
def splash():
    return SPLASH

@app.route('/app')
def index():
    session_cookie = request.cookies.get('session_data')
    
    if not session_cookie:
        # Default session: {"user": "guest", "is_admin": false}
        default_data = {"user": "guest", "is_admin": False}
        json_str = json.dumps(default_data)
        encoded = base64.b64encode(json_str.encode()).decode()
        
        resp = make_response(render_template_string(HTML, user="guest", is_admin=False, flag=FLAG))
        resp.set_cookie('session_data', encoded)
        return resp

    try:
        # Decode the Base64 cookie
        decoded = base64.b64decode(session_cookie).decode()
        data = json.loads(decoded)
        return render_template_string(HTML, user=data.get('user'), is_admin=data.get('is_admin'), flag=FLAG)
    except:
        return "Invalid session data!", 400

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
