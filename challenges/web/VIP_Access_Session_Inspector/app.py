from flask import Flask, request, make_response, render_template_string
import base64
import json

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head><title>Secure Admin Panel</title></head>
<body>
    <h1>System Dashboard</h1>
    {% if is_admin %}
        <div style="background: #e1ffdc; padding: 20px; border: 2px solid green;">
            <h3>Access Granted: Administrator</h3>
            <p>Flag: <b>infodays{b64_d3c0d3_f0und}</b></p>
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

@app.route('/')
def index():
    session_cookie = request.cookies.get('session_data')
    
    if not session_cookie:
        # Default session: {"user": "guest", "is_admin": false}
        default_data = {"user": "guest", "is_admin": False}
        json_str = json.dumps(default_data)
        encoded = base64.b64encode(json_str.encode()).decode()
        
        resp = make_response(render_template_string(HTML, user="guest", is_admin=False))
        resp.set_cookie('session_data', encoded)
        return resp

    try:
        # Decode the Base64 cookie
        decoded = base64.b64decode(session_cookie).decode()
        data = json.loads(decoded)
        return render_template_string(HTML, user=data.get('user'), is_admin=data.get('is_admin'))
    except:
        return "Invalid session data!", 400

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
