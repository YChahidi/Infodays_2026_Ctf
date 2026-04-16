from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

# The front-end template with the World Cup 2030 / Morocco theme
TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Stadium Scout Portal</title>
    <style>
        body { background-color: #1a1a1a; color: white; font-family: sans-serif; text-align: center; padding-top: 50px; }
        .box { border: 2px solid #ce1126; display: inline-block; padding: 20px; border-radius: 10px; background: #2d2d2d; box-shadow: 0 0 15px rgba(0,98,51,0.5); }
        input { padding: 10px; border-radius: 5px; border: none; width: 200px; }
        .btn { background-color: #006233; color: white; padding: 10px 20px; border: none; cursor: pointer; border-radius: 5px; font-weight: bold; }
        .btn:hover { background-color: #008445; }
        .msg { margin-top: 20px; font-weight: bold; min-height: 24px; }
        .footer { margin-top: 30px; font-size: 0.8em; color: #888; }
    </style>
</head>
<body>
    <div class="box">
        <h1>🇲🇦 Stadium Scout Portal</h1>
        <p>World Cup 2030 Security: Verify Player Registration ID</p>
        <form action="/code_search" method="get">
            <input type="text" name="id" placeholder="Enter Player ID (1-11)" required>
            <button type="submit" class="btn">VERIFY</button>
        </form>
        <div class="msg">{{ message|safe }}</div>
        <div class="footer">Securing the Future of the World Cup 2030</div>
    </div>
</body>
</html>
"""

SPLASH = '''<!doctype html>
<html><head><meta charset="utf-8"><title>Scout Database</title>
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
<div class="t"><h1>&#x1F50D; <span>Scout</span> Database</h1>
<p>Stadium Scout Portal</p></div>
</body></html>'''

@app.route('/')
def home():
    return SPLASH

@app.route('/portal')
def portal():
    return render_template_string(TEMPLATE, message="System Ready. Awaiting ID input...")

@app.route('/code_search')
def code_search():
    player_id = request.args.get('id', '')
    message = ""
    
    if player_id:
        # --- THE STADIUM FIREWALL (WAF) ---
        # Blacklisting quotes and spaces forces participants to use CHAR() and /**/
        blacklist = ["'", '"', ' ', 'OR', 'AND', 'UNION']
        for word in blacklist:
            if word in player_id.upper():
                return render_template_string(TEMPLATE, message="<span style='color: #ce1126;'>🚨 Security Alert: Malicious Input Detected!</span>")
        
        try:
            conn = sqlite3.connect('stadium.db')
            # Vulnerable concatenation - requires Boolean Blind SQLi techniques to exploit
            query = f"SELECT * FROM players WHERE id={player_id}"
            result = conn.execute(query).fetchone()
            conn.close()

            if result:
                message = "<span style='color: #006233;'>✅ Player Registered in Database.</span>"
            else:
                message = "<span style='color: #ce1126;'>❌ Player Not Found in Current Lineup.</span>"
        except Exception:
            # Vague errors force the use of Boolean logic (True/False states)
            message = "<span>⚠️ System Error: Please check ID format.</span>"
            
    return render_template_string(TEMPLATE, message=message)

if __name__ == '__main__':
    # Running on port 8005 as configured in your docker-compose
    app.run(host='0.0.0.0', port=8005)
