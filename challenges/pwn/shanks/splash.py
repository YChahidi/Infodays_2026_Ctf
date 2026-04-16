from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    return '''<!doctype html>
<html><head><meta charset="utf-8"><title>SHANKS</title>
<style>*{margin:0;padding:0}body{background:#050a12;overflow:hidden}
.s{width:100vw;height:100vh}
.s img{width:100%;height:100%;object-fit:cover}
.o{position:fixed;inset:0;background:linear-gradient(to bottom,rgba(5,10,18,.1),rgba(5,10,18,.05) 40%,rgba(5,10,18,.5) 80%,rgba(5,10,18,.95));pointer-events:none}
.t{position:fixed;bottom:60px;width:100%;text-align:center;z-index:2;font-family:Inter,system-ui,sans-serif}
.t h1{font-size:48px;font-weight:800;color:#fff;text-shadow:0 2px 40px rgba(0,0,0,.8)}
.t h1 span{color:#e74c3c}
.t p{color:#8899b5;font-size:14px;letter-spacing:2px;text-transform:uppercase;margin-top:8px}
</style></head><body>
<div class="s"><img src="/static/shanks.gif" alt=""></div>
<div class="o"></div>
<div class="t"><h1>&#x2693; <span>SHANKS</span></h1>
<p>Red Hair Pirates Crew Roster</p></div>
</body></html>'''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
