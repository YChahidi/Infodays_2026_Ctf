from flask import Flask, request, jsonify, render_template_string, session, send_file, make_response, redirect
import graphene
import jwt
import datetime
import hashlib
import os
import pickle
import base64
import sqlite3
import threading
import time
import json
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'referee_system_2030_change_me_in_production')

# Database setup function
def get_db():
    conn = sqlite3.connect('/tmp/referee.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY,
                  username TEXT UNIQUE,
                  password TEXT,
                  role TEXT,
                  api_key TEXT)''')
    
    # Decisions table
    c.execute('''CREATE TABLE IF NOT EXISTS decisions
                 (id INTEGER PRIMARY KEY,
                  match_id TEXT,
                  referee_id INTEGER,
                  decision_data TEXT,
                  status TEXT,
                  approved_by INTEGER,
                  created_at INTEGER)''')
    
    # Reports queue table
    c.execute('''CREATE TABLE IF NOT EXISTS reports_queue
                 (id INTEGER PRIMARY KEY,
                  decision_id INTEGER,
                  template TEXT,
                  status TEXT,
                  created_at INTEGER)''')
    
    # Check if users exist
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        users = [
            (1, 'referee_ahmed', hashlib.sha256(b'password123').hexdigest(), 'referee', 'ref_key_001'),
            (2, 'referee_youssef', hashlib.sha256(b'password456').hexdigest(), 'referee', 'ref_key_002'),
            (3, 'admin_system', hashlib.sha256(b'AdminPass2030!').hexdigest(), 'admin', 'admin_master_key'),
            (4, 'reviewer', hashlib.sha256(b'review123').hexdigest(), 'reviewer', 'review_key_001')
        ]
        c.executemany('INSERT INTO users VALUES (?,?,?,?,?)', users)
    
    # Check if decisions exist
    c.execute("SELECT COUNT(*) FROM decisions")
    if c.fetchone()[0] == 0:
        c.execute("""INSERT INTO decisions 
                     (id, match_id, referee_id, decision_data, status, approved_by, created_at) 
                     VALUES (100, 'FINAL_2030', 1, '{"result": "Morocco wins", "notes": "FLAG: INFODAYS{G4D_C0M80_W1TH_7R1CKS_2030}"}', 'pending', NULL, ?)""",
                     (int(time.time()),))
    
    conn.commit()
    conn.close()

# GraphQL Types
class Decision(graphene.ObjectType):
    id = graphene.Int()
    match_id = graphene.String()
    referee_id = graphene.Int()
    decision_data = graphene.String()
    status = graphene.String()

class Query(graphene.ObjectType):
    get_decision = graphene.Field(Decision, decision_id=graphene.Int(required=True))
    list_decisions = graphene.List(Decision, status=graphene.String())
    
    # VULNERABILITY 1: SQL Injection
    def resolve_get_decision(self, info, decision_id):
        conn = get_db()
        c = conn.cursor()
        query = f"SELECT id, match_id, referee_id, decision_data, status FROM decisions WHERE id = {decision_id}"
        result = c.execute(query).fetchone()
        conn.close()
        
        if result:
            return Decision(id=result[0], match_id=result[1], referee_id=result[2], 
                          decision_data=result[3], status=result[4])
        return None
    
    def resolve_list_decisions(self, info, status=None):
        conn = get_db()
        c = conn.cursor()
        if status:
            query = f"SELECT id, match_id, referee_id, decision_data, status FROM decisions WHERE status = '{status}'"
        else:
            query = "SELECT id, match_id, referee_id, decision_data, status FROM decisions"
        
        results = c.execute(query).fetchall()
        conn.close()
        return [Decision(id=r[0], match_id=r[1], referee_id=r[2], decision_data=r[3], status=r[4]) for r in results]

class CreateDecision(graphene.Mutation):
    class Arguments:
        match_id = graphene.String(required=True)
        decision_data = graphene.String(required=True)
    
    success = graphene.Boolean()
    decision_id = graphene.Int()
    
    def mutate(self, info, match_id, decision_data):
        token = request.cookies.get('jwt_token')
        if not token:
            return CreateDecision(success=False)
        
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            referee_id = payload.get('user_id')
            
            conn = get_db()
            c = conn.cursor()
            c.execute("INSERT INTO decisions (match_id, referee_id, decision_data, status, created_at) VALUES (?, ?, ?, 'pending', ?)",
                     (match_id, referee_id, decision_data, int(time.time())))
            decision_id = c.lastrowid
            conn.commit()
            conn.close()
            
            return CreateDecision(success=True, decision_id=decision_id)
        except:
            return CreateDecision(success=False)

class ApproveDecision(graphene.Mutation):
    class Arguments:
        decision_id = graphene.Int(required=True)
        reviewer_notes = graphene.String()
    
    success = graphene.Boolean()
    
    def mutate(self, info, decision_id, reviewer_notes=None):
        token = request.cookies.get('jwt_token')
        if not token:
            return ApproveDecision(success=False)
        
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            
            # VULNERABILITY 2: Race Condition
            time.sleep(0.2)
            
            conn = get_db()
            c = conn.cursor()
            
            c.execute("SELECT status FROM decisions WHERE id = ?", (decision_id,))
            status = c.fetchone()
            
            if status and status[0] == 'pending':
                time.sleep(0.1)
                
                c.execute("UPDATE decisions SET status = 'approved', approved_by = ? WHERE id = ?",
                         (payload['user_id'], decision_id))
                
                if reviewer_notes:
                    c.execute("INSERT INTO reports_queue (decision_id, template, status, created_at) VALUES (?, ?, 'pending', ?)",
                             (decision_id, reviewer_notes, int(time.time())))
                
                conn.commit()
                conn.close()
                return ApproveDecision(success=True)
            
            conn.close()
            return ApproveDecision(success=False)
        except:
            return ApproveDecision(success=False)

class Mutation(graphene.ObjectType):
    create_decision = CreateDecision.Field()
    approve_decision = ApproveDecision.Field()

schema = graphene.Schema(query=Query, mutation=Mutation)

# JWT Functions
def generate_token(user_id, username, role):
    payload = {
        'user_id': user_id,
        'username': username,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def verify_token(token):
    # VULNERABILITY 3: JWT Algorithm Confusion
    try:
        return jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256', 'none'])
    except:
        try:
            return jwt.decode(token, options={'verify_signature': False})
        except:
            return None

# GraphQL endpoint handler
@app.route('/graphql', methods=['POST'])
def graphql_endpoint():
    data = request.get_json()
    query = data.get('query', '')
    variables = data.get('variables', {})
    
    result = schema.execute(query, variables=variables, context_value={'request': request})
    
    if result.errors:
        return jsonify({'errors': [str(e) for e in result.errors]})
    return jsonify({'data': result.data})

@app.route('/graphql', methods=['GET'])
def graphql_playground():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>GraphQL Playground</title>
        <style>
            body { background:#0a0a0a; color:#0f0; font-family:monospace; padding:20px; }
            textarea { background:#000; color:#0f0; border:1px solid #0f0; width:100%; height:200px; font-family:monospace; }
            button { background:#0f0; color:#000; padding:10px; margin:10px; cursor:pointer; }
            pre { background:#000; padding:10px; border:1px solid #0f0; overflow:auto; }
        </style>
    </head>
    <body>
        <h1>📊 GraphQL Playground</h1>
        <textarea id="query" rows="10" cols="80">
query {
  getDecision(decisionId: 1) {
    id
    matchId
    decisionData
    status
  }
}
        </textarea>
        <br>
        <button onclick="send()">Execute Query</button>
        <pre id="result"></pre>
        <script>
        function send() {
            const query = document.getElementById('query').value;
            fetch('/graphql', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({query: query})
            }).then(r => r.json()).then(d => {
                document.getElementById('result').innerText = JSON.stringify(d, null, 2);
            }).catch(e => {
                document.getElementById('result').innerText = 'Error: ' + e;
            });
        }
        </script>
        <p><a href="/">Back</a></p>
    </body>
    </html>
    '''

# Web Routes
@app.route('/')
def index():
    return '''<!doctype html>
<html><head><meta charset="utf-8"><title>Referee Decision System</title>
<style>*{margin:0;padding:0}body{background:#050a12;overflow:hidden}
.s{width:100vw;height:100vh}
.s img{width:100%;height:100%;object-fit:cover}
.o{position:fixed;inset:0;background:linear-gradient(to bottom,rgba(5,10,18,.1),rgba(5,10,18,.05) 40%,rgba(5,10,18,.5) 80%,rgba(5,10,18,.95));pointer-events:none}
.t{position:fixed;bottom:60px;width:100%;text-align:center;z-index:2;font-family:Inter,system-ui,sans-serif}
.t h1{font-size:48px;font-weight:800;color:#fff;text-shadow:0 2px 40px rgba(0,0,0,.8)}
.t h1 span{color:#5e9fff}
.t p{color:#8899b5;font-size:14px;letter-spacing:2px;text-transform:uppercase;margin-top:8px}
</style></head><body>
<div class="s"><img src="/static/evil.gif" alt=""></div>
<div class="o"></div>
<div class="t"><h1>&#x1F3C6; <span>Referee</span> Decision System</h1>
<p>FIFA 2030 Match Management</p></div>
</body></html>'''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db()
        c = conn.cursor()
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        c.execute("SELECT id, username, role FROM users WHERE username = ? AND password = ?", (username, password_hash))
        user = c.fetchone()
        conn.close()
        
        if user:
            token = generate_token(user[0], user[1], user[2])
            resp = make_response(redirect('/dashboard'))
            resp.set_cookie('jwt_token', token, httponly=True)
            return resp
        
        return "Invalid credentials", 401
    
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>Login - FIFA 2030</title></head>
    <body style="background:#0a0a0a;color:#0f0;font-family:monospace;padding:50px;">
        <h1>Referee Login</h1>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" style="background:#000;color:#0f0;border:1px solid #0f0;padding:10px;margin:5px;width:200px;">
            <br>
            <input type="password" name="password" placeholder="Password" style="background:#000;color:#0f0;border:1px solid #0f0;padding:10px;margin:5px;width:200px;">
            <br>
            <button type="submit" style="background:#0f0;color:#000;padding:10px;margin:5px;">Login</button>
        </form>
        <p>Test credentials: <code>referee_ahmed / password123</code></p>
        <p><a href="/">Back</a></p>
    </body>
    </html>
    '''

@app.route('/dashboard')
def dashboard():
    token = request.cookies.get('jwt_token')
    if not token:
        return redirect('/login')
    
    payload = verify_token(token)
    if not payload:
        return redirect('/login')
    
    return render_template_string(f'''
    <!DOCTYPE html>
    <html>
    <head><title>Dashboard - FIFA 2030</title></head>
    <body style="background:#0a0a0a;color:#0f0;font-family:monospace;padding:50px;">
        <h1>Referee Dashboard</h1>
        <p>Welcome <strong>{payload.get('username')}</strong> (Role: {payload.get('role')})</p>
        <p>User ID: {payload.get('user_id')}</p>
        <p>JWT Token: <code>{token[:50]}...</code></p>
        <hr>
        <p><a href="/graphql">📊 GraphQL Playground</a></p>
        <p><a href="/report">📄 Generate Report</a></p>
        <p><a href="/logout">🚪 Logout</a></p>
    </body>
    </html>
    ''')

@app.route('/report')
def report():
    # VULNERABILITY 4: SSTI in template rendering
    template = request.args.get('template', '<h2>Match Report</h2><p>{{ data }}</p>')
    
    from jinja2 import Template
    try:
        tmpl = Template(template)
        result = tmpl.render(data="Morocco wins 2-0")
        return render_template_string(f'''
        <!DOCTYPE html>
        <html>
        <head><title>Report Generator</title></head>
        <body style="background:#0a0a0a;color:#0f0;font-family:monospace;padding:50px;">
            <h1>📄 Match Report</h1>
            <div style="background:#000;padding:20px;border:1px solid #0f0;">
                {result}
            </div>
            <p><a href="/">Back</a></p>
        </body>
        </html>
        ''')
    except Exception as e:
        return f"Error: {e}"

@app.route('/admin/backup')
def admin_backup():
    # VULNERABILITY 5: Path Traversal
    file = request.args.get('file', 'backup.db')
    
    if not file.endswith('.db'):
        return "Only .db files allowed", 403
    
    try:
        return send_file(f'/tmp/backups/{file}')
    except:
        return "File not found", 404

@app.route('/admin/upload', methods=['POST'])
def admin_upload():
    # VULNERABILITY 6: Insecure Deserialization
    token = request.cookies.get('jwt_token')
    if not token:
        return "Unauthorized", 401
    
    payload = verify_token(token)
    if not payload or payload.get('role') != 'admin':
        return "Admin only", 403
    
    data = request.get_data()
    try:
        obj = pickle.loads(data)
        return f"Object loaded: {obj}"
    except:
        return "Invalid data", 400

@app.route('/api/process_reports')
def process_reports():
    conn = get_db()
    c = conn.cursor()
    
    reports = c.execute("SELECT id, decision_id, template FROM reports_queue WHERE status = 'pending'").fetchall()
    
    for report in reports:
        try:
            from jinja2 import Template
            c.execute("SELECT decision_data FROM decisions WHERE id = ?", (report[1],))
            decision = c.fetchone()
            if decision:
                tmpl = Template(report[2])
                result = tmpl.render(data=decision[0])
                c.execute("UPDATE reports_queue SET status = 'processed' WHERE id = ?", (report[0],))
                conn.commit()
                
                os.makedirs('/tmp/reports', exist_ok=True)
                with open(f'/tmp/reports/report_{report[0]}.html', 'w') as f:
                    f.write(result)
        except:
            pass
    
    conn.close()
    return "Processed"

@app.route('/flag')
def flag():
    token = request.cookies.get('jwt_token')
    if not token:
        return "No token", 403
    
    payload = verify_token(token)
    if not payload:
        return "Invalid token", 403
    
    conn = get_db()
    c = conn.cursor()
    
    # Check all conditions independently
    c.execute("SELECT COUNT(*) FROM decisions WHERE decision_data LIKE '%UNION%'")
    sql_injection = c.fetchone()[0] > 0
    
    c.execute("SELECT COUNT(*) FROM reports_queue WHERE template LIKE '%__class__%'")
    ssti = c.fetchone()[0] > 0
    
    c.execute("SELECT COUNT(*) FROM reports_queue WHERE template LIKE '%../../%'")
    traversal = c.fetchone()[0] > 0
    
    conn.close()
    
    # Collect all triggered flags
    flags = []
    
    
    if sql_injection:
        flags.append("INFODAYS{SQL_INJECTION_GRAPHQL_2030}")
    
    if ssti:
        flags.append("INFODAYS{JINJA2_SSTI_W1TH_GRAPHQL_2030}")
    
    if traversal:
        flags.append("INFODAYS{P4TH_TR4V3RSAL_BACKUP_2030}")
    
    if flags:
        return "\n".join(flags)
    else:
        return "Keep exploiting! You haven't found the flag yet."

@app.route('/robots.txt')
def robots():
    return '''User-agent: *
Disallow: /admin/
Disallow: /api/
Disallow: /debug/

# Hidden endpoints:
# /flag - get flag if conditions met
# /api/process_reports - process pending reports

# Admin credentials: admin_system / AdminPass2030!
# Referee credentials: referee_ahmed / password123
'''

@app.route('/logout')
def logout():
    resp = make_response(redirect('/'))
    resp.set_cookie('jwt_token', '', expires=0)
    return resp

def redirect(url):
    from flask import redirect as flask_redirect
    return flask_redirect(url)

if __name__ == '__main__':
    os.makedirs('/tmp/backups', exist_ok=True)
    os.makedirs('/tmp/reports', exist_ok=True)
    
    with open('/tmp/backups/backup.db', 'w') as f:
        f.write("Fake backup data")
    
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
