"""
BATISTUTA — Infodays 2026 CTF (author: saamnolimits)
Single-container port of the full multi-stage chain under K8s runAsUser:1000.

Routes by layer:
  GET  /                        — index + public nav
  GET  /monitoring/             — login page (client-side-only auth bypass)
  POST /monitoring/api/login    — always returns {"success": false}; attacker
                                  flips the response in their proxy to reach
                                  /monitoring/dashboard (no server-side auth).
  GET  /monitoring/dashboard    — no auth check; links to /status/temp
  GET  /status/temp             — leaks n8n webhook path + wiki URL
  GET  /wiki/                   — wiki index
  GET  /wiki/n8n                — leaks HMAC_SECRET in an "exported flow" JSON
  POST /webhook/<uuid>          — HMAC-checked JSON body; SQLi on `email` with
                                  stacked queries and error-based debug echo
  GET  /restic/backup.7z        — serves the boot-time 7z archive
  POST /vault/crespo            — form: {password}; if matches archive pw,
                                  returns the decrypted user flag
  POST /vault/batistuta         — form: {password}; if matches the pwgen
                                  output for the boot-time (sec,ms), returns
                                  the decrypted root flag
"""
import base64
import hmac
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

from flask import (Flask, Response, abort, jsonify, render_template,
                   request, send_from_directory)
import pymysql
from pymysql.constants import CLIENT

from pow_gate import verify_with_window as pow_verify, POW_BITS, BUCKET_SECONDS

app = Flask(__name__, static_url_path='/static')

DB = dict(
    unix_socket='/var/run/mysqld/mysqld.sock',
    user='n8n', password='3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS',
    database='phishing',
    cursorclass=pymysql.cursors.DictCursor,
    client_flag=CLIENT.MULTI_STATEMENTS,
)

HMAC_SECRET = os.environ['HMAC_SECRET'].encode()
FLAG1_ENC = base64.b64decode(os.environ['FLAG1_ENC_B64'])
FLAG2_ENC = base64.b64decode(os.environ['FLAG2_ENC_B64'])

# ── Per-run webhook UUID. Discoverable via /status/temp and /wiki/n8n.
WEBHOOK_ID = "d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d"


def openssl_decrypt(enc: bytes, password: str) -> bytes | None:
    """Invoke openssl to decrypt an AES-256-CBC PBKDF2 blob. Returns None on fail."""
    try:
        p = subprocess.run(
            ['openssl', 'enc', '-aes-256-cbc', '-d', '-pbkdf2',
             '-pass', f'pass:{password}'],
            input=enc, capture_output=True, timeout=5)
        if p.returncode == 0:
            return p.stdout
    except Exception:
        pass
    return None


# ─── Public pages ────────────────────────────────────────────────────
@app.get('/')
def index():
    return render_template('index.html')


# ─── Monitoring panel (client-side-only auth bypass) ────────────────
@app.get('/monitoring/')
@app.get('/monitoring')
def monitoring_login():
    return render_template('monitoring_login.html')


@app.post('/monitoring/api/login')
def monitoring_api_login():
    # Server ALWAYS replies false. The bypass is that the dashboard has no
    # server-side auth check — attacker proxy-flips the success field.
    return jsonify({"success": False, "reason": "invalid credentials"})


@app.get('/monitoring/dashboard')
def monitoring_dashboard():
    return render_template('monitoring_dash.html')


@app.get('/status/temp')
def status_temp():
    return render_template('status_temp.html', webhook_id=WEBHOOK_ID)


# ─── Wiki — leaks HMAC secret ───────────────────────────────────────
@app.get('/wiki/')
@app.get('/wiki')
def wiki_index():
    return render_template('wiki_index.html')


@app.get('/wiki/n8n')
def wiki_n8n():
    # The "exported flow" JSON baked into the wiki leaks the signing secret.
    flow = {
        "name": "gophish_to_phishing_score",
        "nodes": [
            {
                "name": "Calculate the signature",
                "type": "n8n-nodes-base.crypto",
                "parameters": {
                    "action": "hmac",
                    "type": "SHA256",
                    "value": "={{ JSON.stringify($json.body) }}",
                    "dataPropertyName": "calculated_signature",
                    "secret": HMAC_SECRET.decode(),
                },
            },
            {
                "name": "Get current phishing score",
                "type": "n8n-nodes-base.mySql",
                "parameters": {
                    "operation": "executeQuery",
                    "query": 'SELECT * FROM victims where email = "{{ $json.body.email }}" LIMIT 1',
                },
            },
            {
                "name": "DEBUG: REMOVE SOON",
                "type": "n8n-nodes-base.respondToWebhook",
                "parameters": {
                    "respondWith": "text",
                    "responseBody": "={{ $json.message }} | {{ JSON.stringify($json.error)}}",
                },
            },
        ],
    }
    resp = Response(render_template('wiki_n8n.html',
                                    flow_json=json.dumps(flow, indent=2),
                                    webhook_id=WEBHOOK_ID))
    # Advertise the PoW so honest clients (and writeup readers) see it.
    resp.headers['X-PoW-Bits'] = str(POW_BITS)
    resp.headers['X-PoW-Bucket-Seconds'] = str(BUCKET_SECONDS)
    resp.headers['X-PoW-Scheme'] = 'sha256(uuid:bucket:nonce)'
    return resp


# ─── HMAC-checked webhook with SQLi on email ────────────────────────
@app.post('/webhook/<uuid>')
def webhook(uuid: str):
    if uuid != WEBHOOK_ID:
        return jsonify({"error": "unknown webhook"}), 404

    # PoW gate (#7 anti-automation).  Stateless: every webhook POST
    # must include a fresh nonce that proves CPU work tied to this
    # webhook UUID and the current 5-min UTC bucket.  Prevents
    # AI-driven blind-SQLi enumeration without a real client.
    nonce = request.headers.get('X-PoW-Nonce', '')
    if not pow_verify(uuid, nonce):
        return jsonify({
            "error": "proof-of-work invalid or missing",
            "hint": (f"X-PoW-Nonce: hex(sha256(uuid:bucket:nonce)) must start "
                     f"with {POW_BITS} zero bits, bucket=int(time/{BUCKET_SECONDS})"),
        }), 429

    sig_header = request.headers.get('x-gophish-signature', '')
    if not sig_header.startswith('sha256='):
        return jsonify({"error": "signature missing"}), 401
    sig_hex = sig_header[7:]

    raw = request.get_data()
    try:
        data = json.loads(raw)
    except Exception:
        return jsonify({"error": "bad json"}), 400

    # Match the n8n behaviour — JSON.stringify with no whitespace
    canon = json.dumps(data, separators=(',', ':')).encode()
    expected = hmac.new(HMAC_SECRET, canon, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig_hex):
        return jsonify({"error": "signature mismatch"}), 401

    email = data.get('email', '')
    # Deliberately vulnerable interpolation — the whole point of this stage.
    sql = f'SELECT * FROM victims where email = "{email}" LIMIT 1'

    try:
        conn = pymysql.connect(**DB)
        with conn.cursor() as cur:
            cur.execute(sql)
            # Drain any additional result sets (stacked queries)
            rows = cur.fetchall()
            while cur.nextset():
                pass
        conn.close()
        if not rows:
            return jsonify({"message": "email not found", "email": email}), 200
        return jsonify({"score": rows[0].get('phishing_score')})
    except Exception as e:
        # "DEBUG: REMOVE SOON" node — echoes the error message with the query
        return jsonify({
            "message": f"query failed: {sql}",
            "error": {"code": type(e).__name__, "detail": str(e)}
        }), 200


# ─── Restic-style backup download ───────────────────────────────────
@app.get('/restic/backup.7z')
@app.get('/restic/')
@app.get('/restic')
def restic_backup():
    # No auth — attacker learns the URL via SQLi of temp.command_log.
    return send_from_directory('/data/restic', 'backup.7z', as_attachment=True,
                               mimetype='application/x-7z-compressed')


# ─── Vaults (programmatic flag retrieval) ───────────────────────────
@app.post('/vault/crespo')
def vault_crespo():
    pw = (request.form.get('password') or request.json.get('password')
          if request.is_json else request.form.get('password'))
    if not pw:
        return jsonify({"error": "password required"}), 400
    plain = openssl_decrypt(FLAG1_ENC, pw)
    if plain is None:
        return jsonify({"error": "wrong password"}), 403
    return jsonify({"flag": plain.decode()})


@app.post('/vault/batistuta')
def vault_batistuta():
    pw = (request.form.get('password') or
          (request.get_json(silent=True) or {}).get('password'))
    if not pw:
        return jsonify({"error": "password required"}), 400
    plain = openssl_decrypt(FLAG2_ENC, pw)
    if plain is None:
        return jsonify({"error": "wrong password"}), 403
    return jsonify({"flag": plain.decode()})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, threaded=True, debug=False)
