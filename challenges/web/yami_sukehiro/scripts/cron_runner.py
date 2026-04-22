#!/usr/bin/env python3
"""
Cron simulator — replaces the three crons from the original box:
  * every 60s : app_backup (no-op here, just exists for file-read discovery)
  * every 900s: table_cleanup (resets appointments demo rows)
  * every 60s : dbmonitor — if dbstatus.json is missing OR says "database is down",
                executes the newest /data/scripts/fixer-v* script.

The attacker abuses MySQL FILE privilege (SQLi) to write fixer-v99.sh, then
waits ≤ 60s for this process to pick it up and execute it. Output is captured
so the attacker can read the user flag via a second written file.
"""
import glob
import os
import subprocess
import time
import json
import pymysql
from datetime import datetime

DB_SOCK = '/var/run/mysqld/mysqld.sock'
SCRIPTS_DIR = '/data/scripts'
STATE_DIR = '/data/state'
DBSTATUS = f'{SCRIPTS_DIR}/dbstatus.json'

os.makedirs(STATE_DIR, exist_ok=True)


def log(msg):
    print(f'[cron {datetime.utcnow().isoformat()}] {msg}', flush=True)


def run_fixer():
    candidates = sorted(glob.glob(f'{SCRIPTS_DIR}/fixer-v*'))
    if not candidates:
        log('no fixer-v* found')
        return
    latest = candidates[-1]
    log(f'executing {latest}')
    try:
        # /bin/bash "$latest"  — matches original box behaviour exactly
        subprocess.run(['/bin/bash', latest], timeout=30,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        log(f'fixer error: {e}')


def dbmonitor():
    # Is mariadb up?
    try:
        conn = pymysql.connect(unix_socket=DB_SOCK, user='yuno',
                               password='3wDo7gSRZIwIHRxZ!', database='mana_db',
                               connect_timeout=3)
        conn.close()
        up = True
    except Exception:
        up = False

    if not up:
        with open(DBSTATUS, 'w') as f:
            json.dump({'status': 'The database is down',
                       'time': datetime.utcnow().isoformat()}, f)
        run_fixer()
        return

    # DB is up. Run fixer if dbstatus.json exists (from prior failure OR SQLi write)
    if os.path.exists(DBSTATUS):
        try:
            with open(DBSTATUS) as f:
                content = f.read()
            if 'database is down' in content:
                log('db recovered — running fixer once')
            else:
                log('stale dbstatus — running fixer')
            run_fixer()
        finally:
            try:
                os.remove(DBSTATUS)
            except OSError:
                pass


def table_cleanup():
    try:
        conn = pymysql.connect(unix_socket=DB_SOCK, user='yuno',
                               password='3wDo7gSRZIwIHRxZ!', database='mana_db')
        with conn.cursor() as cur:
            cur.execute("DELETE FROM appointments WHERE appointment_id > 3")
            cur.execute("DELETE FROM users WHERE role_id LIKE 'knight_%'")
        conn.commit()
        conn.close()
        log('table cleanup done')
    except Exception as e:
        log(f'table_cleanup error: {e}')


def main():
    last_cleanup = time.time()
    while True:
        try:
            dbmonitor()
            if time.time() - last_cleanup > 900:
                table_cleanup()
                last_cleanup = time.time()
        except Exception as e:
            log(f'loop error: {e}')
        time.sleep(60)


if __name__ == '__main__':
    main()
