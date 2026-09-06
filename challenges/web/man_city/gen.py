#!/usr/bin/env python3
"""
Man-City — flag + asset generator.

Produces 8 flags (easy → extreme insane) and seeds the SQLite database,
JWT secret, pickle cookie, and report files.

Flag difficulty ladder:
  1. Easy        — HTML source comment
  2. Easy        — robots.txt / backup directory listing
  3. Medium      — Default credentials (admin:admin123)
  4. Medium      — SQL injection (UNION SELECT from secrets table)
  5. Hard        — SSTI (Jinja2 template injection)
  6. Hard        — Path traversal on /download
  7. Insane      — Pickle deserialization RCE via cookie
  8. Extreme     — JWT alg:none bypass + command injection
"""
from __future__ import annotations
import argparse, os, secrets, sqlite3, json
from pathlib import Path

HERE = Path(__file__).resolve().parent

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hex", default=None)
    args = ap.parse_args()
    h = args.hex or secrets.token_hex(4)

    # Use env vars if provided, otherwise generate random flags
    flags = {
        "FLAG1": os.environ.get("FLAG1", f"INFODAYS{{SaamNoLimits_view_source_rookie_{h}}}"),
        "FLAG2": os.environ.get("FLAG2", f"INFODAYS{{SaamNoLimits_robots_exposed_{h}}}"),
        "FLAG3": os.environ.get("FLAG3", f"INFODAYS{{SaamNoLimits_default_creds_owned_{h}}}"),
        "FLAG4": os.environ.get("FLAG4", f"INFODAYS{{SaamNoLimits_sqli_union_dumped_{h}}}"),
        "FLAG5": os.environ.get("FLAG5", f"INFODAYS{{SaamNoLimits_ssti_template_pwned_{h}}}"),
        "FLAG6": os.environ.get("FLAG6", f"INFODAYS{{SaamNoLimits_path_traversal_lfi_{h}}}"),
        "FLAG7": os.environ.get("FLAG7", f"INFODAYS{{SaamNoLimits_pickle_deserialized_{h}}}"),
        "FLAG8": os.environ.get("FLAG8", f"INFODAYS{{SaamNoLimits_jwt_none_rce_god_{h}}}"),
    }

    # ── Write .env ──────────────────────────────────────────────
    env_lines = [f"{k}={v}" for k, v in flags.items()]
    env_lines.append(f"JWT_SECRET=manchesterisblue_{h}")
    (HERE / ".env").write_text("\n".join(env_lines) + "\n")

    # ── Write flag files for LFI ────────────────────────────────
    (HERE / "flag6.txt").write_text(flags["FLAG6"] + "\n")
    (HERE / "flag8.txt").write_text(flags["FLAG8"] + "\n")

    # ── Seed SQLite database ────────────────────────────────────
    db = HERE / "man_city.db"
    db.unlink(missing_ok=True)
    con = sqlite3.connect(str(db))
    cur = con.cursor()
    cur.execute("CREATE TABLE players (id INTEGER PRIMARY KEY, name TEXT, position TEXT, number INTEGER, status TEXT)")
    players = [
        (1, "Erling Haaland", "Striker", 9, "active"),
        (2, "Kevin De Bruyne", "Midfielder", 17, "active"),
        (3, "Ederson Moraes", "Goalkeeper", 31, "active"),
        (4, "Ruben Dias", "Defender", 3, "active"),
        (5, "Phil Foden", "Midfielder", 47, "active"),
        (6, "Jack Grealish", "Midfielder", 10, "active"),
        (7, "Bernardo Silva", "Midfielder", 20, "active"),
        (8, "John Stones", "Defender", 5, "active"),
        (9, "Kyle Walker", "Defender", 2, "retired"),
        (10, "Ilkay Gundogan", "Midfielder", 8, "transferred"),
    ]
    cur.executemany("INSERT INTO players VALUES (?,?,?,?,?)", players)
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    cur.execute("INSERT INTO users VALUES (1, 'admin', 'admin123', 'admin')")
    cur.execute("INSERT INTO users VALUES (2, 'scout', 'scout2026', 'viewer')")
    cur.execute("INSERT INTO users VALUES (3, 'manager', 'guardiola', 'manager')")
    cur.execute("CREATE TABLE secrets (id INTEGER PRIMARY KEY, key TEXT, value TEXT)")
    cur.execute("INSERT INTO secrets VALUES (1, 'flag4', ?)", (flags["FLAG4"],))
    cur.execute("INSERT INTO secrets VALUES (2, 'db_password', 'S3cur3_DB_P@ss!')")
    cur.execute("INSERT INTO secrets VALUES (3, 'api_key', 'sk-mancity-prod-9f8e7d6c5b4a')")
    con.commit()
    con.close()

    # ── Write sample report files ───────────────────────────────
    reports = HERE / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "match_report_gw12.txt").write_text("Man City 3 - 1 Arsenal\nGoals: Haaland (23', 67'), Foden (81')\n")
    (reports / "match_report_gw15.txt").write_text("Man City 2 - 0 Chelsea\nGoals: De Bruyne (45'), Haaland (88')\n")
    (reports / "scouting_notes.txt").write_text("Target: Florian Wirtz\nEvaluation: Elite playmaker, high priority\n")

    # ── Summary ─────────────────────────────────────────────────
    print(f"[gen] hex={h}")
    for k, v in flags.items():
        print(f"[gen] {k} -> {v}")
    print(f"[gen] wrote .env, flag6.txt, flag8.txt, man_city.db, reports/")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
