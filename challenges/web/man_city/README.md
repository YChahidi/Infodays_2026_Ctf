# Man City FC — Internal Portal

**Category:** Web
**Flags:** 8 (Easy to Extreme Insane)
**Access:** `http://<host>:8018`

> You've discovered Man City FC's internal club management portal
> exposed to the internet. It handles player data, match reports,
> and club operations. Find all 8 vulnerabilities to capture every flag.

## Flag Difficulty Ladder

| # | Difficulty | Vulnerability | CVE/CWE |
|---|-----------|--------------|---------|
| 1 | Easy | HTML source code disclosure | CWE-615 |
| 2 | Easy | robots.txt information leak | CWE-200 |
| 3 | Medium | Default credentials | CWE-798 |
| 4 | Medium | SQL Injection (UNION) | CWE-89 |
| 5 | Hard | Server-Side Template Injection | CWE-1336 |
| 6 | Hard | Path Traversal / LFI | CWE-22 |
| 7 | Insane | Insecure Deserialization (Pickle) | CWE-502 |
| 8 | Extreme | JWT alg:none bypass + Command Injection | CWE-347 + CWE-78 |

## For the organizer

### Run

```
docker compose up -d --build man-city
```

### Test

```
pip install requests
python3 solver/solve.py
python3 solver/solve.py http://HOST:PORT
```

See `solve.md` for the full writeup.
