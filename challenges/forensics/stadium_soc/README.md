# Stadium FC — SOC Analyst Lab

**Category:** Blue Team / SOC Analysis
**Style:** HTB Academy lab (answer-in-panel)
**Flags:** 1 (medium) — released at 70% threshold (28/40)
**Access:** `http://<host>:8017`

> Stadium FC's SOC detected suspicious activity across the network during
> last night's match. Your task: triage the incident using the provided
> evidence files and answer 40 questions spanning IOC extraction, log
> correlation, MITRE ATT&CK mapping, and kill chain reconstruction.

## For players

1. Open the lab panel: `http://<host>:8017`
2. Review the 7 evidence files (auth.log, access.log, suricata.json,
   firewall.log, dns_queries.log, syslog, timeline.csv)
3. Answer the 40 questions (Easy / Medium / Hard)
4. Hit **Grade Lab**. Score **>= 70%** to get the flag.

Recommended tools: a text editor, `jq`, `grep`, `awk`, and a MITRE
ATT&CK reference.

## For the organizer

### Run

```
docker compose up -d --build stadium-soc
```

### Test the solver

```
pip install requests
python3 solver/solve.py
python3 solver/solve.py http://HOST:PORT
```

See `solve.md` for the full walkthrough.
