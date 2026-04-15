# stadium_ci

**Category:** Web
**Difficulty:** Hard
**Port:** 8008
**Inspired by:** [CVE-2024-27198](https://nvd.nist.gov/vuln/detail/CVE-2024-27198) (JetBrains TeamCity authentication bypass via URL parser differential)

## Player brief

> Stadium CI is the Infodays 2026 tournament continuous-integration and VAR
> replay console. The public build dashboard is open to anyone with scout
> credentials, but the VAR room admin console stays locked behind an
> authentication gate.
>
> Rumour is the tournament's final-match sealed decision — including the
> tournament flag — is published inside the admin console. Find a way in.
>
> The flag lives at `/flag.txt` on the server. The application is written in
> Python/Flask and sits behind a legacy Varnish-style edge cache layer.

Public scout credentials: `scout` / `scout`. They give you the public
dashboard but nothing more.

## Deployment

Added to the root `docker-compose.yml` as `web-stadium-ci`, exposing host port
**8008** → container port 5000.

### Flag

The flag is generated **dynamically at container startup**. The entrypoint
writes a random value like

```
INFODAYS{SaamNoLimits_you_can_overcome_anything_if_you_love_it_enough_<random-hex>}
```

to `/flag.txt`. Override with the `FLAG` env var on the service if you need
a pinned flag for scoreboard validation:

```yaml
  web-stadium-ci:
    build: ./challenges/web/stadium_ci
    environment:
      - FLAG=INFODAYS{your_pinned_flag}
    ports:
      - "8008:5000"
```

Without the env var, each `docker compose up` produces a fresh flag — use
`docker exec <container> cat /flag.txt` to retrieve it for CTFd.

## Files

| Path | Purpose |
|---|---|
| `app.py` | Flask app with the intentional auth bypass bug |
| `templates/` | Minimal Infodays-themed HTML |
| `entrypoint.sh` | Generates the dynamic flag and starts the app |
| `Dockerfile` | Python 3.11-slim + Flask |
| `WRITEUP.md` | Full intended solution (author eyes only) |

See [`WRITEUP.md`](./WRITEUP.md) for the intended exploit chain and why this
challenge is rated Hard.
