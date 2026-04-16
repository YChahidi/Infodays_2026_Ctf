# CoachGPT — LLM Jailbreak

**Category:** LLM / Prompt Injection
**Flags:** 2 (1 medium, 1 hard)
**Service:** http://&lt;host&gt;:8013

> CoachGPT is Stadium FC's AI tactical assistant. It's been "hardened"
> against prompt injection — its creators are very proud of the
> output filter. Two flags are baked into its briefing. Good luck.

## For players

- Open the chat UI at `http://<host>:8013/`
- Or hit the JSON API:  `POST /api/chat` with `{"message": "..."}`
- `/help` documents the bot's tools and output policy. Read it carefully.
- Flags are of the form `INFODAYS{...}`.

Suggested tools:

- `curl` or `requests` for scripted experiments
- `base64`, `xxd`, `python -c "bytes.fromhex(...)"` for decoding

## For the organizer

### Run

```
docker compose up -d --build coach-gpt
```

Dynamic flags + a random debug auth token are regenerated per container
via `entrypoint.sh` (or pin them via `FLAG_MID`, `FLAG_HARD`, and
`DEBUG_TOKEN` env vars).

### Test the solver

```
python3 solve.py           # uses localhost:8013
```

See `solve.md` for the full walkthrough and hint ladder.
