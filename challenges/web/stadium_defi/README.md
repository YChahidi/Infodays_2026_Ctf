# stadium_defi

**Category:** Web / Web3
**Difficulty:** Very Hard (hardest in the set)
**Ports:** 8009 (challenge frontend) · 8010 (anvil RPC)

## Player brief

> The Infodays 2026 tournament opened a DeFi betting pool for fans. The
> house seeded the treasury with ETH liquidity, and the sealed tournament
> flag is locked inside a Trophy Vault that only releases the flag the
> moment the Betting treasury hits zero.
>
> Drain the treasury, then claim the trophy.
>
> - Challenge frontend (addresses, ABIs, source): `http://<host>:8009`
> - Anvil RPC: `http://<host>:8010` (chain ID `31337`)
>
> Ten standard dev accounts are pre-funded with 10000 ETH each. Use any of
> them as your attacker EOA. Private key for account 0:
>
> `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80`
>
> Tooling suggestion: [Foundry](https://getfoundry.sh/) (`forge`, `cast`,
> `anvil`) or Hardhat.

## Deployment

Added to the root `docker-compose.yml` as `web-stadium-defi`, exposing:

- host **8009** → container 5000 (Flask challenge frontend)
- host **8010** → container 8545 (anvil JSON-RPC)

### Flag

The flag is generated **dynamically at container startup** and baked into
the TrophyVault constructor. On each `docker compose up` you get a fresh
value shaped like

```
INFODAYS{SaamNoLimits_the_house_always_falls_<random-hex>}
```

Pin a specific flag via the `FLAG` env var on the service if you need one
for CTFd scoreboard validation:

```yaml
  web-stadium-defi:
    build: ./challenges/web/stadium_defi
    environment:
      - FLAG=INFODAYS{your_pinned_flag}
    ports:
      - "8009:5000"
      - "8010:8545"
```

### Rebuilding the chain

Anvil runs with `--block-time 2`. The chain state lives entirely inside the
container — restart the service to wipe and redeploy with a new flag.

## Files

| Path | Purpose |
|---|---|
| `contracts/StadiumBetting.sol` | Vulnerable treasury contract |
| `contracts/TrophyVault.sol` | Flag holder, gated on treasury drain |
| `script/Deploy.s.sol` | Foundry deploy script |
| `frontend/app.py` | Flask info page + RPC proxy |
| `entrypoint.sh` | Boots anvil, deploys contracts, starts frontend |
| `Dockerfile` | Foundry base + Python for the frontend |
| `WRITEUP.md` | Full intended solution (author eyes) |

See [`WRITEUP.md`](./WRITEUP.md) for the intended exploit chain, a sample
Foundry attacker contract, and why this challenge sits above
`referee_decision_system` in the difficulty ladder.
