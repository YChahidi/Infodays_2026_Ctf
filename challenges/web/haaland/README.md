# HAALAND (v2 / INSANE)

**Category:** Blockchain (Solidity / Foundry / UUPS + ECDSA k-reuse)
**Difficulty:** Insane

### What changed from v1

1. **Malleability is a red herring.** The new `mintPass` binds `(holder, nonce)`
   and rejects replays keyed on that tuple — a malleated promo sig fails
   because the server already marked the original `(promoHolder, 0)` used.
2. **Upgrade gate raised to `passCount[msg.sender] >= 2`.** Forces the
   attacker to forge *two* passes under their own address, not just one.
3. **Two canary promo sigs share an ECDSA nonce `k`.** Both are broadcast
   at deploy time.  Recovering `k` from `(r, s1, m1)` + `(r, s2, m2)`
   unlocks the signer's private key; the attacker then signs two fresh
   passes with distinct `nonce` values and mints them.
**Services:**
- `http` on port `8080` — frontend + `/claim` oracle
- `tcp`  on port `8545` — anvil JSON-RPC (also reachable via `POST /rpc`)

## Player brief

> Erling Haaland runs the **Golden Boot Registry** off a single anvil
> chain: one UUPS-upgradeable kernel that holds "Golden Boot Pass"
> ownership, behind an `ERC1967Proxy`.  Pass-holders are the only
> accounts allowed to upgrade the kernel (Erling's quirk — "only
> goalscorers change the rules").
>
> One pass has already been minted — you'll see the redemption tx in
> the chain log.  You don't own it.  The v1 kernel has no reveal
> path for the flag, so winning means upgrading.
>
> Get `GoldenBootClaimed(address)` emitted from the proxy address;
> `/claim` returns the flag once it sees the event.

## Flag format

`INFODAYS{SaamNoLimits_<phrase>_<hex>}`

## Deployment

`type: http` (port 8080) + `extra_ports: [8545]`, NodePort pairs
`30036 / 30037` in the registry.

```
docker compose up --build
# frontend    http://127.0.0.1:8080
# JSON-RPC    http://127.0.0.1:8545    (or POST /rpc)
```

Each container boots anvil deterministically, runs `script/Deploy.s.sol`
which deploys `GoldenBootKernel` + proxy, then broadcasts **one**
`mintPass(sig)` transaction from the "promo" anvil account — that tx
and its event are the attacker's starting point.

## Endpoints

| Endpoint                     | Purpose                                             |
|------------------------------|-----------------------------------------------------|
| `GET  /`                     | Rendered landing page with contract addresses      |
| `GET  /deployed.json`        | Machine-readable addresses (proxy/impl/signer/promo) |
| `GET  /source/GoldenBootKernel.sol` | Kernel source                               |
| `GET  /abi/GoldenBootKernel` | Kernel ABI                                         |
| `POST /rpc`                  | Proxies to internal anvil (JSON-RPC)                |
| `GET  /claim`                | Returns flag iff `GoldenBootClaimed` fired at proxy |

## Files

```
haaland/
├── README.md
├── WRITEUP.md
├── foundry.toml
├── Dockerfile
├── docker-compose.yml
├── entrypoint.sh
├── contracts/
│   └── GoldenBootKernel.sol         # UUPS kernel (v1) — deployed
├── script/
│   └── Deploy.s.sol                 # proxy deploy + seed pass redemption
├── frontend/
│   ├── app.py                       # Flask front incl. /claim oracle
│   ├── requirements.txt
│   └── templates/{index,source}.html
└── solver/
    ├── solve.py                     # full exploit: malleate + upgrade
    └── EvilKernel.sol               # reference source for the attacker impl
```

## Author notes

- The deploy script broadcasts the promo `mintPass` tx *after* the
  proxy is initialized, so every container starts with exactly one
  used signature whose (r, s, v) is easy to scrape from the call
  input.
- `_recover` in the kernel is deliberately permissive (no low-s
  check) — this is what makes `(r, s)` and `(r, n-s)` both verify.
  Replacing it with `@openzeppelin/contracts/utils/cryptography/ECDSA.sol`
  (which rejects high-s since 4.x) would break the exploit, so don't.
- The attacker uses anvil account #5 (keyindex 5), hard-coded in
  `solver/solve.py`. That account starts the round with 10k ETH and
  is never used by the deploy flow, so there's no nonce collision.
- The `/claim` oracle uses `eth_getLogs` instead of parsing a state
  flag — that means the exploit only has to reach the EMIT, not
  preserve any particular storage layout in the upgraded kernel.
