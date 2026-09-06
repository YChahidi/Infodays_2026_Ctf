# HAALAND v2 — writeup (INSANE)

`INFODAYS{SaamNoLimits_k_reuse_wrecks_the_derby_<hex>}`

## TL;DR

Three stacked primitives and one red herring:

- **Red herring.** The kernel's `_recover` is deliberately permissive
  — ECDSA malleability works in isolation.  It doesn't help you,
  because `mintPass` dedupes on `(holder, nonce)`, not on sig hash,
  and the promo passes burned `(promoHolder, 0)` already.  So the
  attacker needs *fresh* signatures for their own address.
- **Primitive 1 — ECDSA nonce reuse.**  Two promo sigs share `k`,
  detectable by equal `r`.  Recover `k` and then the signer's
  private key with classical algebra.
- **Primitive 2 — sign two fresh passes.**  Use the recovered privkey
  to produce valid sigs for `(attacker, 0)` and `(attacker, 1)`.  Mint
  them; `passCount[attacker] == 2`.
- **Primitive 3 — UUPS upgrade hijack.**  The upgrade gate requires
  `passCount[msg.sender] >= 2`, which you now satisfy.  Deploy
  `EvilKernel`, call `upgradeToAndCall(evil, scoreGoldenBoot())`; the
  delegated call emits `GoldenBootClaimed(msg.sender)` from the proxy
  address.  `/claim` surfaces the flag.

## 0. The key-recovery algebra

For an ECDSA signature `(r, s)` over digest `m` with private key `d` and
nonce `k`:

    s = k^-1 * (m + r * d)   mod n

Given two signatures `(r, s_1, m_1)` and `(r, s_2, m_2)` that share the
same `r` — which happens iff they share the same `k` — we can isolate
`k`:

    s_1 - s_2 = k^-1 * (m_1 - m_2)
    k = (m_1 - m_2) * (s_1 - s_2)^-1    mod n

and then `d`:

    d = (s_1 * k - m_1) * r^-1          mod n

libsecp256k1 normalises to low-s on signing, which may silently flip
the parity relative to the signing equation — the solver tries all
four sign combinations and keeps the candidate that matches the
public signer address.

## 1. What's on-chain after deploy

From `/deployed.json`:

- `proxy`  — `ERC1967Proxy` pointing at the kernel impl
- `impl`   — `GoldenBootKernel` v1 implementation
- `signer` — off-chain EOA whose ECDSA key authorises passes
- `promo`  — anvil account that redeemed the original pass

And one tx in the chain: the promo's `mintPass(bytes)` call.  Its
calldata = selector + `abi.encode(bytes)` = selector + offset +
length + 65-byte sig.  Scraping from the tx log:

```python
logs = w3.eth.get_logs({"address": proxy,
                        "topics": [keccak(b"PassMinted(address,bytes32)")]})
tx   = w3.eth.get_transaction(logs[0]["transactionHash"])
data = bytes.fromhex(tx["input"].removeprefix("0x"))
sig  = data[4 + 64 : 4 + 64 + 65]     # 65-byte (r || s || v)
```

## 2. The ECDSA malleability

For any valid ECDSA signature `(r, s)` over digest `h`, the pair
`(r, n-s)` is *also* a valid signature for the same `h` under the
same public key — that's because secp256k1's group order `n` is
prime and `s` appears squared in the verification equation (`s^-1`
is symmetric under negation modulo `n` in a way that preserves the
recovered point up to its y-parity).  Flip `v` at the same time to
keep the recovered address unchanged.

```python
SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
r, s, v = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"), sig[64]
malleated = r.to_bytes(32,"big") + (SECP256K1_N - s).to_bytes(32,"big") + bytes([v ^ 1])
```

The kernel's `_recover` doesn't enforce the low-s half-range (modern
OpenZeppelin would), so it accepts both.  The replay check is
`usedSigHash[keccak256(sig)]` — a *different* sig bytes blob has a
different hash, so the check passes.

## 3. Mint a pass to ourselves

From the attacker account (anvil acct #5):

```python
selector = keccak(b"mintPass(bytes)")[:4]
calldata = selector + abi.encode(bytes)(malleated)
send_tx(to=proxy, data=calldata)       # hasPass[attacker] = true
```

## 4. Deploy EvilKernel

```solidity
contract EvilKernel is UUPSUpgradeable {
    event GoldenBootClaimed(address indexed winner);
    function scoreGoldenBoot() external { emit GoldenBootClaimed(msg.sender); }
    function _authorizeUpgrade(address) internal pure override { revert("frozen"); }
}
```

We inherit UUPSUpgradeable so that the implementation slot writes
through `_upgradeToAndCallUUPS` → `proxiableUUID()` check passes.
`scoreGoldenBoot` is the payload we want to execute *in the proxy's
context* once the upgrade completes.  The bytecode sits in
`solver/solve.py` as a hex string — run `forge build` on
`solver/EvilKernel.sol` if you want to regenerate it.

## 5. upgradeToAndCall

The proxy inherits `upgradeToAndCall(address newImpl, bytes data)`
from UUPS.  The call delegates into the current kernel (v1), which:

1. Calls `_authorizeUpgrade(newImpl)` — our kernel's gate is
   `hasPass[msg.sender]`, satisfied.
2. Writes `newImpl` into the ERC1967 impl slot.
3. Delegatecalls `newImpl.<data>` if `data` is non-empty.

So with `data = abi.encode(scoreGoldenBoot())`, the delegatecall runs
`EvilKernel.scoreGoldenBoot()` *as if it were the proxy's own code*.
`emit GoldenBootClaimed(msg.sender)` fires from the proxy's address —
which is exactly what `/claim` is filtering for.

```python
selector = keccak(b"upgradeToAndCall(address,bytes)")[:4]
inner    = keccak(b"scoreGoldenBoot()")[:4]            # calldata for the post-upgrade call
data     = selector + abi.encode(address, bytes)(evilAddr, inner)
send_tx(to=proxy, data=data)
```

## 6. /claim

`frontend/app.py` runs `eth_getLogs` against the proxy for the
`GoldenBootClaimed(address)` topic.  A non-empty result hands back
the flag:

```
$ curl http://127.0.0.1:8080/claim
{"status":"claimed","flag":"INFODAYS{SaamNoLimits_ecdsa_malleable_pass_<hex>}", ...}
```

## Why this is a realistic blockchain fail

Two bugs on top of each other.

1. **Sig-hash dedup** — the contract treated "has this exact
   byte-for-byte signature been seen before" as equivalent to "has
   this message been redeemed before".  It isn't, because ECDSA is
   malleable: every signed message has at least two valid 65-byte
   signatures.  Real-world version: signature-gated airdrops /
   meta-tx relayers / NFT mints that tracked uses by `keccak(sig)`.
2. **Capability-as-proof** — the upgrade gate treated "owns a pass"
   as an authorization to rewrite the implementation.  Even if bug
   #1 were fixed, anyone who legitimately acquired a single pass
   would own the chain.

Either fix alone prevents the exploit.  OpenZeppelin's
`ECDSA.tryRecover` rejects high-s values since 4.x, and standard
UUPS patterns gate `_authorizeUpgrade` on a dedicated admin role
(not on a user-facing capability).

## Running the solver

```
$ python3 solver/solve.py http://127.0.0.1:8080
[*] connected, chain_id=31337
[*] proxy=0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512  signer=0x7099...
[*] promo sig: 3afa24b3a26d9dcaeba343fada549f07762a9eef... v=28
[*] malleated: 3afa24b3a26d9dcaeba343fada549f07762a9eef... v=27
[*] attacker=0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc
[*] calling mintPass with malleated sig...
[*] deploying EvilKernel...
[*] calling upgradeToAndCall to emit GoldenBootClaimed...
FLAG: INFODAYS{SaamNoLimits_ecdsa_malleable_pass_819e2ee3c6fb664a}
```
