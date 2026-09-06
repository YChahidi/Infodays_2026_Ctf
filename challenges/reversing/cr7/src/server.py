#!/usr/bin/env python3
"""
Infinity Bank — vulnerable backend for the Infodays 2026 CTF.

Protocol:
    1. Client generates AES-256 key, 16-byte IV, 16-byte salt (salt unused server-side).
    2. Plaintext JSON body is padded+encrypted with AES-CBC and base64'd.
    3. Key / IV / salt are each base64'd, RSA-OAEP(SHA-256) encrypted with the
       server's public key, base64'd, and sent as KEY / IV / SALT headers.
    4. SIGNATURE header is the SHA-256 hex digest of the *plaintext* JSON.
    5. Response body is AES-CBC encrypted with the same key/iv.

Vulnerability (intended):
    /api/v1/transaction/transfer has no server-side check that from_account
    matches the authenticated user's account — a classic BOLA / IDOR.
    The privileged bank account 93478541 was seeded with one transaction
    whose `remark` contains the flag.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import secrets
import string
import time
from pathlib import Path
from typing import Any

from flask import Flask, Response, request
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

HERE = Path(__file__).parent
KEYS = Path(os.environ.get("LAB_KEYS", HERE.parent / "keys")).resolve()
def _read_flag() -> str:
    for candidate in (HERE / "flag.txt", HERE.parent / "flag.txt"):
        if candidate.exists():
            return candidate.read_text().strip()
    return "INFODAYS{placeholder_flag}"


FLAG = os.environ.get("FLAG") or _read_flag()

BANK_ACCOUNT = int(os.environ.get("BANK_ACCOUNT", "93478541"))

PRIV_KEY = RSA.import_key((KEYS / "private.pem").read_bytes())
RSA_CIPHER = PKCS1_OAEP.new(PRIV_KEY, hashAlgo=SHA256)

app = Flask(__name__)


# ---------------------------------------------------------------- storage

# In-memory state — reset every container restart. Fine for a CTF.
USERS: dict[str, dict[str, Any]] = {}        # email -> user record
ACCOUNTS: dict[int, dict[str, Any]] = {}     # account_number -> account
TOKENS: dict[str, str] = {}                  # token -> email
TX_LOG: list[dict[str, Any]] = []


def _new_account_number() -> int:
    while True:
        n = random.randint(100_000_000, 999_999_999)
        if n not in ACCOUNTS:
            return n


def _seed_bank() -> None:
    ACCOUNTS[BANK_ACCOUNT] = {
        "account_number": BANK_ACCOUNT,
        "balance": 1_000_000.00,
        "owner": "bank@infinity-bank.lab",
    }
    USERS["bank@infinity-bank.lab"] = {
        "email": "bank@infinity-bank.lab",
        "username": "infinity_bank_root",
        "first_name": "Infinity",
        "middle_name": "",
        "last_name": "Bank",
        "password_hash": hashlib.sha256(secrets.token_bytes(32)).hexdigest(),
        "account_number": BANK_ACCOUNT,
        "device_id": "server-local",
    }
    TX_LOG.append(
        {
            "txn_id": "FIFRZKSJFUNHVWN",
            "from_account": BANK_ACCOUNT,
            "to_account": BANK_ACCOUNT,
            "amount": 13.37,
            "remark": FLAG,
            "date": time.strftime("%Y-%m-%d"),
        }
    )


_seed_bank()


# ---------------------------------------------------------------- crypto

def _rsa_decrypt_header(b64: str) -> bytes:
    """Headers carry base64( RSA-OAEP( base64(raw) ) )."""
    outer = base64.b64decode(b64)
    inner_b64 = RSA_CIPHER.decrypt(outer)
    return base64.b64decode(inner_b64)


def _decrypt_body(ciphertext_b64: str, key: bytes, iv: bytes) -> bytes:
    data = base64.b64decode(ciphertext_b64)
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data), AES.block_size)


def _encrypt_body(plaintext: bytes, key: bytes, iv: bytes) -> str:
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, AES.block_size))
    return base64.b64encode(ct).decode()


def _err(msg: str, code: int = 400) -> tuple[dict[str, Any], int]:
    return {"errors": [msg]}, code


def _respond(payload: Any, key: bytes, iv: bytes, status: int = 200) -> Response:
    body = _encrypt_body(json.dumps(payload, separators=(",", ":")).encode(), key, iv)
    return Response(body, status=status, mimetype="text/plain")


# ---------------------------------------------------------------- entry

def _unpack_request() -> tuple[dict[str, Any], bytes, bytes] | tuple[None, Any, int]:
    try:
        key = _rsa_decrypt_header(request.headers["KEY"])
        iv = _rsa_decrypt_header(request.headers["IV"])
        _ = _rsa_decrypt_header(request.headers["SALT"])  # accepted but unused
    except Exception:
        return None, {"errors": ["bad key envelope"]}, 400

    if len(key) != 32 or len(iv) != 16:
        return None, {"errors": ["bad key/iv length"]}, 400

    try:
        plaintext = _decrypt_body(request.get_data(as_text=True), key, iv)
    except Exception:
        return None, {"errors": ["bad body"]}, 400

    signature = request.headers.get("SIGNATURE", "")
    if hashlib.sha256(plaintext).hexdigest() != signature:
        return None, {"errors": ["bad signature"]}, 400

    try:
        payload = json.loads(plaintext)
    except Exception:
        return None, {"errors": ["bad json"]}, 400

    return payload, key, iv


def _auth_token(payload: dict[str, Any]) -> str | None:
    """Accept token from Authorization header, `auth.token`, or `token`."""
    raw = request.headers.get("Authorization", "")
    if raw.startswith("Bearer "):
        return raw.split(" ", 1)[1]
    if isinstance(payload.get("auth"), dict):
        t = payload["auth"].get("token")
        if isinstance(t, str):
            return t
    if isinstance(payload.get("token"), str):
        return payload["token"]
    return None


# ---------------------------------------------------------------- routes

@app.route("/api/v1/user/register", methods=["POST"])
def register() -> Response:
    payload, key, iv = _unpack_request()
    if payload is None:
        err_body, err_code = key, iv  # type: ignore[assignment]
        return (err_body, err_code)

    required = {"device_id", "email", "first_name", "last_name", "password", "username"}
    missing = required - set(payload.keys())
    if missing:
        return _respond({"errors": [f"missing fields: {sorted(missing)}"]}, key, iv, 400)

    email = payload["email"].strip().lower()
    if email in USERS:
        return _respond({"errors": ["email already registered"]}, key, iv, 409)

    account_no = _new_account_number()
    ACCOUNTS[account_no] = {
        "account_number": account_no,
        "balance": 13.37,
        "owner": email,
    }
    USERS[email] = {
        "email": email,
        "username": payload["username"],
        "first_name": payload["first_name"],
        "middle_name": payload.get("middle_name", ""),
        "last_name": payload["last_name"],
        "password_hash": hashlib.sha256(payload["password"].encode()).hexdigest(),
        "account_number": account_no,
        "device_id": payload["device_id"],
    }
    return _respond({"message": "user registered", "user": {"email": email, "account_number": account_no}}, key, iv)


@app.route("/api/v1/login", methods=["POST"])
def login() -> Response:
    payload, key, iv = _unpack_request()
    if payload is None:
        err_body, err_code = key, iv  # type: ignore[assignment]
        return (err_body, err_code)

    email = str(payload.get("email", "")).strip().lower()
    password = str(payload.get("password", ""))
    user = USERS.get(email)
    if not user or user["password_hash"] != hashlib.sha256(password.encode()).hexdigest():
        return _respond({"errors": ["invalid credentials"]}, key, iv, 401)

    token = _issue_token(user)
    pin_int = secrets.randbelow(0xFFFF)
    return _respond(
        {
            "token": token,
            "pin": base64.b64encode(pin_int.to_bytes(4, "big")).decode(),
        },
        key, iv,
    )


def _issue_token(user: dict[str, Any]) -> str:
    # Opaque token (not a real JWT — decompilation only sees us call it "token")
    token = secrets.token_urlsafe(24)
    TOKENS[token] = user["email"]
    return token


def _resolve(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    email = TOKENS.get(token)
    if not email:
        return None
    return USERS.get(email)


@app.route("/api/v1/user/me", methods=["POST"])
def me() -> Response:
    payload, key, iv = _unpack_request()
    if payload is None:
        err_body, err_code = key, iv  # type: ignore[assignment]
        return (err_body, err_code)

    user = _resolve(_auth_token(payload))
    if not user:
        return _respond({"errors": ["unauthenticated"]}, key, iv, 401)

    account = ACCOUNTS[user["account_number"]]
    return _respond(
        {
            "user": {k: user[k] for k in ("email", "username", "first_name", "middle_name", "last_name")},
            "account": {"account_number": account["account_number"], "balance": account["balance"]},
        },
        key, iv,
    )


@app.route("/api/v1/transaction/history", methods=["POST"])
def history() -> Response:
    payload, key, iv = _unpack_request()
    if payload is None:
        err_body, err_code = key, iv  # type: ignore[assignment]
        return (err_body, err_code)

    user = _resolve(_auth_token(payload))
    if not user:
        return _respond({"errors": ["unauthenticated"]}, key, iv, 401)

    # Only surface transactions touching the user's account — but we do NOT
    # strip the remark, so the seeded bank-to-bank flag transaction is only
    # visible after the IDOR transfer pulls it to a user's account.
    acct = user["account_number"]
    history = [tx for tx in TX_LOG if tx["from_account"] == acct or tx["to_account"] == acct]
    return _respond({"history": history}, key, iv)


@app.route("/api/v1/transaction/transfer", methods=["POST"])
def transfer() -> Response:
    payload, key, iv = _unpack_request()
    if payload is None:
        err_body, err_code = key, iv  # type: ignore[assignment]
        return (err_body, err_code)

    user = _resolve(_auth_token(payload))
    if not user:
        return _respond({"errors": ["unauthenticated"]}, key, iv, 401)

    try:
        from_acc = int(payload["from_account"])
        to_acc = int(payload["to_account"])
        amount = float(payload["amount"])
    except (KeyError, ValueError, TypeError):
        return _respond({"errors": ["bad transfer params"]}, key, iv, 400)

    remark = str(payload.get("remark", ""))[:128]

    # ⚠️ INTENTIONAL VULNERABILITY — no check that from_acc belongs to `user`.
    src = ACCOUNTS.get(from_acc)
    dst = ACCOUNTS.get(to_acc)
    if not src or not dst:
        return _respond({"errors": ["unknown account"]}, key, iv, 404)
    if amount <= 0 or src["balance"] < amount:
        return _respond({"errors": ["insufficient funds"]}, key, iv, 400)

    src["balance"] = round(src["balance"] - amount, 2)
    dst["balance"] = round(dst["balance"] + amount, 2)

    txn_id = "".join(secrets.choice(string.ascii_uppercase) for _ in range(15))

    # When the bank account is drained, we echo the seeded flag remark back.
    # This mirrors the original HTB behaviour — server logs the transfer with
    # a flavourful message from the "treasurer" on certain special transfers.
    response_remark = remark
    if from_acc == BANK_ACCOUNT and amount >= 1337.0:
        response_remark = FLAG

    entry = {
        "txn_id": txn_id,
        "from_account": from_acc,
        "to_account": to_acc,
        "amount": amount,
        "remark": response_remark,
        "date": time.strftime("%Y-%m-%d"),
    }
    TX_LOG.append(entry)
    return _respond(entry, key, iv)


@app.route("/healthz", methods=["GET"])
def healthz() -> Response:
    return Response("ok", mimetype="text/plain")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
