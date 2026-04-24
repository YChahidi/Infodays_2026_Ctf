# CR7

**Category:** Reversing (Mobile / Flutter) + Web API exploitation
**Difficulty:** Hard

*(The app inside the APK is branded "Infinity Bank" — that's what
players actually see during reverse engineering. The CTF registers
this challenge as `cr7`.)*
**Artifacts:**
- `dist/infinity-bank.apk` — signed Flutter APK (~28 MB)
- Live API at `https://<HOST>:<PORT>/api/v1/` (HTTP in the lab deployment)
- Host header expected: `infinity-bank.lab`

## Player brief

> Infodays volunteers found a beta Android banking app on the
> Ouazzane stadium Wi-Fi: **Infinity Bank**.
>
> Every user gets a brand-new account opened with exactly
> `13.37 MAD` — a "welcome bonus" from the treasury account.
> The bank clearly has lots more money than that, somewhere.
>
> The backend is still up. Figure out how the app talks to it
> and help yourself to the *good* account.

## Flag format

`INFODAYS{SaamNoLimits_<phrase>_<hex>}`

## What the player has to do

1. **Reverse the APK.** It's a Flutter release build, so Dart code is
   compiled to an AOT snapshot inside `lib/<abi>/libapp.so`. Standard
   tools (jadx, apktool) won't help beyond the Java/Kotlin glue; use
   [`blutter`](https://github.com/worawit/blutter) on the `arm64-v8a`
   folder to recover readable pseudo-Dart.
2. **Reconstruct the crypto protocol.** Every request uses a freshly
   generated AES-256-CBC key + IV, wrapped with RSA-OAEP(SHA-256) and
   sent in the `KEY` / `IV` / `SALT` headers. A SHA-256 of the
   plaintext JSON is sent in `SIGNATURE`. Response bodies are AES-CBC
   with the same session key/IV.
3. **Pull the RSA public key out of `libapp.so`.** It's a plain PEM
   string (`-----BEGIN PUBLIC KEY-----`); `grep -a` finds it.
4. **Register → login.** `RegisterRequest.toJson()` lists all fields,
   including `device_id`, `first_name`, `last_name`, `middle_name` —
   miss any of them and the server returns `"internal error"`.
5. **Find the IDOR.** `TransferRequest` ships a `from_account` that
   the server trusts blindly. There is no check that the token's
   account owns that number. Transfer `1337.0` out of the bank's
   privileged account (`93478541`) to yours — the flag comes back in
   the response's `remark`.

## Deployment

`type: http`, port `8080` inside the pod, NodePort `30034` externally.
`docker-compose.yml` at the root of this folder builds and runs the
backend locally:

```
docker compose up --build
# serves on http://127.0.0.1:8080
```

The in-memory state (users, accounts, tokens) is reset every container
restart, so every spawn is clean.

## Files

```
cr7/
├── README.md                   # this file
├── WRITEUP.md                  # full solution
├── flag.txt                    # the flag for this lab build
├── docker-compose.yml          # lab deployment
├── dist/
│   └── infinity-bank.apk       # player artifact (patched + re-signed)
├── keys/
│   ├── private.pem             # lab's RSA private key (server-side)
│   └── public.pem              # matching public key — embedded in APK
├── src/
│   ├── server.py               # Flask backend
│   ├── requirements.txt
│   └── Dockerfile
├── solver/
│   └── solve.py                # full exploit chain (IDOR -> flag)
└── build/
    ├── patch_apk.py            # rebuild pipeline (swap pubkey + re-sign)
    ├── original.apk            # upstream HTB APK (not shipped to players)
    ├── debug.keystore          # throwaway signing key
    └── unpacked/               # last extraction (not shipped)
```

## Notes for authors

- The public key inside `dist/infinity-bank.apk` is the lab's, not the
  HTB original — the server uses the matching private key.
- The `infinity-bank.htb` host string was rewritten to
  `infinity-bank.lab` in the patch step so there's no confusion with
  the original challenge.
- Flag is seeded into `TX_LOG` at startup and only echoed back when a
  transfer attempts to move `>= 1337.0` *from* the bank account. A
  legitimate user who happens to know the bank account number still
  can't get it without exploiting the IDOR, because they don't own
  that account and thus shouldn't be allowed to move money out.
