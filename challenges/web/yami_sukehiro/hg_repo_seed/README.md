# Black Bulls — Captain's Vault

Internal repository for the Black Bulls mana signature service.

The vault is sealed with `CAPTAIN_SECRET`. It is used as the passphrase
to the encrypted `root.txt.enc` file. The encryption is AES-256-CBC with
PBKDF2 via `openssl enc`.

Example decrypt:
```
openssl enc -aes-256-cbc -d -pbkdf2 -pass pass:"$CAPTAIN_SECRET" \
    -in /flags/root.txt.enc
```

— Yami Sukehiro
