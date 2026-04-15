# venue_recon

**Category:** OSINT
**Difficulty:** Medium
**Type:** Static (attachment only, no container)

## Player brief

> The Infodays 2026 organising committee leaked a promo image before the
> official announcement went live. Unfortunately for them, they forgot to
> scrub the image metadata — and the embedded clue pivots straight to the
> organiser's public announcement thread.
>
> Your job: trace the chain, find the announcement, and recover the
> callsign the organiser hid in the thread.
>
> **Attached:** `venue_teaser.png`
>
> **Flag format:** `INFODAYS{SaamNoLimits_<callsign>}`

## Intended pivot chain

1. **Image forensics.** `exiftool venue_teaser.png` exposes three custom
   text chunks: `Signature`, `Reference ID`, `Copyright`. The
   `Reference ID` value is a suspicious base64 blob.
2. **Base64 decode.** Decoding yields a backwards-looking string:
   `8692766017476744402/sutats/stimiLoNmaaS/moc.x//:sptth`
3. **String reverse.** Reversing character-by-character gives the real
   URL: the announcement tweet on X.
4. **Visual recon.** The pinned / attached photo on that tweet is the
   same venue as the teaser. Reverse-image-search confirms the building
   is **ENSA Agadir** (École Nationale des Sciences Appliquées) in
   Morocco.
5. **Thread recon.** A reply in the same thread announces the organiser's
   callsign for the tournament. That callsign becomes the flag.

## Flag

```
INFODAYS{SaamNoLimits_red_facade_at_sunset}
```

The callsign is posted as a reply in the organiser's X thread (see
[`WRITEUP.md`](./WRITEUP.md) for the full solution and tweet URL).

## Files

| Path | Purpose |
|---|---|
| `venue_teaser.png` | Attachment — press-kit photo with hidden URL in metadata |
| `WRITEUP.md` | Author writeup |
| `README.md` | This file |

## Deployment

This challenge is **static**. Upload `venue_teaser.png` as a CTFd
challenge attachment, set the flag in CTFd's admin panel, and publish.
No docker service, no RPC, no frontend. Players download the file and
work offline.

## Hardening notes (if you want to raise difficulty)

- Rename `Reference ID` to something less obvious (e.g. `SourceHash`).
- XOR the base64 blob with a short key hinted at in `Signature`.
- Split the URL across two metadata fields that must be concatenated.
- Put the blob in a `zTXt` (compressed) chunk instead of `tEXt` so
  players must use `pngcheck` or `pnginfo` rather than plain `exiftool`.
