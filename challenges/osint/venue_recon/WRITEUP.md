# venue_recon — Writeup

**Category:** OSINT · **Difficulty:** Medium

A pure OSINT challenge: image forensics leads to a tweet, the tweet
leads to a callsign, the callsign becomes the flag.

---

## 1. Recon the attachment

The player is given a single file: `venue_teaser.png` — a sunset shot of
a red-facade building with palm trees and a Moroccan flag.

Quick look at the strings:

```bash
strings venue_teaser.png | grep -Ei 'http|x.com|twitter|status'
```

Returns nothing useful. The plain URL is not embedded in-band.

Next, pull the metadata:

```bash
exiftool venue_teaser.png
```

Three suspicious custom text chunks jump out:

```
Signature        : Infodays 2026 press kit — do not redistribute
Reference ID     : ODY5Mjc2NjAxNzQ3Njc0NDQwMi9zdXRhdHMvc3RpbWlMb05tYWFTL21vYy54Ly86c3B0dGg=
Copyright        : (c) Infodays 2026 Organising Committee
```

The `Reference ID` trailing `=` and the character set scream base64.

## 2. Decode the blob

```bash
echo 'ODY5Mjc2NjAxNzQ3Njc0NDQwMi9zdXRhdHMvc3RpbWlMb05tYWFTL21vYy54Ly86c3B0dGg=' \
    | base64 -d
```

Output:

```
8692766017476744402/sutats/stimiLoNmaaS/moc.x//:sptth
```

Readable left-to-right it looks like gibberish — but the suffixes
`:sptth`, `moc.x`, and `sutats` are obvious reversed forms of `https:`,
`x.com`, and `status`. Reverse the string:

```bash
echo '8692766017476744402/sutats/stimiLoNmaaS/moc.x//:sptth' | rev
```

```
https://x.com/SaamNoLimits/status/2044476747106672968
```

Pivot complete — the image points directly to an X/Twitter post.

## 3. Identify the venue (optional confirmation)

Reverse image search on `venue_teaser.png` (Google Lens, Yandex, or
TinEye) returns hits for **ENSA Agadir** — École Nationale des Sciences
Appliquées, Université Ibn Zohr, Morocco. Confirms the image is a
real-world public building and not a decoy.

## 4. Recover the callsign from the thread

Open the tweet URL. The anchor post is from `@SaamNoLimits` and mentions
the tournament account (`@InfodaysCTF powered-by SaamNoLimits`). Scroll
the thread — a reply from the same account drops the full flag in plain
text:

```
INFODAYS{SaamNoLimits_red_facade_at_sunset}
```

The callsign `red_facade_at_sunset` matches the imagery in the teaser
photo (the red-walled ENSA Agadir entrance shot at sunset).

## 5. Flag

```
INFODAYS{SaamNoLimits_red_facade_at_sunset}
```

## 6. Why Medium

- Requires knowing to inspect PNG metadata (not just `strings`).
- Requires recognising base64 AND that the decoded payload is reversed.
  One layer would be easy; two layers trips beginners.
- Requires a real X/Twitter pivot — player must read the thread, not
  just the first post.
- The venue identification is a freebie (reverse image search) but
  reinforces that the tweet is legit.

## 7. Remediation (for image authors, not players)

- Never publish press-kit images without stripping metadata:
  `exiftool -all= file.png`.
- Assume everything in a PNG chunk is public.
- Don't rely on base64 as obfuscation — it is transport encoding, not
  encryption.

## 8. Related technique

This challenge mimics the "metadata-leak → social-media pivot" pattern
common in real OSINT investigations (journalists tracing press-kit
leaks, corporate brand-protection teams tracking photo republishing).
