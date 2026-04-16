# KDB Scouting Report

**Category:** OSINT / forensics hybrid
**Flags:** 4 (easy → insane)
**Artifact:** `kevin-de-bruyne.webp`

> A rival scout's report on Kevin De Bruyne leaked into our inbox as a
> single innocent-looking `.webp`. He hid four notes in there, each
> deeper than the last — and the final one is locked behind a fact only
> someone who's actually scouted the man would know.

## For players

You get exactly one file: `kevin-de-bruyne.webp`. Find four flags of
increasing difficulty.

- **L1 (easy)** — anyone with `exiftool` can get this in one command.
- **L2 (medium)** — same tool, deeper namespace, one decoder.
- **L3 (hard)** — the image is hiding more than pixels.
- **L4 (insane)** — the scout's final note is locked. Only someone who
  *knows* Kevin De Bruyne gets in.

All flags are in the format `INFODAYS{...}`.

## For the organizer

### Build

```
python3 create_challenge.py
```

This regenerates `kevin-de-bruyne.webp` and `flags.txt` with fresh
random tails on every run. Requirements:

- `python3` with `Pillow`
- `exiftool`
- `zip`

If you want a real KDB photo instead of the placeholder, drop a
`kdb_photo.jpg` next to `create_challenge.py` before running — the
script will use it as the base image and inject the same four layers.

### Ship

Upload **only** `kevin-de-bruyne.webp` to CTFd. Do **not** ship:

- `create_challenge.py` (reveals the whole structure)
- `flags.txt` (obviously)
- `solve.md`
- `kdb_photo.jpg` (if you added one)

### Layers (author reference)

| Flag | Difficulty | Location | Tool |
|---|---|---|---|
| L1 | easy | `EXIF:Artist` | `exiftool` |
| L2 | medium | `XMP-dc:Description`, base64 | `exiftool` + `base64` |
| L3 | hard | ZIP appended after the WebP, `scout_readme.txt` | `binwalk` / `unzip` |
| L4 | insane | inner `scout_final.zip`, password-protected | `unzip -P <KDB fact>` |

The password for the inner archive is `drongen1991` — Kevin De Bruyne's
birthplace (Drongen, Belgium) concatenated with his birth year (1991).
Both facts are in the first sentence of his Wikipedia page.

See `solve.md` for the full walkthrough and hint ladder.
