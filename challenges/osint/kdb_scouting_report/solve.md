# KDB Scouting Report — Writeup

Four flags hidden inside `kevin-de-bruyne.webp`, increasing in depth.

## L1 — Easy (EXIF Artist)

```
$ exiftool kevin-de-bruyne.webp | grep -i artist
Artist : INFODAYS{SaamNoLimits_the_eye_of_the_scout_XXXXXXXXXXXXXXXX}
```

Flat `exiftool` dump. No tricks.

## L2 — Medium (XMP base64)

```
$ exiftool -XMP-dc:Description kevin-de-bruyne.webp
Description : SCOUT NOTE: SU5GT0RBWVN7U2FhbU5vTGltaXRzX3Ro...
$ echo 'SU5GT0RBWVN7...' | base64 -d
INFODAYS{SaamNoLimits_the_midfield_vision_XXXXXXXXXXXXXXXX}
```

A plain `exiftool` dump (no flags) only shows EXIF + common tags. You
have to know XMP lives in its own namespace and pass `-XMP-dc:Description`
(or `-a -G1 kevin-de-bruyne.webp`). Then base64-decode the `SCOUT NOTE:`
payload.

## L3 — Hard (appended ZIP)

```
$ binwalk kevin-de-bruyne.webp
...
16486   0x4066   Zip archive data, name: scout_readme.txt
16810   0x41AA   Zip archive data, name: scout_final.zip
...
$ unzip kevin-de-bruyne.webp -d out
$ cat out/scout_readme.txt
INFODAYS{SaamNoLimits_the_deep_playmaker_XXXXXXXXXXXXXXXX}

The final target dossier is bundled as scout_final.zip.
Archive password hint: the town where he was born, lowercase,
concatenated with the year he was born. No spaces, no dashes.
```

The WebP has a full ZIP appended after the RIFF ends. `file` shows a
normal WebP (image viewers are happy), but `binwalk` / `unzip` pick up
the trailing archive without complaint. Inside you get the hard flag
and an inner archive that gates the insane flag.

## L4 — Insane (OSINT password on the inner ZIP)

`scout_final.zip` is password-protected. The hint in `scout_readme.txt`
is the whole OSINT ask: find the town where Kevin De Bruyne was born and
his birth year.

- Born: **Drongen, Belgium**, on **28 June 1991**.

So the password is:

```
drongen1991
```

```
$ unzip -P drongen1991 scout_final.zip
$ cat flag.txt
INFODAYS{SaamNoLimits_genius_born_in_drongen_XXXXXXXXXXXXXXXX}
```

## Hint ladder for the room

1. *Free:* "Start with the most boring tool you know. `exiftool` has more
   than one namespace."
2. *Cheap:* "Look past the RIFF chunk. What follows an image, technically?"
3. *Expensive:* "The scout left a readme. Read it carefully — he's telling
   you what he wants you to Google."
4. *Last resort:* "Wikipedia's first sentence on KDB is the password."
