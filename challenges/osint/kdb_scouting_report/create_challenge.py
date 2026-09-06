#!/usr/bin/env python3
"""
create_challenge.py — builds kevin-de-bruyne.webp with 4 layered flags.

Layers (easy → insane):
    L1 : EXIF:Artist field             (exiftool)
    L2 : XMP:Description, base64       (exiftool + b64 decode)
    L3 : ZIP appended after the WebP   (binwalk / unzip)
         - scout_readme.txt → plain flag + hint
    L4 : password-protected inner zip inside the L3 zip
         - password is a KDB OSINT fact: birthplace + birth year

If a file named `kdb_photo.jpg` sits next to this script it will be used
as the base image; otherwise a placeholder is rendered with ImageMagick.
Re-run this script any time the organizer wants a fresh flag rotation.
"""
from __future__ import annotations
import base64
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "kevin-de-bruyne.webp"
# Base image candidates, in priority order. First match wins.
BASE_CANDIDATES = (
    HERE / "kdb_photo.webp",
    HERE / "kdb_photo.jpg",
    HERE / "kdb_photo.png",
)
FLAGS_FILE = HERE / "flags.txt"


def find_base_photo() -> Path | None:
    for p in BASE_CANDIDATES:
        if p.exists():
            return p
    return None


def sh(*args: str) -> None:
    subprocess.run(list(args), check=True)


def random_tail() -> str:
    return secrets.token_hex(8)


def render_placeholder(dst: Path) -> None:
    """Render a placeholder webp when no real photo is supplied."""
    from PIL import Image, ImageDraw, ImageFont

    img = Image.new("RGB", (900, 600), color=(10, 31, 58))
    draw = ImageDraw.Draw(img)

    def load(size: int) -> ImageFont.ImageFont:
        for path in (
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        ):
            if Path(path).exists():
                return ImageFont.truetype(path, size)
        return ImageFont.load_default()

    def centered(text: str, y: int, font, fill):
        bbox = draw.textbbox((0, 0), text, font=font)
        w = bbox[2] - bbox[0]
        draw.text(((900 - w) // 2, y), text, font=font, fill=fill)

    centered("KEVIN DE BRUYNE", 220, load(56), (127, 211, 255))
    centered("SCOUTING REPORT", 310, load(26), (224, 224, 224))
    centered("InfoDays 2026  —  classified", 360, load(18), (136, 153, 170))
    centered("(placeholder — drop in kdb_photo.jpg and rerun)", 395, load(14), (100, 115, 130))

    img.save(dst, format="WEBP", quality=92)


def build() -> None:
    for tool in ("exiftool", "convert", "zip"):
        if shutil.which(tool) is None:
            sys.exit(f"missing required tool: {tool}")

    h1, h2, h3, h4 = (random_tail() for _ in range(4))

    flag1 = f"INFODAYS{{SaamNoLimits_the_eye_of_the_scout_{h1}}}"
    flag2 = f"INFODAYS{{SaamNoLimits_the_midfield_vision_{h2}}}"
    flag3 = f"INFODAYS{{SaamNoLimits_the_deep_playmaker_{h3}}}"
    flag4 = f"INFODAYS{{SaamNoLimits_genius_born_in_drongen_{h4}}}"
    zip_password = "drongen1991"

    base = find_base_photo()
    if base is not None:
        # Re-encode through Pillow so we always end up with a clean WebP
        # regardless of the source format.
        from PIL import Image
        with Image.open(base) as im:
            im.save(OUT, format="WEBP", quality=92)
        print(f"[*] using base photo: {base.name}")
    else:
        render_placeholder(OUT)
        print("[*] no kdb_photo.{webp,jpg,png} found — using placeholder")

    # --- L1: EXIF Artist ---
    sh(
        "exiftool", "-overwrite_original",
        f"-Artist={flag1}",
        str(OUT),
    )

    # --- L2: XMP Description with base64-encoded flag ---
    l2_payload = "SCOUT NOTE: " + base64.b64encode(flag2.encode()).decode()
    sh(
        "exiftool", "-overwrite_original",
        f"-XMP-dc:Description={l2_payload}",
        str(OUT),
    )

    # --- L3 + L4: append a zip with a readme and a nested password-protected zip ---
    with tempfile.TemporaryDirectory() as tdstr:
        td = Path(tdstr)

        readme = td / "scout_readme.txt"
        readme.write_text(
            "=== SCOUT'S DEEPER NOTES ===\n"
            f"{flag3}\n\n"
            "The final target dossier is bundled as scout_final.zip.\n"
            "Archive password hint: the town where he was born, lowercase,\n"
            "concatenated with the year he was born. No spaces, no dashes.\n"
            "(If you don't know who 'he' is, you're not a scout.)\n"
        )

        inner_flag = td / "flag.txt"
        inner_flag.write_text(flag4 + "\n")

        inner_zip = td / "scout_final.zip"
        sh("zip", "-j", "-P", zip_password, str(inner_zip), str(inner_flag))
        inner_flag.unlink()

        outer_zip = HERE / "_append.zip"
        if outer_zip.exists():
            outer_zip.unlink()
        sh("zip", "-j", str(outer_zip), str(readme), str(inner_zip))

        with open(OUT, "ab") as f:
            f.write(outer_zip.read_bytes())
        outer_zip.unlink()

    FLAGS_FILE.write_text(
        "# KDB Scouting Report — flag reference (ORGANIZER ONLY, do NOT ship)\n"
        f"L1 (easy   — EXIF Artist):          {flag1}\n"
        f"L2 (medium — XMP base64):           {flag2}\n"
        f"L3 (hard   — appended zip readme):  {flag3}\n"
        f"L4 (insane — inner zip, OSINT pw):  {flag4}\n"
        f"\nInner zip password: {zip_password}\n"
    )

    print("[+] built", OUT)
    print(f"    L1 EXIF:Artist        → {flag1}")
    print(f"    L2 XMP:Description b64→ {flag2}")
    print(f"    L3 scout_readme.txt   → {flag3}")
    print(f"    L4 scout_final.zip[{zip_password}]→ {flag4}")


if __name__ == "__main__":
    build()
