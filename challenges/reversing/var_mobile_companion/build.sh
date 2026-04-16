#!/usr/bin/env bash
#
# var_mobile_companion — build pipeline.
#
# Pipeline:
#   1. python3 gen.py               regenerate flags + Java sources
#   2. javac src/java/**.java       -> build/classes/**
#   3. java -cp r8.jar D8           -> build/classes.dex
#   4. aapt2 compile --dir src/res  -> build/compiled/*.flat
#   5. aapt2 link                    -> build/base.apk (AXML + arsc)
#   6. zip classes.dex + assets/     into base.apk
#   7. jarsigner V1 sign             -> dist/companion.apk
#
# Required host tools (already present under ~/tools):
#   - r8.jar        (contains d8)    ~/tools/r8/r8.jar
#   - aapt2 + libs                    ~/tools/aapt/aapt2
#   - framework-res.apk (Android)    ~/tools/aapt/framework-res.apk
#   - JDK 11+                         /usr/bin/{javac,jarsigner,keytool}

set -euo pipefail
cd "$(dirname "$0")"

TOOLS="${TOOLS:-$HOME/tools}"
R8_JAR="$TOOLS/r8/r8.jar"
AAPT2="$TOOLS/aapt/aapt2"
AAPT2_LIB="$TOOLS/aapt/lib"
FRAMEWORK="$TOOLS/aapt/framework-res.apk"

export LD_LIBRARY_PATH="$AAPT2_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

for t in "$R8_JAR" "$AAPT2" "$FRAMEWORK"; do
    if [ ! -e "$t" ]; then
        echo "[-] missing tool: $t" >&2
        exit 1
    fi
done

echo "[*] (1) regenerating flags + sources"
python3 gen.py "$@"

rm -rf build dist
mkdir -p build/classes build/compiled dist

echo "[*] (2) javac -> .class"
find src/java -name '*.java' -print0 \
    | xargs -0 javac -d build/classes -source 8 -target 8 -nowarn

echo "[*] (3) d8 -> classes.dex"
CLASSES=$(find build/classes -name '*.class')
java -cp "$R8_JAR" com.android.tools.r8.D8 \
    --release \
    --min-api 21 \
    --output build/ \
    $CLASSES

echo "[*] (4) aapt2 compile res/"
"$AAPT2" compile --dir src/res -o build/compiled/

echo "[*] (5) aapt2 link -> base.apk"
FLATS=$(ls build/compiled/*.flat)
"$AAPT2" link \
    -I "$FRAMEWORK" \
    --manifest src/AndroidManifest.xml \
    -o build/base.apk \
    --min-sdk-version 21 \
    --target-sdk-version 33 \
    $FLATS

echo "[*] (6) merge classes.dex + assets/ into apk"
cp build/base.apk build/unsigned.apk
(cd build && zip -qj unsigned.apk classes.dex)
(cd src && zip -qr ../build/unsigned.apk assets)

echo "[*] (7) sign (V1 jar-signed)"
KEYSTORE="build/debug.keystore"
if [ ! -f "$KEYSTORE" ]; then
    keytool -genkeypair -noprompt \
        -keystore "$KEYSTORE" \
        -storepass android \
        -keypass android \
        -alias companion \
        -keyalg RSA -keysize 2048 \
        -validity 10000 \
        -dname "CN=InfodaysCTF, OU=SaamNoLimits, O=Infodays2026, L=Agadir, S=Souss, C=MA" \
        >/dev/null 2>&1
fi
cp build/unsigned.apk dist/companion.apk
jarsigner -keystore "$KEYSTORE" \
    -storepass android \
    -keypass android \
    -sigalg SHA256withRSA \
    -digestalg SHA-256 \
    dist/companion.apk companion \
    >/dev/null

echo "[+] built $(du -h dist/companion.apk | cut -f1) $(realpath dist/companion.apk)"
