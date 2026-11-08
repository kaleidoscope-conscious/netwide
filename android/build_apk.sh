#!/usr/bin/env bash
set -euo pipefail

ANDROID_DIR="/home/jg/netpulse/android"
BUILD_DIR="$ANDROID_DIR/build"
SDK_DIR="/home/jg/android-sdk"
BUILD_TOOLS="$SDK_DIR/build-tools/35.0.0"
PLATFORM_JAR="$SDK_DIR/platforms/android-35/android.jar"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/gen" "$BUILD_DIR/obj" "$BUILD_DIR/dex" "$BUILD_DIR/assets" "$ANDROID_DIR/assets"

# Copy latest mobile.html into Android assets
cp /home/jg/netpulse/static/mobile.html "$ANDROID_DIR/assets/mobile.html"

echo "[1/6] Compiling Android resources with aapt2..."
"$BUILD_TOOLS/aapt2" compile --dir "$ANDROID_DIR/res" -o "$BUILD_DIR/resources.zip"

echo "[2/6] Linking resources, AndroidManifest.xml, and assets..."
"$BUILD_TOOLS/aapt2" link \
  -o "$BUILD_DIR/unsigned.apk" \
  -I "$PLATFORM_JAR" \
  --manifest "$ANDROID_DIR/AndroidManifest.xml" \
  -A "$ANDROID_DIR/assets" \
  --java "$BUILD_DIR/gen" \
  "$BUILD_DIR/resources.zip"

echo "[3/6] Compiling Java sources against Android 35 SDK..."
javac --release 11 \
  -cp "$PLATFORM_JAR" \
  -d "$BUILD_DIR/obj" \
  "$BUILD_DIR/gen/com/netpulse/mobile/R.java" \
  "$ANDROID_DIR/src/com/netpulse/mobile/MainActivity.java"

echo "[4/6] Converting JVM bytecode to Dalvik DEX (classes.dex) with d8..."
CLASS_FILES=$(find "$BUILD_DIR/obj" -name "*.class")
"$BUILD_TOOLS/d8" --lib "$PLATFORM_JAR" --output "$BUILD_DIR/dex" $CLASS_FILES

# Add classes.dex into unsigned.apk
(cd "$BUILD_DIR/dex" && zip -q "$BUILD_DIR/unsigned.apk" classes.dex)

echo "[5/6] Aligning APK with zipalign..."
"$BUILD_TOOLS/zipalign" -f -p 4 "$BUILD_DIR/unsigned.apk" "$BUILD_DIR/aligned.apk"

KEYSTORE="$ANDROID_DIR/netpulse-release.jks"
if [ ! -f "$KEYSTORE" ]; then
  echo "Generating Android release signing keystore..."
  keytool -genkeypair -v \
    -keystore "$KEYSTORE" \
    -alias netpulse \
    -keyalg RSA \
    -keysize 2048 \
    -validity 10000 \
    -storepass netpulse123 \
    -keypass netpulse123 \
    -dname "CN=NetPulse Sovereign Suite, OU=RF Intelligence, O=NetPulse, L=Indianapolis, ST=IN, C=US"
fi

echo "[6/6] Signing APK (v1 + v2 + v3 signatures) with apksigner..."
OUT_APK="/home/jg/netpulse/static/NetPulse-Mobile.apk"
"$BUILD_TOOLS/apksigner" sign \
  --ks "$KEYSTORE" \
  --ks-key-alias netpulse \
  --ks-pass pass:netpulse123 \
  --key-pass pass:netpulse123 \
  --out "$OUT_APK" \
  "$BUILD_DIR/aligned.apk"

"$BUILD_TOOLS/apksigner" verify --verbose "$OUT_APK"
cp "$OUT_APK" /home/jg/Desktop/NetPulse-Mobile.apk

echo "[7/8] Building Google Play Android App Bundle (.aab) in Protobuf format..."
AAB_STAGING="$BUILD_DIR/aab_staging"
AAB_PROTO_ZIP="$BUILD_DIR/proto_base.zip"
rm -rf "$AAB_STAGING" "$AAB_PROTO_ZIP"
mkdir -p "$AAB_STAGING/base/manifest" "$AAB_STAGING/base/dex"

"$BUILD_TOOLS/aapt2" link \
  --proto-format \
  -o "$AAB_PROTO_ZIP" \
  -I "$PLATFORM_JAR" \
  --manifest "$ANDROID_DIR/AndroidManifest.xml" \
  -A "$ANDROID_DIR/assets" \
  "$BUILD_DIR/resources.zip"

unzip -q "$AAB_PROTO_ZIP" -d "$AAB_STAGING/base_raw"
mv "$AAB_STAGING/base_raw/AndroidManifest.xml" "$AAB_STAGING/base/manifest/AndroidManifest.xml"
mv "$AAB_STAGING/base_raw/resources.pb" "$AAB_STAGING/base/resources.pb"
[ -d "$AAB_STAGING/base_raw/res" ] && mv "$AAB_STAGING/base_raw/res" "$AAB_STAGING/base/res"
[ -d "$AAB_STAGING/base_raw/assets" ] && mv "$AAB_STAGING/base_raw/assets" "$AAB_STAGING/base/assets"
cp "$BUILD_DIR/dex/classes.dex" "$AAB_STAGING/base/dex/classes.dex"
rm -rf "$AAB_STAGING/base_raw"
printf '\x0a\x08\x0a\x061.17.1' > "$AAB_STAGING/BundleConfig.pb"

OUT_AAB="/home/jg/netpulse/static/NetPulse-Mobile-PlayStore.aab"
rm -f "$OUT_AAB"
(cd "$AAB_STAGING" && zip -q -r -D "$OUT_AAB" BundleConfig.pb base)

echo "[8/8] Signing Google Play .aab bundle with jarsigner (SHA256withRSA)..."
jarsigner -sigalg SHA256withRSA -digestalg SHA-256 \
  -keystore "$KEYSTORE" \
  -storepass netpulse123 \
  -keypass netpulse123 \
  "$OUT_AAB" netpulse >/dev/null

jarsigner -verify "$OUT_AAB"
cp "$OUT_AAB" /home/jg/Desktop/NetPulse-Mobile-PlayStore.aab
ls -lh "$OUT_APK" "$OUT_AAB" /home/jg/Desktop/NetPulse-Mobile-PlayStore.aab
echo "SUCCESS: Built and verified NetPulse-Mobile.apk + NetPulse-Mobile-PlayStore.aab"
