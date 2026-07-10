#!/bin/bash
# Exit on any error
set -e

if [ "$#" -ne 4 ]; then
    echo "Usage: ./package_macos.sh <path_to_icon.png> <path_to_binary> <output_app_path> <version>"
    echo "Example: ./package_macos.sh assets/icon.png bin/locksmith-darwin-arm64 bin/Locksmith-arm64.app 1.2.3"
    exit 1
fi

ICON_SRC="$1"
BINARY_SRC="$2"
APP_DEST="$3"
VERSION="$4"
CONTENTS_DIR="${APP_DEST}/Contents"
MACOS_DIR="${CONTENTS_DIR}/MacOS"
RESOURCES_DIR="${CONTENTS_DIR}/Resources"
ICONSET_DIR="/tmp/Locksmith_$RANDOM.iconset"

echo "Packaging ${APP_DEST}..."

rm -rf "${APP_DEST}"
mkdir -p "${MACOS_DIR}"
mkdir -p "${RESOURCES_DIR}"
mkdir -p "${ICONSET_DIR}"

sips -z 16 16     "${ICON_SRC}" --out "${ICONSET_DIR}/icon_16x16.png" > /dev/null
sips -z 32 32     "${ICON_SRC}" --out "${ICONSET_DIR}/icon_16x16@2x.png" > /dev/null
sips -z 32 32     "${ICON_SRC}" --out "${ICONSET_DIR}/icon_32x32.png" > /dev/null
sips -z 64 64     "${ICON_SRC}" --out "${ICONSET_DIR}/icon_32x32@2x.png" > /dev/null
sips -z 128 128   "${ICON_SRC}" --out "${ICONSET_DIR}/icon_128x128.png" > /dev/null
sips -z 256 256   "${ICON_SRC}" --out "${ICONSET_DIR}/icon_128x128@2x.png" > /dev/null
sips -z 256 256   "${ICON_SRC}" --out "${ICONSET_DIR}/icon_256x256.png" > /dev/null
sips -z 512 512   "${ICON_SRC}" --out "${ICONSET_DIR}/icon_256x256@2x.png" > /dev/null
sips -z 512 512   "${ICON_SRC}" --out "${ICONSET_DIR}/icon_512x512.png" > /dev/null
sips -z 1024 1024 "${ICON_SRC}" --out "${ICONSET_DIR}/icon_512x512@2x.png" > /dev/null

iconutil -c icns "${ICONSET_DIR}" -o "${RESOURCES_DIR}/Locksmith.icns"
rm -rf "${ICONSET_DIR}"

# Copy binary
cp "${BINARY_SRC}" "${MACOS_DIR}/locksmith"

# Info.plist
cat > "${CONTENTS_DIR}/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>locksmith</string>
    <key>CFBundleIconFile</key>
    <string>Locksmith</string>
    <key>CFBundleIdentifier</key>
    <string>io.github.bonjoski.locksmith</string>
    <key>CFBundleName</key>
    <string>Locksmith</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.12</string>
    <key>LSUIElement</key>
    <true/>
</dict>
</plist>
EOF
