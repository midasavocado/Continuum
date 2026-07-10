#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SVG="$ROOT_DIR/Assets/ContinuumIcon.svg"
OUTPUT="$ROOT_DIR/Assets/Continuum.icns"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/continuum-icon.XXXXXX")"
ICONSET="$WORK_DIR/Continuum.iconset"
MASTER="$WORK_DIR/ContinuumIcon.png"

cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

if ! command -v rsvg-convert >/dev/null 2>&1; then
  echo "error: rsvg-convert is required to regenerate the icon." >&2
  echo "Install it with: brew install librsvg" >&2
  exit 1
fi

mkdir -p "$ICONSET"
rsvg-convert --width 1024 --height 1024 "$SVG" --output "$MASTER"

make_icon() {
  local size="$1"
  local name="$2"
  /usr/bin/sips --resampleHeightWidth "$size" "$size" "$MASTER" --out "$ICONSET/$name" >/dev/null
}

make_icon 16 icon_16x16.png
make_icon 32 icon_16x16@2x.png
make_icon 32 icon_32x32.png
make_icon 64 icon_32x32@2x.png
make_icon 128 icon_128x128.png
make_icon 256 icon_128x128@2x.png
make_icon 256 icon_256x256.png
make_icon 512 icon_256x256@2x.png
make_icon 512 icon_512x512.png
make_icon 1024 icon_512x512@2x.png

/usr/bin/iconutil --convert icns --output "$OUTPUT" "$ICONSET"
echo "Generated $OUTPUT"
