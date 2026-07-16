#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="0.3.0"
ARCH="arm64"
DIST_DIR="$ROOT_DIR/dist"
APP_LINK="$DIST_DIR/Continuum.app"
ARCHIVE="$DIST_DIR/Continuum-$VERSION-macOS-$ARCH-development.zip"
CHECKSUM="$ARCHIVE.sha256"
VERIFY_DIR="$(mktemp -d /private/tmp/com.midas.continuum-package.XXXXXX)"

cleanup() {
  rm -rf "$VERIFY_DIR"
}
trap cleanup EXIT

cd "$ROOT_DIR"

# A judge build must not depend on this developer's signing certificate.
# It is intentionally ad-hoc signed and therefore not a notarized release.
CONTINUUM_SIGNING_IDENTITY="-" ./script/build_and_run.sh --verify

if [[ ! -L "$APP_LINK" ]]; then
  echo "error: expected staged app symlink at $APP_LINK" >&2
  exit 1
fi

STAGED_APP="$(readlink "$APP_LINK")"
if [[ ! -d "$STAGED_APP" ]]; then
  echo "error: staged app is missing at $STAGED_APP" >&2
  exit 1
fi

rm -f "$ARCHIVE" "$CHECKSUM"
/usr/bin/ditto -c -k --sequesterRsrc --keepParent "$STAGED_APP" "$ARCHIVE"
/usr/bin/ditto -x -k "$ARCHIVE" "$VERIFY_DIR"

EXTRACTED_APP="$VERIFY_DIR/Continuum.app"
/usr/bin/codesign --verify --deep --strict "$EXTRACTED_APP"

PACKAGED_VERSION="$(
  /usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" \
    "$EXTRACTED_APP/Contents/Info.plist"
)"
if [[ "$PACKAGED_VERSION" != "$VERSION" ]]; then
  echo "error: packaged version $PACKAGED_VERSION does not match $VERSION" >&2
  exit 1
fi

(
  cd "$DIST_DIR"
  /usr/bin/shasum -a 256 "$(basename "$ARCHIVE")" >"$(basename "$CHECKSUM")"
)

echo "Judge build: $ARCHIVE"
echo "Checksum:    $CHECKSUM"
echo "Note: this is an ad-hoc-signed development build, not a notarized release."
