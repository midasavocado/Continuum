#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIGNING_IDENTITY="${CONTINUUM_SIGNING_IDENTITY:-}"
SCRATCH_DIR="$(mktemp -d /private/tmp/com.midas.continuum-gui-cold-proof.XXXXXX)"
SWIFT_OPTIONS=(--scratch-path "$SCRATCH_DIR")

cleanup() {
  rm -rf "$SCRATCH_DIR"
}
trap cleanup EXIT

if [[ -z "$SIGNING_IDENTITY" ]]; then
  SIGNING_IDENTITY="$(
    /usr/bin/security find-identity -v -p codesigning |
      /usr/bin/awk '/"Apple Development:/ { print $2; exit }'
  )"
fi

if [[ -z "$SIGNING_IDENTITY" ]]; then
  echo "error: no Apple Development signing identity is available" >&2
  exit 1
fi

mkdir -p "$SCRATCH_DIR/ClangModuleCache" "$SCRATCH_DIR/SwiftPMModuleCache"
export CLANG_MODULE_CACHE_PATH="$SCRATCH_DIR/ClangModuleCache"
export SWIFTPM_MODULECACHE_OVERRIDE="$SCRATCH_DIR/SwiftPMModuleCache"

SIP_BEFORE="$(/usr/bin/csrutil status 2>&1)"

cd "$ROOT_DIR"
swift build "${SWIFT_OPTIONS[@]}" --product ContinuumHarness
swift build "${SWIFT_OPTIONS[@]}" --product ContinuumGUIExternalTarget
swift build "${SWIFT_OPTIONS[@]}" --product ContinuumBootstrap
BIN_DIR="$(swift build --scratch-path "$SCRATCH_DIR" --show-bin-path)"
HARNESS="$BIN_DIR/ContinuumHarness"
TARGET="$BIN_DIR/ContinuumGUIExternalTarget"
BOOTSTRAP="$BIN_DIR/libContinuumBootstrap.dylib"

for binary in "$HARNESS" "$TARGET" "$BOOTSTRAP"; do
  /usr/bin/xattr -cr "$binary"
done

/usr/bin/codesign --force --sign "$SIGNING_IDENTITY" --options runtime \
  --timestamp=none "$BOOTSTRAP"
/usr/bin/codesign --force --sign "$SIGNING_IDENTITY" --options runtime \
  --timestamp=none \
  --entitlements "$ROOT_DIR/Configuration/ContinuumExternalTarget.entitlements" \
  "$TARGET"
/usr/bin/codesign --force --sign "$SIGNING_IDENTITY" --options runtime \
  --timestamp=none \
  --entitlements "$ROOT_DIR/Configuration/ContinuumHarness.entitlements" \
  "$HARNESS"

for binary in "$HARNESS" "$TARGET" "$BOOTSTRAP"; do
  /usr/bin/codesign --verify --strict --verbose=2 "$binary"
done

echo "GUI cold proof signing identity: $SIGNING_IDENTITY"
echo "$SIP_BEFORE"

CONTINUUM_BOOTSTRAP_LIBRARY_PATH="$BOOTSTRAP" \
  "$HARNESS" gui-cold-proof --target "$TARGET"

SIP_AFTER="$(/usr/bin/csrutil status 2>&1)"
if [[ "$SIP_AFTER" != "$SIP_BEFORE" ]]; then
  echo "error: SIP status changed during proof" >&2
  exit 1
fi
echo "SIP status unchanged."
