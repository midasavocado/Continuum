#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CYCLES="${CONTINUUM_EXTERNAL_HOT_CYCLES:-100}"
SIGNING_IDENTITY="${CONTINUUM_SIGNING_IDENTITY:-}"
SCRATCH_DIR="$(mktemp -d /private/tmp/com.midas.continuum-external-hot-proof.XXXXXX)"
SWIFT_OPTIONS=(--scratch-path "$SCRATCH_DIR")

cleanup() {
  rm -rf "$SCRATCH_DIR"
}
trap cleanup EXIT

if [[ ! "$CYCLES" =~ ^[0-9]+$ ]] || (( CYCLES < 100 )); then
  echo "error: CONTINUUM_EXTERNAL_HOT_CYCLES must be an integer of at least 100" >&2
  exit 2
fi

if [[ -z "$SIGNING_IDENTITY" ]]; then
  SIGNING_IDENTITY="$(
    /usr/bin/security find-identity -v -p codesigning |
      /usr/bin/awk '/"Apple Development:/ { print $2; exit }'
  )"
fi

if [[ -z "$SIGNING_IDENTITY" ]]; then
  echo "error: no Apple Development signing identity is available" >&2
  echo "Set CONTINUUM_SIGNING_IDENTITY to an available identity or install one in Keychain." >&2
  exit 1
fi

if [[ "${CONTINUUM_DISABLE_SWIFTPM_SANDBOX:-0}" == "1" ]]; then
  SWIFT_OPTIONS+=(--disable-sandbox -Xswiftc -disable-sandbox)
fi

mkdir -p "$SCRATCH_DIR/ClangModuleCache" "$SCRATCH_DIR/SwiftPMModuleCache"
export CLANG_MODULE_CACHE_PATH="$SCRATCH_DIR/ClangModuleCache"
export SWIFTPM_MODULECACHE_OVERRIDE="$SCRATCH_DIR/SwiftPMModuleCache"

SIP_BEFORE="$(/usr/bin/csrutil status 2>&1)"

cd "$ROOT_DIR"
swift build "${SWIFT_OPTIONS[@]}" --product ContinuumHarness
swift build "${SWIFT_OPTIONS[@]}" --product ContinuumExternalTarget
swift build "${SWIFT_OPTIONS[@]}" --product ContinuumBootstrap
BIN_DIR="$(swift build --scratch-path "$SCRATCH_DIR" --show-bin-path)"
HARNESS="$BIN_DIR/ContinuumHarness"
TARGET="$BIN_DIR/ContinuumExternalTarget"
BOOTSTRAP="$BIN_DIR/libContinuumBootstrap.dylib"

for binary in "$HARNESS" "$TARGET" "$BOOTSTRAP"; do
  if [[ ! -f "$binary" ]]; then
    echo "error: SwiftPM did not produce $binary" >&2
    exit 1
  fi
  /usr/bin/xattr -cr "$binary"
done

/usr/bin/codesign \
  --force \
  --sign "$SIGNING_IDENTITY" \
  --options runtime \
  --timestamp=none \
  "$BOOTSTRAP"

/usr/bin/codesign \
  --force \
  --sign "$SIGNING_IDENTITY" \
  --options runtime \
  --timestamp=none \
  --entitlements "$ROOT_DIR/Configuration/ContinuumExternalTarget.entitlements" \
  "$TARGET"

/usr/bin/codesign \
  --force \
  --sign "$SIGNING_IDENTITY" \
  --options runtime \
  --timestamp=none \
  --entitlements "$ROOT_DIR/Configuration/ContinuumHarness.entitlements" \
  "$HARNESS"

/usr/bin/codesign --verify --strict --verbose=2 "$TARGET"
/usr/bin/codesign --verify --strict --verbose=2 "$HARNESS"
/usr/bin/codesign --verify --strict --verbose=2 "$BOOTSTRAP"

TARGET_ENTITLEMENTS="$SCRATCH_DIR/target-entitlements.plist"
HARNESS_ENTITLEMENTS="$SCRATCH_DIR/harness-entitlements.plist"
/usr/bin/codesign -d --entitlements :- "$TARGET" >"$TARGET_ENTITLEMENTS" 2>/dev/null
/usr/bin/codesign -d --entitlements :- "$HARNESS" >"$HARNESS_ENTITLEMENTS" 2>/dev/null

if [[ "$(/usr/bin/plutil -extract 'com\.apple\.security\.get-task-allow' raw "$TARGET_ENTITLEMENTS")" != "true" ]]; then
  echo "error: signed target is missing com.apple.security.get-task-allow" >&2
  exit 1
fi
if [[ "$(/usr/bin/plutil -extract 'com\.apple\.security\.cs\.allow-dyld-environment-variables' raw "$TARGET_ENTITLEMENTS")" != "true" ]]; then
  echo "error: signed target is missing com.apple.security.cs.allow-dyld-environment-variables" >&2
  exit 1
fi
if [[ "$(/usr/bin/plutil -extract 'com\.apple\.security\.cs\.debugger' raw "$HARNESS_ENTITLEMENTS")" != "true" ]]; then
  echo "error: signed harness is missing com.apple.security.cs.debugger" >&2
  exit 1
fi

echo "External hot proof signing identity: $SIGNING_IDENTITY"
echo "Target entitlement verified: com.apple.security.get-task-allow"
echo "Target entitlement verified: com.apple.security.cs.allow-dyld-environment-variables"
echo "Harness entitlement verified: com.apple.security.cs.debugger"
echo "$SIP_BEFORE"

CONTINUUM_BOOTSTRAP_LIBRARY_PATH="$BOOTSTRAP" \
  "$HARNESS" external-hot-proof --target "$TARGET" --cycles "$CYCLES"

SIP_AFTER="$(/usr/bin/csrutil status 2>&1)"
if [[ "$SIP_AFTER" != "$SIP_BEFORE" ]]; then
  echo "error: SIP status changed during proof" >&2
  echo "before: $SIP_BEFORE" >&2
  echo "after:  $SIP_AFTER" >&2
  exit 1
fi
echo "SIP status unchanged."
