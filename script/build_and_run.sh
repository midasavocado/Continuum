#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-run}"
APP_NAME="Continuum"
BUNDLE_ID="com.midas.continuum"
MIN_SYSTEM_VERSION="15.0"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
APP_BUNDLE="$DIST_DIR/$APP_NAME.app"
APP_BINARY="$APP_BUNDLE/Contents/MacOS/$APP_NAME"
TMP_BASE="${TMPDIR:-/tmp}"
SCRATCH_ROOT="${TMP_BASE%/}/com.midas.continuum-swiftpm"
SWIFTPM_OPTIONS=(--scratch-path "$SCRATCH_ROOT")
SWIFT_BUILD_OPTIONS=(--scratch-path "$SCRATCH_ROOT")

# Some outer CI/Codex sandboxes prohibit SwiftPM and the Swift macro server
# from nesting Apple's sandbox-exec. Opt in only for those already-sandboxed
# environments; ordinary local builds retain SwiftPM's default sandbox.
if [[ "${CONTINUUM_DISABLE_SWIFTPM_SANDBOX:-0}" == "1" ]]; then
  SWIFTPM_OPTIONS+=(--disable-sandbox)
  SWIFT_BUILD_OPTIONS+=(--disable-sandbox -Xswiftc -disable-sandbox)
fi

usage() {
  echo "usage: $0 [run|--debug|--logs|--telemetry|--verify]" >&2
}

case "$MODE" in
  run|--debug|debug|--logs|logs|--telemetry|telemetry|--verify|verify)
    ;;
  *)
    usage
    exit 2
    ;;
esac

if [[ "$#" -gt 1 ]]; then
  usage
  exit 2
fi

pkill -x "$APP_NAME" >/dev/null 2>&1 || true

cd "$ROOT_DIR"
rm -rf "$SCRATCH_ROOT"
mkdir -p "$SCRATCH_ROOT/ClangModuleCache" "$SCRATCH_ROOT/SwiftPMModuleCache"
export CLANG_MODULE_CACHE_PATH="$SCRATCH_ROOT/ClangModuleCache"
export SWIFTPM_MODULECACHE_OVERRIDE="$SCRATCH_ROOT/SwiftPMModuleCache"
swift build "${SWIFT_BUILD_OPTIONS[@]}" --product "$APP_NAME"
swift build "${SWIFT_BUILD_OPTIONS[@]}" --product ContinuumBootstrap
swift build "${SWIFT_BUILD_OPTIONS[@]}" --product ContinuumTerminalRelay
swift build "${SWIFT_BUILD_OPTIONS[@]}" --product ContinuumManagedExec
BUILD_DIR="$(swift build "${SWIFTPM_OPTIONS[@]}" --show-bin-path)"
BUILD_BINARY="$BUILD_DIR/$APP_NAME"
BUILD_BOOTSTRAP="$BUILD_DIR/libContinuumBootstrap.dylib"
BUILD_TERMINAL_RELAY="$BUILD_DIR/ContinuumTerminalRelay"
BUILD_MANAGED_EXEC="$BUILD_DIR/ContinuumManagedExec"

if [[ ! -x "$BUILD_BINARY" ]]; then
  echo "error: SwiftPM did not produce $BUILD_BINARY" >&2
  exit 1
fi
if [[ ! -f "$BUILD_BOOTSTRAP" ]]; then
  echo "error: SwiftPM did not produce $BUILD_BOOTSTRAP" >&2
  exit 1
fi
if [[ ! -x "$BUILD_TERMINAL_RELAY" ]]; then
  echo "error: SwiftPM did not produce $BUILD_TERMINAL_RELAY" >&2
  exit 1
fi
if [[ ! -x "$BUILD_MANAGED_EXEC" ]]; then
  echo "error: SwiftPM did not produce $BUILD_MANAGED_EXEC" >&2
  exit 1
fi

STAGED_BUNDLE="$SCRATCH_ROOT/Staged/$APP_NAME.app"
STAGED_CONTENTS="$STAGED_BUNDLE/Contents"
STAGED_MACOS="$STAGED_CONTENTS/MacOS"
STAGED_RESOURCES="$STAGED_CONTENTS/Resources"
STAGED_FRAMEWORKS="$STAGED_CONTENTS/Frameworks"
STAGED_HELPERS="$STAGED_CONTENTS/Helpers"
STAGED_BINARY="$STAGED_MACOS/$APP_NAME"
STAGED_BOOTSTRAP="$STAGED_FRAMEWORKS/libContinuumBootstrap.dylib"
ARM64E_BOOTSTRAP="$SCRATCH_ROOT/libContinuumBootstrap-arm64e.dylib"
UNIVERSAL_BOOTSTRAP="$SCRATCH_ROOT/libContinuumBootstrap-universal.dylib"
STAGED_TERMINAL_RELAY="$STAGED_HELPERS/ContinuumTerminalRelay"
STAGED_MANAGED_EXEC="$STAGED_HELPERS/ContinuumManagedExec"
INFO_PLIST="$STAGED_CONTENTS/Info.plist"
APP_ICON="$ROOT_DIR/Assets/Continuum.icns"
APP_ENTITLEMENTS="$ROOT_DIR/Configuration/Continuum.entitlements"

if [[ ! -f "$APP_ICON" ]]; then
  echo "error: missing app icon at $APP_ICON" >&2
  exit 1
fi

if [[ ! -f "$APP_ENTITLEMENTS" ]]; then
  echo "error: missing app entitlements at $APP_ENTITLEMENTS" >&2
  exit 1
fi

mkdir -p "$STAGED_MACOS" "$STAGED_RESOURCES" "$STAGED_FRAMEWORKS" "$STAGED_HELPERS"
cp "$BUILD_BINARY" "$STAGED_BINARY"
# Apple's system shells are arm64e while ordinary third-party apps are arm64.
# One signed fat bootstrap lets a managed Terminal session arm both without
# modifying either original executable.
xcrun clang \
  -arch arm64e \
  -mmacosx-version-min="$MIN_SYSTEM_VERSION" \
  -O2 \
  -dynamiclib \
  -install_name @rpath/libContinuumBootstrap.dylib \
  -include mach/mach_vm.h \
  -I "$ROOT_DIR/Sources/ContinuumBootstrap/include" \
  "$ROOT_DIR/Sources/ContinuumBootstrap/ContinuumBootstrap.c" \
  -framework CoreFoundation \
  -lobjc \
  -o "$ARM64E_BOOTSTRAP"
lipo -create "$BUILD_BOOTSTRAP" "$ARM64E_BOOTSTRAP" -output "$UNIVERSAL_BOOTSTRAP"
cp "$UNIVERSAL_BOOTSTRAP" "$STAGED_BOOTSTRAP"
cp "$BUILD_TERMINAL_RELAY" "$STAGED_TERMINAL_RELAY"
cp "$BUILD_MANAGED_EXEC" "$STAGED_MANAGED_EXEC"
cp "$APP_ICON" "$STAGED_RESOURCES/Continuum.icns"
chmod +x "$STAGED_BINARY" "$STAGED_TERMINAL_RELAY" "$STAGED_MANAGED_EXEC"

/usr/libexec/PlistBuddy -c "Clear dict" "$INFO_PLIST" >/dev/null 2>&1 || true
/usr/libexec/PlistBuddy -c "Add :CFBundleDevelopmentRegion string en" "$INFO_PLIST"
/usr/libexec/PlistBuddy -c "Add :CFBundleDisplayName string $APP_NAME" "$INFO_PLIST"
/usr/libexec/PlistBuddy -c "Add :CFBundleExecutable string $APP_NAME" "$INFO_PLIST"
/usr/libexec/PlistBuddy -c "Add :CFBundleIconFile string Continuum.icns" "$INFO_PLIST"
/usr/libexec/PlistBuddy -c "Add :CFBundleIdentifier string $BUNDLE_ID" "$INFO_PLIST"
/usr/libexec/PlistBuddy -c "Add :CFBundleInfoDictionaryVersion string 6.0" "$INFO_PLIST"
/usr/libexec/PlistBuddy -c "Add :CFBundleName string $APP_NAME" "$INFO_PLIST"
/usr/libexec/PlistBuddy -c "Add :CFBundlePackageType string APPL" "$INFO_PLIST"
/usr/libexec/PlistBuddy -c "Add :CFBundleShortVersionString string 0.3.0" "$INFO_PLIST"
/usr/libexec/PlistBuddy -c "Add :CFBundleVersion string 5" "$INFO_PLIST"
/usr/libexec/PlistBuddy -c "Add :LSApplicationCategoryType string public.app-category.utilities" "$INFO_PLIST"
/usr/libexec/PlistBuddy -c "Add :LSMinimumSystemVersion string $MIN_SYSTEM_VERSION" "$INFO_PLIST"
/usr/libexec/PlistBuddy -c "Add :NSAccessibilityUsageDescription string Continuum uses Accessibility only when you ask it to identify and coordinate the app you are capturing." "$INFO_PLIST"
/usr/libexec/PlistBuddy -c "Add :NSAppleEventsUsageDescription string Continuum uses Apple Events only when you approve automation for a selected app." "$INFO_PLIST"
/usr/libexec/PlistBuddy -c "Add :NSApplicationSupportsSecureRestorableState bool true" "$INFO_PLIST"
/usr/libexec/PlistBuddy -c "Add :NSHighResolutionCapable bool true" "$INFO_PLIST"
/usr/libexec/PlistBuddy -c "Add :NSPrincipalClass string NSApplication" "$INFO_PLIST"
/usr/libexec/PlistBuddy -c "Add :NSScreenCaptureUsageDescription string Continuum uses Screen Recording to build a private visual timeline for apps you select." "$INFO_PLIST"
/usr/bin/plutil -lint "$INFO_PLIST"

# Prefer an available Apple Development identity so TCC and the debugger
# entitlement see a stable local signer. Contributors without one still get an
# ad-hoc development build, although external-process setup cannot be certified.
# File-provider workspaces may stamp Finder metadata onto newly created bundles;
# codesign correctly rejects those extended attributes as unsealed detritus.
/usr/bin/xattr -cr "$STAGED_BUNDLE"
SIGNING_IDENTITY="${CONTINUUM_SIGNING_IDENTITY:-}"
if [[ -z "$SIGNING_IDENTITY" ]]; then
  SIGNING_IDENTITY="$(
    /usr/bin/security find-identity -v -p codesigning 2>/dev/null \
      | /usr/bin/sed -n 's/.*"\(Apple Development:[^"]*\)".*/\1/p' \
      | /usr/bin/head -1
  )"
fi
if [[ -z "$SIGNING_IDENTITY" ]]; then
  SIGNING_IDENTITY="-"
fi

/usr/bin/codesign \
  --force \
  --sign "$SIGNING_IDENTITY" \
  --options runtime \
  --timestamp=none \
  "$STAGED_BOOTSTRAP"

/usr/bin/codesign \
  --force \
  --sign "$SIGNING_IDENTITY" \
  --options runtime \
  --timestamp=none \
  "$STAGED_TERMINAL_RELAY"

/usr/bin/codesign \
  --force \
  --sign "$SIGNING_IDENTITY" \
  --options runtime \
  --timestamp=none \
  "$STAGED_MANAGED_EXEC"

/usr/bin/codesign \
  --force \
  --sign "$SIGNING_IDENTITY" \
  --options runtime \
  --entitlements "$APP_ENTITLEMENTS" \
  --timestamp=none \
  "$STAGED_BUNDLE"
/usr/bin/codesign --verify --deep --strict "$STAGED_BUNDLE"

# Keep the signed bundle in the external SwiftPM scratch tree and expose it at
# dist/Continuum.app through a symlink. Some synced Documents folders recreate
# FinderInfo while codesign reads any in-place app, even after `xattr -cr`.
mkdir -p "$DIST_DIR"
rm -rf "$APP_BUNDLE"
ln -s "$STAGED_BUNDLE" "$APP_BUNDLE"
/usr/bin/codesign --verify --deep --strict "$APP_BUNDLE"

open_app() {
  /usr/bin/open -n "$APP_BUNDLE"
}

wait_for_process() {
  local attempt
  for attempt in {1..40}; do
    if pgrep -x "$APP_NAME" >/dev/null; then
      return 0
    fi
    sleep 0.25
  done

  echo "error: $APP_NAME did not remain running after launch" >&2
  return 1
}

case "$MODE" in
  run)
    open_app
    ;;
  --debug|debug)
    exec /usr/bin/lldb -- "$APP_BINARY"
    ;;
  --logs|logs)
    open_app
    wait_for_process
    exec /usr/bin/log stream --info --style compact --predicate "process == \"$APP_NAME\""
    ;;
  --telemetry|telemetry)
    open_app
    wait_for_process
    exec /usr/bin/log stream --info --style compact --predicate "subsystem == \"$BUNDLE_ID\""
    ;;
  --verify|verify)
    open_app
    wait_for_process
    echo "$APP_NAME is running from $APP_BUNDLE"
    ;;
esac
