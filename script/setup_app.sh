#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH_ROOT="${TMPDIR:-/tmp}"
SCRATCH_ROOT="${SCRATCH_ROOT%/}/com.midas.continuum-setup-cli"
SWIFT_OPTIONS=(--scratch-path "$SCRATCH_ROOT")

usage() {
  echo "usage: $0 <app-or-executable-path> [--check-only]" >&2
}

if [[ "$#" -lt 1 || "$#" -gt 2 ]]; then
  usage
  exit 2
fi

TARGET_PATH="$1"
CHECK_ONLY=0
if [[ "$#" -eq 2 ]]; then
  if [[ "$2" != "--check-only" ]]; then
    usage
    exit 2
  fi
  CHECK_ONLY=1
fi

if [[ "${CONTINUUM_DISABLE_SWIFTPM_SANDBOX:-0}" == "1" ]]; then
  SWIFT_OPTIONS+=(--disable-sandbox -Xswiftc -disable-sandbox)
fi

mkdir -p "$SCRATCH_ROOT/ClangModuleCache" "$SCRATCH_ROOT/SwiftPMModuleCache"
export CLANG_MODULE_CACHE_PATH="$SCRATCH_ROOT/ClangModuleCache"
export SWIFTPM_MODULECACHE_OVERRIDE="$SCRATCH_ROOT/SwiftPMModuleCache"

cd "$ROOT_DIR"
swift build "${SWIFT_OPTIONS[@]}" --product ContinuumHarness
BIN_DIR="$(swift build --scratch-path "$SCRATCH_ROOT" --show-bin-path)"

COMMAND=("$BIN_DIR/ContinuumHarness" setup-app --target "$TARGET_PATH")
if [[ -n "${CONTINUUM_APP_SETUP_ROOT:-}" ]]; then
  COMMAND+=(--root "$CONTINUUM_APP_SETUP_ROOT")
fi
if [[ "$CHECK_ONLY" == "1" ]]; then
  COMMAND+=(--check-only)
fi

exec "${COMMAND[@]}"
