# Continuum

Continuum is a native macOS research prototype for safe, branching app snapshots: save a moment, preserve the current future before rewinding, and never label a screenshot as restorable state.

> **Current status: v0.2 research build.** Continuum can now prepare eligible app bundles through one generic managed-copy pipeline and repeatedly restore one explicitly registered memory arena in its signed external proof target. It still does **not** rewind an arbitrary complete app or game. It cannot currently restore a crashed KSP flight, Safari, an IDE, or another process's full RAM and kernel/resource state. The tiny time machine has graduated from cardboard to one real gear—not the whole DeLorean.

Continuum requires macOS 15 or later and keeps System Integrity Protection enabled.

## What v0.2 implements

- A native SwiftUI consumer shell with resumable onboarding, plain-language limits, real opt-in Accessibility and Screen Recording request actions, storage selection, and a self-contained rewind demo.
- A broad inventory of running window owners and installed `.app` bundles, plus explicit selection of an app or executable anywhere on disk.
- One generic managed-copy setup pipeline for eligible app bundles: probe, preserve a verified original, clone a separate managed copy, add only Continuum's marker, ad-hoc sign it with `get-task-allow`, validate every artifact, persist the result, and roll back partial failures.
- Exact blockers for Apple platform binaries, sandbox or identity-bound apps, App Store/DRM targets, restricted entitlements, unsupported nested code, malformed bundles, and standalone executables that cannot use the current bundle route.
- A floating native rewind timeline opened by a configurable global shortcut, with arrow-key navigation, Return to commit validated points, Escape to cancel, and an explicit unavailable state for metadata-only moments.
- Global `Control–Option–Command–S` diagnostic-snapshot registration plus safe rewind-shortcut presets while Continuum is running.
- A metadata-only capture fallback that records the selected process tree's identity and resource counts, explicitly marks the snapshot `Unavailable`, and refuses fake restoration.
- Typed snapshot, checkpoint, branch, compatibility, storage, and external-effect models shared by the app, store, and test harness.
- An encrypted, content-addressed snapshot-store implementation with immutable manual snapshots, provisional pre-rewind safety snapshots, atomic branch creation, deduplication, and integrity verification.
- A signed cross-process Mach proof that suspends the included cooperative target, captures one registered private/COW arena plus ARM64 thread-state evidence, restores and readback-verifies that arena, and alternates two target-owned states for 100 cycles.
- Emergency rollback bytes, PID/start-time/executable-inode pinning, mapping/protection/thread-set validation, bounded protocol timeouts, and balanced target suspend/resume handling in that proof.
- Command-line setup, memory, external-target, and transaction proofs, plus tests for models, storage, setup recovery, app inventory, permissions, hotkeys, and runtime primitives.

The app deliberately distinguishes **Managed Copy Prepared** from rewind certification. Preparation makes an eligible copy attachable for the next runtime gate; it does not enable **Play from Here**.

## What v0.2 does not implement

- Continuous visual history or ScreenCaptureKit recording.
- General capture or restoration of arbitrary memory regions in an external process.
- Thread-register restoration, or complete file-descriptor, Mach-port, XPC, socket, helper-process, WindowServer, GPU, audio, device, or input rollback.
- Deterministic replay, outbound-effect suppression, crash interception, or cold restore after reboot.
- Runtime injection or launch of prepared managed copies, a privileged helper, or app-specific bridges.
- A certified KSP, browser, IDE, Apple-app, DRM, or anti-cheat integration.
- Developer ID distribution, notarization, automatic updates, or a production installer.

Those are roadmap items only after feasibility gates prove real functional restoration. A polished animation is not evidence; the app keeps restoration disabled when state coverage is incomplete.

## Build, run, and test

The project is a SwiftPM macOS application. Xcode's command-line tools must be selected and available.

```bash
./script/build_and_run.sh
```

The script stops an existing Continuum process, performs a clean build in an external per-user temporary SwiftPM scratch directory, stages the app, and signs it with the first available Apple Development identity (or ad-hoc as a fallback). It exposes the result at `dist/Continuum.app`, then launches that path through Launch Services. The `dist` path is a symlink to the externally staged bundle because this workspace is file-provider backed and can reattach forbidden Finder metadata to an in-place bundle during signing. The Codex workspace's **Run** action calls the same script.

Useful modes:

```bash
./script/build_and_run.sh --verify
./script/build_and_run.sh --debug
./script/build_and_run.sh --logs
./script/build_and_run.sh --telemetry
```

- `--verify` launches the bundle and confirms that the process remains alive.
- `--debug` opens the executable in LLDB.
- `--logs` streams unified logs from the Continuum process.
- `--telemetry` streams the `com.midas.continuum` logging subsystem.

Run all tests and the non-destructive proof harnesses with an external scratch path. This avoids FileProvider adding Finder metadata that macOS code signing rejects inside synced workspaces:

```bash
SCRATCH="${TMPDIR%/}/continuum-dev-swiftpm"
swift test --scratch-path "$SCRATCH"
swift run --scratch-path "$SCRATCH" ContinuumHarness inspect
swift run --scratch-path "$SCRATCH" ContinuumHarness memory-proof
swift run --scratch-path "$SCRATCH" ContinuumHarness transaction-proof
```

`memory-proof` touches only memory allocated inside the harness process. `transaction-proof` uses a temporary encrypted store and deletes it on exit. Neither command attaches to another application.

Run the real generic setup probe or setup transaction with:

```bash
./script/setup_app.sh "/path/to/Some App.app" --check-only
./script/setup_app.sh "/path/to/Some App.app"
```

The second command creates `Original.app` and `Managed.app` under Continuum's Application Support setup directory. It never edits the selected source. `PREPARED` means the copies, signature, marker, and attach entitlement passed validation; the command still prints `restore certified: no`.

Run the signed cooperative external-memory proof with:

```bash
./script/run_external_hot_proof.sh
```

That script requires a local Apple Development signing identity, verifies the controller/target entitlements and SIP status, performs at least 100 A↔B cycles, and deletes its temporary products. It proves only the target's registered arena—not whole-app rewind.

## Onboarding and permissions

On first launch, Continuum explains the preserve-before-rewind contract, lets the user explicitly invoke native permission prompts, runs a read-only compatibility scan, lets the user choose a future storage budget, and walks through an isolated text demo. Permission steps are optional. **Skip Prototype Setup** exits without granting anything; **Run Setup Again** in Settings restarts at Welcome.

| Permission | Why it appears | v0.2 behavior |
| --- | --- | --- |
| Accessibility | Identify and coordinate selected app windows | **Allow Accessibility** invokes macOS's native request; Settings opens after an earlier denial |
| Screen Recording | Future private visual timeline thumbnails | **Allow Screen Recording** invokes macOS's native request; no screenshot is treated as restorable state |
| Automation | Future target-specific Apple Events bridges | Informational until a specific integration is exercised |
| Full Disk Access | Future protected local-file versioning | Optional; opens the exact Privacy & Security pane because macOS has no reliable preflight API |

Continuum never grants itself access. Every prompt follows a user click, and onboarding can continue without it. Local builds prefer one stable Apple Development identity so TCC decisions survive rebuilds; a public release still requires Developer ID signing and notarization.

## Keyboard-first rewind

- Open the overlay with the configured rewind shortcut; the default is `Control–Option–Command–R`.
- Move through saved moments with Left and Right Arrow. Settings controls the time step.
- Press Return to choose **Play from Here**, or Escape to close/cancel safely.
- Metadata-only points remain visible but disabled. Pressing Return never substitutes an animation for actual restoration.
- Settings also stores active, game, and idle checkpoint intervals plus hot/rolling retention targets. Those scheduler controls are clearly marked inactive until a restore backend is certified.

## Snapshot semantics

- A manual snapshot is an immutable, pinned root until the user deletes it. Its name and note may change without changing its captured content.
- Beginning a rewind durably commits a provisional **Before Rewind** safety snapshot first.
- Committing promotes that safety snapshot, preserves the abandoned future as a branch, and creates the new active branch atomically.
- Cancelling removes the provisional transaction without creating a permanent branch.
- Undoing a rewind follows the same preserve-first rule; it never overwrites the path being left.
- Content chunks are deduplicated and encrypted at rest. Deleting one snapshot reclaims only chunks no other snapshot references.
- Settings includes **Delete All Snapshot Data**, which atomically clears snapshots, branches, manifests, and content chunks when no rewind transaction is active.
- `Unavailable` snapshots may be inspected but cannot be played. Only a validated runtime may publish `Instant` or `Replay required`.
- Local restoration can never unsend messages, undo purchases, retract uploads, or reverse changes already accepted by a remote service.

The store proves these transaction semantics using harness-owned artifacts. It does not make another app's state restorable by itself.

### Planned capture and storage defaults

These are product targets for a future validated capture runtime; v0.2 does not run this rolling checkpoint scheduler yet.

- Active apps: one checkpoint epoch every 100 ms.
- Game/high-motion mode: 50 ms only when measured frame-time and checkpoint-pause budgets remain healthy.
- Idle apps: back off to one checkpoint per second.
- Hot history: up to 90 seconds and 2 GB in memory.
- Rolling disk history: 30 minutes within a shared 20 GB default budget.

The first functional baseline is not cheap: depending on the app, it may be hundreds of megabytes or multiple gigabytes. Later snapshots should pin content-addressed page/file deltas instead of copying that baseline again, but deduplication cannot be promised until real workloads are measured. The UI must show both logical/shared size and physically unique size for every snapshot and branch; storage marketing based on “basically free” metadata roots is forbidden by the laws of both physics and SSDs.

## Privacy and security warning

Real snapshots can contain extremely sensitive material: document text, window titles, paths, credentials in memory, personal messages, and screen content. Treat a Continuum store like an unlocked session of the captured app even when its chunks are encrypted.

The v0.2 design keeps data local, does not install a privileged daemon, does not weaken SIP, and never edits the selected vendor source. The opt-in setup route does create and re-sign a separate managed copy inside Continuum's private Application Support directory. Do not add broad capture, Full Disk Access, source-bundle mutation, or network synchronization without explicit scope UI, stable code signing, a threat review, tested rollback, and a clear deletion path.

## Uninstall the development build

The build script stages Continuum inside this repository and does not install a background helper. If you copied the development build into `/Applications`, remove that copy too.

1. Quit Continuum.
2. Delete the installed/staged apps, the external scratch bundle, and, if desired, SwiftPM's test/build cache:

```bash
rm -rf /Applications/Continuum.app
rm -rf dist/Continuum.app
rm -rf "${TMPDIR%/}/com.midas.continuum-swiftpm"
rm -rf .build
```

3. To permanently remove snapshot data, local settings, and its device-only Keychain key, delete them together. Deleting only the key makes any remaining encrypted store unreadable:

```bash
rm -rf "$HOME/Library/Application Support/Continuum"
defaults delete com.midas.continuum 2>/dev/null || true
security delete-generic-password -s com.continuum.snapshot-store -a local-encryption-key 2>/dev/null || true
```

4. Optionally remove this development identity's privacy decisions:

```bash
tccutil reset Accessibility com.midas.continuum
tccutil reset ScreenCapture com.midas.continuum
tccutil reset AppleEvents com.midas.continuum
```

The proof harness creates only self-cleaning temporary directories. Full Disk Access, if manually enabled, can also be removed from **System Settings → Privacy & Security → Full Disk Access**.

## Architecture and roadmap

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for module boundaries and the transaction invariants that must remain true while the runtime evolves.

The next engineering gate is not “support KSP somehow.” The registered-arena proof must expand into a general capture cut across writable mappings, thread restoration or replay, helpers, local files, descriptors/IPC, windows, and graphics without SIP changes. Only measured end-to-end restoration can certify an app, with KSP serving as a demanding acceptance workload rather than a special-case illusion.
