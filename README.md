# Continuum

Continuum is a native macOS research prototype for safe, branching app snapshots: save a moment, preserve the current future before rewinding, and never label a screenshot as restorable state.

> **Current status: v0.1 research build.** This repository does **not** yet rewind arbitrary native applications or games. It cannot currently restore a crashed KSP flight, Safari, an IDE, or another process's complete RAM and kernel state. The consumer UI is real; universal restoration remains gated R&D. The tiny time machine is wearing safety goggles, not a cape.

Continuum requires macOS 15 or later and keeps System Integrity Protection enabled.

## What v0.1 implements

- A native SwiftUI consumer shell with resumable onboarding, plain-language limits, read-only permission guidance, app compatibility results, storage selection, and a self-contained rewind demo.
- A read-only inventory of running and installed apps, including code-signing and protection metadata used to classify possible integration routes.
- Read-only permission preflight for future backends. The v0.1 UI does not request Accessibility, Screen Recording, Automation, or Full Disk Access.
- A floating native rewind timeline opened by a configurable global shortcut, with arrow-key navigation, Return to commit validated points, Escape to cancel, and an explicit unavailable state for metadata-only moments.
- Global `Control–Option–Command–S` diagnostic-snapshot registration plus safe rewind-shortcut presets while Continuum is running.
- A metadata-only capture fallback that records the selected process tree's identity and resource counts, explicitly marks the snapshot `Unavailable`, and refuses fake restoration.
- Typed snapshot, checkpoint, branch, compatibility, storage, and external-effect models shared by the app, store, and test harness.
- An encrypted, content-addressed snapshot-store implementation with immutable manual snapshots, provisional pre-rewind safety snapshots, atomic branch creation, deduplication, and integrity verification.
- A narrow Mach runtime experiment that inspects the current process and proves checkpoint/mutate/restore for memory explicitly owned by the included harness.
- A command-line harness for memory and transaction proofs, plus unit tests for models, storage, app inventory, permissions, hotkeys, and runtime primitives.

The app deliberately reports current third-party applications as not yet certified for restoration. Finding an app-supported plug-in directory or a potentially injectable signature is a research lead, not permission to enable **Play from Here**.

## What v0.1 does not implement

- Continuous visual history or ScreenCaptureKit recording.
- Capture or restoration of an arbitrary external process.
- Complete thread, file-descriptor, Mach-port, XPC, socket, helper-process, WindowServer, GPU, audio, or input rollback.
- Deterministic replay, outbound-effect suppression, crash interception, or cold restore after reboot.
- Automatic third-party bundle modification, re-signing, code injection, a privileged helper, or app-specific bridges.
- A certified KSP, browser, IDE, Apple-app, DRM, or anti-cheat integration.
- Developer ID distribution, notarization, automatic updates, or a production installer.

Those are roadmap items only after feasibility gates prove real functional restoration. A polished animation is not evidence; the app keeps restoration disabled when state coverage is incomplete.

## Build, run, and test

The project is a SwiftPM macOS application. Xcode's command-line tools must be selected and available.

```bash
./script/build_and_run.sh
```

The script stops an existing Continuum process, performs a clean build in an external per-user temporary SwiftPM scratch directory, stages and ad-hoc signs the app, exposes it at `dist/Continuum.app`, then launches that path through Launch Services. The `dist` path is a symlink to the externally staged bundle because this workspace is file-provider backed and can reattach forbidden Finder metadata to an in-place bundle during signing. The Codex workspace's **Run** action calls the same script.

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

## Onboarding and permissions

On first launch, Continuum explains the preserve-before-rewind contract, displays permission status without prompting, runs a read-only compatibility scan, lets the user choose a future storage budget, and walks through an isolated text demo. **Skip Prototype Setup** exits without granting anything; **Run Setup Again** in Settings restarts at Welcome.

| Permission | Why it appears | v0.1 behavior |
| --- | --- | --- |
| Accessibility | Future coordination of supported restore actions | Status is displayed; v0.1 does not request it |
| Screen Recording | Future visual timeline thumbnails | Status is displayed; v0.1 does not request or record the screen |
| Automation | Future app-specific bridges using Apple Events | Status is informational; no bridge sends events in v0.1 |
| Full Disk Access | Future versioning of protected app files and databases | Status is informational; v0.1 does not request it |

The prototype never opens a permission prompt from onboarding or Settings. A future feature must explain its exact scope before requesting access. The ad-hoc signature used by local development builds is not a stable consumer identity; a real release requires stable Developer ID signing and notarization.

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

The v0.1 store proves these transaction semantics using harness-owned artifacts. It does not make another app's state restorable by itself.

### Planned capture and storage defaults

These are product targets for a future validated capture runtime; v0.1 does not run this rolling checkpoint scheduler yet.

- Active apps: one checkpoint epoch every 100 ms.
- Game/high-motion mode: 50 ms only when measured frame-time and checkpoint-pause budgets remain healthy.
- Idle apps: back off to one checkpoint per second.
- Hot history: up to 90 seconds and 2 GB in memory.
- Rolling disk history: 30 minutes within a shared 20 GB default budget.

The first functional baseline is not cheap: depending on the app, it may be hundreds of megabytes or multiple gigabytes. Later snapshots should pin content-addressed page/file deltas instead of copying that baseline again, but deduplication cannot be promised until real workloads are measured. The UI must show both logical/shared size and physically unique size for every snapshot and branch; storage marketing based on “basically free” metadata roots is forbidden by the laws of both physics and SSDs.

## Privacy and security warning

Real snapshots can contain extremely sensitive material: document text, window titles, paths, credentials in memory, personal messages, and screen content. Treat a Continuum store like an unlocked session of the captured app even when its chunks are encrypted.

The v0.1 design keeps data local, does not install a privileged daemon, does not modify third-party bundles, and does not weaken SIP. Do not add broad capture, Full Disk Access, app instrumentation, or network synchronization without explicit scope UI, stable code signing, a threat review, tested rollback, and a clear deletion path.

## Uninstall the development build

Continuum is staged inside this repository; the current build does not install anything into `/Applications` or install a background helper.

1. Quit Continuum.
2. Delete `dist/Continuum.app`, the external scratch bundle, and, if desired, SwiftPM's test/build cache:

```bash
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

The next engineering gate is not “support KSP somehow.” It is a general external-process harness proving safe repeated rollback across AppKit, a helper process, files, and graphics without SIP changes. Only after that evidence exists should individual applications be certified, with KSP serving as a demanding acceptance workload rather than a special-case illusion.
