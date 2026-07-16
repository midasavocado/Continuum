# Continuum

Continuum is a native macOS research app that checkpoints a GUI process, lets that process really exit, and reconstructs its saved RAM state in a different process without rolling local files backward. The product goal is deliberately simple: **Save Snapshot → quit normally → Restore**.

> **Current status: v0.3 research build.** Continuum proves one real AppKit cold-restore path: ordinary direct app allocations made during startup and after the first run-loop idle boundary on both the main thread and a worker thread, plus app-defined Objective-C model objects with scalar-only ivars and standard allocation behavior, are captured with durable allocator metadata. The original GUI process fully exits, and a different PID relaunches with all saved values at the same addresses and a new functional WindowServer window. The replacement is fully prepared and validated before the live app is closed. Current files are deliberately left unchanged. The broader signed proof still validates 202 live/cold memory restores and guarded process resources. This is **not** arbitrary-app certification: reference-bearing Objective-C objects, Swift/framework-owned heaps, live background-thread execution state, sockets, Mach/XPC queues, GPU state, audio, devices, and full thread continuation remain outside the proven cold path.

Continuum requires macOS 15 or later. The cooperative signed proof works through explicit development entitlements and verifies that it never changes SIP state. Testing unmodified third-party processes on this development Mac currently relies on the user's SIP-disabled configuration; that is not a consumer distribution plan or proof of universal compatibility.

## OpenAI Build Week 2026

Continuum is entered in **Apps for Your Life**. It addresses a familiar failure mode for people using creative tools, games, and productivity apps: the useful transient state was in memory, not in a saved file, when the app quit or crashed.

The repository existed before the July 13 submission window, so the dated Git history is intentionally explicit about what is new. After the submission period opened at 9:00 AM PT on July 13, the project added process-only cold restore, deterministic address matching, cold thread-set reconstruction, GUI safepoints, reliable one-step quit and restore, allocator-state reconstruction, normal-launch arming, post-startup and worker-thread capture, and scalar Objective-C model restoration. Earlier UI, storage, and cold-restore scaffolding is not presented as Build Week work.

The core implementation was developed interactively in one Codex task. The human set the product contract and made the key scope decisions—real process exit, RAM-only restore, files unchanged, general mechanisms instead of app-specific patches, and fail-closed compatibility. Codex translated those decisions into Swift, C, Objective-C, Mach runtime code, test harnesses, and repeated real-process validation. The `/feedback` session ID attached to the Devpost submission is the authoritative session record.

Codex was most useful in three places:

- keeping the Swift UI, SwiftPM targets, injected C runtime, and signed Mach controller synchronized while the design changed;
- turning repeated runtime failures into narrow hypotheses, then adding proof output for PID replacement, address identity, thread ownership, and file invariants; and
- rejecting convincing-looking shortcuts. Failed Swift-heap and broad Objective-C restore experiments were reverted when they could not pass the real quit-and-relaunch proof.

See [docs/DEVPOST_SUBMISSION.md](docs/DEVPOST_SUBMISSION.md) for the judge checklist, copy-ready submission text, and demo outline.

## What v0.3 implements

- A native SwiftUI consumer shell with resumable onboarding, plain-language limits, real opt-in Accessibility and Screen Recording request actions, storage selection, and a self-contained rewind demo.
- A broad inventory of running window owners and installed `.app` bundles, plus explicit selection of an app or executable anywhere on disk.
- One generic arming pipeline for eligible app bundles: probe, preserve a verified original, build and validate a managed copy, then atomically exchange it into the app's normal launch path. Rollback atomically restores the vendor bundle; setup never terminates or replaces a running process.
- Exact blockers for Apple platform binaries, sandbox or identity-bound apps, App Store/DRM targets, restricted entitlements, unsupported nested code, malformed bundles, and standalone executables that cannot use the current bundle route.
- A floating native snapshot picker opened by a configurable global shortcut, with arrow-key navigation, Return to restore, Escape to cancel, and clear Ready or Unavailable states.
- Global `Control–Option–Command–S` hot-snapshot registration plus safe rewind-shortcut presets while Continuum is running.
- A shipping `HotProcessCheckpointService` that retains live process-group snapshots and promotes an expired snapshot to fresh-process restore only when it contains a deterministic tagged startup capsule; legacy and untagged snapshots fail closed.
- A GUI cold-restorer that preflights a stopped replacement while the original remains alive, validates executable/OS/mapping identity and encrypted chunks, then closes the current app, resumes the new PID, and activates its windows.
- Typed snapshot, checkpoint, branch, compatibility, storage, and external-effect models shared by the app, store, and test harness.
- An encrypted, content-addressed snapshot-store implementation with immutable manual snapshots, provisional pre-rewind safety snapshots, atomic branch creation, deduplication, and integrity verification.
- A signed multi-process Mach proof that discovers a root/helper tree, suspends it with `task_suspend2` tokens, copies every readable+writable private/COW region without aliasing or mutating target VM maps, captures ARM64 general/NEON registers, and restores coalesced changed-page runs plus registers helpers-first.
- A generic kernel-resource fingerprint for descriptor topology, vnode identity and offsets, sockets, pipes, kqueues, shared-memory/semaphore descriptors, Mach rights, and thread identities.
- An automatic pre-restore safety snapshot, full readback validation, rollback on partial failure, PID/start-time/executable-inode pinning, strict VM-layout/resource/thread-set validation, bounded protocol timeouts, and balanced target suspend/resume handling. A descriptor mutation is proven to fail before any memory or register write.
- A separate APFS local-file checkpoint research layer. The current consumer cold-restore path does not invoke it and never rewrites file bytes.
- Snapshot metadata and UI language for per-app capture groups and process-only restore with current files left unchanged.
- Command-line setup, memory, external-target, and transaction proofs, plus tests for models, storage, setup recovery, app inventory, permissions, hotkeys, and runtime primitives.

The app deliberately distinguishes **Normal Launch Armed** from rewind certification. Arming ensures the runtime is present before startup; each saved process still has to pass the cold-restore gate before Restore is enabled.

## What v0.3 does not implement

- Continuous visual history or ScreenCaptureKit recording.
- VM-map topology restoration when an app allocates, frees, splits, or replaces a captured mapping. The runtime fails closed when topology changes, including when private memory becomes a live shared mapping.
- Recreation of file descriptors, closed/renamed/deleted files, Mach ports, XPC, sockets, pipes, kqueues, launchd-reparented/XPC helpers, WindowServer, GPU, audio, devices, or input state. Stable descendant helpers and bytes of currently open writable regular files are now captured; changing or external helpers remain blockers.
- File discovery/attribution, namespace journaling, SQLite WAL/SHM lock restoration, or automatic connection of the APFS byte layer to arbitrary apps.
- Deterministic replay, outbound-effect suppression, crash interception, or a proven cold restore after reboot.
- Resource reconstruction for sockets, Mach/XPC, WindowServer/Core Animation, GPU/Metal/OpenGL, audio, input, and devices. The current live restore engine guards or rejects these instead.
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

### Fastest judge path

To launch the product UI:

```bash
./script/build_and_run.sh --verify
```

To verify the actual cold-restore claim on a controlled AppKit target:

```bash
./script/run_gui_cold_proof.sh
```

The second command is the decisive test. It requires an Apple Development signing identity, launches a signed GUI fixture, records its startup/main-thread/worker-thread/Objective-C scalar state, lets the original PID exit, restores into a different PID, verifies a fresh functional WindowServer window, mutates the restored app again, and checks that local files were not changed. It prints both PIDs and every restored value. It does not attach to or modify an unrelated app.

The downloadable hackathon preview is a development build, not a notarized consumer release. This Mac has Apple Development identities but no Developer ID Application identity or notary profile, so Gatekeeper correctly rejects the current artifact for normal internet distribution. Judges can build from source with the one-step command above; a notarized download remains a release prerequisite, not a checkbox Continuum pretends has passed.

Maintainers can create a certificate-independent, ad-hoc-signed judge archive with:

```bash
./script/package_judge_build.sh
```

The script builds v0.3.0, launches it once, archives the real app bundle, extracts and revalidates the archive, and writes a SHA-256 checksum under `dist/`. Because the archive is not notarized, it is a fallback test build; source build plus the signed proof remains the strongest judging path.

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

The second command requires the target app to be quit. It creates verified `Original.app` and `Managed.app` copies, then atomically installs the managed bundle at the app's existing Finder/Dock path while retaining the displaced vendor bundle. Rollback swaps the vendor bundle back before deleting setup data. `PREPARED` still means launch arming, not blanket restore certification.

Run the signed cooperative external-memory proof with:

```bash
./script/run_external_hot_proof.sh
```

That script requires a local Apple Development signing identity, verifies the controller/target entitlements and SIP status, launches one C root plus a real descendant helper, exercises both the raw runtime and the shipping `HotProcessCheckpointService`, performs one validated process-group A↔B cycle plus at least 100 registered-arena cycles, proves stable membership/resource fingerprints, deliberately changes the root descriptor table to verify a zero-write refusal, and deletes its temporary products.

## Onboarding and permissions

On first launch, Continuum explains the preserve-before-rewind contract, lets the user explicitly invoke native permission prompts, runs a read-only compatibility scan, lets the user choose a future storage budget, and walks through an isolated text demo. Permission steps are optional. **Skip Prototype Setup** exits without granting anything; **Run Setup Again** in Settings restarts at Welcome.

| Permission | Why it appears | v0.3 behavior |
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
- Expired and old metadata-only points remain visible but disabled. Live snapshots are labeled Ready only while their original process state remains available.
- Settings also stores active, game, and idle checkpoint intervals plus hot/rolling retention targets. Those scheduler controls are clearly marked inactive until a restore backend is certified.

## Snapshot semantics

- A manual snapshot is an immutable, pinned root until the user deletes it. Its name and note may change without changing its captured content.
- Beginning a rewind durably commits a provisional **Before Rewind** safety snapshot first.
- Committing promotes that safety snapshot, preserves the abandoned future as a branch, and creates the new active branch atomically.
- Cancelling removes the provisional transaction without creating a permanent branch.
- Undoing a rewind follows the same preserve-first rule; it never overwrites the path being left.
- Content chunks are deduplicated and encrypted at rest. Deleting one snapshot reclaims only chunks no other snapshot references.
- Settings includes **Delete All Snapshot Data**, which atomically clears snapshots, branches, manifests, and content chunks when no rewind transaction is active.
- `Unavailable` snapshots may be inspected but cannot be restored. `Ready` means the original live process tree is still retained.
- Local restoration can never unsend messages, undo purchases, retract uploads, or reverse changes already accepted by a remote service.
- Capture is per app, not full-device: the selected app, its helpers, and certified dependent writers form one capture group. Unrelated apps and system services do not rewind.
- The current cold path restores only its certified RAM capsule. It does not roll files backward; file contents on disk remain current.
- Continuum validates and stops a replacement process before closing the live app, so a corrupt or incompatible checkpoint fails without first destroying the current process.

The store proves these transaction semantics using harness-owned artifacts. It does not make another app's state restorable by itself.

### Planned capture and storage defaults

These are product targets for a future validated capture runtime; v0.3 does not run this rolling checkpoint scheduler yet.

- Active apps: one checkpoint epoch every 100 ms.
- Game/high-motion mode: 50 ms only when measured frame-time and checkpoint-pause budgets remain healthy.
- Idle apps: back off to one checkpoint per second.
- Hot history: up to 90 seconds and 2 GB in memory.
- Rolling disk history: 30 minutes within a shared 20 GB default budget.

The first functional baseline is not cheap: depending on the app, it may be hundreds of megabytes or multiple gigabytes. Later snapshots should pin content-addressed page/file deltas instead of copying that baseline again, but deduplication cannot be promised until real workloads are measured. The UI must show both logical/shared size and physically unique size for every snapshot and branch; storage marketing based on “basically free” metadata roots is forbidden by the laws of both physics and SSDs.

## Privacy and security warning

Real snapshots can contain extremely sensitive material: document text, window titles, paths, credentials in memory, personal messages, and screen content. Treat a Continuum store like an unlocked session of the captured app even when its chunks are encrypted.

The v0.3 design keeps data local, does not install a privileged daemon, and never changes SIP state. This development Mac is currently SIP-disabled by the user for task-port research. The opt-in arming route preserves the vendor bundle, installs only a separately prepared and validated copy at the same launch path, and has a crash-tested atomic rollback. Apple, sandboxed, DRM, identity-bound, and unsupported nested-code apps remain blocked rather than having their signatures weakened silently.

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

The next engineering gate is not “support KSP somehow.” The working memory/register cut and APFS file primitive must gain capture-group file attribution, VM-topology generations, descriptor/Mach/XPC virtualization, and graphics republication. Only measured end-to-end restoration can certify an app, with KSP serving as a demanding acceptance workload rather than a special-case illusion.

## License

Continuum is available under the [Apache License 2.0](LICENSE).
