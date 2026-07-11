# Continuum architecture

Continuum v0.3 is a native macOS per-app rewind research prototype. The current proof has complete private/COW memory cuts, ARM64 register restoration, mandatory safety snapshots, batched in-place page restoration, APFS file preimages, durable branch transactions, and consumer UI. It is intentionally not described as a universal process-restoration engine.

## Module boundaries

| Module | Owns | Must not own |
| --- | --- | --- |
| `ContinuumCore` | Sendable domain models, identifiers, errors, display naming, and protocols | AppKit, persistence, Mach calls, permission prompts, or presentation state |
| `ContinuumStore` | Durable index, content-addressed chunks, APFS per-file COW roots, in-place file-byte restoration, integrity checks, and atomic snapshot/rewind transactions | File discovery/attribution, process inspection, UI, permission prompts, or claims that unvalidated bytes are restorable |
| `ContinuumRuntime` | Mach task/tree identity, coherent descendant-group suspension, nested VM-map byte capture, ARM64 register cuts, safety snapshots, group rollback, batched page restore/readback, writable-vnode inventory callbacks, and fail-closed topology/resource validation | Descriptor/IPC/GPU reconstruction, product policy, user consent, arbitrary-app compatibility claims, or durable storage |
| `ContinuumSystem` | Window-owner/app inventory, code-signing inspection, permission requests/status, generic setup/recovery, global hotkeys, and the live snapshot adapter over `ContinuumRuntime` | Snapshot indexing, branch policy, SwiftUI state, source-app mutation, or bypassing SIP/TCC |
| `ContinuumApp` | SwiftUI/AppKit consumer shell, onboarding, Snapshot Library, timeline/branch presentation, explicit user actions, and evidence-based capability labels | Raw store file mutation, Mach implementation details, or silently requesting broad permissions |
| `ContinuumHarness` | Reproducible command-line proofs for setup, VM-region inspection, the owned/external registered-arena experiments, and store transactions | Shipping UI behavior or compatibility certification |
| `ContinuumExternalTarget` | Cooperative signed proof process with one page-aligned arena and a tiny validation protocol | General app behavior, production instrumentation, or a compatibility shortcut |

Dependencies flow inward: `ContinuumApp` and `ContinuumHarness` compose protocols from `ContinuumCore`; concrete store and system modules implement them. `ContinuumCore` stays independent so transaction behavior can be tested without macOS UI or process privileges.

## Runtime composition

```mermaid
flowchart LR
    UI["ContinuumApp\nconsumer UI"] --> C["ContinuumCore\nmodels + protocols"]
    UI --> S["ContinuumStore\ndurable snapshots"]
    UI --> Y["ContinuumSystem\napps + permissions + capture adapter"]
    Y --> R["ContinuumRuntime\nMach experiment"]
    H["ContinuumHarness\nproof commands"] --> C
    H --> S
    H --> Y
    H --> R
    H --> T["ContinuumExternalTarget\ncooperative arena"]
```

The UI talks to protocol-shaped coordinators and never infers restoration from a screenshot or successful metadata write. A snapshot's `RestoreAvailability` is the user-facing gate. `Ready` means the original live tasks and guarded resources remain restorable; `Unavailable` means inspectable but not restorable.

## Snapshot transaction invariants

These invariants apply even while the runtime remains experimental:

1. **Manual snapshots are immutable roots.** Renaming and notes may change metadata; their checkpoint identity and referenced chunks do not change.
2. **A restore never destroys the state being left.** `beginRewind` must durably save a safety snapshot before preview or restore can advance.
3. **Commit is atomic.** `commitRewind` promotes the safety snapshot, preserves the abandoned future as a branch, changes the active branch, and removes the provisional record in one index transaction—or changes none of them.
4. **Cancel is non-destructive.** `cancelRewind` removes only its provisional transaction after the original live state is retained or revalidated.
5. **One transaction mutates a session at a time.** Competing snapshot, commit, cancel, delete, and restore requests are serialized.
6. **Content is addressed by digest.** A committed chunk's bytes must match its recorded digest; duplicate content reuses one physical object.
7. **References outlive branches.** Deleting a snapshot or branch may reclaim only chunks with no remaining snapshot reference.
8. **Index publication comes last.** Chunk files are fully written and made durable before an index can reference them. Readers either observe the old complete state or the new complete state.
9. **Availability is evidence-based.** The live process adapter publishes `Ready` only while its retained process state remains valid. Metadata-only or expired checkpoints remain `Unavailable`.
10. **External effects remain external.** A local restore cannot unsend a message, reverse a purchase, or change a remote server. Crossing recorded effects produces a warning, never a success claim.
11. **Storage pressure fails closed.** If permanent safety data cannot fit, rewind does not start. Pinned manual and pre-rewind snapshots are not silently evicted.
12. **Unknown state is not fabricated.** Missing process, descriptor, graphics, helper, or IPC state makes the snapshot unavailable; visual continuity is never presented as functional restoration.
13. **Scope is per app.** A capture group contains one app, its helper/process tree, and certified dependent local writers. Continuum never describes this as a whole-device snapshot.
14. **Files branch with memory by default.** Exact restore uses the captured APFS file root. Keeping newer files with older memory is a separate policy that is disabled unless compatibility validation proves it safe.
15. **Open vnode identity survives.** Hot file restore writes captured bytes into the existing inode. Replacing a path or swapping a clone underneath an open descriptor is not accepted as exact restoration.

The state machine is deliberately small:

```mermaid
stateDiagram-v2
    [*] --> Live
    Live --> Provisional: beginRewind(safety capture committed)
    Provisional --> Live: cancelRewind
    Provisional --> Restoring: commitRewind(target)
    Restoring --> BranchedLive: validated restore
    Restoring --> Live: restore failed; return to safety state
    BranchedLive --> Provisional: rewind or undo again
```

## Storage layout and trust boundary

The store owns an index plus content-addressed chunk files. Index replacement uses a temporary file followed by an atomic rename. Chunk creation precedes index publication; garbage collection follows reference removal. Store keys belong in Keychain, not in the snapshot directory.

Snapshot material should be treated like an unlocked session of the captured application. It may include document text, credentials in memory, file paths, window titles, or personal screen content. The consumer UI must state the selected scope and destination before capture, keep data local by default, and make destructive deletion explicit.

The future scheduler defaults to 100 ms active epochs, conditionally tightens to 50 ms for games only when performance gates pass, and backs off to one second while idle. Its default budgets are 2 GB for 90 seconds of hot history and 20 GB for a 30-minute rolling disk window. The current live adapter retains full process images rather than page deltas, so those cadence targets are not active yet. Product surfaces report retained RAM separately from durable encrypted bytes.

The application does not silently change SIP, edit the selected vendor source, or grant itself TCC permissions. Its opt-in setup coordinator clones a verified `Original.app` and a separate `Managed.app` into Application Support. On this development Mac, SIP is user-disabled for research against unmodified tasks; a consumer build still needs a supported authorization/instrumentation route and Apple-granted system-extension entitlements.

## Research boundary

The runtime now has four proof levels:

1. The self-process proof checkpoints memory allocated by the harness.
2. The registered-arena external proof alternates two target-owned states with readback validation for at least 100 cycles.
3. The process-group proof discovers and freezes a root plus descendant helper, walks each nested VM map, copies every readable+writable private/COW mapping without leaving aliases in the target, captures general/NEON registers, creates safety cuts for every member before the first write, restores helpers-first, and rolls touched members back in reverse order on failure. It inventories descriptors, writable vnodes, Mach rights, threads, membership, and parent edges at each cut. Saved Mach names/right types/kernel objects must remain valid, while additive rights acquired after capture are tolerated. A synchronous callback APFS-clones open writable regular files while that same group freeze is held and restores their bytes before resume. The current two-process proof captures about 635 MB: a stabilized cut is roughly 200–250 ms after a slower first cut, and hot group restore is roughly 250–410 ms.
4. The shipping-adapter proof captures that target through `HotProcessCheckpointService`, mutates both root and helper, restores the app-facing snapshot, and validates both target-owned states. This proves the consumer backend reaches the real runtime; it does not prove arbitrary GUI resource reconstruction.

The proof calls `thread_set_state`, but it requires the same tasks, parent topology, thread identities, captured VM topology, descriptor tables, and Mach namespaces. An added vnode descriptor is rejected before memory is written. A post-read VM rewalk prevents a cut from being published if faulting lazy pages changed its own layout. Fingerprinting is a safety gate, not kernel-resource reconstruction, so this still does not prove restoration of an arbitrary GUI process. A general native-app rewind engine must separately solve or reject:

- authenticated access to another app's task and complete helper tree;
- safe thread cuts and in-flight syscalls;
- Mach ports, XPC, sockets, file descriptors, locks, and kernel state;
- WindowServer, Core Animation, Metal, audio, input, and device state;
- code signing, library validation, TCC identity, App Store/DRM constraints, and app updates;
- deterministic replay without duplicating external effects.

## Per-app local file transaction

`APFSLocalFileCheckpointStore` is the first real disk primitive:

1. Discovery supplies regular files attributed to one capture group.
2. Capture creates APFS `clonefile` preimages in a private snapshot root and atomically publishes a manifest only after every clone exists.
3. The manifest pins original path, device, inode, byte length, and mode.
4. Restore refuses a changed device/inode, truncates the existing vnode to the historical length, copies bytes from the clone through `pwrite`, and fsyncs before success.
5. A higher coordinator must create the mandatory current-state file root before calling restore.

The hot adapter now discovers currently open writable regular files across the captured process tree and invokes this layer during the same suspension as its memory/register cut. It intentionally does not yet restore closed files, renames, deletes, hard links, xattrs, SQLite locks, pipes, sockets, or shared-daemon writes. Endpoint Security plus an in-process dirty-range journal is the planned attribution/namespace layer. APFS whole-volume revert is not the hot path because it applies on a later mount and would rewind unrelated apps.

Each application is therefore certified from measured capture and restore behavior. A successful managed-copy transaction certifies only that setup is reversible and attachable—not that the app can rewind. Unsupported software remains visible in inventory with an explanation, but no enabled **Play from Here** action. KSP is an eventual acceptance workload for the general engine, not a special-case claim.
