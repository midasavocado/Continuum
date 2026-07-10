# Continuum architecture

Continuum v0.2 is a native macOS research prototype for the parts of rewind that can be made concrete today: broad target discovery, opt-in permission onboarding, reversible managed-copy setup, cross-process registered-arena experiments, durable snapshot metadata, and branch-safe rewind transactions. It is intentionally not described as a universal process-restoration engine.

## Module boundaries

| Module | Owns | Must not own |
| --- | --- | --- |
| `ContinuumCore` | Sendable domain models, identifiers, errors, display naming, and protocols | AppKit, persistence, Mach calls, permission prompts, or presentation state |
| `ContinuumStore` | Durable index, content-addressed chunks, integrity checks, reference accounting, and atomic snapshot/rewind transactions | Process inspection, UI, permission prompts, or claims that stored bytes are restorable |
| `ContinuumRuntime` | Low-level Mach/VM primitives for owned memory and one registered private/COW arena in an authorized external process | Thread-state restoration, product policy, user consent, arbitrary-app compatibility claims, or durable storage |
| `ContinuumSystem` | Window-owner/app inventory, code-signing inspection, permission requests/status, generic managed-copy setup/recovery, compatibility probing, and global hotkeys | Snapshot indexing, branch policy, SwiftUI state, source-app mutation, or bypassing SIP/TCC |
| `ContinuumApp` | SwiftUI/AppKit consumer shell, onboarding, Snapshot Library, timeline/branch presentation, explicit user actions, and the honest metadata-only checkpoint fallback | Raw store file mutation, Mach implementation details, or silently requesting broad permissions |
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

The UI talks to protocol-shaped coordinators and never infers restoration from a screenshot or successful metadata write. A snapshot's `RestoreAvailability` is the only user-facing restoration gate. `Unavailable` means inspectable but not playable.

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
9. **Availability is evidence-based.** Only a capture adapter that can validate restoration may publish `Instant` or `Replay required`. Metadata-only checkpoints remain `Unavailable`.
10. **External effects remain external.** A local restore cannot unsend a message, reverse a purchase, or change a remote server. Crossing recorded effects produces a warning, never a success claim.
11. **Storage pressure fails closed.** If permanent safety data cannot fit, rewind does not start. Pinned manual and pre-rewind snapshots are not silently evicted.
12. **Unknown state is not fabricated.** Missing process, descriptor, graphics, helper, or IPC state makes the snapshot unavailable; visual continuity is never presented as functional restoration.

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

The future scheduler defaults to 100 ms active epochs, conditionally tightens to 50 ms for games only when performance gates pass, and backs off to one second while idle. Its default budgets are 2 GB for 90 seconds of hot history and 20 GB for a 30-minute rolling disk window. A first restorable baseline may cost hundreds of megabytes to multiple gigabytes; later points reference content-addressed deltas. Product surfaces must report logical/shared and physically unique bytes separately. None of these cadence or retention targets are active in the current metadata-only app capturer.

The v0.2 application does not install a privileged daemon, weaken SIP, edit the selected vendor source, or silently grant itself TCC permissions. Its opt-in setup coordinator clones a verified `Original.app` and a separate `Managed.app` into Application Support, writes a marker only to the managed copy, and ad-hoc signs that copy with `get-task-allow`. Platform, sandbox/identity-bound, App Store/DRM, restricted-entitlement, and unsupported-nested-code targets fail closed. Prepared copies remain uncertified and are not launched by the capture service.

## Research boundary

The runtime now has two proof levels:

1. The self-process proof checkpoints memory allocated by the harness.
2. The signed external proof pins one cooperative target by PID, start time, and executable inode; registers one private/COW arena; suspends the target; captures the arena and ARM64 general/NEON thread-state evidence; validates the mapping/protections/thread set; restores bytes with readback and emergency rollback; and alternates A↔B for at least 100 cycles.

The external proof never calls `thread_set_state`. It does not enumerate or restore arbitrary mappings, and its JSON handshake exists only for the included cooperative target. Therefore it does not prove restoration of an arbitrary GUI process. A general native-app rewind engine must separately solve or reject:

- authenticated access to another app's task and complete helper tree;
- safe thread cuts and in-flight syscalls;
- Mach ports, XPC, sockets, file descriptors, locks, and kernel state;
- WindowServer, Core Animation, Metal, audio, input, and device state;
- code signing, library validation, TCC identity, App Store/DRM constraints, and app updates;
- deterministic replay without duplicating external effects.

Each application is therefore certified from measured capture and restore behavior. A successful managed-copy transaction certifies only that setup is reversible and attachable—not that the app can rewind. Unsupported software remains visible in inventory with an explanation, but no enabled **Play from Here** action. KSP is an eventual acceptance workload for the general engine, not a special-case claim.
