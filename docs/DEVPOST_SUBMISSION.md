# OpenAI Build Week submission kit

This file keeps the Devpost claims aligned with what the repository and proof harness can demonstrate. Update the proof output and links immediately before submission; do not broaden the claim to arbitrary applications.

## Required submission items

- Track: **Apps for Your Life**
- Public repository: <https://github.com/midasavocado/Continuum>
- License: Apache-2.0
- Supported platform: Apple silicon Mac, macOS 15 or later
- Public YouTube demo: **required, under three minutes, with audio**
- Codex `/feedback` session ID: **required from the task where the core restore engine was built**
- Working-project access: source build and controlled GUI proof commands in the README

## Short description

Continuum is a native macOS research app for saving the transient state of a running GUI process, letting that process really quit, and restoring the saved RAM state into a different process without rolling files backward.

## Inspiration

Files are not the whole state of an app. A game can have an unsaved simulation in motion, a creative tool can have a useful undo stack, and a productivity app can have transient state that disappears on quit or crash. Linux checkpoint/restore research shows that process state can be captured, but macOS has different Mach, signing, WindowServer, and runtime constraints. Continuum explores whether a consumer interaction as simple as Save Snapshot → Restore can be built honestly on macOS.

## What it does

Continuum provides a native SwiftUI snapshot library and a generic macOS checkpoint runtime. Its current controlled AppKit proof captures startup, post-run-loop, worker-thread, and scalar Objective-C model state; allows the original process to exit; starts a different process; reconstructs the saved state at the same addresses; republishes a functional window; and confirms that local files remain unchanged.

The app fails closed when it cannot prove compatibility. It does not present screenshots, metadata, or an animation as functional restoration, and it does not claim that sockets, Mach/XPC queues, GPU command state, framework-owned heaps, or arbitrary third-party apps are solved.

## How it was built

Continuum combines a SwiftUI macOS app, encrypted content-addressed snapshot storage, a C/Objective-C injected runtime, Swift Mach checkpoint orchestration, signed proof targets, and Swift Testing/XCTest coverage. The restore flow preflights a replacement before the original exits, validates executable and memory-layout identity, reconstructs captured state, creates a new WindowServer window, and verifies that the replacement remains functional.

The human directed the product and engineering contract: true process exit, process-memory restore instead of file rollback, general runtime mechanisms, no VM, and no fake success states. Codex implemented and debugged the cross-language system, kept tests and UI semantics synchronized, used failed proofs to narrow restore eligibility, and reverted approaches that crashed or could not survive a real PID replacement. Commits after 9:00 AM PT on July 13 distinguish eligible Build Week engine work from earlier scaffolding.

## Challenges

- macOS randomizes process and shared-library layouts, so cold replacement needs deterministic address compatibility before saved pointers can be meaningful.
- A process is more than bytes: allocator metadata, thread-owned state, Objective-C object layouts, Mach rights, descriptors, and framework resources can invalidate a restore.
- Restoring too broadly can create a convincing window followed by memory corruption. Continuum therefore proves narrow state classes and rejects everything else.
- Internet-distributed macOS builds require Developer ID signing and notarization. The current development artifact is locally signed and intentionally documented as a research build.

## Accomplishments

- The original GUI PID exits and a different PID restores captured state.
- Startup, post-idle, worker-thread, and scalar Objective-C model values survive at their captured addresses.
- The replacement owns a new functional WindowServer window and can mutate restored state again.
- Current files remain byte-for-byte unchanged by the restore path.
- The replacement is preflighted before the original app is closed.
- The repository includes repeatable proof commands and automated tests rather than relying on a screen recording.

## What was learned

A useful checkpoint format is the easy half. Correct restoration depends on proving which memory and resources are actually self-contained, recreating derived system resources instead of copying opaque handles, and refusing a restore before any write when an invariant changes. Consumer-grade UX starts with truthful capability detection.

## What's next

The next gates are reference-bearing Objective-C and Swift object graphs, VM-topology generations, controlled thread continuation, descriptor and Mach/XPC reconstruction, and graphics-resource republication. Third-party app support will be enabled only after each required state class passes the same real-exit proof.

## Demo video outline (maximum 2:40)

1. **0:00–0:20 — Problem.** Show Continuum and explain that app state in RAM disappears even when files remain.
2. **0:20–0:40 — Contract.** Save Snapshot → real quit → restore into a new process; files do not rewind.
3. **0:40–1:35 — Live proof.** Run `./script/run_gui_cold_proof.sh`. Show the original PID, change the visible fixture state, restore, then point out the different replacement PID and restored values.
4. **1:35–1:55 — Functional result.** Interact with the replacement window after restore and show the live-mutation proof.
5. **1:55–2:20 — Codex collaboration.** Show the dated July 13–15 commit history and explain one failed approach that Codex reverted after real-process testing.
6. **2:20–2:40 — Honest boundary.** State that the proof is real but narrow: arbitrary apps, sockets, GPU state, and reboot persistence are roadmap work.

Do not show unrelated apps, browser tabs, private paths, notifications, copyrighted music, or third-party branding in the recording.

## Final pre-submit verification

```bash
git status --short
git log --since='2026-07-13 09:00:00 -0700' --oneline
SCRATCH="${TMPDIR%/}/continuum-hackathon-final"
swift test --scratch-path "$SCRATCH"
./script/run_gui_cold_proof.sh
```

Then verify all of the following manually:

- The YouTube video is public, has audible narration, and is shorter than three minutes.
- The video contains only functionality the current commit still passes.
- The repository URL opens in a logged-out browser.
- The `/feedback` session ID belongs to the core-build task and records the required Codex/GPT-5.6 usage.
- The Devpost description does not say “every app,” “GPU restored,” “after reboot,” or “production-ready.”
- The selected category is Apps for Your Life.
