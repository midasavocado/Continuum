import AppKit
import ContinuumCore
import QuartzCore
import SwiftUI

@MainActor
final class RewindOverlayController {
    private let preferences: ContinuumPreferences
    private let selection = RewindTimelineSelection()

    private weak var model: ContinuumModel?
    private var panel: RewindPanel?
    private var refreshTask: Task<Void, Never>?
    private var transactionTask: Task<Void, Never>?
    private var cancellationRequested = false
    private var rewindTransactionStarted = false

    init(preferences: ContinuumPreferences) {
        self.preferences = preferences
    }

    func present(model: ContinuumModel) {
        self.model = model

        if transactionTask == nil, !rewindTransactionStarted {
            cancellationRequested = false
            rewindTransactionStarted = false
            selection.prepare(
                snapshots: model.snapshots,
                stepMilliseconds: preferences.timelineArrowStep.milliseconds
            )
        }

        let panel = panel ?? makePanel()
        self.panel = panel
        position(panel)
        animateIn(panel)

        refreshTask?.cancel()
        refreshTask = Task { [weak self, weak model] in
            guard let self, let model else { return }
            await model.refresh()
            guard !Task.isCancelled, self.transactionTask == nil else { return }
            self.selection.replaceSnapshots(model.snapshots)
        }
    }

    func dismiss() {
        requestDismissal()
    }

    private func makePanel() -> RewindPanel {
        let panel = RewindPanel(
            contentRect: NSRect(x: 0, y: 0, width: 840, height: 440),
            styleMask: [.borderless, .nonactivatingPanel, .utilityWindow],
            backing: .buffered,
            defer: false
        )
        panel.title = "Continuum Rewind"
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.level = .floating
        panel.hidesOnDeactivate = false
        panel.isReleasedWhenClosed = false
        panel.becomesKeyOnlyIfNeeded = false
        panel.isMovableByWindowBackground = true
        panel.collectionBehavior = [
            .canJoinAllSpaces,
            .fullScreenAuxiliary,
            .transient,
            .ignoresCycle
        ]
        panel.animationBehavior = .none
        panel.keyCommandHandler = { [weak self] command in
            self?.handle(command)
        }

        let rootView = RewindOverlayView(
            state: selection,
            onSelect: { [weak self] snapshotID in
                self?.selection.select(snapshotID)
            },
            onCommit: { [weak self] in
                self?.commitSelection()
            },
            onDismiss: { [weak self] in
                self?.requestDismissal()
            }
        )
        panel.contentViewController = NSHostingController(rootView: rootView)
        return panel
    }

    private func handle(_ command: RewindPanelCommand) {
        switch command {
        case .moveBackward:
            selection.move(.backward)
        case .moveForward:
            selection.move(.forward)
        case .commit:
            commitSelection()
        case .dismiss:
            requestDismissal()
        }
    }

    private func commitSelection() {
        guard transactionTask == nil else { return }
        guard selection.canCommit, let snapshot = selection.selectedSnapshot else {
            if selection.selectedSnapshot?.availability == .unavailable {
                NSSound.beep()
            }
            return
        }

        transactionTask = Task { [weak self] in
            await self?.runRewind(to: snapshot.id)
        }
    }

    private func runRewind(to snapshotID: SnapshotID) async {
        defer { transactionTask = nil }
        guard let model else {
            fail("Continuum’s rewind engine is not available.")
            return
        }

        cancellationRequested = false
        rewindTransactionStarted = false
        model.dismissError()
        model.selectedSnapshotID = snapshotID

        withAnimation(.easeInOut(duration: 0.18)) {
            selection.phase = .securingPresent
        }
        await model.beginRewind()

        guard case .previewing = model.rewindPhase else {
            if cancellationRequested {
                animateOut()
            } else {
                fail(modelFailureMessage(default: "Continuum could not secure the state you are leaving, so nothing changed."))
            }
            return
        }

        rewindTransactionStarted = true
        if cancellationRequested {
            await cancelActiveRewindAndDismiss()
            return
        }

        withAnimation(.easeInOut(duration: 0.18)) {
            selection.phase = .restoring
        }
        await model.commitRewind(target: snapshotID)

        if case let .completed(completedSnapshotID) = model.rewindPhase,
           completedSnapshotID == snapshotID {
            rewindTransactionStarted = false
            withAnimation(.spring(response: 0.38, dampingFraction: 0.76)) {
                selection.phase = .committed
            }
            try? await Task.sleep(for: .milliseconds(850))
            animateOut()
            return
        }

        if cancellationRequested {
            await cancelActiveRewindAndDismiss()
        } else {
            fail(modelFailureMessage(default: "This moment could not be restored. Your safety snapshot was kept."))
        }
    }

    private func requestDismissal() {
        switch selection.phase {
        case .browsing, .committed:
            animateOut()

        case .failed where !rewindTransactionStarted:
            animateOut()

        case .securingPresent:
            cancellationRequested = true
            withAnimation(.easeInOut(duration: 0.15)) {
                selection.phase = .cancelling
            }

        case .failed:
            cancellationRequested = true
            transactionTask = Task { [weak self] in
                guard let self else { return }
                await self.cancelActiveRewindAndDismiss()
                self.transactionTask = nil
            }

        case .restoring:
            // A restore that has already started is allowed to finish atomically.
            // The overlay closes as soon as the transaction resolves.
            cancellationRequested = true

        case .cancelling:
            break
        }
    }

    private func cancelActiveRewindAndDismiss() async {
        guard let model else {
            rewindTransactionStarted = false
            animateOut()
            return
        }

        withAnimation(.easeInOut(duration: 0.15)) {
            selection.phase = .cancelling
        }
        model.dismissError()
        await model.cancelRewind()

        if case .idle = model.rewindPhase {
            rewindTransactionStarted = false
            animateOut()
        } else {
            fail(modelFailureMessage(default: "Continuum could not validate the state you started from. The safety snapshot was retained."))
        }
    }

    private func fail(_ message: String) {
        withAnimation(.easeInOut(duration: 0.18)) {
            selection.phase = .failed(message)
        }
        NSSound.beep()
    }

    private func modelFailureMessage(default fallback: String) -> String {
        if let presentedError = model?.presentedError, !presentedError.isEmpty {
            return presentedError
        }
        if let model, case let .failed(detail) = model.rewindPhase {
            return detail
        }
        return fallback
    }

    private func position(_ panel: NSPanel) {
        let mouseLocation = NSEvent.mouseLocation
        let screen = NSScreen.screens.first { NSMouseInRect(mouseLocation, $0.frame, false) }
            ?? NSScreen.main
            ?? NSScreen.screens.first
        guard let visibleFrame = screen?.visibleFrame else {
            panel.center()
            return
        }

        let origin = NSPoint(
            x: visibleFrame.midX - panel.frame.width / 2,
            y: visibleFrame.midY - panel.frame.height / 2
        )
        panel.setFrameOrigin(origin)
    }

    private func animateIn(_ panel: NSPanel) {
        let finalFrame = panel.frame
        var initialFrame = finalFrame
        initialFrame.origin.y -= 10
        panel.setFrame(initialFrame, display: false)
        panel.alphaValue = 0
        panel.orderFrontRegardless()
        panel.makeKey()

        NSAnimationContext.runAnimationGroup { context in
            context.duration = 0.18
            context.timingFunction = CAMediaTimingFunction(name: .easeOut)
            panel.animator().alphaValue = 1
            panel.animator().setFrame(finalFrame, display: true)
        }
    }

    private func animateOut() {
        refreshTask?.cancel()
        refreshTask = nil
        guard let panel, panel.isVisible else { return }

        var finalFrame = panel.frame
        finalFrame.origin.y -= 8
        NSAnimationContext.runAnimationGroup { context in
            context.duration = 0.14
            context.timingFunction = CAMediaTimingFunction(name: .easeIn)
            panel.animator().alphaValue = 0
            panel.animator().setFrame(finalFrame, display: true)
        }

        Task { @MainActor [weak panel] in
            try? await Task.sleep(for: .milliseconds(160))
            panel?.orderOut(nil)
            panel?.alphaValue = 1
        }
    }
}

private enum RewindPanelCommand: Equatable {
    case moveBackward
    case moveForward
    case commit
    case dismiss
}

private final class RewindPanel: NSPanel {
    var keyCommandHandler: ((RewindPanelCommand) -> Void)?

    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }

    override func sendEvent(_ event: NSEvent) {
        guard event.type == .keyDown,
              let command = Self.command(for: event.keyCode) else {
            super.sendEvent(event)
            return
        }

        if event.isARepeat, command != .moveBackward, command != .moveForward {
            return
        }
        keyCommandHandler?(command)
    }

    private static func command(for keyCode: UInt16) -> RewindPanelCommand? {
        switch keyCode {
        case 123: .moveBackward // Left Arrow
        case 124: .moveForward  // Right Arrow
        case 36, 76: .commit    // Return and Keypad Enter
        case 53: .dismiss       // Escape
        default: nil
        }
    }
}
