import AppKit
import SwiftUI
import ContinuumCore

struct ContinuumMenuBarLabel: View {
    @Environment(ContinuumModel.self) private var model

    var body: some View {
        Label("Continuum", systemImage: model.isPerformingAction ? "clock.badge.questionmark" : "clock.arrow.trianglehead.counterclockwise.rotate.90")
    }
}

struct ContinuumMenuBarView: View {
    @Environment(ContinuumModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    private var frontmostAppName: String? {
        model.runningProcesses.first(where: \.isFrontmost)?.app.displayName
            ?? model.runningProcesses.first?.app.displayName
    }

    var body: some View {
        Button("Open Continuum") {
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }

        Divider()

        if let frontmostAppName {
            Text("Frontmost: \(shortTitle(frontmostAppName))")
            Text(model.canCaptureFunctionalState ? "Ready to save a hot state" : "No certified rewind engine yet")
        } else {
            Text("Waiting for a frontmost app")
        }

        if model.canCaptureFunctionalState {
            Button("Save Snapshot") {
                Task { await model.saveManualSnapshot() }
            }
            .disabled(frontmostAppName == nil || model.isPerformingAction)
        }

        Text(model.canCaptureFunctionalState
             ? "Use the Rewind shortcut to open the timeline"
             : "Rewind opens when an app engine is ready")

        if model.canUndoRewind {
            Button("Undo Rewind") {
                Task { await model.undoRewind() }
            }
            .disabled(model.isPerformingAction)
        }

        Divider()

        SettingsLink {
            Text("Settings…")
        }

        Button("Quit Continuum") {
            NSApplication.shared.terminate(nil)
        }
    }

    private func shortTitle(_ title: String) -> String {
        guard title.count > 19 else { return title }
        return String(title.prefix(18)) + "…"
    }
}
