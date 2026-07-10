import AppKit
import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
}

@main
struct ContinuumApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var model: ContinuumModel
    @State private var preferences: ContinuumPreferences
    @State private var lifecycle: AppLifecycleController

    init() {
        let preferences = ContinuumPreferences()
        _model = State(initialValue: AppBootstrap.makeModel())
        _preferences = State(initialValue: preferences)
        _lifecycle = State(
            initialValue: AppLifecycleController(preferences: preferences)
        )
    }

    var body: some Scene {
        WindowGroup("Continuum", id: "main") {
            ContinuumRootView(model: model, lifecycle: lifecycle)
                .frame(minWidth: 900, minHeight: 620)
        }
        .defaultSize(width: 1_160, height: 760)
        .commands {
            CommandMenu("Continuum") {
                Button("Save Diagnostic Snapshot (⌃⌥⌘S)") {
                    Task { await model.saveManualSnapshot() }
                }

                Button("Open Rewind Timeline…") {
                    lifecycle.showRewindOverlay(model: model)
                }

                Divider()

                Button("Undo Rewind") {
                    Task { await model.undoRewind() }
                }
                .disabled(!model.canUndoRewind)
            }
        }

        MenuBarExtra("Continuum", systemImage: "arrow.counterclockwise.circle") {
            ContinuumMenuBarView()
                .environment(model)
        }

        Settings {
            ContinuumSettingsView()
                .environment(model)
                .environment(preferences)
        }
    }
}
