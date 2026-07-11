import ContinuumCore
import ContinuumSystem
import SwiftUI

struct ContinuumSettingsView: View {
    @Environment(ContinuumModel.self) private var model
    @Environment(ContinuumPreferences.self) private var preferences

    var body: some View {
        TabView {
            InteractionSettingsView(preferences: preferences)
                .tabItem { Label("Interaction", systemImage: "keyboard") }

            CaptureSettingsView(preferences: preferences)
                .tabItem { Label("Capture", systemImage: "waveform.path.ecg") }

            PermissionSettingsView(statuses: model.permissionStatuses)
                .tabItem { Label("Permissions", systemImage: "hand.raised.fill") }

            PrivacySettingsView()
                .tabItem { Label("Privacy", systemImage: "lock.shield.fill") }
        }
        .frame(width: 650, height: 510)
        .scenePadding()
    }
}

private struct InteractionSettingsView: View {
    @Environment(ContinuumModel.self) private var model
    @Environment(\.openWindow) private var openWindow
    @Bindable var preferences: ContinuumPreferences

    var body: some View {
        Form {
            Section {
                Picker("Rewind", selection: $preferences.rewindShortcutPreset) {
                    ForEach(RewindShortcutPreset.allCases) { preset in
                        Text(preset.displayName).tag(preset)
                    }
                }

                LabeledContent("Save Snapshot") {
                    Text("⌃⌥⌘S")
                        .monospaced()
                        .foregroundStyle(.secondary)
                }
            } header: {
                SettingsSectionHeader(
                    title: "Global shortcuts",
                    status: .active
                )
            } footer: {
                Text("These global shortcuts are detected over any app while Continuum is running; that does not make the frontmost app rewindable. Safe presets include Control so they do not replace common commands such as Reload.")
            }

            Section {
                Picker("Arrow-key step", selection: $preferences.timelineArrowStep) {
                    ForEach(TimelineArrowStep.allCases) { step in
                        Text(step.displayName).tag(step)
                    }
                }

                LabeledContent("Confirm selected moment") {
                    Text("Return")
                        .foregroundStyle(.secondary)
                }

                LabeledContent("Cancel rewind") {
                    Text("Escape")
                        .foregroundStyle(.secondary)
                }
            } header: {
                SettingsSectionHeader(
                    title: "Timeline navigation",
                    status: .active
                )
            } footer: {
                Text("Use Left and Right Arrow to move through the timeline. Return plays only a state that a restore backend has validated.")
            }

            Section("Setup") {
                LabeledContent {
                    Button("Run Setup Again…") {
                        model.restartOnboarding()
                        openWindow(id: "main")
                    }
                } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Onboarding")
                        Text("Review permissions, compatibility, and storage choices")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .formStyle(.grouped)
    }
}

private struct CaptureSettingsView: View {
    @Bindable var preferences: ContinuumPreferences

    var body: some View {
        Form {
            Section {
                Picker("Active apps", selection: $preferences.activeCheckpointInterval) {
                    ForEach(ActiveCheckpointInterval.allCases) { interval in
                        Text(interval.displayName).tag(interval)
                    }
                }

                Picker("Games and high motion", selection: $preferences.gameCheckpointInterval) {
                    ForEach(GameCheckpointInterval.allCases) { interval in
                        Text(interval.displayName).tag(interval)
                    }
                }

                Picker("Idle apps", selection: $preferences.idleCheckpointInterval) {
                    ForEach(IdleCheckpointInterval.allCases) { interval in
                        Text(interval.displayName).tag(interval)
                    }
                }
            } header: {
                SettingsSectionHeader(
                    title: "Checkpoint intervals",
                    status: .requiresCertifiedBackend
                )
            } footer: {
                Text("These choices are saved now. A certified restore backend is required before Continuum can schedule functional app-state checkpoints at these intervals.")
            }

            Section {
                Stepper(
                    "Instant history: \(preferences.hotHistorySeconds) seconds",
                    value: $preferences.hotHistorySeconds,
                    in: ContinuumPreferences.hotHistoryRange,
                    step: 15
                )

                Stepper(
                    "Rolling history: \(preferences.rollingHistoryMinutes) minutes",
                    value: $preferences.rollingHistoryMinutes,
                    in: ContinuumPreferences.rollingHistoryRange,
                    step: 5
                )

                Stepper(
                    "Disk budget: \(preferences.diskBudgetGigabytes) GB",
                    value: $preferences.diskBudgetGigabytes,
                    in: ContinuumPreferences.diskBudgetRange,
                    step: 5
                )
            } header: {
                SettingsSectionHeader(
                    title: "Retention",
                    status: .requiresCertifiedBackend
                )
            } footer: {
                Text("Saved snapshots remain pinned until you delete them. Continuum saves these preferences, but this build does not yet enforce automatic rolling-history eviction.")
            }
        }
        .formStyle(.grouped)
    }
}

private struct PermissionSettingsView: View {
    let statuses: [PermissionStatus]

    var body: some View {
        Form {
            Section {
                Label {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Requested only when you ask")
                            .fontWeight(.semibold)
                        Text("Onboarding can show the native Accessibility and Screen Recording prompts. Automation and Full Disk Access remain feature-specific.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } icon: {
                    Image(systemName: "checkmark.shield.fill")
                        .foregroundStyle(.green)
                }
            }

            Section("Permission status") {
                if statuses.isEmpty {
                    Text("System status is not available yet. Run onboarding again to request or review access.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(statuses) { status in
                        HStack(spacing: 10) {
                            Image(systemName: status.kind.continuumSymbol)
                                .foregroundStyle(.secondary)
                                .frame(width: 22)

                            VStack(alignment: .leading, spacing: 2) {
                                Text(status.kind.continuumTitle)
                                Text(status.kind.onboardingPurpose)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(2)
                            }

                            Spacer()

                            Text(status.state.continuumTitle)
                                .font(.caption.weight(.medium))
                                .foregroundStyle(status.state.continuumTint)
                        }
                    }
                }
            }
        }
        .formStyle(.grouped)
    }
}

private struct PrivacySettingsView: View {
    @Environment(ContinuumModel.self) private var model
    @State private var showsDeleteConfirmation = false

    var body: some View {
        Form {
            Section("Local by design") {
                Label("Snapshot history stays on this Mac", systemImage: "checkmark.shield.fill")
                Label("Snapshot chunks are encrypted", systemImage: "lock.fill")
                Label("No analytics or cloud sync", systemImage: "icloud.slash")
            }

            Section("What rewind cannot undo") {
                Text("Messages already sent, purchases, uploads, cloud changes, and other actions accepted by an external service remain online.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("Local snapshot data") {
                LabeledContent {
                    Button("Delete All Snapshot Data…", role: .destructive) {
                        showsDeleteConfirmation = true
                    }
                    .disabled(model.snapshots.isEmpty || model.isPerformingAction)
                } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Encrypted snapshots")
                        Text("\(model.snapshots.count) saved on this Mac")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .formStyle(.grouped)
        .alert("Delete all snapshot data?", isPresented: $showsDeleteConfirmation) {
            Button("Cancel", role: .cancel) {}
            Button("Delete Everything", role: .destructive) {
                Task { await model.deleteAllSnapshotData() }
            }
        } message: {
            Text("This permanently removes every snapshot, branch, manifest, and encrypted content chunk. App settings are kept. This cannot be undone.")
        }
    }
}

private struct SettingsSectionHeader: View {
    enum Status {
        case active
        case requiresCertifiedBackend

        var title: String {
            switch self {
            case .active: "Active now"
            case .requiresCertifiedBackend: "Requires certified restore backend"
            }
        }

        var symbol: String {
            switch self {
            case .active: "checkmark.circle.fill"
            case .requiresCertifiedBackend: "exclamationmark.triangle.fill"
            }
        }

        var color: Color {
            switch self {
            case .active: .green
            case .requiresCertifiedBackend: .orange
            }
        }
    }

    let title: String
    let status: Status

    var body: some View {
        HStack(spacing: 8) {
            Text(title)
            Spacer()
            Label(status.title, systemImage: status.symbol)
                .font(.caption2.weight(.semibold))
                .foregroundStyle(status.color)
                .textCase(nil)
        }
    }
}
