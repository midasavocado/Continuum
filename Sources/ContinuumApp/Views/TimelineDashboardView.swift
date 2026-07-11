import SwiftUI
import ContinuumCore

struct TimelineDashboardView: View {
    let snapshots: [SnapshotRecord]
    let runningProcesses: [ProcessDescriptor]
    let rewindPhase: RewindPhase
    let onlineWarning: [ExternalEffect]?
    let isPerformingAction: Bool
    let canCaptureRestorableState: Bool
    let onSaveSnapshot: () -> Void
    let onBeginRewind: (SnapshotRecord) -> Void
    let onCommitRewind: (SnapshotRecord) -> Void
    let onCancelRewind: () -> Void
    let onUndoRewind: () -> Void

    @State private var scrubPosition = 0.0

    private var orderedSnapshots: [SnapshotRecord] {
        snapshots
            .filter { $0.availability != .unavailable }
            .sorted { $0.createdAt < $1.createdAt }
    }

    private var selectedSnapshot: SnapshotRecord? {
        guard !orderedSnapshots.isEmpty else { return nil }
        let index = min(max(Int(scrubPosition.rounded()), 0), orderedSnapshots.count - 1)
        return orderedSnapshots[index]
    }

    private var frontmostApp: AppIdentity? {
        runningProcesses.first(where: \.isFrontmost)?.app ?? runningProcesses.first?.app
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header
                captureStatus

                if let onlineWarning, !onlineWarning.isEmpty {
                    OnlineEffectsWarning(effects: onlineWarning)
                }

                timelineCard
                recentMoments
            }
            .padding(24)
            .frame(maxWidth: 980, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .navigationTitle("Timeline")
        .onAppear { selectNewestSnapshot() }
        .onChange(of: snapshots.count) { _, _ in selectNewestSnapshot() }
    }

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Rewind, proven before promised")
                    .font(.largeTitle.weight(.semibold))
                Text("Browse encrypted diagnostic moments while the exact-restore runtime is being certified.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            if canCaptureRestorableState {
                Button(action: onSaveSnapshot) {
                    Label("Save Snapshot", systemImage: "bookmark.fill")
                }
                .buttonStyle(.bordered)
                .controlSize(.large)
                .disabled(frontmostApp == nil || isPerformingAction)
                .help("Save the frontmost app (⌃⌥⌘S)")
            }
        }
    }

    private var captureStatus: some View {
        SurfaceCard {
            HStack(spacing: 16) {
                ZStack {
                    Circle()
                        .fill(frontmostApp == nil ? Color.secondary.opacity(0.15) : Color.orange.opacity(0.15))
                    Image(systemName: frontmostApp == nil ? "pause.fill" : "stethoscope")
                        .font(.title2)
                        .foregroundStyle(frontmostApp == nil ? Color.secondary : Color.orange)
                }
                .frame(width: 46, height: 46)

                VStack(alignment: .leading, spacing: 3) {
                    Text(canCaptureRestorableState
                         ? (frontmostApp == nil ? "Waiting for an app" : "Ready for \(frontmostApp?.displayName ?? "the frontmost app")")
                         : "Rewind engine not available")
                        .font(.headline)
                    Text(canCaptureRestorableState
                         ? "Continuum saves only moments it can actually restore."
                         : "This build cannot create a restorable state yet, so saving and rewinding are unavailable instead of pretending.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }

                Spacer()

                StatusBadge(
                    title: canCaptureRestorableState ? (frontmostApp == nil ? "Idle" : "Ready") : "Not ready",
                    systemImage: canCaptureRestorableState ? (frontmostApp == nil ? "pause.circle.fill" : "checkmark.circle.fill") : "lock.circle.fill",
                    tint: canCaptureRestorableState ? (frontmostApp == nil ? Color.secondary : Color.green) : Color.secondary
                )
            }
        }
    }

    private var timelineCard: some View {
        SurfaceCard {
            VStack(alignment: .leading, spacing: 18) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Rewind")
                            .font(.title2.weight(.semibold))
                        Text(rewindInstruction)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    phaseIndicator
                }

                if orderedSnapshots.isEmpty {
                    ContentUnavailableView {
                        Label("No saved moments yet", systemImage: "clock.badge.questionmark")
                    } description: {
                        Text(canCaptureRestorableState
                             ? "Save a snapshot to create a restorable moment."
                             : "No restorable moments yet. Older diagnostic records are kept in Snapshots, but cannot be rewound.")
                    }
                    .frame(maxWidth: .infinity, minHeight: 180)
                } else {
                    VStack(spacing: 8) {
                        TimelineMarkerTrack(snapshots: orderedSnapshots)
                        Slider(
                            value: $scrubPosition,
                            in: 0...Double(max(orderedSnapshots.count - 1, 1)),
                            step: 1
                        )
                        .disabled(orderedSnapshots.count < 2 || isPerformingAction)

                        HStack {
                            Text(orderedSnapshots.first?.createdAt.formatted(date: .omitted, time: .shortened) ?? "")
                            Spacer()
                            Text("Now")
                        }
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                    }

                    if let selectedSnapshot {
                        selectedMoment(snapshot: selectedSnapshot)
                    }
                }

                Divider()
                rewindActions
            }
        }
    }

    @ViewBuilder
    private var phaseIndicator: some View {
        switch rewindPhase {
        case .idle:
            StatusBadge(title: "Research build", systemImage: "hammer.fill", tint: .orange)
        case .capturingSafetySnapshot:
            StatusBadge(title: "Saving current state", systemImage: "lock.fill", tint: .blue)
        case .previewing:
            StatusBadge(title: "Previewing", systemImage: "arrow.uturn.backward", tint: .indigo)
        case .restoring:
            StatusBadge(title: "Restoring", systemImage: "hourglass", tint: .blue)
        case .completed:
            StatusBadge(title: "Rewound", systemImage: "checkmark.circle.fill", tint: .green)
        case .failed:
            StatusBadge(title: "Couldn’t rewind", systemImage: "exclamationmark.triangle.fill", tint: .red)
        }
    }

    private var rewindInstruction: String {
        switch rewindPhase {
        case .idle, .completed, .failed:
            "Use the Rewind shortcut to open the keyboard timeline. Only validated states can be selected."
        case .capturingSafetySnapshot:
            "Securing the current future before preview begins."
        case .previewing:
            "This is a validated local state. Online actions are not reversed."
        case .restoring:
            "Restoring local state and rebuilding app resources."
        }
    }

    private func selectedMoment(snapshot: SnapshotRecord) -> some View {
        HStack(spacing: 12) {
            Image(systemName: snapshot.kind.continuumSymbol)
                .font(.title2)
                .foregroundStyle(snapshot.kind.continuumTint)
                .frame(width: 32)

            VStack(alignment: .leading, spacing: 2) {
                Text(snapshot.name)
                    .font(.headline)
                    .lineLimit(1)
                Text("\(snapshot.app.displayName) • \(snapshot.createdAt.formatted(date: .abbreviated, time: .standard))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()
            SnapshotAvailabilityBadge(availability: snapshot.availability)
        }
        .padding(12)
        .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 10))
    }

    @ViewBuilder
    private var rewindActions: some View {
        switch rewindPhase {
        case .idle, .failed:
            VStack(alignment: .leading, spacing: 7) {
                Label("Press your Rewind shortcut to open the floating timeline", systemImage: "keyboard")
                    .font(.headline)
                Text(selectedSnapshot?.availability == .unavailable
                     ? "This selected moment contains diagnostics only, so Return will stay unavailable."
                     : "Left and Right choose a moment, Return continues from it, and Escape cancels.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

        case .capturingSafetySnapshot:
            HStack(spacing: 10) {
                ProgressView().controlSize(.small)
                Text("Saving the state you’re leaving…")
                Spacer()
            }
            .foregroundStyle(.secondary)

        case .previewing:
            HStack {
                Label("Current future safely saved", systemImage: "lock.fill")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Cancel", action: onCancelRewind)
                if let selectedSnapshot, selectedSnapshot.availability != .unavailable {
                    Button("Play from Here", systemImage: "play.fill") {
                        onCommitRewind(selectedSnapshot)
                    }
                    .buttonStyle(.borderedProminent)
                }
            }

            if selectedSnapshot?.availability == .unavailable {
                Label("This moment is visible for context, but its app state cannot be restored.", systemImage: "nosign")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

        case .restoring:
            HStack(spacing: 10) {
                ProgressView().controlSize(.small)
                Text("Restoring the selected local state…")
                Spacer()
            }
            .foregroundStyle(.secondary)

        case .completed:
            HStack {
                Label("You’re on a new branch. The future you left is still safe.", systemImage: "arrow.triangle.branch")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Undo Rewind", action: onUndoRewind)
                    .buttonStyle(.bordered)
                Button("Rewind Again…") {
                    if let selectedSnapshot { onBeginRewind(selectedSnapshot) }
                }
                    .buttonStyle(.borderedProminent)
            }
        }
    }

    private var recentMoments: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Recent moments")
                .font(.title2.weight(.semibold))

            if snapshots.isEmpty {
                Text("Saved diagnostic moments will appear here.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(snapshots.sorted { $0.createdAt > $1.createdAt }.prefix(4)) { snapshot in
                    HStack(spacing: 12) {
                        Image(systemName: snapshot.kind.continuumSymbol)
                            .foregroundStyle(snapshot.kind.continuumTint)
                            .frame(width: 22)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(snapshot.name).lineLimit(1)
                            Text(snapshot.createdAt.formatted(date: .abbreviated, time: .shortened))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        SnapshotAvailabilityBadge(availability: snapshot.availability)
                    }
                    .padding(.vertical, 4)
                }
            }
        }
    }

    private func selectNewestSnapshot() {
        scrubPosition = Double(max(orderedSnapshots.count - 1, 0))
    }
}

private struct TimelineMarkerTrack: View {
    let snapshots: [SnapshotRecord]

    var body: some View {
        GeometryReader { proxy in
            ZStack(alignment: .leading) {
                Capsule()
                    .fill(.quaternary)
                    .frame(height: 3)

                ForEach(Array(snapshots.enumerated()), id: \.element.id) { index, snapshot in
                    Circle()
                        .fill(snapshot.externalEffects.isEmpty ? snapshot.kind.continuumTint : Color.orange)
                        .frame(width: 9, height: 9)
                        .overlay(Circle().stroke(.background, lineWidth: 1.5))
                        .offset(x: markerOffset(index: index, width: proxy.size.width) - 4.5)
                        .help(snapshot.externalEffects.isEmpty ? snapshot.kind.displayName : "Includes online effects")
                }
            }
            .frame(maxHeight: .infinity)
        }
        .frame(height: 12)
        .accessibilityLabel("Snapshot markers")
    }

    private func markerOffset(index: Int, width: CGFloat) -> CGFloat {
        guard snapshots.count > 1 else { return width }
        return width * CGFloat(index) / CGFloat(snapshots.count - 1)
    }
}
