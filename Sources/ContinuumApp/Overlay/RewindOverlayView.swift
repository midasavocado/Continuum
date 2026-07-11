import ContinuumCore
import SwiftUI

struct RewindOverlayView: View {
    @Bindable var state: RewindTimelineSelection
    let onSelect: (SnapshotID) -> Void
    let onCommit: () -> Void
    let onDismiss: () -> Void

    @State private var hasAppeared = false

    var body: some View {
        ZStack {
            background

            VStack(alignment: .leading, spacing: 18) {
                header
                timeline
                selectionDetails
                footer
            }
            .padding(24)

            phaseOverlay
        }
        .frame(width: 840, height: 440)
        .clipShape(RoundedRectangle(cornerRadius: 26, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 26, style: .continuous)
                .strokeBorder(.white.opacity(0.15), lineWidth: 1)
        }
        .shadow(color: .black.opacity(0.26), radius: 36, y: 16)
        .scaleEffect(hasAppeared ? 1 : 0.965)
        .opacity(hasAppeared ? 1 : 0)
        .onAppear {
            withAnimation(.spring(response: 0.32, dampingFraction: 0.84)) {
                hasAppeared = true
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Continuum rewind timeline")
    }

    private var background: some View {
        ZStack {
            Rectangle()
                .fill(.ultraThickMaterial)

            Circle()
                .fill(Color.indigo.opacity(0.20))
                .frame(width: 360, height: 360)
                .blur(radius: 70)
                .offset(x: -310, y: -190)

            Circle()
                .fill(Color.cyan.opacity(0.12))
                .frame(width: 300, height: 300)
                .blur(radius: 75)
                .offset(x: 360, y: 210)
        }
    }

    private var header: some View {
        HStack(spacing: 14) {
            ZStack {
                Circle()
                    .fill(
                        LinearGradient(
                            colors: [.indigo, .blue],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                Image(systemName: "clock.arrow.trianglehead.counterclockwise.rotate.90")
                    .font(.system(size: 20, weight: .semibold))
                    .foregroundStyle(.white)
            }
            .frame(width: 44, height: 44)
            .shadow(color: .indigo.opacity(0.28), radius: 10, y: 5)

            VStack(alignment: .leading, spacing: 2) {
                Text("Rewind")
                    .font(.title2.weight(.semibold))
                Text("Choose a saved moment. Nothing changes until you press Return.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            Button(action: onDismiss) {
                Image(systemName: "xmark")
                    .font(.system(size: 12, weight: .bold))
                    .frame(width: 28, height: 28)
                    .background(.quaternary.opacity(0.65), in: Circle())
            }
            .buttonStyle(.plain)
            .help("Close (Esc)")
            .accessibilityLabel("Close rewind timeline")
        }
    }

    @ViewBuilder
    private var timeline: some View {
        if state.snapshots.isEmpty {
            ContentUnavailableView {
                Label("No saved moments yet", systemImage: "clock.badge.questionmark")
            } description: {
                Text("Save a snapshot first with Control–Option–Command–S.")
            }
            .frame(maxWidth: .infinity, minHeight: 176)
        } else {
            ScrollViewReader { proxy in
                ScrollView(.horizontal) {
                    HStack(alignment: .top, spacing: 0) {
                        ForEach(Array(state.snapshots.enumerated()), id: \.element.id) { index, snapshot in
                            TimelineMoment(
                                snapshot: snapshot,
                                isSelected: snapshot.id == state.selectedSnapshotID,
                                isFirst: index == state.snapshots.startIndex,
                                isLast: index == state.snapshots.index(before: state.snapshots.endIndex),
                                isEnabled: state.phase.acceptsSelection
                            ) {
                                onSelect(snapshot.id)
                            }
                            .id(snapshot.id)
                        }
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                }
                .scrollIndicators(.hidden)
                .frame(height: 176)
                .onAppear {
                    guard let snapshotID = state.selectedSnapshotID else { return }
                    proxy.scrollTo(snapshotID, anchor: .center)
                }
                .onChange(of: state.selectedSnapshotID) { _, snapshotID in
                    guard let snapshotID else { return }
                    withAnimation(.snappy(duration: 0.22)) {
                        proxy.scrollTo(snapshotID, anchor: .center)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var selectionDetails: some View {
        if let snapshot = state.selectedSnapshot {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 12) {
                    Image(systemName: snapshot.kind.continuumSymbol)
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundStyle(snapshot.kind.continuumTint)
                        .frame(width: 34, height: 34)
                        .background(snapshot.kind.continuumTint.opacity(0.13), in: Circle())

                    VStack(alignment: .leading, spacing: 2) {
                        Text(snapshot.name)
                            .font(.headline)
                            .lineLimit(1)
                        Text("\(snapshot.app.displayName) · \(snapshot.createdAt.formatted(date: .abbreviated, time: .standard))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

                    Spacer()
                    SnapshotAvailabilityBadge(availability: snapshot.availability)
                }
                .padding(.horizontal, 13)
                .padding(.vertical, 10)
                .background(.quaternary.opacity(0.38), in: RoundedRectangle(cornerRadius: 13))

                if snapshot.availability == .unavailable {
                    Label {
                        Text("This moment contains metadata only. Its memory and app resources cannot be restored, so Return is disabled.")
                    } icon: {
                        Image(systemName: "exclamationmark.triangle.fill")
                    }
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .transition(.opacity.combined(with: .move(edge: .top)))
                } else if snapshot.availability == .experimentalHot {
                    Label {
                        Text("Experimental Hot restores live memory and threads. Files, connections, windows, and GPU resources are not reconstructed yet.")
                    } icon: {
                        Image(systemName: "flask.fill")
                    }
                    .font(.caption)
                    .foregroundStyle(.orange)
                } else if case let .failed(message) = state.phase {
                    Label(message, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.red)
                        .lineLimit(2)
                }
            }
        }
    }

    private var footer: some View {
        HStack(spacing: 12) {
            KeyHint(keys: ["←", "→"], label: state.stepDescription)
            KeyHint(keys: ["esc"], label: "Close")

            Spacer()

            if let snapshot = state.selectedSnapshot {
                Button(action: onCommit) {
                    HStack(spacing: 8) {
                        Text("↩")
                            .font(.system(.body, design: .rounded, weight: .bold))
                        Text(commitTitle(for: snapshot))
                    }
                    .padding(.horizontal, 14)
                    .padding(.vertical, 8)
                }
                .buttonStyle(.plain)
                .foregroundStyle(snapshot.availability == .unavailable ? Color.secondary : Color.white)
                .background(
                    snapshot.availability == .unavailable ? Color.secondary.opacity(0.12) : Color.accentColor,
                    in: Capsule()
                )
                .disabled(!state.canCommit)
                .help(snapshot.availability == .unavailable
                      ? "This moment cannot be restored"
                      : "Save the present, then rewind to this moment")
            }
        }
        .frame(minHeight: 32)
    }

    private func commitTitle(for snapshot: SnapshotRecord) -> String {
        switch snapshot.availability {
        case .unavailable: "Unavailable"
        case .experimentalHot: "Try from Here"
        case .instant, .replayRequired: "Play from Here"
        }
    }

    @ViewBuilder
    private var phaseOverlay: some View {
        switch state.phase {
        case .browsing, .failed:
            EmptyView()

        case .securingPresent:
            BusyOverlay(
                title: "Saving where you are…",
                detail: "Your current future is being secured before anything changes."
            )

        case .cancelling:
            BusyOverlay(
                title: "Returning safely…",
                detail: "Continuum is validating the state you started from."
            )

        case .restoring:
            BusyOverlay(
                title: "Rewinding…",
                detail: "Restoring local app state and rebuilding resources."
            )

        case .committed:
            CommitBurstView()
                .transition(.opacity.combined(with: .scale(scale: 0.82)))
        }
    }
}

private struct TimelineMoment: View {
    let snapshot: SnapshotRecord
    let isSelected: Bool
    let isFirst: Bool
    let isLast: Bool
    let isEnabled: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: 8) {
                HStack(spacing: 0) {
                    Rectangle()
                        .fill(isFirst ? Color.clear : Color.secondary.opacity(0.25))
                        .frame(height: 2)

                    ZStack {
                        Circle()
                            .fill(isSelected ? Color.accentColor : Color.secondary.opacity(0.45))
                            .frame(width: isSelected ? 14 : 10, height: isSelected ? 14 : 10)
                        if isSelected {
                            Circle()
                                .stroke(Color.accentColor.opacity(0.28), lineWidth: 5)
                                .frame(width: 24, height: 24)
                        }
                    }
                    .frame(width: 26, height: 26)

                    Rectangle()
                        .fill(isLast ? Color.clear : Color.secondary.opacity(0.25))
                        .frame(height: 2)
                }

                VStack(alignment: .leading, spacing: 5) {
                    HStack {
                        Image(systemName: snapshot.availability.continuumSymbol)
                            .foregroundStyle(snapshot.availability.continuumTint)
                        Spacer()
                        Text(snapshot.createdAt.formatted(date: .omitted, time: .shortened))
                            .foregroundStyle(.secondary)
                    }
                    .font(.caption2)

                    Text(snapshot.app.displayName)
                        .font(.subheadline.weight(.semibold))
                        .lineLimit(1)

                    Text(snapshot.name)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .multilineTextAlignment(.leading)
                }
                .frame(maxWidth: .infinity, minHeight: 72, alignment: .topLeading)
                .padding(10)
                .background(
                    isSelected ? Color.accentColor.opacity(0.13) : Color.primary.opacity(0.045),
                    in: RoundedRectangle(cornerRadius: 12)
                )
                .overlay {
                    RoundedRectangle(cornerRadius: 12)
                        .strokeBorder(
                            isSelected ? Color.accentColor.opacity(0.7) : Color.clear,
                            lineWidth: 1.5
                        )
                }
            }
            .frame(width: 154)
            .contentShape(Rectangle())
            .scaleEffect(isSelected ? 1 : 0.96)
            .animation(.snappy(duration: 0.2), value: isSelected)
        }
        .buttonStyle(.plain)
        .disabled(!isEnabled)
        .accessibilityLabel("\(snapshot.name), \(snapshot.availability.displayName)")
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }
}

private struct KeyHint: View {
    let keys: [String]
    let label: String

    var body: some View {
        HStack(spacing: 5) {
            ForEach(keys, id: \.self) { key in
                Text(key)
                    .font(.system(size: 11, weight: .semibold, design: .rounded))
                    .padding(.horizontal, 7)
                    .frame(height: 23)
                    .background(.quaternary.opacity(0.75), in: RoundedRectangle(cornerRadius: 6))
                    .overlay {
                        RoundedRectangle(cornerRadius: 6)
                            .strokeBorder(.primary.opacity(0.10), lineWidth: 1)
                    }
            }
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

private struct BusyOverlay: View {
    let title: String
    let detail: String

    var body: some View {
        ZStack {
            Rectangle()
                .fill(.ultraThinMaterial)

            VStack(spacing: 14) {
                ProgressView()
                    .controlSize(.large)
                Text(title)
                    .font(.title3.weight(.semibold))
                Text(detail)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            .padding(28)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 18))
            .shadow(color: .black.opacity(0.14), radius: 18, y: 8)
        }
    }
}

private struct CommitBurstView: View {
    @State private var expanded = false

    var body: some View {
        ZStack {
            Rectangle()
                .fill(.ultraThinMaterial)

            Circle()
                .stroke(Color.accentColor.opacity(expanded ? 0 : 0.65), lineWidth: 3)
                .frame(width: 120, height: 120)
                .scaleEffect(expanded ? 2.1 : 0.55)

            Circle()
                .fill(Color.accentColor.opacity(expanded ? 0 : 0.12))
                .frame(width: 220, height: 220)
                .scaleEffect(expanded ? 1.7 : 0.45)

            VStack(spacing: 12) {
                Image(systemName: "arrow.uturn.backward.circle.fill")
                    .font(.system(size: 56, weight: .semibold))
                    .symbolRenderingMode(.palette)
                    .foregroundStyle(.white, Color.accentColor)
                    .shadow(color: Color.accentColor.opacity(0.35), radius: 16, y: 6)
                Text("Rewind complete")
                    .font(.title2.weight(.semibold))
                Text("Playing from the selected moment")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            .scaleEffect(expanded ? 1 : 0.82)
        }
        .onAppear {
            withAnimation(.spring(response: 0.42, dampingFraction: 0.72)) {
                expanded = true
            }
        }
    }
}
