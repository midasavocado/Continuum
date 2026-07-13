import ContinuumCore
import SwiftUI

struct SnapshotDetailView: View {
    let snapshot: SnapshotRecord
    let onRestore: () -> Void
    let onDelete: () -> Void
    let onUpdate: (String, String) -> Void

    @State private var draftName: String
    @State private var draftNote: String
    @State private var showsDeleteConfirmation = false

    init(
        snapshot: SnapshotRecord,
        onRestore: @escaping () -> Void,
        onDelete: @escaping () -> Void,
        onUpdate: @escaping (String, String) -> Void
    ) {
        self.snapshot = snapshot
        self.onRestore = onRestore
        self.onDelete = onDelete
        self.onUpdate = onUpdate
        _draftName = State(initialValue: snapshot.name)
        _draftNote = State(initialValue: snapshot.note)
    }

    private var hasChanges: Bool {
        draftName.trimmingCharacters(in: .whitespacesAndNewlines) != snapshot.name
            || draftNote != snapshot.note
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                titleBlock

                if snapshot.availability == .unavailable {
                    archivedDiagnosticCard
                } else {
                    if !snapshot.externalEffects.isEmpty {
                        OnlineEffectsWarning(effects: snapshot.externalEffects)
                    }
                    detailsCard
                    localStateCard
                    resourceCoverageCard
                }
                notesCard
                actionBar
            }
            .padding(24)
            .frame(maxWidth: 680, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .alert("Delete this snapshot?", isPresented: $showsDeleteConfirmation) {
            Button("Cancel", role: .cancel) {}
            Button("Delete Snapshot", role: .destructive, action: onDelete)
        } message: {
            Text(
                "Continuum will remove this saved snapshot. Shared data used by another snapshot stays safe."
            )
        }
    }

    private var titleBlock: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: snapshot.kind.continuumSymbol)
                .font(.system(size: 28))
                .foregroundStyle(snapshot.kind.continuumTint)
                .frame(width: 42, height: 42)
                .background(
                    snapshot.kind.continuumTint.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))

            VStack(alignment: .leading, spacing: 5) {
                Text(snapshot.name)
                    .font(.title.weight(.semibold))
                    .textSelection(.enabled)
                Text(
                    "\(snapshot.app.displayName) • \(snapshot.createdAt.formatted(date: .long, time: .standard))"
                )
                .foregroundStyle(.secondary)
            }

            Spacer()
            if snapshot.availability == .unavailable {
                StatusBadge(title: "Archived record", systemImage: "archivebox", tint: .secondary)
            } else {
                SnapshotAvailabilityBadge(availability: snapshot.availability)
            }
        }
    }

    private var archivedDiagnosticCard: some View {
        SurfaceCard {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "archivebox")
                    .font(.title2)
                    .foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Older diagnostic record")
                        .font(.headline)
                    Text(
                        "This was saved before a restore engine was available. It is kept only for its name and note—Continuum will never offer it as a rewind point."
                    )
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                }
                Spacer()
            }
        }
    }

    private var detailsCard: some View {
        SurfaceCard {
            VStack(alignment: .leading, spacing: 14) {
                Text("Snapshot details")
                    .font(.headline)

                detailRow("Type", value: snapshot.kind.displayName)
                detailRow("Restore", value: snapshot.availability.displayName)
                detailRow("Processes", value: snapshot.checkpoint.processIdentifiers.count.formatted())
                detailRow("Scope", value: "This app + helpers")
                detailRow("Threads", value: snapshot.checkpoint.threadCount.formatted())
                if let hotMemoryBytes = snapshot.hotMemoryBytes, hotMemoryBytes > 0 {
                    detailRow("Hot memory", value: continuumByteCount(hotMemoryBytes))
                }
                detailRow("Stored", value: continuumByteCount(snapshot.uniqueBytes))
                detailRow("Logical state", value: continuumByteCount(snapshot.logicalBytes))
                detailRow("Validation", value: validationTitle)
            }
        }
    }

    private var localStateCard: some View {
        SurfaceCard {
            VStack(alignment: .leading, spacing: 12) {
                Label("Files", systemImage: "internaldrive")
                    .font(.headline)

                detailRow(
                    "Default",
                    value: snapshot.effectiveLocalFileCoverage.displayName
                )

                Text(
                    "Continuum restores the app process only. Files always stay exactly as they are now."
                )
                .font(.subheadline)
                .foregroundStyle(.secondary)
            }
        }
    }

    private var notesCard: some View {
        SurfaceCard {
            VStack(alignment: .leading, spacing: 12) {
                Text("Name and note")
                    .font(.headline)

                TextField("Snapshot name", text: $draftName)
                    .textFieldStyle(.roundedBorder)

                TextEditor(text: $draftNote)
                    .font(.body)
                    .frame(minHeight: 78)
                    .padding(6)
                    .background(.background.opacity(0.45), in: RoundedRectangle(cornerRadius: 7))
                    .overlay {
                        RoundedRectangle(cornerRadius: 7)
                            .stroke(.quaternary, lineWidth: 0.5)
                    }

                HStack {
                    Text("Notes stay local with this snapshot.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("Save Changes") {
                        let cleanName = draftName.trimmingCharacters(in: .whitespacesAndNewlines)
                        onUpdate(cleanName.isEmpty ? snapshot.name : cleanName, draftNote)
                    }
                    .disabled(!hasChanges)
                }
            }
        }
    }

    @ViewBuilder
    private var resourceCoverageCard: some View {
        if let coverage = snapshot.resourceCoverage, !coverage.isEmpty {
            SurfaceCard {
                DisclosureGroup("What this snapshot can restore") {
                    VStack(spacing: 9) {
                        Divider()
                        ForEach(coverage, id: \.domain) { item in
                            HStack(alignment: .firstTextBaseline) {
                                Text(item.domain.displayName)
                                    .foregroundStyle(.secondary)
                                Spacer()
                                Text(item.mode.displayName)
                                    .fontWeight(.medium)
                                    .foregroundStyle(item.mode.continuumTint)
                            }
                            .font(.subheadline)
                            .help(item.detail)
                        }
                    }
                    .padding(.top, 6)
                }
                .font(.headline)
            }
        }
    }

    private var actionBar: some View {
        HStack {
            Button("Delete", systemImage: "trash", role: .destructive) {
                showsDeleteConfirmation = true
            }

            Spacer()

            if snapshot.availability != .unavailable {
                VStack(alignment: .trailing, spacing: 3) {
                    Button(
                        restoreActionTitle,
                        systemImage: snapshot.availability == .instant ? "bolt.fill" : (snapshot.availability == .experimentalHot ? "checkmark.circle.fill" : "play.fill"),
                        action: onRestore
                    )
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)

                    Text("Restores the saved app state.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var validationTitle: String {
        return switch snapshot.checkpoint.validation {
        case .provisional: "Provisional"
        case .validating: "Validating"
        case .valid: "Validated"
        case .invalid: "Invalid"
        }
    }

    private var restoreActionTitle: String {
        switch snapshot.availability {
        case .instant, .experimentalHot: "Restore Snapshot"
        case .replayRequired: "Restore Snapshot"
        case .unavailable: "Unavailable"
        }
    }

    private func detailRow(_ label: String, value: String) -> some View {
        HStack {
            Text(label).foregroundStyle(.secondary)
            Spacer()
            Text(value).fontWeight(.medium)
        }
        .font(.subheadline)
    }
}
