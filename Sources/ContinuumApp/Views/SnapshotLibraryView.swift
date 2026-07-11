import SwiftUI
import ContinuumCore

struct SnapshotLibraryView: View {
    let snapshots: [SnapshotRecord]
    @Binding var selectedSnapshotID: SnapshotID?
    @Binding var filter: SnapshotFilter
    let onRestore: (SnapshotRecord) -> Void
    let onDelete: (SnapshotRecord) -> Void
    let onUpdate: (SnapshotRecord, String, String) -> Void

    @State private var searchText = ""
    @State private var groupByApp = false

    private var filteredSnapshots: [SnapshotRecord] {
        snapshots
            .filter { filter.includes($0) }
            .filter { snapshot in
                guard !searchText.isEmpty else { return true }
                return snapshot.name.localizedStandardContains(searchText)
                    || snapshot.note.localizedStandardContains(searchText)
                    || snapshot.app.displayName.localizedStandardContains(searchText)
            }
            .sorted { $0.createdAt > $1.createdAt }
    }

    private var selectedSnapshot: SnapshotRecord? {
        snapshots.first { $0.id == selectedSnapshotID }
    }

    var body: some View {
        VStack(spacing: 0) {
            filterBar
            Divider()

            HSplitView {
                snapshotList
                    .frame(minWidth: 300, idealWidth: 340)

                Group {
                    if let selectedSnapshot {
                        SnapshotDetailView(
                            snapshot: selectedSnapshot,
                            onRestore: { onRestore(selectedSnapshot) },
                            onDelete: { onDelete(selectedSnapshot) },
                            onUpdate: { name, note in onUpdate(selectedSnapshot, name, note) }
                        )
                        .id(selectedSnapshot.id)
                    } else {
                        ContentUnavailableView {
                            Label("Choose a snapshot", systemImage: "square.stack.3d.up")
                        } description: {
                            Text("Select a saved moment to see what it contains and whether it can be restored.")
                        }
                    }
                }
                .frame(minWidth: 420, maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .navigationTitle("Snapshots")
        .searchable(text: $searchText, prompt: "Search snapshots")
        .onAppear(perform: ensureSelection)
        .onChange(of: filteredSnapshots.map(\.id)) { _, _ in ensureSelection() }
    }

    private var filterBar: some View {
        HStack(spacing: 12) {
            Picker("Filter", selection: $filter) {
                ForEach([SnapshotFilter.all, .manual]) { filter in
                    Text(filter.title).tag(filter)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(maxWidth: 520)

            Toggle(isOn: $groupByApp) {
                Label("By App", systemImage: "square.grid.2x2")
            }
            .toggleStyle(.button)

            Spacer()

            Text("\(filteredSnapshots.count) saved")
                .font(.caption)
                .foregroundStyle(.secondary)
                .monospacedDigit()
        }
        .padding(12)
    }

    @ViewBuilder
    private var snapshotList: some View {
        if filteredSnapshots.isEmpty {
            ContentUnavailableView {
                Label(emptyTitle, systemImage: "tray")
            } description: {
                Text(emptyDescription)
            } actions: {
                if filter != .all || !searchText.isEmpty {
                    Button("Clear Filters") {
                        filter = .all
                        searchText = ""
                        groupByApp = false
                    }
                }
            }
        } else {
            List(selection: $selectedSnapshotID) {
                if groupByApp {
                    ForEach(groupedAppNames, id: \.self) { appName in
                        Section(appName) {
                            ForEach(filteredSnapshots.filter { $0.app.displayName == appName }) { snapshot in
                                SnapshotRow(snapshot: snapshot)
                                    .tag(snapshot.id)
                            }
                        }
                    }
                } else {
                    ForEach(filteredSnapshots) { snapshot in
                        SnapshotRow(snapshot: snapshot)
                            .tag(snapshot.id)
                    }
                }
            }
            .listStyle(.inset)
        }
    }

    private var groupedAppNames: [String] {
        Set(filteredSnapshots.map(\.app.displayName)).sorted()
    }

    private var emptyTitle: String {
        searchText.isEmpty ? "No snapshots in this view" : "No matching snapshots"
    }

    private var emptyDescription: String {
        if snapshots.isEmpty {
            return "Use Save Snapshot to capture an app, then select it and press Restore."
        }
        return "Try another filter or search term."
    }

    private func ensureSelection() {
        guard selectedSnapshot == nil else { return }
        selectedSnapshotID = filteredSnapshots.first?.id
    }
}
private struct SnapshotRow: View {
    let snapshot: SnapshotRecord

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: snapshot.kind.continuumSymbol)
                .foregroundStyle(snapshot.kind.continuumTint)
                .frame(width: 20)

            VStack(alignment: .leading, spacing: 3) {
                Text(snapshot.name)
                    .fontWeight(.medium)
                    .lineLimit(1)
                HStack(spacing: 5) {
                    Text(snapshot.app.displayName)
                    Text("•")
                    Text(snapshot.createdAt.formatted(date: .omitted, time: .shortened))
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            }

            Spacer(minLength: 4)

            Image(systemName: snapshot.availability.continuumSymbol)
                .foregroundStyle(snapshot.availability.continuumTint)
                .help(snapshot.availability.displayName)
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .combine)
    }
}
