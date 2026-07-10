import SwiftUI
import ContinuumCore

struct BranchTreeView: View {
    let branches: [BranchRecord]
    let snapshots: [SnapshotRecord]
    @Binding var selectedBranchID: BranchID?

    private var orderedBranches: [BranchRecord] {
        branches.sorted { lhs, rhs in
            if lhs.parentBranchID == nil, rhs.parentBranchID != nil { return true }
            if lhs.parentBranchID != nil, rhs.parentBranchID == nil { return false }
            return lhs.createdAt < rhs.createdAt
        }
    }

    private var selectedBranch: BranchRecord? {
        branches.first { $0.id == selectedBranchID }
            ?? branches.first(where: \.isActive)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header
                explanation

                if branches.isEmpty {
                    ContentUnavailableView {
                        Label("One timeline, no branches yet", systemImage: "arrow.triangle.branch")
                    } description: {
                        Text("When you rewind and continue, Continuum keeps the future you left here.")
                    }
                    .frame(maxWidth: .infinity, minHeight: 260)
                } else {
                    SurfaceCard {
                        VStack(spacing: 0) {
                            ForEach(orderedBranches) { branch in
                                BranchRow(
                                    branch: branch,
                                    depth: depth(of: branch),
                                    rootSnapshotName: snapshotName(branch.rootSnapshotID),
                                    isSelected: selectedBranch?.id == branch.id
                                ) {
                                    selectedBranchID = branch.id
                                }

                                if branch.id != orderedBranches.last?.id {
                                    Divider().padding(.leading, 44)
                                }
                            }
                        }
                    }
                }

                if let selectedBranch {
                    branchDetail(selectedBranch)
                }
            }
            .padding(24)
            .frame(maxWidth: 900, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .navigationTitle("Branches")
        .onAppear {
            if selectedBranchID == nil {
                selectedBranchID = branches.first(where: \.isActive)?.id ?? branches.first?.id
            }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Every future stays yours")
                .font(.largeTitle.weight(.semibold))
            Text("Rewinding creates a new path without erasing the one you leave.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
    }

    private var explanation: some View {
        SurfaceCard {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "arrow.triangle.branch")
                    .font(.title2)
                    .foregroundStyle(.indigo)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Rewinds are non-destructive")
                        .font(.headline)
                    Text("Before Continuum moves backward, it saves the current state as a permanent “Before Rewind” snapshot. You can return to either future later.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
        }
    }

    private func branchDetail(_ branch: BranchRecord) -> some View {
        SurfaceCard {
            HStack(alignment: .top, spacing: 16) {
                Image(systemName: branch.isActive ? "checkmark.circle.fill" : "circle.dotted")
                    .font(.title2)
                    .foregroundStyle(branch.isActive ? .green : .secondary)

                VStack(alignment: .leading, spacing: 5) {
                    Text(branch.name)
                        .font(.title3.weight(.semibold))
                    Text(branch.isActive
                         ? "This is the active metadata branch."
                         : "This branch is preserved, but activating it requires a validated app-state restore.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    Text("Created \(branch.createdAt.formatted(date: .abbreviated, time: .shortened))")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }

                Spacer()

                if !branch.isActive {
                    StatusBadge(
                        title: "Restore required",
                        systemImage: "lock.fill",
                        tint: .secondary
                    )
                }
            }
        }
    }

    private func snapshotName(_ id: SnapshotID?) -> String? {
        guard let id else { return nil }
        return snapshots.first { $0.id == id }?.name
    }

    private func depth(of branch: BranchRecord) -> Int {
        var depth = 0
        var parentID = branch.parentBranchID
        var visited = Set<BranchID>()

        while let id = parentID,
              visited.insert(id).inserted,
              let parent = branches.first(where: { $0.id == id }) {
            depth += 1
            parentID = parent.parentBranchID
        }

        return min(depth, 6)
    }
}

private struct BranchRow: View {
    let branch: BranchRecord
    let depth: Int
    let rootSnapshotName: String?
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                HStack(spacing: 7) {
                    ForEach(0..<depth, id: \.self) { _ in
                        Capsule()
                            .fill(.quaternary)
                            .frame(width: 2, height: 34)
                            .frame(width: 10)
                    }

                    Image(systemName: branch.isActive ? "circle.inset.filled" : "circle")
                        .foregroundStyle(branch.isActive ? .green : .secondary)
                }

                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 7) {
                        Text(branch.name)
                            .fontWeight(.medium)
                        if branch.isActive {
                            Text("ACTIVE")
                                .font(.caption2.weight(.bold))
                                .foregroundStyle(.green)
                        }
                    }
                    Text(rootSnapshotName ?? (branch.parentBranchID == nil ? "Original timeline" : "Branch point retained"))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }

                Spacer()
                Text(branch.createdAt.formatted(date: .omitted, time: .shortened))
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            .padding(.vertical, 10)
            .padding(.horizontal, 8)
            .background(isSelected ? Color.accentColor.opacity(0.1) : .clear, in: RoundedRectangle(cornerRadius: 8))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}
