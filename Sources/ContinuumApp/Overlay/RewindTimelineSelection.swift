import ContinuumCore
import Foundation
import Observation

enum RewindOverlayPhase: Equatable {
    case browsing
    case securingPresent
    case cancelling
    case restoring
    case committed
    case failed(String)

    var acceptsSelection: Bool {
        switch self {
        case .browsing, .failed:
            true
        case .securingPresent, .cancelling, .restoring, .committed:
            false
        }
    }
}

enum TimelineMoveDirection {
    case backward
    case forward
}

@MainActor
@Observable
final class RewindTimelineSelection {
    private(set) var snapshots: [SnapshotRecord] = []
    private(set) var selectedSnapshotID: SnapshotID?
    private(set) var stepMilliseconds = 1_000
    var phase: RewindOverlayPhase = .browsing

    var selectedSnapshot: SnapshotRecord? {
        guard let selectedSnapshotID else { return nil }
        return snapshots.first { $0.id == selectedSnapshotID }
    }

    var canCommit: Bool {
        phase.acceptsSelection && selectedSnapshot?.availability != .unavailable
    }

    var stepDescription: String {
        if stepMilliseconds < 1_000 {
            return "\(stepMilliseconds) ms"
        }

        let seconds = Double(stepMilliseconds) / 1_000
        if seconds.rounded() == seconds {
            return "\(Int(seconds)) sec"
        }
        return "\(seconds.formatted(.number.precision(.fractionLength(1)))) sec"
    }

    func prepare(
        snapshots newSnapshots: [SnapshotRecord],
        stepMilliseconds: Int
    ) {
        self.stepMilliseconds = max(stepMilliseconds, 1)
        phase = .browsing
        replaceSnapshots(newSnapshots, preserveSelection: false)
    }

    func replaceSnapshots(
        _ newSnapshots: [SnapshotRecord],
        preserveSelection: Bool = true
    ) {
        let previousSelection = preserveSelection ? selectedSnapshotID : nil
        snapshots = newSnapshots.sorted {
            if $0.createdAt == $1.createdAt {
                return $0.name.localizedStandardCompare($1.name) == .orderedAscending
            }
            return $0.createdAt < $1.createdAt
        }

        if let previousSelection,
           snapshots.contains(where: { $0.id == previousSelection }) {
            selectedSnapshotID = previousSelection
        } else {
            selectedSnapshotID = snapshots.last?.id
        }
    }

    func select(_ snapshotID: SnapshotID) {
        guard phase.acceptsSelection,
              snapshots.contains(where: { $0.id == snapshotID }) else {
            return
        }
        selectedSnapshotID = snapshotID
        if case .failed = phase {
            phase = .browsing
        }
    }

    func move(_ direction: TimelineMoveDirection) {
        guard phase.acceptsSelection, !snapshots.isEmpty else { return }
        guard let selectedSnapshotID,
              let currentIndex = snapshots.firstIndex(where: { $0.id == selectedSnapshotID }) else {
            self.selectedSnapshotID = snapshots.last?.id
            return
        }

        let step = TimeInterval(stepMilliseconds) / 1_000
        let currentDate = snapshots[currentIndex].createdAt

        switch direction {
        case .backward:
            guard currentIndex > snapshots.startIndex else { return }
            let targetDate = currentDate.addingTimeInterval(-step)
            let targetIndex = snapshots[..<currentIndex].lastIndex {
                $0.createdAt <= targetDate
            } ?? snapshots.index(before: currentIndex)
            self.selectedSnapshotID = snapshots[targetIndex].id

        case .forward:
            guard currentIndex < snapshots.index(before: snapshots.endIndex) else { return }
            let targetDate = currentDate.addingTimeInterval(step)
            let afterCurrent = snapshots.index(after: currentIndex)..<snapshots.endIndex
            let targetIndex = afterCurrent.first {
                snapshots[$0].createdAt >= targetDate
            } ?? snapshots.index(before: snapshots.endIndex)
            self.selectedSnapshotID = snapshots[targetIndex].id
        }

        if case .failed = phase {
            phase = .browsing
        }
    }
}
