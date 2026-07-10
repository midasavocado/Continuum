import Foundation

public enum ContinuumSection: String, Codable, CaseIterable, Identifiable, Sendable {
    case timeline
    case snapshots
    case branches
    case apps
    case storage

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .timeline: "Timeline"
        case .snapshots: "Snapshots"
        case .branches: "Branches"
        case .apps: "Apps"
        case .storage: "Storage"
        }
    }

    public var systemImage: String {
        switch self {
        case .timeline: "clock.arrow.trianglehead.counterclockwise.rotate.90"
        case .snapshots: "camera.aperture"
        case .branches: "arrow.triangle.branch"
        case .apps: "square.grid.2x2"
        case .storage: "internaldrive"
        }
    }
}

public enum SnapshotFilter: String, Codable, CaseIterable, Identifiable, Sendable {
    case all
    case manual
    case beforeRewind
    case crashRecovery

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .all: "All"
        case .manual: "Manual"
        case .beforeRewind: "Before Rewind"
        case .crashRecovery: "Crash Recovery"
        }
    }

    public func includes(_ snapshot: SnapshotRecord) -> Bool {
        switch self {
        case .all: true
        case .manual: snapshot.kind == .manual
        case .beforeRewind: snapshot.kind == .beforeRewind
        case .crashRecovery: snapshot.kind == .crashRecovery
        }
    }
}

public enum RewindPhase: Sendable, Equatable {
    case idle
    case capturingSafetySnapshot
    case previewing(ProvisionalRewindID)
    case restoring(SnapshotID)
    case completed(SnapshotID)
    case failed(String)
}

public struct StorageMetrics: Codable, Hashable, Sendable {
    public var logicalBytes: Int64
    public var physicalBytes: Int64
    public var pinnedBytes: Int64
    public var budgetBytes: Int64

    public init(
        logicalBytes: Int64 = 0,
        physicalBytes: Int64 = 0,
        pinnedBytes: Int64 = 0,
        budgetBytes: Int64 = ContinuumConstants.defaultDiskBudgetBytes
    ) {
        self.logicalBytes = logicalBytes
        self.physicalBytes = physicalBytes
        self.pinnedBytes = pinnedBytes
        self.budgetBytes = budgetBytes
    }

    public var usageFraction: Double {
        guard budgetBytes > 0 else { return 0 }
        return min(max(Double(physicalBytes) / Double(budgetBytes), 0), 1)
    }
}

public enum SnapshotNaming {
    public static func automaticName(appName: String, date: Date, kind: SnapshotKind) -> String {
        let time = date.formatted(date: .omitted, time: .standard)
        switch kind {
        case .beforeRewind:
            return "Before Rewind — \(appName) — \(time)"
        case .crashRecovery:
            return "Before Crash — \(appName) — \(time)"
        case .manual, .automatic:
            return "\(appName) — \(time)"
        }
    }
}
