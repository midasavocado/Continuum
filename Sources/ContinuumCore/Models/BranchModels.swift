import Foundation

public struct BranchRecord: Codable, Hashable, Identifiable, Sendable {
    public let id: BranchID
    public var name: String
    public let parentBranchID: BranchID?
    public let rootSnapshotID: SnapshotID?
    public var tipSnapshotID: SnapshotID?
    public let createdAt: Date
    public var isActive: Bool

    public init(
        id: BranchID = UUID(),
        name: String,
        parentBranchID: BranchID?,
        rootSnapshotID: SnapshotID?,
        tipSnapshotID: SnapshotID?,
        createdAt: Date = .now,
        isActive: Bool
    ) {
        self.id = id
        self.name = name
        self.parentBranchID = parentBranchID
        self.rootSnapshotID = rootSnapshotID
        self.tipSnapshotID = tipSnapshotID
        self.createdAt = createdAt
        self.isActive = isActive
    }
}

public struct ProvisionalRewind: Codable, Hashable, Identifiable, Sendable {
    public let id: ProvisionalRewindID
    public let safetySnapshotID: SnapshotID
    public let sourceBranchID: BranchID
    public let createdAt: Date

    public init(
        id: ProvisionalRewindID = UUID(),
        safetySnapshotID: SnapshotID,
        sourceBranchID: BranchID,
        createdAt: Date = .now
    ) {
        self.id = id
        self.safetySnapshotID = safetySnapshotID
        self.sourceBranchID = sourceBranchID
        self.createdAt = createdAt
    }
}

public struct RewindCommit: Codable, Hashable, Sendable {
    public let targetSnapshotID: SnapshotID
    public let safetySnapshotID: SnapshotID
    public let abandonedFutureBranchID: BranchID
    public let activeBranchID: BranchID

    public init(
        targetSnapshotID: SnapshotID,
        safetySnapshotID: SnapshotID,
        abandonedFutureBranchID: BranchID,
        activeBranchID: BranchID
    ) {
        self.targetSnapshotID = targetSnapshotID
        self.safetySnapshotID = safetySnapshotID
        self.abandonedFutureBranchID = abandonedFutureBranchID
        self.activeBranchID = activeBranchID
    }
}

public struct StoreIndex: Codable, Sendable {
    public var schemaVersion: Int
    public var snapshots: [SnapshotRecord]
    public var branches: [BranchRecord]
    public var provisionalRewinds: [ProvisionalRewind]

    public init(
        schemaVersion: Int = ContinuumConstants.schemaVersion,
        snapshots: [SnapshotRecord] = [],
        branches: [BranchRecord] = [],
        provisionalRewinds: [ProvisionalRewind] = []
    ) {
        self.schemaVersion = schemaVersion
        self.snapshots = snapshots
        self.branches = branches
        self.provisionalRewinds = provisionalRewinds
    }
}
