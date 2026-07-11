import Foundation

public enum SnapshotKind: String, Codable, CaseIterable, Sendable {
    case manual
    case beforeRewind
    case crashRecovery
    case automatic

    public var displayName: String {
        switch self {
        case .manual: "Manual"
        case .beforeRewind: "Before Rewind"
        case .crashRecovery: "Crash Recovery"
        case .automatic: "Automatic"
        }
    }
}

public enum RestoreAvailability: String, Codable, CaseIterable, Sendable {
    case instant
    case experimentalHot
    case replayRequired
    case unavailable

    public var displayName: String {
        switch self {
        case .instant: "Instant"
        case .experimentalHot: "Experimental Hot"
        case .replayRequired: "Replay required"
        case .unavailable: "Unavailable"
        }
    }
}

public enum LocalFileCoverage: String, Codable, CaseIterable, Sendable {
    case exact
    case unchanged
    case unavailable

    public var displayName: String {
        switch self {
        case .exact: "Rewind with app"
        case .unchanged: "No local changes"
        case .unavailable: "Not captured"
        }
    }
}

public enum LocalFileRestorePolicy: String, Codable, CaseIterable, Sendable {
    case rewindCapturedFiles
    case keepCurrentFiles

    public var displayName: String {
        switch self {
        case .rewindCapturedFiles: "App + Local Files"
        case .keepCurrentFiles: "App Only — Keep Current Files"
        }
    }
}

public enum CheckpointValidation: String, Codable, Sendable {
    case provisional
    case validating
    case valid
    case invalid
}

public enum CapturedArtifactKind: String, Codable, Sendable {
    case memoryPage
    case threadState
    case fileBlock
    case descriptorState
    case graphicsState
    case inputEvent
    case nondeterminismEvent
    case metadata
}

public struct CapturedArtifact: Codable, Hashable, Sendable {
    public let kind: CapturedArtifactKind
    public let logicalName: String
    public let data: Data

    public init(kind: CapturedArtifactKind, logicalName: String, data: Data) {
        self.kind = kind
        self.logicalName = logicalName
        self.data = data
    }
}

public struct CheckpointRecord: Codable, Hashable, Identifiable, Sendable {
    public let id: CheckpointID
    public let capturedAt: Date
    public let monotonicNanoseconds: UInt64
    public let processIdentifiers: [Int32]
    public let memoryRegionCount: Int
    public let threadCount: Int
    public var validation: CheckpointValidation

    public init(
        id: CheckpointID = UUID(),
        capturedAt: Date = .now,
        monotonicNanoseconds: UInt64,
        processIdentifiers: [Int32],
        memoryRegionCount: Int,
        threadCount: Int,
        validation: CheckpointValidation
    ) {
        self.id = id
        self.capturedAt = capturedAt
        self.monotonicNanoseconds = monotonicNanoseconds
        self.processIdentifiers = processIdentifiers
        self.memoryRegionCount = memoryRegionCount
        self.threadCount = threadCount
        self.validation = validation
    }
}

public struct SnapshotRecord: Codable, Hashable, Identifiable, Sendable {
    public let id: SnapshotID
    public var name: String
    public var note: String
    public let kind: SnapshotKind
    public let app: AppIdentity
    public let checkpoint: CheckpointRecord
    public let branchID: BranchID
    public let createdAt: Date
    public var availability: RestoreAvailability
    public var chunkHashes: [String]
    public var logicalBytes: Int64
    public var uniqueBytes: Int64
    /// Live RAM retained by an in-process hot backend. Nil/zero means the
    /// snapshot has no separately retained hot image.
    public var hotMemoryBytes: Int64?
    public var isPinned: Bool
    public var externalEffects: [ExternalEffect]
    /// Nil decodes old store records as unavailable without a schema-breaking
    /// migration. New exact snapshots set this explicitly.
    public var localFileCoverage: LocalFileCoverage?
    public var allowsKeepingCurrentFiles: Bool?

    public init(
        id: SnapshotID = UUID(),
        name: String,
        note: String = "",
        kind: SnapshotKind,
        app: AppIdentity,
        checkpoint: CheckpointRecord,
        branchID: BranchID,
        createdAt: Date = .now,
        availability: RestoreAvailability,
        chunkHashes: [String] = [],
        logicalBytes: Int64 = 0,
        uniqueBytes: Int64 = 0,
        hotMemoryBytes: Int64? = nil,
        isPinned: Bool = true,
        externalEffects: [ExternalEffect] = [],
        localFileCoverage: LocalFileCoverage? = .unavailable,
        allowsKeepingCurrentFiles: Bool? = false
    ) {
        self.id = id
        self.name = name
        self.note = note
        self.kind = kind
        self.app = app
        self.checkpoint = checkpoint
        self.branchID = branchID
        self.createdAt = createdAt
        self.availability = availability
        self.chunkHashes = chunkHashes
        self.logicalBytes = logicalBytes
        self.uniqueBytes = uniqueBytes
        self.hotMemoryBytes = hotMemoryBytes
        self.isPinned = isPinned
        self.externalEffects = externalEffects
        self.localFileCoverage = localFileCoverage
        self.allowsKeepingCurrentFiles = allowsKeepingCurrentFiles
    }

    public var effectiveLocalFileCoverage: LocalFileCoverage {
        localFileCoverage ?? .unavailable
    }

    public var isKeepingCurrentFilesCertified: Bool {
        allowsKeepingCurrentFiles ?? false
    }
}

public struct SnapshotCapture: Sendable {
    public let snapshot: SnapshotRecord
    public let artifacts: [CapturedArtifact]

    public init(snapshot: SnapshotRecord, artifacts: [CapturedArtifact]) {
        self.snapshot = snapshot
        self.artifacts = artifacts
    }
}
