import Foundation
import Security

public enum SnapshotStoreError: Error, Equatable, LocalizedError, Sendable {
    case invalidKeyLength
    case keychain(OSStatus)
    case unsupportedSchema(Int)
    case snapshotNotFound(UUID)
    case branchNotFound(UUID)
    case provisionalRewindNotFound(UUID)
    case duplicateSnapshot(UUID)
    case invalidSafetySnapshot
    case invalidSnapshotName
    case snapshotIsReferenced(UUID)
    case rewindInProgress
    case corruptData(String)
    case integrityFailure(String)
    case decryptionFailed
    case injectedFailure(String)

    public var errorDescription: String? {
        switch self {
        case .invalidKeyLength:
            "Snapshot encryption keys must contain exactly 32 bytes."
        case let .keychain(status):
            "The snapshot encryption key could not be accessed (Keychain status \(status))."
        case let .unsupportedSchema(version):
            "Snapshot store schema \(version) is not supported."
        case let .snapshotNotFound(id):
            "Snapshot \(id) was not found."
        case let .branchNotFound(id):
            "Branch \(id) was not found."
        case let .provisionalRewindNotFound(id):
            "Rewind transaction \(id) was not found."
        case let .duplicateSnapshot(id):
            "Snapshot \(id) already exists and cannot be overwritten."
        case .invalidSafetySnapshot:
            "A rewind safety capture must be a pinned Before Rewind snapshot on the source branch."
        case .invalidSnapshotName:
            "Snapshot names cannot be empty."
        case let .snapshotIsReferenced(id):
            "Snapshot \(id) is still referenced by a branch or rewind transaction."
        case .rewindInProgress:
            "Snapshot data cannot be deleted while a rewind is in progress."
        case let .corruptData(detail):
            "Snapshot data is corrupt: \(detail)"
        case let .integrityFailure(detail):
            "Snapshot integrity verification failed: \(detail)"
        case .decryptionFailed:
            "Snapshot data could not be decrypted with this store key."
        case let .injectedFailure(point):
            "A test failure was injected at \(point)."
        }
    }
}
