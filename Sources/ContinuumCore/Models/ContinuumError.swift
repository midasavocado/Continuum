import Foundation

public enum ContinuumError: Error, LocalizedError, Equatable, Sendable {
    case snapshotNotFound
    case branchNotFound
    case provisionalRewindNotFound
    case noFrontmostApplication
    case storageBudgetExceeded(requiredBytes: Int64, availableBytes: Int64)
    case integrityFailure(String)
    case restoreUnavailable(String)
    case permissionDenied(PermissionKind)
    case runtimeUnsupported(String)
    case transactionInProgress
    case cancelled

    public var errorDescription: String? {
        switch self {
        case .snapshotNotFound:
            "That snapshot no longer exists."
        case .branchNotFound:
            "That timeline branch no longer exists."
        case .provisionalRewindNotFound:
            "The rewind safety snapshot could not be found."
        case .noFrontmostApplication:
            "Open the app you want to snapshot, then try again."
        case let .storageBudgetExceeded(requiredBytes, availableBytes):
            "Continuum needs \(requiredBytes.formatted(.byteCount(style: .file))) but only \(availableBytes.formatted(.byteCount(style: .file))) is available in its storage budget."
        case let .integrityFailure(detail):
            "Snapshot integrity check failed: \(detail)"
        case let .restoreUnavailable(detail):
            "This snapshot cannot be restored: \(detail)"
        case let .permissionDenied(permission):
            "Continuum does not have \(permission.rawValue) permission."
        case let .runtimeUnsupported(detail):
            "This app cannot use the rewind runtime: \(detail)"
        case .transactionInProgress:
            "Another snapshot or rewind transaction is still finishing."
        case .cancelled:
            "The operation was cancelled."
        }
    }
}
