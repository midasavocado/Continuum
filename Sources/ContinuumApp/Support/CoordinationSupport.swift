import Foundation
import ContinuumCore

enum CoordinationError: LocalizedError, Sendable {
    case noActiveBranch
    case noSnapshotSelected
    case snapshotNameEmpty
    case appNotRunning(String)
    case rewindAlreadyActive
    case rewindNotActive
    case safetySnapshotMissing
    case cancellationValidationFailed(String)
    case snapshotUsedByActiveRewind

    var errorDescription: String? {
        switch self {
        case .noActiveBranch:
            "Continuum could not find an active timeline branch. Refresh and try again."
        case .noSnapshotSelected:
            "Choose a snapshot to rewind to first."
        case .snapshotNameEmpty:
            "A snapshot name cannot be empty."
        case let .appNotRunning(name):
            "Open \(name) before rewinding this snapshot."
        case .rewindAlreadyActive:
            "Finish or cancel the current rewind before starting another one."
        case .rewindNotActive:
            "There is no rewind waiting to be completed."
        case .safetySnapshotMissing:
            "Continuum cannot find the safety snapshot for this rewind. The rewind was left untouched."
        case let .cancellationValidationFailed(detail):
            "Continuum could not validate the state from before rewind, so it kept the safety snapshot. \(detail)"
        case .snapshotUsedByActiveRewind:
            "That snapshot is protecting the active rewind and cannot be deleted yet."
        }
    }
}

enum ErrorPresentation {
    static func message(for error: any Error) -> String {
        if let localized = error as? any LocalizedError,
           let description = localized.errorDescription,
           !description.isEmpty {
            return description
        }

        let description = error.localizedDescription
        return description.isEmpty ? "Continuum hit an unexpected problem." : description
    }
}

enum SnapshotCaptureNaming {
    static func applyingAutomaticName(to capture: SnapshotCapture) -> SnapshotCapture {
        var snapshot = capture.snapshot
        snapshot.name = SnapshotNaming.automaticName(
            appName: snapshot.app.displayName,
            date: snapshot.createdAt,
            kind: snapshot.kind
        )
        return SnapshotCapture(snapshot: snapshot, artifacts: capture.artifacts)
    }
}
