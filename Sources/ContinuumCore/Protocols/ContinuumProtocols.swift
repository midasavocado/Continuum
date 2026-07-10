import Foundation

public protocol SnapshotRepository: Sendable {
    func loadIndex() async throws -> StoreIndex
    func save(_ capture: SnapshotCapture) async throws -> SnapshotRecord
    func beginRewind(safetyCapture: SnapshotCapture, sourceBranchID: BranchID) async throws -> ProvisionalRewind
    func commitRewind(_ provisionalID: ProvisionalRewindID, targetSnapshotID: SnapshotID) async throws -> RewindCommit
    func cancelRewind(_ provisionalID: ProvisionalRewindID) async throws
    func renameSnapshot(_ snapshotID: SnapshotID, to name: String) async throws
    func updateNote(_ snapshotID: SnapshotID, note: String) async throws
    func deleteSnapshot(_ snapshotID: SnapshotID) async throws
    func deleteAllSnapshots() async throws
    func artifacts(for snapshotID: SnapshotID) async throws -> [CapturedArtifact]
    func switchBranch(to branchID: BranchID) async throws
}

public protocol AppInventoryProviding: Sendable {
    func runningApplications() async -> [ProcessDescriptor]
    func installedApplications() async -> [AppIdentity]
    func frontmostApplication() async -> ProcessDescriptor?
    func compatibility(for app: AppIdentity) async -> CompatibilityReport
}

public protocol AppSetupCoordinating: Sendable {
    func records() async throws -> [AppSetupRecord]
    func probe(_ app: AppIdentity) async throws -> AppSetupRecord
    func setup(_ app: AppIdentity) async throws -> AppSetupRecord
    func revalidate(_ setupID: AppSetupID) async throws -> AppSetupRecord
    func rollback(_ setupID: AppSetupID) async throws
    func recoverInterruptedSetups() async throws
}

public protocol PermissionProviding: Sendable {
    func statuses() async -> [PermissionStatus]
    func request(_ permission: PermissionKind) async -> PermissionStatus
    func openSystemSettings(for permission: PermissionKind) async
}

public protocol CheckpointCapturing: Sendable {
    func capture(app: AppIdentity, processIdentifiers: [Int32], kind: SnapshotKind, branchID: BranchID) async throws -> SnapshotCapture
    func restore(snapshot: SnapshotRecord, artifacts: [CapturedArtifact]) async -> RestoreResult
}
