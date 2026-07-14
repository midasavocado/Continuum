import ContinuumCore
import ContinuumStore
import ContinuumSystem
import Foundation

@MainActor
enum AppBootstrap {
    static func makeModel() -> ContinuumModel {
        let repository: any SnapshotRepository
        do {
            repository = try EncryptedSnapshotStore(rootURL: snapshotStoreURL())
        } catch {
            repository = UnavailableSnapshotRepository(initializationError: error)
        }

        return ContinuumModel(
            repository: repository,
            inventory: MacAppInventoryService(),
            permissionProvider: MacPermissionService(),
            checkpointCapturer: HotProcessCheckpointService(
                usesInjectedSafepoints: true
            ),
            coldProcessRestorer: ColdProcessRestorer(),
            appSetupCoordinator: MacAppSetupCoordinator(
                rootDirectory: try? appSetupStoreURL(),
                bootstrapLibraryURL: Bundle.main.privateFrameworksURL?
                    .appendingPathComponent("libContinuumBootstrap.dylib")
            ),
            automaticallyPreparesCaptureTargets: true
        )
    }

    static func snapshotStoreURL() throws -> URL {
        let base = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        return base
            .appendingPathComponent("Continuum", isDirectory: true)
            .appendingPathComponent("SnapshotStore", isDirectory: true)
    }

    static func appSetupStoreURL() throws -> URL {
        let base = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        return base
            .appendingPathComponent("Continuum", isDirectory: true)
            .appendingPathComponent("AppSetups", isDirectory: true)
    }

}

private actor UnavailableSnapshotRepository: SnapshotRepository {
    private let initializationError: any Error

    init(initializationError: any Error) {
        self.initializationError = initializationError
    }

    func loadIndex() async throws -> StoreIndex { throw initializationError }
    func save(_ capture: SnapshotCapture) async throws -> SnapshotRecord { throw initializationError }
    func beginRewind(
        safetyCapture: SnapshotCapture,
        sourceBranchID: BranchID
    ) async throws -> ProvisionalRewind { throw initializationError }
    func commitRewind(
        _ provisionalID: ProvisionalRewindID,
        targetSnapshotID: SnapshotID
    ) async throws -> RewindCommit { throw initializationError }
    func cancelRewind(_ provisionalID: ProvisionalRewindID) async throws { throw initializationError }
    func renameSnapshot(_ snapshotID: SnapshotID, to name: String) async throws { throw initializationError }
    func updateNote(_ snapshotID: SnapshotID, note: String) async throws { throw initializationError }
    func deleteSnapshot(_ snapshotID: SnapshotID) async throws { throw initializationError }
    func deleteAllSnapshots() async throws { throw initializationError }
    func artifacts(for snapshotID: SnapshotID) async throws -> [CapturedArtifact] { throw initializationError }
    func switchBranch(to branchID: BranchID) async throws { throw initializationError }
}
