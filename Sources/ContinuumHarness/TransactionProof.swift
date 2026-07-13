import ContinuumCore
import ContinuumStore
import Foundation

enum TransactionProof {
    static func run() async throws {
        let fileManager = FileManager.default
        let rootURL = fileManager.temporaryDirectory
            .appendingPathComponent("continuum-transaction-proof-\(UUID().uuidString)", isDirectory: true)
        try fileManager.createDirectory(at: rootURL, withIntermediateDirectories: true)
        defer { try? fileManager.removeItem(at: rootURL) }

        let store = try EncryptedSnapshotStore(
            rootURL: rootURL,
            encryptionKey: Data(repeating: 0x42, count: 32)
        )
        let sourceBranchID = UUID()
        let manualPayload = Data("continuum-harness-manual-plaintext-proof".utf8)
        let safetyPayload = Data("continuum-harness-abandoned-future-proof".utf8)

        let targetCapture = ProofFixtures.capture(
            name: "Manual proof snapshot",
            kind: .manual,
            branchID: sourceBranchID,
            payload: manualPayload,
            monotonicNanoseconds: 1
        )
        let targetSnapshot = try await store.save(targetCapture)

        let safetyCapture = ProofFixtures.capture(
            name: "Before Rewind — Continuum Harness",
            kind: .beforeRewind,
            branchID: sourceBranchID,
            payload: safetyPayload,
            monotonicNanoseconds: 2
        )
        let provisional = try await store.beginRewind(
            safetyCapture: safetyCapture,
            sourceBranchID: sourceBranchID
        )
        let commit = try await store.commitRewind(
            provisional.id,
            targetSnapshotID: targetSnapshot.id
        )

        try require(commit.targetSnapshotID == targetSnapshot.id, "commit points at the wrong rewind target")
        try require(commit.safetySnapshotID == provisional.safetySnapshotID, "commit lost its safety snapshot")
        try require(commit.activeBranchID != commit.abandonedFutureBranchID, "active and abandoned branches are identical")

        let index = try await store.loadIndex()
        try verifyIndex(index, provisional: provisional, commit: commit)

        let restoredTargetArtifacts = try await store.artifacts(for: targetSnapshot.id)
        try require(
            restoredTargetArtifacts == targetCapture.artifacts,
            "manual snapshot artifacts did not decrypt to the original bytes"
        )
        let restoredSafetyArtifacts = try await store.artifacts(for: provisional.safetySnapshotID)
        try require(
            restoredSafetyArtifacts == safetyCapture.artifacts,
            "safety snapshot artifacts did not decrypt to the abandoned-future bytes"
        )

        let liveFileURL = rootURL.appendingPathComponent("app-local-state.bin")
        let fileCheckpointRoot = rootURL.appendingPathComponent(
            "file-checkpoints",
            isDirectory: true
        )
        let savedFileBytes = Data("continuum-saved-local-file-state".utf8)
        try savedFileBytes.write(to: liveFileURL)
        let fileCheckpointStore = try APFSLocalFileCheckpointStore(
            rootURL: fileCheckpointRoot
        )
        let fileCheckpointID = UUID()
        _ = try await fileCheckpointStore.capture(
            snapshotID: fileCheckpointID,
            files: [liveFileURL]
        )
        try Data("continuum-future-local-file-state".utf8).write(to: liveFileURL)
        let filePayloads = try fileCheckpointStore.payloadsCoherently(
            snapshotID: fileCheckpointID
        )
        try require(
            filePayloads.count == 1
                && filePayloads[0].entry.originalPath == liveFileURL.path
                && filePayloads[0].data == savedFileBytes,
            "the coherent APFS clone did not export its captured bytes"
        )
        try fileManager.removeItem(at: fileCheckpointRoot)
        try fileManager.removeItem(at: liveFileURL)

        let persistedFiles = try regularFiles(beneath: rootURL, fileManager: fileManager)
        try require(!persistedFiles.isEmpty, "store committed no durable files")
        for fileURL in persistedFiles {
            let bytes = try Data(contentsOf: fileURL, options: [.mappedIfSafe])
            try require(bytes.range(of: manualPayload) == nil, "manual artifact appears in plaintext at \(fileURL.path)")
            try require(bytes.range(of: safetyPayload) == nil, "safety artifact appears in plaintext at \(fileURL.path)")
        }

        print("transaction-proof: PASS")
        print("  target snapshot:       \(targetSnapshot.id.uuidString)")
        print("  safety snapshot:       \(provisional.safetySnapshotID.uuidString)")
        print("  active branch:         \(commit.activeBranchID.uuidString)")
        print("  abandoned future:      \(commit.abandonedFutureBranchID.uuidString)")
        print("  encrypted store files: \(persistedFiles.count)")
        print("  coherent file bytes:  APFS clone exported after live mutation")
    }

    private static func verifyIndex(
        _ index: StoreIndex,
        provisional: ProvisionalRewind,
        commit: RewindCommit
    ) throws {
        try require(
            index.provisionalRewinds.allSatisfy { $0.id != provisional.id },
            "committed provisional rewind still exists"
        )
        try require(
            index.snapshots.contains { $0.id == commit.targetSnapshotID },
            "manual target snapshot is missing"
        )
        guard let safetySnapshot = index.snapshots.first(where: { $0.id == commit.safetySnapshotID }) else {
            throw HarnessFailure.invariant("promoted safety snapshot is missing")
        }
        try require(safetySnapshot.kind == .beforeRewind, "safety snapshot has the wrong kind")
        try require(safetySnapshot.isPinned, "safety snapshot was not retained")

        guard let abandonedFuture = index.branches.first(where: { $0.id == commit.abandonedFutureBranchID }) else {
            throw HarnessFailure.invariant("abandoned-future branch is missing")
        }
        try require(abandonedFuture.rootSnapshotID == commit.safetySnapshotID, "abandoned branch has the wrong root")
        try require(abandonedFuture.tipSnapshotID == commit.safetySnapshotID, "abandoned branch has the wrong tip")
        try require(!abandonedFuture.isActive, "abandoned branch is still active")

        guard let activeBranch = index.branches.first(where: { $0.id == commit.activeBranchID }) else {
            throw HarnessFailure.invariant("new active branch is missing")
        }
        try require(activeBranch.rootSnapshotID == commit.targetSnapshotID, "active branch has the wrong root")
        try require(activeBranch.tipSnapshotID == commit.targetSnapshotID, "active branch has the wrong tip")
        try require(activeBranch.isActive, "new branch was not activated")
        try require(index.branches.filter(\.isActive).count == 1, "store has more than one active branch")
    }

    private static func regularFiles(
        beneath rootURL: URL,
        fileManager: FileManager
    ) throws -> [URL] {
        guard let enumerator = fileManager.enumerator(
            at: rootURL,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else {
            return []
        }

        var files: [URL] = []
        for case let fileURL as URL in enumerator {
            let values = try fileURL.resourceValues(forKeys: [.isRegularFileKey])
            if values.isRegularFile == true {
                files.append(fileURL)
            }
        }
        return files
    }

    private static func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        guard condition() else { throw HarnessFailure.invariant(message) }
    }
}
