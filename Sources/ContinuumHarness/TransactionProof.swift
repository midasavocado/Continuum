import ContinuumCore
import ContinuumRuntime
import ContinuumStore
import ContinuumSystem
import CryptoKit
import Darwin
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
        let futureFileBytes = Data("continuum-future-local-file-state".utf8)
        try savedFileBytes.write(to: liveFileURL)
        let originalInode = try fileManager.attributesOfItem(
            atPath: liveFileURL.path
        )[.systemFileNumber] as? NSNumber
        let fileCheckpointStore = try APFSLocalFileCheckpointStore(
            rootURL: fileCheckpointRoot
        )
        let fileCheckpointID = UUID()
        _ = try await fileCheckpointStore.capture(
            snapshotID: fileCheckpointID,
            files: [liveFileURL]
        )
        try futureFileBytes.write(to: liveFileURL)
        let filePayloads = try fileCheckpointStore.payloadsCoherently(
            snapshotID: fileCheckpointID
        )
        try require(
            filePayloads.count == 1
                && filePayloads[0].entry.originalPath == liveFileURL.path
                && filePayloads[0].data == savedFileBytes,
            "the coherent APFS clone did not export its captured bytes"
        )

        let rollbackCheckpointID = UUID()
        _ = try await fileCheckpointStore.capture(
            snapshotID: rollbackCheckpointID,
            files: [liveFileURL]
        )
        let savedEntry = filePayloads[0].entry
        let replacementReport = try fileCheckpointStore.replaceCoherently([
            LocalFileReplacement(
                originalPath: savedEntry.originalPath,
                device: savedEntry.device,
                inode: savedEntry.inode,
                mode: savedEntry.mode,
                data: filePayloads[0].data
            )
        ])
        let inodeAfterReplacement = try fileManager.attributesOfItem(
            atPath: liveFileURL.path
        )[.systemFileNumber] as? NSNumber
        let replacedFileBytes = try Data(contentsOf: liveFileURL)
        try require(
            replacementReport.restoredFileCount == 1
                && replacementReport.restoredBytes == Int64(savedFileBytes.count)
                && replacedFileBytes == savedFileBytes
                && inodeAfterReplacement == originalInode,
            "saved file replacement did not preserve the live vnode"
        )

        let rollbackReport = try await fileCheckpointStore.restore(
            snapshotID: rollbackCheckpointID
        )
        let inodeAfterRollback = try fileManager.attributesOfItem(
            atPath: liveFileURL.path
        )[.systemFileNumber] as? NSNumber
        let rolledBackFileBytes = try Data(contentsOf: liveFileURL)
        try require(
            rollbackReport.restoredFileCount == 1
                && rollbackReport.restoredBytes == Int64(futureFileBytes.count)
                && rolledBackFileBytes == futureFileBytes
                && inodeAfterRollback == originalInode,
            "file safety rollback did not restore the abandoned current bytes"
        )

        try await verifyWriterConflictGate(
            liveFileURL: liveFileURL,
            rootURL: rootURL
        )

        let coldTransactionRoot = rootURL.appendingPathComponent(
            "cold-file-transactions",
            isDirectory: true
        )
        let coldTransactionID = UUID()
        let coldTransactionURL = coldTransactionRoot.appendingPathComponent(
            coldTransactionID.uuidString,
            isDirectory: true
        )
        let coldSafetyStore = try APFSLocalFileCheckpointStore(
            rootURL: coldTransactionURL
        )
        let coldSafetySnapshotID = UUID()
        _ = try await coldSafetyStore.capture(
            snapshotID: coldSafetySnapshotID,
            files: [liveFileURL]
        )
        _ = try coldSafetyStore.replaceCoherently([
            LocalFileReplacement(
                originalPath: savedEntry.originalPath,
                device: savedEntry.device,
                inode: savedEntry.inode,
                mode: savedEntry.mode,
                data: savedFileBytes
            )
        ])
        let coldJournal = ProofColdFileJournal(
            formatVersion: 1,
            transactionID: coldTransactionID,
            safetySnapshotID: coldSafetySnapshotID,
            replacementProcessIdentifier: Int32.max,
            state: "prepared",
            createdAt: Date(),
            entries: [
                ProofColdFileJournal.Entry(
                    originalPath: savedEntry.originalPath,
                    device: savedEntry.device,
                    inode: savedEntry.inode,
                    installedSHA256: SHA256.hash(data: savedFileBytes).map {
                        String(format: "%02x", $0)
                    }.joined()
                )
            ]
        )
        let journalEncoder = JSONEncoder()
        journalEncoder.dateEncodingStrategy = .iso8601
        try journalEncoder.encode(coldJournal).write(
            to: coldTransactionURL.appendingPathComponent(
                "ColdFileTransaction.json"
            ),
            options: .atomic
        )
        let coldRestorer = ColdProcessRestorer(
            fileSafetyRootURL: coldTransactionRoot
        )
        let recoveredTransactions = try await coldRestorer
            .recoverInterruptedFileTransactions()
        let recoveredFileBytes = try Data(contentsOf: liveFileURL)
        let remainingColdTransactions = try fileManager.contentsOfDirectory(
            at: coldTransactionRoot,
            includingPropertiesForKeys: nil
        )
        try require(
            recoveredTransactions == 1
                && recoveredFileBytes == futureFileBytes
                && remainingColdTransactions.isEmpty,
            "durable cold-file recovery did not restore and retire its journal"
        )
        let committedTransactionID = UUID()
        let committedTransactionURL = coldTransactionRoot.appendingPathComponent(
            committedTransactionID.uuidString,
            isDirectory: true
        )
        let committedStore = try APFSLocalFileCheckpointStore(
            rootURL: committedTransactionURL
        )
        let committedSnapshotID = UUID()
        _ = try await committedStore.capture(
            snapshotID: committedSnapshotID,
            files: [liveFileURL]
        )
        let committedJournal = ProofColdFileJournal(
            formatVersion: 1,
            transactionID: committedTransactionID,
            safetySnapshotID: committedSnapshotID,
            replacementProcessIdentifier: 0,
            state: "committed",
            createdAt: Date(),
            entries: [
                ProofColdFileJournal.Entry(
                    originalPath: savedEntry.originalPath,
                    device: savedEntry.device,
                    inode: savedEntry.inode,
                    installedSHA256: SHA256.hash(data: futureFileBytes).map {
                        String(format: "%02x", $0)
                    }.joined()
                )
            ]
        )
        try journalEncoder.encode(committedJournal).write(
            to: committedTransactionURL.appendingPathComponent(
                "ColdFileTransaction.json"
            ),
            options: .atomic
        )
        _ = try committedStore.replaceCoherently([
            LocalFileReplacement(
                originalPath: savedEntry.originalPath,
                device: savedEntry.device,
                inode: savedEntry.inode,
                mode: savedEntry.mode,
                data: savedFileBytes
            )
        ])

        let committedSnapshots = try await coldRestorer
            .committedFileSafetySnapshots()
        try require(
            committedSnapshots.count == 1
                && committedSnapshots[0].id == committedTransactionID
                && committedSnapshots[0].fileCount == 1
                && committedSnapshots[0].logicalBytes == UInt64(futureFileBytes.count),
            "committed cold-file safety snapshot was not catalogued"
        )
        let committedRestore = try await coldRestorer
            .restoreCommittedFileSafetySnapshot(committedTransactionID)
        let bytesAfterCommittedRestore = try Data(contentsOf: liveFileURL)
        try require(
            bytesAfterCommittedRestore == futureFileBytes
                && committedRestore.restoredSnapshotID == committedTransactionID
                && committedRestore.reciprocalSafetySnapshotID != committedTransactionID
                && committedRestore.restoredFileCount == 1
                && committedRestore.restoredBytes == UInt64(futureFileBytes.count),
            "committed cold-file safety snapshot did not restore exact bytes"
        )
        let snapshotsAfterRestore = try await coldRestorer
            .committedFileSafetySnapshots()
        let snapshotIDsAfterRestore = Set(snapshotsAfterRestore.map(\.id))
        try require(
            snapshotsAfterRestore.count == 2
                && snapshotIDsAfterRestore == Set([
                    committedTransactionID,
                    committedRestore.reciprocalSafetySnapshotID
                ]),
            "committed restore did not preserve the state being abandoned"
        )
        let interruptedRestoreID = UUID()
        let interruptedRestoreURL = coldTransactionRoot.appendingPathComponent(
            interruptedRestoreID.uuidString,
            isDirectory: true
        )
        let interruptedRestoreStore = try APFSLocalFileCheckpointStore(
            rootURL: interruptedRestoreURL
        )
        let interruptedRestoreSnapshotID = UUID()
        _ = try await interruptedRestoreStore.capture(
            snapshotID: interruptedRestoreSnapshotID,
            files: [liveFileURL]
        )
        let interruptedRestoreJournal = ProofColdFileJournal(
            formatVersion: 1,
            transactionID: interruptedRestoreID,
            safetySnapshotID: interruptedRestoreSnapshotID,
            replacementProcessIdentifier: 0,
            state: "restoringCommitted",
            createdAt: Date(),
            entries: [
                ProofColdFileJournal.Entry(
                    originalPath: savedEntry.originalPath,
                    device: savedEntry.device,
                    inode: savedEntry.inode,
                    installedSHA256: SHA256.hash(data: futureFileBytes).map {
                        String(format: "%02x", $0)
                    }.joined()
                )
            ]
        )
        try journalEncoder.encode(interruptedRestoreJournal).write(
            to: interruptedRestoreURL.appendingPathComponent(
                "ColdFileTransaction.json"
            ),
            options: .atomic
        )
        _ = try interruptedRestoreStore.replaceCoherently([
            LocalFileReplacement(
                originalPath: savedEntry.originalPath,
                device: savedEntry.device,
                inode: savedEntry.inode,
                mode: savedEntry.mode,
                data: savedFileBytes
            )
        ])
        let recoveredInterruptedRestore = try await coldRestorer
            .recoverInterruptedFileTransactions()
        let bytesAfterInterruptedRecovery = try Data(contentsOf: liveFileURL)
        try require(
            recoveredInterruptedRestore == 1
                && bytesAfterInterruptedRecovery == futureFileBytes
                && !fileManager.fileExists(atPath: interruptedRestoreURL.path),
            "interrupted committed restore did not recover its reciprocal bytes"
        )

        try await coldRestorer.deleteCommittedFileSafetySnapshot(
            committedTransactionID
        )
        try await coldRestorer.deleteCommittedFileSafetySnapshot(
            committedRestore.reciprocalSafetySnapshotID
        )
        let snapshotsAfterDeletion = try await coldRestorer
            .committedFileSafetySnapshots()
        try require(
            snapshotsAfterDeletion.isEmpty,
            "deleted cold-file safety snapshots remained in the catalog"
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
        print("  file rollback:         saved -> current on one preserved vnode")
        print("  crash recovery:        durable journal restored + retired")
        print("  committed safety:      list -> reciprocal restore -> delete")
        print("  writer conflict:       external writable vnode rejected by PID")
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

    private static func verifyWriterConflictGate(
        liveFileURL: URL,
        rootURL: URL
    ) async throws {
        let readyURL = rootURL.appendingPathComponent("writer-ready")
        let writer = Process()
        writer.executableURL = URL(fileURLWithPath: "/bin/sh")
        writer.arguments = [
            "-c",
            "exec 9>>\"$1\"; : > \"$2\"; exec sleep 30",
            "continuum-writer-proof",
            liveFileURL.path,
            readyURL.path
        ]
        try writer.run()
        defer {
            if writer.isRunning {
                writer.terminate()
                writer.waitUntilExit()
            }
            try? FileManager.default.removeItem(at: readyURL)
        }

        for _ in 0..<200 {
            if FileManager.default.fileExists(atPath: readyURL.path) {
                break
            }
            usleep(10_000)
        }
        try require(
            FileManager.default.fileExists(atPath: readyURL.path),
            "writer-conflict proof process did not become ready"
        )
        var conflictingProcessIdentifier: Int32 = 0
        let conflictStatus = liveFileURL.path.withCString {
            continuum_find_writable_vnode_conflict(
                $0,
                0,
                &conflictingProcessIdentifier
            )
        }
        try require(
            conflictStatus == CONTINUUM_STATUS_FILE_WRITER_CONFLICT
                && conflictingProcessIdentifier == writer.processIdentifier,
            "writer-conflict gate did not identify the external vnode writer"
        )

        writer.terminate()
        writer.waitUntilExit()
        var staleConflict: Int32 = 0
        let clearStatus = liveFileURL.path.withCString {
            continuum_find_writable_vnode_conflict(
                $0,
                0,
                &staleConflict
            )
        }
        try require(
            clearStatus == CONTINUUM_STATUS_OK && staleConflict == 0,
            "writer-conflict gate remained blocked after the writer exited"
        )
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

private struct ProofColdFileJournal: Codable {
    struct Entry: Codable {
        let originalPath: String
        let device: UInt64
        let inode: UInt64
        let installedSHA256: String
    }

    let formatVersion: Int
    let transactionID: UUID
    let safetySnapshotID: UUID
    let replacementProcessIdentifier: Int32
    let state: String
    let createdAt: Date
    let entries: [Entry]
}
