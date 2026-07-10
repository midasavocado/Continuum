import ContinuumCore
@testable import ContinuumStore
import Foundation
import XCTest

final class EncryptedSnapshotStoreTests: XCTestCase {
    private let key = Data(repeating: 0x42, count: 32)

    func testContentAddressedChunksDeduplicateAndRoundTripArtifactMetadata() async throws {
        try await withTemporaryDirectory { root in
            let store = try EncryptedSnapshotStore(rootURL: root, encryptionKey: key)
            let branchID = UUID()
            let shared = Data(repeating: 0xAB, count: 32_768)
            let firstCapture = makeCapture(
                branchID: branchID,
                artifacts: [
                    CapturedArtifact(kind: .memoryPage, logicalName: "page-1", data: shared),
                    CapturedArtifact(kind: .threadState, logicalName: "thread-1", data: Data("thread".utf8))
                ]
            )
            let secondCapture = makeCapture(
                branchID: branchID,
                artifacts: [
                    CapturedArtifact(kind: .fileBlock, logicalName: "different-name", data: shared)
                ]
            )

            let first = try await store.save(firstCapture)
            let second = try await store.save(secondCapture)

            XCTAssertEqual(first.logicalBytes, Int64(shared.count + 6))
            XCTAssertEqual(second.logicalBytes, Int64(shared.count))
            XCTAssertEqual(second.uniqueBytes, 0)
            XCTAssertEqual(first.chunkHashes.first, second.chunkHashes.first)
            XCTAssertEqual(try chunkFiles(at: root).count, 2)

            let loaded = try await store.artifacts(for: second.id)
            XCTAssertEqual(loaded.count, 1)
            XCTAssertEqual(loaded[0].kind, .fileBlock)
            XCTAssertEqual(loaded[0].logicalName, "different-name")
            XCTAssertEqual(loaded[0].data, shared)
        }
    }

    func testEncryptedStoreRoundTripsAfterReopenWithoutPlaintextLeakage() async throws {
        try await withTemporaryDirectory { root in
            let secret = Data("continuum-super-secret-payload".utf8)
            let capture = makeCapture(
                branchID: UUID(),
                artifacts: [CapturedArtifact(kind: .metadata, logicalName: "secret", data: secret)]
            )
            let snapshotID: SnapshotID
            do {
                let store = try EncryptedSnapshotStore(rootURL: root, encryptionKey: key)
                snapshotID = try await store.save(capture).id
            }

            for file in try allRegularFiles(at: root) {
                let bytes = try Data(contentsOf: file)
                XCTAssertNil(bytes.range(of: secret), "Plaintext leaked into \(file.lastPathComponent)")
            }

            let reopened = try EncryptedSnapshotStore(rootURL: root, encryptionKey: key)
            let loaded = try await reopened.artifacts(for: snapshotID)
            XCTAssertEqual(loaded, capture.artifacts)
        }
    }

    func testFailedSaveNeverPublishesPartialSnapshotOrLeavesArtifacts() async throws {
        try await withTemporaryDirectory { root in
            let provider = FixedSnapshotStoreKeyProvider(keyData: key)
            let store = try EncryptedSnapshotStore(
                rootURL: root,
                keyProvider: provider,
                failureInjector: { $0 == .beforeCommittingIndex }
            )
            let capture = makeCapture(
                branchID: UUID(),
                artifacts: [CapturedArtifact(kind: .memoryPage, logicalName: "page", data: Data(repeating: 7, count: 8_192))]
            )

            do {
                _ = try await store.save(capture)
                XCTFail("Expected the injected commit failure")
            } catch let error as SnapshotStoreError {
                XCTAssertEqual(error, .injectedFailure(StoreFailurePoint.beforeCommittingIndex.rawValue))
            }

            let indexAfterFailure = try await store.loadIndex()
            XCTAssertTrue(indexAfterFailure.snapshots.isEmpty)
            XCTAssertTrue(try chunkFiles(at: root).isEmpty)
            XCTAssertTrue(try manifestFiles(at: root).isEmpty)

            let reopened = try EncryptedSnapshotStore(rootURL: root, encryptionKey: key)
            let reopenedIndex = try await reopened.loadIndex()
            XCTAssertTrue(reopenedIndex.snapshots.isEmpty)
        }
    }

    func testManualSnapshotIsPinnedImmutableAndRetainedAcrossReopen() async throws {
        try await withTemporaryDirectory { root in
            let snapshotID = UUID()
            let branchID = UUID()
            let capture = makeCapture(
                id: snapshotID,
                branchID: branchID,
                kind: .manual,
                isPinned: false,
                artifacts: [CapturedArtifact(kind: .metadata, logicalName: "state", data: Data("original".utf8))]
            )
            let store = try EncryptedSnapshotStore(rootURL: root, encryptionKey: key)
            let saved = try await store.save(capture)
            XCTAssertTrue(saved.isPinned)

            let overwrite = makeCapture(
                id: snapshotID,
                branchID: branchID,
                kind: .manual,
                artifacts: [CapturedArtifact(kind: .metadata, logicalName: "state", data: Data("replacement".utf8))]
            )
            do {
                _ = try await store.save(overwrite)
                XCTFail("Immutable snapshot IDs must not be overwritten")
            } catch let error as SnapshotStoreError {
                XCTAssertEqual(error, .duplicateSnapshot(snapshotID))
            }

            let reopened = try EncryptedSnapshotStore(rootURL: root, encryptionKey: key)
            let reopenedIndex = try await reopened.loadIndex()
            let persisted = try XCTUnwrap(reopenedIndex.snapshots.first { $0.id == snapshotID })
            XCTAssertTrue(persisted.isPinned)
            let reopenedArtifacts = try await reopened.artifacts(for: snapshotID)
            XCTAssertEqual(reopenedArtifacts, capture.artifacts)
        }
    }

    func testBeginAndCancelRewindAtomicallyRemovesProvisionalSafetySnapshot() async throws {
        try await withTemporaryDirectory { root in
            let store = try EncryptedSnapshotStore(rootURL: root, encryptionKey: key)
            let branchID = UUID()
            _ = try await store.save(makeCapture(branchID: branchID))
            let safety = makeCapture(
                branchID: branchID,
                kind: .beforeRewind,
                isPinned: false,
                artifacts: [CapturedArtifact(kind: .memoryPage, logicalName: "safety", data: Data("future".utf8))]
            )

            let provisional = try await store.beginRewind(safetyCapture: safety, sourceBranchID: branchID)
            var index = try await store.loadIndex()
            XCTAssertEqual(index.provisionalRewinds, [provisional])
            XCTAssertTrue(index.snapshots.contains { $0.id == safety.snapshot.id && $0.isPinned })

            do {
                try await store.deleteSnapshot(safety.snapshot.id)
                XCTFail("A provisional safety snapshot must remain protected")
            } catch let error as SnapshotStoreError {
                XCTAssertEqual(error, .snapshotIsReferenced(safety.snapshot.id))
            }

            try await store.cancelRewind(provisional.id)
            index = try await store.loadIndex()
            XCTAssertTrue(index.provisionalRewinds.isEmpty)
            XCTAssertFalse(index.snapshots.contains { $0.id == safety.snapshot.id })
            XCTAssertFalse(try manifestFiles(at: root).contains { $0.lastPathComponent.contains(safety.snapshot.id.uuidString.lowercased()) })

            do {
                _ = try await store.artifacts(for: safety.snapshot.id)
                XCTFail("Cancelled safety snapshot should no longer be visible")
            } catch let error as SnapshotStoreError {
                XCTAssertEqual(error, .snapshotNotFound(safety.snapshot.id))
            }
        }
    }

    func testCommitRewindCreatesAbandonedFutureAndNewActiveBranch() async throws {
        try await withTemporaryDirectory { root in
            let store = try EncryptedSnapshotStore(rootURL: root, encryptionKey: key)
            let sourceBranchID = UUID()
            let target = try await store.save(makeCapture(branchID: sourceBranchID, name: "Target"))
            let safetyCapture = makeCapture(
                branchID: sourceBranchID,
                kind: .beforeRewind,
                name: "Before Rewind",
                artifacts: [CapturedArtifact(kind: .memoryPage, logicalName: "future", data: Data("future".utf8))]
            )
            let provisional = try await store.beginRewind(
                safetyCapture: safetyCapture,
                sourceBranchID: sourceBranchID
            )

            let commit = try await store.commitRewind(provisional.id, targetSnapshotID: target.id)
            let index = try await store.loadIndex()
            XCTAssertTrue(index.provisionalRewinds.isEmpty)
            XCTAssertEqual(index.branches.filter(\.isActive).map(\.id), [commit.activeBranchID])

            let abandoned = try XCTUnwrap(index.branches.first { $0.id == commit.abandonedFutureBranchID })
            XCTAssertEqual(abandoned.parentBranchID, sourceBranchID)
            XCTAssertEqual(abandoned.rootSnapshotID, safetyCapture.snapshot.id)
            XCTAssertEqual(abandoned.tipSnapshotID, safetyCapture.snapshot.id)

            let active = try XCTUnwrap(index.branches.first { $0.id == commit.activeBranchID })
            XCTAssertEqual(active.parentBranchID, target.branchID)
            XCTAssertEqual(active.rootSnapshotID, target.id)
            XCTAssertEqual(active.tipSnapshotID, target.id)
            let safetyArtifacts = try await store.artifacts(for: safetyCapture.snapshot.id)
            XCTAssertEqual(safetyArtifacts, safetyCapture.artifacts)
        }
    }

    func testRenameNoteDeleteAndReferenceAwareGarbageCollection() async throws {
        try await withTemporaryDirectory { root in
            let store = try EncryptedSnapshotStore(rootURL: root, encryptionKey: key)
            let branchID = UUID()
            let shared = Data("shared".utf8)
            let rootSnapshot = try await store.save(makeCapture(
                branchID: branchID,
                artifacts: [CapturedArtifact(kind: .memoryPage, logicalName: "shared", data: shared)]
            ))
            let deletable = try await store.save(makeCapture(
                branchID: branchID,
                artifacts: [
                    CapturedArtifact(kind: .memoryPage, logicalName: "shared", data: shared),
                    CapturedArtifact(kind: .fileBlock, logicalName: "delete-me", data: Data("only-second".utf8))
                ]
            ))
            _ = try await store.save(makeCapture(
                branchID: branchID,
                artifacts: [
                    CapturedArtifact(kind: .memoryPage, logicalName: "shared", data: shared),
                    CapturedArtifact(kind: .fileBlock, logicalName: "tip", data: Data("only-third".utf8))
                ]
            ))
            XCTAssertEqual(try chunkFiles(at: root).count, 3)

            try await store.renameSnapshot(deletable.id, to: "  Renamed  ")
            try await store.updateNote(deletable.id, note: "A useful note")
            let indexAfterMetadataUpdate = try await store.loadIndex()
            let updated = try XCTUnwrap(indexAfterMetadataUpdate.snapshots.first { $0.id == deletable.id })
            XCTAssertEqual(updated.name, "Renamed")
            XCTAssertEqual(updated.note, "A useful note")

            try await store.deleteSnapshot(deletable.id)
            let indexAfterDelete = try await store.loadIndex()
            XCTAssertFalse(indexAfterDelete.snapshots.contains { $0.id == deletable.id })
            XCTAssertEqual(try chunkFiles(at: root).count, 2)
            let rootArtifacts = try await store.artifacts(for: rootSnapshot.id)
            XCTAssertEqual(rootArtifacts.first?.data, shared)

            do {
                try await store.deleteSnapshot(rootSnapshot.id)
                XCTFail("A branch root must not be deleted")
            } catch let error as SnapshotStoreError {
                XCTAssertEqual(error, .snapshotIsReferenced(rootSnapshot.id))
            }
        }
    }

    func testDeletingOnlySnapshotRemovesEmptyMainAndNextSaveRecreatesIt() async throws {
        try await withTemporaryDirectory { root in
            let store = try EncryptedSnapshotStore(rootURL: root, encryptionKey: key)
            let firstBranchID = UUID()
            let first = try await store.save(makeCapture(
                branchID: firstBranchID,
                kind: .manual,
                artifacts: [
                    CapturedArtifact(
                        kind: .memoryPage,
                        logicalName: "first",
                        data: Data("first-state".utf8)
                    )
                ]
            ))

            let initialIndex = try await store.loadIndex()
            let initialMain = try XCTUnwrap(initialIndex.branches.only)
            XCTAssertEqual(initialMain.id, firstBranchID)
            XCTAssertEqual(initialMain.name, "Main")
            XCTAssertEqual(initialMain.rootSnapshotID, first.id)
            XCTAssertEqual(initialMain.tipSnapshotID, first.id)
            XCTAssertTrue(initialMain.isActive)

            try await store.deleteSnapshot(first.id)
            let emptyIndex = try await store.loadIndex()
            XCTAssertTrue(emptyIndex.snapshots.isEmpty)
            XCTAssertTrue(emptyIndex.branches.isEmpty)
            XCTAssertTrue(try chunkFiles(at: root).isEmpty)
            XCTAssertTrue(try manifestFiles(at: root).isEmpty)

            let replacementBranchID = UUID()
            let replacement = try await store.save(makeCapture(
                branchID: replacementBranchID,
                kind: .manual
            ))
            let recreatedIndex = try await store.loadIndex()
            let recreatedMain = try XCTUnwrap(recreatedIndex.branches.only)
            XCTAssertEqual(recreatedMain.id, replacementBranchID)
            XCTAssertEqual(recreatedMain.name, "Main")
            XCTAssertEqual(recreatedMain.rootSnapshotID, replacement.id)
            XCTAssertEqual(recreatedMain.tipSnapshotID, replacement.id)
            XCTAssertTrue(recreatedMain.isActive)
        }
    }

    func testDeletingSingletonBranchSnapshotRejectsAncestryReferences() async throws {
        try await withTemporaryDirectory { root in
            let store = try EncryptedSnapshotStore(rootURL: root, encryptionKey: key)
            let sourceBranchID = UUID()
            let target = try await store.save(makeCapture(branchID: sourceBranchID, name: "Target"))
            let safety = makeCapture(
                branchID: sourceBranchID,
                kind: .beforeRewind,
                name: "Before Rewind"
            )
            let provisional = try await store.beginRewind(
                safetyCapture: safety,
                sourceBranchID: sourceBranchID
            )
            _ = try await store.commitRewind(provisional.id, targetSnapshotID: target.id)

            do {
                try await store.deleteSnapshot(target.id)
                XCTFail("A snapshot referenced by branch ancestry must remain protected")
            } catch let error as SnapshotStoreError {
                XCTAssertEqual(error, .snapshotIsReferenced(target.id))
            }

            let index = try await store.loadIndex()
            XCTAssertTrue(index.snapshots.contains { $0.id == target.id })
            XCTAssertGreaterThan(index.branches.filter {
                $0.rootSnapshotID == target.id || $0.tipSnapshotID == target.id
            }.count, 1)
        }
    }

    func testDeleteAllSnapshotsClearsReferencedBranchesAndNextSaveRecreatesMain() async throws {
        try await withTemporaryDirectory { root in
            let store = try EncryptedSnapshotStore(rootURL: root, encryptionKey: key)
            let firstBranchID = UUID()
            let first = try await store.save(makeCapture(
                branchID: firstBranchID,
                artifacts: [
                    CapturedArtifact(
                        kind: .memoryPage,
                        logicalName: "first",
                        data: Data("first-state".utf8)
                    )
                ]
            ))
            _ = try await store.save(makeCapture(
                branchID: firstBranchID,
                artifacts: [
                    CapturedArtifact(
                        kind: .fileBlock,
                        logicalName: "second",
                        data: Data("second-state".utf8)
                    )
                ]
            ))
            _ = try await store.save(makeCapture(
                branchID: UUID(),
                artifacts: [
                    CapturedArtifact(
                        kind: .threadState,
                        logicalName: "third",
                        data: Data("third-state".utf8)
                    )
                ]
            ))

            do {
                try await store.deleteSnapshot(first.id)
                XCTFail("Individual deletion should still protect a referenced branch root")
            } catch let error as SnapshotStoreError {
                XCTAssertEqual(error, .snapshotIsReferenced(first.id))
            }
            XCTAssertEqual(try manifestFiles(at: root).count, 3)
            XCTAssertEqual(try chunkFiles(at: root).count, 3)

            try await store.deleteAllSnapshots()
            let emptyIndex = try await store.loadIndex()
            XCTAssertEqual(emptyIndex.schemaVersion, ContinuumConstants.schemaVersion)
            XCTAssertTrue(emptyIndex.snapshots.isEmpty)
            XCTAssertTrue(emptyIndex.branches.isEmpty)
            XCTAssertTrue(emptyIndex.provisionalRewinds.isEmpty)
            XCTAssertTrue(try manifestFiles(at: root).isEmpty)
            XCTAssertTrue(try chunkFiles(at: root).isEmpty)

            let reopened = try EncryptedSnapshotStore(rootURL: root, encryptionKey: key)
            let reopenedIndex = try await reopened.loadIndex()
            XCTAssertTrue(reopenedIndex.snapshots.isEmpty)
            XCTAssertTrue(reopenedIndex.branches.isEmpty)

            let replacementBranchID = UUID()
            let replacement = try await reopened.save(makeCapture(branchID: replacementBranchID))
            let recreatedIndex = try await reopened.loadIndex()
            let main = try XCTUnwrap(recreatedIndex.branches.only)
            XCTAssertEqual(main.id, replacementBranchID)
            XCTAssertEqual(main.name, "Main")
            XCTAssertEqual(main.rootSnapshotID, replacement.id)
            XCTAssertEqual(main.tipSnapshotID, replacement.id)
            XCTAssertTrue(main.isActive)
        }
    }

    func testDeleteAllSnapshotsRefusesDuringProvisionalRewindWithoutMutation() async throws {
        try await withTemporaryDirectory { root in
            let store = try EncryptedSnapshotStore(rootURL: root, encryptionKey: key)
            let sourceBranchID = UUID()
            let source = try await store.save(makeCapture(
                branchID: sourceBranchID,
                artifacts: [
                    CapturedArtifact(
                        kind: .memoryPage,
                        logicalName: "source",
                        data: Data("source-state".utf8)
                    )
                ]
            ))
            let safety = makeCapture(
                branchID: sourceBranchID,
                kind: .beforeRewind,
                artifacts: [
                    CapturedArtifact(
                        kind: .memoryPage,
                        logicalName: "safety",
                        data: Data("safety-state".utf8)
                    )
                ]
            )
            let provisional = try await store.beginRewind(
                safetyCapture: safety,
                sourceBranchID: sourceBranchID
            )
            let before = try await store.loadIndex()

            do {
                try await store.deleteAllSnapshots()
                XCTFail("Delete all must refuse while a rewind transaction is live")
            } catch let error as SnapshotStoreError {
                XCTAssertEqual(error, .rewindInProgress)
            }

            let after = try await store.loadIndex()
            XCTAssertEqual(after.snapshots, before.snapshots)
            XCTAssertEqual(after.branches, before.branches)
            XCTAssertEqual(after.provisionalRewinds, before.provisionalRewinds)
            XCTAssertEqual(try manifestFiles(at: root).count, 2)
            XCTAssertEqual(try chunkFiles(at: root).count, 2)
            let sourceArtifacts = try await store.artifacts(for: source.id)
            XCTAssertEqual(sourceArtifacts.first?.data, Data("source-state".utf8))

            try await store.cancelRewind(provisional.id)
        }
    }

    func testWrongKeyCannotOpenStore() async throws {
        try await withTemporaryDirectory { root in
            let store = try EncryptedSnapshotStore(rootURL: root, encryptionKey: key)
            _ = try await store.save(makeCapture(branchID: UUID()))

            XCTAssertThrowsError(
                try EncryptedSnapshotStore(
                    rootURL: root,
                    encryptionKey: Data(repeating: 0x99, count: 32)
                )
            ) { error in
                XCTAssertEqual(error as? SnapshotStoreError, .decryptionFailed)
            }
        }
    }

    func testSwitchBranchPersistsExactlyOneActiveBranch() async throws {
        try await withTemporaryDirectory { root in
            let store = try EncryptedSnapshotStore(rootURL: root, encryptionKey: key)
            let firstBranch = UUID()
            let secondBranch = UUID()
            _ = try await store.save(makeCapture(branchID: firstBranch))
            _ = try await store.save(makeCapture(branchID: secondBranch))

            try await store.switchBranch(to: secondBranch)
            let switchedIndex = try await store.loadIndex()
            XCTAssertEqual(switchedIndex.branches.filter(\.isActive).map(\.id), [secondBranch])

            let reopened = try EncryptedSnapshotStore(rootURL: root, encryptionKey: key)
            let reopenedIndex = try await reopened.loadIndex()
            XCTAssertEqual(reopenedIndex.branches.filter(\.isActive).map(\.id), [secondBranch])
        }
    }

    private func makeCapture(
        id: SnapshotID = UUID(),
        branchID: BranchID,
        kind: SnapshotKind = .manual,
        name: String = "Snapshot",
        isPinned: Bool = true,
        artifacts: [CapturedArtifact] = [
            CapturedArtifact(kind: .metadata, logicalName: "default", data: Data("state".utf8))
        ]
    ) -> SnapshotCapture {
        let app = AppIdentity(
            bundleIdentifier: "com.example.fixture",
            displayName: "Fixture",
            bundleURL: URL(fileURLWithPath: "/Applications/Fixture.app"),
            executableURL: URL(fileURLWithPath: "/Applications/Fixture.app/Contents/MacOS/Fixture"),
            version: "1.0",
            signingIdentifier: "com.example.fixture",
            teamIdentifier: "TESTTEAM",
            isApplePlatformBinary: false
        )
        let checkpoint = CheckpointRecord(
            capturedAt: Date(timeIntervalSince1970: 1_700_000_000),
            monotonicNanoseconds: 123_456,
            processIdentifiers: [123],
            memoryRegionCount: 1,
            threadCount: 1,
            validation: .valid
        )
        let snapshot = SnapshotRecord(
            id: id,
            name: name,
            kind: kind,
            app: app,
            checkpoint: checkpoint,
            branchID: branchID,
            createdAt: Date(timeIntervalSince1970: 1_700_000_001),
            availability: .instant,
            isPinned: isPinned
        )
        return SnapshotCapture(snapshot: snapshot, artifacts: artifacts)
    }

    private func withTemporaryDirectory(
        _ operation: (URL) async throws -> Void
    ) async throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("ContinuumStoreTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: url) }
        try await operation(url)
    }

    private func chunkFiles(at root: URL) throws -> [URL] {
        try FileManager.default.contentsOfDirectory(
            at: root.appendingPathComponent("chunks", isDirectory: true),
            includingPropertiesForKeys: nil
        ).filter { $0.pathExtension == "ctm" }
    }

    private func manifestFiles(at root: URL) throws -> [URL] {
        try FileManager.default.contentsOfDirectory(
            at: root.appendingPathComponent("manifests", isDirectory: true),
            includingPropertiesForKeys: nil
        ).filter { $0.pathExtension == "ctm" }
    }

    private func allRegularFiles(at root: URL) throws -> [URL] {
        guard let enumerator = FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: [.isRegularFileKey]
        ) else { return [] }
        return try enumerator.compactMap { value in
            guard let url = value as? URL else { return nil }
            return try url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true ? url : nil
        }
    }
}

private extension Array {
    var only: Element? {
        count == 1 ? first : nil
    }
}
