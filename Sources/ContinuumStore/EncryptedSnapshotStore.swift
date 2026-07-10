import ContinuumCore
import CryptoKit
import Foundation

enum StoreFailurePoint: String, Equatable, Sendable {
    case afterWritingChunks
    case afterWritingManifest
    case beforeCommittingIndex
}

private struct ArtifactReference: Codable, Sendable {
    let kind: CapturedArtifactKind
    let logicalName: String
    let chunkHash: String
}

private struct SnapshotManifest: Codable, Sendable {
    let snapshotID: SnapshotID
    let artifacts: [ArtifactReference]
}

public actor EncryptedSnapshotStore: SnapshotRepository {
    private let rootURL: URL
    private let chunksURL: URL
    private let manifestsURL: URL
    private let indexURL: URL
    private let codec: EncryptedBlobCodec
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder
    private let failureInjector: (@Sendable (StoreFailurePoint) -> Bool)?
    private var index: StoreIndex

    public init(rootURL: URL) throws {
        try self.init(rootURL: rootURL, keyProvider: KeychainSnapshotStoreKeyProvider())
    }

    public init(rootURL: URL, encryptionKey: Data) throws {
        try self.init(rootURL: rootURL, keyProvider: FixedSnapshotStoreKeyProvider(keyData: encryptionKey))
    }

    public init(rootURL: URL, keyProvider: any SnapshotStoreKeyProviding) throws {
        try self.init(rootURL: rootURL, keyProvider: keyProvider, failureInjector: nil)
    }

    init(
        rootURL: URL,
        keyProvider: any SnapshotStoreKeyProviding,
        failureInjector: (@Sendable (StoreFailurePoint) -> Bool)?
    ) throws {
        let fileManager = FileManager.default
        try fileManager.createDirectory(
            at: rootURL,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let chunksURL = rootURL.appendingPathComponent("chunks", isDirectory: true)
        let manifestsURL = rootURL.appendingPathComponent("manifests", isDirectory: true)
        try fileManager.createDirectory(at: chunksURL, withIntermediateDirectories: true)
        try fileManager.createDirectory(at: manifestsURL, withIntermediateDirectories: true)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let decoder = JSONDecoder()
        let codec = EncryptedBlobCodec(key: try SymmetricKey(validating: keyProvider.loadOrCreateKey()))
        let indexURL = rootURL.appendingPathComponent("index.ctm")

        let loadedIndex: StoreIndex
        if fileManager.fileExists(atPath: indexURL.path) {
            let encrypted = try Data(contentsOf: indexURL)
            loadedIndex = try decoder.decode(StoreIndex.self, from: codec.open(encrypted))
            guard loadedIndex.schemaVersion == ContinuumConstants.schemaVersion else {
                throw SnapshotStoreError.unsupportedSchema(loadedIndex.schemaVersion)
            }
        } else {
            loadedIndex = StoreIndex()
            let encoded = try encoder.encode(loadedIndex)
            try AtomicFileWriter.write(codec.seal(encoded), to: indexURL)
        }

        self.rootURL = rootURL
        self.chunksURL = chunksURL
        self.manifestsURL = manifestsURL
        self.indexURL = indexURL
        self.codec = codec
        self.encoder = encoder
        self.decoder = decoder
        self.failureInjector = failureInjector
        self.index = loadedIndex

        Self.cleanupOrphans(
            index: loadedIndex,
            chunksURL: chunksURL,
            manifestsURL: manifestsURL,
            fileManager: fileManager
        )
    }

    public func loadIndex() async throws -> StoreIndex {
        index
    }

    public func save(_ capture: SnapshotCapture) async throws -> SnapshotRecord {
        guard !index.snapshots.contains(where: { $0.id == capture.snapshot.id }) else {
            throw SnapshotStoreError.duplicateSnapshot(capture.snapshot.id)
        }

        let prepared = try prepare(capture)
        var updated = index
        updated.snapshots.append(prepared.snapshot)
        updateBranch(for: prepared.snapshot, in: &updated)
        try commitPrepared(prepared, updatedIndex: updated)
        return prepared.snapshot
    }

    public func beginRewind(
        safetyCapture: SnapshotCapture,
        sourceBranchID: BranchID
    ) async throws -> ProvisionalRewind {
        guard index.branches.contains(where: { $0.id == sourceBranchID }) else {
            throw SnapshotStoreError.branchNotFound(sourceBranchID)
        }
        guard safetyCapture.snapshot.kind == .beforeRewind,
              safetyCapture.snapshot.branchID == sourceBranchID else {
            throw SnapshotStoreError.invalidSafetySnapshot
        }
        guard !index.snapshots.contains(where: { $0.id == safetyCapture.snapshot.id }) else {
            throw SnapshotStoreError.duplicateSnapshot(safetyCapture.snapshot.id)
        }

        let prepared = try prepare(safetyCapture, forcePinned: true)
        let provisional = ProvisionalRewind(
            safetySnapshotID: prepared.snapshot.id,
            sourceBranchID: sourceBranchID
        )
        var updated = index
        updated.snapshots.append(prepared.snapshot)
        updated.provisionalRewinds.append(provisional)
        try commitPrepared(prepared, updatedIndex: updated)
        return provisional
    }

    public func commitRewind(
        _ provisionalID: ProvisionalRewindID,
        targetSnapshotID: SnapshotID
    ) async throws -> RewindCommit {
        guard let provisional = index.provisionalRewinds.first(where: { $0.id == provisionalID }) else {
            throw SnapshotStoreError.provisionalRewindNotFound(provisionalID)
        }
        guard index.snapshots.contains(where: { $0.id == provisional.safetySnapshotID }) else {
            throw SnapshotStoreError.snapshotNotFound(provisional.safetySnapshotID)
        }
        guard let target = index.snapshots.first(where: { $0.id == targetSnapshotID }) else {
            throw SnapshotStoreError.snapshotNotFound(targetSnapshotID)
        }

        let abandonedFuture = BranchRecord(
            name: "Abandoned Future",
            parentBranchID: provisional.sourceBranchID,
            rootSnapshotID: provisional.safetySnapshotID,
            tipSnapshotID: provisional.safetySnapshotID,
            isActive: false
        )
        let newActive = BranchRecord(
            name: "Rewind from \(target.name)",
            parentBranchID: target.branchID,
            rootSnapshotID: targetSnapshotID,
            tipSnapshotID: targetSnapshotID,
            isActive: true
        )

        var updated = index
        for branchIndex in updated.branches.indices {
            updated.branches[branchIndex].isActive = false
        }
        updated.branches.append(abandonedFuture)
        updated.branches.append(newActive)
        updated.provisionalRewinds.removeAll { $0.id == provisionalID }
        try persist(updated)

        return RewindCommit(
            targetSnapshotID: targetSnapshotID,
            safetySnapshotID: provisional.safetySnapshotID,
            abandonedFutureBranchID: abandonedFuture.id,
            activeBranchID: newActive.id
        )
    }

    public func cancelRewind(_ provisionalID: ProvisionalRewindID) async throws {
        guard let provisional = index.provisionalRewinds.first(where: { $0.id == provisionalID }) else {
            throw SnapshotStoreError.provisionalRewindNotFound(provisionalID)
        }
        var updated = index
        updated.provisionalRewinds.removeAll { $0.id == provisionalID }
        updated.snapshots.removeAll { $0.id == provisional.safetySnapshotID }
        try persist(updated)
        removeManifest(for: provisional.safetySnapshotID)
        garbageCollectChunks(referencedBy: updated)
    }

    public func renameSnapshot(_ snapshotID: SnapshotID, to name: String) async throws {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw SnapshotStoreError.invalidSnapshotName
        }
        guard let snapshotIndex = index.snapshots.firstIndex(where: { $0.id == snapshotID }) else {
            throw SnapshotStoreError.snapshotNotFound(snapshotID)
        }
        var updated = index
        updated.snapshots[snapshotIndex].name = trimmed
        try persist(updated)
    }

    public func updateNote(_ snapshotID: SnapshotID, note: String) async throws {
        guard let snapshotIndex = index.snapshots.firstIndex(where: { $0.id == snapshotID }) else {
            throw SnapshotStoreError.snapshotNotFound(snapshotID)
        }
        var updated = index
        updated.snapshots[snapshotIndex].note = note
        try persist(updated)
    }

    public func deleteSnapshot(_ snapshotID: SnapshotID) async throws {
        guard index.snapshots.contains(where: { $0.id == snapshotID }) else {
            throw SnapshotStoreError.snapshotNotFound(snapshotID)
        }

        let provisionalReference = index.provisionalRewinds.contains { $0.safetySnapshotID == snapshotID }
        guard !provisionalReference else {
            throw SnapshotStoreError.snapshotIsReferenced(snapshotID)
        }

        let referencingBranches = index.branches.filter {
            $0.rootSnapshotID == snapshotID || $0.tipSnapshotID == snapshotID
        }
        let removableBranch: BranchRecord?
        if referencingBranches.isEmpty {
            removableBranch = nil
        } else if referencingBranches.count == 1,
                  let branch = referencingBranches.first,
                  branch.rootSnapshotID == snapshotID,
                  branch.tipSnapshotID == snapshotID,
                  !index.branches.contains(where: { $0.parentBranchID == branch.id }) {
            removableBranch = branch
        } else {
            throw SnapshotStoreError.snapshotIsReferenced(snapshotID)
        }

        var updated = index
        updated.snapshots.removeAll { $0.id == snapshotID }
        if let removableBranch {
            updated.branches.removeAll { $0.id == removableBranch.id }
            if removableBranch.isActive,
               !updated.branches.contains(where: \.isActive) {
                let nextActiveID = removableBranch.parentBranchID.flatMap { parentID in
                    updated.branches.contains(where: { $0.id == parentID }) ? parentID : nil
                } ?? updated.branches.max(by: { $0.createdAt < $1.createdAt })?.id
                if let nextActiveID,
                   let branchIndex = updated.branches.firstIndex(where: { $0.id == nextActiveID }) {
                    updated.branches[branchIndex].isActive = true
                }
            }
        }
        try persist(updated)
        removeManifest(for: snapshotID)
        garbageCollectChunks(referencedBy: updated)
    }

    public func deleteAllSnapshots() async throws {
        guard index.provisionalRewinds.isEmpty else {
            throw SnapshotStoreError.rewindInProgress
        }

        let emptyIndex = StoreIndex()
        try persist(emptyIndex)
        try removeAllItems(in: manifestsURL)
        try removeAllItems(in: chunksURL)
    }

    public func artifacts(for snapshotID: SnapshotID) async throws -> [CapturedArtifact] {
        guard index.snapshots.contains(where: { $0.id == snapshotID }) else {
            throw SnapshotStoreError.snapshotNotFound(snapshotID)
        }
        let manifest = try loadManifest(for: snapshotID)
        return try manifest.artifacts.map { reference in
            let encrypted = try Data(contentsOf: chunkURL(for: reference.chunkHash))
            let plaintext = try codec.open(encrypted)
            guard Self.hash(plaintext) == reference.chunkHash else {
                throw SnapshotStoreError.integrityFailure("chunk \(reference.chunkHash)")
            }
            return CapturedArtifact(
                kind: reference.kind,
                logicalName: reference.logicalName,
                data: plaintext
            )
        }
    }

    public func switchBranch(to branchID: BranchID) async throws {
        guard index.branches.contains(where: { $0.id == branchID }) else {
            throw SnapshotStoreError.branchNotFound(branchID)
        }
        var updated = index
        for branchIndex in updated.branches.indices {
            updated.branches[branchIndex].isActive = updated.branches[branchIndex].id == branchID
        }
        try persist(updated)
    }

    private struct PreparedCapture {
        var snapshot: SnapshotRecord
        let manifest: SnapshotManifest
        let chunks: [String: Data]
    }

    private func prepare(_ capture: SnapshotCapture, forcePinned: Bool = false) throws -> PreparedCapture {
        var references: [ArtifactReference] = []
        var chunks: [String: Data] = [:]
        var logicalBytes: Int64 = 0

        for artifact in capture.artifacts {
            let hash = Self.hash(artifact.data)
            references.append(ArtifactReference(
                kind: artifact.kind,
                logicalName: artifact.logicalName,
                chunkHash: hash
            ))
            chunks[hash] = artifact.data
            logicalBytes += Int64(artifact.data.count)
        }

        let existingHashes = Set(index.snapshots.flatMap(\.chunkHashes))
        let uniqueBytes = chunks.reduce(into: Int64(0)) { total, item in
            if !existingHashes.contains(item.key) {
                total += Int64(item.value.count)
            }
        }

        var snapshot = capture.snapshot
        snapshot.chunkHashes = references.map(\.chunkHash)
        snapshot.logicalBytes = logicalBytes
        snapshot.uniqueBytes = uniqueBytes
        if forcePinned || snapshot.kind == .manual || snapshot.kind == .beforeRewind {
            snapshot.isPinned = true
        }
        return PreparedCapture(
            snapshot: snapshot,
            manifest: SnapshotManifest(snapshotID: snapshot.id, artifacts: references),
            chunks: chunks
        )
    }

    private func commitPrepared(_ prepared: PreparedCapture, updatedIndex: StoreIndex) throws {
        var newlyCreatedChunks: [URL] = []
        let manifestURL = manifestURL(for: prepared.snapshot.id)
        do {
            for (hash, plaintext) in prepared.chunks {
                let destination = chunkURL(for: hash)
                if !FileManager.default.fileExists(atPath: destination.path) {
                    try AtomicFileWriter.write(codec.seal(plaintext), to: destination)
                    newlyCreatedChunks.append(destination)
                }
            }
            try injectFailure(at: .afterWritingChunks)

            let manifestData = try encoder.encode(prepared.manifest)
            try AtomicFileWriter.write(codec.seal(manifestData), to: manifestURL)
            try injectFailure(at: .afterWritingManifest)
            try injectFailure(at: .beforeCommittingIndex)
            try persist(updatedIndex)
        } catch {
            try? FileManager.default.removeItem(at: manifestURL)
            for chunk in newlyCreatedChunks {
                try? FileManager.default.removeItem(at: chunk)
            }
            throw error
        }
    }

    private func persist(_ updated: StoreIndex) throws {
        let encoded = try encoder.encode(updated)
        let encrypted = try codec.seal(encoded)
        try AtomicFileWriter.write(encrypted, to: indexURL)
        index = updated
    }

    private func updateBranch(for snapshot: SnapshotRecord, in updated: inout StoreIndex) {
        if let branchIndex = updated.branches.firstIndex(where: { $0.id == snapshot.branchID }) {
            updated.branches[branchIndex].tipSnapshotID = snapshot.id
            return
        }
        let shouldActivate = !updated.branches.contains(where: \.isActive)
        updated.branches.append(BranchRecord(
            id: snapshot.branchID,
            name: updated.branches.isEmpty ? "Main" : "Branch \(updated.branches.count + 1)",
            parentBranchID: nil,
            rootSnapshotID: snapshot.id,
            tipSnapshotID: snapshot.id,
            isActive: shouldActivate
        ))
    }

    private func loadManifest(for snapshotID: SnapshotID) throws -> SnapshotManifest {
        let encrypted: Data
        do {
            encrypted = try Data(contentsOf: manifestURL(for: snapshotID))
        } catch {
            throw SnapshotStoreError.corruptData("manifest for snapshot \(snapshotID) is missing")
        }
        let manifest = try decoder.decode(SnapshotManifest.self, from: codec.open(encrypted))
        guard manifest.snapshotID == snapshotID else {
            throw SnapshotStoreError.integrityFailure("manifest belongs to a different snapshot")
        }
        return manifest
    }

    private func injectFailure(at point: StoreFailurePoint) throws {
        if failureInjector?(point) == true {
            throw SnapshotStoreError.injectedFailure(point.rawValue)
        }
    }

    private func chunkURL(for hash: String) -> URL {
        chunksURL.appendingPathComponent("\(hash).ctm")
    }

    private func manifestURL(for snapshotID: SnapshotID) -> URL {
        manifestsURL.appendingPathComponent("\(snapshotID.uuidString.lowercased()).ctm")
    }

    private func removeManifest(for snapshotID: SnapshotID) {
        try? FileManager.default.removeItem(at: manifestURL(for: snapshotID))
    }

    private func removeAllItems(in directory: URL) throws {
        guard FileManager.default.fileExists(atPath: directory.path) else { return }
        for item in try FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: nil
        ) {
            try FileManager.default.removeItem(at: item)
        }
    }

    private func garbageCollectChunks(referencedBy index: StoreIndex) {
        let referencedHashes = Set(index.snapshots.flatMap(\.chunkHashes))
        guard let files = try? FileManager.default.contentsOfDirectory(
            at: chunksURL,
            includingPropertiesForKeys: nil
        ) else { return }
        for file in files where file.pathExtension == "ctm" {
            if !referencedHashes.contains(file.deletingPathExtension().lastPathComponent) {
                try? FileManager.default.removeItem(at: file)
            }
        }
    }

    private static func cleanupOrphans(
        index: StoreIndex,
        chunksURL: URL,
        manifestsURL: URL,
        fileManager: FileManager
    ) {
        let referencedHashes = Set(index.snapshots.flatMap(\.chunkHashes))
        if let chunkFiles = try? fileManager.contentsOfDirectory(
            at: chunksURL,
            includingPropertiesForKeys: nil
        ) {
            for file in chunkFiles where file.pathExtension == "ctm" {
                if !referencedHashes.contains(file.deletingPathExtension().lastPathComponent) {
                    try? fileManager.removeItem(at: file)
                }
            }
        }

        let snapshotNames = Set(index.snapshots.map { $0.id.uuidString.lowercased() })
        if let manifestFiles = try? fileManager.contentsOfDirectory(
            at: manifestsURL,
            includingPropertiesForKeys: nil
        ) {
            for file in manifestFiles where file.pathExtension == "ctm" {
                if !snapshotNames.contains(file.deletingPathExtension().lastPathComponent) {
                    try? fileManager.removeItem(at: file)
                }
            }
        }
    }

    private static func hash(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
