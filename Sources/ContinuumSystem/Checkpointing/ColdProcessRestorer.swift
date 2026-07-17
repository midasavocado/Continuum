import ContinuumCore
import ContinuumRuntime
import ContinuumStore
import CryptoKit
import Darwin
import Foundation

public struct ColdProcessPreparation: Hashable, Sendable {
    public let id: UUID
    public let replacementProcessIdentifier: Int32
    public let capturedProcessIdentifier: Int32
    public let reconstructedRegionCount: Int
    public let reconstructedChunkCount: Int
    public let reconstructedBytes: UInt64
    public let deferredMaximumProtectionRegionCount: Int
    public let reconstructedThreadCount: Int
    public let reconstructedThreadStateBytes: UInt64
    public let replacementThreadIdentifier: UInt64
    public let reconstructedFileDescriptorCount: Int
    public let reconstructedFileCount: Int
    public let reconstructedFileBytes: UInt64
}

private struct ManifestOverlayRepository: SnapshotRepository {
    let base: any SnapshotRepository
    let snapshotID: SnapshotID
    let manifestData: Data

    func loadIndex() async throws -> StoreIndex {
        try await base.loadIndex()
    }

    func save(_ capture: SnapshotCapture) async throws -> SnapshotRecord {
        try await base.save(capture)
    }

    func beginRewind(
        safetyCapture: SnapshotCapture,
        sourceBranchID: BranchID
    ) async throws -> ProvisionalRewind {
        try await base.beginRewind(
            safetyCapture: safetyCapture,
            sourceBranchID: sourceBranchID
        )
    }

    func commitRewind(
        _ provisionalID: ProvisionalRewindID,
        targetSnapshotID: SnapshotID
    ) async throws -> RewindCommit {
        try await base.commitRewind(
            provisionalID,
            targetSnapshotID: targetSnapshotID
        )
    }

    func cancelRewind(_ provisionalID: ProvisionalRewindID) async throws {
        try await base.cancelRewind(provisionalID)
    }

    func renameSnapshot(_ snapshotID: SnapshotID, to name: String) async throws {
        try await base.renameSnapshot(snapshotID, to: name)
    }

    func updateNote(_ snapshotID: SnapshotID, note: String) async throws {
        try await base.updateNote(snapshotID, note: note)
    }

    func deleteSnapshot(_ snapshotID: SnapshotID) async throws {
        try await base.deleteSnapshot(snapshotID)
    }

    func deleteAllSnapshots() async throws {
        try await base.deleteAllSnapshots()
    }

    func artifacts(for requestedSnapshotID: SnapshotID) async throws -> [CapturedArtifact] {
        var artifacts = try await base.artifacts(for: requestedSnapshotID)
        guard requestedSnapshotID == snapshotID else { return artifacts }
        let manifest = CapturedArtifact(
            kind: .metadata,
            logicalName: "durable-checkpoint-v3.json",
            data: manifestData
        )
        if let index = artifacts.firstIndex(where: {
            $0.logicalName == manifest.logicalName
        }) {
            artifacts[index] = manifest
        } else {
            artifacts.append(manifest)
        }
        return artifacts
    }

    func artifact(
        for requestedSnapshotID: SnapshotID,
        logicalName: String
    ) async throws -> CapturedArtifact {
        if requestedSnapshotID == snapshotID,
           logicalName == "durable-checkpoint-v3.json" {
            return CapturedArtifact(
                kind: .metadata,
                logicalName: logicalName,
                data: manifestData
            )
        }
        return try await base.artifact(
            for: requestedSnapshotID,
            logicalName: logicalName
        )
    }

    func switchBranch(to branchID: BranchID) async throws {
        try await base.switchBranch(to: branchID)
    }
}

public struct ColdProcessCommit: Hashable, Sendable {
    public let processIdentifier: Int32
    public let safetyTransactionRootURL: URL?
    public let retainedFileCount: Int
    public let retainedFileBytes: UInt64
}

public struct ColdProcessForestMember: Hashable, Sendable {
    public let capturedProcessIdentifier: Int32
    public let capturedParentProcessIdentifier: Int32
    public let replacementProcessIdentifier: Int32
    public let replacementParentProcessIdentifier: Int32?
}

public struct ColdProcessForestPreparation: Hashable, Sendable {
    public let id: UUID
    public let rootReplacementProcessIdentifier: Int32
    public let members: [ColdProcessForestMember]
    public let terminalPresentations: [ColdTerminalPresentation]
}

public struct ColdTerminalPresentation: Hashable, Sendable {
    public let sessionIdentifier: UUID
    public let socketPath: String
    public let ttyIndex: UInt32
}

public struct ColdProcessForestCommit: Hashable, Sendable {
    public let rootProcessIdentifier: Int32
    public let processIdentifiers: [Int32]
}

public struct ColdFileSafetySnapshot: Hashable, Sendable {
    public let id: UUID
    public let createdAt: Date
    public let fileCount: Int
    public let logicalBytes: UInt64
}

public struct ColdFileSafetyRestore: Hashable, Sendable {
    public let restoredSnapshotID: UUID
    public let reciprocalSafetySnapshotID: UUID
    public let restoredFileCount: Int
    public let restoredBytes: UInt64
}

/// Rebuilds a durable process image into a disposable child that remains
/// stopped before main. A certified single-thread image also receives its saved
/// ARM64 general and vector register state. Writable descriptors reconnect to
/// their current files, but file contents are never restored. Commit detaches
/// the verified replacement; unsupported resources remain certification
/// boundaries.
public actor ColdProcessRestorer {
    private static let appStatePayloadUserTag: UInt32 = 240
    private static let appStateMetadataUserTag: UInt32 = 241

    private enum ResumeMethod: Sendable {
        case entryStop
        case rehydrateStop
    }

    private struct PreparedReplacement: @unchecked Sendable {
        let processIdentifier: Int32
        let session: OpaquePointer
        let fileRollback: PreparedFileRollback?
        let requiresSafepointRelease: Bool
        let resumeMethod: ResumeMethod
    }

    private struct PreparedFileRollback: Sendable {
        let store: APFSLocalFileCheckpointStore
        let snapshotID: UUID
        let rootURL: URL
        let replacedFileCount: Int
        let replacedBytes: UInt64
        let installedFiles: [LocalFileReplacement]
    }

    private struct PreparedForest: @unchecked Sendable {
        let rootCapturedProcessIdentifier: Int32
        let preparationIdentifiers: [UUID]
        let members: [ColdProcessForestMember]
        let terminalPresentationSessionIdentifiers: [UUID]
        let brokeredPair: OpaquePointer?
        let brokeredForest: OpaquePointer?
    }

    private struct PendingBrokeredForestCleanup: @unchecked Sendable {
        let handle: OpaquePointer
    }

    struct PreparedPresentationMaster {
        let ttyIndex: UInt32
        let descriptor: Int32
    }

    struct PreparedDescriptorGraph {
        let remapsByCapturedProcess: [Int32: [continuum_spawn_descriptor_remap]]
        let controllerDescriptors: [Int32]
        let presentationMasters: [PreparedPresentationMaster]
    }

    private struct BootstrapResourceHandles {
        let pipes: [DurableDescriptorHandle]
        let sockets: [DurableDescriptorHandle]
        let kqueues: [BootstrapKqueue]
    }

    struct BootstrapKqueue {
        let resource: DurableKqueueResource
        let handle: DurableDescriptorHandle
    }

    private struct BrokerLaunchPreparation {
        let descriptor: Int32
        let remaps: [continuum_spawn_descriptor_remap]
        let environment: [String]
    }

    private enum BrokerSessionAuthorization: @unchecked Sendable {
        case pair(OpaquePointer, continuum_brokered_process_role)
        case forest(OpaquePointer, Int32)
    }

    private struct ColdFileTransactionJournal: Codable, Sendable {
        struct Entry: Codable, Sendable {
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

    private let bootstrapLibraryPath: String?
    private let fileSafetyRootURL: URL
    private let terminalPresentationRegistry: TerminalPresentationSessionRegistry?
    private var preparedReplacements: [UUID: PreparedReplacement] = [:]
    private var preparedForests: [UUID: PreparedForest] = [:]
    private var pendingBrokeredForestCleanups: [PendingBrokeredForestCleanup] = []

    public init(
        bootstrapLibraryURL: URL? = nil,
        fileSafetyRootURL: URL? = nil
    ) {
        self.fileSafetyRootURL = fileSafetyRootURL
            ?? Self.defaultFileSafetyRootURL()
        if let bootstrapLibraryURL {
            self.bootstrapLibraryPath = bootstrapLibraryURL.standardizedFileURL.path
        } else if let environmentPath = ProcessInfo.processInfo.environment[
            "CONTINUUM_BOOTSTRAP_LIBRARY_PATH"
        ], !environmentPath.isEmpty {
            self.bootstrapLibraryPath = URL(fileURLWithPath: environmentPath)
                .standardizedFileURL.path
        } else {
            self.bootstrapLibraryPath = Bundle.main.privateFrameworksURL?
                .appendingPathComponent("libContinuumBootstrap.dylib")
                .path
        }
        self.terminalPresentationRegistry = try? TerminalPresentationSessionRegistry()
    }

    deinit {
        let brokeredPreparationIdentifiers = Set(
            preparedForests.values
                .filter {
                    $0.brokeredPair != nil || $0.brokeredForest != nil
                }
                .flatMap(\.preparationIdentifiers)
        )
        for pair in preparedForests.values.compactMap(\.brokeredPair) {
            _ = continuum_brokered_pair_abort(pair, 5_000)
        }
        for forest in preparedForests.values.compactMap(\.brokeredForest) {
            _ = continuum_brokered_forest_abort(forest, 5_000)
        }
        for pending in pendingBrokeredForestCleanups {
            _ = continuum_brokered_forest_abort(pending.handle, 5_000)
        }
        for (identifier, replacement) in preparedReplacements {
            if !brokeredPreparationIdentifiers.contains(identifier) {
                _ = Self.killAndReap(replacement.processIdentifier)
            }
            continuum_remote_session_destroy(replacement.session)
            try? Self.rollbackFiles(replacement.fileRollback)
        }
    }

    public func prepareProcessForest(
        from snapshotID: SnapshotID,
        repository: any SnapshotRepository
    ) async throws -> ColdProcessForestPreparation {
        retryPendingBrokeredForestCleanups()
        let manifest = try await repository.artifact(
            for: snapshotID,
            logicalName: "durable-checkpoint-v3.json"
        )
        let image: DurableCheckpointImage
        do {
            image = try JSONDecoder().decode(
                DurableCheckpointImage.self,
                from: manifest.data
            )
        } catch {
            throw ContinuumError.integrityFailure(
                "The durable checkpoint manifest is invalid."
            )
        }
        try validate(image)
        guard !image.members.isEmpty,
              image.members.contains(where: {
                  $0.processIdentifier == image.rootProcessIdentifier
              }) else {
            throw ContinuumError.integrityFailure(
                "The durable process forest has no valid root member."
            )
        }
        guard image.members.allSatisfy({ Self.processIsAbsent($0.processIdentifier) }) else {
            throw ContinuumError.restoreUnavailable(
                "Cold restoration requires every captured process to be fully exited."
            )
        }

        let forestID = UUID()
        let descriptorGraph = try prepareDescriptorGraph(for: image)
        defer {
            for descriptor in descriptorGraph.controllerDescriptors {
                Darwin.close(descriptor)
            }
        }
        var terminalPresentations: [ColdTerminalPresentation] = []
        do {
            if !descriptorGraph.presentationMasters.isEmpty,
               terminalPresentationRegistry == nil {
                throw ContinuumError.restoreUnavailable(
                    "Continuum could not create its private terminal presentation service."
                )
            }
            for presentation in descriptorGraph.presentationMasters {
                guard let terminalPresentationRegistry else { continue }
                let endpoint = try await terminalPresentationRegistry.stage(
                    workloadPTYMaster: presentation.descriptor,
                    forestIdentifier: forestID
                )
                terminalPresentations.append(ColdTerminalPresentation(
                    sessionIdentifier: endpoint.sessionIdentifier,
                    socketPath: endpoint.socketPath,
                    ttyIndex: presentation.ttyIndex
                ))
            }
        } catch {
            for presentation in terminalPresentations {
                try? await terminalPresentationRegistry?.discard(
                    presentation.sessionIdentifier
                )
            }
            throw error
        }

        var preparationIdentifiers: [UUID] = []
        var members: [ColdProcessForestMember] = []
        var brokeredPair: OpaquePointer?
        var brokeredForest: OpaquePointer?
        do {
            let orderedMembers = try Self.parentFirstMembers(image.members)
            if Self.shouldUseBrokeredPair(
                orderedMembers,
                rootProcessIdentifier: image.rootProcessIdentifier
            ) {
                let root = orderedMembers[0]
                let child = orderedMembers[1]
                let prepared = try await prepareBrokeredPair(
                    root: root,
                    child: child,
                    image: image,
                    snapshotID: snapshotID,
                    repository: repository,
                    descriptorGraph: descriptorGraph
                )
                preparationIdentifiers = prepared.preparationIdentifiers
                members = prepared.members
                brokeredPair = prepared.pair
            } else if orderedMembers.count == 1 {
                let process = orderedMembers[0]
                guard process.launchContract != nil else {
                    throw ContinuumError.restoreUnavailable(
                        "The captured process has no relaunch contract."
                    )
                }
                let memberImage = DurableCheckpointImage(
                    checkpointID: image.checkpointID,
                    createdAt: image.createdAt,
                    architecture: image.architecture,
                    operatingSystemBuild: image.operatingSystemBuild,
                    pageSize: image.pageSize,
                    rootProcessIdentifier: process.processIdentifier,
                    app: image.app,
                    members: [process],
                    writableFiles: image.writableFiles,
                    writableFileDescriptors: image.writableFileDescriptors.filter {
                        $0.processIdentifier == process.processIdentifier
                    },
                    descriptorGraph: image.descriptorGraph
                )
                let encoded = try JSONEncoder().encode(memberImage)
                let overlay = ManifestOverlayRepository(
                    base: repository,
                    snapshotID: snapshotID,
                    manifestData: encoded
                )
                let preparation = try await prepareRootProcess(
                    from: snapshotID,
                    repository: overlay,
                    descriptorRemaps: descriptorGraph.remapsByCapturedProcess[
                        process.processIdentifier
                    ] ?? []
                )
                preparationIdentifiers.append(preparation.id)
                members.append(ColdProcessForestMember(
                    capturedProcessIdentifier: process.processIdentifier,
                    capturedParentProcessIdentifier: process.parentProcessIdentifier,
                    replacementProcessIdentifier: preparation.replacementProcessIdentifier,
                    replacementParentProcessIdentifier: Self.parentProcessIdentifier(
                        for: preparation.replacementProcessIdentifier
                    )
                ))
            } else {
                let prepared = try await prepareBrokeredForest(
                    orderedMembers: orderedMembers,
                    image: image,
                    snapshotID: snapshotID,
                    repository: repository,
                    descriptorGraph: descriptorGraph
                )
                preparationIdentifiers = prepared.preparationIdentifiers
                members = prepared.members
                brokeredForest = prepared.forest
            }
        } catch {
            for preparationIdentifier in preparationIdentifiers.reversed() {
                try? discard(preparationIdentifier)
            }
            for presentation in terminalPresentations {
                try? await terminalPresentationRegistry?.discard(
                    presentation.sessionIdentifier
                )
            }
            throw error
        }

        guard let rootReplacement = members.first(where: {
            $0.capturedProcessIdentifier == image.rootProcessIdentifier
        })?.replacementProcessIdentifier else {
            if let brokeredPair {
                _ = continuum_brokered_pair_abort(brokeredPair, 5_000)
            }
            if let brokeredForest {
                _ = continuum_brokered_forest_abort(brokeredForest, 5_000)
            }
            for preparationIdentifier in preparationIdentifiers.reversed() {
                if brokeredPair == nil && brokeredForest == nil {
                    try? discard(preparationIdentifier)
                } else {
                    try? discardBrokerAbortedReplacement(preparationIdentifier)
                }
            }
            for presentation in terminalPresentations {
                try? await terminalPresentationRegistry?.discard(
                    presentation.sessionIdentifier
                )
            }
            throw ContinuumError.integrityFailure(
                "The durable process forest root was not prepared."
            )
        }
        preparedForests[forestID] = PreparedForest(
            rootCapturedProcessIdentifier: image.rootProcessIdentifier,
            preparationIdentifiers: preparationIdentifiers,
            members: members,
            terminalPresentationSessionIdentifiers: terminalPresentations.map(
                \.sessionIdentifier
            ),
            brokeredPair: brokeredPair,
            brokeredForest: brokeredForest
        )
        return ColdProcessForestPreparation(
            id: forestID,
            rootReplacementProcessIdentifier: rootReplacement,
            members: members,
            terminalPresentations: terminalPresentations
        )
    }

    private func prepareBrokeredPair(
        root: DurableProcessImage,
        child: DurableProcessImage,
        image: DurableCheckpointImage,
        snapshotID: SnapshotID,
        repository: any SnapshotRepository,
        descriptorGraph: PreparedDescriptorGraph
    ) async throws -> (
        preparationIdentifiers: [UUID],
        members: [ColdProcessForestMember],
        pair: OpaquePointer
    ) {
        guard let bootstrapLibraryPath,
              let rootLaunch = root.launchContract,
              let childLaunch = child.launchContract,
              let rootTopology = root.topology,
              let childTopology = child.topology else {
            throw ContinuumError.restoreUnavailable(
                "The two-process restore component is missing launch or kernel-topology state."
            )
        }
        guard rootTopology.sessionIdentifier == root.processIdentifier,
              rootTopology.processGroupIdentifier == root.processIdentifier,
              childTopology.sessionIdentifier == root.processIdentifier,
              childTopology.processGroupIdentifier == root.processIdentifier
                || childTopology.processGroupIdentifier == child.processIdentifier,
              rootTopology.foregroundProcessGroupIdentifier
                == childTopology.foregroundProcessGroupIdentifier,
              rootTopology.foregroundProcessGroupIdentifier
                == root.processIdentifier
                || rootTopology.foregroundProcessGroupIdentifier
                    == child.processIdentifier else {
            throw ContinuumError.restoreUnavailable(
                "The captured two-process session cannot be mapped exactly by the current launch broker."
            )
        }
        let rootPTYSlaves = (image.ptyDescriptors ?? []).filter {
            $0.processIdentifier == root.processIdentifier && $0.role == .slave
        }
        if !(image.ptyDescriptors ?? []).isEmpty, rootPTYSlaves.isEmpty {
            throw ContinuumError.restoreUnavailable(
                "The session leader has no captured PTY slave for controlling-terminal restoration."
            )
        }
        let controllingTerminalDescriptor = rootPTYSlaves
            .map(\.fileDescriptor)
            .sorted()
            .first ?? -1

        let rootLaunchPreparation = try makeBrokerLaunchPreparation(
            launch: rootLaunch,
            remaps: descriptorGraph.remapsByCapturedProcess[
                root.processIdentifier
            ] ?? [],
            resourceHandles: Self.bootstrapResourceHandles(
                in: image,
                processIdentifier: root.processIdentifier
            )
        )
        let childLaunchPreparation = try makeBrokerLaunchPreparation(
            launch: childLaunch,
            remaps: descriptorGraph.remapsByCapturedProcess[
                child.processIdentifier
            ] ?? [],
            resourceHandles: Self.bootstrapResourceHandles(
                in: image,
                processIdentifier: child.processIdentifier
            )
        )
        var ownsRootDescriptor = true
        var ownsChildDescriptor = true
        defer {
            if ownsRootDescriptor {
                Darwin.close(rootLaunchPreparation.descriptor)
            }
            if ownsChildDescriptor {
                Darwin.close(childLaunchPreparation.descriptor)
            }
        }

        var pair: OpaquePointer?
        let prepareStatus = rootLaunchPreparation.remaps.withUnsafeBufferPointer {
            rootRemaps in
            childLaunchPreparation.remaps.withUnsafeBufferPointer {
                childRemaps in
                Self.withCStringArray(rootLaunch.arguments) { rootArguments in
                    Self.withCStringArray(rootLaunchPreparation.environment) {
                        rootEnvironment in
                        Self.withCStringArray(childLaunch.arguments) {
                            childArguments in
                            Self.withCStringArray(
                                childLaunchPreparation.environment
                            ) { childEnvironment in
                                var rootSpec = continuum_brokered_process_spec()
                                rootSpec.structure_size = UInt32(
                                    MemoryLayout<continuum_brokered_process_spec>.size
                                )
                                rootSpec.captured_process_id = root.processIdentifier
                                rootSpec.captured_process_group_id =
                                    rootTopology.processGroupIdentifier
                                rootSpec.foreground_process_group_id =
                                    rootTopology.foregroundProcessGroupIdentifier
                                rootSpec.arguments = rootArguments
                                rootSpec.environment = rootEnvironment
                                rootSpec.descriptor_remaps = rootRemaps.baseAddress
                                rootSpec.descriptor_remap_count = rootRemaps.count
                                rootSpec.topology = continuum_spawn_process_topology(
                                    structure_size: UInt32(
                                        MemoryLayout<continuum_spawn_process_topology>.size
                                    ),
                                    create_session: 1,
                                    process_group_policy:
                                        CONTINUUM_SPAWN_PROCESS_GROUP_CREATE,
                                    process_group_id: 0,
                                    controlling_terminal_descriptor:
                                        controllingTerminalDescriptor
                                )
                                rootSpec.disable_aslr = rootLaunch.addressSpacePolicy
                                        == .continuumDeterministic ? 1 : 0

                                var childSpec = continuum_brokered_process_spec()
                                childSpec.structure_size = rootSpec.structure_size
                                childSpec.captured_process_id = child.processIdentifier
                                childSpec.captured_process_group_id =
                                    childTopology.processGroupIdentifier
                                childSpec.foreground_process_group_id =
                                    childTopology.foregroundProcessGroupIdentifier
                                childSpec.arguments = childArguments
                                childSpec.environment = childEnvironment
                                childSpec.descriptor_remaps = childRemaps.baseAddress
                                childSpec.descriptor_remap_count = childRemaps.count
                                childSpec.topology = continuum_spawn_process_topology(
                                    structure_size: UInt32(
                                        MemoryLayout<continuum_spawn_process_topology>.size
                                    ),
                                    create_session: 0,
                                    process_group_policy:
                                        childTopology.processGroupIdentifier
                                            == root.processIdentifier
                                        ? CONTINUUM_SPAWN_PROCESS_GROUP_JOIN
                                        : CONTINUUM_SPAWN_PROCESS_GROUP_CREATE,
                                    process_group_id:
                                        childTopology.processGroupIdentifier
                                            == root.processIdentifier
                                        ? root.processIdentifier : 0,
                                    controlling_terminal_descriptor: -1
                                )
                                childSpec.disable_aslr =
                                    childLaunch.addressSpacePolicy
                                        == .continuumDeterministic ? 1 : 0
                                return rootLaunch.executablePath.withCString {
                                    rootExecutable in
                                    rootLaunch.workingDirectory.withCString {
                                        rootDirectory in
                                        childLaunch.executablePath.withCString {
                                            childExecutable in
                                            childLaunch.workingDirectory.withCString {
                                                childDirectory in
                                                rootSpec.executable_path = rootExecutable
                                                rootSpec.working_directory = rootDirectory
                                                childSpec.executable_path = childExecutable
                                                childSpec.working_directory = childDirectory
                                                return bootstrapLibraryPath.withCString {
                                                    continuum_brokered_pair_prepare(
                                                        $0,
                                                        &rootSpec,
                                                        &childSpec,
                                                        &pair
                                                    )
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        try requireRuntimeOK(
            prepareStatus,
            operation: "prepare the exact parent/child launch broker"
        )
        guard let pair else {
            throw ContinuumError.restoreUnavailable(
                "The launch broker returned no prepared process pair."
            )
        }
        var rootReplacement: Int32 = 0
        var childReplacement: Int32 = 0
        let identifierStatus = continuum_brokered_pair_process_identifiers(
            pair,
            &rootReplacement,
            &childReplacement
        )
        guard identifierStatus == CONTINUUM_STATUS_OK else {
            _ = continuum_brokered_pair_abort(pair, 5_000)
            try requireRuntimeOK(
                identifierStatus,
                operation: "read the brokered process identities"
            )
            throw ContinuumError.restoreUnavailable(
                "The launch broker returned invalid process identities."
            )
        }
        let advanceStatus = continuum_brokered_pair_advance_to_entry_stops(
            pair,
            10_000
        )
        guard advanceStatus == CONTINUUM_STATUS_OK else {
            _ = continuum_brokered_pair_abort(pair, 5_000)
            try requireRuntimeOK(
                advanceStatus,
                operation: "advance the brokered process pair to entry stops"
            )
            throw ContinuumError.restoreUnavailable(
                "The launch broker did not reach its entry stops."
            )
        }

        var preparationIdentifiers: [UUID] = []
        do {
            let rootOverlay = try memberOverlay(
                root,
                image: image,
                snapshotID: snapshotID,
                repository: repository
            )
            ownsRootDescriptor = false
            let rootPreparation = try await prepareRootProcess(
                from: snapshotID,
                repository: rootOverlay,
                descriptorRemaps: rootLaunchPreparation.remaps,
                prelaunchedProcessIdentifier: rootReplacement,
                prelaunchedBootstrapDescriptor:
                    rootLaunchPreparation.descriptor,
                brokerAuthorization: .pair(
                    pair,
                    CONTINUUM_BROKERED_PROCESS_ROOT
                )
            )
            preparationIdentifiers.append(rootPreparation.id)

            let childOverlay = try memberOverlay(
                child,
                image: image,
                snapshotID: snapshotID,
                repository: repository
            )
            ownsChildDescriptor = false
            let childPreparation = try await prepareRootProcess(
                from: snapshotID,
                repository: childOverlay,
                descriptorRemaps: childLaunchPreparation.remaps,
                prelaunchedProcessIdentifier: childReplacement,
                prelaunchedBootstrapDescriptor:
                    childLaunchPreparation.descriptor,
                brokerAuthorization: .pair(
                    pair,
                    CONTINUUM_BROKERED_PROCESS_CHILD
                )
            )
            preparationIdentifiers.append(childPreparation.id)
            return (
                preparationIdentifiers,
                [
                    ColdProcessForestMember(
                        capturedProcessIdentifier: root.processIdentifier,
                        capturedParentProcessIdentifier:
                            root.parentProcessIdentifier,
                        replacementProcessIdentifier: rootReplacement,
                        replacementParentProcessIdentifier:
                            Self.parentProcessIdentifier(for: rootReplacement)
                    ),
                    ColdProcessForestMember(
                        capturedProcessIdentifier: child.processIdentifier,
                        capturedParentProcessIdentifier:
                            child.parentProcessIdentifier,
                        replacementProcessIdentifier: childReplacement,
                        replacementParentProcessIdentifier:
                            Self.parentProcessIdentifier(for: childReplacement)
                    ),
                ],
                pair
            )
        } catch {
            _ = continuum_brokered_pair_abort(pair, 5_000)
            for identifier in preparationIdentifiers.reversed() {
                try? discardBrokerAbortedReplacement(identifier)
            }
            throw error
        }
    }

    private func prepareBrokeredForest(
        orderedMembers: [DurableProcessImage],
        image: DurableCheckpointImage,
        snapshotID: SnapshotID,
        repository: any SnapshotRepository,
        descriptorGraph: PreparedDescriptorGraph
    ) async throws -> (
        preparationIdentifiers: [UUID],
        members: [ColdProcessForestMember],
        forest: OpaquePointer
    ) {
        guard let bootstrapLibraryPath else {
            throw ContinuumError.restoreUnavailable(
                "The process-forest launch broker is unavailable."
            )
        }
        let capturedIdentifiers = Set(
            orderedMembers.map(\.processIdentifier)
        )
        let roots = orderedMembers.filter {
            !capturedIdentifiers.contains($0.parentProcessIdentifier)
        }
        guard !roots.isEmpty else {
            throw ContinuumError.restoreUnavailable(
                "The captured process forest has no root."
            )
        }
        let rootBySession = Dictionary(
            uniqueKeysWithValues: roots.compactMap { root -> (Int32, Int32)? in
                guard let topology = root.topology,
                      topology.sessionIdentifier == root.processIdentifier,
                      topology.processGroupIdentifier == root.processIdentifier
                else { return nil }
                return (topology.sessionIdentifier, root.processIdentifier)
            }
        )
        guard rootBySession.count == roots.count else {
            throw ContinuumError.restoreUnavailable(
                "Every restored forest root must lead its captured session and process group."
            )
        }

        var launchPreparations: [Int32: BrokerLaunchPreparation] = [:]
        for process in orderedMembers {
            guard let launch = process.launchContract,
                  let topology = process.topology,
                  capturedIdentifiers.contains(topology.processGroupIdentifier),
                  rootBySession[topology.sessionIdentifier] != nil else {
                throw ContinuumError.restoreUnavailable(
                    "A forest member is missing a mappable launch or kernel-topology contract."
                )
            }
            launchPreparations[process.processIdentifier] =
                try makeBrokerLaunchPreparation(
                    launch: launch,
                    remaps: descriptorGraph.remapsByCapturedProcess[
                        process.processIdentifier
                    ] ?? [],
                    resourceHandles: Self.bootstrapResourceHandles(
                        in: image,
                        processIdentifier: process.processIdentifier
                    )
                )
        }
        var descriptorsOwned = Set(launchPreparations.keys)
        defer {
            for identifier in descriptorsOwned {
                if let descriptor = launchPreparations[identifier]?.descriptor {
                    Darwin.close(descriptor)
                }
            }
        }

        var allocatedStrings: [UnsafeMutablePointer<CChar>] = []
        var allocatedArrays: [UnsafeMutablePointer<UnsafePointer<CChar>?>] = []
        var allocatedRemaps: [
            UnsafeMutablePointer<continuum_spawn_descriptor_remap>
        ] = []
        defer {
            allocatedStrings.forEach { free($0) }
            allocatedArrays.forEach { $0.deallocate() }
            allocatedRemaps.forEach { $0.deallocate() }
        }
        func copiedString(_ value: String) throws -> UnsafePointer<CChar> {
            guard let copy = strdup(value) else {
                throw ContinuumError.restoreUnavailable(
                    "Continuum ran out of memory while encoding a launch contract."
                )
            }
            allocatedStrings.append(copy)
            return UnsafePointer(copy)
        }
        func copiedArray(
            _ values: [String]
        ) throws -> UnsafePointer<UnsafePointer<CChar>?> {
            let result = UnsafeMutablePointer<UnsafePointer<CChar>?>
                .allocate(capacity: values.count + 1)
            allocatedArrays.append(result)
            for (index, value) in values.enumerated() {
                result[index] = try copiedString(value)
            }
            result[values.count] = nil
            return UnsafePointer(result)
        }

        var specs: [continuum_brokered_process_spec] = []
        specs.reserveCapacity(orderedMembers.count)
        for process in orderedMembers {
            guard let launch = process.launchContract,
                  let topology = process.topology,
                  let preparation = launchPreparations[
                    process.processIdentifier
                  ] else {
                throw ContinuumError.restoreUnavailable(
                    "A forest launch contract disappeared during preparation."
                )
            }
            let isRoot = !capturedIdentifiers.contains(
                process.parentProcessIdentifier
            )
            let rootPTYSlaves = (image.ptyDescriptors ?? []).filter {
                $0.processIdentifier == process.processIdentifier
                    && $0.role == .slave
            }
            let controllingTerminalDescriptor = isRoot
                ? rootPTYSlaves.map(\.fileDescriptor).sorted().first ?? -1
                : -1
            var spec = continuum_brokered_process_spec()
            spec.structure_size = UInt32(
                MemoryLayout<continuum_brokered_process_spec>.size
            )
            spec.captured_process_id = process.processIdentifier
            spec.captured_parent_process_id = process.parentProcessIdentifier
            spec.captured_process_group_id =
                topology.processGroupIdentifier
            spec.foreground_process_group_id =
                topology.foregroundProcessGroupIdentifier
            spec.executable_path = try copiedString(launch.executablePath)
            spec.arguments = try copiedArray(launch.arguments)
            spec.environment = try copiedArray(preparation.environment)
            spec.working_directory = try copiedString(
                launch.workingDirectory
            )
            if !preparation.remaps.isEmpty {
                let remaps = UnsafeMutablePointer<
                    continuum_spawn_descriptor_remap
                >.allocate(capacity: preparation.remaps.count)
                remaps.initialize(
                    from: preparation.remaps,
                    count: preparation.remaps.count
                )
                allocatedRemaps.append(remaps)
                spec.descriptor_remaps = UnsafePointer(remaps)
            }
            spec.descriptor_remap_count = preparation.remaps.count
            spec.topology = continuum_spawn_process_topology(
                structure_size: UInt32(
                    MemoryLayout<continuum_spawn_process_topology>.size
                ),
                create_session: isRoot ? 1 : 0,
                process_group_policy:
                    topology.processGroupIdentifier == process.processIdentifier
                    ? CONTINUUM_SPAWN_PROCESS_GROUP_CREATE
                    : CONTINUUM_SPAWN_PROCESS_GROUP_JOIN,
                process_group_id:
                    topology.processGroupIdentifier == process.processIdentifier
                    ? 0 : topology.processGroupIdentifier,
                controlling_terminal_descriptor:
                    controllingTerminalDescriptor
            )
            spec.disable_aslr = launch.addressSpacePolicy
                    == .continuumDeterministic ? 1 : 0
            specs.append(spec)
        }
        var forest: OpaquePointer?
        let prepareStatus = specs.withUnsafeBufferPointer { processSpecs in
            bootstrapLibraryPath.withCString {
                continuum_brokered_forest_prepare(
                    $0,
                    processSpecs.baseAddress,
                    processSpecs.count,
                    &forest
                )
            }
        }
        if prepareStatus != CONTINUUM_STATUS_OK, let failedForest = forest {
            if continuum_brokered_forest_abort(failedForest, 5_000)
                != CONTINUUM_STATUS_OK {
                pendingBrokeredForestCleanups.append(
                    PendingBrokeredForestCleanup(handle: failedForest)
                )
            }
        }
        try requireRuntimeOK(
            prepareStatus,
            operation: "prepare the exact process-forest launch broker"
        )
        guard let forest else {
            throw ContinuumError.restoreUnavailable(
                "The launch broker returned no prepared process forest."
            )
        }

        var identities = Array(
            repeating: continuum_brokered_process_identity(),
            count: orderedMembers.count
        )
        var identityCount = 0
        let identityStatus = identities.withUnsafeMutableBufferPointer {
            continuum_brokered_forest_process_identities(
                forest,
                $0.baseAddress,
                $0.count,
                &identityCount
            )
        }
        guard identityStatus == CONTINUUM_STATUS_OK,
              identityCount == orderedMembers.count else {
            _ = continuum_brokered_forest_abort(forest, 5_000)
            try requireRuntimeOK(
                identityStatus,
                operation: "read the brokered forest identities"
            )
            throw ContinuumError.restoreUnavailable(
                "The launch broker returned an incomplete forest mapping."
            )
        }
        let replacements = Dictionary(
            uniqueKeysWithValues: identities.prefix(identityCount).map {
                ($0.captured_process_id, $0.replacement_process_id)
            }
        )
        let replacementParents = Dictionary(
            uniqueKeysWithValues: identities.prefix(identityCount).map {
                ($0.captured_process_id, $0.replacement_parent_process_id)
            }
        )
        let advanceStatus = continuum_brokered_forest_advance_to_entry_stops(
            forest,
            15_000
        )
        guard advanceStatus == CONTINUUM_STATUS_OK else {
            if advanceStatus == CONTINUUM_STATUS_ROLLBACK_FAILED,
               continuum_brokered_forest_abort(forest, 5_000)
                    != CONTINUUM_STATUS_OK {
                pendingBrokeredForestCleanups.append(
                    PendingBrokeredForestCleanup(handle: forest)
                )
            }
            try requireRuntimeOK(
                advanceStatus,
                operation: "advance the process forest to entry stops"
            )
            throw ContinuumError.restoreUnavailable(
                "The process forest did not reach its exact entry stops."
            )
        }

        var preparationIdentifiers: [UUID] = []
        var preparedMembers: [ColdProcessForestMember] = []
        do {
            for process in orderedMembers {
                guard let replacement = replacements[process.processIdentifier],
                      let replacementParent = replacementParents[
                        process.processIdentifier
                      ],
                      let launchPreparation = launchPreparations[
                        process.processIdentifier
                      ] else {
                    throw ContinuumError.integrityFailure(
                        "The replacement forest lost a process mapping."
                    )
                }
                let overlay = try memberOverlay(
                    process,
                    image: image,
                    snapshotID: snapshotID,
                    repository: repository
                )
                descriptorsOwned.remove(process.processIdentifier)
                let preparation = try await prepareRootProcess(
                    from: snapshotID,
                    repository: overlay,
                    descriptorRemaps: launchPreparation.remaps,
                    prelaunchedProcessIdentifier: replacement,
                    prelaunchedBootstrapDescriptor:
                        launchPreparation.descriptor,
                    brokerAuthorization: .forest(
                        forest,
                        process.processIdentifier
                    )
                )
                preparationIdentifiers.append(preparation.id)
                preparedMembers.append(ColdProcessForestMember(
                    capturedProcessIdentifier: process.processIdentifier,
                    capturedParentProcessIdentifier:
                        process.parentProcessIdentifier,
                    replacementProcessIdentifier: replacement,
                    replacementParentProcessIdentifier: replacementParent
                ))
            }
            return (preparationIdentifiers, preparedMembers, forest)
        } catch {
            _ = continuum_brokered_forest_abort(forest, 5_000)
            for identifier in preparationIdentifiers.reversed() {
                try? discardBrokerAbortedReplacement(identifier)
            }
            throw error
        }
    }

    private func makeBrokerLaunchPreparation(
        launch: DurableLaunchContract,
        remaps: [continuum_spawn_descriptor_remap],
        resourceHandles: BootstrapResourceHandles
    ) throws -> BrokerLaunchPreparation {
        var template = Array(
            "/private/tmp/com.midas.continuum-broker-XXXXXX".utf8CString
        )
        var descriptor = template.withUnsafeMutableBufferPointer { buffer in
            mkstemp(buffer.baseAddress)
        }
        guard descriptor >= 0 else {
            throw ContinuumError.restoreUnavailable(
                "Continuum could not create a private broker descriptor."
            )
        }
        _ = template.withUnsafeBufferPointer { buffer in
            unlink(buffer.baseAddress)
        }
        var retained = false
        defer {
            if !retained { Darwin.close(descriptor) }
        }
        let maximum = remaps.reduce(Int32(255)) {
            max($0, $1.source_descriptor, $1.target_descriptor)
        }
        if remaps.contains(where: {
            $0.source_descriptor == descriptor
                || $0.target_descriptor == descriptor
        }) {
            let relocated = fcntl(descriptor, F_DUPFD_CLOEXEC, maximum + 1)
            guard relocated >= 0 else {
                throw ContinuumError.restoreUnavailable(
                    "Continuum could not isolate its broker descriptor."
                )
            }
            Darwin.close(descriptor)
            descriptor = relocated
        }
        let plan = try Self.bootstrapDescriptorPlan(
            [],
            pipeHandles: resourceHandles.pipes,
            socketHandles: resourceHandles.sockets,
            kqueues: resourceHandles.kqueues
        )
        try Self.writeBootstrapDescriptorPlan(plan, to: descriptor)
        var brokerRemaps = remaps
        brokerRemaps.append(continuum_spawn_descriptor_remap(
            source_descriptor: descriptor,
            target_descriptor: descriptor
        ))
        var environment = launch.environment.filter {
            !$0.hasPrefix("CONTINUUM_BOOTSTRAP_STOP=")
                && !$0.hasPrefix("CONTINUUM_BOOTSTRAP_DESCRIPTOR_FD=")
                && !$0.hasPrefix("CONTINUUM_ENABLE_CHECKPOINT_SAFEPOINTS=")
                && !$0.hasPrefix("CONTINUUM_BROKER_")
        }
        environment.append("CONTINUUM_BOOTSTRAP_STOP=1")
        environment.append("CONTINUUM_BOOTSTRAP_DESCRIPTOR_FD=\(descriptor)")
        retained = true
        return BrokerLaunchPreparation(
            descriptor: descriptor,
            remaps: brokerRemaps,
            environment: environment
        )
    }

    private func memberOverlay(
        _ process: DurableProcessImage,
        image: DurableCheckpointImage,
        snapshotID: SnapshotID,
        repository: any SnapshotRepository
    ) throws -> ManifestOverlayRepository {
        let memberImage = DurableCheckpointImage(
            checkpointID: image.checkpointID,
            createdAt: image.createdAt,
            architecture: image.architecture,
            operatingSystemBuild: image.operatingSystemBuild,
            pageSize: image.pageSize,
            rootProcessIdentifier: process.processIdentifier,
            app: image.app,
            members: [process],
            writableFiles: image.writableFiles,
            writableFileDescriptors: image.writableFileDescriptors.filter {
                $0.processIdentifier == process.processIdentifier
            },
            descriptorGraph: image.descriptorGraph
        )
        return ManifestOverlayRepository(
            base: repository,
            snapshotID: snapshotID,
            manifestData: try JSONEncoder().encode(memberImage)
        )
    }

    public func waitUntilTerminalPresentationReady(
        _ sessionIdentifier: UUID,
        timeout: Duration = .seconds(5)
    ) async throws {
        guard let terminalPresentationRegistry else {
            throw ContinuumError.restoreUnavailable(
                "Continuum's terminal presentation service is unavailable."
            )
        }
        try await terminalPresentationRegistry.waitUntilReady(
            sessionIdentifier,
            timeout: timeout
        )
    }

    public func discardProcessForest(_ forestID: UUID) async throws {
        retryPendingBrokeredForestCleanups()
        guard let forest = preparedForests[forestID] else {
            return
        }
        var firstError: Error?
        if let pair = forest.brokeredPair {
            let status = continuum_brokered_pair_abort(pair, 5_000)
            if status != CONTINUUM_STATUS_OK {
                firstError = ContinuumError.restoreUnavailable(
                    "Continuum could not abort the brokered replacement forest."
                )
            }
        }
        if let brokeredForest = forest.brokeredForest {
            let status = continuum_brokered_forest_abort(
                brokeredForest,
                5_000
            )
            guard status == CONTINUUM_STATUS_OK else {
                throw ContinuumError.restoreUnavailable(
                    "Continuum could not abort the brokered replacement forest."
                )
            }
        }
        preparedForests.removeValue(forKey: forestID)
        for preparationIdentifier in forest.preparationIdentifiers.reversed() {
            do {
                if forest.brokeredPair == nil
                    && forest.brokeredForest == nil {
                    try discard(preparationIdentifier)
                } else {
                    try discardBrokerAbortedReplacement(preparationIdentifier)
                }
            } catch where firstError == nil {
                firstError = error
            } catch {}
        }
        for sessionIdentifier in forest.terminalPresentationSessionIdentifiers {
            do {
                try await terminalPresentationRegistry?.discard(sessionIdentifier)
            } catch where firstError == nil {
                firstError = error
            } catch {}
        }
        if let firstError { throw firstError }
    }

    private func retryPendingBrokeredForestCleanups() {
        pendingBrokeredForestCleanups.removeAll { pending in
            continuum_brokered_forest_abort(pending.handle, 5_000)
                == CONTINUUM_STATUS_OK
        }
    }

    public func commitProcessForest(
        _ forestID: UUID
    ) async throws -> ColdProcessForestCommit {
        guard let forest = preparedForests[forestID] else {
            throw ContinuumError.restoreUnavailable(
                "The prepared process forest no longer exists."
            )
        }
        var committedProcessIdentifiers: [Int32] = []
        do {
            if let brokeredForest = forest.brokeredForest {
                try requireRuntimeOK(
                    continuum_brokered_forest_begin_commit(brokeredForest),
                    operation: "hold the reconstructed forest transaction"
                )
            }
            for preparationIdentifier in forest.preparationIdentifiers.reversed() {
                let committed = try commit(preparationIdentifier)
                committedProcessIdentifiers.append(committed.processIdentifier)
                if let pair = forest.brokeredPair {
                    try requireRuntimeOK(
                        continuum_brokered_pair_note_released_process(
                            pair,
                            committed.processIdentifier
                        ),
                        operation: "record the brokered replacement release"
                    )
                }
                if let brokeredForest = forest.brokeredForest {
                    try requireRuntimeOK(
                        continuum_brokered_forest_note_released_process(
                            brokeredForest,
                            committed.processIdentifier
                        ),
                        operation: "record the brokered forest replacement release"
                    )
                }
            }
            for sessionIdentifier in forest.terminalPresentationSessionIdentifiers {
                try await terminalPresentationRegistry?.promote(sessionIdentifier)
            }
            if let pair = forest.brokeredPair {
                try requireRuntimeOK(
                    continuum_brokered_pair_finish(pair),
                    operation: "finish the brokered replacement forest"
                )
            }
            if let brokeredForest = forest.brokeredForest {
                try requireRuntimeOK(
                    continuum_brokered_forest_finish(brokeredForest),
                    operation: "finish the brokered replacement forest"
                )
            }
        } catch {
            if let pair = forest.brokeredPair {
                _ = continuum_brokered_pair_abort(pair, 5_000)
            } else if let brokeredForest = forest.brokeredForest {
                _ = continuum_brokered_forest_abort(
                    brokeredForest,
                    5_000
                )
            } else {
                for processIdentifier in committedProcessIdentifiers {
                    _ = Self.killAndReap(processIdentifier)
                }
            }
            for preparationIdentifier in forest.preparationIdentifiers.reversed() {
                if forest.brokeredPair == nil
                    && forest.brokeredForest == nil {
                    try? discard(preparationIdentifier)
                } else {
                    try? discardBrokerAbortedReplacement(preparationIdentifier)
                }
            }
            for sessionIdentifier in forest.terminalPresentationSessionIdentifiers {
                try? await terminalPresentationRegistry?.discard(sessionIdentifier)
            }
            preparedForests.removeValue(forKey: forestID)
            throw error
        }
        preparedForests.removeValue(forKey: forestID)
        guard let rootProcessIdentifier = forest.members.first(where: {
            $0.capturedProcessIdentifier == forest.rootCapturedProcessIdentifier
        })?.replacementProcessIdentifier else {
            for processIdentifier in committedProcessIdentifiers {
                _ = Self.killAndReap(processIdentifier)
            }
            throw ContinuumError.integrityFailure(
                "The committed process forest lost its root mapping."
            )
        }
        return ColdProcessForestCommit(
            rootProcessIdentifier: rootProcessIdentifier,
            processIdentifiers: committedProcessIdentifiers
        )
    }

    public func prepareRootProcess(
        from snapshotID: SnapshotID,
        repository: any SnapshotRepository
    ) async throws -> ColdProcessPreparation {
        try await prepareRootProcess(
            from: snapshotID,
            repository: repository,
            descriptorRemaps: []
        )
    }

    private func prepareRootProcess(
        from snapshotID: SnapshotID,
        repository: any SnapshotRepository,
        descriptorRemaps: [continuum_spawn_descriptor_remap],
        prelaunchedProcessIdentifier: Int32? = nil,
        prelaunchedBootstrapDescriptor: Int32? = nil,
        brokerAuthorization: BrokerSessionAuthorization? = nil
    ) async throws -> ColdProcessPreparation {
        defer {
            if let prelaunchedBootstrapDescriptor {
                Darwin.close(prelaunchedBootstrapDescriptor)
            }
        }
        let manifest = try await repository.artifact(
            for: snapshotID,
            logicalName: "durable-checkpoint-v3.json"
        )
        let image: DurableCheckpointImage
        do {
            image = try JSONDecoder().decode(
                DurableCheckpointImage.self,
                from: manifest.data
            )
        } catch {
            throw ContinuumError.integrityFailure(
                "The durable checkpoint manifest is invalid."
            )
        }
        try validate(image)

        guard let process = image.members.first(where: {
            $0.processIdentifier == image.rootProcessIdentifier
        }), let launch = process.launchContract else {
            throw ContinuumError.restoreUnavailable(
                "The root process relaunch contract is missing."
            )
        }
        let usesDeterministicAddressSpace =
            launch.addressSpacePolicy == .continuumDeterministic
        try validateExecutable(process: process, launch: launch)
        guard let bootstrapLibraryPath,
              FileManager.default.fileExists(atPath: bootstrapLibraryPath) else {
            throw ContinuumError.restoreUnavailable(
                "Continuum's pre-main restore bootstrap is missing."
            )
        }
        // A safepoint is required for every armed process, including command-
        // line helpers. It does not by itself make a process a GUI. Only a
        // process whose captured image contains derived graphics mappings must
        // take the AppKit/WindowServer rehydration route; ordinary helpers use
        // the full pre-main memory and thread reconstruction path.
        if process.regions.contains(where: {
            $0.preservesLiveDerivedGraphics == true
        }) {
            guard descriptorRemaps.isEmpty else {
                throw ContinuumError.restoreUnavailable(
                    "A derived GUI process still owns a live stream that Continuum cannot reconnect yet."
                )
            }
            return try await prepareRehydratedRootProcess(
                process: process,
                launch: launch,
                snapshotID: snapshotID,
                repository: repository,
                bootstrapLibraryPath: bootstrapLibraryPath,
                usesDeterministicAddressSpace: usesDeterministicAddressSpace
            )
        }
        guard image.members.allSatisfy({
            Self.processIsAbsent($0.processIdentifier)
        }) else {
            throw ContinuumError.restoreUnavailable(
                "Cold restoration requires the captured process tree to be fully exited."
            )
        }

        let descriptorDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                "com.midas.continuum-bootstrap-\(UUID().uuidString)",
                isDirectory: true
            )
        let descriptorURL = descriptorDirectory
            .appendingPathComponent("descriptor", isDirectory: false)
        defer {
            try? FileManager.default.removeItem(at: descriptorDirectory)
        }
        var descriptor: Int32
        if let prelaunchedBootstrapDescriptor {
            guard prelaunchedProcessIdentifier != nil,
                  prelaunchedBootstrapDescriptor >= 0 else {
                throw ContinuumError.restoreUnavailable(
                    "The brokered replacement has no private bootstrap descriptor."
                )
            }
            descriptor = prelaunchedBootstrapDescriptor
        } else {
            do {
            try FileManager.default.createDirectory(
                at: descriptorDirectory,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: NSNumber(value: 0o700)]
            )
            descriptor = descriptorURL.path.withCString {
                Darwin.open(
                    $0,
                    O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW,
                    S_IRUSR | S_IWUSR
                )
            }
            let unlinkResult = descriptorURL.path.withCString { Darwin.unlink($0) }
            guard descriptor >= 0, unlinkResult == 0 else {
                if descriptor >= 0 {
                    Darwin.close(descriptor)
                }
                throw ContinuumError.restoreUnavailable(
                    "Continuum could not create its private bootstrap descriptor."
                )
            }
            } catch let error as ContinuumError {
                throw error
            } catch {
                throw ContinuumError.restoreUnavailable(
                    "Continuum could not create its private bootstrap descriptor."
                )
            }
        }
        defer {
            if prelaunchedBootstrapDescriptor == nil {
                Darwin.close(descriptor)
            }
        }

        if prelaunchedBootstrapDescriptor == nil,
           descriptorRemaps.contains(where: {
            $0.source_descriptor == descriptor
                || $0.target_descriptor == descriptor
        }) {
            let maximumRemapDescriptor = descriptorRemaps.reduce(Int32(255)) {
                max($0, $1.source_descriptor, $1.target_descriptor)
            }
            let relocated = fcntl(
                descriptor,
                F_DUPFD_CLOEXEC,
                maximumRemapDescriptor + 1
            )
            guard relocated >= 0 else {
                throw ContinuumError.restoreUnavailable(
                    "Continuum could not isolate its private bootstrap descriptor from restored descriptors."
                )
            }
            Darwin.close(descriptor)
            descriptor = relocated
        }

        // File state is intentionally outside the cold-rewind boundary.
        // Recreating captured writable descriptors would couple a process
        // restore to stale vnode identities and can mutate current files.
        let rootDescriptors: [DurableWritableFileDescriptor] = []
        let resourceHandles = Self.bootstrapResourceHandles(
            in: image,
            processIdentifier: process.processIdentifier
        )
        if prelaunchedBootstrapDescriptor == nil {
            let descriptorPlan = try Self.bootstrapDescriptorPlan(
                rootDescriptors,
                pipeHandles: resourceHandles.pipes,
                socketHandles: resourceHandles.sockets,
                kqueues: resourceHandles.kqueues
            )
            try Self.writeBootstrapDescriptorPlan(
                descriptorPlan,
                to: descriptor
            )
        }

        var localBootstrapIdentity = continuum_bootstrap_identity()
        try requireRuntimeOK(
            bootstrapLibraryPath.withCString {
                continuum_inspect_local_bootstrap_library(
                    $0,
                    &localBootstrapIdentity
                )
            },
            operation: "authenticate Continuum's restore bootstrap"
        )
        var environment = launch.environment.filter {
            !$0.hasPrefix("CONTINUUM_BOOTSTRAP_STOP=")
                && !$0.hasPrefix("CONTINUUM_BOOTSTRAP_DESCRIPTOR_PATH=")
                && !$0.hasPrefix("CONTINUUM_BOOTSTRAP_DESCRIPTOR_FD=")
                && !$0.hasPrefix("CONTINUUM_ENABLE_CHECKPOINT_SAFEPOINTS=")
                && !$0.hasPrefix("DYLD_INSERT_LIBRARIES=")
                && (!usesDeterministicAddressSpace
                    || (!$0.hasPrefix("DYLD_SHARED_REGION=")
                        && !$0.hasPrefix("CONTINUUM_DETERMINISTIC_ADDRESS_SPACE=")
                        && !$0.hasPrefix("MallocLargeCache=")))
        }
        var insertedLibraries = launch.environment.first(where: {
            $0.hasPrefix("DYLD_INSERT_LIBRARIES=")
        }).map {
            String($0.dropFirst("DYLD_INSERT_LIBRARIES=".count))
                .split(separator: ":")
                .map(String.init)
        } ?? []
        let bootstrapName = URL(fileURLWithPath: bootstrapLibraryPath)
            .lastPathComponent
        insertedLibraries.removeAll {
            URL(fileURLWithPath: $0).lastPathComponent == bootstrapName
        }
        insertedLibraries.append(bootstrapLibraryPath)
        if usesDeterministicAddressSpace {
            environment.append("DYLD_SHARED_REGION=private")
            environment.append("CONTINUUM_DETERMINISTIC_ADDRESS_SPACE=1")
            environment.append("MallocLargeCache=0")
        }
        environment.append("CONTINUUM_BOOTSTRAP_STOP=1")
        environment.append(
            "CONTINUUM_BOOTSTRAP_DESCRIPTOR_FD=\(descriptor)"
        )
        environment.append(
            "DYLD_INSERT_LIBRARIES=\(insertedLibraries.joined(separator: ":"))"
        )

        var replacementProcessIdentifier = prelaunchedProcessIdentifier ?? 0
        let spawnStatus: continuum_status = prelaunchedProcessIdentifier == nil
            ? descriptorRemaps.withUnsafeBufferPointer { remaps in
            Self.withCStringArray(launch.arguments) { arguments in
                Self.withCStringArray(environment) { environmentEntries in
                    launch.executablePath.withCString { executable in
                        launch.workingDirectory.withCString { directory in
                            if usesDeterministicAddressSpace {
                                continuum_spawn_process_suspended_with_inherited_descriptor_and_remaps(
                                    executable,
                                    arguments,
                                    environmentEntries,
                                    directory,
                                    descriptor,
                                    remaps.baseAddress,
                                    remaps.count,
                                    &replacementProcessIdentifier
                                )
                            } else {
                                continuum_spawn_process_suspended_with_inherited_descriptor_and_remaps_system_aslr(
                                    executable,
                                    arguments,
                                    environmentEntries,
                                    directory,
                                    descriptor,
                                    remaps.baseAddress,
                                    remaps.count,
                                    &replacementProcessIdentifier
                                )
                            }
                        }
                    }
                }
            }
            } : CONTINUUM_STATUS_OK
        try requireRuntimeOK(spawnStatus, operation: "launch a cold replacement")

        var session: OpaquePointer?
        var retained = false
        defer {
            if !retained {
                _ = Self.killAndReap(replacementProcessIdentifier)
                if let session {
                    continuum_remote_session_destroy(session)
                }
            }
        }
        if prelaunchedProcessIdentifier == nil {
            try requireRuntimeOK(
                continuum_advance_process_to_entry_stop(
                    replacementProcessIdentifier,
                    5_000
                ),
                operation: "reach Continuum's executable-entry restore boundary"
            )
        }
        var bootstrapIdentity = try Self.bootstrapIdentity(
            from: descriptor,
            expectedProcessIdentifier: replacementProcessIdentifier,
            localIdentity: localBootstrapIdentity,
            expectedRestoredDescriptorCount:
                rootDescriptors.count + resourceHandles.pipes.count
                    + resourceHandles.sockets.count
                    + resourceHandles.kqueues.count
        )
        try requireRuntimeOK(
            continuum_remote_session_open(replacementProcessIdentifier, &session),
            operation: "open the cold replacement task"
        )
        guard let session else {
            throw ContinuumError.restoreUnavailable(
                "The replacement process did not expose a task session."
            )
        }
        if let brokerAuthorization {
            let authorizationStatus: continuum_status
            switch brokerAuthorization {
            case let .pair(pair, role):
                authorizationStatus =
                    continuum_brokered_pair_authorize_remote_session(
                        pair,
                        session,
                        role
                    )
            case let .forest(forest, capturedProcessIdentifier):
                authorizationStatus =
                    continuum_brokered_forest_authorize_remote_session(
                        forest,
                        session,
                        capturedProcessIdentifier
                    )
            }
            try requireRuntimeOK(
                authorizationStatus,
                operation: "authorize the brokered replacement stop"
            )
        }
        try requireRuntimeOK(
            bootstrapLibraryPath.withCString {
                continuum_remote_session_set_bootstrap_copy_identity(
                    session,
                    &bootstrapIdentity,
                    $0
                )
            },
            operation: "validate Continuum's in-process reconstruction entry"
        )

        var replacementLayout = continuum_remote_process_layout_info()
        try requireRuntimeOK(
            continuum_remote_session_inspect_process_layout(
                session,
                &replacementLayout
            ),
            operation: "validate the replacement address space"
        )
        guard let immutableLayoutDigest = process.immutableLayoutDigest,
              immutableLayoutDigest.count == 64 else {
            throw ContinuumError.restoreUnavailable(
                "This checkpoint predates immutable address-space validation."
            )
        }
        guard Self.hexDigest(replacementLayout.immutable_layout_digest)
                == immutableLayoutDigest else {
            throw ContinuumError.restoreUnavailable(
                "The replacement executable and shared-library layout does not match the captured process."
            )
        }

        guard !process.threads.contains(where: {
            $0.origin == nil || $0.origin == .unknown
        }) else {
            throw ContinuumError.restoreUnavailable(
                "This snapshot contains a thread whose origin cannot be reconstructed safely."
            )
        }
        guard !process.threads.contains(where: {
            $0.origin == .workqueue
                && $0.preservesKernelContinuation != true
        }) else {
            throw ContinuumError.restoreUnavailable(
                "A workqueue thread was executing user code when this snapshot was taken."
            )
        }
        let reconstructedThreads = process.threads.filter {
            $0.origin != .workqueue
        }
        let savedPthreads = process.threads.filter { $0.origin == .pthread }
        guard !savedPthreads.isEmpty else {
            throw ContinuumError.restoreUnavailable(
                "The durable process image does not identify its primary pthread."
            )
        }
        let pthreadGeometry = try savedPthreads.map { thread in
            guard let pthreadAddress = thread.pthreadObjectAddress,
                  let stackPointer = thread.stackPointer,
                  let stackRegionAddress = thread.stackRegionAddress,
                  let stackRegionLength = thread.stackRegionLength,
                  let pthreadRegionAddress = thread.pthreadRegionAddress,
                  let pthreadRegionLength = thread.pthreadRegionLength else {
                throw ContinuumError.restoreUnavailable(
                    "A captured pthread is missing exact stack geometry."
                )
            }
            return continuum_saved_pthread_geometry(
                saved_thread_identifier: thread.threadIdentifier,
                pthread_address: pthreadAddress,
                stack_pointer: stackPointer,
                stack_region_address: stackRegionAddress,
                stack_region_length: stackRegionLength,
                pthread_region_address: pthreadRegionAddress,
                pthread_region_length: pthreadRegionLength
            )
        }
        var pthreadBootstrap = continuum_remote_pthread_bootstrap_report()
        try requireRuntimeOK(
            continuum_remote_session_prepare_suspended_pthreads(
                session,
                UInt32(savedPthreads.count - 1),
                &pthreadBootstrap
            ),
            operation: "prepare the replacement pthread set"
        )
        var pthreadPlan = continuum_pthread_reconstruction_plan()
        let planStatus = pthreadGeometry.withUnsafeBufferPointer { geometry in
            continuum_plan_exact_pthread_reconstruction(
                geometry.baseAddress,
                geometry.count,
                &pthreadBootstrap,
                &pthreadPlan
            )
        }
        try requireRuntimeOK(
            planStatus,
            operation: "match captured pthread stacks to the replacement"
        )
        var planTuple = pthreadPlan.entries
        let pthreadPlanEntries = withUnsafeBytes(of: &planTuple) { bytes in
            Array(
                bytes.bindMemory(
                    to: continuum_pthread_reconstruction_plan_entry.self
                ).prefix(Int(pthreadPlan.entry_count))
            )
        }
        guard pthreadPlanEntries.count == savedPthreads.count else {
            throw ContinuumError.integrityFailure(
                "The replacement pthread plan is incomplete."
            )
        }

        var reconstructedRegionCount = 0
        var reconstructedChunkCount = 0
        var reconstructedBytes: UInt64 = 0
        var deferredMaximumProtectionRegionCount = 0

        for region in process.regions.sorted(by: { $0.address < $1.address }) {
            if region.preservesLiveDerivedGraphics == true {
                continue
            }
            if process.threads.contains(where: { thread in
                guard thread.origin == .workqueue else { return false }
                return (thread.stackRegionAddress == region.address
                        && thread.stackRegionLength == region.length)
                    || (thread.pthreadRegionAddress == region.address
                        && thread.pthreadRegionLength == region.length)
            }) {
                continue
            }
            if Self.regionIntersectsPreparedPthread(
                region,
                entries: pthreadPlanEntries
            ) {
                let result = try await restorePreparedPthreadRegion(
                    region,
                    entries: pthreadPlanEntries,
                    session: session,
                    processIdentifier: process.processIdentifier,
                    snapshotID: snapshotID,
                    repository: repository
                )
                let (nextChunkCount, chunkCountOverflow) =
                    reconstructedChunkCount.addingReportingOverflow(
                        result.chunkCount
                    )
                let (nextByteCount, byteCountOverflow) =
                    reconstructedBytes.addingReportingOverflow(
                        result.writtenBytes
                    )
                let (nextRegionCount, regionCountOverflow) =
                    reconstructedRegionCount.addingReportingOverflow(1)
                guard !chunkCountOverflow, !byteCountOverflow,
                      !regionCountOverflow else {
                    throw ContinuumError.integrityFailure(
                        "The durable pthread image exceeds Continuum's numeric limits."
                    )
                }
                reconstructedChunkCount = nextChunkCount
                reconstructedBytes = nextByteCount
                reconstructedRegionCount = nextRegionCount
                continue
            }
            var runtimeRegion = continuum_remote_process_region_info()
            runtimeRegion.address = region.address
            runtimeRegion.length = region.length
            runtimeRegion.protection = region.protection
            runtimeRegion.maximum_protection = region.maximumProtection
            runtimeRegion.inheritance = region.inheritance
            runtimeRegion.share_mode = region.shareMode
            runtimeRegion.user_tag = region.userTag

            var report = continuum_remote_restore_report()
            try requireRuntimeOK(
                continuum_remote_session_begin_reconstruct_region(
                    session,
                    &runtimeRegion,
                    &report
                ),
                operation: reconstructionOperation("prepare", region: region, report: report)
            )

            var offset: UInt64 = 0
            for chunk in region.chunks {
                guard chunk.logicalBytes > 0,
                      chunk.logicalBytes <= 1_024 * 1_024,
                      offset <= region.length,
                      chunk.logicalBytes <= region.length - offset else {
                    throw ContinuumError.integrityFailure(
                        "Memory chunks exceed Continuum's one-megabyte policy or the captured mapping at 0x\(String(region.address, radix: 16))."
                    )
                }
                let logicalName = chunk.artifactName
                    ?? Self.legacyMemoryArtifactName(
                        processIdentifier: process.processIdentifier,
                        address: region.address,
                        offset: offset
                    )
                let artifact = try await repository.artifact(
                    for: snapshotID,
                    logicalName: logicalName
                )
                guard artifact.kind == .memoryPage,
                      UInt64(artifact.data.count) == chunk.logicalBytes,
                      Self.sha256(artifact.data) == chunk.hash else {
                    throw ContinuumError.integrityFailure(
                        "Memory chunk \(logicalName) does not match its manifest."
                    )
                }
                let writeStatus = artifact.data.withUnsafeBytes { bytes in
                    continuum_remote_session_write_reconstructed_region(
                        session,
                        &runtimeRegion,
                        offset,
                        bytes.baseAddress,
                        bytes.count,
                        &report
                    )
                }
                try requireRuntimeOK(
                    writeStatus,
                    operation: reconstructionOperation(
                        "write",
                        region: region,
                        report: report
                    )
                )
                guard report.readback_verified != 0,
                      report.bytes_written == chunk.logicalBytes else {
                    throw ContinuumError.integrityFailure(
                        "Memory chunk \(logicalName) failed readback verification."
                    )
                }
                offset += chunk.logicalBytes
                let (nextChunkCount, chunkCountOverflow) =
                    reconstructedChunkCount.addingReportingOverflow(1)
                let (nextByteCount, byteCountOverflow) =
                    reconstructedBytes.addingReportingOverflow(chunk.logicalBytes)
                guard !chunkCountOverflow, !byteCountOverflow else {
                    throw ContinuumError.integrityFailure(
                        "The durable memory manifest exceeds Continuum's numeric limits."
                    )
                }
                reconstructedChunkCount = nextChunkCount
                reconstructedBytes = nextByteCount
            }
            guard offset == region.length else {
                throw ContinuumError.integrityFailure(
                    "Memory mapping at 0x\(String(region.address, radix: 16)) is incomplete."
                )
            }

            try requireRuntimeOK(
                continuum_remote_session_finish_reconstruct_region(
                    session,
                    &runtimeRegion,
                    &report
                ),
                operation: reconstructionOperation("protect", region: region, report: report)
            )
            if report.max_protection_verified == 0 {
                guard report.reconstruction_stage
                        == CONTINUUM_RECONSTRUCTION_STAGE_MAX_PROTECT.rawValue,
                      report.mach_result == KERN_PROTECTION_FAILURE else {
                    throw ContinuumError.restoreUnavailable(
                        "The replacement mapping protection could not be verified."
                    )
                }
                let (nextDeferredCount, deferredCountOverflow) =
                    deferredMaximumProtectionRegionCount.addingReportingOverflow(1)
                guard !deferredCountOverflow else {
                    throw ContinuumError.integrityFailure(
                        "The durable memory manifest contains too many deferred protections."
                    )
                }
                deferredMaximumProtectionRegionCount = nextDeferredCount
            }
            let (nextRegionCount, regionCountOverflow) =
                reconstructedRegionCount.addingReportingOverflow(1)
            guard !regionCountOverflow else {
                throw ContinuumError.integrityFailure(
                    "The durable memory manifest contains too many mappings."
                )
            }
            reconstructedRegionCount = nextRegionCount
        }

        guard !reconstructedThreads.isEmpty else {
            throw ContinuumError.restoreUnavailable(
                "The durable process image contains no captured threads."
            )
        }
        var threadInputs: [continuum_remote_thread_reconstruction_input] = []
        threadInputs.reserveCapacity(reconstructedThreads.count)
        var threadStateAllocations: [UnsafeMutableRawPointer] = []
        threadStateAllocations.reserveCapacity(reconstructedThreads.count * 2)
        defer {
            for pointer in threadStateAllocations {
                pointer.deallocate()
            }
        }
        var threadStateBytes: UInt64 = 0
        for thread in reconstructedThreads {
            let generalState = try await threadStateData(
                thread.generalState,
                fallbackName: "threads/\(process.processIdentifier)/\(thread.threadIdentifier)-general.bin",
                snapshotID: snapshotID,
                repository: repository
            )
            let vectorState = try await threadStateData(
                thread.vectorState,
                fallbackName: "threads/\(process.processIdentifier)/\(thread.threadIdentifier)-vector.bin",
                snapshotID: snapshotID,
                repository: repository
            )
            guard !generalState.isEmpty, !vectorState.isEmpty else {
                throw ContinuumError.integrityFailure(
                    "A durable thread image contains an empty register bank."
                )
            }

            let generalPointer = UnsafeMutableRawPointer.allocate(
                byteCount: generalState.count,
                alignment: 16
            )
            generalState.copyBytes(
                to: generalPointer.assumingMemoryBound(to: UInt8.self),
                count: generalState.count
            )
            threadStateAllocations.append(generalPointer)
            let vectorPointer = UnsafeMutableRawPointer.allocate(
                byteCount: vectorState.count,
                alignment: 16
            )
            vectorState.copyBytes(
                to: vectorPointer.assumingMemoryBound(to: UInt8.self),
                count: vectorState.count
            )
            threadStateAllocations.append(vectorPointer)

            var input = continuum_remote_thread_reconstruction_input()
            input.saved_thread_identifier = thread.threadIdentifier
            if let pthreadEntry = pthreadPlanEntries.first(where: {
                $0.saved_thread_identifier == thread.threadIdentifier
            }) {
                input.thread_handle = pthreadEntry.replacement_thread_handle
                input.dispatch_queue_address = 0
            } else {
                input.thread_handle = 0
                input.dispatch_queue_address = 0
            }
            input.general_state_flavor = thread.generalStateFlavor
            input.general_state = UnsafeRawPointer(generalPointer)
            input.general_state_length = generalState.count
            input.vector_state_flavor = thread.vectorStateFlavor
            input.vector_state = UnsafeRawPointer(vectorPointer)
            input.vector_state_length = vectorState.count
            threadInputs.append(input)

            let (afterGeneral, generalOverflow) = threadStateBytes
                .addingReportingOverflow(UInt64(generalState.count))
            let (afterVector, vectorOverflow) = afterGeneral
                .addingReportingOverflow(UInt64(vectorState.count))
            guard !generalOverflow, !vectorOverflow else {
                throw ContinuumError.integrityFailure(
                    "The durable thread image exceeds Continuum's numeric limits."
                )
            }
            threadStateBytes = afterVector
        }

        var threadReport =
            continuum_remote_thread_set_reconstruction_report()
        let threadStatus = threadInputs.withUnsafeBufferPointer { inputs in
            continuum_remote_session_reconstruct_prepared_thread_set(
                session,
                inputs.baseAddress,
                inputs.count,
                &threadReport
            )
        }
        if threadStatus != CONTINUUM_STATUS_OK {
            let detail = continuum_status_string(threadStatus).map {
                String(cString: $0)
            } ?? "status \(threadStatus.rawValue)"
            guard threadReport.validation_kind == 1
                    || threadReport.validation_kind == 2 else {
                throw ContinuumError.restoreUnavailable(
                    "Could not reconstruct the captured thread set: \(detail)."
                )
            }
            let register = threadReport.validation_kind == 1 ? "PC" : "SP"
            throw ContinuumError.restoreUnavailable(
                "Could not reconstruct captured thread \(threadReport.validation_thread_index): \(register) address 0x\(String(threadReport.validation_address, radix: 16)) failed validation (\(detail))."
            )
        }
        let expectedRawThreadCount = reconstructedThreads.count
            - savedPthreads.count
        let reportedStateBytes = threadReport.general_state_bytes
            .addingReportingOverflow(threadReport.vector_state_bytes)
        guard threadReport.all_states_verified != 0,
              threadReport.reconstructed_thread_count
                == UInt64(reconstructedThreads.count),
              threadReport.created_raw_thread_count
                == UInt64(expectedRawThreadCount),
              !reportedStateBytes.overflow,
              reportedStateBytes.partialValue == threadStateBytes,
              threadReport.primary_replacement_thread_identifier != 0 else {
            throw ContinuumError.integrityFailure(
                "The replacement thread set did not match the captured register images."
            )
        }

        let fileRollback: PreparedFileRollback? = nil
        let preparationID = UUID()
        preparedReplacements[preparationID] = PreparedReplacement(
            processIdentifier: replacementProcessIdentifier,
            session: session,
            fileRollback: fileRollback,
            requiresSafepointRelease: reconstructedThreads.contains {
                $0.isUserspaceSafepoint == true
            },
            resumeMethod: .entryStop
        )
        retained = true
        return ColdProcessPreparation(
            id: preparationID,
            replacementProcessIdentifier: replacementProcessIdentifier,
            capturedProcessIdentifier: process.processIdentifier,
            reconstructedRegionCount: reconstructedRegionCount,
            reconstructedChunkCount: reconstructedChunkCount,
            reconstructedBytes: reconstructedBytes,
            deferredMaximumProtectionRegionCount: deferredMaximumProtectionRegionCount,
            reconstructedThreadCount: reconstructedThreads.count,
            reconstructedThreadStateBytes: threadStateBytes,
            replacementThreadIdentifier:
                threadReport.primary_replacement_thread_identifier,
            reconstructedFileDescriptorCount:
                rootDescriptors.count + descriptorRemaps.count,
            reconstructedFileCount: fileRollback?.replacedFileCount ?? 0,
            reconstructedFileBytes: fileRollback?.replacedBytes ?? 0
        )
    }

    /// GUI processes cannot transplant AppKit, WindowServer, or GPU-owned
    /// heaps into a new PID. Launch the app normally to rebuild those graphs,
    /// stop at the bootstrap's first idle main-run-loop boundary, and replace
    /// only pages owned by Continuum's isolated app-state zone.
    private func prepareRehydratedRootProcess(
        process: DurableProcessImage,
        launch: DurableLaunchContract,
        snapshotID: SnapshotID,
        repository: any SnapshotRepository,
        bootstrapLibraryPath: String,
        usesDeterministicAddressSpace: Bool
    ) async throws -> ColdProcessPreparation {
        let appStateRegions = process.regions.filter {
            $0.isAppOwnedState == true
                && $0.preservesLiveDerivedGraphics != true
        }
        guard !appStateRegions.isEmpty else {
            throw ContinuumError.restoreUnavailable(
                "This GUI snapshot has no isolated app-owned RAM to transplant safely."
            )
        }
        guard appStateRegions.contains(where: {
            $0.userTag == Self.appStatePayloadUserTag
        }) else {
            throw ContinuumError.restoreUnavailable(
                "This GUI snapshot has no isolated app-owned RAM payload."
            )
        }
        guard appStateRegions.filter({
            $0.userTag == Self.appStateMetadataUserTag
        }).count == 1 else {
            throw ContinuumError.restoreUnavailable(
                "This snapshot predates Continuum's durable allocator metadata. Save a new snapshot before quitting the app."
            )
        }

        var environment = launch.environment.filter {
            !$0.hasPrefix("CONTINUUM_BOOTSTRAP_STOP=")
                && !$0.hasPrefix("CONTINUUM_BOOTSTRAP_REHYDRATE_STOP=")
                && !$0.hasPrefix("CONTINUUM_BOOTSTRAP_DESCRIPTOR_PATH=")
                && !$0.hasPrefix("CONTINUUM_BOOTSTRAP_DESCRIPTOR_FD=")
                && !$0.hasPrefix("CONTINUUM_ENABLE_CHECKPOINT_SAFEPOINTS=")
                && !$0.hasPrefix("DYLD_INSERT_LIBRARIES=")
                && (!usesDeterministicAddressSpace
                    || (!$0.hasPrefix("DYLD_SHARED_REGION=")
                        && !$0.hasPrefix("CONTINUUM_DETERMINISTIC_ADDRESS_SPACE=")
                        && !$0.hasPrefix("MallocLargeCache=")))
        }
        var insertedLibraries = launch.environment.first(where: {
            $0.hasPrefix("DYLD_INSERT_LIBRARIES=")
        }).map {
            String($0.dropFirst("DYLD_INSERT_LIBRARIES=".count))
                .split(separator: ":")
                .map(String.init)
        } ?? []
        let bootstrapName = URL(fileURLWithPath: bootstrapLibraryPath)
            .lastPathComponent
        insertedLibraries.removeAll {
            URL(fileURLWithPath: $0).lastPathComponent == bootstrapName
        }
        insertedLibraries.append(bootstrapLibraryPath)
        if usesDeterministicAddressSpace {
            environment.append("DYLD_SHARED_REGION=private")
            environment.append("CONTINUUM_DETERMINISTIC_ADDRESS_SPACE=1")
            environment.append("MallocLargeCache=0")
        }
        environment.append("CONTINUUM_ENABLE_CHECKPOINT_SAFEPOINTS=1")
        environment.append("CONTINUUM_BOOTSTRAP_REHYDRATE_STOP=1")
        environment.append(
            "DYLD_INSERT_LIBRARIES=\(insertedLibraries.joined(separator: ":"))"
        )

        var replacementProcessIdentifier: Int32 = 0
        let spawnStatus = Self.withCStringArray(launch.arguments) { arguments in
            Self.withCStringArray(environment) { environmentEntries in
                launch.executablePath.withCString { executable in
                    launch.workingDirectory.withCString { directory in
                        continuum_spawn_process(
                            executable,
                            arguments,
                            environmentEntries,
                            directory,
                            usesDeterministicAddressSpace ? 1 : 0,
                            &replacementProcessIdentifier
                        )
                    }
                }
            }
        }
        try requireRuntimeOK(
            spawnStatus,
            operation: "launch a GUI rehydration replacement"
        )

        var session: OpaquePointer?
        var retained = false
        defer {
            if !retained {
                _ = Self.killAndReap(replacementProcessIdentifier)
                if let session {
                    continuum_remote_session_destroy(session)
                }
            }
        }
        try requireRuntimeOK(
            continuum_wait_for_process_stop(
                replacementProcessIdentifier,
                15_000
            ),
            operation: "reach the replacement app's idle rehydration gate"
        )
        try requireRuntimeOK(
            continuum_remote_session_open(
                replacementProcessIdentifier,
                &session
            ),
            operation: "open the GUI replacement task"
        )
        guard let session else {
            throw ContinuumError.restoreUnavailable(
                "The GUI replacement did not expose a task session."
            )
        }
        var hasBootstrap: UInt8 = 0
        try requireRuntimeOK(
            bootstrapLibraryPath.withCString {
                continuum_remote_process_has_bootstrap(
                    replacementProcessIdentifier,
                    $0,
                    &hasBootstrap
                )
            },
            operation: "authenticate the GUI replacement bootstrap"
        )
        guard hasBootstrap != 0 else {
            throw ContinuumError.restoreUnavailable(
                "The GUI replacement did not load Continuum's restore bootstrap."
            )
        }

        var reconstructedRegionCount = 0
        var reconstructedChunkCount = 0
        var reconstructedBytes: UInt64 = 0
        var deferredMaximumProtectionRegionCount = 0
        let orderedAppStateRegions = appStateRegions.sorted {
            $0.address < $1.address
        }
        for region in orderedAppStateRegions {
            var runtimeRegion = continuum_remote_process_region_info()
            runtimeRegion.address = region.address
            runtimeRegion.length = region.length
            runtimeRegion.protection = region.protection
            runtimeRegion.maximum_protection = region.maximumProtection
            runtimeRegion.inheritance = region.inheritance
            runtimeRegion.share_mode = region.shareMode
            runtimeRegion.user_tag = region.userTag

            var matches: UInt8 = 0
            try requireRuntimeOK(
                continuum_remote_session_region_matches(
                    session,
                    &runtimeRegion,
                    &matches
                ),
                operation: "validate an app-owned replacement mapping"
            )
            if matches == 0 {
                var isUnmapped: UInt8 = 0
                try requireRuntimeOK(
                    continuum_remote_session_range_is_unmapped(
                        session,
                        region.address,
                        region.length,
                        &isUnmapped
                    ),
                    operation: "validate an app-owned replacement address range"
                )
                guard isUnmapped != 0 else {
                    throw ContinuumError.restoreUnavailable(
                        "The replacement process is using a saved app-state address for an incompatible mapping."
                    )
                }
            }
        }
        for region in orderedAppStateRegions {
            var runtimeRegion = continuum_remote_process_region_info()
            runtimeRegion.address = region.address
            runtimeRegion.length = region.length
            runtimeRegion.protection = region.protection
            runtimeRegion.maximum_protection = region.maximumProtection
            runtimeRegion.inheritance = region.inheritance
            runtimeRegion.share_mode = region.shareMode
            runtimeRegion.user_tag = region.userTag

            var report = continuum_remote_restore_report()
            try requireRuntimeOK(
                continuum_remote_session_begin_reconstruct_region(
                    session,
                    &runtimeRegion,
                    &report
                ),
                operation: reconstructionOperation(
                    "prepare app-owned",
                    region: region,
                    report: report
                )
            )
            var offset: UInt64 = 0
            for chunk in region.chunks {
                guard chunk.logicalBytes > 0,
                      chunk.logicalBytes <= 1_024 * 1_024,
                      offset <= region.length,
                      chunk.logicalBytes <= region.length - offset else {
                    throw ContinuumError.integrityFailure(
                        "App-owned RAM chunks exceed their captured mapping."
                    )
                }
                let logicalName = chunk.artifactName
                    ?? Self.legacyMemoryArtifactName(
                        processIdentifier: process.processIdentifier,
                        address: region.address,
                        offset: offset
                    )
                let artifact = try await repository.artifact(
                    for: snapshotID,
                    logicalName: logicalName
                )
                guard artifact.kind == .memoryPage,
                      UInt64(artifact.data.count) == chunk.logicalBytes,
                      Self.sha256(artifact.data) == chunk.hash else {
                    throw ContinuumError.integrityFailure(
                        "App-owned RAM chunk \(logicalName) failed validation."
                    )
                }
                let writeStatus = artifact.data.withUnsafeBytes { bytes in
                    continuum_remote_session_write_reconstructed_region(
                        session,
                        &runtimeRegion,
                        offset,
                        bytes.baseAddress,
                        bytes.count,
                        &report
                    )
                }
                try requireRuntimeOK(
                    writeStatus,
                    operation: reconstructionOperation(
                        "write app-owned",
                        region: region,
                        report: report
                    )
                )
                let (nextOffset, offsetOverflow) = offset
                    .addingReportingOverflow(chunk.logicalBytes)
                let (nextChunkCount, chunkCountOverflow) =
                    reconstructedChunkCount.addingReportingOverflow(1)
                let (nextByteCount, byteCountOverflow) = reconstructedBytes
                    .addingReportingOverflow(chunk.logicalBytes)
                guard !offsetOverflow,
                      !chunkCountOverflow,
                      !byteCountOverflow else {
                    throw ContinuumError.integrityFailure(
                        "App-owned RAM accounting exceeds numeric limits."
                    )
                }
                offset = nextOffset
                reconstructedChunkCount = nextChunkCount
                reconstructedBytes = nextByteCount
            }
            guard offset == region.length else {
                throw ContinuumError.integrityFailure(
                    "App-owned RAM mapping is incomplete."
                )
            }
            try requireRuntimeOK(
                continuum_remote_session_finish_reconstruct_region(
                    session,
                    &runtimeRegion,
                    &report
                ),
                operation: reconstructionOperation(
                    "protect app-owned",
                    region: region,
                    report: report
                )
            )
            if report.max_protection_verified == 0 {
                let (next, overflow) = deferredMaximumProtectionRegionCount
                    .addingReportingOverflow(1)
                guard !overflow else {
                    throw ContinuumError.integrityFailure(
                        "App-owned RAM protection accounting exceeds numeric limits."
                    )
                }
                deferredMaximumProtectionRegionCount = next
            }
            let (nextRegionCount, regionCountOverflow) =
                reconstructedRegionCount.addingReportingOverflow(1)
            guard !regionCountOverflow else {
                throw ContinuumError.integrityFailure(
                    "App-owned RAM region accounting exceeds numeric limits."
                )
            }
            reconstructedRegionCount = nextRegionCount
        }

        let preparationID = UUID()
        preparedReplacements[preparationID] = PreparedReplacement(
            processIdentifier: replacementProcessIdentifier,
            session: session,
            fileRollback: nil,
            requiresSafepointRelease: false,
            resumeMethod: .rehydrateStop
        )
        retained = true
        return ColdProcessPreparation(
            id: preparationID,
            replacementProcessIdentifier: replacementProcessIdentifier,
            capturedProcessIdentifier: process.processIdentifier,
            reconstructedRegionCount: reconstructedRegionCount,
            reconstructedChunkCount: reconstructedChunkCount,
            reconstructedBytes: reconstructedBytes,
            deferredMaximumProtectionRegionCount:
                deferredMaximumProtectionRegionCount,
            reconstructedThreadCount: 0,
            reconstructedThreadStateBytes: 0,
            replacementThreadIdentifier: 0,
            reconstructedFileDescriptorCount: 0,
            reconstructedFileCount: 0,
            reconstructedFileBytes: 0
        )
    }

    public func discard(_ preparationID: UUID) throws {
        guard let replacement = preparedReplacements[preparationID] else {
            return
        }
        let terminationStatus = Self.killAndReap(
            replacement.processIdentifier
        )
        guard terminationStatus == CONTINUUM_STATUS_OK
                || (terminationStatus == CONTINUUM_STATUS_TARGET_EXITED
                    && Self.processIsAbsent(replacement.processIdentifier)) else {
            throw ContinuumError.restoreUnavailable(
                "Continuum could not stop the prepared replacement; current files were left untouched."
            )
        }
        do {
            try Self.rollbackFiles(replacement.fileRollback)
        } catch {
            throw ContinuumError.integrityFailure(
                "Continuum stopped the replacement but could not restore the pre-restore files. The safety root remains at \(replacement.fileRollback?.rootURL.path ?? "no file transaction")."
            )
        }
        continuum_remote_session_destroy(replacement.session)
        preparedReplacements.removeValue(forKey: preparationID)
    }

    private func discardBrokerAbortedReplacement(
        _ preparationID: UUID
    ) throws {
        guard let replacement = preparedReplacements[preparationID] else {
            return
        }
        do {
            try Self.rollbackFiles(replacement.fileRollback)
        } catch {
            throw ContinuumError.integrityFailure(
                "Continuum aborted the replacement forest but could not restore its pre-restore files. The safety root remains at \(replacement.fileRollback?.rootURL.path ?? "no file transaction")."
            )
        }
        continuum_remote_session_destroy(replacement.session)
        preparedReplacements.removeValue(forKey: preparationID)
    }

    public func commit(
        _ preparationID: UUID
    ) throws -> ColdProcessCommit {
        guard let replacement = preparedReplacements[preparationID] else {
            throw ContinuumError.restoreUnavailable(
                "The prepared cold replacement no longer exists."
            )
        }
        if let rollback = replacement.fileRollback {
            try Self.validateInstalledFiles(
                rollback,
                allowedProcessIdentifier: replacement.processIdentifier
            )
            try Self.updateFileTransactionState(
                rollback,
                state: "committed"
            )
        }

        let releaseStatus: continuum_status
        switch replacement.resumeMethod {
        case .entryStop:
            releaseStatus =
                continuum_remote_session_release_entry_stopped_child(
                    replacement.session,
                    replacement.processIdentifier
                )
        case .rehydrateStop:
            releaseStatus = kill(replacement.processIdentifier, SIGCONT) == 0
                ? CONTINUUM_STATUS_OK
                : CONTINUUM_STATUS_RESUME_FAILED
        }
        guard releaseStatus == CONTINUUM_STATUS_OK else {
            if let rollback = replacement.fileRollback,
               (try? Self.updateFileTransactionState(
                    rollback,
                    state: "prepared"
               )) == nil {
                _ = Self.killAndReap(replacement.processIdentifier)
                guard (try? Self.rollbackFiles(rollback)) != nil else {
                    throw ContinuumError.integrityFailure(
                        "Cold resume failed, its transaction state could not be reverted, and file rollback also failed. The safety root remains at \(rollback.rootURL.path)."
                    )
                }
                continuum_remote_session_destroy(replacement.session)
                preparedReplacements.removeValue(forKey: preparationID)
                throw ContinuumError.restoreUnavailable(
                    "Cold resume failed; Continuum restored the pre-restore files."
                )
            }
            throw ContinuumError.restoreUnavailable(
                "Continuum could not release the reconstructed process: \(String(cString: continuum_status_string(releaseStatus)))."
            )
        }
        if replacement.requiresSafepointRelease,
           kill(replacement.processIdentifier, SIGUSR1) != 0 {
            _ = Self.killAndReap(replacement.processIdentifier)
            continuum_remote_session_destroy(replacement.session)
            preparedReplacements.removeValue(forKey: preparationID)
            throw ContinuumError.restoreUnavailable(
                "Continuum reconstructed the app but could not release its main-thread restore gate."
            )
        }

        continuum_remote_session_destroy(replacement.session)
        preparedReplacements.removeValue(forKey: preparationID)
        return ColdProcessCommit(
            processIdentifier: replacement.processIdentifier,
            safetyTransactionRootURL: replacement.fileRollback?.rootURL,
            retainedFileCount: replacement.fileRollback?.replacedFileCount ?? 0,
            retainedFileBytes: replacement.fileRollback?.replacedBytes ?? 0
        )
    }

    public func committedFileSafetySnapshots() throws -> [ColdFileSafetySnapshot] {
        guard preparedReplacements.isEmpty else {
            throw ContinuumError.transactionInProgress
        }
        guard FileManager.default.fileExists(atPath: fileSafetyRootURL.path) else {
            return []
        }
        let roots = try FileManager.default.contentsOfDirectory(
            at: fileSafetyRootURL,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles]
        )
        var snapshots: [ColdFileSafetySnapshot] = []
        for rootURL in roots {
            let values = try rootURL.resourceValues(forKeys: [.isDirectoryKey])
            guard values.isDirectory == true else { continue }
            let journal = try Self.readFileTransactionJournal(rootURL: rootURL)
            guard journal.formatVersion == 1,
                  journal.transactionID.uuidString == rootURL.lastPathComponent else {
                throw ContinuumError.integrityFailure(
                    "A cold-file safety snapshot has an invalid identity."
                )
            }
            guard journal.state == "committed" else { continue }
            let store = try APFSLocalFileCheckpointStore(rootURL: rootURL)
            let manifest = try store.manifestCoherently(
                snapshotID: journal.safetySnapshotID
            )
            var logicalBytes: UInt64 = 0
            for entry in manifest.entries {
                guard entry.byteCount >= 0 else {
                    throw ContinuumError.integrityFailure(
                        "A cold-file safety snapshot has a negative byte count."
                    )
                }
                let (next, overflow) = logicalBytes.addingReportingOverflow(
                    UInt64(entry.byteCount)
                )
                guard !overflow else {
                    throw ContinuumError.integrityFailure(
                        "A cold-file safety snapshot exceeds numeric limits."
                    )
                }
                logicalBytes = next
            }
            snapshots.append(ColdFileSafetySnapshot(
                id: journal.transactionID,
                createdAt: journal.createdAt,
                fileCount: manifest.entries.count,
                logicalBytes: logicalBytes
            ))
        }
        return snapshots.sorted { $0.createdAt > $1.createdAt }
    }

    public func deleteCommittedFileSafetySnapshot(_ id: UUID) throws {
        guard preparedReplacements.isEmpty else {
            throw ContinuumError.transactionInProgress
        }
        let rootURL = fileSafetyRootURL.appendingPathComponent(
            id.uuidString,
            isDirectory: true
        )
        let journal = try Self.readFileTransactionJournal(rootURL: rootURL)
        guard journal.transactionID == id, journal.state == "committed" else {
            throw ContinuumError.restoreUnavailable(
                "Only a committed cold-file safety snapshot can be deleted."
            )
        }
        try FileManager.default.removeItem(at: rootURL)
    }

    @discardableResult
    public func restoreCommittedFileSafetySnapshot(
        _ id: UUID
    ) async throws -> ColdFileSafetyRestore {
        guard preparedReplacements.isEmpty else {
            throw ContinuumError.transactionInProgress
        }
        let targetRootURL = fileSafetyRootURL.appendingPathComponent(
            id.uuidString,
            isDirectory: true
        )
        let targetJournal = try Self.readFileTransactionJournal(
            rootURL: targetRootURL
        )
        guard targetJournal.transactionID == id,
              targetJournal.state == "committed" else {
            throw ContinuumError.restoreUnavailable(
                "The requested cold-file safety snapshot is not committed."
            )
        }
        guard targetJournal.replacementProcessIdentifier <= 0
                || Self.processIsAbsent(
                    targetJournal.replacementProcessIdentifier
                ) else {
            throw ContinuumError.restoreUnavailable(
                "Close the process created by this restore before returning to its file safety snapshot."
            )
        }
        let targetStore = try APFSLocalFileCheckpointStore(
            rootURL: targetRootURL
        )
        let targetManifest = try targetStore.manifestCoherently(
            snapshotID: targetJournal.safetySnapshotID
        )
        let targetPaths = targetManifest.entries.map(\.originalPath)
        try Self.ensureNoExternalWriters(
            paths: targetPaths,
            allowedProcessIdentifier: 0
        )

        let reciprocalID = UUID()
        let reciprocalRootURL = fileSafetyRootURL.appendingPathComponent(
            reciprocalID.uuidString,
            isDirectory: true
        )
        let reciprocalStore = try APFSLocalFileCheckpointStore(
            rootURL: reciprocalRootURL
        )
        let reciprocalSnapshotID = UUID()
        let reciprocalManifest: LocalFileCheckpointManifest
        do {
            reciprocalManifest = try await reciprocalStore.capture(
                snapshotID: reciprocalSnapshotID,
                files: targetPaths.map { URL(fileURLWithPath: $0) }
            )
            let reciprocalJournal = ColdFileTransactionJournal(
                formatVersion: 1,
                transactionID: reciprocalID,
                safetySnapshotID: reciprocalSnapshotID,
                replacementProcessIdentifier: 0,
                state: "restoringCommitted",
                createdAt: Date(),
                entries: try reciprocalManifest.entries.map {
                    ColdFileTransactionJournal.Entry(
                        originalPath: $0.originalPath,
                        device: $0.device,
                        inode: $0.inode,
                        installedSHA256: try Self.sha256File(
                            atPath: $0.originalPath
                        )
                    )
                }
            )
            try Self.writeFileTransactionJournal(
                reciprocalJournal,
                rootURL: reciprocalRootURL
            )
            try Self.ensureNoExternalWriters(
                paths: targetPaths,
                allowedProcessIdentifier: 0
            )
        } catch {
            try? FileManager.default.removeItem(at: reciprocalRootURL)
            throw error
        }

        let report: LocalFileRestoreReport
        do {
            report = try targetStore.restoreCoherently(
                snapshotID: targetJournal.safetySnapshotID
            )
            try Self.updateFileTransactionState(
                rootURL: reciprocalRootURL,
                state: "committed"
            )
        } catch {
            do {
                _ = try reciprocalStore.restoreCoherently(
                    snapshotID: reciprocalSnapshotID
                )
                try FileManager.default.removeItem(at: reciprocalRootURL)
            } catch {
                throw ContinuumError.integrityFailure(
                    "Cold-file safety restore failed and its reciprocal rollback also failed. The reciprocal safety root remains at \(reciprocalRootURL.path)."
                )
            }
            throw error
        }
        guard report.restoredBytes >= 0 else {
            throw ContinuumError.integrityFailure(
                "Cold-file safety restore reported a negative byte count."
            )
        }
        return ColdFileSafetyRestore(
            restoredSnapshotID: id,
            reciprocalSafetySnapshotID: reciprocalID,
            restoredFileCount: report.restoredFileCount,
            restoredBytes: UInt64(report.restoredBytes)
        )
    }

    @discardableResult
    public func recoverInterruptedFileTransactions() throws -> Int {
        guard preparedReplacements.isEmpty else {
            throw ContinuumError.transactionInProgress
        }
        guard FileManager.default.fileExists(atPath: fileSafetyRootURL.path) else {
            return 0
        }
        let roots = try FileManager.default.contentsOfDirectory(
            at: fileSafetyRootURL,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles]
        ).sorted { $0.lastPathComponent < $1.lastPathComponent }
        var recovered = 0
        for rootURL in roots {
            let values = try rootURL.resourceValues(forKeys: [.isDirectoryKey])
            guard values.isDirectory == true else { continue }
            let journal = try Self.readFileTransactionJournal(rootURL: rootURL)
            guard journal.formatVersion == 1,
                  journal.transactionID.uuidString == rootURL.lastPathComponent else {
                throw ContinuumError.integrityFailure(
                    "A durable cold-file transaction journal has an invalid identity."
                )
            }
            if journal.state == "committed" {
                continue
            }
            let interruptedCommittedRestore = journal.state
                == "restoringCommitted"
            guard journal.state == "prepared"
                    || interruptedCommittedRestore else {
                throw ContinuumError.integrityFailure(
                    "A durable cold-file transaction has an unknown state."
                )
            }
            guard journal.replacementProcessIdentifier <= 0
                    || Self.processIsAbsent(
                        journal.replacementProcessIdentifier
                    ) else {
                throw ContinuumError.restoreUnavailable(
                    "An interrupted cold replacement is still running; Continuum will not touch its files."
                )
            }
            for entry in journal.entries {
                var conflictingProcessIdentifier: Int32 = 0
                let writerStatus = entry.originalPath.withCString {
                    continuum_find_writable_vnode_conflict(
                        $0,
                        0,
                        &conflictingProcessIdentifier
                    )
                }
                guard writerStatus == CONTINUUM_STATUS_OK else {
                    throw ContinuumError.restoreUnavailable(
                        writerStatus == CONTINUUM_STATUS_FILE_WRITER_CONFLICT
                            ? "Process \(conflictingProcessIdentifier) is writing an interrupted transaction target. Continuum preserved its safety root."
                            : "Continuum could not prove exclusive ownership while recovering an interrupted file transaction."
                    )
                }
                if !interruptedCommittedRestore {
                    guard try Self.fileIdentity(
                        atPath: entry.originalPath
                    ) == (entry.device, entry.inode),
                          try Self.sha256File(atPath: entry.originalPath)
                            == entry.installedSHA256 else {
                        throw ContinuumError.integrityFailure(
                            "A file changed after an interrupted cold restore. Continuum preserved the safety transaction at \(rootURL.path) instead of overwriting newer bytes."
                        )
                    }
                }
            }
            let store = try APFSLocalFileCheckpointStore(rootURL: rootURL)
            _ = try store.restoreCoherently(
                snapshotID: journal.safetySnapshotID
            )
            try FileManager.default.removeItem(at: rootURL)
            recovered += 1
        }
        return recovered
    }

    private func validate(_ image: DurableCheckpointImage) throws {
        guard image.formatVersion == 6
                || image.formatVersion == DurableCheckpointImage.currentFormatVersion else {
            throw ContinuumError.restoreUnavailable(
                "This checkpoint uses an unsupported durable format."
            )
        }
        guard image.architecture == "arm64" else {
            throw ContinuumError.restoreUnavailable(
                "Only native arm64 cold restoration is implemented."
            )
        }
        guard image.pageSize == UInt64(getpagesize()) else {
            throw ContinuumError.restoreUnavailable(
                "The checkpoint page size does not match this Mac."
            )
        }
        guard image.operatingSystemBuild == (try currentOperatingSystemBuild()) else {
            throw ContinuumError.restoreUnavailable(
                "macOS changed since this checkpoint was captured."
            )
        }
    }

    func prepareDescriptorGraph(
        for image: DurableCheckpointImage
    ) throws -> PreparedDescriptorGraph {
        // Format-seven images use the normalized graph as the sole socket source
        // of truth. Endpoint-per-fd records remain only for legacy images.
        let endpoints = image.descriptorGraph == nil
            ? image.establishedTCPEndpoints ?? []
            : []
        let ptyDescriptors = image.ptyDescriptors ?? []
        let durableGraph = image.descriptorGraph
        let socketIDs = Set(durableGraph?.sockets.map(\.id) ?? [])
        let pipeIDs = Set(durableGraph?.pipes.map(\.id) ?? [])
        let kqueueIDs = Set(durableGraph?.kqueues.map(\.id) ?? [])
        let socketHandles = durableGraph?.handles.filter {
            socketIDs.contains($0.resourceID)
        } ?? []
        let pipeHandles = durableGraph?.handles.filter { handle in
            pipeIDs.contains(handle.resourceID)
        } ?? []
        let kqueueHandles = durableGraph?.handles.filter { handle in
            kqueueIDs.contains(handle.resourceID)
        } ?? []
        if let durableGraph {
            let allResourceIDs = socketIDs.union(pipeIDs).union(kqueueIDs)
            guard socketIDs.count == durableGraph.sockets.count,
                  pipeIDs.count == durableGraph.pipes.count,
                  kqueueIDs.count == durableGraph.kqueues.count,
                  allResourceIDs.count == socketIDs.count + pipeIDs.count
                    + kqueueIDs.count,
                  durableGraph.handles.allSatisfy({
                      allResourceIDs.contains($0.resourceID)
                  }) else {
                throw ContinuumError.integrityFailure(
                    "The durable descriptor graph contains duplicate or unknown resources."
                )
            }
            try Self.validateColdSockets(
                graph: durableGraph,
                handles: socketHandles,
                capturedProcessIdentifiers: Set(image.members.map(\.processIdentifier))
            )
            try validateColdKqueues(
                graph: durableGraph,
                handles: kqueueHandles,
                capturedProcessIdentifiers: Set(image.members.map(\.processIdentifier))
            )
        }
        guard !endpoints.isEmpty || !ptyDescriptors.isEmpty
                || durableGraph?.pipes.isEmpty == false
                || durableGraph?.sockets.isEmpty == false
                || durableGraph?.kqueues.isEmpty == false else {
            return PreparedDescriptorGraph(
                remapsByCapturedProcess: [:],
                controllerDescriptors: [],
                presentationMasters: []
            )
        }

        let capturedProcesses = Set(image.members.map(\.processIdentifier))
        var targetDescriptorsByProcess: [Int32: Set<Int32>] = [:]
        for endpoint in endpoints {
            guard capturedProcesses.contains(endpoint.processIdentifier),
                  endpoint.fileDescriptor >= 0,
                  targetDescriptorsByProcess[endpoint.processIdentifier,
                    default: []].insert(endpoint.fileDescriptor).inserted else {
                throw ContinuumError.integrityFailure(
                    "The durable TCP graph contains an invalid or duplicate descriptor."
                )
            }
        }
        for descriptor in ptyDescriptors {
            guard capturedProcesses.contains(descriptor.processIdentifier),
                  descriptor.fileDescriptor >= 0,
                  targetDescriptorsByProcess[descriptor.processIdentifier,
                    default: []].insert(descriptor.fileDescriptor).inserted else {
                throw ContinuumError.integrityFailure(
                    "The durable PTY graph contains an invalid or duplicate descriptor."
                )
            }
        }
        for handle in pipeHandles {
            guard capturedProcesses.contains(handle.processIdentifier),
                  handle.fileDescriptor >= 0,
                  targetDescriptorsByProcess[handle.processIdentifier,
                    default: []].insert(handle.fileDescriptor).inserted else {
                throw ContinuumError.integrityFailure(
                    "The durable pipe graph contains an invalid or duplicate descriptor."
                )
            }
        }
        for handle in socketHandles {
            guard capturedProcesses.contains(handle.processIdentifier),
                  handle.fileDescriptor >= 0,
                  targetDescriptorsByProcess[handle.processIdentifier,
                    default: []].insert(handle.fileDescriptor).inserted else {
                throw ContinuumError.integrityFailure(
                    "The durable socket graph contains an invalid or duplicate descriptor."
                )
            }
        }
        for handle in kqueueHandles {
            guard capturedProcesses.contains(handle.processIdentifier),
                  handle.fileDescriptor >= 0,
                  targetDescriptorsByProcess[handle.processIdentifier,
                    default: []].insert(handle.fileDescriptor).inserted else {
                throw ContinuumError.integrityFailure(
                    "The durable kqueue graph contains an invalid or duplicate descriptor."
                )
            }
        }

        var targetDescriptorNumbers = endpoints.map(\.fileDescriptor)
        targetDescriptorNumbers.append(contentsOf: ptyDescriptors.map(\.fileDescriptor))
        targetDescriptorNumbers.append(contentsOf: pipeHandles.map(\.fileDescriptor))
        targetDescriptorNumbers.append(contentsOf: socketHandles.map(\.fileDescriptor))
        targetDescriptorNumbers.append(contentsOf: kqueueHandles.map(\.fileDescriptor))
        let maximumTarget = targetDescriptorNumbers.max() ?? 255
        let descriptorCount = endpoints.count + ptyDescriptors.count
            + pipeHandles.count + socketHandles.count + kqueueHandles.count
        guard maximumTarget < Int32.max - Int32(descriptorCount * 2 + 16) else {
            throw ContinuumError.integrityFailure(
                "The durable TCP descriptor numbers exceed process limits."
            )
        }
        var nextControllerDescriptor = max(Int32(256), maximumTarget + 1)
        var remaining = Set(endpoints.indices)
        var remapsByProcess: [Int32: [continuum_spawn_descriptor_remap]] = [:]
        var controllerDescriptors: [Int32] = []
        var presentationMasters: [PreparedPresentationMaster] = []

        func closeControllerDescriptors() {
            for descriptor in controllerDescriptors {
                Darwin.close(descriptor)
            }
        }

        do {
            if let durableGraph, !durableGraph.pipes.isEmpty {
                guard Set(durableGraph.pipes.map(\.id)).count
                        == durableGraph.pipes.count else {
                    throw ContinuumError.integrityFailure(
                        "The durable pipe graph contains duplicate resource identities."
                    )
                }
                let pipeByID = Dictionary(
                    uniqueKeysWithValues: durableGraph.pipes.map { ($0.id, $0) }
                )
                let handlesByResource = Dictionary(
                    grouping: pipeHandles,
                    by: \.resourceID
                )
                guard handlesByResource.keys.allSatisfy({ pipeByID[$0] != nil }),
                      pipeByID.keys.allSatisfy({ handlesByResource[$0]?.isEmpty == false })
                else {
                    throw ContinuumError.integrityFailure(
                        "The durable pipe graph contains an unowned resource."
                    )
                }

                var restoredPipeIDs: Set<UUID> = []
                for first in durableGraph.pipes.sorted(by: {
                    $0.id.uuidString < $1.id.uuidString
                }) where !restoredPipeIDs.contains(first.id) {
                    guard let second = pipeByID[first.peerResourceID],
                          second.peerResourceID == first.id,
                          second.id != first.id else {
                        throw ContinuumError.integrityFailure(
                            "The durable pipe graph contains a nonreciprocal peer."
                        )
                    }
                    guard !restoredPipeIDs.contains(second.id),
                          let firstHandles = handlesByResource[first.id],
                          let secondHandles = handlesByResource[second.id],
                          let firstStatus = firstHandles.first?.statusFlags,
                          let secondStatus = secondHandles.first?.statusFlags,
                          firstHandles.allSatisfy({ $0.statusFlags == firstStatus }),
                          secondHandles.allSatisfy({ $0.statusFlags == secondStatus }),
                          firstHandles.allSatisfy({
                              $0.descriptorFlags == 0
                                  || $0.descriptorFlags == FD_CLOEXEC
                          }),
                          secondHandles.allSatisfy({
                              $0.descriptorFlags == 0
                                  || $0.descriptorFlags == FD_CLOEXEC
                          }) else {
                        throw ContinuumError.restoreUnavailable(
                            "A saved pipe has inconsistent aliases or per-descriptor flags that require bootstrap replay."
                        )
                    }

                    let firstAccess = firstStatus & O_ACCMODE
                    let secondAccess = secondStatus & O_ACCMODE
                    let readResource: DurablePipeResource
                    let writeResource: DurablePipeResource
                    let readHandles: [DurableDescriptorHandle]
                    let writeHandles: [DurableDescriptorHandle]
                    let readStatus: Int32
                    let writeStatus: Int32
                    if firstAccess == O_RDONLY, secondAccess == O_WRONLY {
                        readResource = first
                        writeResource = second
                        readHandles = firstHandles
                        writeHandles = secondHandles
                        readStatus = firstStatus
                        writeStatus = secondStatus
                    } else if firstAccess == O_WRONLY, secondAccess == O_RDONLY {
                        readResource = second
                        writeResource = first
                        readHandles = secondHandles
                        writeHandles = firstHandles
                        readStatus = secondStatus
                        writeStatus = firstStatus
                    } else {
                        throw ContinuumError.restoreUnavailable(
                            "A saved pipe does not contain one read end and one write end."
                        )
                    }

                    let mutableStatusMask = O_NONBLOCK | O_ASYNC
                    let supportedStatusMask = O_ACCMODE | mutableStatusMask
                    guard readStatus & ~supportedStatusMask == 0,
                          writeStatus & ~supportedStatusMask == 0 else {
                        throw ContinuumError.restoreUnavailable(
                            "A saved pipe uses status flags Continuum cannot replay yet."
                        )
                    }

                    var readRuntime = continuum_remote_pipe_resource_info()
                    readRuntime.resource_identity = 1
                    readRuntime.peer_identity = 2
                    readRuntime.capacity = readResource.capacity
                    readRuntime.queued_bytes = readResource.queuedBytes
                    readRuntime.status = readResource.status
                    var writeRuntime = continuum_remote_pipe_resource_info()
                    writeRuntime.resource_identity = 2
                    writeRuntime.peer_identity = 1
                    writeRuntime.capacity = writeResource.capacity
                    writeRuntime.queued_bytes = writeResource.queuedBytes
                    writeRuntime.status = writeResource.status
                    var recreatedRead: Int32 = -1
                    var recreatedWrite: Int32 = -1
                    let recreateStatus = continuum_recreate_closed_empty_pipe_pair(
                        &readRuntime,
                        &writeRuntime,
                        &recreatedRead,
                        &recreatedWrite
                    )
                    guard recreateStatus == CONTINUUM_STATUS_OK,
                          recreatedRead >= 0,
                          recreatedWrite >= 0 else {
                        if recreatedRead >= 0 { Darwin.close(recreatedRead) }
                        if recreatedWrite >= 0 { Darwin.close(recreatedWrite) }
                        throw ContinuumError.restoreUnavailable(
                            "Continuum could not recreate an empty local pipe."
                        )
                    }

                    let promotedRead = fcntl(
                        recreatedRead,
                        F_DUPFD_CLOEXEC,
                        nextControllerDescriptor
                    )
                    if promotedRead >= 0 {
                        nextControllerDescriptor = promotedRead + 1
                    }
                    let promotedWrite = promotedRead < 0 ? -1 : fcntl(
                        recreatedWrite,
                        F_DUPFD_CLOEXEC,
                        nextControllerDescriptor
                    )
                    Darwin.close(recreatedRead)
                    Darwin.close(recreatedWrite)
                    guard promotedRead >= 0, promotedWrite >= 0 else {
                        if promotedRead >= 0 { Darwin.close(promotedRead) }
                        if promotedWrite >= 0 { Darwin.close(promotedWrite) }
                        throw ContinuumError.restoreUnavailable(
                            "Continuum could not isolate recreated pipe descriptors for relaunch."
                        )
                    }
                    nextControllerDescriptor = promotedWrite + 1
                    controllerDescriptors.append(contentsOf: [
                        promotedRead, promotedWrite,
                    ])

                    guard fcntl(
                        promotedRead,
                        F_SETFL,
                        readStatus & mutableStatusMask
                    ) == 0,
                    fcntl(
                        promotedWrite,
                        F_SETFL,
                        writeStatus & mutableStatusMask
                    ) == 0 else {
                        throw ContinuumError.restoreUnavailable(
                            "Continuum could not replay saved pipe status flags."
                        )
                    }

                    for handle in readHandles {
                        remapsByProcess[handle.processIdentifier, default: []]
                            .append(continuum_spawn_descriptor_remap(
                                source_descriptor: promotedRead,
                                target_descriptor: handle.fileDescriptor
                            ))
                    }
                    for handle in writeHandles {
                        remapsByProcess[handle.processIdentifier, default: []]
                            .append(continuum_spawn_descriptor_remap(
                                source_descriptor: promotedWrite,
                                target_descriptor: handle.fileDescriptor
                            ))
                    }
                    restoredPipeIDs.insert(readResource.id)
                    restoredPipeIDs.insert(writeResource.id)
                }
            }

            if let durableGraph, !durableGraph.sockets.isEmpty {
                let socketByID = Dictionary(
                    uniqueKeysWithValues: durableGraph.sockets.map { ($0.id, $0) }
                )
                let handlesByResource = Dictionary(
                    grouping: socketHandles,
                    by: \.resourceID
                )
                guard socketByID.keys.allSatisfy({
                    handlesByResource[$0]?.isEmpty == false
                }) else {
                    throw ContinuumError.integrityFailure(
                        "The durable socket graph contains an unowned resource."
                    )
                }

                var listenerDescriptors: [UUID: Int32] = [:]
                for listener in durableGraph.sockets.filter({
                    $0.kind == .tcpListener
                }).sorted(by: {
                    $0.id.uuidString < $1.id.uuidString
                }) {
                    guard let listenerHandles = handlesByResource[listener.id],
                          let representative = listenerHandles.first else {
                        throw ContinuumError.integrityFailure(
                            "The durable listener graph contains an unowned resource."
                        )
                    }
                    let recreated = try Self.createExactLoopbackListener(listener)
                    let promoted = fcntl(
                        recreated,
                        F_DUPFD_CLOEXEC,
                        nextControllerDescriptor
                    )
                    Darwin.close(recreated)
                    guard promoted >= 0 else {
                        throw ContinuumError.restoreUnavailable(
                            "Continuum could not isolate a recreated listener for relaunch."
                        )
                    }
                    nextControllerDescriptor = promoted + 1
                    controllerDescriptors.append(promoted)
                    listenerDescriptors[listener.id] = promoted
                    for handle in listenerHandles {
                        remapsByProcess[handle.processIdentifier, default: []]
                            .append(continuum_spawn_descriptor_remap(
                                source_descriptor: promoted,
                                target_descriptor: handle.fileDescriptor
                            ))
                    }
                    // Leave it blocking until all linked accepted streams have
                    // been recreated through this exact listener.
                    guard representative.statusFlags & O_ACCMODE == O_RDWR else {
                        throw ContinuumError.restoreUnavailable(
                            "A saved listener has invalid access flags."
                        )
                    }
                }

                var restoredSocketIDs = Set(listenerDescriptors.keys)
                for first in durableGraph.sockets.filter({
                    $0.kind == .unixConnected
                }).sorted(by: {
                    $0.id.uuidString < $1.id.uuidString
                }) where !restoredSocketIDs.contains(first.id) {
                    guard let peerID = first.peerResourceID,
                          let second = socketByID[peerID],
                          second.peerResourceID == first.id,
                          second.id != first.id,
                          first.domain == second.domain,
                          first.type == second.type,
                          first.protocol == second.protocol,
                          first.localAddress == second.remoteAddress,
                          first.remoteAddress == second.localAddress,
                          let firstHandles = handlesByResource[first.id],
                          let secondHandles = handlesByResource[second.id],
                          let firstHandle = firstHandles.first,
                          let secondHandle = secondHandles.first else {
                        throw ContinuumError.integrityFailure(
                            "The durable Unix socket graph contains a nonreciprocal peer."
                        )
                    }
                    let pair = try Self.createEmptyUnixSocketPair(
                        first: first,
                        second: second
                    )
                    let firstDescriptor = pair.first
                    let secondDescriptor = pair.second
                    let mutableStatusMask = O_NONBLOCK
                    guard fcntl(
                        firstDescriptor,
                        F_SETFL,
                        firstHandle.statusFlags & mutableStatusMask
                    ) == 0,
                    fcntl(
                        secondDescriptor,
                        F_SETFL,
                        secondHandle.statusFlags & mutableStatusMask
                    ) == 0 else {
                        Darwin.close(firstDescriptor)
                        Darwin.close(secondDescriptor)
                        throw ContinuumError.restoreUnavailable(
                            "Continuum could not replay saved Unix socket status flags."
                        )
                    }

                    let promotedFirst = fcntl(
                        firstDescriptor,
                        F_DUPFD_CLOEXEC,
                        nextControllerDescriptor
                    )
                    if promotedFirst >= 0 {
                        nextControllerDescriptor = promotedFirst + 1
                    }
                    let promotedSecond = promotedFirst < 0 ? -1 : fcntl(
                        secondDescriptor,
                        F_DUPFD_CLOEXEC,
                        nextControllerDescriptor
                    )
                    Darwin.close(firstDescriptor)
                    Darwin.close(secondDescriptor)
                    guard promotedFirst >= 0, promotedSecond >= 0 else {
                        if promotedFirst >= 0 { Darwin.close(promotedFirst) }
                        if promotedSecond >= 0 { Darwin.close(promotedSecond) }
                        throw ContinuumError.restoreUnavailable(
                            "Continuum could not isolate recreated Unix socket descriptors for relaunch."
                        )
                    }
                    nextControllerDescriptor = promotedSecond + 1
                    controllerDescriptors.append(contentsOf: [
                        promotedFirst, promotedSecond,
                    ])
                    for handle in firstHandles {
                        remapsByProcess[handle.processIdentifier, default: []]
                            .append(continuum_spawn_descriptor_remap(
                                source_descriptor: promotedFirst,
                                target_descriptor: handle.fileDescriptor
                            ))
                    }
                    for handle in secondHandles {
                        remapsByProcess[handle.processIdentifier, default: []]
                            .append(continuum_spawn_descriptor_remap(
                                source_descriptor: promotedSecond,
                                target_descriptor: handle.fileDescriptor
                            ))
                    }
                    restoredSocketIDs.insert(first.id)
                    restoredSocketIDs.insert(second.id)
                }
                for first in durableGraph.sockets.filter({
                    $0.kind == .tcpConnected
                }).sorted(by: {
                    $0.id.uuidString < $1.id.uuidString
                }) where !restoredSocketIDs.contains(first.id) {
                    guard let peerID = first.peerResourceID,
                          let second = socketByID[peerID],
                          second.peerResourceID == first.id,
                          second.id != first.id,
                          first.domain == second.domain,
                          first.type == second.type,
                          first.protocol == second.protocol,
                          first.localAddress == second.remoteAddress,
                          first.remoteAddress == second.localAddress,
                          let firstHandles = handlesByResource[first.id],
                          let secondHandles = handlesByResource[second.id],
                          let firstHandle = firstHandles.first,
                          let secondHandle = secondHandles.first else {
                        throw ContinuumError.integrityFailure(
                            "The durable TCP graph contains a nonreciprocal peer."
                        )
                    }
                    let supportedStatusMask = O_ACCMODE | O_NONBLOCK | O_ASYNC
                    guard firstHandles.allSatisfy({
                        $0.statusFlags == firstHandle.statusFlags
                            && ($0.descriptorFlags == 0
                                || $0.descriptorFlags == FD_CLOEXEC)
                    }), secondHandles.allSatisfy({
                        $0.statusFlags == secondHandle.statusFlags
                            && ($0.descriptorFlags == 0
                                || $0.descriptorFlags == FD_CLOEXEC)
                    }), firstHandle.statusFlags & O_ACCMODE == O_RDWR,
                    secondHandle.statusFlags & O_ACCMODE == O_RDWR,
                    firstHandle.statusFlags & ~supportedStatusMask == 0,
                    secondHandle.statusFlags & ~supportedStatusMask == 0 else {
                        throw ContinuumError.restoreUnavailable(
                            "A saved TCP stream uses descriptor flags Continuum cannot replay yet."
                        )
                    }

                    var firstDescriptor: Int32 = -1
                    var secondDescriptor: Int32 = -1
                    if let listenerID = first.listenerResourceID {
                        guard let listenerDescriptor = listenerDescriptors[listenerID] else {
                            throw ContinuumError.integrityFailure(
                                "A saved accepted stream references a missing listener."
                            )
                        }
                        let pair = try Self.createConnectedPairThroughListener(
                            listenerDescriptor: listenerDescriptor,
                            accepted: first,
                            client: second
                        )
                        firstDescriptor = pair.accepted
                        secondDescriptor = pair.client
                    } else if let listenerID = second.listenerResourceID {
                        guard let listenerDescriptor = listenerDescriptors[listenerID] else {
                            throw ContinuumError.integrityFailure(
                                "A saved accepted stream references a missing listener."
                            )
                        }
                        let pair = try Self.createConnectedPairThroughListener(
                            listenerDescriptor: listenerDescriptor,
                            accepted: second,
                            client: first
                        )
                        firstDescriptor = pair.client
                        secondDescriptor = pair.accepted
                    } else {
                        var firstRuntime = try Self.runtimeTCPEndpoint(
                            first,
                            handle: firstHandle
                        )
                        var secondRuntime = try Self.runtimeTCPEndpoint(
                            second,
                            handle: secondHandle
                        )
                        let status = continuum_recreate_closed_loopback_tcp_pair(
                            &firstRuntime,
                            &secondRuntime,
                            &firstDescriptor,
                            &secondDescriptor
                        )
                        guard status == CONTINUUM_STATUS_OK else {
                            if firstDescriptor >= 0 { Darwin.close(firstDescriptor) }
                            if secondDescriptor >= 0 { Darwin.close(secondDescriptor) }
                            let detail = continuum_status_string(status).map {
                                String(cString: $0)
                            } ?? "status \(status.rawValue)"
                            throw ContinuumError.restoreUnavailable(
                                "Continuum could not recreate a closed local TCP stream: \(detail)."
                            )
                        }
                    }
                    guard try Self.replayConnectedSocketOptions(
                        descriptor: firstDescriptor,
                        resource: first
                    ), try Self.replayConnectedSocketOptions(
                        descriptor: secondDescriptor,
                        resource: second
                    ) else {
                        Darwin.close(firstDescriptor)
                        Darwin.close(secondDescriptor)
                        throw ContinuumError.restoreUnavailable(
                            "Continuum could not replay saved TCP socket options."
                        )
                    }
                    guard firstDescriptor >= 0,
                          secondDescriptor >= 0,
                          fcntl(
                        firstDescriptor,
                        F_SETFL,
                        firstHandle.statusFlags & (O_NONBLOCK | O_ASYNC)
                    ) == 0,
                    fcntl(
                        secondDescriptor,
                        F_SETFL,
                        secondHandle.statusFlags & (O_NONBLOCK | O_ASYNC)
                    ) == 0 else {
                        Darwin.close(firstDescriptor)
                        Darwin.close(secondDescriptor)
                        throw ContinuumError.restoreUnavailable(
                            "Continuum could not replay saved TCP status flags."
                        )
                    }

                    let promotedFirst = fcntl(
                        firstDescriptor,
                        F_DUPFD_CLOEXEC,
                        nextControllerDescriptor
                    )
                    if promotedFirst >= 0 {
                        nextControllerDescriptor = promotedFirst + 1
                    }
                    let promotedSecond = promotedFirst < 0 ? -1 : fcntl(
                        secondDescriptor,
                        F_DUPFD_CLOEXEC,
                        nextControllerDescriptor
                    )
                    Darwin.close(firstDescriptor)
                    Darwin.close(secondDescriptor)
                    guard promotedFirst >= 0, promotedSecond >= 0 else {
                        if promotedFirst >= 0 { Darwin.close(promotedFirst) }
                        if promotedSecond >= 0 { Darwin.close(promotedSecond) }
                        throw ContinuumError.restoreUnavailable(
                            "Continuum could not isolate recreated TCP descriptors for relaunch."
                        )
                    }
                    nextControllerDescriptor = promotedSecond + 1
                    controllerDescriptors.append(contentsOf: [
                        promotedFirst, promotedSecond,
                    ])

                    for handle in firstHandles {
                        remapsByProcess[handle.processIdentifier, default: []]
                            .append(continuum_spawn_descriptor_remap(
                                source_descriptor: promotedFirst,
                                target_descriptor: handle.fileDescriptor
                            ))
                    }
                    for handle in secondHandles {
                        remapsByProcess[handle.processIdentifier, default: []]
                            .append(continuum_spawn_descriptor_remap(
                                source_descriptor: promotedSecond,
                                target_descriptor: handle.fileDescriptor
                            ))
                    }
                    restoredSocketIDs.insert(first.id)
                    restoredSocketIDs.insert(second.id)
                }

                for listener in durableGraph.sockets where
                    listener.kind == .tcpListener {
                    guard let descriptor = listenerDescriptors[listener.id],
                          let statusFlags = handlesByResource[listener.id]?
                            .first?.statusFlags,
                          fcntl(
                              descriptor,
                              F_SETFL,
                              statusFlags & (O_NONBLOCK | O_ASYNC)
                          ) == 0 else {
                        throw ContinuumError.restoreUnavailable(
                            "Continuum could not replay saved listener status flags."
                        )
                    }
                }
            }

            while let firstIndex = remaining.min() {
                let first = endpoints[firstIndex]
                let matches = remaining.filter { candidateIndex in
                    guard candidateIndex != firstIndex else { return false }
                    let candidate = endpoints[candidateIndex]
                    return candidate.domain == first.domain
                        && candidate.socketType == first.socketType
                        && candidate.socketProtocol == first.socketProtocol
                        && candidate.localAddress == first.remoteAddress
                        && candidate.remoteAddress == first.localAddress
                }
                guard matches.count == 1, let secondIndex = matches.first else {
                    throw ContinuumError.restoreUnavailable(
                        "A saved TCP stream has no unique local peer in this snapshot."
                    )
                }
                let second = endpoints[secondIndex]
                var firstRuntime = try Self.runtimeTCPEndpoint(first)
                var secondRuntime = try Self.runtimeTCPEndpoint(second)
                var firstDescriptor: Int32 = -1
                var secondDescriptor: Int32 = -1
                let status = continuum_recreate_closed_loopback_tcp_pair(
                    &firstRuntime,
                    &secondRuntime,
                    &firstDescriptor,
                    &secondDescriptor
                )
                guard status == CONTINUUM_STATUS_OK,
                      firstDescriptor >= 0,
                      secondDescriptor >= 0 else {
                    if firstDescriptor >= 0 { Darwin.close(firstDescriptor) }
                    if secondDescriptor >= 0 { Darwin.close(secondDescriptor) }
                    let detail = continuum_status_string(status).map {
                        String(cString: $0)
                    } ?? "status \(status.rawValue)"
                    throw ContinuumError.restoreUnavailable(
                        "Continuum could not recreate a closed local TCP stream: \(detail)."
                    )
                }

                let promotedFirst = fcntl(
                    firstDescriptor,
                    F_DUPFD_CLOEXEC,
                    nextControllerDescriptor
                )
                if promotedFirst >= 0 {
                    nextControllerDescriptor = promotedFirst + 1
                }
                let promotedSecond = promotedFirst < 0 ? -1 : fcntl(
                    secondDescriptor,
                    F_DUPFD_CLOEXEC,
                    nextControllerDescriptor
                )
                Darwin.close(firstDescriptor)
                Darwin.close(secondDescriptor)
                guard promotedFirst >= 0, promotedSecond >= 0 else {
                    if promotedFirst >= 0 { Darwin.close(promotedFirst) }
                    if promotedSecond >= 0 { Darwin.close(promotedSecond) }
                    throw ContinuumError.restoreUnavailable(
                        "Continuum could not isolate recreated TCP descriptors for relaunch."
                    )
                }
                nextControllerDescriptor = promotedSecond + 1
                controllerDescriptors.append(contentsOf: [
                    promotedFirst, promotedSecond,
                ])

                var firstRemap = continuum_spawn_descriptor_remap()
                firstRemap.source_descriptor = promotedFirst
                firstRemap.target_descriptor = first.fileDescriptor
                remapsByProcess[first.processIdentifier, default: []].append(
                    firstRemap
                )
                var secondRemap = continuum_spawn_descriptor_remap()
                secondRemap.source_descriptor = promotedSecond
                secondRemap.target_descriptor = second.fileDescriptor
                remapsByProcess[second.processIdentifier, default: []].append(
                    secondRemap
                )
                remaining.remove(firstIndex)
                remaining.remove(secondIndex)
            }

            let descriptorsByTTY = Dictionary(
                grouping: ptyDescriptors,
                by: \.ttyIndex
            )
            for ttyIndex in descriptorsByTTY.keys.sorted() {
                guard let descriptors = descriptorsByTTY[ttyIndex],
                      let slave = descriptors.first(where: { $0.role == .slave }) else {
                    throw ContinuumError.restoreUnavailable(
                        "A saved PTY has no workload-side slave in this snapshot."
                    )
                }
                var runtimeSlave = try Self.runtimePTYDescriptor(slave)
                var masterDescriptor: Int32 = -1
                var slaveDescriptor: Int32 = -1
                let capturedMaster = descriptors.first(where: { $0.role == .master })
                let status: continuum_status
                if let capturedMaster {
                    var runtimeMaster = try Self.runtimePTYDescriptor(capturedMaster)
                    status = continuum_recreate_closed_pty_pair(
                        &runtimeMaster,
                        &runtimeSlave,
                        &masterDescriptor,
                        &slaveDescriptor
                    )
                } else {
                    status = continuum_recreate_closed_pty_from_slave(
                        &runtimeSlave,
                        &masterDescriptor,
                        &slaveDescriptor
                    )
                }
                guard status == CONTINUUM_STATUS_OK,
                      masterDescriptor >= 0,
                      slaveDescriptor >= 0 else {
                    if masterDescriptor >= 0 { Darwin.close(masterDescriptor) }
                    if slaveDescriptor >= 0 { Darwin.close(slaveDescriptor) }
                    let detail = continuum_status_string(status).map {
                        String(cString: $0)
                    } ?? "status \(status.rawValue)"
                    throw ContinuumError.restoreUnavailable(
                        "Continuum could not recreate a closed terminal stream: \(detail)."
                    )
                }

                let promotedMaster = fcntl(
                    masterDescriptor,
                    F_DUPFD_CLOEXEC,
                    nextControllerDescriptor
                )
                if promotedMaster >= 0 {
                    nextControllerDescriptor = promotedMaster + 1
                }
                let promotedSlave = promotedMaster < 0 ? -1 : fcntl(
                    slaveDescriptor,
                    F_DUPFD_CLOEXEC,
                    nextControllerDescriptor
                )
                Darwin.close(masterDescriptor)
                Darwin.close(slaveDescriptor)
                guard promotedMaster >= 0, promotedSlave >= 0 else {
                    if promotedMaster >= 0 { Darwin.close(promotedMaster) }
                    if promotedSlave >= 0 { Darwin.close(promotedSlave) }
                    throw ContinuumError.restoreUnavailable(
                        "Continuum could not isolate recreated PTY descriptors for relaunch."
                    )
                }
                nextControllerDescriptor = promotedSlave + 1
                controllerDescriptors.append(contentsOf: [
                    promotedMaster, promotedSlave,
                ])
                if capturedMaster == nil {
                    presentationMasters.append(PreparedPresentationMaster(
                        ttyIndex: ttyIndex,
                        descriptor: promotedMaster
                    ))
                }

                for descriptor in descriptors {
                    var remap = continuum_spawn_descriptor_remap()
                    remap.source_descriptor = descriptor.role == .master
                        ? promotedMaster
                        : promotedSlave
                    remap.target_descriptor = descriptor.fileDescriptor
                    remapsByProcess[descriptor.processIdentifier, default: []]
                        .append(remap)
                }
            }
        } catch {
            closeControllerDescriptors()
            throw error
        }

        return PreparedDescriptorGraph(
            remapsByCapturedProcess: remapsByProcess,
            controllerDescriptors: controllerDescriptors,
            presentationMasters: presentationMasters
        )
    }

    private static func runtimeTCPEndpoint(
        _ socket: DurableSocketResource,
        handle: DurableDescriptorHandle
    ) throws -> continuum_remote_tcp_endpoint_info {
        var result = continuum_remote_tcp_endpoint_info()
        let addressCapacity = MemoryLayout.size(ofValue: result.local_address)
        guard socket.kind == .tcpConnected,
              let localAddress = socket.localAddress,
              let remoteAddress = socket.remoteAddress,
              !localAddress.isEmpty,
              !remoteAddress.isEmpty,
              localAddress.count <= addressCapacity,
              remoteAddress.count <= addressCapacity else {
            throw ContinuumError.integrityFailure(
                "A durable TCP resource contains invalid native address bytes."
            )
        }
        result.process_id = handle.processIdentifier
        result.file_descriptor = handle.fileDescriptor
        result.domain = socket.domain
        result.socket_type = socket.type
        result.protocol = socket.protocol
        result.tcp_state = Int32(TSI_S_ESTABLISHED)
        result.socket_state = 0
        result.local_address_length = UInt32(localAddress.count)
        result.remote_address_length = UInt32(remoteAddress.count)
        result.receive_shutdown = socket.receiveShutdown ? 1 : 0
        result.send_shutdown = socket.sendShutdown ? 1 : 0
        result.receive_queue_bytes = socket.receiveQueueBytes
        result.send_queue_bytes = socket.sendQueueBytes
        withUnsafeMutableBytes(of: &result.local_address) { destination in
            destination.copyBytes(from: localAddress)
        }
        withUnsafeMutableBytes(of: &result.remote_address) { destination in
            destination.copyBytes(from: remoteAddress)
        }
        return result
    }

    private static func socketOptionValues(
        _ socket: DurableSocketResource
    ) throws -> [Int32: Int32] {
        var result: [Int32: Int32] = [:]
        for option in socket.options {
            guard option.level == SOL_SOCKET,
                  option.value.count == MemoryLayout<Int32>.size,
                  result[option.name] == nil else {
                throw ContinuumError.integrityFailure(
                    "A durable listener contains malformed or duplicate socket options."
                )
            }
            result[option.name] = option.value.withUnsafeBytes {
                $0.loadUnaligned(as: Int32.self)
            }
        }
        return result
    }

    private static func isExactLoopbackAddress(
        _ data: Data,
        domain: Int32
    ) -> Bool {
        if domain == AF_INET,
           data.count == MemoryLayout<sockaddr_in>.size {
            let address = data.withUnsafeBytes {
                $0.loadUnaligned(as: sockaddr_in.self)
            }
            return address.sin_len == UInt8(MemoryLayout<sockaddr_in>.size)
                && address.sin_family == sa_family_t(AF_INET)
                && address.sin_port != 0
                && address.sin_addr.s_addr == in_addr_t(INADDR_LOOPBACK).bigEndian
        }
        if domain == AF_INET6,
           data.count == MemoryLayout<sockaddr_in6>.size {
            let address = data.withUnsafeBytes {
                $0.loadUnaligned(as: sockaddr_in6.self)
            }
            var loopback = in6addr_loopback
            return address.sin6_len == UInt8(MemoryLayout<sockaddr_in6>.size)
                && address.sin6_family == sa_family_t(AF_INET6)
                && address.sin6_port != 0
                && withUnsafeBytes(of: address.sin6_addr) { actual in
                    withUnsafeBytes(of: &loopback) { expected in
                        actual.elementsEqual(expected)
                    }
                }
        }
        return false
    }

    static func validateColdSockets(
        graph: DurableDescriptorGraph,
        handles: [DurableDescriptorHandle],
        capturedProcessIdentifiers: Set<Int32>
    ) throws {
        let socketsByID = Dictionary(
            uniqueKeysWithValues: graph.sockets.map { ($0.id, $0) }
        )
        let handlesByResource = Dictionary(grouping: handles, by: \.resourceID)
        let listenerAddresses = graph.sockets.compactMap { socket -> Data? in
            socket.kind == .tcpListener ? socket.localAddress : nil
        }
        guard Set(listenerAddresses).count == listenerAddresses.count else {
            throw ContinuumError.restoreUnavailable(
                "Multiple saved listeners share one address, so their reuse-port routing is ambiguous."
            )
        }
        let supportedStatusMask = O_ACCMODE | O_NONBLOCK | O_ASYNC
        for socket in graph.sockets {
            guard socket.type == SOCK_STREAM,
                  socket.receiveQueueBytes == 0,
                  socket.sendQueueBytes == 0,
                  socket.externalPath == nil,
                  let resourceHandles = handlesByResource[socket.id],
                  let representative = resourceHandles.first,
                  resourceHandles.allSatisfy({ handle in
                      capturedProcessIdentifiers.contains(handle.processIdentifier)
                          && handle.fileDescriptor >= 0
                          && (handle.descriptorFlags == 0
                              || handle.descriptorFlags == FD_CLOEXEC)
                          && handle.statusFlags == representative.statusFlags
                          && handle.statusFlags & O_ACCMODE == O_RDWR
                          && handle.statusFlags & ~supportedStatusMask == 0
                  }) else {
                throw ContinuumError.restoreUnavailable(
                    "A saved socket is not an empty, exactly replayable loopback TCP resource."
                )
            }
            switch socket.kind {
            case .tcpListener:
                guard (socket.domain == AF_INET || socket.domain == AF_INET6),
                      socket.protocol == IPPROTO_TCP,
                      let localAddress = socket.localAddress,
                      isExactLoopbackAddress(
                          localAddress,
                          domain: socket.domain
                      ) else {
                    throw ContinuumError.restoreUnavailable(
                        "A saved TCP listener has an invalid local address."
                    )
                }
                let options = try socketOptionValues(socket)
                guard socket.remoteAddress == nil,
                      socket.peerResourceID == nil,
                      socket.listenerResourceID == nil,
                      !socket.receiveShutdown,
                      !socket.sendShutdown,
                      let backlog = socket.backlog,
                      backlog > 0,
                      Set(options.keys) == Set([
                          SO_REUSEADDR, SO_REUSEPORT, SO_RCVBUF, SO_SNDBUF,
                      ]),
                      options[SO_REUSEADDR] == 0
                        || options[SO_REUSEADDR] == 1,
                      options[SO_REUSEPORT] == 0
                        || options[SO_REUSEPORT] == 1,
                      options[SO_RCVBUF, default: 0] > 0,
                      options[SO_SNDBUF, default: 0] > 0 else {
                    throw ContinuumError.restoreUnavailable(
                        "A saved TCP listener has unsupported options or an invalid backlog."
                    )
                }
            case .tcpConnected:
                guard (socket.domain == AF_INET || socket.domain == AF_INET6),
                      socket.protocol == IPPROTO_TCP,
                      let localAddress = socket.localAddress,
                      isExactLoopbackAddress(
                          localAddress,
                          domain: socket.domain
                      ) else {
                    throw ContinuumError.restoreUnavailable(
                        "A saved TCP stream has an invalid local address."
                    )
                }
                let options = try socketOptionValues(socket)
                let hasReplayableOptions = options.isEmpty || (
                    Set(options.keys) == Set([
                        SO_REUSEADDR, SO_REUSEPORT, SO_RCVBUF, SO_SNDBUF,
                    ])
                    && (options[SO_REUSEADDR] == 0
                        || options[SO_REUSEADDR] == 1)
                    && (options[SO_REUSEPORT] == 0
                        || options[SO_REUSEPORT] == 1)
                    && options[SO_RCVBUF, default: 0] > 0
                    && options[SO_SNDBUF, default: 0] > 0
                )
                guard let remoteAddress = socket.remoteAddress,
                      isExactLoopbackAddress(remoteAddress, domain: socket.domain),
                      hasReplayableOptions,
                      let peerID = socket.peerResourceID,
                      let peer = socketsByID[peerID],
                      peer.peerResourceID == socket.id,
                      peer.localAddress == socket.remoteAddress,
                      peer.remoteAddress == socket.localAddress else {
                    throw ContinuumError.restoreUnavailable(
                        "A saved TCP stream has no unique reciprocal loopback peer."
                    )
                }
                if let listenerID = socket.listenerResourceID {
                    guard let listener = socketsByID[listenerID],
                          listener.kind == .tcpListener,
                          listener.localAddress == socket.localAddress,
                          peer.listenerResourceID == nil else {
                        throw ContinuumError.restoreUnavailable(
                            "A saved accepted TCP stream has no unique matching listener."
                        )
                    }
                }
            case .unixConnected:
                let options = try socketOptionValues(socket)
                guard socket.domain == AF_UNIX,
                      socket.protocol == 0,
                      socket.localAddress == nil,
                      socket.remoteAddress == nil,
                      socket.backlog == nil,
                      socket.listenerResourceID == nil,
                      socket.tcpNoDelay == nil,
                      Set(options.keys) == Set([SO_RCVBUF, SO_SNDBUF]),
                      options[SO_RCVBUF, default: 0] > 0,
                      options[SO_SNDBUF, default: 0] > 0,
                      let peerID = socket.peerResourceID,
                      peerID != socket.id,
                      let peer = socketsByID[peerID],
                      peer.kind == .unixConnected,
                      peer.domain == socket.domain,
                      peer.type == socket.type,
                      peer.protocol == socket.protocol,
                      peer.peerResourceID == socket.id,
                      peer.localAddress == socket.remoteAddress,
                      peer.remoteAddress == socket.localAddress,
                      peer.sendShutdown == socket.receiveShutdown,
                      peer.receiveShutdown == socket.sendShutdown else {
                    throw ContinuumError.restoreUnavailable(
                        "A saved Unix stream is not an empty unnamed reciprocal socket pair."
                    )
                }
                guard resourceHandles.allSatisfy({
                    $0.statusFlags & O_ASYNC == 0
                }) else {
                    throw ContinuumError.restoreUnavailable(
                        "A saved Unix stream uses asynchronous ownership state Continuum cannot replay."
                    )
                }
            case .unixListener:
                throw ContinuumError.restoreUnavailable(
                    "Unix listeners cannot be cold-restored yet."
                )
            }
        }
    }

    static func createEmptyUnixSocketPair(
        first: DurableSocketResource,
        second: DurableSocketResource
    ) throws -> (first: Int32, second: Int32) {
        guard first.kind == .unixConnected,
              second.kind == .unixConnected,
              first.domain == AF_UNIX,
              second.domain == AF_UNIX,
              first.type == SOCK_STREAM,
              second.type == SOCK_STREAM,
              first.protocol == 0,
              second.protocol == 0,
              first.receiveQueueBytes == 0,
              first.sendQueueBytes == 0,
              second.receiveQueueBytes == 0,
              second.sendQueueBytes == 0,
              first.localAddress == nil,
              first.remoteAddress == nil,
              second.localAddress == nil,
              second.remoteAddress == nil,
              first.externalPath == nil,
              second.externalPath == nil,
              first.backlog == nil,
              second.backlog == nil,
              first.listenerResourceID == nil,
              second.listenerResourceID == nil,
              first.tcpNoDelay == nil,
              second.tcpNoDelay == nil,
              first.peerResourceID == second.id,
              second.peerResourceID == first.id,
              first.sendShutdown == second.receiveShutdown,
              first.receiveShutdown == second.sendShutdown else {
            throw ContinuumError.integrityFailure(
                "A durable Unix socket pair is not reciprocal."
            )
        }
        var descriptors = [Int32](repeating: -1, count: 2)
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0,
              fcntl(descriptors[0], F_SETFD, FD_CLOEXEC) == 0,
              fcntl(descriptors[1], F_SETFD, FD_CLOEXEC) == 0 else {
            let savedError = errno
            descriptors.forEach { if $0 >= 0 { Darwin.close($0) } }
            throw ContinuumError.restoreUnavailable(
                "Continuum could not recreate an unnamed Unix socket pair (errno \(savedError))."
            )
        }
        var keepDescriptors = false
        defer {
            if !keepDescriptors {
                Darwin.close(descriptors[0])
                Darwin.close(descriptors[1])
            }
        }
        guard try replayUnixSocketOptions(
            descriptor: descriptors[0],
            resource: first
        ), try replayUnixSocketOptions(
            descriptor: descriptors[1],
            resource: second
        ), applyUnixPairShutdowns(
            firstDescriptor: descriptors[0],
            first: first,
            secondDescriptor: descriptors[1],
            second: second
        ) else {
            throw ContinuumError.restoreUnavailable(
                "Continuum could not replay saved Unix socket options or half-close state."
            )
        }
        keepDescriptors = true
        return (descriptors[0], descriptors[1])
    }

    private static func replayUnixSocketOptions(
        descriptor: Int32,
        resource: DurableSocketResource
    ) throws -> Bool {
        let options = try socketOptionValues(resource)
        guard Set(options.keys) == Set([SO_RCVBUF, SO_SNDBUF]) else {
            return false
        }
        for name in [SO_RCVBUF, SO_SNDBUF] {
            guard let value = options[name], value > 0,
                  setSocketOption(
                      descriptor: descriptor,
                      name: name,
                      value: value
                  ), socketOption(
                      descriptor: descriptor,
                      name: name
                  ) == value else {
                return false
            }
        }
        return true
    }

    private static func applyUnixPairShutdowns(
        firstDescriptor: Int32,
        first: DurableSocketResource,
        secondDescriptor: Int32,
        second: DurableSocketResource
    ) -> Bool {
        if first.sendShutdown,
           Darwin.shutdown(firstDescriptor, SHUT_WR) != 0 {
            return false
        }
        if second.sendShutdown,
           Darwin.shutdown(secondDescriptor, SHUT_WR) != 0 {
            return false
        }
        return true
    }

    private static func setSocketOption(
        descriptor: Int32,
        name: Int32,
        value: Int32,
        level: Int32 = SOL_SOCKET
    ) -> Bool {
        var nativeValue = value
        return setsockopt(
            descriptor,
            level,
            name,
            &nativeValue,
            socklen_t(MemoryLayout.size(ofValue: nativeValue))
        ) == 0
    }

    private static func socketOption(
        descriptor: Int32,
        name: Int32,
        level: Int32 = SOL_SOCKET
    ) -> Int32? {
        var value: Int32 = 0
        var length = socklen_t(MemoryLayout.size(ofValue: value))
        guard getsockopt(
            descriptor,
            level,
            name,
            &value,
            &length
        ) == 0, length == MemoryLayout.size(ofValue: value) else {
            return nil
        }
        return value
    }

    private static func withSocketAddress<Result>(
        _ data: Data,
        _ body: (UnsafePointer<sockaddr>, socklen_t) -> Result
    ) -> Result {
        data.withUnsafeBytes { bytes in
            body(
                bytes.baseAddress!.assumingMemoryBound(to: sockaddr.self),
                socklen_t(bytes.count)
            )
        }
    }

    private static func socketAddress(
        descriptor: Int32,
        peer: Bool
    ) -> Data? {
        var storage = sockaddr_storage()
        var length = socklen_t(MemoryLayout.size(ofValue: storage))
        let status = withUnsafeMutablePointer(to: &storage) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                peer
                    ? getpeername(descriptor, $0, &length)
                    : getsockname(descriptor, $0, &length)
            }
        }
        guard status == 0, length > 0,
              Int(length) <= MemoryLayout.size(ofValue: storage) else {
            return nil
        }
        return withUnsafeBytes(of: &storage) { Data($0.prefix(Int(length))) }
    }

    private static func ephemeralPortAddress(_ data: Data) -> Data? {
        if data.count == MemoryLayout<sockaddr_in>.size {
            var address = data.withUnsafeBytes {
                $0.loadUnaligned(as: sockaddr_in.self)
            }
            address.sin_port = 0
            return withUnsafeBytes(of: &address) { Data($0) }
        }
        if data.count == MemoryLayout<sockaddr_in6>.size {
            var address = data.withUnsafeBytes {
                $0.loadUnaligned(as: sockaddr_in6.self)
            }
            address.sin6_port = 0
            return withUnsafeBytes(of: &address) { Data($0) }
        }
        return nil
    }

    private static func createExactLoopbackListener(
        _ listener: DurableSocketResource
    ) throws -> Int32 {
        guard let address = listener.localAddress,
              let backlog = listener.backlog else {
            throw ContinuumError.integrityFailure(
                "A durable TCP listener is missing its address or backlog."
            )
        }
        let options = try socketOptionValues(listener)
        let occupancyProbe = Darwin.socket(
            listener.domain,
            listener.type,
            listener.protocol
        )
        guard occupancyProbe >= 0 else {
            throw ContinuumError.restoreUnavailable(
                "Continuum could not test the saved listener address for conflicts."
            )
        }
        let probeReusable = setSocketOption(
            descriptor: occupancyProbe,
            name: SO_REUSEADDR,
            value: options[SO_REUSEADDR, default: 0]
        )
        let probeStatus = withSocketAddress(address) {
            Darwin.bind(occupancyProbe, $0, $1)
        }
        Darwin.close(occupancyProbe)
        guard probeReusable, probeStatus == 0 else {
            throw ContinuumError.restoreUnavailable(
                "The exact saved TCP listener address is occupied by another socket."
            )
        }
        let descriptor = Darwin.socket(
            listener.domain,
            listener.type,
            listener.protocol
        )
        guard descriptor >= 0 else {
            throw ContinuumError.restoreUnavailable(
                "Continuum could not create the saved TCP listener."
            )
        }
        var keepDescriptor = false
        defer { if !keepDescriptor { Darwin.close(descriptor) } }
        for name in [SO_REUSEADDR, SO_REUSEPORT, SO_RCVBUF, SO_SNDBUF] {
            guard let value = options[name] else {
                throw ContinuumError.integrityFailure(
                    "A durable TCP listener is missing option \(name)."
                )
            }
            let applied = setSocketOption(
                descriptor: descriptor,
                name: name,
                value: value
            )
            let observed = socketOption(descriptor: descriptor, name: name)
            let matches: Bool
            if name == SO_REUSEADDR || name == SO_REUSEPORT {
                matches = observed.map { ($0 == 0) == (value == 0) } == true
            } else {
                matches = observed == value
            }
            guard applied, matches else {
                let observedText = observed.map(String.init) ?? "unavailable"
                throw ContinuumError.restoreUnavailable(
                    "Continuum could not replay TCP listener option \(name) exactly (saved \(value), observed \(observedText))."
                )
            }
        }
        let bindStatus = withSocketAddress(address) {
            Darwin.bind(descriptor, $0, $1)
        }
        guard fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0,
              bindStatus == 0,
              Darwin.listen(descriptor, backlog) == 0,
              socketAddress(descriptor: descriptor, peer: false) == address else {
            throw ContinuumError.restoreUnavailable(
                "Continuum could not reclaim the exact saved loopback listener address."
            )
        }
        keepDescriptor = true
        return descriptor
    }

    private static func replayConnectedSocketOptions(
        descriptor: Int32,
        resource: DurableSocketResource
    ) throws -> Bool {
        let options = try socketOptionValues(resource)
        if options.isEmpty { return true }
        guard Set(options.keys) == Set([
            SO_REUSEADDR, SO_REUSEPORT, SO_RCVBUF, SO_SNDBUF,
        ]) else {
            return false
        }
        for name in [SO_REUSEADDR, SO_REUSEPORT, SO_RCVBUF, SO_SNDBUF] {
            guard let value = options[name],
                  setSocketOption(
                      descriptor: descriptor,
                      name: name,
                      value: value
                  ),
                  let observed = socketOption(
                      descriptor: descriptor,
                      name: name
                  ) else {
                return false
            }
            if name == SO_REUSEADDR || name == SO_REUSEPORT {
                guard (observed == 0) == (value == 0) else { return false }
            } else if observed != value {
                return false
            }
        }
        if let tcpNoDelay = resource.tcpNoDelay {
            let value: Int32 = tcpNoDelay ? 1 : 0
            guard setSocketOption(
                descriptor: descriptor,
                name: TCP_NODELAY,
                value: value,
                level: IPPROTO_TCP
            ), socketOption(
                descriptor: descriptor,
                name: TCP_NODELAY,
                level: IPPROTO_TCP
            ).map({ ($0 == 0) == !tcpNoDelay }) == true else {
                return false
            }
        }
        return true
    }

    private static func createConnectedPairThroughListener(
        listenerDescriptor: Int32,
        accepted: DurableSocketResource,
        client: DurableSocketResource
    ) throws -> (accepted: Int32, client: Int32) {
        guard let listenerAddress = accepted.localAddress,
              let clientAddress = client.localAddress else {
            throw ContinuumError.integrityFailure(
                "A linked TCP pair is missing its exact endpoint addresses."
            )
        }
        func makeClient(
            boundTo address: Data,
            permitAddressInUse: Bool
        ) throws -> Int32? {
            let descriptor = Darwin.socket(
                client.domain,
                client.type,
                client.protocol
            )
            guard descriptor >= 0 else {
                throw ContinuumError.restoreUnavailable(
                    "Continuum could not create the client side of a saved TCP stream."
                )
            }
            guard fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0,
                  setSocketOption(
                      descriptor: descriptor,
                      name: SO_REUSEADDR,
                      value: 1
                  ),
                  setSocketOption(
                      descriptor: descriptor,
                      name: SO_REUSEPORT,
                      value: 1
                  ) else {
                let savedError = errno
                Darwin.close(descriptor)
                throw ContinuumError.restoreUnavailable(
                    "Continuum could not configure a saved accepted-stream client (errno \(savedError))."
                )
            }
            let bindStatus = withSocketAddress(address) {
                Darwin.bind(descriptor, $0, $1)
            }
            if bindStatus != 0 {
                let savedError = errno
                Darwin.close(descriptor)
                if permitAddressInUse, savedError == EADDRINUSE {
                    return nil
                }
                throw ContinuumError.restoreUnavailable(
                    "Continuum could not bind a saved accepted-stream client (errno \(savedError))."
                )
            }
            return descriptor
        }
        let ephemeralAddress = ephemeralPortAddress(clientAddress)
        var clientDescriptor: Int32
        if let exactDescriptor = try makeClient(
            boundTo: clientAddress,
            permitAddressInUse: ephemeralAddress != nil
        ) {
            clientDescriptor = exactDescriptor
        } else if let ephemeralAddress,
                  let fallbackDescriptor = try makeClient(
                      boundTo: ephemeralAddress,
                      permitAddressInUse: false
                  ) {
            clientDescriptor = fallbackDescriptor
        } else {
            throw ContinuumError.restoreUnavailable(
                "Continuum could not bind a saved accepted-stream client."
            )
        }
        var acceptedDescriptor: Int32 = -1
        var keepDescriptors = false
        defer {
            if !keepDescriptors {
                if clientDescriptor >= 0 { Darwin.close(clientDescriptor) }
                if acceptedDescriptor >= 0 { Darwin.close(acceptedDescriptor) }
            }
        }
        var connectStatus = withSocketAddress(listenerAddress) {
            Darwin.connect(clientDescriptor, $0, $1)
        }
        // A killed connection can leave its exact four-tuple in TIME_WAIT.
        // Keep the listener address exact, but use a fresh loopback client port
        // only when Darwin explicitly refuses that tuple as already in use.
        if connectStatus != 0, errno == EADDRINUSE,
           let ephemeralAddress {
            Darwin.close(clientDescriptor)
            clientDescriptor = -1
            guard let fallbackDescriptor = try makeClient(
                boundTo: ephemeralAddress,
                permitAddressInUse: false
            ) else {
                throw ContinuumError.restoreUnavailable(
                    "Continuum could not bind a fallback accepted-stream client."
                )
            }
            clientDescriptor = fallbackDescriptor
            connectStatus = withSocketAddress(listenerAddress) {
                Darwin.connect(clientDescriptor, $0, $1)
            }
        }
        guard connectStatus == 0 else {
            throw ContinuumError.restoreUnavailable(
                "Continuum could not reconnect a saved client through its exact listener (errno \(errno))."
            )
        }
        guard setSocketOption(
            descriptor: clientDescriptor,
            name: SO_REUSEADDR,
            value: 0
        ), setSocketOption(
            descriptor: clientDescriptor,
            name: SO_REUSEPORT,
            value: 0
        ), socketOption(descriptor: clientDescriptor, name: SO_REUSEADDR)
            .map({ $0 == 0 }) == true,
        socketOption(descriptor: clientDescriptor, name: SO_REUSEPORT)
            .map({ $0 == 0 }) == true else {
            throw ContinuumError.restoreUnavailable(
                "Continuum could not clear temporary client socket options."
            )
        }
        acceptedDescriptor = Darwin.accept(listenerDescriptor, nil, nil)
        guard acceptedDescriptor >= 0,
              fcntl(acceptedDescriptor, F_SETFD, FD_CLOEXEC) == 0,
              socketAddress(descriptor: acceptedDescriptor, peer: false)
                == accepted.localAddress,
              socketAddress(descriptor: acceptedDescriptor, peer: true)
                == socketAddress(descriptor: clientDescriptor, peer: false),
              socketAddress(descriptor: clientDescriptor, peer: true)
                == client.remoteAddress else {
            throw ContinuumError.restoreUnavailable(
                "The kernel did not recreate a reciprocal accepted TCP stream."
            )
        }
        func applyShutdowns(
            descriptor: Int32,
            resource: DurableSocketResource
        ) -> Bool {
            if resource.receiveShutdown && resource.sendShutdown {
                return Darwin.shutdown(descriptor, SHUT_RDWR) == 0
            }
            if resource.receiveShutdown,
               Darwin.shutdown(descriptor, SHUT_RD) != 0 {
                return false
            }
            if resource.sendShutdown,
               Darwin.shutdown(descriptor, SHUT_WR) != 0 {
                return false
            }
            return true
        }
        guard applyShutdowns(descriptor: acceptedDescriptor, resource: accepted),
              applyShutdowns(descriptor: clientDescriptor, resource: client) else {
            throw ContinuumError.restoreUnavailable(
                "Continuum could not replay a saved TCP half-close."
            )
        }
        keepDescriptors = true
        return (acceptedDescriptor, clientDescriptor)
    }

    private static func runtimeTCPEndpoint(
        _ endpoint: DurableTCPEndpoint
    ) throws -> continuum_remote_tcp_endpoint_info {
        var result = continuum_remote_tcp_endpoint_info()
        let addressCapacity = MemoryLayout.size(ofValue: result.local_address)
        guard endpoint.localAddress.count == Int(endpoint.localAddressLength),
              endpoint.remoteAddress.count == Int(endpoint.remoteAddressLength),
              endpoint.localAddress.count <= addressCapacity,
              endpoint.remoteAddress.count <= addressCapacity else {
            throw ContinuumError.integrityFailure(
                "A durable TCP endpoint contains invalid native address bytes."
            )
        }
        result.process_id = endpoint.processIdentifier
        result.file_descriptor = endpoint.fileDescriptor
        result.domain = endpoint.domain
        result.socket_type = endpoint.socketType
        result.protocol = endpoint.socketProtocol
        result.tcp_state = endpoint.tcpState
        result.socket_state = endpoint.socketState
        result.local_address_length = endpoint.localAddressLength
        result.remote_address_length = endpoint.remoteAddressLength
        result.receive_shutdown = endpoint.receiveShutdown ? 1 : 0
        result.send_shutdown = endpoint.sendShutdown ? 1 : 0
        result.receive_queue_bytes = endpoint.receiveQueueBytes
        result.send_queue_bytes = endpoint.sendQueueBytes
        withUnsafeMutableBytes(of: &result.local_address) { destination in
            destination.copyBytes(from: endpoint.localAddress)
        }
        withUnsafeMutableBytes(of: &result.remote_address) { destination in
            destination.copyBytes(from: endpoint.remoteAddress)
        }
        return result
    }

    private static func runtimePTYDescriptor(
        _ descriptor: DurablePTYDescriptor
    ) throws -> continuum_remote_pty_descriptor_info {
        var result = continuum_remote_pty_descriptor_info()
        result.process_id = descriptor.processIdentifier
        result.file_descriptor = descriptor.fileDescriptor
        result.open_flags = descriptor.openFlags
        result.role = descriptor.role == .master
            ? CONTINUUM_REMOTE_PTY_ROLE_MASTER
            : CONTINUUM_REMOTE_PTY_ROLE_SLAVE
        result.device = descriptor.device
        result.inode = descriptor.inode
        result.raw_device = descriptor.rawDevice
        result.device_major = descriptor.deviceMajor
        result.device_minor = descriptor.deviceMinor
        result.tty_index = descriptor.ttyIndex
        result.alias_identity = descriptor.aliasIdentity
        if let inputQueueBytes = descriptor.inputQueueBytes {
            result.input_queue_known = 1
            result.input_queue_bytes = inputQueueBytes
        }
        if let outputQueueBytes = descriptor.outputQueueBytes {
            result.output_queue_known = 1
            result.output_queue_bytes = outputQueueBytes
        }
        if let attributes = descriptor.terminalAttributes {
            guard attributes.count == MemoryLayout.size(
                ofValue: result.terminal_attributes
            ) else {
                throw ContinuumError.integrityFailure(
                    "A durable PTY record contains invalid terminal attributes."
                )
            }
            withUnsafeMutableBytes(of: &result.terminal_attributes) {
                $0.copyBytes(from: attributes)
            }
            result.terminal_attributes_known = 1
        }
        if let windowSize = descriptor.windowSize {
            guard windowSize.count == MemoryLayout.size(
                ofValue: result.window_size
            ) else {
                throw ContinuumError.integrityFailure(
                    "A durable PTY record contains an invalid window size."
                )
            }
            withUnsafeMutableBytes(of: &result.window_size) {
                $0.copyBytes(from: windowSize)
            }
            result.window_size_known = 1
        }
        return result
    }

    static func shouldUseBrokeredPair(
        _ orderedMembers: [DurableProcessImage],
        rootProcessIdentifier: Int32
    ) -> Bool {
        guard orderedMembers.count == 2 else { return false }
        let root = orderedMembers[0]
        let child = orderedMembers[1]
        return root.processIdentifier == rootProcessIdentifier
            && child.parentProcessIdentifier == root.processIdentifier
    }

    private static func parentFirstMembers(
        _ members: [DurableProcessImage]
    ) throws -> [DurableProcessImage] {
        var remaining: [Int32: DurableProcessImage] = [:]
        for member in members {
            guard member.processIdentifier > 1,
                  remaining.updateValue(
                      member,
                      forKey: member.processIdentifier
                  ) == nil else {
                throw ContinuumError.integrityFailure(
                    "The durable process forest contains an invalid or duplicate process identity."
                )
            }
        }
        var ordered: [DurableProcessImage] = []
        while !remaining.isEmpty {
            let ready = remaining.values.filter {
                remaining[$0.parentProcessIdentifier] == nil
            }.sorted { $0.processIdentifier < $1.processIdentifier }
            if ready.isEmpty {
                throw ContinuumError.integrityFailure(
                    "The durable process forest contains a parent cycle."
                )
            }
            for process in ready {
                ordered.append(process)
                remaining.removeValue(forKey: process.processIdentifier)
            }
        }
        return ordered
    }

    private func validateExecutable(
        process: DurableProcessImage,
        launch: DurableLaunchContract
    ) throws {
        guard !launch.arguments.isEmpty,
              FileManager.default.isExecutableFile(atPath: launch.executablePath) else {
            throw ContinuumError.restoreUnavailable(
                "The captured executable is missing or no longer executable."
            )
        }
        let attributes = try FileManager.default.attributesOfItem(
            atPath: launch.executablePath
        )
        guard let device = attributes[.systemNumber] as? NSNumber,
              let inode = attributes[.systemFileNumber] as? NSNumber,
              device.uint64Value == process.executableDevice,
              inode.uint64Value == process.executableInode else {
            throw ContinuumError.restoreUnavailable(
                "The app executable changed after this checkpoint was captured."
            )
        }
    }

    private func validateColdKqueues(
        graph: DurableDescriptorGraph,
        handles: [DurableDescriptorHandle],
        capturedProcessIdentifiers: Set<Int32>
    ) throws {
        guard !graph.kqueues.isEmpty else { return }
        let handlesByResource = Dictionary(grouping: handles, by: \.resourceID)
        var handlesByProcessAndDescriptor: [String: DurableDescriptorHandle] = [:]
        for handle in graph.handles {
            let key = "\(handle.processIdentifier):\(handle.fileDescriptor)"
            guard handlesByProcessAndDescriptor.updateValue(handle, forKey: key) == nil else {
                throw ContinuumError.integrityFailure(
                    "The durable descriptor graph contains duplicate process descriptors."
                )
            }
        }
        let pipesByID = Dictionary(
            uniqueKeysWithValues: graph.pipes.map { ($0.id, $0) }
        )
        let socketsByID = Dictionary(
            uniqueKeysWithValues: graph.sockets.map { ($0.id, $0) }
        )
        let supportedRegistrationFlags: UInt16 = 0x01BD
        for queue in graph.kqueues {
            guard queue.state & ~0x0002 == 0x0010,
                  capturedProcessIdentifiers.contains(queue.processIdentifier),
                  let queueHandles = handlesByResource[queue.id],
                  queueHandles.count == 1,
                  let queueHandle = queueHandles.first,
                  queueHandle.processIdentifier == queue.processIdentifier,
                  queueHandle.fileDescriptor >= 0,
                  queueHandle.statusFlags == O_RDWR,
                  queueHandle.descriptorFlags
                    & ~(FD_CLOEXEC | FD_CLOFORK) == 0 else {
                throw ContinuumError.restoreUnavailable(
                    "This snapshot contains a shared, workloop, or non-KEV64 kqueue that Continuum cannot rebuild safely."
                )
            }
            for registration in queue.registrations {
                guard registration.status == 0,
                      registration.qos == 0,
                      registration.flags & ~supportedRegistrationFlags == 0,
                      registration.flags & 0x0002 == 0,
                      registration.flags & 0x0040 == 0 else {
                    throw ContinuumError.restoreUnavailable(
                        "A saved kqueue contains an active event or unsupported registration flags."
                    )
                }
                switch registration.filter {
                case Int16(EVFILT_USER):
                    guard registration.fflags & 0xFF00_0000 == 0,
                          registration.savedFflags & 0xFF00_0000 == 0 else {
                        throw ContinuumError.restoreUnavailable(
                            "A saved EVFILT_USER registration is triggered or uses unsupported control flags."
                        )
                    }
                case Int16(EVFILT_READ):
                    guard registration.ident <= UInt64(Int32.max),
                          registration.fflags & ~UInt32(NOTE_LOWAT) == 0,
                          registration.savedFflags & ~UInt32(NOTE_LOWAT) == 0,
                          registration.data == 0,
                          registration.savedData >= 0,
                          let referenced = handlesByProcessAndDescriptor[
                            "\(queue.processIdentifier):\(registration.ident)"
                          ],
                          (pipesByID[referenced.resourceID]?.queuedBytes == 0
                            || socketsByID[referenced.resourceID]?.receiveQueueBytes == 0)
                    else {
                        throw ContinuumError.restoreUnavailable(
                            "A saved EVFILT_READ registration references missing or queued descriptor state."
                        )
                    }
                default:
                    throw ContinuumError.restoreUnavailable(
                        "A saved kqueue uses a filter Continuum cannot rebuild yet."
                    )
                }
            }
        }
    }

    private static func regionIntersectsPreparedPthread(
        _ region: DurableMemoryRegion,
        entries: [continuum_pthread_reconstruction_plan_entry]
    ) -> Bool {
        guard let regionEnd = checkedEnd(region.address, region.length) else {
            return true
        }
        return entries.contains { entry in
            rangesIntersect(
                region.address,
                regionEnd,
                entry.stack_copy_address,
                checkedEnd(entry.stack_copy_address, entry.stack_copy_length)
                    ?? UInt64.max
            ) || rangesIntersect(
                region.address,
                regionEnd,
                entry.preserved_pthread_address,
                checkedEnd(
                    entry.preserved_pthread_address,
                    entry.preserved_pthread_length
                ) ?? UInt64.max
            )
        }
    }

    private func restorePreparedPthreadRegion(
        _ region: DurableMemoryRegion,
        entries: [continuum_pthread_reconstruction_plan_entry],
        session: OpaquePointer,
        processIdentifier: Int32,
        snapshotID: SnapshotID,
        repository: any SnapshotRepository
    ) async throws -> (chunkCount: Int, writtenBytes: UInt64) {
        guard let regionEnd = Self.checkedEnd(region.address, region.length) else {
            throw ContinuumError.integrityFailure(
                "A pthread mapping exceeds the address space."
            )
        }
        var coverage: [(UInt64, UInt64)] = []
        for entry in entries {
            for (start, length) in [
                (entry.stack_copy_address, entry.stack_copy_length),
                (entry.preserved_pthread_address, entry.preserved_pthread_length),
            ] {
                guard let end = Self.checkedEnd(start, length) else {
                    throw ContinuumError.integrityFailure(
                        "The prepared pthread plan exceeds the address space."
                    )
                }
                let clippedStart = max(start, region.address)
                let clippedEnd = min(end, regionEnd)
                if clippedStart < clippedEnd {
                    coverage.append((clippedStart, clippedEnd))
                }
            }
        }
        coverage.sort { $0.0 < $1.0 }
        var coveredThrough = region.address
        for interval in coverage {
            guard interval.0 <= coveredThrough else {
                throw ContinuumError.restoreUnavailable(
                    "A captured pthread mapping does not match the live libpthread allocation."
                )
            }
            coveredThrough = max(coveredThrough, interval.1)
        }
        guard coveredThrough == regionEnd else {
            throw ContinuumError.restoreUnavailable(
                "A captured pthread mapping is only partially represented by the replacement."
            )
        }

        var chunkOffset: UInt64 = 0
        var chunkCount = 0
        var writtenBytes: UInt64 = 0
        for chunk in region.chunks {
            guard chunk.logicalBytes > 0,
                  chunk.logicalBytes <= 1_024 * 1_024,
                  chunkOffset <= region.length,
                  chunk.logicalBytes <= region.length - chunkOffset,
                  let chunkAddress = Self.checkedEnd(
                    region.address,
                    chunkOffset
                  ),
                  let chunkEnd = Self.checkedEnd(
                    chunkAddress,
                    chunk.logicalBytes
                  ) else {
                throw ContinuumError.integrityFailure(
                    "A pthread memory chunk exceeds its captured mapping."
                )
            }
            let logicalName = chunk.artifactName
                ?? Self.legacyMemoryArtifactName(
                    processIdentifier: processIdentifier,
                    address: region.address,
                    offset: chunkOffset
                )
            let artifact = try await repository.artifact(
                for: snapshotID,
                logicalName: logicalName
            )
            guard artifact.kind == .memoryPage,
                  UInt64(artifact.data.count) == chunk.logicalBytes,
                  Self.sha256(artifact.data) == chunk.hash else {
                throw ContinuumError.integrityFailure(
                    "Pthread stack chunk \(logicalName) does not match its manifest."
                )
            }

            for originalEntry in entries {
                guard let stackEnd = Self.checkedEnd(
                    originalEntry.stack_copy_address,
                    originalEntry.stack_copy_length
                ) else {
                    throw ContinuumError.integrityFailure(
                        "The prepared pthread stack range overflowed."
                    )
                }
                let writeStart = max(chunkAddress, originalEntry.stack_copy_address)
                let writeEnd = min(chunkEnd, stackEnd)
                guard writeStart < writeEnd else { continue }
                let dataStart = Int(writeStart - chunkAddress)
                let dataEnd = Int(writeEnd - chunkAddress)
                let slice = artifact.data.subdata(in: dataStart..<dataEnd)
                var entry = originalEntry
                var report = continuum_remote_restore_report()
                let status = slice.withUnsafeBytes { bytes in
                    continuum_remote_session_write_prepared_pthread_stack(
                        session,
                        &entry,
                        writeStart - entry.stack_copy_address,
                        bytes.baseAddress,
                        bytes.count,
                        &report
                    )
                }
                guard status == CONTINUUM_STATUS_OK else {
                    let detail = continuum_status_string(status).map {
                        String(cString: $0)
                    } ?? "status \(status.rawValue)"
                    throw ContinuumError.restoreUnavailable(
                        "Could not restore pthread stack 0x\(String(entry.stack_copy_address, radix: 16)) + 0x\(String(writeStart - entry.stack_copy_address, radix: 16)) (\(slice.count) bytes): \(detail); wrote \(report.bytes_written) bytes, mismatch +0x\(String(report.observed_offset, radix: 16)) expected \(report.observed_flags) observed \(report.observed_user_tag), Mach \(report.mach_result)."
                    )
                }
                guard report.readback_verified != 0,
                      report.bytes_written == UInt64(slice.count) else {
                    throw ContinuumError.integrityFailure(
                        "A prepared pthread stack failed readback verification."
                    )
                }
                let (nextBytes, overflow) = writtenBytes.addingReportingOverflow(
                    UInt64(slice.count)
                )
                guard !overflow else {
                    throw ContinuumError.integrityFailure(
                        "The prepared pthread stacks exceed numeric limits."
                    )
                }
                writtenBytes = nextBytes
            }
            chunkOffset += chunk.logicalBytes
            chunkCount += 1
        }
        guard chunkOffset == region.length else {
            throw ContinuumError.integrityFailure(
                "A prepared pthread mapping is incomplete."
            )
        }
        return (chunkCount, writtenBytes)
    }

    private static func checkedEnd(_ start: UInt64, _ length: UInt64) -> UInt64? {
        let result = start.addingReportingOverflow(length)
        return result.overflow ? nil : result.partialValue
    }

    private static func rangesIntersect(
        _ firstStart: UInt64,
        _ firstEnd: UInt64,
        _ secondStart: UInt64,
        _ secondEnd: UInt64
    ) -> Bool {
        firstStart < secondEnd && secondStart < firstEnd
    }

    private func requireRuntimeOK(
        _ status: continuum_status,
        operation: String
    ) throws {
        guard status == CONTINUUM_STATUS_OK else {
            let detail = continuum_status_string(status).map(String.init(cString:))
                ?? "status \(status.rawValue)"
            throw ContinuumError.restoreUnavailable(
                "Could not \(operation): \(detail)."
            )
        }
    }

    private func reconstructionOperation(
        _ operation: String,
        region: DurableMemoryRegion,
        report: continuum_remote_restore_report
    ) -> String {
        var description = "\(operation) mapping 0x\(String(region.address, radix: 16))"
            + " length 0x\(String(region.length, radix: 16))"
        if report.observed_mapping_length > 0 {
            description += ", observed 0x\(String(report.observed_mapping_address, radix: 16))"
                + " length 0x\(String(report.observed_mapping_length, radix: 16))"
                + " prot \(report.observed_protection)/\(report.observed_maximum_protection)"
                + " share \(report.observed_share_mode)"
                + " inherit \(report.observed_inheritance)"
                + " tag \(report.observed_user_tag)"
                + " pager \(report.observed_external_pager)"
                + " flags \(report.observed_flags)"
        }
        description += report.reconstruction_stage == 0
                ? ""
                : " at stage \(report.reconstruction_stage), Mach \(report.mach_result)"
        return description
    }

    private static func bootstrapIdentity(
        from descriptor: Int32,
        expectedProcessIdentifier: Int32,
        localIdentity: continuum_bootstrap_identity,
        expectedRestoredDescriptorCount: Int
    ) throws -> continuum_bootstrap_identity {
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_uid == geteuid(),
              metadata.st_nlink == 0,
              (metadata.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO))
                == (S_IRUSR | S_IWUSR),
              metadata.st_size > 0,
              metadata.st_size < 256 else {
            throw ContinuumError.restoreUnavailable(
                "Continuum's private bootstrap descriptor changed unexpectedly."
            )
        }

        var bytes = [UInt8](repeating: 0, count: 256)
        let count = bytes.withUnsafeMutableBytes { buffer in
            pread(descriptor, buffer.baseAddress, buffer.count, 0)
        }
        guard count > 0, count < bytes.count else {
            throw ContinuumError.restoreUnavailable(
                "Continuum's pre-main bootstrap did not report its reconstruction entry."
            )
        }
        var extra: UInt8 = 0
        guard pread(descriptor, &extra, 1, off_t(count)) == 0 else {
            throw ContinuumError.restoreUnavailable(
                "Continuum's pre-main bootstrap descriptor is too large."
            )
        }
        let contents = String(decoding: bytes.prefix(count), as: UTF8.self)
        let fields = contents.split(whereSeparator: { $0.isWhitespace })
        if ProcessInfo.processInfo.environment["CONTINUUM_CAPTURE_TRACE"] != nil {
            fputs(
                "continuum bootstrap report expected-pid=\(expectedProcessIdentifier) "
                    + "expected-descriptors=\(expectedRestoredDescriptorCount) "
                    + "contents=\(contents.debugDescription)\n",
                stderr
            )
        }
        guard fields.count == 6,
              fields[0] == "CONTINUUM_BOOTSTRAP_V4",
              Int(fields[5]) == expectedRestoredDescriptorCount,
              Int32(fields[1]) == expectedProcessIdentifier else {
            throw ContinuumError.restoreUnavailable(
                "Continuum's pre-main bootstrap descriptor is invalid."
            )
        }
        let imageBaseText = fields[2].hasPrefix("0x")
            ? fields[2].dropFirst(2)
            : fields[2][...]
        let addressText = fields[3].hasPrefix("0x")
            ? fields[3].dropFirst(2)
            : fields[3][...]
        let pthreadPrepareAddressText = fields[4].hasPrefix("0x")
            ? fields[4].dropFirst(2)
            : fields[4][...]
        guard let imageBase = UInt64(imageBaseText, radix: 16), imageBase != 0,
              let address = UInt64(addressText, radix: 16), address != 0,
              let pthreadPrepareAddress = UInt64(
                pthreadPrepareAddressText,
                radix: 16
              ), pthreadPrepareAddress != 0 else {
            throw ContinuumError.restoreUnavailable(
                "Continuum's pre-main bootstrap address is invalid."
            )
        }
        let (expectedAddress, overflow) = imageBase.addingReportingOverflow(
            localIdentity.copy_offset
        )
        let (expectedPthreadPrepareAddress, pthreadPrepareOverflow) =
            imageBase.addingReportingOverflow(
                localIdentity.pthread_prepare_offset
            )
        guard !overflow, expectedAddress == address,
              !pthreadPrepareOverflow,
              expectedPthreadPrepareAddress == pthreadPrepareAddress else {
            throw ContinuumError.restoreUnavailable(
                "Continuum's pre-main bootstrap symbol does not match its signed library."
            )
        }
        var identity = localIdentity
        identity.image_base = imageBase
        identity.copy_address = address
        identity.pthread_prepare_address = pthreadPrepareAddress
        return identity
    }

    private static func processIsAbsent(_ processIdentifier: Int32) -> Bool {
        errno = 0
        return kill(processIdentifier, 0) != 0 && errno == ESRCH
    }

    private static func parentProcessIdentifier(
        for processIdentifier: Int32
    ) -> Int32? {
        var info = proc_bsdinfo()
        let byteCount = proc_pidinfo(
            processIdentifier,
            PROC_PIDTBSDINFO,
            0,
            &info,
            Int32(MemoryLayout<proc_bsdinfo>.size)
        )
        guard byteCount == MemoryLayout<proc_bsdinfo>.size else { return nil }
        return Int32(bitPattern: info.pbi_ppid)
    }

    private static func fileReplacements(
        descriptors: [DurableWritableFileDescriptor],
        files: [DurableFileImage],
        snapshotID: SnapshotID,
        repository: any SnapshotRepository
    ) async throws -> [LocalFileReplacement] {
        var paths: Set<String> = []
        var replacements: [LocalFileReplacement] = []
        for descriptor in descriptors where paths.insert(
            descriptor.originalPath
        ).inserted {
            guard let file = files.first(where: {
                $0.originalPath == descriptor.originalPath
                    && $0.device == descriptor.device
                    && $0.inode == descriptor.inode
                    && $0.mode == descriptor.mode
            }) else {
                throw ContinuumError.integrityFailure(
                    "The durable descriptor references a missing file image."
                )
            }
            let data = try await durableFileData(
                file,
                snapshotID: snapshotID,
                repository: repository
            )
            replacements.append(LocalFileReplacement(
                originalPath: file.originalPath,
                device: file.device,
                inode: file.inode,
                mode: file.mode,
                data: data
            ))
        }
        return replacements.sorted { $0.originalPath < $1.originalPath }
    }

    private static func durableFileData(
        _ file: DurableFileImage,
        snapshotID: SnapshotID,
        repository: any SnapshotRepository
    ) async throws -> Data {
        guard file.byteCount <= UInt64(Int.max) else {
            throw ContinuumError.restoreUnavailable(
                "A durable local file is too large for this Continuum build."
            )
        }
        var data = Data()
        data.reserveCapacity(Int(file.byteCount))
        for (index, reference) in file.chunks.enumerated() {
            guard reference.logicalBytes > 0,
                  reference.logicalBytes <= UInt64(Int.max),
                  let logicalName = reference.artifactName else {
                throw ContinuumError.integrityFailure(
                    "A durable file block has invalid metadata."
                )
            }
            let artifact = try await repository.artifact(
                for: snapshotID,
                logicalName: logicalName
            )
            guard artifact.kind == .fileBlock,
                  UInt64(artifact.data.count) == reference.logicalBytes,
                  sha256(artifact.data) == reference.hash else {
                throw ContinuumError.integrityFailure(
                    "File block \(index) for \(file.originalPath) failed validation."
                )
            }
            data.append(artifact.data)
        }
        guard UInt64(data.count) == file.byteCount else {
            throw ContinuumError.integrityFailure(
                "The durable file image for \(file.originalPath) is incomplete."
            )
        }
        return data
    }

    private static func beginFileReplacement(
        _ replacements: [LocalFileReplacement],
        replacementProcessIdentifier: Int32,
        safetyRootURL: URL
    ) async throws -> PreparedFileRollback? {
        guard !replacements.isEmpty else { return nil }
        do {
            try FileManager.default.createDirectory(
                at: safetyRootURL,
                withIntermediateDirectories: true
            )
        } catch {
            throw ContinuumError.restoreUnavailable(
                "Continuum could not create its durable cold-file transaction directory."
            )
        }
        let transactionID = UUID()
        let rootURL = safetyRootURL.appendingPathComponent(
            transactionID.uuidString,
            isDirectory: true
        )
        let store: APFSLocalFileCheckpointStore
        do {
            store = try APFSLocalFileCheckpointStore(rootURL: rootURL)
        } catch {
            throw ContinuumError.restoreUnavailable(
                "Continuum could not create a cold file safety root."
            )
        }
        let safetySnapshotID = UUID()
        var safetyCaptured = false
        do {
            try ensureNoExternalWriters(
                replacements,
                allowedProcessIdentifier: replacementProcessIdentifier
            )
            _ = try await store.capture(
                snapshotID: safetySnapshotID,
                files: replacements.map {
                    URL(fileURLWithPath: $0.originalPath)
                }
            )
            safetyCaptured = true
            let journal = ColdFileTransactionJournal(
                formatVersion: 1,
                transactionID: transactionID,
                safetySnapshotID: safetySnapshotID,
                replacementProcessIdentifier: replacementProcessIdentifier,
                state: "prepared",
                createdAt: Date(),
                entries: replacements.map {
                    ColdFileTransactionJournal.Entry(
                        originalPath: $0.originalPath,
                        device: $0.device,
                        inode: $0.inode,
                        installedSHA256: sha256($0.data)
                    )
                }
            )
            try writeFileTransactionJournal(
                journal,
                rootURL: rootURL
            )
            try ensureNoExternalWriters(
                replacements,
                allowedProcessIdentifier: replacementProcessIdentifier
            )
            let report = try store.replaceCoherently(replacements)
            var byteCount: UInt64 = 0
            for replacement in replacements {
                let (next, overflow) = byteCount.addingReportingOverflow(
                    UInt64(replacement.data.count)
                )
                guard !overflow else {
                    throw ContinuumError.integrityFailure(
                        "The cold file transaction exceeds numeric limits."
                    )
                }
                byteCount = next
            }
            guard report.restoredFileCount == replacements.count,
                  byteCount <= UInt64(Int64.max),
                  report.restoredBytes == Int64(byteCount) else {
                throw ContinuumError.integrityFailure(
                    "The cold file transaction returned an incomplete report."
                )
            }
            return PreparedFileRollback(
                store: store,
                snapshotID: safetySnapshotID,
                rootURL: rootURL,
                replacedFileCount: replacements.count,
                replacedBytes: byteCount,
                installedFiles: replacements
            )
        } catch {
            if safetyCaptured {
                do {
                    _ = try store.restoreCoherently(
                        snapshotID: safetySnapshotID
                    )
                } catch {
                    throw ContinuumError.integrityFailure(
                        "Cold file replacement failed and its safety rollback also failed."
                    )
                }
            }
            try? FileManager.default.removeItem(at: rootURL)
            if let continuumError = error as? ContinuumError {
                throw continuumError
            }
            throw ContinuumError.restoreUnavailable(
                "Cold file replacement failed: \(error.localizedDescription)"
            )
        }
    }

    private static func rollbackFiles(
        _ rollback: PreparedFileRollback?
    ) throws {
        guard let rollback else { return }
        try validateInstalledFiles(
            rollback,
            allowedProcessIdentifier: 0
        )
        _ = try rollback.store.restoreCoherently(
            snapshotID: rollback.snapshotID
        )
        try FileManager.default.removeItem(at: rollback.rootURL)
    }

    private static func validateInstalledFiles(
        _ rollback: PreparedFileRollback,
        allowedProcessIdentifier: Int32
    ) throws {
        try ensureNoExternalWriters(
            rollback.installedFiles,
            allowedProcessIdentifier: allowedProcessIdentifier
        )
        for file in rollback.installedFiles {
            guard try fileIdentity(atPath: file.originalPath)
                    == (file.device, file.inode),
                  try sha256File(atPath: file.originalPath)
                    == sha256(file.data) else {
                throw ContinuumError.integrityFailure(
                    "A cold-restore file changed after preparation. Continuum preserved its safety transaction instead of overwriting newer bytes."
                )
            }
        }
    }

    static func bootstrapDescriptorPlan(
        _ descriptors: [DurableWritableFileDescriptor],
        pipeHandles: [DurableDescriptorHandle] = [],
        socketHandles: [DurableDescriptorHandle] = [],
        kqueues: [BootstrapKqueue] = []
    ) throws -> Data {
        let resourceCount = pipeHandles.count + socketHandles.count
            + kqueues.count
        let registrationCount = kqueues.reduce(0) {
            $0 + $1.resource.registrations.count
        }
        guard descriptors.count + resourceCount <= 1_024,
              registrationCount <= 1_024 else {
            throw ContinuumError.restoreUnavailable(
                "The process owns too many descriptors or kqueue registrations for cold reconstruction."
            )
        }
        var seenDescriptors: Set<Int32> = []
        var lines: [String]
        if !kqueues.isEmpty {
            lines = [
                "CONTINUUM_FD_PLAN_V4 \(descriptors.count) "
                    + "\(resourceCount) \(registrationCount)",
            ]
        } else if !socketHandles.isEmpty {
            lines = [
                "CONTINUUM_FD_PLAN_V3 \(descriptors.count) \(resourceCount)",
            ]
        } else if !pipeHandles.isEmpty {
            lines = [
                "CONTINUUM_FD_PLAN_V2 \(descriptors.count) "
                    + "\(pipeHandles.count)",
            ]
        } else {
            lines = ["CONTINUUM_FD_PLAN_V1 \(descriptors.count)"]
        }
        lines.reserveCapacity(descriptors.count + resourceCount + 1)
        for descriptor in descriptors {
            guard descriptor.fileDescriptor >= 0,
                  descriptor.offset >= 0,
                  seenDescriptors.insert(descriptor.fileDescriptor).inserted,
                  descriptor.originalPath.hasPrefix("/"),
                  let pathBytes = descriptor.originalPath.data(using: .utf8),
                  !pathBytes.isEmpty,
                  pathBytes.count < Int(PATH_MAX),
                  !pathBytes.contains(0) else {
                throw ContinuumError.integrityFailure(
                    "The durable writable-descriptor plan is invalid."
                )
            }
            let encodedPath = pathBytes.map {
                String(format: "%02x", $0)
            }.joined()
            lines.append(
                "\(descriptor.fileDescriptor) \(descriptor.openFlags) "
                    + "\(descriptor.offset) \(descriptor.device) "
                    + "\(descriptor.inode) \(descriptor.mode) \(encodedPath)"
            )
        }
        let supportedStatusMask = O_ACCMODE | O_NONBLOCK | O_ASYNC
        for handle in pipeHandles.sorted(by: {
            $0.fileDescriptor < $1.fileDescriptor
        }) {
            let accessMode = handle.statusFlags & O_ACCMODE
            guard handle.fileDescriptor >= 0,
                  seenDescriptors.insert(handle.fileDescriptor).inserted,
                  handle.descriptorFlags == 0
                    || handle.descriptorFlags == FD_CLOEXEC,
                  accessMode == O_RDONLY || accessMode == O_WRONLY,
                  handle.statusFlags & ~supportedStatusMask == 0 else {
                throw ContinuumError.integrityFailure(
                    "The durable pipe-descriptor plan is invalid."
                )
            }
            let prefix = socketHandles.isEmpty && kqueues.isEmpty
                ? "PIPE" : "RESOURCE 1"
            lines.append(
                "\(prefix) \(handle.fileDescriptor) \(handle.descriptorFlags) "
                    + "\(handle.statusFlags)"
            )
        }
        for handle in socketHandles.sorted(by: {
            $0.fileDescriptor < $1.fileDescriptor
        }) {
            let accessMode = handle.statusFlags & O_ACCMODE
            guard handle.fileDescriptor >= 0,
                  seenDescriptors.insert(handle.fileDescriptor).inserted,
                  handle.descriptorFlags == 0
                    || handle.descriptorFlags == FD_CLOEXEC,
                  accessMode == O_RDWR,
                  handle.statusFlags & ~supportedStatusMask == 0 else {
                throw ContinuumError.integrityFailure(
                    "The durable socket-descriptor plan is invalid."
                )
            }
            lines.append(
                "RESOURCE 2 \(handle.fileDescriptor) "
                    + "\(handle.descriptorFlags) \(handle.statusFlags)"
            )
        }
        for queue in kqueues.sorted(by: {
            $0.handle.fileDescriptor < $1.handle.fileDescriptor
        }) {
            let handle = queue.handle
            guard handle.fileDescriptor >= 0,
                  seenDescriptors.insert(handle.fileDescriptor).inserted,
                  handle.descriptorFlags
                    & ~(FD_CLOEXEC | FD_CLOFORK) == 0,
                  handle.statusFlags == O_RDWR,
                  queue.resource.state & ~0x0002 == 0x0010 else {
                throw ContinuumError.integrityFailure(
                    "The durable kqueue-descriptor plan is invalid."
                )
            }
            lines.append(
                "RESOURCE 3 \(handle.fileDescriptor) "
                    + "\(handle.descriptorFlags) \(handle.statusFlags) "
                    + "16 "
                    + "\(queue.resource.registrations.count)"
            )
        }
        for queue in kqueues.sorted(by: {
            $0.handle.fileDescriptor < $1.handle.fileDescriptor
        }) {
            for registration in queue.resource.registrations {
                lines.append(
                    "KREG \(queue.handle.fileDescriptor) \(registration.ident) "
                        + "\(registration.filter) \(registration.flags) "
                        + "\(registration.fflags) \(registration.data) "
                        + "\(registration.udata) \(registration.qos) "
                        + "\(registration.savedData) "
                        + "\(registration.savedFflags) \(registration.status)"
                )
            }
        }
        guard let plan = (lines.joined(separator: "\n") + "\n")
                .data(using: .utf8),
              plan.count <= 1_024 * 1_024 else {
            throw ContinuumError.integrityFailure(
                "The durable writable-descriptor plan exceeds one megabyte."
            )
        }
        return plan
    }

    private static func bootstrapResourceHandles(
        in image: DurableCheckpointImage,
        processIdentifier: Int32
    ) -> BootstrapResourceHandles {
        guard let graph = image.descriptorGraph else {
            return BootstrapResourceHandles(
                pipes: [], sockets: [], kqueues: []
            )
        }
        let pipeIDs = Set(graph.pipes.map(\.id))
        let socketIDs = Set(graph.sockets.map(\.id))
        let owned = graph.handles.filter {
            $0.processIdentifier == processIdentifier
        }
        return BootstrapResourceHandles(
            pipes: owned.filter { pipeIDs.contains($0.resourceID) },
            sockets: owned.filter { socketIDs.contains($0.resourceID) },
            kqueues: graph.kqueues.compactMap { queue in
                guard queue.processIdentifier == processIdentifier,
                      let handle = owned.first(where: {
                        $0.resourceID == queue.id
                      }) else { return nil }
                return BootstrapKqueue(resource: queue, handle: handle)
            }
        )
    }

    private static func writeBootstrapDescriptorPlan(
        _ plan: Data,
        to descriptor: Int32
    ) throws {
        guard ftruncate(descriptor, 0) == 0 else {
            throw ContinuumError.restoreUnavailable(
                "Continuum could not initialize its private descriptor plan."
            )
        }
        var offset = 0
        while offset < plan.count {
            let written = plan.withUnsafeBytes { bytes in
                pwrite(
                    descriptor,
                    bytes.baseAddress?.advanced(by: offset),
                    plan.count - offset,
                    off_t(offset)
                )
            }
            guard written > 0 else {
                throw ContinuumError.restoreUnavailable(
                    "Continuum could not write its private descriptor plan."
                )
            }
            offset += written
        }
        guard fsync(descriptor) == 0 else {
            throw ContinuumError.restoreUnavailable(
                "Continuum could not secure its private descriptor plan."
            )
        }
    }

    private func threadStateData(
        _ reference: DurableChunkReference,
        fallbackName: String,
        snapshotID: SnapshotID,
        repository: any SnapshotRepository
    ) async throws -> Data {
        guard reference.logicalBytes > 0,
              reference.logicalBytes <= 4_096 else {
            throw ContinuumError.integrityFailure(
                "The durable thread image exceeds Continuum's four-kilobyte state limit."
            )
        }
        let logicalName = reference.artifactName ?? fallbackName
        let artifact = try await repository.artifact(
            for: snapshotID,
            logicalName: logicalName
        )
        guard artifact.kind == .threadState,
              UInt64(artifact.data.count) == reference.logicalBytes,
              Self.sha256(artifact.data) == reference.hash else {
            throw ContinuumError.integrityFailure(
                "Thread state \(logicalName) does not match its manifest."
            )
        }
        return artifact.data
    }

    private static func readFileTransactionJournal(
        rootURL: URL
    ) throws -> ColdFileTransactionJournal {
        let journalURL = rootURL.appendingPathComponent(
            "ColdFileTransaction.json",
            isDirectory: false
        )
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            return try decoder.decode(
                ColdFileTransactionJournal.self,
                from: Data(contentsOf: journalURL)
            )
        } catch {
            throw ContinuumError.integrityFailure(
                "A durable cold-file transaction journal could not be decoded."
            )
        }
    }

    private static func updateFileTransactionState(
        _ rollback: PreparedFileRollback,
        state: String
    ) throws {
        try updateFileTransactionState(
            rootURL: rollback.rootURL,
            state: state
        )
    }

    private static func updateFileTransactionState(
        rootURL: URL,
        state: String
    ) throws {
        guard state == "prepared"
                || state == "committed"
                || state == "restoringCommitted" else {
            throw ContinuumError.integrityFailure(
                "Continuum refused an invalid cold-file transaction state."
            )
        }
        let journal = try readFileTransactionJournal(rootURL: rootURL)
        let updated = ColdFileTransactionJournal(
            formatVersion: journal.formatVersion,
            transactionID: journal.transactionID,
            safetySnapshotID: journal.safetySnapshotID,
            replacementProcessIdentifier: journal.replacementProcessIdentifier,
            state: state,
            createdAt: journal.createdAt,
            entries: journal.entries
        )
        try writeFileTransactionJournal(updated, rootURL: rootURL)
    }

    private static func ensureNoExternalWriters(
        _ files: [LocalFileReplacement],
        allowedProcessIdentifier: Int32
    ) throws {
        try ensureNoExternalWriters(
            paths: files.map(\.originalPath),
            allowedProcessIdentifier: allowedProcessIdentifier
        )
    }

    private static func ensureNoExternalWriters(
        paths: [String],
        allowedProcessIdentifier: Int32
    ) throws {
        for path in paths {
            var conflictingProcessIdentifier: Int32 = 0
            let status = path.withCString {
                continuum_find_writable_vnode_conflict(
                    $0,
                    allowedProcessIdentifier,
                    &conflictingProcessIdentifier
                )
            }
            switch status {
            case CONTINUUM_STATUS_OK:
                continue
            case CONTINUUM_STATUS_FILE_WRITER_CONFLICT:
                throw ContinuumError.restoreUnavailable(
                    "Process \(conflictingProcessIdentifier) is writing \(path). Continuum will not start a file transaction while another writer owns the vnode."
                )
            case CONTINUUM_STATUS_ACCESS_DENIED:
                throw ContinuumError.restoreUnavailable(
                    "Continuum could not prove exclusive write ownership for \(path)."
                )
            default:
                let description = String(cString: continuum_status_string(status))
                throw ContinuumError.restoreUnavailable(
                    "Continuum could not validate file writers for \(path): \(description)."
                )
            }
        }
    }

    private static func fileIdentity(
        atPath path: String
    ) throws -> (UInt64, UInt64) {
        var info = stat()
        guard path.withCString({ lstat($0, &info) }) == 0,
              (info.st_mode & S_IFMT) == S_IFREG else {
            throw ContinuumError.integrityFailure(
                "A cold-file transaction target is missing or no longer regular."
            )
        }
        return (UInt64(info.st_dev), UInt64(info.st_ino))
    }

    private static func sha256File(atPath path: String) throws -> String {
        let descriptor = path.withCString {
            Darwin.open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw ContinuumError.integrityFailure(
                "A cold-file transaction target could not be opened for validation."
            )
        }
        defer { Darwin.close(descriptor) }
        var hasher = SHA256()
        var buffer = [UInt8](repeating: 0, count: 1024 * 1024)
        while true {
            let count = buffer.withUnsafeMutableBytes {
                Darwin.read(descriptor, $0.baseAddress, $0.count)
            }
            if count == 0 { break }
            guard count > 0 else {
                if errno == EINTR { continue }
                throw ContinuumError.integrityFailure(
                    "A cold-file transaction target changed during validation."
                )
            }
            hasher.update(data: Data(buffer[0..<count]))
        }
        return hasher.finalize().map {
            String(format: "%02x", $0)
        }.joined()
    }

    private static func writeFileTransactionJournal(
        _ journal: ColdFileTransactionJournal,
        rootURL: URL
    ) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(journal)
        let journalURL = rootURL.appendingPathComponent(
            "ColdFileTransaction.json",
            isDirectory: false
        )
        try data.write(to: journalURL, options: .atomic)
        let descriptor = rootURL.path.withCString {
            Darwin.open($0, O_RDONLY | O_CLOEXEC)
        }
        guard descriptor >= 0 else {
            throw ContinuumError.integrityFailure(
                "Continuum wrote the cold-file journal but could not open its transaction directory for synchronization."
            )
        }
        defer { Darwin.close(descriptor) }
        guard fsync(descriptor) == 0 else {
            throw ContinuumError.integrityFailure(
                "Continuum could not durably synchronize the cold-file transaction journal."
            )
        }
    }

    private static func defaultFileSafetyRootURL() -> URL {
        let applicationSupport = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first ?? FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support")
        return applicationSupport
            .appendingPathComponent("Continuum", isDirectory: true)
            .appendingPathComponent(
                "ColdFileTransactions",
                isDirectory: true
            )
    }

    private static func legacyMemoryArtifactName(
        processIdentifier: Int32,
        address: UInt64,
        offset: UInt64
    ) -> String {
        String(
            format: "memory/%d/%016llx/%016llx.bin",
            processIdentifier,
            address,
            offset
        )
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func hexDigest(_ digest: continuum_sha256_digest) -> String {
        var copy = digest
        return withUnsafeBytes(of: &copy) { bytes in
            bytes.map { String(format: "%02x", $0) }.joined()
        }
    }

    private static func killAndReap(
        _ processIdentifier: Int32
    ) -> continuum_status {
        guard processIdentifier > 0 else {
            return CONTINUUM_STATUS_INVALID_ARGUMENT
        }
        return continuum_terminate_direct_child(processIdentifier, 2_000)
    }

    private static func withCStringArray<Result>(
        _ strings: [String],
        _ body: (UnsafePointer<UnsafePointer<CChar>?>?) throws -> Result
    ) rethrows -> Result {
        let allocated: [UnsafeMutablePointer<CChar>?] = strings.map { value in
            value.withCString { strdup($0) }
        }
        defer { allocated.forEach { free($0) } }
        var pointers: [UnsafePointer<CChar>?] = allocated.map { pointer in
            pointer.map { UnsafePointer<CChar>($0) }
        }
        pointers.append(nil)
        return try pointers.withUnsafeBufferPointer { buffer in
            try body(buffer.baseAddress)
        }
    }
}
