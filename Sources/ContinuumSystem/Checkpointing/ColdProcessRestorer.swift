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

public struct ColdProcessCommit: Hashable, Sendable {
    public let processIdentifier: Int32
    public let safetyTransactionRootURL: URL?
    public let retainedFileCount: Int
    public let retainedFileBytes: UInt64
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
    private var preparedReplacements: [UUID: PreparedReplacement] = [:]

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
    }

    deinit {
        for replacement in preparedReplacements.values {
            _ = Self.killAndReap(replacement.processIdentifier)
            continuum_remote_session_destroy(replacement.session)
            try? Self.rollbackFiles(replacement.fileRollback)
        }
    }

    public func prepareRootProcess(
        from snapshotID: SnapshotID,
        repository: any SnapshotRepository
    ) async throws -> ColdProcessPreparation {
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
        if process.threads.contains(where: {
            $0.isUserspaceSafepoint == true
        }) {
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
        let descriptor: Int32
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
        defer { Darwin.close(descriptor) }

        // File state is intentionally outside the cold-rewind boundary.
        // Recreating captured writable descriptors would couple a process
        // restore to stale vnode identities and can mutate current files.
        let rootDescriptors: [DurableWritableFileDescriptor] = []
        let descriptorPlan = try Self.bootstrapDescriptorPlan(
            rootDescriptors
        )
        try Self.writeBootstrapDescriptorPlan(
            descriptorPlan,
            to: descriptor
        )

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

        var replacementProcessIdentifier: Int32 = 0
        let spawnStatus = Self.withCStringArray(launch.arguments) { arguments in
            Self.withCStringArray(environment) { environmentEntries in
                launch.executablePath.withCString { executable in
                    launch.workingDirectory.withCString { directory in
                        if usesDeterministicAddressSpace {
                            continuum_spawn_process_suspended_with_inherited_descriptor(
                                executable,
                                arguments,
                                environmentEntries,
                                directory,
                                descriptor,
                                &replacementProcessIdentifier
                            )
                        } else {
                            continuum_spawn_process_suspended_with_inherited_descriptor_system_aslr(
                                executable,
                                arguments,
                                environmentEntries,
                                directory,
                                descriptor,
                                &replacementProcessIdentifier
                            )
                        }
                    }
                }
            }
        }
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
        try requireRuntimeOK(
            continuum_advance_process_to_entry_stop(
                replacementProcessIdentifier,
                5_000
            ),
            operation: "reach Continuum's executable-entry restore boundary"
        )
        var bootstrapIdentity = try Self.bootstrapIdentity(
            from: descriptor,
            expectedProcessIdentifier: replacementProcessIdentifier,
            localIdentity: localBootstrapIdentity,
            expectedRestoredDescriptorCount: rootDescriptors.count
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
            reconstructedFileDescriptorCount: rootDescriptors.count,
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
        for region in appStateRegions {
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
                operation: "validate the replacement app-state mapping"
            )
            guard matches != 0 else {
                throw ContinuumError.restoreUnavailable(
                    "The relaunched app did not recreate its tagged state mapping at the captured address."
                )
            }
        }
        for region in appStateRegions.sorted(by: { $0.address < $1.address }) {
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
        guard image.formatVersion == DurableCheckpointImage.currentFormatVersion else {
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

    private static func bootstrapDescriptorPlan(
        _ descriptors: [DurableWritableFileDescriptor]
    ) throws -> Data {
        guard descriptors.count <= 1_024 else {
            throw ContinuumError.restoreUnavailable(
                "The root process owns too many writable descriptors for cold reconstruction."
            )
        }
        var seenDescriptors: Set<Int32> = []
        var lines = ["CONTINUUM_FD_PLAN_V1 \(descriptors.count)"]
        lines.reserveCapacity(descriptors.count + 1)
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
        guard let plan = (lines.joined(separator: "\n") + "\n")
                .data(using: .utf8),
              plan.count <= 1_024 * 1_024 else {
            throw ContinuumError.integrityFailure(
                "The durable writable-descriptor plan exceeds one megabyte."
            )
        }
        return plan
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
