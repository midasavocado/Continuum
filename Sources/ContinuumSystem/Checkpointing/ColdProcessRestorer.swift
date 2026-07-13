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

/// Rebuilds a durable process image into a disposable child that remains
/// stopped before main. A certified single-thread image also receives its saved
/// ARM64 general and vector register state. Validated regular writable files
/// are reconnected before memory reconstruction. Other resources and execution
/// resume intentionally remain later phases.
public actor ColdProcessRestorer {
    private struct PreparedReplacement: @unchecked Sendable {
        let processIdentifier: Int32
        let session: OpaquePointer
        let fileRollback: PreparedFileRollback?
    }

    private struct PreparedFileRollback: Sendable {
        let store: APFSLocalFileCheckpointStore
        let snapshotID: UUID
        let rootURL: URL
        let replacedFileCount: Int
        let replacedBytes: UInt64
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
            continuum_remote_session_destroy(replacement.session)
            _ = Self.killAndReap(replacement.processIdentifier)
            try? Self.rollbackFiles(replacement.fileRollback)
        }
    }

    public func prepareRootProcess(
        from snapshotID: SnapshotID,
        repository: any SnapshotRepository
    ) async throws -> ColdProcessPreparation {
        if preparedReplacements.isEmpty {
            _ = try recoverInterruptedFileTransactions()
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
        guard launch.addressSpacePolicy == .continuumDeterministic else {
            throw ContinuumError.restoreUnavailable(
                "This app was not launched with Continuum's deterministic address policy."
            )
        }
        guard launch.environment.contains("MallocLargeCache=0") else {
            throw ContinuumError.restoreUnavailable(
                "This checkpoint predates Continuum's deterministic allocator policy."
            )
        }
        try validateExecutable(process: process, launch: launch)
        guard image.members.allSatisfy({
            Self.processIsAbsent($0.processIdentifier)
        }) else {
            throw ContinuumError.restoreUnavailable(
                "Cold restoration requires the captured process tree to be fully exited."
            )
        }
        guard let bootstrapLibraryPath,
              FileManager.default.fileExists(atPath: bootstrapLibraryPath) else {
            throw ContinuumError.restoreUnavailable(
                "Continuum's pre-main restore bootstrap is missing."
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

        let rootDescriptors = image.writableFileDescriptors
            .filter { $0.processIdentifier == process.processIdentifier }
            .sorted { $0.fileDescriptor < $1.fileDescriptor }
        let descriptorPlan = try Self.bootstrapDescriptorPlan(
            rootDescriptors,
            files: image.writableFiles
        )
        let fileReplacements = try await Self.fileReplacements(
            descriptors: rootDescriptors,
            files: image.writableFiles,
            snapshotID: snapshotID,
            repository: repository
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
            !$0.hasPrefix("DYLD_SHARED_REGION=")
                && !$0.hasPrefix("CONTINUUM_DETERMINISTIC_ADDRESS_SPACE=")
                && !$0.hasPrefix("CONTINUUM_BOOTSTRAP_STOP=")
                && !$0.hasPrefix("CONTINUUM_BOOTSTRAP_DESCRIPTOR_PATH=")
                && !$0.hasPrefix("CONTINUUM_BOOTSTRAP_DESCRIPTOR_FD=")
                && !$0.hasPrefix("DYLD_INSERT_LIBRARIES=")
                && !$0.hasPrefix("MallocLargeCache=")
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
        environment.append("DYLD_SHARED_REGION=private")
        environment.append("CONTINUUM_DETERMINISTIC_ADDRESS_SPACE=1")
        environment.append("CONTINUUM_BOOTSTRAP_STOP=1")
        environment.append("MallocLargeCache=0")
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
                        continuum_spawn_process_suspended_with_inherited_descriptor(
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
        try requireRuntimeOK(spawnStatus, operation: "launch a cold replacement")

        var session: OpaquePointer?
        var retained = false
        defer {
            if !retained {
                if let session {
                    continuum_remote_session_destroy(session)
                }
                _ = Self.killAndReap(replacementProcessIdentifier)
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

        var reconstructedRegionCount = 0
        var reconstructedChunkCount = 0
        var reconstructedBytes: UInt64 = 0
        var deferredMaximumProtectionRegionCount = 0

        for region in process.regions.sorted(by: { $0.address < $1.address }) {
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

        guard process.threads.count == 1, let thread = process.threads.first else {
            throw ContinuumError.restoreUnavailable(
                "Cold thread reconstruction currently requires exactly one captured thread."
            )
        }
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
        var threadReport = continuum_remote_thread_reconstruction_report()
        let threadStatus = generalState.withUnsafeBytes { generalBytes in
            vectorState.withUnsafeBytes { vectorBytes in
                continuum_remote_session_reconstruct_single_thread(
                    session,
                    thread.generalStateFlavor,
                    generalBytes.baseAddress,
                    generalBytes.count,
                    thread.vectorStateFlavor,
                    vectorBytes.baseAddress,
                    vectorBytes.count,
                    &threadReport
                )
            }
        }
        try requireRuntimeOK(
            threadStatus,
            operation: "reconstruct the captured ARM64 thread state"
        )
        guard threadReport.general_state_verified != 0,
              threadReport.vector_state_verified != 0,
              threadReport.general_state_bytes == UInt64(generalState.count),
              threadReport.vector_state_bytes == UInt64(vectorState.count),
              threadReport.replacement_thread_identifier != 0 else {
            throw ContinuumError.integrityFailure(
                "The replacement thread did not match the captured register image."
            )
        }
        let (threadStateBytes, threadByteOverflow) = UInt64(generalState.count)
            .addingReportingOverflow(UInt64(vectorState.count))
        guard !threadByteOverflow else {
            throw ContinuumError.integrityFailure(
                "The durable thread image exceeds Continuum's numeric limits."
            )
        }

        let fileRollback = try await Self.beginFileReplacement(
            fileReplacements,
            replacementProcessIdentifier: replacementProcessIdentifier,
            safetyRootURL: fileSafetyRootURL
        )
        let preparationID = UUID()
        preparedReplacements[preparationID] = PreparedReplacement(
            processIdentifier: replacementProcessIdentifier,
            session: session,
            fileRollback: fileRollback
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
            reconstructedThreadCount: 1,
            reconstructedThreadStateBytes: threadStateBytes,
            replacementThreadIdentifier: threadReport.replacement_thread_identifier,
            reconstructedFileDescriptorCount: rootDescriptors.count,
            reconstructedFileCount: fileRollback?.replacedFileCount ?? 0,
            reconstructedFileBytes: fileRollback?.replacedBytes ?? 0
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
            guard Self.processIsAbsent(
                journal.replacementProcessIdentifier
            ) else {
                throw ContinuumError.restoreUnavailable(
                    "An interrupted cold replacement is still running; Continuum will not touch its files."
                )
            }
            for entry in journal.entries {
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
        guard image.operatingSystemBuild
                == ProcessInfo.processInfo.operatingSystemVersionString else {
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
        guard fields.count == 5,
              fields[0] == "CONTINUUM_BOOTSTRAP_V3",
              Int(fields[4]) == expectedRestoredDescriptorCount,
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
        guard let imageBase = UInt64(imageBaseText, radix: 16), imageBase != 0,
              let address = UInt64(addressText, radix: 16), address != 0 else {
            throw ContinuumError.restoreUnavailable(
                "Continuum's pre-main bootstrap address is invalid."
            )
        }
        let (expectedAddress, overflow) = imageBase.addingReportingOverflow(
            localIdentity.copy_offset
        )
        guard !overflow, expectedAddress == address else {
            throw ContinuumError.restoreUnavailable(
                "Continuum's pre-main bootstrap symbol does not match its signed library."
            )
        }
        var identity = localIdentity
        identity.image_base = imageBase
        identity.copy_address = address
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
                replacedBytes: byteCount
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
        _ = try rollback.store.restoreCoherently(
            snapshotID: rollback.snapshotID
        )
        try FileManager.default.removeItem(at: rollback.rootURL)
    }

    private static func bootstrapDescriptorPlan(
        _ descriptors: [DurableWritableFileDescriptor],
        files: [DurableFileImage]
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
                  !pathBytes.contains(0),
                  files.contains(where: { file in
                      file.originalPath == descriptor.originalPath
                          && file.device == descriptor.device
                          && file.inode == descriptor.inode
                          && file.mode == descriptor.mode
                  }) else {
                throw ContinuumError.integrityFailure(
                    "The durable writable-descriptor plan does not match its file root."
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
