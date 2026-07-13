import ContinuumCore
import ContinuumRuntime
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
}

/// Rebuilds a durable process image into a disposable child that remains
/// stopped before main. A certified single-thread image also receives its saved
/// ARM64 general and vector register state. Resource restoration and execution
/// resume intentionally remain later phases.
public actor ColdProcessRestorer {
    private struct PreparedReplacement: @unchecked Sendable {
        let processIdentifier: Int32
        let session: OpaquePointer
    }

    private let bootstrapLibraryPath: String?
    private var preparedReplacements: [UUID: PreparedReplacement] = [:]

    public init(bootstrapLibraryURL: URL? = nil) {
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
            Self.killAndReap(replacement.processIdentifier)
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
                Self.killAndReap(replacementProcessIdentifier)
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
            localIdentity: localBootstrapIdentity
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

        let preparationID = UUID()
        preparedReplacements[preparationID] = PreparedReplacement(
            processIdentifier: replacementProcessIdentifier,
            session: session
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
            replacementThreadIdentifier: threadReport.replacement_thread_identifier
        )
    }

    public func discard(_ preparationID: UUID) {
        guard let replacement = preparedReplacements.removeValue(
            forKey: preparationID
        ) else {
            return
        }
        continuum_remote_session_destroy(replacement.session)
        Self.killAndReap(replacement.processIdentifier)
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
        localIdentity: continuum_bootstrap_identity
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
        guard fields.count == 4,
              fields[0] == "CONTINUUM_BOOTSTRAP_V2",
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

    private static func killAndReap(_ processIdentifier: Int32) {
        guard processIdentifier > 0 else { return }
        _ = continuum_terminate_direct_child(processIdentifier, 2_000)
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
