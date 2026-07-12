import ContinuumCore
import ContinuumRuntime
import ContinuumStore
import CryptoKit
import Darwin
import Foundation

/// Connects the process-group Mach proof to the shipping app as an explicitly
/// experimental, hot-only backend. The C snapshot owns live task ports and is
/// therefore valid only while this service and the exact original processes
/// remain alive.
public actor HotProcessCheckpointService: CheckpointCapturing {
    public nonisolated var supportsFunctionalRestore: Bool { true }

    private let maximumCapturedBytes: UInt64
    private let maximumRetainedSnapshots: Int
    private let fileCheckpointStore: APFSLocalFileCheckpointStore?
    private var handles: [SnapshotID: HotProcessSnapshotHandle] = [:]
    private var retentionOrder: [SnapshotID] = []

    public init(
        maximumCapturedBytes: UInt64 = UInt64(ContinuumConstants.defaultHotMemoryBudgetBytes),
        maximumRetainedSnapshots: Int = 8,
        fileCheckpointRootURL: URL? = nil
    ) {
        self.maximumCapturedBytes = maximumCapturedBytes
        self.maximumRetainedSnapshots = max(maximumRetainedSnapshots, 2)
        if let fileCheckpointRootURL {
            // Hot file roots cannot outlive their in-memory task snapshots.
            // Clear leftovers from a prior Continuum process before arming.
            try? FileManager.default.removeItem(at: fileCheckpointRootURL)
            self.fileCheckpointStore = try? APFSLocalFileCheckpointStore(
                rootURL: fileCheckpointRootURL
            )
        } else {
            self.fileCheckpointStore = nil
        }
    }

    public func capture(
        app: AppIdentity,
        processIdentifiers: [Int32],
        kind: SnapshotKind,
        branchID: BranchID
    ) async throws -> SnapshotCapture {
        guard let rootProcessIdentifier = processIdentifiers.first,
              rootProcessIdentifier > 0 else {
            throw ContinuumError.runtimeUnsupported(
                "Continuum could not identify the root process for this app."
            )
        }

        let snapshotID = UUID()
        var rawSnapshot: OpaquePointer?
        var info = continuum_remote_process_group_snapshot_info()
        let resourceBox = HotResourceInventoryCallbackBox(
            fileCheckpointStore: fileCheckpointStore,
            captureSnapshotID: snapshotID
        )
        let resourceContext = Unmanaged.passUnretained(resourceBox).toOpaque()
        let status = continuum_remote_process_group_capture_with_resources(
            rootProcessIdentifier,
            maximumCapturedBytes,
            continuumCaptureHotResourceInventory,
            resourceContext,
            &rawSnapshot,
            &info
        )
        guard status == CONTINUUM_STATUS_OK, let rawSnapshot else {
            if let failureDescription = resourceBox.failureDescription {
                throw ContinuumError.runtimeUnsupported(failureDescription)
            }
            throw captureError(status: status, appName: app.displayName)
        }

        guard let writableVnodes = resourceBox.inventory else {
            continuum_remote_process_group_snapshot_destroy(rawSnapshot)
            throw ContinuumError.runtimeUnsupported(
                "The coherent resource callback returned without a writable-file inventory."
            )
        }
        let handle = HotProcessSnapshotHandle(
            pointer: rawSnapshot,
            writableVnodes: writableVnodes,
            snapshotID: snapshotID,
            appID: app.id,
            kind: kind,
            fileCheckpointStore: fileCheckpointStore
        )
        do {
            let members = try groupMembers(in: rawSnapshot)
            guard !members.isEmpty,
                  members.contains(where: { $0.processIdentifier == rootProcessIdentifier }) else {
                throw ContinuumError.runtimeUnsupported(
                    "The runtime did not capture the selected app's root process."
                )
            }

            let capturedAt = Date.now
            let checkpoint = CheckpointRecord(
                capturedAt: capturedAt,
                monotonicNanoseconds: clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW),
                processIdentifiers: members.map(\.processIdentifier).sorted(),
                memoryRegionCount: Int(info.captured_region_count),
                threadCount: Int(info.thread_count),
                validation: .valid
            )
            let snapshot = SnapshotRecord(
                id: snapshotID,
                name: SnapshotNaming.automaticName(
                    appName: app.displayName,
                    date: capturedAt,
                    kind: kind
                ),
                kind: kind,
                app: app,
                checkpoint: checkpoint,
                branchID: branchID,
                createdAt: capturedAt,
                availability: .experimentalHot,
                logicalBytes: clampedInt64(info.captured_bytes),
                uniqueBytes: clampedInt64(info.captured_bytes),
                hotMemoryBytes: clampedInt64(info.captured_bytes),
                isPinned: kind != .automatic,
                localFileCoverage: fileCheckpointStore == nil ? .unavailable : .openFiles,
                allowsKeepingCurrentFiles: false,
                resourceCoverage: Self.experimentalResourceCoverage(
                    writableVnodeCount: writableVnodes.count
                )
            )

            let manifest = HotProcessManifest(
                formatVersion: 1,
                rootProcessIdentifier: rootProcessIdentifier,
                processIdentifiers: members.map(\.processIdentifier).sorted(),
                capturedBytes: info.captured_bytes,
                capturedRegionCount: info.captured_region_count,
                excludedRegionCount: info.excluded_region_count,
                threadCount: info.thread_count,
                writableVnodes: writableVnodes,
                resourceCoverage: Self.experimentalResourceCoverage(
                    writableVnodeCount: writableVnodes.count
                )
            )
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let manifestData = try encoder.encode(manifest)

            retain(handle, for: snapshotID)
            var artifacts = try durableArtifacts(
                snapshot: rawSnapshot,
                checkpoint: checkpoint,
                app: app,
                writableVnodes: writableVnodes
            )
            artifacts.append(
                CapturedArtifact(
                    kind: .metadata,
                    logicalName: "live-checkpoint-manifest.json",
                    data: manifestData
                )
            )
            return SnapshotCapture(
                snapshot: snapshot,
                artifacts: artifacts
            )
        } catch {
            // `handle` owns and destroys the C snapshot when this scope exits.
            throw error
        }
    }

    public func restore(
        snapshot: SnapshotRecord,
        artifacts: [CapturedArtifact]
    ) async -> RestoreResult {
        guard snapshot.availability == .experimentalHot else {
            return .failed("This snapshot is not available to the live restore engine.")
        }
        guard let handle = handles[snapshot.id] else {
            return .failed(
                "The hot process state expired because Continuum or the captured app was relaunched."
            )
        }

        let rollbackSnapshotID = UUID()
        if let fileCheckpointStore = handle.fileCheckpointStore {
            let safetyBox = HotResourceInventoryCallbackBox(
                fileCheckpointStore: fileCheckpointStore,
                captureSnapshotID: rollbackSnapshotID
            )
            let safetyContext = Unmanaged.passUnretained(safetyBox).toOpaque()
            let safetyStatus = continuum_remote_process_group_with_suspended_resources(
                handle.pointer,
                continuumCaptureHotResourceInventory,
                safetyContext
            )
            guard safetyStatus == CONTINUUM_STATUS_OK else {
                if safetyStatus == CONTINUUM_STATUS_TARGET_EXITED
                    || safetyStatus == CONTINUUM_STATUS_PROCESS_IDENTITY_CHANGED {
                    expire(snapshot.id)
                }
                return .failed(
                    safetyBox.failureDescription
                        ?? "Continuum could not secure the live state before restoring: \(statusDescription(safetyStatus)). No memory was changed."
                )
            }
        }
        defer {
            try? handle.fileCheckpointStore?.deleteCoherently(
                snapshotID: rollbackSnapshotID
            )
        }

        var report = continuum_remote_process_group_restore_report()
        let resourceBox = HotResourceInventoryCallbackBox(
            expectedInventory: handle.writableVnodes,
            fileCheckpointStore: handle.fileCheckpointStore,
            restoreSnapshotID: handle.snapshotID,
            rollbackSnapshotID: handle.fileCheckpointStore == nil
                ? nil
                : rollbackSnapshotID
        )
        let resourceContext = Unmanaged.passUnretained(resourceBox).toOpaque()
        let status = continuum_remote_process_group_restore_with_resources(
            handle.pointer,
            continuumValidateHotResourceInventory,
            resourceContext,
            &report
        )
        guard status == CONTINUUM_STATUS_OK else {
            if let failureDescription = resourceBox.failureDescription {
                return .failed(failureDescription)
            }
            return .failed(restoreFailureDescription(status: status, report: report))
        }
        guard report.memory_readback_verified != 0,
              report.processes_restored > 0,
              report.thread_states_restored > 0 else {
            return .failed(
                "The runtime returned without validating restored memory, processes, and thread state."
            )
        }
        return .experimentalHot
    }

    public func currentRestoreAvailability(
        for snapshot: SnapshotRecord
    ) async -> RestoreAvailability {
        guard snapshot.availability == .experimentalHot else {
            return snapshot.availability
        }
        guard let handle = handles[snapshot.id] else {
            return .unavailable
        }
        guard continuum_remote_process_group_live_status(handle.pointer)
                == CONTINUUM_STATUS_OK else {
            expire(snapshot.id)
            return .unavailable
        }
        return .experimentalHot
    }

    private func expire(_ snapshotID: SnapshotID) {
        handles.removeValue(forKey: snapshotID)
        retentionOrder.removeAll { $0 == snapshotID }
    }

    private func retain(_ handle: HotProcessSnapshotHandle, for snapshotID: SnapshotID) {
        handles[snapshotID] = handle
        retentionOrder.removeAll { $0 == snapshotID }
        retentionOrder.append(snapshotID)

        while retentionOrder.count > maximumRetainedSnapshots {
            let expiredID = retentionOrder.removeFirst()
            handles.removeValue(forKey: expiredID)
        }
    }

    private func durableArtifacts(
        snapshot: OpaquePointer,
        checkpoint: CheckpointRecord,
        app: AppIdentity,
        writableVnodes: [HotWritableVnode]
    ) throws -> [CapturedArtifact] {
        let chunkSize = 1_024 * 1_024
        var artifacts: [CapturedArtifact] = []
        var processImages: [DurableProcessImage] = []
        let memberCount = continuum_remote_process_group_member_count(snapshot)

        for memberIndex in 0..<memberCount {
            var member = continuum_remote_process_group_member_info()
            try requireRuntimeOK(
                continuum_remote_process_group_copy_member_info(
                    snapshot, memberIndex, &member
                ),
                operation: "export process metadata"
            )

            var regions: [DurableMemoryRegion] = []
            let regionCount = continuum_remote_process_group_member_region_count(
                snapshot, memberIndex
            )
            for regionIndex in 0..<regionCount {
                var region = continuum_remote_process_region_info()
                try requireRuntimeOK(
                    continuum_remote_process_group_copy_member_region_info(
                        snapshot, memberIndex, regionIndex, &region
                    ),
                    operation: "export memory-region metadata"
                )
                var references: [DurableChunkReference] = []
                var offset: UInt64 = 0
                while offset < region.length {
                    let length = Int(min(UInt64(chunkSize), region.length - offset))
                    var data = Data(count: length)
                    let status = data.withUnsafeMutableBytes { buffer in
                        continuum_remote_process_group_copy_member_region_bytes_range(
                            snapshot,
                            memberIndex,
                            regionIndex,
                            offset,
                            buffer.baseAddress,
                            buffer.count
                        )
                    }
                    try requireRuntimeOK(status, operation: "export memory bytes")
                    let hash = Self.sha256(data)
                    let logicalName = String(
                        format: "memory/%d/%016llx/%016llx.bin",
                        member.process_id,
                        region.address,
                        offset
                    )
                    artifacts.append(CapturedArtifact(
                        kind: .memoryPage,
                        logicalName: logicalName,
                        data: data
                    ))
                    references.append(DurableChunkReference(
                        hash: hash,
                        logicalBytes: UInt64(length),
                        storedBytes: 0,
                        compression: .none
                    ))
                    offset += UInt64(length)
                }
                regions.append(DurableMemoryRegion(
                    address: region.address,
                    length: region.length,
                    protection: region.protection,
                    maximumProtection: region.maximum_protection,
                    inheritance: region.inheritance,
                    shareMode: region.share_mode,
                    userTag: region.user_tag,
                    chunks: references
                ))
            }

            var threads: [DurableThreadImage] = []
            let threadCount = continuum_remote_process_group_member_thread_count(
                snapshot, memberIndex
            )
            for threadIndex in 0..<threadCount {
                var thread = continuum_remote_thread_state_info()
                try requireRuntimeOK(
                    continuum_remote_process_group_copy_member_thread_info(
                        snapshot, memberIndex, threadIndex, &thread
                    ),
                    operation: "export thread metadata"
                )
                let general = try copyThreadState(
                    snapshot: snapshot,
                    memberIndex: memberIndex,
                    threadIndex: threadIndex,
                    length: thread.general_state_length,
                    vector: false
                )
                let vector = try copyThreadState(
                    snapshot: snapshot,
                    memberIndex: memberIndex,
                    threadIndex: threadIndex,
                    length: thread.vector_state_length,
                    vector: true
                )
                let generalName = "threads/\(member.process_id)/\(thread.thread_identifier)-general.bin"
                let vectorName = "threads/\(member.process_id)/\(thread.thread_identifier)-vector.bin"
                artifacts.append(CapturedArtifact(
                    kind: .threadState,
                    logicalName: generalName,
                    data: general
                ))
                artifacts.append(CapturedArtifact(
                    kind: .threadState,
                    logicalName: vectorName,
                    data: vector
                ))
                threads.append(DurableThreadImage(
                    threadIdentifier: thread.thread_identifier,
                    generalStateFlavor: thread.general_state_flavor,
                    generalState: DurableChunkReference(
                        hash: Self.sha256(general),
                        logicalBytes: UInt64(general.count),
                        storedBytes: 0,
                        compression: .none
                    ),
                    vectorStateFlavor: thread.vector_state_flavor,
                    vectorState: DurableChunkReference(
                        hash: Self.sha256(vector),
                        logicalBytes: UInt64(vector.count),
                        storedBytes: 0,
                        compression: .none
                    )
                ))
            }

            processImages.append(DurableProcessImage(
                processIdentifier: member.process_id,
                parentProcessIdentifier: member.parent_process_id,
                executableDevice: member.executable_device,
                executableInode: member.executable_inode,
                vmLayoutHash: member.vm_layout_hash,
                regions: regions,
                threads: threads
            ))
        }

        let image = DurableCheckpointImage(
            checkpointID: checkpoint.id,
            createdAt: checkpoint.capturedAt,
            architecture: "arm64",
            operatingSystemBuild: ProcessInfo.processInfo.operatingSystemVersionString,
            pageSize: UInt64(getpagesize()),
            rootProcessIdentifier: checkpoint.processIdentifiers.first ?? 0,
            app: app,
            members: processImages,
            writableFiles: []
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        artifacts.append(CapturedArtifact(
            kind: .metadata,
            logicalName: "durable-checkpoint-v1.json",
            data: try encoder.encode(image)
        ))
        return artifacts
    }

    private func copyThreadState(
        snapshot: OpaquePointer,
        memberIndex: Int,
        threadIndex: Int,
        length: Int,
        vector: Bool
    ) throws -> Data {
        var data = Data(count: length)
        var requiredLength = 0
        let status = data.withUnsafeMutableBytes { buffer in
            if vector {
                continuum_remote_process_group_copy_member_thread_vector_state(
                    snapshot, memberIndex, threadIndex,
                    buffer.baseAddress, buffer.count, &requiredLength
                )
            } else {
                continuum_remote_process_group_copy_member_thread_general_state(
                    snapshot, memberIndex, threadIndex,
                    buffer.baseAddress, buffer.count, &requiredLength
                )
            }
        }
        try requireRuntimeOK(status, operation: "export thread registers")
        guard requiredLength == length else {
            throw ContinuumError.runtimeUnsupported(
                "The runtime exported an incomplete thread register bank."
            )
        }
        return data
    }

    private func requireRuntimeOK(
        _ status: continuum_status,
        operation: String
    ) throws {
        guard status == CONTINUUM_STATUS_OK else {
            throw ContinuumError.runtimeUnsupported(
                "Could not \(operation): \(statusDescription(status))."
            )
        }
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func groupMembers(
        in snapshot: OpaquePointer
    ) throws -> [HotProcessMember] {
        let count = continuum_remote_process_group_member_count(snapshot)
        var members: [HotProcessMember] = []
        members.reserveCapacity(count)

        for index in 0..<count {
            var info = continuum_remote_process_group_member_info()
            let status = continuum_remote_process_group_copy_member_info(
                snapshot,
                index,
                &info
            )
            guard status == CONTINUUM_STATUS_OK else {
                throw ContinuumError.runtimeUnsupported(
                    "The runtime could not inspect captured process \(index): \(statusDescription(status))."
                )
            }
            members.append(HotProcessMember(
                processIdentifier: info.process_id,
                parentProcessIdentifier: info.parent_process_id
            ))
        }
        return members
    }

    private func captureError(
        status: continuum_status,
        appName: String
    ) -> ContinuumError {
        let detail: String
        switch status {
        case CONTINUUM_STATUS_ACCESS_DENIED:
            detail = "macOS denied task access to \(appName). Its signing or protection policy blocks the current research runtime."
        case CONTINUUM_STATUS_SNAPSHOT_BUDGET_EXCEEDED:
            detail = "\(appName)'s writable memory exceeds the \(ByteCountFormatter.string(fromByteCount: Int64(maximumCapturedBytes), countStyle: .memory)) hot-snapshot limit."
        case CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR:
            detail = "\(appName) owns a descriptor type the resource guard cannot safely preserve yet."
        default:
            detail = "Hot process capture failed: \(statusDescription(status))."
        }
        return .runtimeUnsupported(detail)
    }

    private func restoreFailureDescription(
        status: continuum_status,
        report: continuum_remote_process_group_restore_report
    ) -> String {
        let guardMessage: String
        switch status {
        case CONTINUUM_STATUS_DESCRIPTOR_TABLE_CHANGED:
            guardMessage = "The app's file descriptors or sockets changed."
        case CONTINUUM_STATUS_MACH_NAMESPACE_CHANGED:
            guardMessage = "The app's Mach/XPC namespace changed."
        case CONTINUUM_STATUS_THREAD_SET_CHANGED:
            guardMessage = "The app created or removed threads."
        case CONTINUUM_STATUS_PROCESS_TREE_CHANGED:
            guardMessage = "The app's helper-process tree changed."
        case CONTINUUM_STATUS_REGION_MAPPING_CHANGED:
            guardMessage = "The app's memory layout changed."
        case CONTINUUM_STATUS_TARGET_EXITED:
            guardMessage = "The captured app exited."
        default:
            guardMessage = "The hot restore failed: \(statusDescription(status))."
        }

        if report.rollback_attempted != 0 {
            return guardMessage + (report.rollback_verified != 0
                ? " Continuum restored the pre-attempt safety state."
                : " The emergency rollback could not be verified; keep the app paused and close it.")
        }
        return guardMessage + " No memory was changed."
    }

    private func statusDescription(_ status: continuum_status) -> String {
        continuum_status_string(status).map(String.init(cString:)) ?? "status \(status.rawValue)"
    }

    private func clampedInt64(_ value: UInt64) -> Int64 {
        value > UInt64(Int64.max) ? Int64.max : Int64(value)
    }

    private static func experimentalResourceCoverage(
        writableVnodeCount: Int
    ) -> [ResourceCoverage] {[
        ResourceCoverage(
            domain: .memory,
            mode: .restored,
            detail: "Readable+writable private/COW memory is restored with readback validation."
        ),
        ResourceCoverage(
            domain: .threads,
            mode: .restored,
            detail: "ARM64 general and vector thread state is restored for the unchanged thread set."
        ),
        ResourceCoverage(
            domain: .localFiles,
            mode: .guarded,
            detail: "\(writableVnodeCount) writable open file\(writableVnodeCount == 1 ? "" : "s") are APFS-cloned during the coherent cut. Rename/delete history, closed files, and external writers remain uncovered."
        ),
        ResourceCoverage(
            domain: .descriptors,
            mode: .guarded,
            detail: "Descriptor topology and vnode identity must remain unchanged."
        ),
        ResourceCoverage(
            domain: .sockets,
            mode: .guarded,
            detail: "Socket identity and buffer counts are checked, not recreated."
        ),
        ResourceCoverage(
            domain: .machIPC,
            mode: .guarded,
            detail: "Every saved Mach name/right/object must remain valid. Additive XPC rights are allowed; queued messages are not replayed."
        ),
        ResourceCoverage(
            domain: .windowServer,
            mode: .unavailable,
            detail: "WindowServer state is not rebuilt in this checkpoint."
        ),
        ResourceCoverage(
            domain: .graphicsGPU,
            mode: .unavailable,
            detail: "Core Animation, Metal, and OpenGL resources are not rebuilt yet."
        ),
        ResourceCoverage(
            domain: .audioDevices,
            mode: .unavailable,
            detail: "Audio and device resources are not reopened yet."
        ),
        ResourceCoverage(
            domain: .clocksRandomInput,
            mode: .unavailable,
            detail: "Clock, randomness, and input events are not replayed yet."
        ),
    ]}
}

private final class HotProcessSnapshotHandle: @unchecked Sendable {
    let pointer: OpaquePointer
    let writableVnodes: [HotWritableVnode]
    let snapshotID: SnapshotID
    let appID: String
    let kind: SnapshotKind
    let fileCheckpointStore: APFSLocalFileCheckpointStore?

    init(
        pointer: OpaquePointer,
        writableVnodes: [HotWritableVnode],
        snapshotID: SnapshotID,
        appID: String,
        kind: SnapshotKind,
        fileCheckpointStore: APFSLocalFileCheckpointStore?
    ) {
        self.pointer = pointer
        self.writableVnodes = writableVnodes
        self.snapshotID = snapshotID
        self.appID = appID
        self.kind = kind
        self.fileCheckpointStore = fileCheckpointStore
    }

    deinit {
        continuum_remote_process_group_snapshot_destroy(pointer)
        try? fileCheckpointStore?.deleteCoherently(snapshotID: snapshotID)
    }
}

private struct HotProcessMember: Sendable {
    let processIdentifier: Int32
    let parentProcessIdentifier: Int32
}

private struct HotProcessManifest: Codable, Sendable {
    let formatVersion: Int
    let rootProcessIdentifier: Int32
    let processIdentifiers: [Int32]
    let capturedBytes: UInt64
    let capturedRegionCount: UInt64
    let excludedRegionCount: UInt64
    let threadCount: UInt64
    let writableVnodes: [HotWritableVnode]
    let resourceCoverage: [ResourceCoverage]
}

private struct HotWritableVnode: Codable, Hashable, Sendable, Comparable {
    let processIdentifier: Int32
    let fileDescriptor: Int32
    let openFlags: UInt32
    let offset: Int64
    let device: UInt64
    let inode: UInt64
    let byteCount: UInt64
    let mode: UInt32
    let path: String

    static func < (lhs: Self, rhs: Self) -> Bool {
        if lhs.processIdentifier != rhs.processIdentifier {
            return lhs.processIdentifier < rhs.processIdentifier
        }
        if lhs.fileDescriptor != rhs.fileDescriptor {
            return lhs.fileDescriptor < rhs.fileDescriptor
        }
        return lhs.path < rhs.path
    }
}

private final class HotResourceInventoryCallbackBox: @unchecked Sendable {
    let expectedInventory: [HotWritableVnode]?
    let fileCheckpointStore: APFSLocalFileCheckpointStore?
    let captureSnapshotID: SnapshotID?
    let restoreSnapshotID: SnapshotID?
    let rollbackSnapshotID: SnapshotID?
    var inventory: [HotWritableVnode]?
    var failureDescription: String?

    init(
        expectedInventory: [HotWritableVnode]? = nil,
        fileCheckpointStore: APFSLocalFileCheckpointStore? = nil,
        captureSnapshotID: SnapshotID? = nil,
        restoreSnapshotID: SnapshotID? = nil,
        rollbackSnapshotID: SnapshotID? = nil
    ) {
        self.expectedInventory = expectedInventory
        self.fileCheckpointStore = fileCheckpointStore
        self.captureSnapshotID = captureSnapshotID
        self.restoreSnapshotID = restoreSnapshotID
        self.rollbackSnapshotID = rollbackSnapshotID
    }

    func capture(from snapshot: OpaquePointer) -> continuum_status {
        var count = 0
        var status = continuum_remote_process_group_copy_writable_vnodes(
            snapshot,
            nil,
            0,
            &count
        )
        guard status == CONTINUUM_STATUS_OK else { return status }

        var rawEntries = Array(
            repeating: continuum_remote_writable_vnode_info(),
            count: count
        )
        var returnedCount = count
        status = rawEntries.withUnsafeMutableBufferPointer { buffer in
            continuum_remote_process_group_copy_writable_vnodes(
                snapshot,
                buffer.baseAddress,
                buffer.count,
                &returnedCount
            )
        }
        guard status == CONTINUUM_STATUS_OK, returnedCount == count else {
            return status == CONTINUUM_STATUS_OK
                ? CONTINUUM_STATUS_VALIDATION_FAILED
                : status
        }

        let captured = rawEntries.map(Self.convert).sorted()
        inventory = captured
        if let expectedInventory,
           !Self.hasMatchingStableIdentity(captured, expectedInventory) {
            return CONTINUUM_STATUS_DESCRIPTOR_TABLE_CHANGED
        }

        let files = Array(Set(captured.map(\.path)))
            .map { URL(fileURLWithPath: $0) }
            .sorted { $0.path < $1.path }
        if let fileCheckpointStore, let captureSnapshotID {
            do {
                _ = try fileCheckpointStore.captureCoherently(
                    snapshotID: captureSnapshotID,
                    files: files
                )
            } catch {
                failureDescription = "The coherent open-file checkpoint failed: \(error.localizedDescription)"
                return CONTINUUM_STATUS_VALIDATION_FAILED
            }
        }
        if let fileCheckpointStore, let restoreSnapshotID {
            do {
                _ = try fileCheckpointStore.restoreCoherently(
                    snapshotID: restoreSnapshotID
                )
            } catch {
                if let rollbackSnapshotID {
                    _ = try? fileCheckpointStore.restoreCoherently(
                        snapshotID: rollbackSnapshotID
                    )
                }
                failureDescription = "Open-file restoration failed and the process memory safety cut was reapplied: \(error.localizedDescription)"
                return CONTINUUM_STATUS_VALIDATION_FAILED
            }
        }
        return CONTINUUM_STATUS_OK
    }

    private static func hasMatchingStableIdentity(
        _ current: [HotWritableVnode],
        _ saved: [HotWritableVnode]
    ) -> Bool {
        guard current.count == saved.count else { return false }
        return zip(current, saved).allSatisfy { current, saved in
            current.processIdentifier == saved.processIdentifier
                && current.fileDescriptor == saved.fileDescriptor
                && current.openFlags == saved.openFlags
                && current.device == saved.device
                && current.inode == saved.inode
                && current.mode == saved.mode
                && current.path == saved.path
        }
    }

    private static func convert(
        _ rawValue: continuum_remote_writable_vnode_info
    ) -> HotWritableVnode {
        var rawValue = rawValue
        let path = withUnsafePointer(to: &rawValue.path) { pathPointer in
            pathPointer.withMemoryRebound(
                to: CChar.self,
                capacity: Int(CONTINUUM_REMOTE_PATH_MAX)
            ) {
                String(cString: $0)
            }
        }
        return HotWritableVnode(
            processIdentifier: rawValue.process_id,
            fileDescriptor: rawValue.file_descriptor,
            openFlags: rawValue.open_flags,
            offset: rawValue.offset,
            device: rawValue.device,
            inode: rawValue.inode,
            byteCount: rawValue.byte_count,
            mode: rawValue.mode,
            path: path
        )
    }
}

private func continuumCaptureHotResourceInventory(
    _ snapshot: OpaquePointer?,
    _ context: UnsafeMutableRawPointer?
) -> continuum_status {
    guard let snapshot, let context else {
        return CONTINUUM_STATUS_INVALID_ARGUMENT
    }
    let box = Unmanaged<HotResourceInventoryCallbackBox>
        .fromOpaque(context)
        .takeUnretainedValue()
    return box.capture(from: snapshot)
}

private func continuumValidateHotResourceInventory(
    _ snapshot: OpaquePointer?,
    _ context: UnsafeMutableRawPointer?
) -> continuum_status {
    continuumCaptureHotResourceInventory(snapshot, context)
}
