import ContinuumCore
import ContinuumRuntime
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
    private var handles: [SnapshotID: HotProcessSnapshotHandle] = [:]
    private var retentionOrder: [SnapshotID] = []

    public init(
        maximumCapturedBytes: UInt64 = UInt64(ContinuumConstants.defaultHotMemoryBudgetBytes),
        maximumRetainedSnapshots: Int = 8
    ) {
        self.maximumCapturedBytes = maximumCapturedBytes
        self.maximumRetainedSnapshots = max(maximumRetainedSnapshots, 2)
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

        var rawSnapshot: OpaquePointer?
        var info = continuum_remote_process_group_snapshot_info()
        let status = continuum_remote_process_group_capture(
            rootProcessIdentifier,
            maximumCapturedBytes,
            &rawSnapshot,
            &info
        )
        guard status == CONTINUUM_STATUS_OK, let rawSnapshot else {
            throw captureError(status: status, appName: app.displayName)
        }

        let handle = HotProcessSnapshotHandle(pointer: rawSnapshot)
        do {
            let members = try groupMembers(in: rawSnapshot)
            guard !members.isEmpty,
                  members.contains(where: { $0.processIdentifier == rootProcessIdentifier }) else {
                throw ContinuumError.runtimeUnsupported(
                    "The runtime did not capture the selected app's root process."
                )
            }

            let capturedAt = Date.now
            let snapshotID = UUID()
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
                localFileCoverage: .unavailable,
                allowsKeepingCurrentFiles: false
            )

            let manifest = HotProcessManifest(
                formatVersion: 1,
                rootProcessIdentifier: rootProcessIdentifier,
                processIdentifiers: members.map(\.processIdentifier).sorted(),
                capturedBytes: info.captured_bytes,
                capturedRegionCount: info.captured_region_count,
                excludedRegionCount: info.excluded_region_count,
                threadCount: info.thread_count,
                resourceCoverage: .guardedHotOnly
            )
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let manifestData = try encoder.encode(manifest)

            retain(handle, for: snapshotID)
            return SnapshotCapture(
                snapshot: snapshot,
                artifacts: [
                    CapturedArtifact(
                        kind: .metadata,
                        logicalName: "experimental-hot-manifest.json",
                        data: manifestData
                    )
                ]
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
            return .failed("This backend only restores Experimental Hot snapshots.")
        }
        guard let handle = handles[snapshot.id] else {
            return .failed(
                "The hot process state expired because Continuum or the captured app was relaunched."
            )
        }

        var report = continuum_remote_process_group_restore_report()
        let status = continuum_remote_process_group_restore(handle.pointer, &report)
        guard status == CONTINUUM_STATUS_OK else {
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
        return handles[snapshot.id] == nil ? .unavailable : .experimentalHot
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
}

private final class HotProcessSnapshotHandle: @unchecked Sendable {
    let pointer: OpaquePointer

    init(pointer: OpaquePointer) {
        self.pointer = pointer
    }

    deinit {
        continuum_remote_process_group_snapshot_destroy(pointer)
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
    let resourceCoverage: HotResourceCoverage
}

/// This is the reconstruction contract that must be upgraded component by
/// component. `guarded` means restore is rejected if the resource changed;
/// it does not mean the resource has been serialized or recreated.
private struct HotResourceCoverage: Codable, Sendable {
    enum Level: String, Codable, Sendable {
        case restored
        case reconnected
        case rebuilt
        case guarded
        case unavailable
    }

    let memory: Level
    let threads: Level
    let files: Level
    let descriptorsAndSockets: Level
    let machAndXPC: Level
    let windowServer: Level
    let graphicsAndGPU: Level
    let audioAndDevices: Level

    static let guardedHotOnly = HotResourceCoverage(
        memory: .restored,
        threads: .restored,
        files: .unavailable,
        descriptorsAndSockets: .guarded,
        machAndXPC: .guarded,
        windowServer: .unavailable,
        graphicsAndGPU: .unavailable,
        audioAndDevices: .unavailable
    )
}
