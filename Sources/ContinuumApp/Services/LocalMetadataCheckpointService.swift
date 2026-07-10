import Darwin
import Foundation
import ContinuumCore

/// An honest last-resort capturer. It records enough information to explain what
/// was running, but deliberately marks the result as unavailable for restore.
struct LocalMetadataCheckpointService: CheckpointCapturing {
    private let exactBackend: (any CheckpointCapturing)?

    init(exactBackend: (any CheckpointCapturing)? = nil) {
        self.exactBackend = exactBackend
    }

    func capture(
        app: AppIdentity,
        processIdentifiers: [Int32],
        kind: SnapshotKind,
        branchID: BranchID
    ) async throws -> SnapshotCapture {
        if let exactBackend {
            return try await exactBackend.capture(
                app: app,
                processIdentifiers: processIdentifiers,
                kind: kind,
                branchID: branchID
            )
        }

        let capturedAt = Date.now
        let processMetadata = processIdentifiers
            .sorted()
            .compactMap(ProcessMetadataProbe.inspect)

        guard !processMetadata.isEmpty else {
            throw ContinuumError.runtimeUnsupported(
                "The process ended before Continuum could record its metadata."
            )
        }

        let manifest = MetadataCheckpointManifest(
            capturedAt: capturedAt,
            appIdentifier: app.id,
            appVersion: app.version,
            processes: processMetadata,
            restoreCapability: .metadataOnly,
            limitations: [
                "No writable memory pages were captured.",
                "No thread registers or kernel resources were captured.",
                "This record is diagnostic and cannot restore application state."
            ]
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let manifestData = try encoder.encode(manifest)

        let checkpoint = CheckpointRecord(
            capturedAt: capturedAt,
            monotonicNanoseconds: clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW),
            processIdentifiers: processMetadata.map(\.processIdentifier),
            memoryRegionCount: 0,
            threadCount: processMetadata.reduce(0) { $0 + $1.threadCount },
            validation: .valid
        )

        let snapshot = SnapshotRecord(
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
            availability: .unavailable,
            logicalBytes: Int64(manifestData.count),
            uniqueBytes: Int64(manifestData.count),
            isPinned: kind != .automatic
        )

        return SnapshotCapture(
            snapshot: snapshot,
            artifacts: [
                CapturedArtifact(
                    kind: .metadata,
                    logicalName: "process-metadata.json",
                    data: manifestData
                )
            ]
        )
    }

    func restore(
        snapshot: SnapshotRecord,
        artifacts: [CapturedArtifact]
    ) async -> RestoreResult {
        guard let exactBackend else {
            return .failed(
                "This snapshot contains process metadata only. Continuum did not capture memory, thread registers, files, or live resources, so restoring it would be fake."
            )
        }

        return await exactBackend.restore(snapshot: snapshot, artifacts: artifacts)
    }
}

private enum RestoreCapability: String, Codable, Sendable {
    case metadataOnly
}

private struct MetadataCheckpointManifest: Codable, Sendable {
    let capturedAt: Date
    let appIdentifier: String
    let appVersion: String?
    let processes: [ProcessMetadata]
    let restoreCapability: RestoreCapability
    let limitations: [String]
}

private struct ProcessMetadata: Codable, Sendable {
    let processIdentifier: Int32
    let parentProcessIdentifier: Int32
    let executablePath: String?
    let startedAt: Date
    let threadCount: Int
    let runningThreadCount: Int
    let virtualMemoryBytes: UInt64
    let residentMemoryBytes: UInt64
    let pageFaultCount: Int32
    let contextSwitchCount: Int32
}

private enum ProcessMetadataProbe {
    static func inspect(processIdentifier: Int32) -> ProcessMetadata? {
        var bsdInfo = proc_bsdinfo()
        let bsdInfoSize = Int32(MemoryLayout<proc_bsdinfo>.stride)
        let bsdResult = proc_pidinfo(
            processIdentifier,
            PROC_PIDTBSDINFO,
            0,
            &bsdInfo,
            bsdInfoSize
        )

        guard bsdResult == bsdInfoSize else { return nil }

        var taskInfo = proc_taskinfo()
        let taskInfoSize = Int32(MemoryLayout<proc_taskinfo>.stride)
        let taskResult = proc_pidinfo(
            processIdentifier,
            PROC_PIDTASKINFO,
            0,
            &taskInfo,
            taskInfoSize
        )

        guard taskResult == taskInfoSize else { return nil }

        return ProcessMetadata(
            processIdentifier: processIdentifier,
            parentProcessIdentifier: Int32(bitPattern: bsdInfo.pbi_ppid),
            executablePath: executablePath(for: processIdentifier),
            startedAt: Date(
                timeIntervalSince1970: TimeInterval(bsdInfo.pbi_start_tvsec)
                    + TimeInterval(bsdInfo.pbi_start_tvusec) / 1_000_000
            ),
            threadCount: Int(taskInfo.pti_threadnum),
            runningThreadCount: Int(taskInfo.pti_numrunning),
            virtualMemoryBytes: taskInfo.pti_virtual_size,
            residentMemoryBytes: taskInfo.pti_resident_size,
            pageFaultCount: taskInfo.pti_faults,
            contextSwitchCount: taskInfo.pti_csw
        )
    }

    private static func executablePath(for processIdentifier: Int32) -> String? {
        // `PROC_PIDPATHINFO_MAXSIZE` is a C expression Swift does not import.
        // Four PATH_MAX buffers matches libproc's documented maximum.
        var buffer = [CChar](repeating: 0, count: 4 * Int(PATH_MAX))
        let length = proc_pidpath(processIdentifier, &buffer, UInt32(buffer.count))
        guard length > 0 else { return nil }
        let bytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self)
    }
}
