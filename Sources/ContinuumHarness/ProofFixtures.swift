import ContinuumCore
import Foundation

enum ProofFixtures {
    static let app = AppIdentity(
        bundleIdentifier: "com.example.ContinuumHarness",
        displayName: "Continuum Harness",
        bundleURL: nil,
        executableURL: URL(fileURLWithPath: CommandLine.arguments[0]),
        version: "1",
        signingIdentifier: nil,
        teamIdentifier: nil,
        isApplePlatformBinary: false
    )

    static func capture(
        id: SnapshotID = UUID(),
        name: String,
        kind: SnapshotKind,
        branchID: BranchID,
        payload: Data,
        monotonicNanoseconds: UInt64
    ) -> SnapshotCapture {
        let checkpoint = CheckpointRecord(
            capturedAt: .now,
            monotonicNanoseconds: monotonicNanoseconds,
            processIdentifiers: [ProcessInfo.processInfo.processIdentifier],
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
            availability: .instant,
            logicalBytes: Int64(payload.count),
            isPinned: true
        )
        let artifact = CapturedArtifact(
            kind: .metadata,
            logicalName: "proof-payload",
            data: payload
        )
        return SnapshotCapture(snapshot: snapshot, artifacts: [artifact])
    }
}
