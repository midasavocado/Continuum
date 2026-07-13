import Foundation
import XCTest
@testable import ContinuumCore

final class ModelRoundTripTests: XCTestCase {
    private let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }()

    private let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return decoder
    }()

    func testSnapshotRecordRoundTripsThroughJSON() throws {
        let snapshot = makeSnapshot()

        let encoded = try encoder.encode(snapshot)
        let decoded = try decoder.decode(SnapshotRecord.self, from: encoded)

        XCTAssertEqual(decoded, snapshot)
    }

    func testDurableCheckpointImageRoundTripsWithoutLivePointers() throws {
        let chunk = DurableChunkReference(
            hash: String(repeating: "a", count: 64),
            logicalBytes: 16_384,
            storedBytes: 1_024,
            compression: .lzfse
        )
        let image = DurableCheckpointImage(
            checkpointID: UUID(),
            createdAt: Date(timeIntervalSince1970: 1_750_000_000),
            architecture: "arm64",
            operatingSystemBuild: "test-build",
            pageSize: 16_384,
            rootProcessIdentifier: 4242,
            app: makeApp(),
            members: [
                DurableProcessImage(
                    processIdentifier: 4242,
                    parentProcessIdentifier: 1,
                    executableDevice: 7,
                    executableInode: 9,
                    vmLayoutHash: 11,
                    launchContract: DurableLaunchContract(
                        executablePath: "/Applications/Test.app/Contents/MacOS/Test",
                        arguments: ["Test", "--restore-me"],
                        environment: ["LANG=en_US.UTF-8", "CONTINUUM_TEST=1"],
                        workingDirectory: "/private/tmp",
                        addressSpacePolicy: .continuumDeterministic
                    ),
                    regions: [
                        DurableMemoryRegion(
                            address: 0x1_0000_0000,
                            length: 16_384,
                            protection: 3,
                            maximumProtection: 7,
                            inheritance: 2,
                            shareMode: 2,
                            userTag: 0,
                            chunks: [chunk]
                        )
                    ],
                    threads: [
                        DurableThreadImage(
                            threadIdentifier: 13,
                            threadHandle: 0x1_2345_0000,
                            dispatchQueueAddress: 0x1_2346_0000,
                            generalStateFlavor: 6,
                            generalState: chunk,
                            vectorStateFlavor: 17,
                            vectorState: chunk
                        )
                    ]
                )
            ],
            writableFiles: []
        )

        XCTAssertEqual(try roundTrip(image), image)
        XCTAssertEqual(image.formatVersion, DurableCheckpointImage.currentFormatVersion)
    }

    func testStoreIndexRoundTripsNestedSnapshotBranchAndProvisionalRewind() throws {
        let snapshot = makeSnapshot()
        let branch = BranchRecord(
            id: snapshot.branchID,
            name: "Main timeline",
            parentBranchID: nil,
            rootSnapshotID: snapshot.id,
            tipSnapshotID: snapshot.id,
            createdAt: Date(timeIntervalSince1970: 1_750_000_001),
            isActive: true
        )
        let provisional = ProvisionalRewind(
            id: UUID(uuidString: "44444444-4444-4444-4444-444444444444")!,
            safetySnapshotID: snapshot.id,
            sourceBranchID: branch.id,
            createdAt: Date(timeIntervalSince1970: 1_750_000_002)
        )
        let index = StoreIndex(
            schemaVersion: ContinuumConstants.schemaVersion,
            snapshots: [snapshot],
            branches: [branch],
            provisionalRewinds: [provisional]
        )

        let encoded = try encoder.encode(index)
        let decoded = try decoder.decode(StoreIndex.self, from: encoded)

        XCTAssertEqual(decoded.schemaVersion, index.schemaVersion)
        XCTAssertEqual(decoded.snapshots, index.snapshots)
        XCTAssertEqual(decoded.branches, index.branches)
        XCTAssertEqual(decoded.provisionalRewinds, index.provisionalRewinds)
    }

    func testCaptureSessionRoundTripsSetAndBudgets() throws {
        let session = CaptureSession(
            id: UUID(uuidString: "55555555-5555-5555-5555-555555555555")!,
            scope: .selectedApps,
            appIDs: ["com.example.editor", "com.example.game"],
            activeBranchID: UUID(uuidString: "33333333-3333-3333-3333-333333333333")!,
            startedAt: Date(timeIntervalSince1970: 1_750_000_003),
            diskBudgetBytes: 42_000_000,
            hotMemoryBudgetBytes: 7_000_000
        )

        let encoded = try encoder.encode(session)
        let decoded = try decoder.decode(CaptureSession.self, from: encoded)

        XCTAssertEqual(decoded, session)
    }

    func testCompatibilityReportRoundTripsSigningIdentity() throws {
        let report = CompatibilityReport(
            app: makeApp(),
            tier: .managedInstrumentation,
            canCaptureNow: true,
            canRestoreNow: false,
            explanation: "Capture proof passed; restore proof is pending.",
            inspectedAt: Date(timeIntervalSince1970: 1_750_000_004)
        )

        let encoded = try encoder.encode(report)
        let decoded = try decoder.decode(CompatibilityReport.self, from: encoded)

        XCTAssertEqual(decoded, report)
    }

    func testProcessAndPermissionModelsRoundTrip() throws {
        let process = ProcessDescriptor(
            processIdentifier: 4242,
            parentProcessIdentifier: 42,
            app: makeApp(),
            isFrontmost: true,
            isTerminated: false
        )
        let permission = PermissionStatus(
            kind: .accessibility,
            state: .requiresSystemSettings,
            detail: "Finish setup in System Settings."
        )

        XCTAssertEqual(try roundTrip(process), process)
        XCTAssertEqual(try roundTrip(permission), permission)
    }

    func testStorageMetricsRoundTripKeepsPhysicalAccounting() throws {
        let metrics = StorageMetrics(
            logicalBytes: 20_000,
            physicalBytes: 5_000,
            pinnedBytes: 2_500,
            budgetBytes: 50_000
        )

        XCTAssertEqual(try roundTrip(metrics), metrics)
        XCTAssertEqual(metrics.usageFraction, 0.1, accuracy: 0.000_001)
    }

    func testCodableEnumsRoundTripEverySupportedValue() throws {
        try assertRoundTrips(CaptureScope.allCases)
        try assertRoundTrips(SnapshotKind.allCases)
        try assertRoundTrips(RestoreAvailability.allCases)
        try assertRoundTrips(CompatibilityTier.allCases)
        try assertRoundTrips(PermissionKind.allCases)
        try assertRoundTrips(ExternalEffectKind.allCases)
        try assertRoundTrips(ResourceDomain.allCases)
        try assertRoundTrips(ResourceRestoreMode.allCases)
        try assertRoundTrips([
            CheckpointValidation.provisional,
            .validating,
            .valid,
            .invalid,
        ])
        try assertRoundTrips([
            PermissionState.granted,
            .denied,
            .notRequested,
            .requiresSystemSettings,
            .unknown,
        ])
        try assertRoundTrips([
            CapturedArtifactKind.memoryPage,
            .threadState,
            .fileBlock,
            .descriptorState,
            .graphicsState,
            .inputEvent,
            .nondeterminismEvent,
            .metadata,
        ])
    }

    func testCompleteResourceCoverageRejectsMissingGuardedAndDuplicateDomains() {
        let complete = ResourceDomain.allCases.map {
            ResourceCoverage(domain: $0, mode: .restored, detail: "fixture")
        }
        var snapshot = makeSnapshot()
        snapshot.resourceCoverage = complete
        XCTAssertTrue(snapshot.hasCompleteResourceCoverage)

        snapshot.resourceCoverage = Array(complete.dropLast())
        XCTAssertFalse(snapshot.hasCompleteResourceCoverage)

        snapshot.resourceCoverage = complete.map {
            $0.domain == .sockets
                ? ResourceCoverage(domain: .sockets, mode: .guarded, detail: "guard only")
                : $0
        }
        XCTAssertFalse(snapshot.hasCompleteResourceCoverage)

        snapshot.resourceCoverage = complete + [complete[0]]
        XCTAssertFalse(snapshot.hasCompleteResourceCoverage)
    }

    private func makeApp() -> AppIdentity {
        AppIdentity(
            bundleIdentifier: "com.example.continuum-fixture",
            displayName: "Continuum Fixture",
            bundleURL: URL(fileURLWithPath: "/Applications/Continuum Fixture.app"),
            executableURL: URL(fileURLWithPath: "/Applications/Continuum Fixture.app/Contents/MacOS/Fixture"),
            version: "1.2.3",
            signingIdentifier: "com.example.continuum-fixture",
            teamIdentifier: "EXAMPLETEAM",
            isApplePlatformBinary: false
        )
    }

    private func makeSnapshot() -> SnapshotRecord {
        let branchID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
        let checkpoint = CheckpointRecord(
            id: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
            capturedAt: Date(timeIntervalSince1970: 1_750_000_000),
            monotonicNanoseconds: 987_654_321,
            processIdentifiers: [101, 102],
            memoryRegionCount: 23,
            threadCount: 7,
            validation: .valid
        )
        let effect = ExternalEffect(
            id: UUID(uuidString: "66666666-6666-6666-6666-666666666666")!,
            occurredAt: Date(timeIntervalSince1970: 1_749_999_999),
            destination: "example.invalid",
            kind: .networkRequest,
            summary: "Fixture request"
        )

        return SnapshotRecord(
            id: UUID(uuidString: "11111111-1111-1111-1111-111111111111")!,
            name: "Before Rewind — Continuum Fixture",
            note: "Round-trip me, Scotty.",
            kind: .beforeRewind,
            app: makeApp(),
            checkpoint: checkpoint,
            branchID: branchID,
            createdAt: Date(timeIntervalSince1970: 1_750_000_000),
            availability: .instant,
            chunkHashes: ["abc123", "def456"],
            logicalBytes: 32_768,
            uniqueBytes: 16_384,
            hotMemoryBytes: 65_536,
            isPinned: true,
            externalEffects: [effect],
            resourceCoverage: ResourceDomain.allCases.map {
                ResourceCoverage(domain: $0, mode: .restored, detail: "fixture")
            }
        )
    }

    private func roundTrip<Value: Codable>(_ value: Value) throws -> Value {
        try decoder.decode(Value.self, from: encoder.encode(value))
    }

    private func assertRoundTrips<Value: Codable & Equatable>(_ values: [Value]) throws {
        for value in values {
            XCTAssertEqual(try roundTrip(value), value)
        }
    }
}
