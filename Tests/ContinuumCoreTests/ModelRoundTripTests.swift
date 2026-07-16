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
            artifactName: "memory/4242/0000000100000000/0000000000000000.bin",
            logicalBytes: 16_384,
            storedBytes: 1_024,
            compression: .lzfse
        )
        let listenerID = UUID(uuidString: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")!
        let connectedSocketID = UUID(uuidString: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")!
        let pipeReadID = UUID(uuidString: "cccccccc-cccc-cccc-cccc-cccccccccccc")!
        let pipeWriteID = UUID(uuidString: "dddddddd-dddd-dddd-dddd-dddddddddddd")!
        let kqueueID = UUID(uuidString: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee")!
        let image = DurableCheckpointImage(
            checkpointID: UUID(),
            createdAt: Date(timeIntervalSince1970: 1_750_000_000),
            architecture: "arm64",
            operatingSystemBuild: "test-build",
            pageSize: 16_384,
            rootProcessIdentifier: 4242,
            rootProcessIdentifiers: [4242, 5252],
            app: makeApp(),
            members: [
                DurableProcessImage(
                    processIdentifier: 4242,
                    parentProcessIdentifier: 1,
                    executableDevice: 7,
                    executableInode: 9,
                    vmLayoutHash: 11,
                    immutableLayoutDigest: String(repeating: "b", count: 64),
                    launchContract: DurableLaunchContract(
                        executablePath: "/Applications/Test.app/Contents/MacOS/Test",
                        arguments: ["Test", "--restore-me"],
                        environment: ["LANG=en_US.UTF-8", "CONTINUUM_TEST=1"],
                        workingDirectory: "/private/tmp",
                        addressSpacePolicy: .continuumDeterministic
                    ),
                    topology: DurableProcessTopology(
                        processGroupIdentifier: 4242,
                        sessionIdentifier: 4000,
                        controllingTerminalDevice: 0x0100_0007,
                        foregroundProcessGroupIdentifier: 4242
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
                            pthreadObjectAddress: 0x1_2344_FF20,
                            origin: .pthread,
                            dispatchQueueAddress: 0x1_2346_0000,
                            stackPointer: 0x1_0000_3000,
                            stackRegionAddress: 0x1_0000_0000,
                            stackRegionLength: 16_384,
                            pthreadRegionAddress: 0x1_0000_0000,
                            pthreadRegionLength: 16_384,
                            generalStateFlavor: 6,
                            generalState: chunk,
                            vectorStateFlavor: 17,
                            vectorState: chunk
                        )
                    ]
                )
            ],
            writableFiles: [
                DurableFileImage(
                    originalPath: "/private/tmp/continuum-state.bin",
                    device: 7,
                    inode: 21,
                    byteCount: 16_384,
                    mode: 0o100600,
                    chunks: [chunk]
                )
            ],
            writableFileDescriptors: [
                DurableWritableFileDescriptor(
                    processIdentifier: 4242,
                    fileDescriptor: 9,
                    openFlags: 2,
                    offset: 512,
                    device: 7,
                    inode: 21,
                    mode: 0o100600,
                    originalPath: "/private/tmp/continuum-state.bin"
                )
            ],
            establishedTCPEndpoints: [
                DurableTCPEndpoint(
                    processIdentifier: 4242,
                    fileDescriptor: 11,
                    domain: 2,
                    socketType: 1,
                    socketProtocol: 6,
                    tcpState: 4,
                    socketState: 0x20,
                    localAddressLength: 16,
                    remoteAddressLength: 16,
                    localAddress: Array(0..<16),
                    remoteAddress: Array(16..<32),
                    receiveQueueBytes: 128,
                    sendQueueBytes: 64,
                    receiveShutdown: false,
                    sendShutdown: true
                )
            ],
            ptyDescriptors: [
                DurablePTYDescriptor(
                    processIdentifier: 4242,
                    fileDescriptor: 1,
                    openFlags: 2,
                    role: .slave,
                    device: 16,
                    inode: 3_163,
                    rawDevice: 4_097,
                    deviceMajor: 16,
                    deviceMinor: 1,
                    ttyIndex: 1,
                    aliasIdentity: 0x10_0000_0001,
                    terminalAttributes: [1, 2, 3, 4],
                    windowSize: [40, 0, 120, 0]
                )
            ],
            descriptorGraph: DurableDescriptorGraph(
                handles: [
                    DurableDescriptorHandle(
                        resourceID: listenerID,
                        processIdentifier: 4242,
                        fileDescriptor: 5,
                        descriptorFlags: 1,
                        statusFlags: 4
                    ),
                    DurableDescriptorHandle(
                        resourceID: connectedSocketID,
                        processIdentifier: 4242,
                        fileDescriptor: 6,
                        descriptorFlags: 0,
                        statusFlags: 4
                    ),
                    DurableDescriptorHandle(
                        resourceID: connectedSocketID,
                        processIdentifier: 5252,
                        fileDescriptor: 8,
                        descriptorFlags: 1,
                        statusFlags: 4
                    ),
                    DurableDescriptorHandle(
                        resourceID: pipeReadID,
                        processIdentifier: 4242,
                        fileDescriptor: 7,
                        descriptorFlags: 0,
                        statusFlags: 0
                    ),
                    DurableDescriptorHandle(
                        resourceID: pipeWriteID,
                        processIdentifier: 5252,
                        fileDescriptor: 9,
                        descriptorFlags: 0,
                        statusFlags: 4
                    ),
                    DurableDescriptorHandle(
                        resourceID: kqueueID,
                        processIdentifier: 4242,
                        fileDescriptor: 10,
                        descriptorFlags: 1,
                        statusFlags: 0
                    ),
                ],
                sockets: [
                    DurableSocketResource(
                        id: listenerID,
                        kind: .tcpListener,
                        domain: 2,
                        type: 1,
                        protocol: 6,
                        localAddress: Data([2, 0, 44, 204, 127, 0, 0, 1]),
                        backlog: 128,
                        receiveQueueBytes: 0,
                        sendQueueBytes: 0,
                        receiveShutdown: false,
                        sendShutdown: false,
                        options: [
                            DurableSocketOption(level: 0xffff, name: 0x0004, value: Data([1, 0, 0, 0]))
                        ]
                    ),
                    DurableSocketResource(
                        id: connectedSocketID,
                        kind: .unixConnected,
                        domain: 1,
                        type: 1,
                        protocol: 0,
                        localAddress: Data([1, 0]),
                        remoteAddress: Data([1, 0, 47, 118, 97, 114, 47, 114, 117, 110]),
                        receiveQueueBytes: 0,
                        sendQueueBytes: 0,
                        receiveShutdown: false,
                        sendShutdown: false,
                        externalPath: "/var/run/example.sock"
                    ),
                ],
                pipes: [
                    DurablePipeResource(
                        id: pipeReadID,
                        peerResourceID: pipeWriteID,
                        capacity: 65_536,
                        queuedBytes: 16_384,
                        status: 1,
                        payload: chunk
                    ),
                    DurablePipeResource(
                        id: pipeWriteID,
                        peerResourceID: pipeReadID,
                        capacity: 65_536,
                        queuedBytes: 0,
                        status: 2
                    ),
                ],
                kqueues: [
                    DurableKqueueResource(
                        id: kqueueID,
                        processIdentifier: 4242,
                        registrations: [
                            DurableKqueueRegistration(
                                ident: 6,
                                filter: -1,
                                flags: 0x0021,
                                fflags: 0,
                                data: 0,
                                udata: 0x1234,
                                qos: 4,
                                savedData: 0,
                                status: 1
                            )
                        ]
                    )
                ]
            )
        )

        XCTAssertEqual(try roundTrip(image), image)
        XCTAssertEqual(image.formatVersion, DurableCheckpointImage.currentFormatVersion)
        XCTAssertEqual(image.descriptorGraph?.handles.filter { $0.resourceID == connectedSocketID }.count, 2)
    }

    func testDurableCheckpointImageDecodesVersionFourWithoutDescriptorGraph() throws {
        let checkpointID = UUID(uuidString: "ffffffff-ffff-ffff-ffff-ffffffffffff")!
        let legacyJSON = """
        {
          "formatVersion": 4,
          "checkpointID": "\(checkpointID.uuidString)",
          "createdAt": 1750000000000,
          "architecture": "arm64",
          "operatingSystemBuild": "legacy-build",
          "pageSize": 16384,
          "rootProcessIdentifier": 4242,
          "app": {
            "bundleIdentifier": "com.example.legacy",
            "displayName": "Legacy Fixture",
            "bundleURL": "file:///Applications/Legacy.app",
            "executableURL": "file:///Applications/Legacy.app/Contents/MacOS/Legacy",
            "version": "1.0",
            "signingIdentifier": "com.example.legacy",
            "isApplePlatformBinary": false
          },
          "members": [],
          "writableFiles": [],
          "writableFileDescriptors": []
        }
        """

        let decoded = try decoder.decode(DurableCheckpointImage.self, from: Data(legacyJSON.utf8))

        XCTAssertEqual(decoded.formatVersion, 4)
        XCTAssertEqual(decoded.checkpointID, checkpointID)
        XCTAssertNil(decoded.descriptorGraph)
        XCTAssertNil(decoded.establishedTCPEndpoints)
        XCTAssertNil(decoded.ptyDescriptors)
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
            },
            coldRestoreCertified: true
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
