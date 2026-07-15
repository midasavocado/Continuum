import Foundation
import Testing
import ContinuumCore
@testable import ContinuumSystem

@Suite("Generic managed-copy app setup")
struct AppSetupCoordinatorTests {
    @Test("Atomically arms the normal launch path while preserving the vendor original")
    func preparesManagedCopy() async throws {
        let fixture = try SetupFixture()
        defer { fixture.remove() }
        let coordinator = fixture.coordinator()
        let sourceTokenBefore = try Data(contentsOf: fixture.sourceTokenURL)

        let record = try await coordinator.setup(fixture.app)

        #expect(record.state == .prepared)
        #expect(record.validation?.sourceUnchanged == true)
        #expect(record.validation?.originalCloneVerified == true)
        #expect(record.validation?.instrumentationMarkerValid == true)
        #expect(record.validation?.managedSignatureValid == true)
        #expect(record.validation?.managedAttachEntitlementValid == true)
        #expect(record.validation?.restoreCertificationPassed == false)
        #expect(record.managedInstalledAtSource == true)
        #expect(try Data(contentsOf: fixture.sourceTokenURL) == sourceTokenBefore)

        let originalURL = try #require(record.originalCloneURL)
        let managedURL = try #require(record.managedBundleURL)
        #expect(FileManager.default.fileExists(atPath: originalURL.path))
        #expect(FileManager.default.fileExists(atPath: managedURL.path))
        #expect(!FileManager.default.fileExists(atPath: markerURL(in: originalURL).path))
        #expect(FileManager.default.fileExists(atPath: markerURL(in: managedURL).path))
        #expect(FileManager.default.fileExists(atPath: markerURL(in: fixture.sourceURL).path))
        #expect(FileManager.default.fileExists(atPath: try #require(record.displacedOriginalURL).path))
        let embeddedBootstrap = managedURL
            .appendingPathComponent("Contents/Frameworks/libContinuumBootstrap.dylib")
        #expect(try Data(contentsOf: embeddedBootstrap) == Data(contentsOf: fixture.bootstrapURL))
        let managedInfo = try #require(
            PropertyListSerialization.propertyList(
                from: Data(contentsOf: managedURL.appendingPathComponent("Contents/Info.plist")),
                options: [],
                format: nil
            ) as? [String: Any]
        )
        let environment = try #require(managedInfo["LSEnvironment"] as? [String: String])
        #expect(environment["CONTINUUM_ENABLE_CHECKPOINT_SAFEPOINTS"] == "1")
        #expect(environment["CONTINUUM_DETERMINISTIC_ADDRESS_SPACE"] == "1")
        #expect(environment["DYLD_SHARED_REGION"] == "private")
        #expect(environment["MallocLargeCache"] == "0")
        #expect(environment["DYLD_INSERT_LIBRARIES"] == "@executable_path/../Frameworks/libContinuumBootstrap.dylib")

        let reloaded = fixture.coordinator()
        let persisted = try await reloaded.records()
        #expect(persisted.count == 1)
        #expect(persisted.first?.id == record.id)
        #expect(persisted.first?.state == .prepared)
    }

    @Test("Persists generic blockers without creating a managed workspace")
    func blocksUnsupportedBundleFacts() async throws {
        let blockers: [AppSetupBlocker] = [
            .applePlatformBinary,
            .sandboxIdentityBound,
            .appStoreReceiptOrDRM,
            .signedIdentityBound,
            .restrictedEntitlements(["example.identity-bound"]),
            .nestedCodeUnsupported
        ]
        let fixture = try SetupFixture(blockers: blockers)
        defer { fixture.remove() }
        let coordinator = fixture.coordinator()

        let record = try await coordinator.setup(fixture.app)

        #expect(record.state == .blocked(blockers))
        #expect(!FileManager.default.fileExists(
            atPath: fixture.rootURL
                .appendingPathComponent("Workspaces")
                .appendingPathComponent(record.id.uuidString)
                .path
        ))
        #expect(FileManager.default.fileExists(atPath: fixture.sourceURL.path))
    }

    @Test("A source fingerprint update marks the setup stale")
    func updateMarksStale() async throws {
        let fixture = try SetupFixture()
        defer { fixture.remove() }
        let coordinator = fixture.coordinator()
        let prepared = try await coordinator.setup(fixture.app)
        let workspaceURL = fixture.rootURL
            .appendingPathComponent("Workspaces")
            .appendingPathComponent(prepared.id.uuidString)
        try Data("version-two".utf8).write(to: fixture.sourceTokenURL, options: .atomic)

        let revalidated = try await coordinator.revalidate(prepared.id)

        #expect(revalidated.state == .stale)
        #expect(revalidated.validation?.sourceUnchanged == false)
        #expect(FileManager.default.fileExists(atPath: workspaceURL.path))
    }

    @Test("A vendor update replaces the old armed backup without orphaning it")
    func vendorUpdateRearmsCurrentVersion() async throws {
        let fixture = try SetupFixture()
        defer { fixture.remove() }
        let coordinator = fixture.coordinator()
        let first = try await coordinator.setup(fixture.app)
        let preservedOriginal = try #require(first.originalCloneURL)

        try FileManager.default.removeItem(at: fixture.sourceURL)
        try FileManager.default.copyItem(at: preservedOriginal, to: fixture.sourceURL)
        try Data("version-two".utf8).write(to: fixture.sourceTokenURL, options: .atomic)

        let updated = try await coordinator.setup(fixture.app)
        let hiddenBackups = try FileManager.default.contentsOfDirectory(
            at: fixture.parentURL,
            includingPropertiesForKeys: nil
        ).filter {
            $0.lastPathComponent.hasPrefix(".Continuum-")
                && $0.lastPathComponent.hasSuffix("-Original.app")
        }

        #expect(updated.managedInstalledAtSource == true)
        #expect(updated.sourceFingerprint == FixtureProbe.fingerprint(token: "version-two"))
        #expect(FileManager.default.fileExists(atPath: markerURL(in: fixture.sourceURL).path))
        #expect(hiddenBackups.count == 1)
    }

    @Test("Repeated probe and setup reuse one durable record and workspace")
    func repeatedSetupIsIdempotent() async throws {
        let fixture = try SetupFixture()
        defer { fixture.remove() }
        let coordinator = fixture.coordinator()

        let first = try await coordinator.setup(fixture.app)
        let checked = try await coordinator.probe(fixture.app)
        let second = try await coordinator.setup(fixture.app)
        let records = try await coordinator.records()

        #expect(first.id == checked.id)
        #expect(first.id == second.id)
        #expect(records.count == 1)
        #expect(records.first?.state == .prepared)
        #expect(first.managedBundleURL == second.managedBundleURL)
        #expect(FileManager.default.fileExists(atPath: try #require(second.managedBundleURL).path))
    }

    @Test("Rollback removes only its managed workspace")
    func rollbackIsTargeted() async throws {
        let fixture = try SetupFixture()
        defer { fixture.remove() }
        let coordinator = fixture.coordinator()
        let prepared = try await coordinator.setup(fixture.app)
        let workspaceURL = fixture.rootURL
            .appendingPathComponent("Workspaces")
            .appendingPathComponent(prepared.id.uuidString)
        let unrelatedURL = fixture.rootURL.appendingPathComponent("KeepMe")
        try FileManager.default.createDirectory(at: unrelatedURL, withIntermediateDirectories: true)

        try await coordinator.rollback(prepared.id)

        #expect(!FileManager.default.fileExists(atPath: workspaceURL.path))
        #expect(FileManager.default.fileExists(atPath: unrelatedURL.path))
        #expect(FileManager.default.fileExists(atPath: fixture.sourceURL.path))
        #expect(!FileManager.default.fileExists(atPath: markerURL(in: fixture.sourceURL).path))
        #expect(try Data(contentsOf: fixture.sourceTokenURL) == Data("version-one".utf8))
        #expect(try await coordinator.records().first?.state == .rolledBack)
    }

    @Test("Interrupted setup recovery durably rolls back its workspace")
    func recoversInterruptedSetup() async throws {
        let fixture = try SetupFixture()
        defer { fixture.remove() }
        let recordID = UUID()
        let workspaceURL = fixture.rootURL
            .appendingPathComponent("Workspaces")
            .appendingPathComponent(recordID.uuidString)
        try FileManager.default.createDirectory(at: workspaceURL, withIntermediateDirectories: true)
        try Data("partial".utf8).write(to: workspaceURL.appendingPathComponent("partial"))

        let record = AppSetupRecord(
            id: recordID,
            app: fixture.app,
            sourceURL: fixture.sourceURL,
            sourceFingerprint: FixtureProbe.fingerprint(token: "version-one"),
            state: .preparing(.cloningManaged)
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        try FileManager.default.createDirectory(at: fixture.rootURL, withIntermediateDirectories: true)
        try encoder.encode([record]).write(
            to: fixture.rootURL.appendingPathComponent("SetupJournal.json"),
            options: .atomic
        )
        let coordinator = fixture.coordinator()

        try await coordinator.recoverInterruptedSetups()

        #expect(!FileManager.default.fileExists(atPath: workspaceURL.path))
        #expect(FileManager.default.fileExists(atPath: fixture.sourceURL.path))
        #expect(try await coordinator.records().first?.state == .rolledBack)
    }

    @Test("Interrupted armed installation restores the vendor launch path")
    func recoversInterruptedInstalledBundle() async throws {
        let fixture = try SetupFixture()
        defer { fixture.remove() }
        let prepared = try await fixture.coordinator().setup(fixture.app)
        #expect(FileManager.default.fileExists(atPath: markerURL(in: fixture.sourceURL).path))

        var interrupted = prepared
        interrupted.state = .preparing(.installingManaged)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        try encoder.encode([interrupted]).write(
            to: fixture.rootURL.appendingPathComponent("SetupJournal.json"),
            options: .atomic
        )

        let coordinator = fixture.coordinator()
        try await coordinator.recoverInterruptedSetups()

        #expect(!FileManager.default.fileExists(atPath: markerURL(in: fixture.sourceURL).path))
        #expect(try Data(contentsOf: fixture.sourceTokenURL) == Data("version-one".utf8))
        #expect(try await coordinator.records().first?.state == .rolledBack)
    }

    @Test("A failed signing step rolls back and leaves a durable failure record")
    func signingFailureRollsBack() async throws {
        let fixture = try SetupFixture(signer: FailingFixtureSigner())
        defer { fixture.remove() }
        let coordinator = fixture.coordinator()

        do {
            _ = try await coordinator.setup(fixture.app)
            Issue.record("Setup unexpectedly succeeded.")
        } catch {
            #expect(error.localizedDescription.contains("deliberate signing failure"))
        }

        let record = try #require(try await coordinator.records().first)
        if case .failed(let detail) = record.state {
            #expect(detail.contains("deliberate signing failure"))
        } else {
            Issue.record("Expected a durable failed state, got \(record.state).")
        }
        #expect(!FileManager.default.fileExists(
            atPath: fixture.rootURL
                .appendingPathComponent("Workspaces")
                .appendingPathComponent(record.id.uuidString)
                .path
        ))
        #expect(FileManager.default.fileExists(atPath: fixture.sourceURL.path))
    }

    @Test("Managed signing is injectable and never recursively re-signs nested code")
    func signingCommandIsNarrow() throws {
        let runner = RecordingCommandRunner()
        let signer = MacManagedBundleSigner(runner: runner)
        let bundleURL = URL(fileURLWithPath: "/tmp/Managed.app")
        let entitlementsURL = URL(fileURLWithPath: "/tmp/ManagedAttach.entitlements")

        try signer.sign(bundleURL: bundleURL, entitlementsURL: entitlementsURL)

        let invocation = try #require(runner.invocation())
        #expect(invocation.executableURL.path == "/usr/bin/codesign")
        #expect(invocation.arguments == [
            "--force", "--sign", "-", "--entitlements",
            entitlementsURL.path, bundleURL.path
        ])
        #expect(!invocation.arguments.contains("--deep"))
    }

    private func markerURL(in bundleURL: URL) -> URL {
        bundleURL
            .appendingPathComponent("Contents")
            .appendingPathComponent("Resources")
            .appendingPathComponent("Continuum")
            .appendingPathComponent("ManagedSetup.json")
    }
}

private struct SetupFixture {
    let parentURL: URL
    let rootURL: URL
    let sourceURL: URL
    let sourceTokenURL: URL
    let bootstrapURL: URL
    let app: AppIdentity
    let blockers: [AppSetupBlocker]
    let signer: any ManagedBundleSigning

    init(
        blockers: [AppSetupBlocker] = [],
        signer: any ManagedBundleSigning = FixtureSigner()
    ) throws {
        let parentURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("ContinuumAppSetupTests-\(UUID().uuidString)", isDirectory: true)
        let sourceURL = parentURL.appendingPathComponent("Vendor.app", isDirectory: true)
        let contentsURL = sourceURL.appendingPathComponent("Contents", isDirectory: true)
        let executableURL = contentsURL
            .appendingPathComponent("MacOS", isDirectory: true)
            .appendingPathComponent("Fixture", isDirectory: false)
        try FileManager.default.createDirectory(
            at: executableURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        #expect(FileManager.default.createFile(atPath: executableURL.path, contents: Data("fixture".utf8)))
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: executableURL.path)

        let info: [String: Any] = [
            "CFBundleExecutable": "Fixture",
            "CFBundleIdentifier": "dev.continuum.generic-fixture",
            "CFBundleName": "Generic Fixture",
            "CFBundleShortVersionString": "1.0"
        ]
        let infoData = try PropertyListSerialization.data(fromPropertyList: info, format: .binary, options: 0)
        try infoData.write(to: contentsURL.appendingPathComponent("Info.plist"), options: .atomic)
        let tokenURL = contentsURL.appendingPathComponent("fixture-token")
        try Data("version-one".utf8).write(to: tokenURL, options: .atomic)
        let bootstrapURL = parentURL.appendingPathComponent("libContinuumBootstrap.dylib")
        try Data("fixture-bootstrap".utf8).write(to: bootstrapURL, options: .atomic)

        self.parentURL = parentURL
        self.rootURL = parentURL.appendingPathComponent("ContinuumData", isDirectory: true)
        self.sourceURL = sourceURL
        self.sourceTokenURL = tokenURL
        self.bootstrapURL = bootstrapURL
        self.app = AppIdentity(
            bundleIdentifier: "dev.continuum.generic-fixture",
            displayName: "Generic Fixture",
            bundleURL: sourceURL,
            executableURL: executableURL,
            version: "1.0",
            signingIdentifier: nil,
            teamIdentifier: nil,
            isApplePlatformBinary: false
        )
        self.blockers = blockers
        self.signer = signer
    }

    func coordinator() -> MacAppSetupCoordinator {
        MacAppSetupCoordinator(
            rootProvider: FixedAppSetupRoot(rootDirectory: rootURL),
            fileSystem: LocalAppSetupFileSystem(),
            probeService: FixtureProbe(sourceURL: sourceURL, blockers: blockers),
            signer: signer,
            bootstrapLibraryURL: bootstrapURL,
            now: { Date(timeIntervalSince1970: 1_800_000_000) }
        )
    }

    func remove() {
        try? FileManager.default.removeItem(at: parentURL)
    }
}

private struct FixtureProbe: AppSetupProbing {
    let sourceURL: URL
    let blockers: [AppSetupBlocker]

    func inspect(bundleURL: URL, declaredIdentity: AppIdentity?) throws -> AppSetupProbeResult {
        let contentsURL = bundleURL.appendingPathComponent("Contents")
        let tokenURL = contentsURL.appendingPathComponent("fixture-token")
        let executableURL = contentsURL.appendingPathComponent("MacOS/Fixture")
        guard let token = String(data: try Data(contentsOf: tokenURL), encoding: .utf8) else {
            throw AppSetupError.invalidBundle("fixture token is unreadable")
        }
        let isManagedSigned = FileManager.default.fileExists(
            atPath: bundleURL.appendingPathComponent(".continuum-test-signed").path
        )
        let identity = AppIdentity(
            bundleIdentifier: "dev.continuum.generic-fixture",
            displayName: "Generic Fixture",
            bundleURL: bundleURL,
            executableURL: executableURL,
            version: token,
            signingIdentifier: isManagedSigned ? "dev.continuum.generic-fixture" : nil,
            teamIdentifier: nil,
            isApplePlatformBinary: false
        )
        return AppSetupProbeResult(
            identity: identity,
            fingerprint: Self.fingerprint(token: isManagedSigned ? "managed-\(token)" : token),
            blockers: bundleURL.standardizedFileURL == sourceURL.standardizedFileURL ? blockers : [],
            isSigned: isManagedSigned,
            isAdHocSigned: isManagedSigned,
            signatureValid: isManagedSigned,
            hasAttachEntitlement: isManagedSigned
        )
    }

    static func fingerprint(token: String) -> AppFingerprint {
        AppFingerprint(
            bundleIdentifier: "dev.continuum.generic-fixture",
            bundleVersion: token,
            executableSHA256: "executable-\(token)",
            infoPlistSHA256: "plist-\(token)",
            bundleContentSHA256: "bundle-\(token)",
            signingIdentifier: nil,
            teamIdentifier: nil,
            isAdHocSigned: false
        )
    }
}

private struct FixtureSigner: ManagedBundleSigning {
    func sign(bundleURL: URL, entitlementsURL: URL) throws {
        let data = try Data(contentsOf: entitlementsURL)
        var format = PropertyListSerialization.PropertyListFormat.binary
        let raw = try PropertyListSerialization.propertyList(
            from: data,
            options: [],
            format: &format
        )
        guard let entitlements = raw as? [String: Any],
              entitlements["com.apple.security.get-task-allow"] as? Bool == true,
              format == .xml else {
            throw AppSetupError.operationFailed("test signer did not receive get-task-allow")
        }
        try Data("signed".utf8).write(
            to: bundleURL.appendingPathComponent(".continuum-test-signed"),
            options: .atomic
        )
    }
}

private struct FailingFixtureSigner: ManagedBundleSigning {
    func sign(bundleURL: URL, entitlementsURL: URL) throws {
        throw AppSetupError.operationFailed("deliberate signing failure")
    }
}

private final class RecordingCommandRunner: AppSetupCommandRunning, @unchecked Sendable {
    struct Invocation {
        let executableURL: URL
        let arguments: [String]
    }

    private let lock = NSLock()
    private var recordedInvocation: Invocation?

    func run(executableURL: URL, arguments: [String]) throws -> AppSetupCommandResult {
        lock.lock()
        recordedInvocation = Invocation(executableURL: executableURL, arguments: arguments)
        lock.unlock()
        return AppSetupCommandResult(
            terminationStatus: 0,
            standardOutput: Data(),
            standardError: Data()
        )
    }

    func invocation() -> Invocation? {
        lock.lock()
        defer { lock.unlock() }
        return recordedInvocation
    }
}
