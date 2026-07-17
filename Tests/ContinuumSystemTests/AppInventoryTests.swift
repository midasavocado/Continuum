import Foundation
import Testing
@testable import ContinuumSystem
import ContinuumCore

@Suite("macOS app inventory")
struct AppInventoryTests {
    @Test("Resolves one selected terminal session without capturing the emulator")
    func resolvesTerminalWorkload() {
        let root = MacAppInventoryService.terminalWorkloadRoot(
            descendants: [110, 111, 112, 210],
            sessions: [110: 110, 111: 110, 112: 110, 210: 210],
            terminalDevices: [110: 7, 111: 7, 112: 7, 210: 8],
            selectedTerminalDevice: 7
        )

        #expect(root == 110)
    }

    @Test("Keeps the shell as root while including its foreground job")
    func resolvesShellRootWithForegroundTerminalJob() {
        let terminalProcessIdentifier: Int32 = 80
        let descendants: Set<Int32> = [110, 211, 212]
        let sessions: [Int32: Int32] = [110: 110, 211: 110, 212: 110]
        let processGroups: [Int32: Int32] = [110: 110, 211: 211, 212: 211]
        let foregroundProcessGroups: [Int32: Int32] = [110: 211, 211: 211, 212: 211]
        let root = MacAppInventoryService.terminalWorkloadRoot(
            descendants: descendants,
            sessions: sessions,
            terminalDevices: [110: 7, 211: 7, 212: 7],
            processGroups: processGroups,
            foregroundProcessGroups: foregroundProcessGroups,
            selectedTerminalDevice: 7
        )

        #expect(root == 110)
        #expect(descendants.contains(211))
        #expect(processGroups[211] == foregroundProcessGroups[110])
        #expect(sessions[211] == root)
        #expect(!descendants.contains(terminalProcessIdentifier))
    }

    @Test("Pairs only established loopback TCP peers")
    func parsesLoopbackPeers() {
        let output = """
        p410
        f7
        n127.0.0.1:55123->127.0.0.1:11434
        p420
        f9
        n127.0.0.1:11434->127.0.0.1:55123
        p430
        f3
        n192.168.1.10:50000->1.1.1.1:443
        """

        let connections = MacAppInventoryService.parseLoopbackConnections(output)

        #expect(connections.count == 2)
        #expect(Set(connections.map(\.processIdentifier)) == [410, 420])
    }

    @Test("Adds a same-user peer's complete launch tree as a capture root")
    func expandsPeerProcessTree() {
        let roots = MacAppInventoryService.dependencyRoots(
            rootProcessIdentifier: 100,
            selectedUserIdentifier: 501,
            parents: [
                100: 1,
                101: 100,
                190: 1,
                200: 190,
                201: 200
            ],
            userIdentifiers: [
                100: 501,
                101: 501,
                190: 501,
                200: 501,
                201: 501
            ],
            sessions: [
                100: 100,
                101: 100,
                190: 190,
                200: 190,
                201: 190
            ],
            connections: [
                LoopbackConnection(
                    processIdentifier: 101,
                    localEndpoint: "127.0.0.1:55123",
                    remoteEndpoint: "127.0.0.1:11434"
                ),
                LoopbackConnection(
                    processIdentifier: 200,
                    localEndpoint: "127.0.0.1:11434",
                    remoteEndpoint: "127.0.0.1:55123"
                )
            ]
        )

        #expect(roots == [100, 190])
    }

    @Test("Does not absorb a terminal emulator across a session boundary")
    func stopsPeerRootAtSessionLeader() {
        let roots = MacAppInventoryService.dependencyRoots(
            rootProcessIdentifier: 100,
            selectedUserIdentifier: 501,
            parents: [100: 90, 200: 190, 190: 80, 80: 1],
            userIdentifiers: [80: 501, 90: 501, 100: 501, 190: 501, 200: 501],
            sessions: [80: 80, 90: 90, 100: 90, 190: 190, 200: 190],
            connections: [
                LoopbackConnection(
                    processIdentifier: 100,
                    localEndpoint: "127.0.0.1:55123",
                    remoteEndpoint: "127.0.0.1:11434"
                ),
                LoopbackConnection(
                    processIdentifier: 200,
                    localEndpoint: "127.0.0.1:11434",
                    remoteEndpoint: "127.0.0.1:55123"
                )
            ]
        )

        #expect(roots == [100, 190])
    }

    @Test("Expands transitively across same-user Unix sockets and pipes")
    func expandsKernelPeerForest() {
        let roots = MacAppInventoryService.dependencyRoots(
            rootProcessIdentifier: 100,
            selectedUserIdentifier: 501,
            parents: [100: 1, 200: 190, 190: 1, 300: 290, 290: 1],
            userIdentifiers: [100: 501, 190: 501, 200: 501, 290: 501, 300: 501],
            sessions: [100: 100, 190: 190, 200: 190, 290: 290, 300: 290],
            connections: [],
            kernelPeers: [
                KernelPeerEndpoint(
                    processIdentifier: 100,
                    kind: .unixSocket,
                    localHandle: 11,
                    peerHandle: 22
                ),
                KernelPeerEndpoint(
                    processIdentifier: 200,
                    kind: .unixSocket,
                    localHandle: 22,
                    peerHandle: 11
                ),
                KernelPeerEndpoint(
                    processIdentifier: 200,
                    kind: .pipe,
                    localHandle: 33,
                    peerHandle: 44
                ),
                KernelPeerEndpoint(
                    processIdentifier: 300,
                    kind: .pipe,
                    localHandle: 44,
                    peerHandle: 33
                )
            ]
        )

        #expect(roots == [100, 190, 290])
    }

    @Test("Does not absorb a different-user kernel peer")
    func rejectsDifferentUserKernelPeer() {
        let roots = MacAppInventoryService.dependencyRoots(
            rootProcessIdentifier: 100,
            selectedUserIdentifier: 501,
            parents: [100: 1, 900: 1],
            userIdentifiers: [100: 501, 900: 0],
            connections: [],
            kernelPeers: [
                KernelPeerEndpoint(
                    processIdentifier: 100,
                    kind: .unixSocket,
                    localHandle: 11,
                    peerHandle: 22
                ),
                KernelPeerEndpoint(
                    processIdentifier: 900,
                    kind: .unixSocket,
                    localHandle: 22,
                    peerHandle: 11
                )
            ]
        )

        #expect(roots == [100])
    }

    @Test("Fails closed when a kernel peer identity is ambiguous")
    func rejectsAmbiguousKernelPeer() {
        let roots = MacAppInventoryService.dependencyRoots(
            rootProcessIdentifier: 100,
            selectedUserIdentifier: 501,
            parents: [100: 1, 200: 1, 300: 1],
            userIdentifiers: [100: 501, 200: 501, 300: 501],
            connections: [],
            kernelPeers: [
                KernelPeerEndpoint(
                    processIdentifier: 100,
                    kind: .pipe,
                    localHandle: 11,
                    peerHandle: 22
                ),
                KernelPeerEndpoint(
                    processIdentifier: 200,
                    kind: .pipe,
                    localHandle: 22,
                    peerHandle: 11
                ),
                KernelPeerEndpoint(
                    processIdentifier: 300,
                    kind: .pipe,
                    localHandle: 22,
                    peerHandle: 11
                )
            ]
        )

        #expect(roots == [100])
    }

    @Test("Parses a fixture app without reading its documents")
    func parsesFixtureMetadata() throws {
        let fixture = try FixtureApp(
            displayName: "Orbit Lab",
            bundleIdentifier: "dev.continuum.orbit-lab",
            version: "2.4.1"
        )
        defer { fixture.remove() }

        let inspected = AppBundleInspector().inspect(bundleURL: fixture.bundleURL)

        #expect(inspected?.identity.displayName == "Orbit Lab")
        #expect(inspected?.identity.bundleIdentifier == "dev.continuum.orbit-lab")
        #expect(inspected?.identity.version == "2.4.1")
        #expect(inspected?.identity.executableURL == fixture.executableURL)
        #expect(inspected?.identity.signingIdentifier == nil)
    }

    @Test("Finds app bundles below configured installation roots")
    func enumeratesConfiguredRoot() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let fixture = try FixtureApp(parentDirectory: directory, displayName: "Timeline")
        let service = MacAppInventoryService(applicationDirectories: [directory])
        let apps = await service.installedApplications()

        #expect(apps.map(\.displayName) == ["Timeline"])
        #expect(apps.first?.bundleURL == fixture.bundleURL)
    }

    @Test("Finds top-level app symlinks such as the system Safari bundle")
    func enumeratesSymlinkedApp() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let targetParent = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let fixture = try FixtureApp(parentDirectory: targetParent, displayName: "Cryptex Browser")
        defer {
            try? FileManager.default.removeItem(at: root)
            fixture.remove()
        }
        let link = root.appendingPathComponent("Browser.app", isDirectory: true)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: fixture.bundleURL)

        let apps = await MacAppInventoryService(applicationDirectories: [root]).installedApplications()

        #expect(apps.count == 1)
        #expect(apps.first?.displayName == "Cryptex Browser")
        #expect(apps.first?.bundleURL == link)
    }

    @Test("Resolves an explicitly selected app or standalone executable")
    func resolvesExplicitWindowTarget() async throws {
        let fixture = try FixtureApp(displayName: "Window Target")
        defer { fixture.remove() }
        let service = MacAppInventoryService(applicationDirectories: [])

        let bundled = await service.application(at: fixture.executableURL)
        #expect(bundled?.bundleURL == fixture.bundleURL)
        #expect(bundled?.displayName == "Window Target")

        let executable = fixture.parentDirectory.appendingPathComponent("Standalone Window")
        #expect(FileManager.default.createFile(atPath: executable.path, contents: Data([0])))
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755],
            ofItemAtPath: executable.path
        )

        let standalone = await service.application(at: executable)
        #expect(standalone?.bundleURL == nil)
        #expect(standalone?.displayName == "Standalone Window")
        #expect(standalone?.executableURL == executable)
    }

    @Test("Classifies a bundle-adjacent plug-in directory generically")
    func detectsPluginOpportunity() throws {
        let fixture = try FixtureApp(displayName: "Physics Game")
        defer { fixture.remove() }
        let gameData = fixture.parentDirectory.appendingPathComponent("GameData", isDirectory: true)
        try FileManager.default.createDirectory(at: gameData, withIntermediateDirectories: true)

        let inspected = try #require(AppBundleInspector().inspect(bundleURL: fixture.bundleURL))
        let report = AppCompatibilityClassifier().report(for: inspected.identity)

        #expect(report.tier == .directPlugin)
        #expect(report.canCaptureNow == false)
        #expect(report.canRestoreNow == false)
        #expect(report.explanation.contains("certify"))
    }

    @Test("Treats an unsigned ordinary app as launch-injection candidate, not certified")
    func classifiesUnsignedAppConservatively() throws {
        let fixture = try FixtureApp(displayName: "Unsigned Lab")
        defer { fixture.remove() }

        let inspected = try #require(AppBundleInspector().inspect(bundleURL: fixture.bundleURL))
        let report = AppCompatibilityClassifier().report(for: inspected.identity)

        #expect(report.tier == .launchInjection)
        #expect(report.canCaptureNow == false)
        #expect(report.canRestoreNow == false)
    }

    @Test("Never proposes re-signing an Apple platform app")
    func protectsPlatformApp() throws {
        let fixture = try FixtureApp(displayName: "Platform Fixture")
        defer { fixture.remove() }
        let inspected = try #require(AppBundleInspector().inspect(bundleURL: fixture.bundleURL))
        let protectedIdentity = AppIdentity(
            bundleIdentifier: inspected.identity.bundleIdentifier,
            displayName: inspected.identity.displayName,
            bundleURL: inspected.identity.bundleURL,
            executableURL: inspected.identity.executableURL,
            version: inspected.identity.version,
            signingIdentifier: inspected.identity.signingIdentifier,
            teamIdentifier: inspected.identity.teamIdentifier,
            isApplePlatformBinary: true
        )

        let report = AppCompatibilityClassifier().report(for: protectedIdentity)

        #expect(report.tier == .protectedBridge)
        #expect(report.explanation.contains("platform app"))
    }
}

private struct FixtureApp {
    let parentDirectory: URL
    let bundleURL: URL
    let executableURL: URL

    init(
        parentDirectory: URL? = nil,
        displayName: String,
        bundleIdentifier: String = "dev.continuum.fixture",
        version: String = "1.0"
    ) throws {
        let parent = parentDirectory ?? FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let bundle = parent.appendingPathComponent("\(displayName).app", isDirectory: true)
        let contents = bundle.appendingPathComponent("Contents", isDirectory: true)
        let macOS = contents.appendingPathComponent("MacOS", isDirectory: true)
        try FileManager.default.createDirectory(at: macOS, withIntermediateDirectories: true)

        let executable = macOS.appendingPathComponent("Fixture", isDirectory: false)
        #expect(FileManager.default.createFile(atPath: executable.path, contents: Data([0])))
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755],
            ofItemAtPath: executable.path
        )

        let plist: [String: Any] = [
            "CFBundleDisplayName": displayName,
            "CFBundleExecutable": "Fixture",
            "CFBundleIdentifier": bundleIdentifier,
            "CFBundleShortVersionString": version
        ]
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .binary, options: 0)
        try data.write(to: contents.appendingPathComponent("Info.plist"), options: .atomic)

        self.parentDirectory = parent
        self.bundleURL = bundle
        self.executableURL = executable
    }

    func remove() {
        try? FileManager.default.removeItem(at: parentDirectory)
    }
}
