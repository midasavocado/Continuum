import Foundation
import Testing
@testable import ContinuumSystem
import ContinuumCore

@Suite("macOS app inventory")
struct AppInventoryTests {
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
