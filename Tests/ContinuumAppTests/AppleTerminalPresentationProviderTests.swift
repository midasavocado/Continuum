import Foundation
import Testing
@testable import ContinuumApp

@Suite("Apple Terminal managed shell", .serialized)
struct AppleTerminalPresentationProviderTests {
    @Test("Matching source bytes reuse the managed shell path and inode")
    func matchingSourceReusesManagedShell() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }

        let first = try fixture.prepare()
        let firstInode = try inode(of: first)
        let second = try fixture.prepare()

        #expect(first == second)
        #expect(try inode(of: second) == firstInode)
        #expect(fixture.signCount == 1)
    }

    @Test("Changed source bytes create a new path and retain the old shell")
    func changedSourceRetainsPriorManagedShell() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }

        let first = try fixture.prepare()
        try Data("second shell".utf8).write(to: fixture.source)
        let second = try fixture.prepare()

        #expect(first != second)
        #expect(FileManager.default.fileExists(atPath: first.path))
        #expect(FileManager.default.fileExists(atPath: second.path))
        #expect(try Data(contentsOf: first) == Data("first shell".utf8))
        #expect(try Data(contentsOf: second) == Data("second shell".utf8))
    }

    @Test("Command wrappers reserve the generic service supervisor entry point")
    func serviceSupervisorWrapperIsReserved() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("ContinuumCommandWrapperTests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let commands = root.appendingPathComponent("commands", isDirectory: true)
        try FileManager.default.createDirectory(at: commands, withIntermediateDirectories: true)
        let helper = root.appendingPathComponent("ContinuumManagedExec")

        let wrappers = try AppleTerminalPresentationProvider.prepareCommandWrappers(
            managedExecURL: helper,
            originalPath: commands.path,
            base: root,
            fallbackDirectories: []
        )
        let wrapper = wrappers.appendingPathComponent("continuum-with-service")
        let script = try String(contentsOf: wrapper, encoding: .utf8)
        let permissions = try #require(
            FileManager.default.attributesOfItem(atPath: wrapper.path)[.posixPermissions] as? NSNumber
        )

        #expect(script.contains("--continuum-with-service \"$@\""))
        #expect(permissions.intValue & 0o700 == 0o700)
    }

    @Test("Fallback-only commands use the same effective original PATH as wrapper discovery")
    func fallbackCommandUsesEffectiveOriginalPath() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("ContinuumFallbackPathTests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let inherited = root.appendingPathComponent("inherited", isDirectory: true)
        let fallback = root.appendingPathComponent("fallback", isDirectory: true)
        try FileManager.default.createDirectory(at: inherited, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: fallback, withIntermediateDirectories: true)
        let fallbackCommand = fallback.appendingPathComponent("fallback-only")
        try FileManager.default.copyItem(
            at: URL(fileURLWithPath: "/usr/bin/true"),
            to: fallbackCommand
        )

        let originalPath = AppleTerminalPresentationProvider.effectiveOriginalPath(
            inheritedPath: ".:relative:\(inherited.path):../bin:\(inherited.path)",
            fallbackDirectories: ["fallback-relative", fallback.path, inherited.path]
        )
        #expect(originalPath == "\(inherited.path):\(fallback.path)")

        let wrappers = try AppleTerminalPresentationProvider.prepareCommandWrappers(
            managedExecURL: root.appendingPathComponent("ContinuumManagedExec"),
            originalPath: originalPath,
            base: root,
            fallbackDirectories: []
        )
        let script = try String(
            contentsOf: wrappers.appendingPathComponent("fallback-only"),
            encoding: .utf8
        )
        #expect(script.contains(fallbackCommand.path))
        #expect(
            AppleTerminalPresentationProvider.terminalPathEnvironment(
                wrappers: wrappers,
                originalPath: originalPath
            ) == [
                "CONTINUUM_ORIGINAL_PATH=\(originalPath)",
                "PATH=\(wrappers.path):\(originalPath)"
            ]
        )
    }

    private func inode(of url: URL) throws -> UInt64 {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        return try #require(attributes[.systemFileNumber] as? UInt64)
    }

    private final class Fixture {
        let root: URL
        let source: URL
        let managedShells: URL
        var signCount = 0

        init() throws {
            root = FileManager.default.temporaryDirectory
                .appendingPathComponent("ContinuumManagedShellTests-\(UUID().uuidString)")
            source = root.appendingPathComponent("source-zsh")
            managedShells = root.appendingPathComponent("managed", isDirectory: true)
            try FileManager.default.createDirectory(
                at: root,
                withIntermediateDirectories: true
            )
            try Data("first shell".utf8).write(to: source)
        }

        func prepare() throws -> URL {
            try AppleTerminalPresentationProvider.prepareManagedShell(
                source: source,
                base: managedShells
            ) { _ in
                self.signCount += 1
            }
        }

        func remove() {
            try? FileManager.default.removeItem(at: root)
        }
    }
}
