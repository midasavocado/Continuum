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
