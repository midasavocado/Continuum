import Darwin
import Foundation
import XCTest

final class ContinuumManagedExecTests: XCTestCase {
    func testCopiesSignsAndExecutesMachOWithoutChangingSource() throws {
        let temporary = FileManager.default.temporaryDirectory
            .appendingPathComponent("ContinuumManagedExecTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: temporary) }

        let source = temporary.appendingPathComponent("fixture.c")
        let executable = temporary.appendingPathComponent("fixture")
        try Self.fixtureSource.write(to: source, atomically: true, encoding: .utf8)
        try run("/usr/bin/clang", [source.path, "-o", executable.path])
        let originalBytes = try Data(contentsOf: executable)

        let workingDirectory = temporary.appendingPathComponent("working", isDirectory: true)
        try FileManager.default.createDirectory(at: workingDirectory, withIntermediateDirectories: false)
        let output = try run(
            Self.productsDirectory.appendingPathComponent("ContinuumManagedExec").path,
            [executable.path, "hello", "continuum"],
            currentDirectory: workingDirectory,
            environment: ["CONTINUUM_TEST_MARKER": "preserved"]
        )
        let fields = output.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        XCTAssertEqual(fields.count, 6)
        XCTAssertEqual(fields[0], executable.path)
        XCTAssertEqual(fields[1], "hello")
        XCTAssertEqual(fields[2], "continuum")
        XCTAssertEqual(fields[3], "preserved")
        XCTAssertEqual(
            URL(fileURLWithPath: fields[4]).resolvingSymlinksInPath().path,
            workingDirectory.resolvingSymlinksInPath().path
        )
        XCTAssertEqual(try Data(contentsOf: executable), originalBytes)

        let managedExecutable = URL(fileURLWithPath: fields[5])
        addTeardownBlock {
            try? FileManager.default.removeItem(at: managedExecutable.deletingLastPathComponent())
        }
        XCTAssertTrue(managedExecutable.path.contains("/Library/Application Support/Continuum/ManagedExecutables/"))
        XCTAssertNotEqual(managedExecutable.path, executable.path)
        XCTAssertNoThrow(try run("/usr/bin/codesign", ["--verify", "--strict", managedExecutable.path]))

        let reusedOutput = try run(
            Self.productsDirectory.appendingPathComponent("ContinuumManagedExec").path,
            [executable.path, "hello", "continuum"],
            currentDirectory: workingDirectory,
            environment: ["CONTINUUM_TEST_MARKER": "preserved"]
        )
        let reusedFields = reusedOutput.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        XCTAssertEqual(reusedFields.last, managedExecutable.path)
    }

    func testRejectsSymlinkSource() throws {
        let temporary = FileManager.default.temporaryDirectory
            .appendingPathComponent("ContinuumManagedExecSymlinkTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: temporary) }
        let link = temporary.appendingPathComponent("echo")
        try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: "/bin/echo")

        XCTAssertThrowsError(try run(
            Self.productsDirectory.appendingPathComponent("ContinuumManagedExec").path,
            [link.path]
        ))
    }

    private static let fixtureSource = #"""
    #include <mach-o/dyld.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>
    int main(int argc, char **argv) {
        char cwd[4096];
        char executable[4096];
        uint32_t executable_size = sizeof(executable);
        if (argc != 3 || getcwd(cwd, sizeof(cwd)) == NULL ||
            _NSGetExecutablePath(executable, &executable_size) != 0) return 71;
        printf("%s\n%s\n%s\n%s\n%s\n%s", argv[0], argv[1], argv[2],
               getenv("CONTINUUM_TEST_MARKER"), cwd, executable);
        return 0;
    }
    """#

    private static var productsDirectory: URL {
        Bundle.allBundles.first(where: { $0.bundleURL.pathExtension == "xctest" })!
            .bundleURL.deletingLastPathComponent()
    }

    @discardableResult
    private func run(
        _ executable: String,
        _ arguments: [String],
        currentDirectory: URL? = nil,
        environment additions: [String: String] = [:]
    ) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.currentDirectoryURL = currentDirectory
        process.environment = ProcessInfo.processInfo.environment.merging(additions) { _, new in new }
        let output = Pipe()
        let error = Pipe()
        process.standardOutput = output
        process.standardError = error
        try process.run()
        process.waitUntilExit()
        let stdout = output.fileHandleForReading.readDataToEndOfFile()
        let stderr = error.fileHandleForReading.readDataToEndOfFile()
        guard process.terminationReason == .exit, process.terminationStatus == 0 else {
            throw NSError(domain: "ContinuumManagedExecTests", code: Int(process.terminationStatus), userInfo: [
                NSLocalizedDescriptionKey: String(decoding: stderr, as: UTF8.self)
            ])
        }
        return String(decoding: stdout, as: UTF8.self)
    }
}
