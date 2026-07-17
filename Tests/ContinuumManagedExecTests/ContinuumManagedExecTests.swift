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
        try Self.run("/usr/bin/clang", [source.path, "-o", executable.path])
        let originalBytes = try Data(contentsOf: executable)

        let workingDirectory = temporary.appendingPathComponent("working", isDirectory: true)
        try FileManager.default.createDirectory(at: workingDirectory, withIntermediateDirectories: false)
        let output = try Self.run(
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
        XCTAssertNoThrow(try Self.run("/usr/bin/codesign", ["--verify", "--strict", managedExecutable.path]))

        let reusedOutput = try Self.run(
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

        XCTAssertThrowsError(try Self.run(
            Self.productsDirectory.appendingPathComponent("ContinuumManagedExec").path,
            [link.path]
        ))
    }

    func testServiceModeRejectsMalformedGrammarBeforeLaunchingAnything() throws {
        let helper = Self.productsDirectory.appendingPathComponent("ContinuumManagedExec").path
        let cases = [
            ["--continuum-with-service"],
            ["--continuum-with-service", "--ready-unix", "/tmp/example", "--", "service"],
            ["--continuum-with-service", "--ready-unix", "/tmp/example", "--ready-tcp", "127.0.0.1:1", "--", "service", ":::", "client"],
            ["--continuum-with-service", "--env", "NOT-VALID=value", "--ready-unix", "/tmp/example", "--", "service", ":::", "client"],
            ["--continuum-with-service", "--ready-tcp", "127.0.0.1:70000", "--", "service", ":::", "client"]
        ]

        for arguments in cases {
            let result = try runResult(helper, arguments)
            XCTAssertNotEqual(result.status, 0, "unexpected success for \(arguments)")
        }
    }

    func testServiceModeRefusesAnOccupiedTCPEndpointBeforeServiceLaunch() throws {
        let fixture = try ServiceFixture()
        defer { fixture.remove() }
        let listener = socket(AF_INET, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(listener, 0)
        defer { Darwin.close(listener) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        address.sin_port = 0
        let bindResult = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        XCTAssertEqual(bindResult, 0)
        XCTAssertEqual(Darwin.listen(listener, 4), 0)
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        XCTAssertEqual(withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(listener, $0, &length)
            }
        }, 0)
        let endpoint = "127.0.0.1:\(UInt16(bigEndian: address.sin_port))"

        let result = try fixture.run([
            "--ready-tcp", endpoint,
            "--", "service-fixture", fixture.socket.path, fixture.serviceRecord.path,
            ":::", "client-fixture", fixture.socket.path, fixture.clientRecord.path, "exit"
        ])
        XCTAssertEqual(result.status, 69)
        XCTAssertTrue(result.stderr.contains("already live"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.serviceRecord.path))
    }

    func testServiceModeUsesOriginalPathAndPropagatesEnvironmentCWDAndTopology() throws {
        let fixture = try ServiceFixture()
        defer { fixture.remove() }

        let result = try fixture.run([
            "--env", "OVERLAY_MARKER=overlaid",
            "--ready-unix", fixture.socket.path,
            "--", "service-fixture", fixture.socket.path, fixture.serviceRecord.path,
            ":::", "client-fixture", fixture.socket.path, fixture.clientRecord.path, "exit"
        ])
        XCTAssertEqual(result.status, 23, result.stderr)

        let service = try fixture.fields(at: fixture.serviceRecord)
        let client = try fixture.fields(at: fixture.clientRecord)
        XCTAssertEqual(service[3], fixture.workingDirectory.path)
        XCTAssertEqual(client[3], fixture.workingDirectory.path)
        XCTAssertEqual(service[4], "overlaid")
        XCTAssertEqual(client[4], "overlaid")
        XCTAssertEqual(service[5], "inherited")
        XCTAssertEqual(client[5], "inherited")
        XCTAssertEqual(service[6], "bootstrap-value")
        XCTAssertEqual(client[6], "bootstrap-value")

        let servicePID = try XCTUnwrap(pid_t(service[0]))
        let clientPID = try XCTUnwrap(pid_t(client[0]))
        let serviceParent = try XCTUnwrap(pid_t(service[1]))
        let clientParent = try XCTUnwrap(pid_t(client[1]))
        XCTAssertEqual(serviceParent, clientParent)
        XCTAssertEqual(try XCTUnwrap(pid_t(service[2])), servicePID)
        XCTAssertEqual(try XCTUnwrap(pid_t(client[2])), clientPID)
        XCTAssertTrue(service[7].contains("/Library/Application Support/Continuum/ManagedExecutables/"))
        XCTAssertTrue(client[7].contains("/Library/Application Support/Continuum/ManagedExecutables/"))
        XCTAssertEqual(service[8], "service-fixture")
        XCTAssertEqual(client[8], "client-fixture")
        XCTAssertEqual(service[9], "default")
        XCTAssertEqual(client[9], "default")

        let workerPID = try XCTUnwrap(pid_t(service[10]))
        XCTAssertEqual(try XCTUnwrap(pid_t(service[11])), workerPID)
        XCTAssertNotEqual(try XCTUnwrap(pid_t(service[2])), workerPID)
        XCTAssertTrue(waitUntilProcessIsGone(servicePID))
        XCTAssertTrue(waitUntilProcessIsGone(clientPID))
        XCTAssertTrue(waitUntilProcessIsGone(workerPID))
    }

    func testSignalTerminatesAndReapsServiceClientAndServiceWorker() throws {
        let fixture = try ServiceFixture()
        defer { fixture.remove() }
        let process = fixture.process([
            "--ready-unix", fixture.socket.path,
            "--", "service-fixture", fixture.socket.path, fixture.serviceRecord.path,
            ":::", "client-fixture", fixture.socket.path, fixture.clientRecord.path, "wait"
        ])
        try process.run()
        XCTAssertTrue(waitForFile(fixture.clientRecord))
        let service = try fixture.fields(at: fixture.serviceRecord)
        let client = try fixture.fields(at: fixture.clientRecord)
        let servicePID = try XCTUnwrap(pid_t(service[0]))
        let clientPID = try XCTUnwrap(pid_t(client[0]))
        let workerPID = try XCTUnwrap(pid_t(service[10]))
        XCTAssertEqual(service[9], "default")
        XCTAssertEqual(client[9], "default")
        XCTAssertEqual(try XCTUnwrap(pid_t(service[11])), workerPID)

        XCTAssertEqual(Darwin.kill(process.processIdentifier, SIGTERM), 0)
        process.waitUntilExit()
        XCTAssertEqual(process.terminationReason, .exit)
        XCTAssertEqual(process.terminationStatus, 128 + SIGTERM)
        XCTAssertTrue(waitUntilProcessIsGone(servicePID))
        XCTAssertTrue(waitUntilProcessIsGone(clientPID))
        XCTAssertTrue(waitUntilProcessIsGone(workerPID))
    }

    func testServiceExitBeforeReadinessIsRejected() throws {
        let fixture = try ServiceFixture()
        defer { fixture.remove() }
        let result = try fixture.run([
            "--ready-unix", fixture.socket.path,
            "--", "client-fixture", fixture.socket.path, fixture.clientRecord.path, "exit",
            ":::", "client-fixture", fixture.socket.path, fixture.clientRecord.path, "exit"
        ])
        XCTAssertEqual(result.status, 69)
        XCTAssertTrue(result.stderr.contains("before readiness"))
    }

    func testDoubleForkedServiceIsPromptlyRejectedAndDetachedFixtureSelfCleans() throws {
        let fixture = try ServiceFixture()
        defer { fixture.remove() }
        let started = Date()
        let result = try fixture.run([
            "--ready-unix", fixture.socket.path,
            "--", "daemon-fixture", fixture.daemonRecord.path,
            ":::", "client-fixture", fixture.socket.path, fixture.clientRecord.path, "exit"
        ])

        XCTAssertEqual(result.status, 69)
        XCTAssertTrue(result.stderr.contains("daemonized before readiness"))
        XCTAssertTrue(result.stderr.contains("must remain in the foreground"))
        XCTAssertLessThan(Date().timeIntervalSince(started), 3)
        XCTAssertTrue(waitForFile(fixture.daemonRecord))
        let detachedPID = try XCTUnwrap(pid_t(
            String(contentsOf: fixture.daemonRecord, encoding: .utf8)
                .trimmingCharacters(in: .whitespacesAndNewlines)
        ))
        XCTAssertTrue(waitUntilProcessIsGone(detachedPID, timeout: 3))
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

    private struct ProcessResult {
        let status: Int32
        let stdout: String
        let stderr: String
    }

    private final class ServiceFixture {
        let root: URL
        let binaries: URL
        let workingDirectory: URL
        let socket: URL
        let serviceRecord: URL
        let clientRecord: URL
        let daemonRecord: URL
        let managedDirectories: [URL]

        init() throws {
            root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
                .appendingPathComponent("cms-\(UUID().uuidString.prefix(8))", isDirectory: true)
            binaries = root.appendingPathComponent("bin", isDirectory: true)
            workingDirectory = root.appendingPathComponent("working", isDirectory: true)
            socket = root.appendingPathComponent("ready.sock")
            serviceRecord = root.appendingPathComponent("service.txt")
            clientRecord = root.appendingPathComponent("client.txt")
            daemonRecord = root.appendingPathComponent("daemon.txt")
            try FileManager.default.createDirectory(at: binaries, withIntermediateDirectories: true)
            try FileManager.default.createDirectory(at: workingDirectory, withIntermediateDirectories: true)
            let serviceSource = root.appendingPathComponent("service.c")
            let clientSource = root.appendingPathComponent("client.c")
            let daemonSource = root.appendingPathComponent("daemon.c")
            try ContinuumManagedExecTests.serviceFixtureSource.write(to: serviceSource, atomically: true, encoding: .utf8)
            try ContinuumManagedExecTests.clientFixtureSource.write(to: clientSource, atomically: true, encoding: .utf8)
            try ContinuumManagedExecTests.daemonFixtureSource.write(to: daemonSource, atomically: true, encoding: .utf8)
            try ContinuumManagedExecTests.run(
                "/usr/bin/clang",
                [serviceSource.path, "-o", binaries.appendingPathComponent("service-fixture").path]
            )
            try ContinuumManagedExecTests.run(
                "/usr/bin/clang",
                [clientSource.path, "-o", binaries.appendingPathComponent("client-fixture").path]
            )
            try ContinuumManagedExecTests.run(
                "/usr/bin/clang",
                [daemonSource.path, "-o", binaries.appendingPathComponent("daemon-fixture").path]
            )
            let helper = ContinuumManagedExecTests.productsDirectory
                .appendingPathComponent("ContinuumManagedExec").path
            let serviceManaged = try ContinuumManagedExecTests.run(
                helper,
                [binaries.appendingPathComponent("service-fixture").path, "managed-path"]
            ).trimmingCharacters(in: .whitespacesAndNewlines)
            let clientManaged = try ContinuumManagedExecTests.run(
                helper,
                [binaries.appendingPathComponent("client-fixture").path, "managed-path"]
            ).trimmingCharacters(in: .whitespacesAndNewlines)
            let daemonManaged = try ContinuumManagedExecTests.run(
                helper,
                [binaries.appendingPathComponent("daemon-fixture").path, "managed-path"]
            ).trimmingCharacters(in: .whitespacesAndNewlines)
            managedDirectories = [serviceManaged, clientManaged, daemonManaged].map {
                URL(fileURLWithPath: $0).deletingLastPathComponent()
            }
        }

        func process(_ arguments: [String]) -> Process {
            let process = Process()
            process.executableURL = ContinuumManagedExecTests.productsDirectory
                .appendingPathComponent("ContinuumManagedExec")
            process.arguments = ["--continuum-with-service"] + arguments
            process.currentDirectoryURL = workingDirectory
            process.environment = ProcessInfo.processInfo.environment.merging([
                "PATH": "/path/that/must/not/be/used",
                "CONTINUUM_ORIGINAL_PATH": binaries.path,
                "INHERITED_MARKER": "inherited",
                "CONTINUUM_BOOTSTRAP_MARKER": "bootstrap-value"
            ]) { _, new in new }
            return process
        }

        func run(_ arguments: [String]) throws -> ProcessResult {
            let process = process(arguments)
            let output = Pipe()
            let error = Pipe()
            process.standardOutput = output
            process.standardError = error
            try process.run()
            process.waitUntilExit()
            return ProcessResult(
                status: process.terminationStatus,
                stdout: String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self),
                stderr: String(decoding: error.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            )
        }

        func fields(at url: URL) throws -> [String] {
            try String(contentsOf: url, encoding: .utf8)
                .split(separator: "\n", omittingEmptySubsequences: false)
                .map(String.init)
        }

        func remove() {
            try? FileManager.default.removeItem(at: root)
            for directory in managedDirectories {
                try? FileManager.default.removeItem(at: directory)
            }
        }
    }

    private static let serviceFixtureSource = #"""
    #include <mach-o/dyld.h>
    #include <signal.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <sys/socket.h>
    #include <sys/un.h>
    #include <unistd.h>
    static void stop(int signal_number) { (void)signal_number; _exit(0); }
    int main(int argc, char **argv) {
        if (argc == 2 && strcmp(argv[1], "managed-path") == 0) {
            char executable[4096];
            uint32_t executable_size = sizeof(executable);
            if (_NSGetExecutablePath(executable, &executable_size) != 0) return 70;
            puts(executable);
            return 0;
        }
        if (argc != 3) return 64;
        signal(SIGTERM, stop);
        signal(SIGINT, stop);
        int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un address = { .sun_family = AF_UNIX };
        if (descriptor < 0 || strlen(argv[1]) >= sizeof(address.sun_path)) return 71;
        strcpy(address.sun_path, argv[1]);
        unlink(argv[1]);
        if (bind(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0 || listen(descriptor, 8) != 0) return 72;
        pid_t worker = fork();
        if (worker < 0) return 73;
        if (worker == 0) {
            if (setsid() < 0) _exit(76);
            signal(SIGTERM, SIG_IGN);
            signal(SIGINT, SIG_IGN);
            for (;;) pause();
        }
        for (int attempt = 0; attempt < 100 && getpgid(worker) != worker; ++attempt) usleep(1000);
        char cwd[4096], executable[4096];
        uint32_t executable_size = sizeof(executable);
        if (getcwd(cwd, sizeof(cwd)) == NULL || _NSGetExecutablePath(executable, &executable_size) != 0) return 74;
        FILE *record = fopen(argv[2], "w");
        if (record == NULL) return 75;
        struct sigaction pipe_action;
        sigaction(SIGPIPE, NULL, &pipe_action);
        fprintf(record, "%ld\n%ld\n%ld\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%ld\n%ld\n",
                (long)getpid(), (long)getppid(), (long)getpgrp(), cwd,
                getenv("OVERLAY_MARKER"), getenv("INHERITED_MARKER"),
                getenv("CONTINUUM_BOOTSTRAP_MARKER"), executable, argv[0],
                pipe_action.sa_handler == SIG_DFL ? "default" : "not-default",
                (long)worker, (long)getpgid(worker));
        fclose(record);
        for (;;) {
            int connection = accept(descriptor, NULL, NULL);
            if (connection >= 0) close(connection);
        }
    }
    """#

    private static let clientFixtureSource = #"""
    #include <mach-o/dyld.h>
    #include <signal.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <sys/socket.h>
    #include <sys/un.h>
    #include <unistd.h>
    int main(int argc, char **argv) {
        if (argc == 2 && strcmp(argv[1], "managed-path") == 0) {
            char executable[4096];
            uint32_t executable_size = sizeof(executable);
            if (_NSGetExecutablePath(executable, &executable_size) != 0) return 70;
            puts(executable);
            return 0;
        }
        if (argc != 4) return 64;
        int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un address = { .sun_family = AF_UNIX };
        if (descriptor < 0 || strlen(argv[1]) >= sizeof(address.sun_path)) return 71;
        strcpy(address.sun_path, argv[1]);
        if (connect(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0) return 72;
        close(descriptor);
        char cwd[4096], executable[4096];
        uint32_t executable_size = sizeof(executable);
        if (getcwd(cwd, sizeof(cwd)) == NULL || _NSGetExecutablePath(executable, &executable_size) != 0) return 73;
        FILE *record = fopen(argv[2], "w");
        if (record == NULL) return 74;
        struct sigaction pipe_action;
        sigaction(SIGPIPE, NULL, &pipe_action);
        fprintf(record, "%ld\n%ld\n%ld\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
                (long)getpid(), (long)getppid(), (long)getpgrp(), cwd,
                getenv("OVERLAY_MARKER"), getenv("INHERITED_MARKER"),
                getenv("CONTINUUM_BOOTSTRAP_MARKER"), executable, argv[0],
                pipe_action.sa_handler == SIG_DFL ? "default" : "not-default");
        fclose(record);
        if (strcmp(argv[3], "wait") == 0) for (;;) pause();
        return 23;
    }
    """#

    private static let daemonFixtureSource = #"""
    #include <mach-o/dyld.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    int main(int argc, char **argv) {
        if (argc == 2 && strcmp(argv[1], "managed-path") == 0) {
            char executable[4096];
            uint32_t executable_size = sizeof(executable);
            if (_NSGetExecutablePath(executable, &executable_size) != 0) return 70;
            puts(executable);
            return 0;
        }
        if (argc != 2) return 64;
        int ready[2];
        if (pipe(ready) != 0) return 71;
        pid_t middle = fork();
        if (middle < 0) return 72;
        if (middle > 0) {
            close(ready[1]);
            char byte;
            int result = read(ready[0], &byte, 1) == 1 ? 0 : 73;
            close(ready[0]);
            return result;
        }
        close(ready[0]);
        if (setsid() < 0) _exit(74);
        pid_t detached = fork();
        if (detached < 0) _exit(75);
        if (detached == 0) {
            close(ready[1]);
            usleep(750000);
            _exit(0);
        }
        FILE *record = fopen(argv[1], "w");
        if (record == NULL) _exit(76);
        fprintf(record, "%ld\n", (long)detached);
        fclose(record);
        if (write(ready[1], "1", 1) != 1) _exit(77);
        close(ready[1]);
        _exit(0);
    }
    """#

    private func waitForFile(_ url: URL, timeout: TimeInterval = 5) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            if FileManager.default.fileExists(atPath: url.path) { return true }
            usleep(20_000)
        } while Date() < deadline
        return false
    }

    private func waitUntilProcessIsGone(_ process: pid_t, timeout: TimeInterval = 2) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            errno = 0
            if Darwin.kill(process, 0) != 0 && errno == ESRCH { return true }
            usleep(20_000)
        } while Date() < deadline
        return false
    }

    private func runResult(_ executable: String, _ arguments: [String]) throws -> ProcessResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let output = Pipe()
        let error = Pipe()
        process.standardOutput = output
        process.standardError = error
        try process.run()
        process.waitUntilExit()
        return ProcessResult(
            status: process.terminationStatus,
            stdout: String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self),
            stderr: String(decoding: error.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        )
    }

    @discardableResult
    private static func run(
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
