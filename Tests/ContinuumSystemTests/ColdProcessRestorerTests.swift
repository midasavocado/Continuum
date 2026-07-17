import Testing
@testable import ContinuumSystem
import ContinuumCore
import ContinuumRuntime
import Darwin
import Foundation

private final class ColdProofBundleMarker: NSObject {}

@Suite("Cold process restore routing")
struct ColdProcessRestorerTests {
    @Test("Two independent roots use generic forest routing")
    func independentRootsDoNotUseBrokeredPair() {
        let roots = [
            makeProcess(processIdentifier: 100, parentProcessIdentifier: 1),
            makeProcess(processIdentifier: 200, parentProcessIdentifier: 1),
        ]

        #expect(!ColdProcessRestorer.shouldUseBrokeredPair(
            roots,
            rootProcessIdentifier: 100
        ))
    }

    @Test("A root and its direct child preserve pair routing")
    func directChildUsesBrokeredPair() {
        let pair = [
            makeProcess(processIdentifier: 100, parentProcessIdentifier: 1),
            makeProcess(processIdentifier: 200, parentProcessIdentifier: 100),
        ]

        #expect(ColdProcessRestorer.shouldUseBrokeredPair(
            pair,
            rootProcessIdentifier: 100
        ))
    }

    @Test("Unnamed reciprocal Unix stream pairs pass cold validation")
    func validatesUnnamedReciprocalUnixPairAndAliases() throws {
        let pair = makeUnixPair()
        let handles = [
            DurableDescriptorHandle(
                resourceID: pair.first.id,
                processIdentifier: 100,
                fileDescriptor: 20,
                descriptorFlags: 0,
                statusFlags: O_RDWR | O_NONBLOCK
            ),
            DurableDescriptorHandle(
                resourceID: pair.first.id,
                processIdentifier: 100,
                fileDescriptor: 21,
                descriptorFlags: FD_CLOEXEC,
                statusFlags: O_RDWR | O_NONBLOCK
            ),
            DurableDescriptorHandle(
                resourceID: pair.second.id,
                processIdentifier: 200,
                fileDescriptor: 22,
                descriptorFlags: FD_CLOEXEC,
                statusFlags: O_RDWR
            ),
        ]
        try ColdProcessRestorer.validateColdSockets(
            graph: DurableDescriptorGraph(
                handles: handles,
                sockets: [pair.first, pair.second],
                pipes: [],
                kqueues: []
            ),
            handles: handles,
            capturedProcessIdentifiers: [100, 200]
        )
    }

    @Test("Unix cold validation fails closed outside the first exact slice")
    func rejectsUnsupportedUnixSocketState() {
        let valid = makeUnixPair()
        let handles = [
            DurableDescriptorHandle(
                resourceID: valid.first.id,
                processIdentifier: 100,
                fileDescriptor: 20,
                descriptorFlags: 0,
                statusFlags: O_RDWR
            ),
            DurableDescriptorHandle(
                resourceID: valid.second.id,
                processIdentifier: 100,
                fileDescriptor: 21,
                descriptorFlags: 0,
                statusFlags: O_RDWR
            ),
        ]
        func rejected(_ sockets: [DurableSocketResource]) -> Bool {
            do {
                try ColdProcessRestorer.validateColdSockets(
                    graph: DurableDescriptorGraph(
                        handles: handles,
                        sockets: sockets,
                        pipes: [],
                        kqueues: []
                    ),
                    handles: handles,
                    capturedProcessIdentifiers: [100]
                )
                return false
            } catch {
                return true
            }
        }

        #expect(rejected([
            unixSocket(
                id: valid.first.id,
                peerID: UUID(),
                sendShutdown: true
            ),
            valid.second,
        ]))
        #expect(rejected([
            unixSocket(
                id: valid.first.id,
                peerID: valid.second.id,
                localAddress: Data([UInt8(MemoryLayout<sockaddr_un>.size), UInt8(AF_UNIX)]),
                sendShutdown: true
            ),
            valid.second,
        ]))
        #expect(rejected([
            unixSocket(
                id: valid.first.id,
                peerID: valid.second.id,
                receiveQueueBytes: 1,
                sendShutdown: true
            ),
            valid.second,
        ]))
        #expect(rejected([
            unixSocket(
                id: valid.first.id,
                peerID: valid.second.id,
                sendQueueBytes: 1,
                sendShutdown: true
            ),
            valid.second,
        ]))
        #expect(rejected([
            unixSocket(
                id: valid.first.id,
                peerID: valid.second.id,
                kind: .unixListener,
                sendShutdown: true
            ),
            valid.second,
        ]))
        #expect(rejected([
            unixSocket(
                id: valid.first.id,
                peerID: valid.second.id,
                socketType: SOCK_DGRAM,
                sendShutdown: true
            ),
            valid.second,
        ]))
        #expect(rejected([
            unixSocket(
                id: valid.first.id,
                peerID: valid.second.id,
                socketProtocol: 1,
                sendShutdown: true
            ),
            valid.second,
        ]))
        #expect(rejected([
            unixSocket(
                id: valid.first.id,
                peerID: valid.second.id,
                sendShutdown: true,
                externalPath: "/tmp/external.sock"
            ),
            valid.second,
        ]))
        #expect(rejected([
            unixSocket(
                id: valid.first.id,
                peerID: valid.second.id,
                sendShutdown: true,
                options: socketOptions() + [socketOption(SO_KEEPALIVE, 1)]
            ),
            valid.second,
        ]))

        let asynchronousHandles = handles.map {
            DurableDescriptorHandle(
                resourceID: $0.resourceID,
                processIdentifier: $0.processIdentifier,
                fileDescriptor: $0.fileDescriptor,
                descriptorFlags: $0.descriptorFlags,
                statusFlags: $0.statusFlags | O_ASYNC
            )
        }
        #expect(rejectsColdValidation(
            sockets: [valid.first, valid.second],
            handles: asynchronousHandles
        ))
    }

    @Test("Unix raw socket state admits only exact connected replay state")
    func validatesRawUnixSocketState() {
        let connected = UInt32(SOI_S_ISCONNECTED)
        let receiveShutdown = UInt32(SOI_S_CANTRCVMORE)
        let sendShutdown = UInt32(SOI_S_CANTSENDMORE)
        let nonblocking = UInt32(SOI_S_NBIO)
        #expect(HotProcessCheckpointService.unixSocketStateIsColdReplayable(
            connected | receiveShutdown | sendShutdown,
            statusFlags: [O_RDWR, O_RDWR]
        ))
        #expect(HotProcessCheckpointService.unixSocketStateIsColdReplayable(
            connected | nonblocking,
            statusFlags: [O_RDWR | O_NONBLOCK, O_RDWR | O_NONBLOCK]
        ))
        #expect(!HotProcessCheckpointService.unixSocketStateIsColdReplayable(
            connected,
            statusFlags: [O_RDWR | O_NONBLOCK]
        ))
        #expect(!HotProcessCheckpointService.unixSocketStateIsColdReplayable(
            connected | nonblocking,
            statusFlags: [O_RDWR]
        ))
        #expect(!HotProcessCheckpointService.unixSocketStateIsColdReplayable(
            connected,
            statusFlags: [O_RDWR | O_ASYNC]
        ))
        for forbidden in [
            SOI_S_NOFDREF, SOI_S_ISCONNECTING, SOI_S_ISDISCONNECTING,
            SOI_S_RCVATMARK, SOI_S_PRIV, SOI_S_ASYNC, SOI_S_INCOMP,
            SOI_S_COMP, SOI_S_ISDISCONNECTED, SOI_S_DRAINING,
        ] {
            #expect(!HotProcessCheckpointService.unixSocketStateIsColdReplayable(
                connected | UInt32(forbidden),
                statusFlags: [O_RDWR]
            ))
        }
    }

    @Test("Recreates Unix pair buffers, CLOEXEC, and reciprocal half-close")
    func recreatesUnnamedUnixPair() throws {
        let saved = makeUnixPair()
        let recreated = try ColdProcessRestorer.createEmptyUnixSocketPair(
            first: saved.first,
            second: saved.second
        )
        defer {
            Darwin.close(recreated.first)
            Darwin.close(recreated.second)
        }
        #expect(fcntl(recreated.first, F_GETFD) == FD_CLOEXEC)
        #expect(fcntl(recreated.second, F_GETFD) == FD_CLOEXEC)
        #expect(socketBuffer(recreated.first, SO_RCVBUF) == 32_768)
        #expect(socketBuffer(recreated.first, SO_SNDBUF) == 32_768)

        var sent: UInt8 = 0xA7
        #expect(Darwin.write(recreated.second, &sent, 1) == 1)
        var received: UInt8 = 0
        #expect(Darwin.read(recreated.first, &received, 1) == 1)
        #expect(received == sent)
        #expect(Darwin.read(recreated.second, &received, 1) == 0)
    }

    @Test("Cold replacement receives Unix aliases, flags, buffers, and half-close")
    func replacementProcessReceivesPreparedUnixPair() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("continuum-unix-cold-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("proof.c")
        let executable = root.appendingPathComponent("proof")
        let result = root.appendingPathComponent("result.txt")
        try Self.replacementProofSource.write(
            to: source,
            atomically: true,
            encoding: .utf8
        )
        try runTool("/usr/bin/clang", [source.path, "-o", executable.path])
        let entitlements = root.appendingPathComponent("debug.entitlements")
        try Self.debugEntitlements.write(
            to: entitlements,
            atomically: true,
            encoding: .utf8
        )
        try runTool("/usr/bin/codesign", [
            "--force", "--sign", "-", "--entitlements",
            entitlements.path, executable.path,
        ])
        let bootstrapLibrary = try bootstrapLibraryURL()

        let saved = makeUnixPair()
        let capturedProcess: Int32 = 42_424
        let handles = [
            DurableDescriptorHandle(
                resourceID: saved.first.id,
                processIdentifier: capturedProcess,
                fileDescriptor: 300,
                descriptorFlags: 0,
                statusFlags: O_RDWR | O_NONBLOCK
            ),
            DurableDescriptorHandle(
                resourceID: saved.first.id,
                processIdentifier: capturedProcess,
                fileDescriptor: 301,
                descriptorFlags: FD_CLOEXEC,
                statusFlags: O_RDWR | O_NONBLOCK
            ),
            DurableDescriptorHandle(
                resourceID: saved.second.id,
                processIdentifier: capturedProcess,
                fileDescriptor: 302,
                descriptorFlags: FD_CLOEXEC,
                statusFlags: O_RDWR
            ),
        ]
        let graph = DurableDescriptorGraph(
            handles: handles,
            sockets: [saved.first, saved.second],
            pipes: [],
            kqueues: []
        )
        let image = DurableCheckpointImage(
            checkpointID: UUID(),
            createdAt: Date(),
            architecture: "arm64",
            operatingSystemBuild: "proof",
            pageSize: UInt64(getpagesize()),
            rootProcessIdentifier: capturedProcess,
            app: AppIdentity(
                bundleIdentifier: nil,
                displayName: "Unix proof",
                bundleURL: nil,
                executableURL: executable,
                version: nil,
                signingIdentifier: nil,
                teamIdentifier: nil,
                isApplePlatformBinary: false
            ),
            members: [makeProcess(
                processIdentifier: capturedProcess,
                parentProcessIdentifier: 1
            )],
            writableFiles: [],
            descriptorGraph: graph
        )
        let restorer = ColdProcessRestorer(
            bootstrapLibraryURL: bootstrapLibrary,
            fileSafetyRootURL: root.appendingPathComponent("safety")
        )
        let prepared = try await restorer.prepareDescriptorGraph(for: image)
        defer {
            prepared.controllerDescriptors.forEach { Darwin.close($0) }
        }
        guard let remaps = prepared.remapsByCapturedProcess[capturedProcess] else {
            Issue.record("Prepared graph omitted the replacement remaps")
            return
        }
        #expect(remaps.count == handles.count)

        let plan = try ColdProcessRestorer.bootstrapDescriptorPlan(
            [],
            socketHandles: handles
        )
        let planURL = root.appendingPathComponent("plan")
        let planDescriptor = Darwin.open(
            planURL.path,
            O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC,
            S_IRUSR | S_IWUSR
        )
        #expect(planDescriptor >= 0)
        guard planDescriptor >= 0 else { return }
        defer { Darwin.close(planDescriptor) }
        #expect(Darwin.unlink(planURL.path) == 0)
        let written = plan.withUnsafeBytes {
            Darwin.write(planDescriptor, $0.baseAddress, $0.count)
        }
        #expect(written == plan.count)
        #expect(lseek(planDescriptor, 0, SEEK_SET) == 0)

        var environment = ProcessInfo.processInfo.environment.map {
            "\($0.key)=\($0.value)"
        }.filter {
            !$0.hasPrefix("DYLD_INSERT_LIBRARIES=")
                && !$0.hasPrefix("CONTINUUM_BOOTSTRAP_STOP=")
                && !$0.hasPrefix("CONTINUUM_BOOTSTRAP_DESCRIPTOR_FD=")
        }
        environment.append("DYLD_INSERT_LIBRARIES=\(bootstrapLibrary.path)")
        environment.append("CONTINUUM_BOOTSTRAP_STOP=1")
        environment.append(
            "CONTINUUM_BOOTSTRAP_DESCRIPTOR_FD=\(planDescriptor)"
        )
        let arguments = [executable.path, result.path]
        var replacement: Int32 = 0
        let spawnStatus = withCStringArray(arguments) { argumentPointers in
            withCStringArray(environment) { environmentPointers in
                remaps.withUnsafeBufferPointer { remapBuffer in
                    executable.path.withCString { executablePath in
                        root.path.withCString { workingDirectory in
                            continuum_spawn_process_suspended_with_inherited_descriptor_and_remaps_system_aslr(
                                executablePath,
                                argumentPointers,
                                environmentPointers,
                                workingDirectory,
                                planDescriptor,
                                remapBuffer.baseAddress,
                                remapBuffer.count,
                                &replacement
                            )
                        }
                    }
                }
            }
        }
        #expect(spawnStatus == CONTINUUM_STATUS_OK)
        guard spawnStatus == CONTINUUM_STATUS_OK, replacement > 0 else { return }
        var reaped = false
        defer {
            if !reaped {
                _ = continuum_terminate_direct_child(replacement, 2_000)
            }
        }
        #expect(continuum_advance_process_to_entry_stop(
            replacement,
            5_000
        ) == CONTINUUM_STATUS_OK)
        #expect(continuum_release_entry_stopped_child(replacement)
            == CONTINUUM_STATUS_OK)
        var childStatus: Int32 = 0
        var waitResult: Int32 = 0
        let waitDeadline = Date().addingTimeInterval(2)
        repeat {
            waitResult = waitpid(replacement, &childStatus, WNOHANG)
            if waitResult == 0 { usleep(1_000) }
        } while waitResult == 0 && Date() < waitDeadline
        #expect(waitResult == replacement)
        guard waitResult == replacement else { return }
        reaped = true
        #expect(childStatus == 0)
        #expect(try String(contentsOf: result, encoding: .utf8) == "PASS\n")
    }

    private func makeProcess(
        processIdentifier: Int32,
        parentProcessIdentifier: Int32
    ) -> DurableProcessImage {
        DurableProcessImage(
            processIdentifier: processIdentifier,
            parentProcessIdentifier: parentProcessIdentifier,
            executableDevice: 0,
            executableInode: 0,
            vmLayoutHash: 0,
            regions: [],
            threads: []
        )
    }

    private func rejectsColdValidation(
        sockets: [DurableSocketResource],
        handles: [DurableDescriptorHandle]
    ) -> Bool {
        do {
            try ColdProcessRestorer.validateColdSockets(
                graph: DurableDescriptorGraph(
                    handles: handles,
                    sockets: sockets,
                    pipes: [],
                    kqueues: []
                ),
                handles: handles,
                capturedProcessIdentifiers: Set(
                    handles.map(\.processIdentifier)
                )
            )
            return false
        } catch {
            return true
        }
    }

    private func makeUnixPair() -> (
        first: DurableSocketResource,
        second: DurableSocketResource
    ) {
        let firstID = UUID()
        let secondID = UUID()
        return (
            unixSocket(
                id: firstID,
                peerID: secondID,
                sendShutdown: true
            ),
            unixSocket(
                id: secondID,
                peerID: firstID,
                receiveShutdown: true
            )
        )
    }

    private func unixSocket(
        id: UUID,
        peerID: UUID,
        kind: DurableSocketKind = .unixConnected,
        socketType: Int32 = SOCK_STREAM,
        socketProtocol: Int32 = 0,
        localAddress: Data? = nil,
        receiveQueueBytes: UInt64 = 0,
        sendQueueBytes: UInt64 = 0,
        receiveShutdown: Bool = false,
        sendShutdown: Bool = false,
        externalPath: String? = nil,
        options: [DurableSocketOption]? = nil
    ) -> DurableSocketResource {
        DurableSocketResource(
            id: id,
            kind: kind,
            domain: AF_UNIX,
            type: socketType,
            protocol: socketProtocol,
            localAddress: localAddress,
            receiveQueueBytes: receiveQueueBytes,
            sendQueueBytes: sendQueueBytes,
            receiveShutdown: receiveShutdown,
            sendShutdown: sendShutdown,
            peerResourceID: peerID,
            externalPath: externalPath,
            options: options ?? socketOptions()
        )
    }

    private func socketOptions() -> [DurableSocketOption] {
        [socketOption(SO_RCVBUF, 32_768), socketOption(SO_SNDBUF, 32_768)]
    }

    private func socketOption(_ name: Int32, _ value: Int32) -> DurableSocketOption {
        var value = value
        return withUnsafeBytes(of: &value) {
            DurableSocketOption(level: SOL_SOCKET, name: name, value: Data($0))
        }
    }

    private func socketBuffer(_ descriptor: Int32, _ name: Int32) -> Int32 {
        var value: Int32 = 0
        var length = socklen_t(MemoryLayout.size(ofValue: value))
        #expect(getsockopt(
            descriptor,
            SOL_SOCKET,
            name,
            &value,
            &length
        ) == 0)
        return value
    }

    private func runTool(_ executable: String, _ arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        let errors = Pipe()
        process.standardError = errors
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw NSError(
                domain: "ColdProcessRestorerTests",
                code: Int(process.terminationStatus),
                userInfo: [NSLocalizedDescriptionKey: String(
                    decoding: errors.fileHandleForReading.readDataToEndOfFile(),
                    as: UTF8.self
                )]
            )
        }
    }

    private func bootstrapLibraryURL() throws -> URL {
        var executableSize: UInt32 = 0
        _ = _NSGetExecutablePath(nil, &executableSize)
        var executableBytes = [CChar](
            repeating: 0,
            count: Int(executableSize)
        )
        let executablePath = executableBytes.withUnsafeMutableBufferPointer {
            _NSGetExecutablePath($0.baseAddress, &executableSize) == 0
                ? String(cString: $0.baseAddress!)
                : nil
        }
        var starts = [
            executablePath.map { URL(fileURLWithPath: $0) },
            Bundle.main.executableURL,
            Bundle(for: ColdProofBundleMarker.self).bundleURL,
            URL(fileURLWithPath: CommandLine.arguments[0]),
        ].compactMap { $0 }
        for key in [
            "BUILT_PRODUCTS_DIR", "TARGET_BUILD_DIR", "SWIFT_BUILD_PATH",
        ] {
            if let path = ProcessInfo.processInfo.environment[key] {
                starts.append(URL(fileURLWithPath: path))
            }
        }
        for key in ["DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH"] {
            starts.append(contentsOf: ProcessInfo.processInfo.environment[key]?
                .split(separator: ":")
                .map { URL(fileURLWithPath: String($0)) } ?? [])
        }
        for start in starts {
            var directory = start.deletingLastPathComponent()
            for _ in 0..<8 {
                let candidate = directory
                    .appendingPathComponent("libContinuumBootstrap.dylib")
                if FileManager.default.fileExists(atPath: candidate.path) {
                    return candidate
                }
                directory.deleteLastPathComponent()
            }
        }
        throw NSError(
            domain: "ColdProcessRestorerTests",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: "ContinuumBootstrap was not built"]
        )
    }

    private func withCStringArray<Result>(
        _ strings: [String],
        _ body: (UnsafePointer<UnsafePointer<CChar>?>) -> Result
    ) -> Result {
        let storage = strings.map { strdup($0)! }
        defer { storage.forEach { free($0) } }
        var pointers = storage.map { UnsafePointer<CChar>($0) as Optional }
        pointers.append(nil)
        return pointers.withUnsafeBufferPointer { body($0.baseAddress!) }
    }

    private static let debugEntitlements = """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" \
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict>
    <key>com.apple.security.get-task-allow</key><true/>
    </dict></plist>
    """

    private static let replacementProofSource = #"""
    #include <fcntl.h>
    #include <poll.h>
    #include <stdio.h>
    #include <sys/socket.h>
    #include <unistd.h>
    int main(int argc, char **argv) {
        if (argc != 2) return 64;
        int first = 300, alias = 301, second = 302;
        int type = 0, receive = 0, send = 0;
        socklen_t length = sizeof(int);
        if (getsockopt(first, SOL_SOCKET, SO_TYPE, &type, &length) != 0
            || type != SOCK_STREAM
            || getsockopt(first, SOL_SOCKET, SO_RCVBUF, &receive, &length) != 0
            || getsockopt(first, SOL_SOCKET, SO_SNDBUF, &send, &length) != 0
            || receive != 32768 || send != 32768
            || fcntl(first, F_GETFD) != 0
            || fcntl(alias, F_GETFD) != FD_CLOEXEC
            || fcntl(second, F_GETFD) != FD_CLOEXEC
            || (fcntl(first, F_GETFL) & O_NONBLOCK) == 0
            || fcntl(first, F_GETFL) != fcntl(alias, F_GETFL)
            || (fcntl(second, F_GETFL) & O_NONBLOCK) != 0) return 65;
        unsigned char byte = 0;
        struct pollfd event = { .fd = second, .events = POLLIN | POLLHUP };
        if (poll(&event, 1, 1000) <= 0 || read(second, &byte, 1) != 0) return 66;
        byte = 0xA9;
        if (write(second, &byte, 1) != 1 || close(first) != 0) return 67;
        unsigned char observed = 0;
        if (read(alias, &observed, 1) != 1 || observed != byte) return 68;
        FILE *result = fopen(argv[1], "w");
        if (result == NULL) return 69;
        fputs("PASS\n", result);
        return fclose(result) == 0 ? 0 : 70;
    }
    """#
}
