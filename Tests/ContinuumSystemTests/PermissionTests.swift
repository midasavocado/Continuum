import Foundation
import Testing
@testable import ContinuumSystem
import ContinuumCore
import ContinuumTerminalRelayCore
import Darwin

@Suite("macOS permission reporting")
struct PermissionTests {
    @Test("Reports every permission without prompting")
    func reportsStatusShape() async {
        let environment = PermissionEnvironment(
            accessibilityPreflight: { true },
            accessibilityRequest: { Issue.record("Request closure must not run during preflight"); return false },
            screenRecordingPreflight: { false },
            screenRecordingRequest: { Issue.record("Request closure must not run during preflight"); return false },
            openURL: { _ in Issue.record("Settings must not open during preflight") }
        )
        let service = MacPermissionService(environment: environment)

        let statuses = await service.statuses()
        let byKind = Dictionary(uniqueKeysWithValues: statuses.map { ($0.kind, $0) })

        #expect(statuses.count == PermissionKind.allCases.count)
        #expect(byKind[.accessibility]?.state == .granted)
        #expect(byKind[.screenRecording]?.state == .denied)
        #expect(byKind[.automation]?.state == .unknown)
        #expect(byKind[.fullDiskAccess]?.state == .requiresSystemSettings)
    }

    @Test("Uses the privacy-pane deep links")
    func privacyDeepLinks() {
        #expect(MacPermissionService.systemSettingsURL(for: .accessibility)?.absoluteString.hasSuffix("Privacy_Accessibility") == true)
        #expect(MacPermissionService.systemSettingsURL(for: .screenRecording)?.absoluteString.hasSuffix("Privacy_ScreenCapture") == true)
        #expect(MacPermissionService.systemSettingsURL(for: .automation)?.absoluteString.hasSuffix("Privacy_Automation") == true)
        #expect(MacPermissionService.systemSettingsURL(for: .fullDiskAccess)?.absoluteString.hasSuffix("Privacy_AllFiles") == true)
    }

    @Test("Invokes the native request hooks for interactive permissions")
    func requestsInteractivePermissions() async {
        let environment = PermissionEnvironment(
            accessibilityPreflight: { false },
            accessibilityRequest: { true },
            screenRecordingPreflight: { false },
            screenRecordingRequest: { true },
            openURL: { _ in Issue.record("Interactive requests must not open Settings directly") }
        )
        let service = MacPermissionService(environment: environment)

        let accessibility = await service.request(.accessibility)
        let screenRecording = await service.request(.screenRecording)

        #expect(accessibility.state == .granted)
        #expect(screenRecording.state == .granted)
    }
}

private final class RelayCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var storedResult: Int32?

    func finish(_ result: Int32) {
        lock.lock()
        storedResult = result
        lock.unlock()
    }

    var result: Int32? {
        lock.lock()
        defer { lock.unlock() }
        return storedResult
    }
}

private struct RelayFrame {
    let type: UInt8
    let payload: [UInt8]
}

private func relaySocketAddress(_ path: String) throws -> sockaddr_un {
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    let bytes = Array(path.utf8) + [0]
    guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
        throw POSIXError(.ENAMETOOLONG)
    }
    withUnsafeMutableBytes(of: &address.sun_path) { destination in
        destination.copyBytes(from: bytes)
    }
    return address
}

private func relayReadExactly(_ fd: Int32, count: Int) throws -> [UInt8] {
    var result: [UInt8] = []
    result.reserveCapacity(count)
    while result.count < count {
        var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        guard poll(&descriptor, 1, 2_000) > 0 else {
            throw CocoaError(.coderReadCorrupt)
        }
        var chunk = [UInt8](repeating: 0, count: count - result.count)
        let readCount = chunk.withUnsafeMutableBytes { buffer in
            Darwin.read(fd, buffer.baseAddress, buffer.count)
        }
        guard readCount > 0 else { throw CocoaError(.coderReadCorrupt) }
        result.append(contentsOf: chunk.prefix(readCount))
    }
    return result
}

private func relayReadFrame(_ fd: Int32) throws -> RelayFrame {
    let header = try relayReadExactly(fd, count: 5)
    let length = header[1...4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    return RelayFrame(
        type: header[0],
        payload: try relayReadExactly(fd, count: Int(length))
    )
}

private func relayWriteFrame(_ fd: Int32, type: UInt8, payload: [UInt8]) throws {
    let length = UInt32(payload.count)
    var bytes: [UInt8] = [
        type,
        UInt8(truncatingIfNeeded: length >> 24),
        UInt8(truncatingIfNeeded: length >> 16),
        UInt8(truncatingIfNeeded: length >> 8),
        UInt8(truncatingIfNeeded: length)
    ]
    bytes.append(contentsOf: payload)
    let written = bytes.withUnsafeBytes { buffer in
        Darwin.write(fd, buffer.baseAddress, buffer.count)
    }
    guard written == bytes.count else { throw CocoaError(.fileWriteUnknown) }
}

@Suite("Terminal relay transport", .serialized)
struct TerminalRelayTransportTests {
    @Test("Forwards bytes, resize, EOF, and restores terminal mode")
    func forwardsTerminalSession() throws {
        let shortID = UUID().uuidString.prefix(8)
        let directory = URL(fileURLWithPath: "/tmp/cr-\(shortID)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let socketPath = directory.appendingPathComponent("relay.sock").path

        let listener = socket(AF_UNIX, SOCK_STREAM, 0)
        #expect(listener >= 0)
        defer { close(listener) }
        var address = try relaySocketAddress(socketPath)
        let bindResult = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        #expect(bindResult == 0)
        #expect(listen(listener, 1) == 0)

        var master: Int32 = -1
        var slave: Int32 = -1
        #expect(openpty(&master, &slave, nil, nil, nil) == 0)
        defer {
            if master >= 0 { close(master) }
            if slave >= 0 { close(slave) }
        }
        var original = termios()
        #expect(tcgetattr(slave, &original) == 0)
        var initialSize = winsize(ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0)
        #expect(ioctl(master, TIOCSWINSZ, &initialSize) == 0)

        let completion = RelayCompletion()
        let relayTerminalFD = slave
        DispatchQueue.global().async {
            let result = socketPath.withCString {
                continuum_terminal_relay_run($0, relayTerminalFD, relayTerminalFD, 1)
            }
            completion.finish(result)
        }

        let connection = accept(listener, nil, nil)
        #expect(connection >= 0)
        defer { close(connection) }

        let ready = try relayReadFrame(connection)
        #expect(ready.type == 3)
        #expect(ready.payload.isEmpty)
        let initialResize = try relayReadFrame(connection)
        #expect(initialResize.type == 2)
        #expect(initialResize.payload == [0, 0, 0, 24, 0, 0, 0, 80])
        var activeMode = termios()
        #expect(tcgetattr(slave, &activeMode) == 0)
        #expect(activeMode.c_lflag & tcflag_t(ECHO | ICANON) == 0)

        let keyboardBytes = Array("typed byte-for-byte".utf8)
        #expect(master >= 0)
        #expect(keyboardBytes.withUnsafeBytes {
            Darwin.write(master, $0.baseAddress, $0.count)
        } == keyboardBytes.count)
        let outbound = try relayReadFrame(connection)
        #expect(outbound.type == 1)
        #expect(outbound.payload == keyboardBytes)

        let outputBytes = Array("generated byte-for-byte".utf8)
        try relayWriteFrame(connection, type: 1, payload: outputBytes)
        #expect(try relayReadExactly(master, count: outputBytes.count) == outputBytes)

        var resized = winsize(ws_row: 43, ws_col: 132, ws_xpixel: 0, ws_ypixel: 0)
        #expect(ioctl(master, TIOCSWINSZ, &resized) == 0)
        #expect(kill(getpid(), SIGWINCH) == 0)
        let resize = try relayReadFrame(connection)
        #expect(resize.type == 2)
        #expect(resize.payload == [0, 0, 0, 43, 0, 0, 0, 132])

        try relayWriteFrame(connection, type: 4, payload: [])
        let deadline = Date().addingTimeInterval(2)
        while completion.result == nil && Date() < deadline {
            usleep(10_000)
        }
        #expect(completion.result == 0)
        var restored = termios()
        #expect(tcgetattr(slave, &restored) == 0)
        let userModeFlags = tcflag_t(ECHO | ICANON | ISIG | IEXTEN)
        #expect(restored.c_lflag & userModeFlags == original.c_lflag & userModeFlags)
    }

    @Test("Controller retains a workload PTY across relay reconnects")
    func controllerRetainsWorkloadAcrossReconnect() async throws {
        let shortID = UUID().uuidString.prefix(8)
        let runtimeDirectory = URL(
            fileURLWithPath: "/tmp/continuum-present-\(shortID)",
            isDirectory: true
        )
        defer { try? FileManager.default.removeItem(at: runtimeDirectory) }

        var workloadMaster: Int32 = -1
        var workloadSlave: Int32 = -1
        #expect(openpty(&workloadMaster, &workloadSlave, nil, nil, nil) == 0)
        guard workloadMaster >= 0, workloadSlave >= 0 else { return }
        defer {
            if workloadMaster >= 0 { close(workloadMaster) }
            if workloadSlave >= 0 { close(workloadSlave) }
        }
        var workloadMode = termios()
        #expect(tcgetattr(workloadSlave, &workloadMode) == 0)
        cfmakeraw(&workloadMode)
        #expect(tcsetattr(workloadSlave, TCSANOW, &workloadMode) == 0)

        let registry = try TerminalPresentationSessionRegistry(
            runtimeDirectory: runtimeDirectory
        )
        let forestIdentifier = UUID()
        let sessionIdentifier = UUID()
        let firstEndpoint = try await registry.stage(
            workloadPTYMaster: workloadMaster,
            forestIdentifier: forestIdentifier,
            sessionIdentifier: sessionIdentifier
        )
        close(workloadMaster)
        workloadMaster = -1

        var directoryStatus = stat()
        #expect(lstat(runtimeDirectory.path, &directoryStatus) == 0)
        #expect(directoryStatus.st_mode & mode_t(0o777) == mode_t(0o700))
        #expect(directoryStatus.st_uid == getuid())

        var firstPresentationMaster: Int32 = -1
        var firstPresentationSlave: Int32 = -1
        #expect(openpty(
            &firstPresentationMaster,
            &firstPresentationSlave,
            nil,
            nil,
            nil
        ) == 0)
        let firstCompletion = RelayCompletion()
        let firstRelayFD = firstPresentationSlave
        DispatchQueue.global().async {
            let result = firstEndpoint.socketPath.withCString {
                continuum_terminal_relay_run($0, firstRelayFD, firstRelayFD, 1)
            }
            firstCompletion.finish(result)
        }

        try await registry.waitUntilReady(sessionIdentifier)
        #expect(try await registry.state(of: sessionIdentifier) == .ready)
        #expect(!FileManager.default.fileExists(atPath: firstEndpoint.socketPath))

        let relayInput = Array("relay to workload".utf8)
        #expect(relayInput.withUnsafeBytes {
            Darwin.write(firstPresentationMaster, $0.baseAddress, $0.count)
        } == relayInput.count)
        #expect(try relayReadExactly(workloadSlave, count: relayInput.count) == relayInput)

        let workloadOutput = Array("workload to relay".utf8)
        #expect(workloadOutput.withUnsafeBytes {
            Darwin.write(workloadSlave, $0.baseAddress, $0.count)
        } == workloadOutput.count)
        #expect(
            try relayReadExactly(firstPresentationMaster, count: workloadOutput.count)
                == workloadOutput
        )

        var requestedSize = winsize(ws_row: 51, ws_col: 141, ws_xpixel: 0, ws_ypixel: 0)
        #expect(ioctl(firstPresentationMaster, TIOCSWINSZ, &requestedSize) == 0)
        #expect(kill(getpid(), SIGWINCH) == 0)
        let resizeDeadline = Date().addingTimeInterval(2)
        var observedSize = winsize()
        repeat {
            #expect(ioctl(workloadSlave, TIOCGWINSZ, &observedSize) == 0)
            if observedSize.ws_row == 51, observedSize.ws_col == 141 { break }
            try await Task.sleep(for: .milliseconds(10))
        } while Date() < resizeDeadline
        #expect(observedSize.ws_row == 51)
        #expect(observedSize.ws_col == 141)

        try await registry.promote(sessionIdentifier)
        close(firstPresentationMaster)
        firstPresentationMaster = -1
        let disconnectDeadline = Date().addingTimeInterval(2)
        while try await registry.state(of: sessionIdentifier) != .disconnected,
              Date() < disconnectDeadline {
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(try await registry.state(of: sessionIdentifier) == .disconnected)

        let bufferedWhileDetached = Array("survived disconnect".utf8)
        #expect(bufferedWhileDetached.withUnsafeBytes {
            Darwin.write(workloadSlave, $0.baseAddress, $0.count)
        } == bufferedWhileDetached.count)

        let secondEndpoint = try await registry.reconnect(sessionIdentifier)
        #expect(secondEndpoint.socketPath != firstEndpoint.socketPath)
        var secondPresentationMaster: Int32 = -1
        var secondPresentationSlave: Int32 = -1
        #expect(openpty(
            &secondPresentationMaster,
            &secondPresentationSlave,
            nil,
            nil,
            nil
        ) == 0)
        let secondCompletion = RelayCompletion()
        let secondRelayFD = secondPresentationSlave
        DispatchQueue.global().async {
            let result = secondEndpoint.socketPath.withCString {
                continuum_terminal_relay_run($0, secondRelayFD, secondRelayFD, 1)
            }
            secondCompletion.finish(result)
        }

        try await registry.waitUntilReady(sessionIdentifier)
        #expect(
            try relayReadExactly(
                secondPresentationMaster,
                count: bufferedWhileDetached.count
            ) == bufferedWhileDetached
        )

        close(secondPresentationMaster)
        secondPresentationMaster = -1
        close(firstPresentationSlave)
        firstPresentationSlave = -1
        close(secondPresentationSlave)
        secondPresentationSlave = -1
        try await registry.discard(sessionIdentifier)
        await registry.closeAll()

        #expect(!FileManager.default.fileExists(atPath: runtimeDirectory.path))
        var orphanedByte: UInt8 = 0
        let orphanedRead = Darwin.read(workloadSlave, &orphanedByte, 1)
        #expect(orphanedRead <= 0)

        let completionDeadline = Date().addingTimeInterval(2)
        while (firstCompletion.result == nil || secondCompletion.result == nil),
              Date() < completionDeadline {
            usleep(10_000)
        }
        #expect(firstCompletion.result == 0)
        #expect(secondCompletion.result == 0)
    }
}
