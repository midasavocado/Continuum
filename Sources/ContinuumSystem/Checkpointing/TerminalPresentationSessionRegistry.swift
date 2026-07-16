import Darwin
import Foundation

/// Controller-side ownership for a restored terminal workload's PTY master.
///
/// Relay peers are currently authenticated by Unix uid. Code-signature authentication is
/// intentionally left for the presentation-launch layer; a uid match alone is not sufficient
/// protection against another process running as the same user.
public actor TerminalPresentationSessionRegistry {
    public struct Endpoint: Sendable, Equatable {
        public let sessionIdentifier: UUID
        public let forestIdentifier: UUID
        public let socketPath: String
    }

    public enum PresentationState: Sendable, Equatable {
        case listening
        case connected
        case ready
        case disconnected
        case failed(String)
        case closed
    }

    public enum RegistryError: Error, Sendable, Equatable {
        case duplicateSession
        case unknownSession
        case invalidDescriptor
        case invalidRuntimeDirectory
        case socketPathTooLong
        case timedOutWaitingForReady
        case sessionFailed(String)
        case posix(operation: String, code: Int32)
    }

    private let runtimeDirectory: URL
    private var sessions: [UUID: TerminalPresentationSession] = [:]

    public init(runtimeDirectory: URL? = nil) throws {
        let selectedDirectory = runtimeDirectory ?? URL(
            fileURLWithPath: "/tmp/continuum-terminal-\(getuid())-\(UUID().uuidString.prefix(12))",
            isDirectory: true
        )
        try Self.preparePrivateDirectory(selectedDirectory)
        self.runtimeDirectory = selectedDirectory
    }

    public func stage(
        workloadPTYMaster: Int32,
        forestIdentifier: UUID,
        sessionIdentifier: UUID = UUID()
    ) throws -> Endpoint {
        guard sessions[sessionIdentifier] == nil else {
            throw RegistryError.duplicateSession
        }
        guard fcntl(workloadPTYMaster, F_GETFD) >= 0 else {
            throw RegistryError.invalidDescriptor
        }

        let sessionDirectory = runtimeDirectory.appendingPathComponent(
            String(sessionIdentifier.uuidString.prefix(12)),
            isDirectory: true
        )
        try Self.preparePrivateDirectory(sessionDirectory)
        do {
            let session = try TerminalPresentationSession(
                sessionIdentifier: sessionIdentifier,
                forestIdentifier: forestIdentifier,
                sessionDirectory: sessionDirectory,
                workloadPTYMaster: workloadPTYMaster
            )
            sessions[sessionIdentifier] = session
            return session.endpoint
        } catch {
            try? FileManager.default.removeItem(at: sessionDirectory)
            throw error
        }
    }

    public func state(of sessionIdentifier: UUID) throws -> PresentationState {
        guard let session = sessions[sessionIdentifier] else {
            throw RegistryError.unknownSession
        }
        return session.state
    }

    public func waitUntilReady(
        _ sessionIdentifier: UUID,
        timeout: Duration = .seconds(5)
    ) async throws {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: timeout)
        while clock.now < deadline {
            switch try state(of: sessionIdentifier) {
            case .ready:
                return
            case let .failed(description):
                throw RegistryError.sessionFailed(description)
            case .closed:
                throw RegistryError.unknownSession
            case .listening, .connected, .disconnected:
                try await Task.sleep(for: .milliseconds(10))
            }
        }
        throw RegistryError.timedOutWaitingForReady
    }

    /// Marks a staged session as retained by the committed restore transaction.
    public func promote(_ sessionIdentifier: UUID) throws {
        guard let session = sessions[sessionIdentifier] else {
            throw RegistryError.unknownSession
        }
        session.promote()
    }

    /// Drops the current relay connection and publishes a fresh one-shot listener.
    /// The controller-owned workload PTY master remains open throughout the handoff.
    public func reconnect(_ sessionIdentifier: UUID) throws -> Endpoint {
        guard let session = sessions[sessionIdentifier] else {
            throw RegistryError.unknownSession
        }
        return try session.reconnect()
    }

    public func discard(_ sessionIdentifier: UUID) throws {
        guard let session = sessions.removeValue(forKey: sessionIdentifier) else {
            throw RegistryError.unknownSession
        }
        session.close()
    }

    public func closeAll() {
        let retained = sessions.values
        sessions.removeAll()
        retained.forEach { $0.close() }
        try? FileManager.default.removeItem(at: runtimeDirectory)
    }

    private static func preparePrivateDirectory(_ directory: URL) throws {
        let path = directory.path
        if mkdir(path, S_IRWXU) != 0, errno != EEXIST {
            throw RegistryError.posix(operation: "mkdir", code: errno)
        }
        var status = stat()
        guard lstat(path, &status) == 0,
              (status.st_mode & S_IFMT) == S_IFDIR,
              status.st_uid == getuid(),
              chmod(path, S_IRWXU) == 0 else {
            throw RegistryError.invalidRuntimeDirectory
        }
    }
}

private final class TerminalPresentationSession: @unchecked Sendable {
    private static let bufferCapacity = 256 * 1024
    private static let dataChunkSize = 16 * 1024
    private static let headerSize = 5

    let sessionIdentifier: UUID
    let forestIdentifier: UUID
    let sessionDirectory: URL

    private let queue: DispatchQueue
    private var masterDescriptor: Int32
    private var listenerDescriptor: Int32 = -1
    private var peerDescriptor: Int32 = -1
    private var socketPath = ""
    private var generation: UInt64 = 0
    private var currentState: TerminalPresentationSessionRegistry.PresentationState = .listening
    private var isPromoted = false
    private var isClosed = false
    private var socketInput = Data()
    private var pendingToMaster = Data()
    private var outboundFrames: [Data] = []
    private var outboundFrameOffset = 0
    private var outboundByteCount = 0
    private var masterReachedEOF = false

    init(
        sessionIdentifier: UUID,
        forestIdentifier: UUID,
        sessionDirectory: URL,
        workloadPTYMaster: Int32
    ) throws {
        self.sessionIdentifier = sessionIdentifier
        self.forestIdentifier = forestIdentifier
        self.sessionDirectory = sessionDirectory
        self.queue = DispatchQueue(label: "Continuum.TerminalPresentation.\(sessionIdentifier)")
        self.masterDescriptor = dup(workloadPTYMaster)
        guard masterDescriptor >= 0 else {
            throw TerminalPresentationSessionRegistry.RegistryError.posix(
                operation: "dup",
                code: errno
            )
        }
        do {
            try Self.makeNonblockingAndCloseOnExec(masterDescriptor)
            try queue.sync { try openListener() }
        } catch {
            Darwin.close(masterDescriptor)
            masterDescriptor = -1
            throw error
        }
    }

    deinit {
        if masterDescriptor >= 0 { Darwin.close(masterDescriptor) }
        if peerDescriptor >= 0 { Darwin.close(peerDescriptor) }
        if listenerDescriptor >= 0 { Darwin.close(listenerDescriptor) }
        if !socketPath.isEmpty { unlink(socketPath) }
    }

    var endpoint: TerminalPresentationSessionRegistry.Endpoint {
        queue.sync {
            TerminalPresentationSessionRegistry.Endpoint(
                sessionIdentifier: sessionIdentifier,
                forestIdentifier: forestIdentifier,
                socketPath: socketPath
            )
        }
    }

    var state: TerminalPresentationSessionRegistry.PresentationState {
        queue.sync { currentState }
    }

    func promote() {
        queue.sync { isPromoted = true }
    }

    func reconnect() throws -> TerminalPresentationSessionRegistry.Endpoint {
        try queue.sync {
            guard !isClosed else {
                throw TerminalPresentationSessionRegistry.RegistryError.unknownSession
            }
            disconnectPeer(nextState: .disconnected)
            if listenerDescriptor >= 0 {
                Darwin.close(listenerDescriptor)
                listenerDescriptor = -1
            }
            if !socketPath.isEmpty { unlink(socketPath) }
            socketInput.removeAll(keepingCapacity: true)
            outboundFrameOffset = 0
            try openListener()
            return TerminalPresentationSessionRegistry.Endpoint(
                sessionIdentifier: sessionIdentifier,
                forestIdentifier: forestIdentifier,
                socketPath: socketPath
            )
        }
    }

    func close() {
        queue.sync {
            guard !isClosed else { return }
            isClosed = true
            generation &+= 1
            disconnectPeer(nextState: .closed)
            if listenerDescriptor >= 0 {
                Darwin.close(listenerDescriptor)
                listenerDescriptor = -1
            }
            if masterDescriptor >= 0 {
                Darwin.close(masterDescriptor)
                masterDescriptor = -1
            }
            if !socketPath.isEmpty { unlink(socketPath) }
            try? FileManager.default.removeItem(at: sessionDirectory)
            currentState = .closed
        }
    }

    private func openListener() throws {
        generation &+= 1
        let activeGeneration = generation
        let candidate = sessionDirectory.appendingPathComponent(
            "r-\(String(activeGeneration, radix: 16)).sock"
        ).path
        guard candidate.utf8.count < MemoryLayout.size(ofValue: sockaddr_un().sun_path) else {
            throw TerminalPresentationSessionRegistry.RegistryError.socketPathTooLong
        }

        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw TerminalPresentationSessionRegistry.RegistryError.posix(
                operation: "socket",
                code: errno
            )
        }
        do {
            try Self.makeNonblockingAndCloseOnExec(descriptor)
            var address = try Self.socketAddress(candidate)
            let bindResult = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            guard bindResult == 0 else {
                throw TerminalPresentationSessionRegistry.RegistryError.posix(
                    operation: "bind",
                    code: errno
                )
            }
            guard chmod(candidate, S_IRUSR | S_IWUSR) == 0 else {
                throw TerminalPresentationSessionRegistry.RegistryError.posix(
                    operation: "chmod socket",
                    code: errno
                )
            }
            guard listen(descriptor, 1) == 0 else {
                throw TerminalPresentationSessionRegistry.RegistryError.posix(
                    operation: "listen",
                    code: errno
                )
            }
        } catch {
            Darwin.close(descriptor)
            unlink(candidate)
            throw error
        }

        listenerDescriptor = descriptor
        socketPath = candidate
        currentState = .listening
        schedulePump(generation: activeGeneration)
    }

    private func schedulePump(generation expectedGeneration: UInt64) {
        queue.asyncAfter(deadline: .now() + .milliseconds(2)) { [weak self] in
            guard let self,
                  !self.isClosed,
                  self.generation == expectedGeneration else { return }
            self.pump()
            self.schedulePump(generation: expectedGeneration)
        }
    }

    private func pump() {
        if peerDescriptor < 0 { acceptPeerIfAvailable() }
        guard peerDescriptor >= 0 else { return }

        parseFrames()
        writePendingInputToMaster()
        readMasterOutput()
        writeOutputToPeer()
        readPeerInput()
        parseFrames()
        writePendingInputToMaster()

        if peerDescriptor >= 0 {
            var descriptor = pollfd(fd: peerDescriptor, events: 0, revents: 0)
            if poll(&descriptor, 1, 0) > 0,
               descriptor.revents & Int16(POLLERR | POLLHUP | POLLNVAL) != 0 {
                disconnectAfterTransportEnded()
            }
        }
    }

    private func acceptPeerIfAvailable() {
        guard listenerDescriptor >= 0 else { return }
        let accepted = accept(listenerDescriptor, nil, nil)
        guard accepted >= 0 else {
            if errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR {
                fail("accept failed: \(String(cString: strerror(errno)))")
            }
            return
        }
        do {
            var effectiveUID: uid_t = 0
            var effectiveGID: gid_t = 0
            guard getpeereid(accepted, &effectiveUID, &effectiveGID) == 0,
                  effectiveUID == getuid() else {
                Darwin.close(accepted)
                return
            }
            try Self.makeNonblockingAndCloseOnExec(accepted)
            var noSignal = Int32(1)
            guard setsockopt(
                accepted,
                SOL_SOCKET,
                SO_NOSIGPIPE,
                &noSignal,
                socklen_t(MemoryLayout.size(ofValue: noSignal))
            ) == 0 else {
                throw TerminalPresentationSessionRegistry.RegistryError.posix(
                    operation: "setsockopt SO_NOSIGPIPE",
                    code: errno
                )
            }
            peerDescriptor = accepted
            currentState = .connected
            Darwin.close(listenerDescriptor)
            listenerDescriptor = -1
            unlink(socketPath)
        } catch {
            Darwin.close(accepted)
            fail(String(describing: error))
        }
    }

    private func readPeerInput() {
        guard socketInput.count < Self.bufferCapacity else { return }
        var bytes = [UInt8](
            repeating: 0,
            count: min(Self.dataChunkSize, Self.bufferCapacity - socketInput.count)
        )
        let count = bytes.withUnsafeMutableBytes {
            Darwin.read(peerDescriptor, $0.baseAddress, $0.count)
        }
        if count > 0 {
            socketInput.append(contentsOf: bytes.prefix(count))
        } else if count == 0 {
            disconnectAfterTransportEnded()
        } else if errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR {
            disconnectAfterTransportEnded()
        }
    }

    private func parseFrames() {
        while socketInput.count >= Self.headerSize {
            let payloadLength = socketInput[1...4].reduce(0) {
                ($0 << 8) | Int($1)
            }
            guard payloadLength <= Self.bufferCapacity - Self.headerSize else {
                fail("Relay sent an oversized frame.")
                return
            }
            let frameLength = Self.headerSize + payloadLength
            guard socketInput.count >= frameLength else { return }
            let type = socketInput[0]

            switch type {
            case 1:
                guard pendingToMaster.count + payloadLength <= Self.bufferCapacity else {
                    return
                }
                pendingToMaster.append(socketInput[Self.headerSize..<frameLength])
            case 2:
                guard payloadLength == 8 else {
                    fail("Relay sent a malformed resize frame.")
                    return
                }
                let payload = socketInput[Self.headerSize..<frameLength]
                let values = Array(payload)
                let rows = UInt16(clamping: values[0...3].reduce(0) { ($0 << 8) | Int($1) })
                let columns = UInt16(clamping: values[4...7].reduce(0) { ($0 << 8) | Int($1) })
                var size = winsize(ws_row: rows, ws_col: columns, ws_xpixel: 0, ws_ypixel: 0)
                guard ioctl(masterDescriptor, TIOCSWINSZ, &size) == 0 else {
                    fail("Could not apply the relay terminal size.")
                    return
                }
            case 3:
                guard payloadLength == 0 else {
                    fail("Relay sent a malformed ready frame.")
                    return
                }
                currentState = .ready
            case 4:
                guard payloadLength == 0 else {
                    fail("Relay sent a malformed EOF frame.")
                    return
                }
                socketInput.removeSubrange(0..<frameLength)
                disconnectPeer(nextState: .disconnected)
                return
            case 5:
                let description = String(
                    decoding: socketInput[Self.headerSize..<frameLength],
                    as: UTF8.self
                )
                fail(description.isEmpty ? "Terminal relay reported an error." : description)
                return
            default:
                fail("Relay sent an unknown frame type.")
                return
            }
            socketInput.removeSubrange(0..<frameLength)
        }
    }

    private func writePendingInputToMaster() {
        guard !pendingToMaster.isEmpty else { return }
        let written = pendingToMaster.withUnsafeBytes {
            Darwin.write(masterDescriptor, $0.baseAddress, $0.count)
        }
        if written > 0 {
            pendingToMaster.removeSubrange(0..<written)
        } else if written < 0,
                  errno != EAGAIN,
                  errno != EWOULDBLOCK,
                  errno != EINTR {
            fail("The restored workload PTY rejected relay input.")
        }
    }

    private func readMasterOutput() {
        guard !masterReachedEOF,
              outboundByteCount <= Self.bufferCapacity - Self.dataChunkSize - Self.headerSize else {
            return
        }
        var bytes = [UInt8](repeating: 0, count: Self.dataChunkSize)
        let count = bytes.withUnsafeMutableBytes {
            Darwin.read(masterDescriptor, $0.baseAddress, $0.count)
        }
        if count > 0 {
            enqueueFrame(type: 1, payload: bytes.prefix(count))
        } else if count == 0 || (count < 0 && errno == EIO) {
            masterReachedEOF = true
            enqueueFrame(type: 4, payload: EmptyCollection<UInt8>())
        } else if errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR {
            fail("Could not read the restored workload PTY.")
        }
    }

    private func writeOutputToPeer() {
        guard peerDescriptor >= 0, let frame = outboundFrames.first else { return }
        let written = frame.withUnsafeBytes { buffer -> Int in
            let start = buffer.baseAddress?.advanced(by: outboundFrameOffset)
            return Darwin.write(peerDescriptor, start, buffer.count - outboundFrameOffset)
        }
        if written > 0 {
            outboundFrameOffset += written
            if outboundFrameOffset == frame.count {
                outboundByteCount -= frame.count
                outboundFrames.removeFirst()
                outboundFrameOffset = 0
            }
        } else if written < 0,
                  errno != EAGAIN,
                  errno != EWOULDBLOCK,
                  errno != EINTR {
            disconnectAfterTransportEnded()
        }
    }

    private func enqueueFrame<C: Collection>(type: UInt8, payload: C) where C.Element == UInt8 {
        let payloadCount = payload.count
        var frame = Data(capacity: Self.headerSize + payloadCount)
        frame.append(type)
        frame.append(UInt8(truncatingIfNeeded: payloadCount >> 24))
        frame.append(UInt8(truncatingIfNeeded: payloadCount >> 16))
        frame.append(UInt8(truncatingIfNeeded: payloadCount >> 8))
        frame.append(UInt8(truncatingIfNeeded: payloadCount))
        frame.append(contentsOf: payload)
        outboundFrames.append(frame)
        outboundByteCount += frame.count
    }

    private func disconnectPeer(
        nextState: TerminalPresentationSessionRegistry.PresentationState
    ) {
        if peerDescriptor >= 0 {
            Darwin.close(peerDescriptor)
            peerDescriptor = -1
        }
        socketInput.removeAll(keepingCapacity: true)
        // Replaying a partially written frame can duplicate a prefix, but never silently drops
        // bytes. A future acknowledged frame protocol can remove that ambiguity.
        outboundFrameOffset = 0
        if !isClosed { currentState = nextState }
    }

    private func disconnectAfterTransportEnded() {
        let nextState: TerminalPresentationSessionRegistry.PresentationState =
            socketInput.isEmpty
                ? .disconnected
                : .failed("Terminal relay disconnected in the middle of a frame.")
        disconnectPeer(nextState: nextState)
    }

    private func fail(_ description: String) {
        disconnectPeer(nextState: .failed(description))
        currentState = .failed(description)
    }

    private static func makeNonblockingAndCloseOnExec(_ descriptor: Int32) throws {
        let flags = fcntl(descriptor, F_GETFL)
        let descriptorFlags = fcntl(descriptor, F_GETFD)
        guard flags >= 0,
              descriptorFlags >= 0,
              fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0,
              fcntl(descriptor, F_SETFD, descriptorFlags | FD_CLOEXEC) == 0 else {
            throw TerminalPresentationSessionRegistry.RegistryError.posix(
                operation: "fcntl",
                code: errno
            )
        }
    }

    private static func socketAddress(_ path: String) throws -> sockaddr_un {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8) + [0]
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
            throw TerminalPresentationSessionRegistry.RegistryError.socketPathTooLong
        }
        withUnsafeMutableBytes(of: &address.sun_path) { destination in
            destination.copyBytes(from: bytes)
        }
        return address
    }
}
