import ContinuumRuntime
import Darwin
import Dispatch
import Foundation

enum ExternalHotProof {
    static let minimumCycleCount = 100

    static func run(targetPath: String, cycles: Int) throws {
        guard cycles >= minimumCycleCount else {
            throw HarnessFailure.usage(
                "external-hot-proof requires at least \(minimumCycleCount) cycles; received \(cycles)."
            )
        }

        let target = try ExternalTargetProcess(executablePath: targetPath)
        var exitedCleanly = false
        defer {
            if !exitedCleanly {
                target.stopAfterFailure()
            }
        }

        let ready = try target.launch()
        try require(ready.event == "ready", "target did not send the ready handshake")
        try require(ready.protocolVersion == 1, "target uses an unsupported protocol version")

        guard let targetPID = ready.processIdentifier,
              targetPID == target.processIdentifier,
              let address = ready.address,
              let length = ready.length,
              length > 0
        else {
            throw ExternalHotProofFailure.protocolViolation(
                "ready handshake did not identify the launched process and arena"
            )
        }
        try require(ready.state == "A", "target did not start in state A")
        try require(
            address % UInt64(Int(sysconf(_SC_PAGESIZE))) == 0,
            "target arena is not page-aligned"
        )

        var session: OpaquePointer?
        try check(
            continuum_remote_session_open(targetPID, &session),
            operation: "open task session for PID \(targetPID)"
        )
        guard let session else {
            throw ExternalHotProofFailure.invariant("runtime returned a nil remote session")
        }
        defer { continuum_remote_session_destroy(session) }

        try check(
            continuum_remote_session_register_region(session, address, UInt64(length)),
            operation: "register target arena"
        )

        let stateA = try capture(session: session, expectedAddress: address, expectedLength: length)
        try require(stateA.digest == ready.digest, "captured A bytes differ from target handshake")

        let mutated = try target.send(command: "mutate", state: "B")
        try require(mutated.event == "mutated", "target did not acknowledge mutation to B")
        try require(mutated.state == "B", "target did not enter state B")

        let safetyB = try capture(session: session, expectedAddress: address, expectedLength: length)
        try require(stateA.bytes != safetyB.bytes, "target mutation did not change captured bytes")
        try require(safetyB.digest == mutated.digest, "captured safety B differs from target state")
        try require(
            stateA.descriptor.thread_set_hash == safetyB.descriptor.thread_set_hash,
            "target thread set changed between A and safety B captures"
        )

        for cycle in 1...cycles {
            try restore(stateA, into: session, label: "A", cycle: cycle)
            try validate(target: target, expected: "A", digest: stateA.digest, cycle: cycle)

            try restore(safetyB, into: session, label: "B", cycle: cycle)
            try validate(target: target, expected: "B", digest: safetyB.digest, cycle: cycle)
        }

        try target.exitCleanly()
        exitedCleanly = true

        print("external-hot-proof: PASS")
        print("  target binary:       \(target.executablePath)")
        print("  target PID:          \(targetPID)")
        print("  registered arena:    0x\(String(address, radix: 16)) + \(length) bytes")
        print("  captured threads:    A=\(stateA.threadCount), B=\(safetyB.threadCount)")
        print("  restore cycles:      \(cycles)")
        print("  verified restores:   \(cycles * 2) (target-owned byte validation)")
        print("  safety state B was captured before the first rewind and restored last")
    }

    private static func capture(
        session: OpaquePointer,
        expectedAddress: UInt64,
        expectedLength: Int
    ) throws -> RemoteCapture {
        var descriptor = continuum_remote_region_descriptor()
        var ownedBytes = continuum_owned_buffer()
        var threadSnapshot: OpaquePointer?
        defer {
            continuum_owned_buffer_destroy(&ownedBytes)
            if let threadSnapshot {
                continuum_remote_thread_snapshot_destroy(threadSnapshot)
            }
        }

        try check(
            continuum_remote_session_capture(
                session,
                &descriptor,
                &ownedBytes,
                &threadSnapshot
            ),
            operation: "capture external target"
        )

        guard descriptor.address == expectedAddress,
              descriptor.length == UInt64(expectedLength),
              descriptor.mapping_address <= expectedAddress,
              expectedAddress - descriptor.mapping_address <= descriptor.mapping_length,
              UInt64(expectedLength)
                <= descriptor.mapping_length - (expectedAddress - descriptor.mapping_address),
              ownedBytes.length == expectedLength,
              let bytePointer = ownedBytes.bytes,
              let threadSnapshot
        else {
            throw ExternalHotProofFailure.invariant(
                "runtime capture did not return the registered arena and thread evidence"
            )
        }

        let threadCount = continuum_remote_thread_snapshot_count(threadSnapshot)
        try require(threadCount > 0, "capture contained no target thread evidence")
        for index in 0..<threadCount {
            var info = continuum_remote_thread_state_info()
            try check(
                continuum_remote_thread_snapshot_info(threadSnapshot, index, &info),
                operation: "inspect captured thread \(index)"
            )
            try require(
                info.general_state_length > 0,
                "captured thread \(index) has no general register state"
            )
        }

        let bytes = Data(bytes: bytePointer, count: ownedBytes.length)
        return RemoteCapture(
            descriptor: descriptor,
            bytes: bytes,
            digest: digest(bytes),
            threadCount: threadCount
        )
    }

    private static func restore(
        _ capture: RemoteCapture,
        into session: OpaquePointer,
        label: String,
        cycle: Int
    ) throws {
        var descriptor = capture.descriptor
        var report = continuum_remote_restore_report()
        let status = capture.bytes.withUnsafeBytes { bytes in
            continuum_remote_session_restore(
                session,
                &descriptor,
                bytes.baseAddress,
                bytes.count,
                &report
            )
        }
        try check(status, operation: "restore \(label) on cycle \(cycle)")
        try require(
            report.bytes_written == UInt64(capture.bytes.count),
            "restore \(label) on cycle \(cycle) reported a short write"
        )
        try require(
            report.readback_verified == 1,
            "restore \(label) on cycle \(cycle) lacked runtime readback verification"
        )
        try require(
            report.rollback_attempted == 0,
            "restore \(label) on cycle \(cycle) unexpectedly needed rollback"
        )
    }

    private static func validate(
        target: ExternalTargetProcess,
        expected: String,
        digest: String,
        cycle: Int
    ) throws {
        let reply = try target.send(command: "validate", state: expected)
        try require(reply.event == "validated", "target did not validate cycle \(cycle)")
        try require(reply.valid == true, "target rejected state \(expected) on cycle \(cycle)")
        try require(reply.state == expected, "target observed the wrong state on cycle \(cycle)")
        try require(
            reply.digest == digest,
            "target digest differed after restoring \(expected) on cycle \(cycle)"
        )
    }

    private static func check(_ status: continuum_status, operation: String) throws {
        guard status == CONTINUUM_STATUS_OK else {
            let detail = continuum_status_string(status).map(String.init(cString:))
                ?? String(describing: status)
            throw ExternalHotProofFailure.runtime(operation: operation, status: detail)
        }
    }

    private static func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        guard condition() else { throw ExternalHotProofFailure.invariant(message) }
    }

    private static func digest(_ data: Data) -> String {
        var value: UInt64 = 0xcbf29ce484222325
        for byte in data {
            value ^= UInt64(byte)
            value &*= 0x100000001b3
        }
        return String(format: "%016llx", value)
    }
}

private struct RemoteCapture {
    var descriptor: continuum_remote_region_descriptor
    let bytes: Data
    let digest: String
    let threadCount: Int
}

private final class ExternalTargetProcess {
    private static let replyTimeoutNanoseconds: UInt64 = 5_000_000_000
    private static let exitTimeoutSeconds: TimeInterval = 2

    let executablePath: String

    private let process = Process()
    private let standardInput = Pipe()
    private let standardOutput = Pipe()
    private let standardError = Pipe()
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private var launched = false
    private var finished = false

    var processIdentifier: Int32 { process.processIdentifier }

    init(executablePath: String) throws {
        let expanded = NSString(string: executablePath).expandingTildeInPath
        let url = URL(fileURLWithPath: expanded).standardizedFileURL
        var isDirectory = ObjCBool(false)
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory),
              !isDirectory.boolValue,
              FileManager.default.isExecutableFile(atPath: url.path)
        else {
            throw ExternalHotProofFailure.target(
                "target is not an executable file: \(url.path)"
            )
        }

        self.executablePath = url.path
        encoder.outputFormatting = [.sortedKeys]
        process.executableURL = url
        process.standardInput = standardInput
        process.standardOutput = standardOutput
        process.standardError = standardError
    }

    func launch() throws -> TargetReply {
        do {
            try process.run()
            launched = true
            return try readReply()
        } catch let error as ExternalHotProofFailure {
            throw error
        } catch {
            throw ExternalHotProofFailure.target(
                "could not launch exact target binary \(executablePath): \(error.localizedDescription)"
            )
        }
    }

    func send(command: String, state: String? = nil) throws -> TargetReply {
        guard launched, !finished else {
            throw ExternalHotProofFailure.target("target is not running")
        }

        var data = try encoder.encode(TargetCommand(command: command, state: state))
        data.append(0x0A)
        do {
            try standardInput.fileHandleForWriting.write(contentsOf: data)
        } catch {
            throw ExternalHotProofFailure.target(
                "could not send \(command) to target: \(error.localizedDescription)"
            )
        }
        return try readReply()
    }

    func exitCleanly() throws {
        let reply = try send(command: "exit")
        guard reply.event == "exiting" else {
            throw ExternalHotProofFailure.protocolViolation("target did not acknowledge exit")
        }
        try? standardInput.fileHandleForWriting.close()
        guard waitForExit(timeout: Self.exitTimeoutSeconds) else {
            if process.isRunning {
                kill(process.processIdentifier, SIGKILL)
                _ = waitForExit(timeout: Self.exitTimeoutSeconds)
            }
            finished = !process.isRunning
            throw ExternalHotProofFailure.target(
                "cooperative target did not exit within \(Int(Self.exitTimeoutSeconds)) seconds"
            )
        }
        finished = true

        guard process.terminationReason == .exit, process.terminationStatus == EXIT_SUCCESS else {
            throw ExternalHotProofFailure.target(terminationDescription())
        }
    }

    func stopAfterFailure() {
        guard launched, !finished else { return }
        try? standardInput.fileHandleForWriting.close()
        if process.isRunning {
            process.terminate()
        }
        if !waitForExit(timeout: Self.exitTimeoutSeconds), process.isRunning {
            kill(process.processIdentifier, SIGKILL)
            _ = waitForExit(timeout: Self.exitTimeoutSeconds)
        }
        finished = !process.isRunning
    }

    private func readReply() throws -> TargetReply {
        var line = Data()
        let deadline = DispatchTime.now().uptimeNanoseconds
            &+ Self.replyTimeoutNanoseconds
        while line.count <= 1_048_576 {
            try waitForProtocolData(until: deadline)
            let chunk = try standardOutput.fileHandleForReading.read(upToCount: 1) ?? Data()
            guard !chunk.isEmpty else {
                if !process.isRunning {
                    process.waitUntilExit()
                    finished = true
                }
                throw ExternalHotProofFailure.target(terminationDescription())
            }
            if chunk.first == 0x0A {
                break
            }
            line.append(chunk)
        }

        guard line.count <= 1_048_576 else {
            throw ExternalHotProofFailure.protocolViolation("target reply exceeded 1 MiB")
        }

        let reply: TargetReply
        do {
            reply = try decoder.decode(TargetReply.self, from: line)
        } catch {
            throw ExternalHotProofFailure.protocolViolation(
                "target sent invalid JSON: \(error.localizedDescription)"
            )
        }
        if reply.event == "error" {
            throw ExternalHotProofFailure.target(reply.error ?? "target reported an unknown error")
        }
        return reply
    }

    private func waitForProtocolData(until deadline: UInt64) throws {
        let fileDescriptor = standardOutput.fileHandleForReading.fileDescriptor

        while true {
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else {
                throw ExternalHotProofFailure.target(
                    "cooperative target protocol timed out after 5 seconds"
                )
            }

            let remainingNanoseconds = deadline - now
            let remainingMilliseconds = max(
                1,
                min(
                    Int64(Int32.max),
                    Int64((remainingNanoseconds + 999_999) / 1_000_000)
                )
            )
            var descriptor = pollfd(
                fd: fileDescriptor,
                events: Int16(POLLIN | POLLHUP | POLLERR),
                revents: 0
            )
            let result = poll(&descriptor, 1, Int32(remainingMilliseconds))
            if result > 0 {
                return
            }
            if result == 0 {
                throw ExternalHotProofFailure.target(
                    "cooperative target protocol timed out after 5 seconds"
                )
            }
            if errno != EINTR {
                throw ExternalHotProofFailure.target(
                    "could not wait for cooperative target output: errno \(errno)"
                )
            }
        }
    }

    private func waitForExit(timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning, Date() < deadline {
            usleep(10_000)
        }
        guard !process.isRunning else { return false }
        process.waitUntilExit()
        return true
    }

    private func terminationDescription() -> String {
        guard !process.isRunning else {
            return "cooperative target closed protocol output while it was still running"
        }
        process.waitUntilExit()
        let errorData = standardError.fileHandleForReading.readDataToEndOfFile()
        let errorText = String(data: errorData, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let detail = errorText.flatMap { $0.isEmpty ? nil : $0 } ?? "no stderr output"
        return "target exited with status \(process.terminationStatus): \(detail)"
    }
}

private struct TargetCommand: Encodable {
    let command: String
    let state: String?
}

private struct TargetReply: Decodable {
    let protocolVersion: Int?
    let event: String
    let command: String?
    let processIdentifier: Int32?
    let address: UInt64?
    let length: Int?
    let state: String?
    let counter: UInt64?
    let digest: String?
    let expectedState: String?
    let valid: Bool?
    let error: String?
}

private enum ExternalHotProofFailure: LocalizedError {
    case invariant(String)
    case protocolViolation(String)
    case runtime(operation: String, status: String)
    case target(String)

    var errorDescription: String? {
        switch self {
        case let .invariant(message):
            "External hot proof failed: \(message)."
        case let .protocolViolation(message):
            "External target protocol violation: \(message)."
        case let .runtime(operation, status):
            "External runtime operation '\(operation)' failed with status \(status). "
                + "No SIP or task-access bypass was attempted."
        case let .target(message):
            "External target failed: \(message)."
        }
    }
}
