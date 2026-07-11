import ContinuumRuntime
import Darwin
import Dispatch
import Foundation

enum ExternalHotProof {
    static let minimumCycleCount = 100
    private static let fullProcessCycleCount = 1
    private static let fullProcessCaptureBudget: UInt64 = 512 * 1_024 * 1_024

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

        // Exercise the command, JSON, allocator, and reply paths before the
        // first full-process cut. A production compatibility probe must reach
        // a stable VM topology before publishing a restorable checkpoint.
        for pass in 1...8 {
            let warmB = try target.send(command: "mutate", state: "B")
            try require(
                warmB.state == "B",
                "target warm-up \(pass) did not enter state B"
            )
            let checkedB = try target.send(command: "validate", state: "B")
            try require(
                checkedB.valid == true,
                "target warm-up \(pass) did not validate state B"
            )
            let warmA = try target.send(command: "mutate", state: "A")
            try require(
                warmA.state == "A",
                "target warm-up \(pass) did not return to state A"
            )
            let checkedA = try target.send(command: "validate", state: "A")
            try require(
                checkedA.valid == true,
                "target warm-up \(pass) did not validate state A"
            )
        }
        usleep(100_000)

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
        usleep(100_000)

        let safetyB = try capture(session: session, expectedAddress: address, expectedLength: length)
        try require(stateA.bytes != safetyB.bytes, "target mutation did not change captured bytes")
        try require(safetyB.digest == mutated.digest, "captured safety B differs from target state")
        try require(
            stateA.descriptor.thread_set_hash == safetyB.descriptor.thread_set_hash,
            "target thread set changed between A and safety B captures"
        )
        // Establish both whole-process images from one stable VM topology. The
        // target command above supplies real target-owned B bytes; the runtime
        // then moves only the registered arena between A and B while the target
        // remains parked, avoiding transient Foundation allocator mappings.
        try restore(stateA, into: session, label: "staging A", cycle: 0)
        var resourceStateA = try captureResources(session: session)
        let processStateAStart = DispatchTime.now().uptimeNanoseconds
        let processStateA = try captureProcess(session: session)
        progress(
            "full-process A snapshot: \(milliseconds(since: processStateAStart)) ms"
        )
        defer { continuum_remote_process_snapshot_destroy(processStateA.snapshot) }

        try restore(safetyB, into: session, label: "staging B", cycle: 0)
        var resourceSafetyB = try captureResources(session: session)
        let processSafetyBStart = DispatchTime.now().uptimeNanoseconds
        let processSafetyB = try captureProcess(session: session)
        progress(
            "full-process B snapshot: \(milliseconds(since: processSafetyBStart)) ms"
        )
        defer { continuum_remote_process_snapshot_destroy(processSafetyB.snapshot) }

        if processStateA.info.vm_layout_hash != processSafetyB.info.vm_layout_hash {
            let difference = try processLayoutDifference(processStateA, processSafetyB)
            throw ExternalHotProofFailure.invariant(
                "target VM layout changed between full-process captures "
                    + "(A captured=\(processStateA.info.captured_region_count)/\(processStateA.info.captured_bytes), "
                    + "excluded=\(processStateA.info.excluded_region_count)/\(processStateA.info.excluded_bytes); "
                    + "B captured=\(processSafetyB.info.captured_region_count)/\(processSafetyB.info.captured_bytes), "
                    + "excluded=\(processSafetyB.info.excluded_region_count)/\(processSafetyB.info.excluded_bytes); "
                    + difference + ")"
            )
        }
        try require(
            processStateA.info.thread_set_hash == processSafetyB.info.thread_set_hash,
            "target thread set changed between full-process captures"
        )
        let resourceChanges = continuum_remote_resource_fingerprint_changes(
            &resourceStateA,
            &resourceSafetyB
        )
        try require(
            resourceChanges == UInt32(CONTINUUM_RESOURCE_CHANGE_NONE.rawValue),
            "target kernel resources changed between full-process captures: "
                + resourceChangeDescription(resourceChanges)
        )

        for cycle in 1...fullProcessCycleCount {
            try restoreProcess(processStateA, into: session, label: "A", cycle: cycle)
            try validate(target: target, expected: "A", digest: stateA.digest, cycle: cycle)

            try restoreProcess(processSafetyB, into: session, label: "B", cycle: cycle)
            try validate(target: target, expected: "B", digest: safetyB.digest, cycle: cycle)
        }

        for cycle in 1...cycles {
            try restore(stateA, into: session, label: "A", cycle: cycle)
            try validate(target: target, expected: "A", digest: stateA.digest, cycle: cycle)

            try restore(safetyB, into: session, label: "B", cycle: cycle)
            try validate(target: target, expected: "B", digest: safetyB.digest, cycle: cycle)
        }

        let opened = try target.send(command: "open-resource")
        try require(
            opened.event == "resource-opened",
            "target did not open the descriptor-change probe"
        )
        try verifyDescriptorMutationIsRejected(
            processSafetyB,
            by: session
        )
        try validate(
            target: target,
            expected: "B",
            digest: safetyB.digest,
            cycle: cycles + 1
        )
        let closed = try target.send(command: "close-resource")
        try require(
            closed.event == "resource-closed",
            "target did not close the descriptor-change probe"
        )

        try target.exitCleanly()
        exitedCleanly = true

        print("external-hot-proof: PASS")
        print("  target binary:       \(target.executablePath)")
        print("  target PID:          \(targetPID)")
        print("  registered arena:    0x\(String(address, radix: 16)) + \(length) bytes")
        print("  captured threads:    A=\(stateA.threadCount), B=\(safetyB.threadCount)")
        print("  full VM regions:     \(processStateA.info.captured_region_count)")
        print("  full captured bytes: \(processStateA.info.captured_bytes)")
        print("  excluded VM regions: \(processStateA.info.excluded_region_count)")
        print(
            "  kernel resources:    \(resourceSummary(resourceStateA))"
        )
        print("  resource A->B gate:  unchanged")
        print("  descriptor mutation: rejected before memory write")
        print("  restore cycles:      \(fullProcessCycleCount) full-process + \(cycles) arena-only")
        print(
            "  verified restores:   \((fullProcessCycleCount + cycles) * 2) (target-owned validation)"
        )
        print("  safety state B was captured before the first rewind and restored last")
    }

    private static func verifyDescriptorMutationIsRejected(
        _ capture: RemoteProcessCapture,
        by session: OpaquePointer
    ) throws {
        var report = continuum_remote_process_restore_report()
        let status = continuum_remote_session_restore_process(
            session,
            capture.snapshot,
            &report
        )
        try require(
            status == CONTINUUM_STATUS_DESCRIPTOR_TABLE_CHANGED,
            "descriptor-change restore returned \(runtimeStatusDescription(status))"
        )
        try require(
            report.bytes_written == 0
                && report.thread_states_restored == 0
                && report.rollback_attempted == 0,
            "descriptor-change guard modified the target before rejecting restore"
        )
    }

    private static func captureResources(
        session: OpaquePointer
    ) throws -> continuum_remote_resource_fingerprint {
        var fingerprint = continuum_remote_resource_fingerprint()
        try check(
            continuum_remote_session_capture_resource_fingerprint(
                session,
                &fingerprint
            ),
            operation: "capture external target kernel-resource fingerprint"
        )
        try require(
            fingerprint.file_descriptor_count > 0,
            "resource fingerprint contained no file descriptors"
        )
        try require(
            fingerprint.descriptor_table_hash != 0,
            "resource fingerprint contained no descriptor hash"
        )
        try require(
            fingerprint.mach_name_count > 0 && fingerprint.mach_space_hash != 0,
            "resource fingerprint contained no Mach namespace"
        )
        try require(
            fingerprint.thread_count > 0 && fingerprint.thread_set_hash != 0,
            "resource fingerprint contained no thread set"
        )
        return fingerprint
    }

    private static func resourceSummary(
        _ fingerprint: continuum_remote_resource_fingerprint
    ) -> String {
        "fd=\(fingerprint.file_descriptor_count) "
            + "vnode=\(fingerprint.vnode_count) "
            + "socket=\(fingerprint.socket_count) "
            + "pipe=\(fingerprint.pipe_count) "
            + "kqueue=\(fingerprint.kqueue_count) "
            + "mach=\(fingerprint.mach_name_count) "
            + "threads=\(fingerprint.thread_count) "
            + "unsupported=\(fingerprint.unsupported_descriptor_count)"
    }

    private static func resourceChangeDescription(_ changes: UInt32) -> String {
        var names: [String] = []
        if changes & UInt32(CONTINUUM_RESOURCE_CHANGE_DESCRIPTOR_TABLE.rawValue) != 0 {
            names.append("descriptor table")
        }
        if changes & UInt32(CONTINUUM_RESOURCE_CHANGE_MACH_SPACE.rawValue) != 0 {
            names.append("Mach namespace")
        }
        if changes & UInt32(CONTINUUM_RESOURCE_CHANGE_THREAD_SET.rawValue) != 0 {
            names.append("thread set")
        }
        if changes
            & UInt32(CONTINUUM_RESOURCE_CHANGE_UNSUPPORTED_DESCRIPTOR.rawValue) != 0
        {
            names.append("unsupported descriptor")
        }
        return names.isEmpty ? "none" : names.joined(separator: ", ")
    }

    private static func captureProcess(session: OpaquePointer) throws -> RemoteProcessCapture {
        var snapshot: OpaquePointer?
        var info = continuum_remote_process_snapshot_info()
        try check(
            continuum_remote_session_capture_process(
                session,
                fullProcessCaptureBudget,
                &snapshot,
                &info
            ),
            operation: "capture full external process"
        )
        guard let snapshot else {
            throw ExternalHotProofFailure.invariant(
                "runtime returned a nil full-process snapshot"
            )
        }
        try require(info.captured_region_count > 0, "full-process capture had no regions")
        try require(info.captured_bytes > 0, "full-process capture had no bytes")
        try require(info.thread_count > 0, "full-process capture had no threads")
        try require(info.vm_layout_hash != 0, "full-process capture had no VM hash")
        try require(info.thread_set_hash != 0, "full-process capture had no thread hash")
        return RemoteProcessCapture(snapshot: snapshot, info: info)
    }

    private static func processLayoutDifference(
        _ left: RemoteProcessCapture,
        _ right: RemoteProcessCapture
    ) throws -> String {
        func regions(
            _ capture: RemoteProcessCapture
        ) throws -> [UInt64: continuum_remote_process_region_info] {
            let count = continuum_remote_process_snapshot_region_count(capture.snapshot)
            var result: [UInt64: continuum_remote_process_region_info] = [:]
            for index in 0..<count {
                var info = continuum_remote_process_region_info()
                try check(
                    continuum_remote_process_snapshot_region_info(
                        capture.snapshot,
                        index,
                        &info
                    ),
                    operation: "inspect full-process region \(index)"
                )
                result[info.address] = info
            }
            return result
        }

        let leftRegions = try regions(left)
        let rightRegions = try regions(right)
        let addresses = Set(leftRegions.keys).union(rightRegions.keys).sorted()
        var changes: [String] = []
        for address in addresses {
            let a = leftRegions[address]
            let b = rightRegions[address]
            guard
                a?.length != b?.length
                    || a?.protection != b?.protection
                    || a?.maximum_protection != b?.maximum_protection
                    || a?.inheritance != b?.inheritance
                    || a?.share_mode != b?.share_mode
                    || a?.user_tag != b?.user_tag
            else { continue }
            let aText =
                a.map {
                    "A=\($0.length)b/p\($0.protection)/m\($0.maximum_protection)"
                        + "/i\($0.inheritance)/s\($0.share_mode)/tag\($0.user_tag)"
                } ?? "A=missing"
            let bText =
                b.map {
                    "B=\($0.length)b/p\($0.protection)/m\($0.maximum_protection)"
                        + "/i\($0.inheritance)/s\($0.share_mode)/tag\($0.user_tag)"
                } ?? "B=missing"
            changes.append("0x\(String(address, radix: 16)) \(aText) \(bText)")
            if changes.count == 8 { break }
        }
        return changes.isEmpty
            ? "eligible regions match; an excluded mapping changed" : changes.joined(separator: ", ")
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

    private static func restoreProcess(
        _ capture: RemoteProcessCapture,
        into session: OpaquePointer,
        label: String,
        cycle: Int
    ) throws {
        let started = DispatchTime.now().uptimeNanoseconds
        var report = continuum_remote_process_restore_report()
        try check(
            continuum_remote_session_restore_process(
                session,
                capture.snapshot,
                &report
            ),
            operation: "restore full process \(label) on cycle \(cycle)"
        )
        try require(
            report.regions_written > 0
                && report.regions_written <= capture.info.captured_region_count,
            "full-process restore \(label) on cycle \(cycle) reported invalid dirty-region coverage"
        )
        try require(
            report.bytes_written > 0
                && report.bytes_written <= capture.info.captured_bytes,
            "full-process restore \(label) on cycle \(cycle) reported invalid dirty-page bytes"
        )
        try require(
            report.thread_states_restored == capture.info.thread_count,
            "full-process restore \(label) on cycle \(cycle) missed a thread"
        )
        try require(
            report.memory_readback_verified == 1,
            "full-process restore \(label) on cycle \(cycle) lacked readback verification"
        )
        try require(
            report.rollback_attempted == 0,
            "full-process restore \(label) on cycle \(cycle) unexpectedly needed rollback"
        )
        progress(
            "full-process restore \(label) cycle \(cycle): "
                + "\(milliseconds(since: started)) ms, \(report.bytes_written) dirty bytes"
        )
    }

    private static func milliseconds(since start: UInt64) -> UInt64 {
        (DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
    }

    private static func progress(_ message: String) {
        print(message)
        fflush(stdout)
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
            let detail = runtimeStatusDescription(status)
            throw ExternalHotProofFailure.runtime(operation: operation, status: detail)
        }
    }

    private static func runtimeStatusDescription(_ status: continuum_status) -> String {
        continuum_status_string(status).map(String.init(cString:))
            ?? String(describing: status)
    }

    private static func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        guard condition() else { throw ExternalHotProofFailure.invariant(message) }
    }

    private static func digest(_ data: Data) -> String {
        var value: UInt64 = 0xcbf2_9ce4_8422_2325
        for byte in data {
            value ^= UInt64(byte)
            value &*= 0x100_0000_01b3
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

private struct RemoteProcessCapture {
    let snapshot: OpaquePointer
    let info: continuum_remote_process_snapshot_info
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
        let deadline =
            DispatchTime.now().uptimeNanoseconds
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
        case .invariant(let message):
            "External hot proof failed: \(message)."
        case .protocolViolation(let message):
            "External target protocol violation: \(message)."
        case .runtime(let operation, let status):
            "External runtime operation '\(operation)' failed with status \(status). "
                + "No SIP or task-access bypass was attempted."
        case .target(let message):
            "External target failed: \(message)."
        }
    }
}
