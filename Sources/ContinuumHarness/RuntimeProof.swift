import ContinuumRuntime
import Darwin
import Foundation

enum RuntimeProof {
    static func inspect() throws {
        let info = try runtimeInfo()

        print("ContinuumRuntime self-inspection")
        print("page size:          \(info.page_size) bytes")
        print("VM regions:         \(info.region_count)")
        print("  readable:         \(info.readable_region_count)")
        print("  writable:         \(info.writable_region_count)")
        print("  executable:       \(info.executable_region_count)")
        print("virtual bytes:      \(info.virtual_bytes)")
        print("writable bytes:     \(info.writable_bytes)")
        print("threads:            \(info.thread_count)")
    }

    static func runMemoryProof() throws {
        let info = try runtimeInfo()
        let pageSize = max(Int(info.page_size), 4_096)
        let trackedBytes = pageSize * 4
        let address = UnsafeMutableRawPointer.allocate(
            byteCount: trackedBytes,
            alignment: pageSize
        )
        defer { address.deallocate() }

        let bytes = address.bindMemory(to: UInt8.self, capacity: trackedBytes)
        for index in 0..<trackedBytes {
            bytes[index] = UInt8(truncatingIfNeeded: index &* 31 &+ 7)
        }
        let original = Data(bytes: address, count: trackedBytes)

        var region: OpaquePointer?
        try check(
            continuum_tracked_region_create(address, trackedBytes, &region),
            operation: "create tracked region"
        )
        guard let region else {
            throw HarnessFailure.invariant("runtime returned a nil tracked region")
        }
        defer { continuum_tracked_region_destroy(region) }

        var originalCheckpoint: UInt64 = 0
        try check(
            continuum_tracked_region_checkpoint(region, &originalCheckpoint),
            operation: "checkpoint original bytes"
        )

        for index in 0..<trackedBytes {
            bytes[index] ^= 0xA5
        }
        let mutated = Data(bytes: address, count: trackedBytes)
        try require(mutated != original, "mutation did not change the tracked bytes")

        var mutatedCheckpoint: UInt64 = 0
        try check(
            continuum_tracked_region_checkpoint(region, &mutatedCheckpoint),
            operation: "checkpoint mutated bytes"
        )
        try require(mutatedCheckpoint != originalCheckpoint, "runtime reused a checkpoint identifier")
        try require(
            continuum_tracked_region_checkpoint_count(region) == 2,
            "runtime did not retain both checkpoints"
        )

        try check(
            continuum_tracked_region_restore(region, originalCheckpoint),
            operation: "restore original checkpoint"
        )
        try require(
            Data(bytes: address, count: trackedBytes) == original,
            "restored memory differs from the checkpoint byte for byte"
        )

        try check(
            continuum_tracked_region_restore(region, mutatedCheckpoint),
            operation: "restore mutated checkpoint"
        )
        try require(
            Data(bytes: address, count: trackedBytes) == mutated,
            "forward restoration differs from the mutated checkpoint"
        )

        try check(
            continuum_tracked_region_restore(region, originalCheckpoint),
            operation: "return to original checkpoint"
        )

        print("memory-proof: PASS")
        print("  tracked bytes:       \(trackedBytes)")
        print("  original checkpoint: \(originalCheckpoint)")
        print("  mutated checkpoint:  \(mutatedCheckpoint)")
        print("  byte-for-byte restore verified in both directions")
    }

    static func runDescriptorFlagsProof(
        targetPath: String,
        bootstrapPath: String
    ) throws {
        guard FileManager.default.isExecutableFile(atPath: targetPath) else {
            throw HarnessFailure.usage("Target is not executable: \(targetPath)")
        }
        guard FileManager.default.fileExists(atPath: bootstrapPath) else {
            throw HarnessFailure.usage("Bootstrap does not exist: \(bootstrapPath)")
        }

        // Both pipe endpoints are inherited by the target, so descriptor-graph
        // certification sees a closed resource instead of an external peer.
        let channel = Pipe()
        let readDescriptor = channel.fileHandleForReading.fileDescriptor
        let expectedStatusFlags = fcntl(readDescriptor, F_GETFL)
        try require(expectedStatusFlags >= 0, "could not inspect proof pipe flags")

        let process = Process()
        process.executableURL = URL(fileURLWithPath: targetPath)
        process.arguments = ["--continuum-idle-child"]
        var environment = ProcessInfo.processInfo.environment
        environment["DYLD_INSERT_LIBRARIES"] = bootstrapPath
        environment["CONTINUUM_ENABLE_CHECKPOINT_SAFEPOINTS"] = "1"
        process.environment = environment
        process.standardInput = channel.fileHandleForReading
        process.standardOutput = channel.fileHandleForWriting
        process.standardError = channel.fileHandleForWriting
        try process.run()
        defer {
            _ = kill(process.processIdentifier, SIGUSR1)
            if process.isRunning {
                process.terminate()
                process.waitUntilExit()
            }
        }

        let bootstrapDeadline = Date().addingTimeInterval(5)
        var hasBootstrap: UInt8 = 0
        repeat {
            _ = bootstrapPath.withCString { path in
                continuum_remote_process_has_bootstrap(
                    process.processIdentifier,
                    path,
                    &hasBootstrap
                )
            }
            if hasBootstrap == 0 { usleep(10_000) }
        } while hasBootstrap == 0 && Date() < bootstrapDeadline
        try require(hasBootstrap == 1, "target did not load the authenticated bootstrap")
        // Dyld image visibility can precede the bootstrap constructor that
        // installs the SIGUSR2 handler. Match the proven CLI test's bounded
        // constructor-settle window so SIGUSR2 cannot take its default action.
        usleep(100_000)
        try require(
            kill(process.processIdentifier, SIGUSR2) == 0,
            "could not request the CLI safepoint"
        )

        var capturedSnapshot: OpaquePointer?
        var capturedGraph: OpaquePointer?
        var lastCaptureStatus = CONTINUUM_STATUS_INVALID_ARGUMENT
        var lastGraphStatus = CONTINUUM_STATUS_INVALID_ARGUMENT
        let captureDeadline = Date().addingTimeInterval(5)
        repeat {
            usleep(25_000)
            var snapshot: OpaquePointer?
            var information = continuum_remote_process_group_snapshot_info()
            let captureStatus = continuum_remote_process_group_capture(
                process.processIdentifier,
                1024 * 1024 * 1024,
                &snapshot,
                &information
            )
            lastCaptureStatus = captureStatus
            guard captureStatus == CONTINUUM_STATUS_OK, let snapshot else {
                continue
            }
            var graph: OpaquePointer?
            let graphStatus = bootstrapPath.withCString { path in
                continuum_remote_process_group_capture_descriptor_graph_authenticated(
                    snapshot,
                    path,
                    &graph
                )
            }
            lastGraphStatus = graphStatus
            if graphStatus == CONTINUUM_STATUS_OK, let graph {
                capturedSnapshot = snapshot
                capturedGraph = graph
            } else {
                if let graph { continuum_remote_descriptor_graph_destroy(graph) }
                continuum_remote_process_group_snapshot_destroy(snapshot)
            }
        } while capturedSnapshot == nil && Date() < captureDeadline

        guard let capturedSnapshot, let capturedGraph else {
            throw HarnessFailure.invariant(
                "target never published an authenticated descriptor safepoint "
                    + "(capture=\(statusText(lastCaptureStatus)), "
                    + "graph=\(statusText(lastGraphStatus)), "
                    + "alive=\(process.isRunning))"
            )
        }
        defer {
            continuum_remote_descriptor_graph_destroy(capturedGraph)
            continuum_remote_process_group_snapshot_destroy(capturedSnapshot)
        }

        let count = continuum_remote_descriptor_graph_handle_count(capturedGraph)
        var handles = Array(
            repeating: continuum_remote_descriptor_handle_info(),
            count: count
        )
        try check(
            handles.withUnsafeMutableBufferPointer { buffer in
                continuum_remote_descriptor_graph_copy_handles(
                    capturedGraph,
                    buffer.baseAddress,
                    buffer.count
                )
            },
            operation: "copy authenticated descriptor handles"
        )
        let matches = handles.filter {
            $0.process_id == process.processIdentifier
                && $0.file_descriptor == STDIN_FILENO
        }
        try require(matches.count == 1, "proof descriptor 0 was not captured once")
        let input = matches[0]
        try require(
            input.resource_kind == CONTINUUM_REMOTE_DESCRIPTOR_RESOURCE_PIPE,
            "proof descriptor 0 was not the expected pipe"
        )
        try require(input.descriptor_flags == 0, "F_GETFD was not captured exactly")
        try require(
            input.status_flags == expectedStatusFlags,
            "F_GETFL was not captured exactly"
        )

        try require(
            kill(process.processIdentifier, SIGUSR1) == 0,
            "could not release the CLI safepoint"
        )
        usleep(50_000)
        var staleGraph: OpaquePointer?
        let staleStatus = bootstrapPath.withCString { path in
            continuum_remote_process_group_capture_descriptor_graph_authenticated(
                capturedSnapshot,
                path,
                &staleGraph
            )
        }
        if let staleGraph { continuum_remote_descriptor_graph_destroy(staleGraph) }
        try require(
            staleStatus == CONTINUUM_STATUS_VALIDATION_FAILED,
            "released descriptor generation was accepted"
        )

        print("descriptor-flags-proof: PASS")
        print("  PID:              \(process.processIdentifier)")
        print("  descriptor:       0 (pipe)")
        print("  F_GETFD:          \(input.descriptor_flags)")
        print("  F_GETFL:          \(input.status_flags)")
        print("  stale generation: rejected")
    }

    private static func runtimeInfo() throws -> continuum_runtime_info {
        var info = continuum_runtime_info()
        try check(
            continuum_runtime_inspect_self(&info),
            operation: "inspect this process"
        )
        return info
    }

    private static func check(_ status: continuum_status, operation: String) throws {
        guard status == CONTINUUM_STATUS_OK else {
            let detail = continuum_status_string(status).map(String.init(cString:))
                ?? String(describing: status)
            throw HarnessFailure.runtime(operation: operation, status: detail)
        }
    }

    private static func statusText(_ status: continuum_status) -> String {
        continuum_status_string(status).map(String.init(cString:))
            ?? String(describing: status)
    }

    private static func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        guard condition() else { throw HarnessFailure.invariant(message) }
    }
}
