import ContinuumRuntime
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

    private static func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        guard condition() else { throw HarnessFailure.invariant(message) }
    }
}
