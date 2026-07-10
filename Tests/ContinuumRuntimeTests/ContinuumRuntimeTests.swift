import XCTest
import ContinuumRuntime

final class ContinuumRuntimeTests: XCTestCase {
    func testRuntimeInventoryReportsCurrentTask() {
        var info = continuum_runtime_info()
        XCTAssertEqual(continuum_runtime_inspect_self(&info), CONTINUUM_STATUS_OK)
        XCTAssertGreaterThan(info.page_size, 0)
        XCTAssertGreaterThan(info.region_count, 0)
        XCTAssertGreaterThan(info.readable_region_count, 0)
        XCTAssertGreaterThan(info.writable_region_count, 0)
        XCTAssertGreaterThan(info.thread_count, 0)
    }

    func testTrackedMemoryMovesBackwardAndForward() {
        let length = 16_384
        let memory = UnsafeMutableRawPointer.allocate(
            byteCount: length,
            alignment: 16_384
        )
        defer { memory.deallocate() }
        memory.initializeMemory(as: UInt8.self, repeating: 0x11, count: length)

        var region: OpaquePointer?
        XCTAssertEqual(
            continuum_tracked_region_create(memory, length, &region),
            CONTINUUM_STATUS_OK
        )
        guard let region else { return XCTFail("Expected tracked region") }
        defer { continuum_tracked_region_destroy(region) }

        var first: UInt64 = 0
        XCTAssertEqual(
            continuum_tracked_region_checkpoint(region, &first),
            CONTINUUM_STATUS_OK
        )

        memory.initializeMemory(as: UInt8.self, repeating: 0x77, count: length)
        var second: UInt64 = 0
        XCTAssertEqual(
            continuum_tracked_region_checkpoint(region, &second),
            CONTINUUM_STATUS_OK
        )

        memory.initializeMemory(as: UInt8.self, repeating: 0xCC, count: length)
        XCTAssertEqual(
            continuum_tracked_region_restore(region, first),
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(memory.load(as: UInt8.self), 0x11)

        XCTAssertEqual(
            continuum_tracked_region_restore(region, second),
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(memory.load(as: UInt8.self), 0x77)
        XCTAssertEqual(continuum_tracked_region_checkpoint_count(region), 2)
    }

    func testInvalidArgumentsAndMissingCheckpointFailSafely() {
        var info = continuum_runtime_info()
        XCTAssertEqual(
            continuum_runtime_inspect_self(nil),
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
        XCTAssertEqual(continuum_runtime_inspect_self(&info), CONTINUUM_STATUS_OK)

        let memory = UnsafeMutableRawPointer.allocate(byteCount: 32, alignment: 16)
        defer { memory.deallocate() }
        var region: OpaquePointer?
        XCTAssertEqual(
            continuum_tracked_region_create(memory, 32, &region),
            CONTINUUM_STATUS_OK
        )
        guard let region else { return XCTFail("Expected tracked region") }
        defer { continuum_tracked_region_destroy(region) }

        XCTAssertEqual(
            continuum_tracked_region_restore(region, 999),
            CONTINUUM_STATUS_CHECKPOINT_NOT_FOUND
        )
        XCTAssertEqual(
            String(cString: continuum_status_string(CONTINUUM_STATUS_CHECKPOINT_NOT_FOUND)),
            "checkpoint not found"
        )
    }

    func testRepeatedCreateCheckpointDestroy() {
        for value in UInt8(0)..<64 {
            let memory = UnsafeMutableRawPointer.allocate(byteCount: 512, alignment: 16)
            memory.initializeMemory(as: UInt8.self, repeating: value, count: 512)
            var region: OpaquePointer?
            XCTAssertEqual(
                continuum_tracked_region_create(memory, 512, &region),
                CONTINUUM_STATUS_OK
            )
            if let region {
                var identifier: UInt64 = 0
                XCTAssertEqual(
                    continuum_tracked_region_checkpoint(region, &identifier),
                    CONTINUUM_STATUS_OK
                )
                continuum_tracked_region_destroy(region)
            }
            memory.deallocate()
        }
    }
}
