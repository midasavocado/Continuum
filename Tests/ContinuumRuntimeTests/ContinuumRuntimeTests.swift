import XCTest
import ContinuumRuntime
import Darwin

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

    func testRemoteSelfSessionPinsIdentityAndRejectsUnregisteredCapture() {
        var session: OpaquePointer?
        XCTAssertEqual(
            continuum_remote_session_open(getpid(), &session),
            CONTINUUM_STATUS_OK
        )
        guard let session else { return XCTFail("Expected self session") }
        defer { continuum_remote_session_destroy(session) }

        var identity = continuum_remote_identity()
        XCTAssertEqual(
            continuum_remote_session_identity(session, &identity),
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(identity.process_id, getpid())
        XCTAssertGreaterThan(identity.start_seconds, 0)
        XCTAssertGreaterThan(identity.executable_device, 0)
        XCTAssertGreaterThan(identity.executable_inode, 0)

        var descriptor = continuum_remote_region_descriptor()
        var bytes = continuum_owned_buffer()
        var threads: OpaquePointer?
        XCTAssertEqual(
            continuum_remote_session_capture(
                session,
                &descriptor,
                &bytes,
                &threads
            ),
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
        XCTAssertNil(bytes.bytes)
        XCTAssertNil(threads)
    }

    func testResourceFingerprintInventoriesSelfAndClassifiesChanges() {
        var session: OpaquePointer?
        XCTAssertEqual(
            continuum_remote_session_open(getpid(), &session),
            CONTINUUM_STATUS_OK
        )
        guard let session else { return XCTFail("Expected self session") }
        defer { continuum_remote_session_destroy(session) }

        var captured = continuum_remote_resource_fingerprint()
        XCTAssertEqual(
            continuum_remote_session_capture_resource_fingerprint(
                session,
                &captured
            ),
            CONTINUUM_STATUS_OK
        )
        XCTAssertGreaterThanOrEqual(captured.file_descriptor_count, 3)
        XCTAssertGreaterThan(captured.descriptor_table_hash, 0)
        XCTAssertGreaterThan(captured.mach_name_count, 0)
        XCTAssertGreaterThan(captured.mach_space_hash, 0)
        XCTAssertGreaterThan(captured.thread_count, 0)
        XCTAssertGreaterThan(captured.thread_set_hash, 0)

        let descriptorChange = UInt32(
            CONTINUUM_RESOURCE_CHANGE_DESCRIPTOR_TABLE.rawValue
        )
        let machChange = UInt32(CONTINUUM_RESOURCE_CHANGE_MACH_SPACE.rawValue)
        let threadChange = UInt32(CONTINUUM_RESOURCE_CHANGE_THREAD_SET.rawValue)
        let unsupportedChange = UInt32(
            CONTINUUM_RESOURCE_CHANGE_UNSUPPORTED_DESCRIPTOR.rawValue
        )

        var saved = continuum_remote_resource_fingerprint()
        var current = saved
        XCTAssertEqual(
            continuum_remote_resource_fingerprint_changes(&saved, &current),
            UInt32(CONTINUUM_RESOURCE_CHANGE_NONE.rawValue)
        )

        current.descriptor_table_hash = 1
        XCTAssertEqual(
            continuum_remote_resource_fingerprint_changes(&saved, &current),
            descriptorChange
        )
        current = saved
        current.mach_space_hash = 1
        XCTAssertEqual(
            continuum_remote_resource_fingerprint_changes(&saved, &current),
            machChange
        )
        current = saved
        current.thread_set_hash = 1
        XCTAssertEqual(
            continuum_remote_resource_fingerprint_changes(&saved, &current),
            threadChange
        )
        current = saved
        current.unsupported_descriptor_count = 1
        XCTAssertEqual(
            continuum_remote_resource_fingerprint_changes(&saved, &current),
            unsupportedChange
        )

        let allChanges = descriptorChange | machChange | threadChange
            | unsupportedChange
        XCTAssertEqual(
            continuum_remote_resource_fingerprint_changes(nil, &current),
            allChanges
        )
        XCTAssertEqual(
            continuum_remote_session_capture_resource_fingerprint(nil, &captured),
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
        XCTAssertEqual(
            continuum_remote_session_capture_resource_fingerprint(session, nil),
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
    }

    func testProcessGroupAPIsRejectInvalidOrSelfTargets() {
        var snapshot: OpaquePointer?
        var info = continuum_remote_process_group_snapshot_info()
        XCTAssertEqual(
            continuum_remote_process_group_capture(
                getpid(),
                1_024,
                &snapshot,
                &info
            ),
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
        XCTAssertNil(snapshot)
        XCTAssertEqual(continuum_remote_process_group_member_count(nil), 0)

        var member = continuum_remote_process_group_member_info()
        XCTAssertEqual(
            continuum_remote_process_group_copy_member_info(nil, 0, &member),
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
        XCTAssertEqual(
            continuum_remote_process_group_member_region_count(nil, 0),
            0
        )
        var region = continuum_remote_process_region_info()
        XCTAssertEqual(
            continuum_remote_process_group_copy_member_region_info(
                nil,
                0,
                0,
                &region
            ),
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
        var report = continuum_remote_process_group_restore_report()
        XCTAssertEqual(
            continuum_remote_process_group_restore(nil, &report),
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
        XCTAssertEqual(
            continuum_remote_process_group_capture_with_resources(
                getpid(),
                1_024,
                nil,
                nil,
                &snapshot,
                &info
            ),
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
        XCTAssertEqual(
            continuum_remote_process_group_restore_with_resources(
                nil,
                nil,
                nil,
                &report
            ),
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
        var vnodeCount = 0
        XCTAssertEqual(
            continuum_remote_process_group_copy_writable_vnodes(
                nil,
                nil,
                0,
                &vnodeCount
            ),
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
    }

    func testRemoteSelfSessionCapturesThreadEvidenceAndRestoresArenaBytes() {
        let length = 16_384
        guard let memory = mmap(
            nil,
            length,
            PROT_READ | PROT_WRITE,
            MAP_ANON | MAP_PRIVATE,
            -1,
            0
        ), memory != MAP_FAILED else {
            return XCTFail("Could not allocate a private VM arena")
        }
        defer { XCTAssertEqual(munmap(memory, length), 0) }
        memory.initializeMemory(as: UInt8.self, repeating: 0x21, count: length)

        var session: OpaquePointer?
        XCTAssertEqual(
            continuum_remote_session_open(getpid(), &session),
            CONTINUUM_STATUS_OK
        )
        guard let session else { return XCTFail("Expected self session") }
        defer { continuum_remote_session_destroy(session) }

        let address = UInt64(UInt(bitPattern: memory))
        XCTAssertEqual(
            continuum_remote_session_register_region(
                session,
                address,
                UInt64(length)
            ),
            CONTINUUM_STATUS_OK
        )

        var descriptor = continuum_remote_region_descriptor()
        var captured = continuum_owned_buffer()
        var threads: OpaquePointer?
        XCTAssertEqual(
            continuum_remote_session_capture(
                session,
                &descriptor,
                &captured,
                &threads
            ),
            CONTINUUM_STATUS_OK
        )
        defer { continuum_owned_buffer_destroy(&captured) }
        defer { continuum_remote_thread_snapshot_destroy(threads) }

        XCTAssertEqual(descriptor.address, address)
        XCTAssertEqual(descriptor.length, UInt64(length))
        XCTAssertLessThanOrEqual(descriptor.mapping_address, address)
        XCTAssertGreaterThanOrEqual(
            descriptor.mapping_address + descriptor.mapping_length,
            address + UInt64(length)
        )
        XCTAssertNotEqual(descriptor.thread_set_hash, 0)
        XCTAssertEqual(captured.length, length)
        guard let capturedBytes = captured.bytes?.assumingMemoryBound(to: UInt8.self)
        else { return XCTFail("Expected captured arena bytes") }
        XCTAssertEqual(capturedBytes[0], 0x21)
        XCTAssertEqual(capturedBytes[length - 1], 0x21)

#if arch(arm64)
        guard let threads else { return XCTFail("Expected thread evidence") }
        let threadCount = continuum_remote_thread_snapshot_count(threads)
        XCTAssertGreaterThan(threadCount, 0)
        var first = continuum_remote_thread_state_info()
        XCTAssertEqual(
            continuum_remote_thread_snapshot_info(threads, 0, &first),
            CONTINUUM_STATUS_OK
        )
        XCTAssertGreaterThan(first.thread_identifier, 0)
        XCTAssertGreaterThan(first.general_state_length, 0)
        XCTAssertGreaterThan(first.vector_state_length, 0)

        var generalLength = 0
        XCTAssertEqual(
            continuum_remote_thread_snapshot_copy_general_state(
                threads,
                0,
                nil,
                0,
                &generalLength
            ),
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(generalLength, first.general_state_length)
        let generalState = UnsafeMutableRawPointer.allocate(
            byteCount: generalLength,
            alignment: MemoryLayout<UInt64>.alignment
        )
        defer { generalState.deallocate() }
        XCTAssertEqual(
            continuum_remote_thread_snapshot_copy_general_state(
                threads,
                0,
                generalState,
                generalLength,
                &generalLength
            ),
            CONTINUUM_STATUS_OK
        )

        var vectorLength = 0
        XCTAssertEqual(
            continuum_remote_thread_snapshot_copy_vector_state(
                threads,
                0,
                nil,
                0,
                &vectorLength
            ),
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(vectorLength, first.vector_state_length)
#else
        XCTAssertNil(threads)
#endif

        memory.initializeMemory(as: UInt8.self, repeating: 0xA7, count: length)
        var report = continuum_remote_restore_report()
        XCTAssertEqual(
            continuum_remote_session_restore(
                session,
                &descriptor,
                captured.bytes,
                captured.length,
                &report
            ),
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(report.bytes_written, UInt64(length))
        XCTAssertEqual(report.readback_verified, 1)
        XCTAssertEqual(report.rollback_attempted, 0)
        XCTAssertEqual(report.rollback_verified, 0)

        let restored = memory.assumingMemoryBound(to: UInt8.self)
        XCTAssertEqual(restored[0], 0x21)
        XCTAssertEqual(restored[length / 2], 0x21)
        XCTAssertEqual(restored[length - 1], 0x21)
    }

    func testPrivateAndCOWShareModesAreRestoreEquivalent() {
        let length = 16_384
        guard let memory = mmap(
            nil,
            length,
            PROT_READ | PROT_WRITE,
            MAP_ANON | MAP_PRIVATE,
            -1,
            0
        ), memory != MAP_FAILED else {
            return XCTFail("Could not allocate a private VM arena")
        }
        defer { XCTAssertEqual(munmap(memory, length), 0) }
        memory.initializeMemory(as: UInt8.self, repeating: 0x18, count: length)

        var session: OpaquePointer?
        XCTAssertEqual(
            continuum_remote_session_open(getpid(), &session),
            CONTINUUM_STATUS_OK
        )
        guard let session else { return XCTFail("Expected self session") }
        defer { continuum_remote_session_destroy(session) }
        XCTAssertEqual(
            continuum_remote_session_register_region(
                session,
                UInt64(UInt(bitPattern: memory)),
                UInt64(length)
            ),
            CONTINUUM_STATUS_OK
        )

        var descriptor = continuum_remote_region_descriptor()
        var captured = continuum_owned_buffer()
        var threads: OpaquePointer?
        XCTAssertEqual(
            continuum_remote_session_capture(
                session,
                &descriptor,
                &captured,
                &threads
            ),
            CONTINUUM_STATUS_OK
        )
        defer { continuum_owned_buffer_destroy(&captured) }
        defer { continuum_remote_thread_snapshot_destroy(threads) }

        let privateMode = UInt32(SM_PRIVATE)
        let cowMode = UInt32(SM_COW)
        XCTAssertTrue(descriptor.share_mode == privateMode || descriptor.share_mode == cowMode)
        descriptor.share_mode = descriptor.share_mode == privateMode ? cowMode : privateMode

        memory.initializeMemory(as: UInt8.self, repeating: 0x91, count: length)
        var report = continuum_remote_restore_report()
        XCTAssertEqual(
            continuum_remote_session_restore(
                session,
                &descriptor,
                captured.bytes,
                captured.length,
                &report
            ),
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(report.readback_verified, 1)
        XCTAssertEqual(memory.load(as: UInt8.self), 0x18)
        XCTAssertEqual(
            memory.advanced(by: length - 1).load(as: UInt8.self),
            0x18
        )
    }

    func testRemoteRestoreRejectsChangedProtectionAndThreadSetWithoutWriting() {
        let length = 16_384
        guard let memory = mmap(
            nil,
            length,
            PROT_READ | PROT_WRITE,
            MAP_ANON | MAP_PRIVATE,
            -1,
            0
        ), memory != MAP_FAILED else {
            return XCTFail("Could not allocate a private VM arena")
        }
        defer { XCTAssertEqual(munmap(memory, length), 0) }
        memory.initializeMemory(as: UInt8.self, repeating: 0x31, count: length)

        var session: OpaquePointer?
        XCTAssertEqual(
            continuum_remote_session_open(getpid(), &session),
            CONTINUUM_STATUS_OK
        )
        guard let session else { return XCTFail("Expected self session") }
        defer { continuum_remote_session_destroy(session) }
        XCTAssertEqual(
            continuum_remote_session_register_region(
                session,
                UInt64(UInt(bitPattern: memory)),
                UInt64(length)
            ),
            CONTINUUM_STATUS_OK
        )

        var descriptor = continuum_remote_region_descriptor()
        var captured = continuum_owned_buffer()
        var threads: OpaquePointer?
        XCTAssertEqual(
            continuum_remote_session_capture(
                session,
                &descriptor,
                &captured,
                &threads
            ),
            CONTINUUM_STATUS_OK
        )
        defer { continuum_owned_buffer_destroy(&captured) }
        defer { continuum_remote_thread_snapshot_destroy(threads) }

        memory.initializeMemory(as: UInt8.self, repeating: 0x52, count: length)
        XCTAssertEqual(mprotect(memory, length, PROT_READ), 0)
        var report = continuum_remote_restore_report()
        XCTAssertEqual(
            continuum_remote_session_restore(
                session,
                &descriptor,
                captured.bytes,
                captured.length,
                &report
            ),
            CONTINUUM_STATUS_REGION_PROTECTION_CHANGED
        )
        XCTAssertEqual(report.bytes_written, 0)
        XCTAssertEqual(report.rollback_attempted, 0)
        XCTAssertEqual(mprotect(memory, length, PROT_READ | PROT_WRITE), 0)
        XCTAssertEqual(memory.load(as: UInt8.self), 0x52)

        var wrongThreads = descriptor
        wrongThreads.thread_set_hash ^= 0x5A5A
        XCTAssertEqual(
            continuum_remote_session_restore(
                session,
                &wrongThreads,
                captured.bytes,
                captured.length,
                &report
            ),
            CONTINUUM_STATUS_THREAD_SET_CHANGED
        )
        XCTAssertEqual(report.bytes_written, 0)
        XCTAssertEqual(memory.load(as: UInt8.self), 0x52)

        guard let unreadableHistory = UnsafeRawPointer(bitPattern: 1) else {
            return XCTFail("Expected a non-null invalid source pointer")
        }
        XCTAssertEqual(
            continuum_remote_session_restore(
                session,
                &descriptor,
                unreadableHistory,
                length,
                &report
            ),
            CONTINUUM_STATUS_SHORT_WRITE
        )
        XCTAssertEqual(report.bytes_written, 0)
        XCTAssertEqual(report.readback_verified, 0)
        XCTAssertEqual(report.rollback_attempted, 1)
        XCTAssertEqual(report.rollback_verified, 1)
        XCTAssertEqual(memory.load(as: UInt8.self), 0x52)
    }

    func testRemoteRegistrationRejectsUnmappedAndReadOnlyMemory() {
        var session: OpaquePointer?
        XCTAssertEqual(
            continuum_remote_session_open(getpid(), &session),
            CONTINUUM_STATUS_OK
        )
        guard let session else { return XCTFail("Expected self session") }
        defer { continuum_remote_session_destroy(session) }

        XCTAssertEqual(
            continuum_remote_session_register_region(session, 1, 4_096),
            CONTINUUM_STATUS_REGION_UNMAPPED
        )

        let length = 16_384
        guard let memory = mmap(
            nil,
            length,
            PROT_READ,
            MAP_ANON | MAP_PRIVATE,
            -1,
            0
        ), memory != MAP_FAILED else {
            return XCTFail("Could not allocate a read-only VM arena")
        }
        defer { XCTAssertEqual(munmap(memory, length), 0) }
        XCTAssertEqual(
            continuum_remote_session_register_region(
                session,
                UInt64(UInt(bitPattern: memory)),
                UInt64(length)
            ),
            CONTINUUM_STATUS_REGION_PROTECTION_CHANGED
        )
    }

    func testEveryRuntimeStatusHasAUsefulString() {
        let statuses: [continuum_status] = [
            CONTINUUM_STATUS_OK,
            CONTINUUM_STATUS_INVALID_ARGUMENT,
            CONTINUUM_STATUS_OUT_OF_MEMORY,
            CONTINUUM_STATUS_MACH_ERROR,
            CONTINUUM_STATUS_CHECKPOINT_NOT_FOUND,
            CONTINUUM_STATUS_RANGE_ERROR,
            CONTINUUM_STATUS_ACCESS_DENIED,
            CONTINUUM_STATUS_TARGET_EXITED,
            CONTINUUM_STATUS_PROCESS_IDENTITY_CHANGED,
            CONTINUUM_STATUS_REGION_UNMAPPED,
            CONTINUUM_STATUS_REGION_PROTECTION_CHANGED,
            CONTINUUM_STATUS_REGION_NOT_PRIVATE,
            CONTINUUM_STATUS_THREAD_SET_CHANGED,
            CONTINUUM_STATUS_SHORT_READ,
            CONTINUUM_STATUS_SHORT_WRITE,
            CONTINUUM_STATUS_VALIDATION_FAILED,
            CONTINUUM_STATUS_ROLLBACK_FAILED,
            CONTINUUM_STATUS_UNSUPPORTED_ARCHITECTURE,
            CONTINUUM_STATUS_SUSPEND_FAILED,
            CONTINUUM_STATUS_RESUME_FAILED,
            CONTINUUM_STATUS_THREAD_STATE_FAILED,
            CONTINUUM_STATUS_REGION_MAPPING_CHANGED,
            CONTINUUM_STATUS_SNAPSHOT_BUDGET_EXCEEDED,
            CONTINUUM_STATUS_THREAD_RESTORE_FAILED,
            CONTINUUM_STATUS_DESCRIPTOR_TABLE_CHANGED,
            CONTINUUM_STATUS_MACH_NAMESPACE_CHANGED,
            CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR,
            CONTINUUM_STATUS_PROCESS_TREE_CHANGED
        ]

        for status in statuses {
            let message = String(cString: continuum_status_string(status))
            XCTAssertFalse(message.isEmpty)
            XCTAssertNotEqual(message, "unknown status")
        }
    }
}
