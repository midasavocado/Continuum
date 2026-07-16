import XCTest
import ContinuumRuntime
import ContinuumBootstrap
import Darwin
import Foundation

private func continuumTestProcessForestResourceCallback(
    _ snapshot: OpaquePointer?,
    _ context: UnsafeMutableRawPointer?
) -> continuum_status {
    guard snapshot != nil, let context else {
        return CONTINUUM_STATUS_INVALID_ARGUMENT
    }
    context.assumingMemoryBound(to: Int32.self).pointee += 1
    return CONTINUUM_STATUS_OK
}

private final class ContinuumTestTCPEndpointCapture {
    var status = CONTINUUM_STATUS_OK
    var undersizedStatus = CONTINUUM_STATUS_OK
    var endpoints: [continuum_remote_tcp_endpoint_info] = []
}

private final class ContinuumTestPTYDescriptorCapture {
    var status = CONTINUUM_STATUS_OK
    var undersizedStatus = CONTINUUM_STATUS_OK
    var descriptors: [continuum_remote_pty_descriptor_info] = []
}

private final class ContinuumTestDescriptorGraphCapture {
    var status = CONTINUUM_STATUS_OK
    var undersizedStatus = CONTINUUM_STATUS_OK
    var handles: [continuum_remote_descriptor_handle_info] = []
    var sockets: [continuum_remote_socket_resource_info] = []
    var pipes: [continuum_remote_pipe_resource_info] = []
    var kqueues: [continuum_remote_kqueue_resource_info] = []
    var registrations: [continuum_remote_kqueue_registration_info] = []
}

private func continuumTestDescriptorGraphResourceCallback(
    _ snapshot: OpaquePointer?,
    _ context: UnsafeMutableRawPointer?
) -> continuum_status {
    guard let snapshot, let context else {
        return CONTINUUM_STATUS_INVALID_ARGUMENT
    }
    let capture = Unmanaged<ContinuumTestDescriptorGraphCapture>
        .fromOpaque(context)
        .takeUnretainedValue()
    var rawGraph: OpaquePointer?
    var status = continuum_remote_process_group_capture_descriptor_graph(
        snapshot,
        &rawGraph
    )
    guard status == CONTINUUM_STATUS_OK, let rawGraph else {
        capture.status = status
        return status
    }
    defer { continuum_remote_descriptor_graph_destroy(rawGraph) }

    capture.handles = Array(
        repeating: continuum_remote_descriptor_handle_info(),
        count: continuum_remote_descriptor_graph_handle_count(rawGraph)
    )
    capture.sockets = Array(
        repeating: continuum_remote_socket_resource_info(),
        count: continuum_remote_descriptor_graph_socket_count(rawGraph)
    )
    capture.pipes = Array(
        repeating: continuum_remote_pipe_resource_info(),
        count: continuum_remote_descriptor_graph_pipe_count(rawGraph)
    )
    capture.kqueues = Array(
        repeating: continuum_remote_kqueue_resource_info(),
        count: continuum_remote_descriptor_graph_kqueue_count(rawGraph)
    )
    capture.registrations = Array(
        repeating: continuum_remote_kqueue_registration_info(),
        count: continuum_remote_descriptor_graph_kqueue_registration_count(rawGraph)
    )
    status = capture.handles.withUnsafeMutableBufferPointer {
        continuum_remote_descriptor_graph_copy_handles(
            rawGraph, $0.baseAddress, $0.count
        )
    }
    if status == CONTINUUM_STATUS_OK {
        status = capture.sockets.withUnsafeMutableBufferPointer {
            continuum_remote_descriptor_graph_copy_sockets(
                rawGraph, $0.baseAddress, $0.count
            )
        }
    }
    if status == CONTINUUM_STATUS_OK {
        status = capture.pipes.withUnsafeMutableBufferPointer {
            continuum_remote_descriptor_graph_copy_pipes(
                rawGraph, $0.baseAddress, $0.count
            )
        }
    }
    if status == CONTINUUM_STATUS_OK {
        status = capture.kqueues.withUnsafeMutableBufferPointer {
            continuum_remote_descriptor_graph_copy_kqueues(
                rawGraph, $0.baseAddress, $0.count
            )
        }
    }
    if status == CONTINUUM_STATUS_OK {
        status = capture.registrations.withUnsafeMutableBufferPointer {
            continuum_remote_descriptor_graph_copy_kqueue_registrations(
                rawGraph, $0.baseAddress, $0.count
            )
        }
    }
    capture.status = status
    if status == CONTINUUM_STATUS_OK, !capture.handles.isEmpty {
        var undersized = Array(
            repeating: continuum_remote_descriptor_handle_info(),
            count: capture.handles.count - 1
        )
        capture.undersizedStatus = undersized.withUnsafeMutableBufferPointer {
            continuum_remote_descriptor_graph_copy_handles(
                rawGraph, $0.baseAddress, $0.count
            )
        }
    }
    return status
}

private func continuumTestPTYDescriptorResourceCallback(
    _ snapshot: OpaquePointer?,
    _ context: UnsafeMutableRawPointer?
) -> continuum_status {
    guard let snapshot, let context else {
        return CONTINUUM_STATUS_INVALID_ARGUMENT
    }
    let capture = Unmanaged<ContinuumTestPTYDescriptorCapture>
        .fromOpaque(context)
        .takeUnretainedValue()
    var count = 0
    var status = continuum_remote_process_group_copy_pty_descriptors(
        snapshot,
        nil,
        0,
        &count
    )
    guard status == CONTINUUM_STATUS_OK else {
        capture.status = status
        return status
    }
    var descriptors = Array(
        repeating: continuum_remote_pty_descriptor_info(),
        count: count
    )
    status = descriptors.withUnsafeMutableBufferPointer { buffer in
        continuum_remote_process_group_copy_pty_descriptors(
            snapshot,
            buffer.baseAddress,
            buffer.count,
            &count
        )
    }
    capture.status = status
    if status == CONTINUUM_STATUS_OK {
        capture.descriptors = descriptors
        if count > 0 {
            var undersized = Array(
                repeating: continuum_remote_pty_descriptor_info(),
                count: count - 1
            )
            capture.undersizedStatus = undersized.withUnsafeMutableBufferPointer {
                buffer in
                var undersizedCount = 0
                return continuum_remote_process_group_copy_pty_descriptors(
                    snapshot,
                    buffer.baseAddress,
                    buffer.count,
                    &undersizedCount
                )
            }
        }
    }
    return status
}

private func continuumTestPTYAlias(
    ttyIndex: UInt32,
    role: continuum_remote_pty_role
) -> UInt64 {
    var hash: UInt64 = 1_469_598_103_934_665_603
    let prime: UInt64 = 1_099_511_628_211
    for value in [UInt64(0x505459414C494153), UInt64(ttyIndex), UInt64(role.rawValue)] {
        for byte in 0..<8 {
            hash ^= (value >> UInt64(byte * 8)) & 0xff
            hash = hash &* prime
        }
    }
    return hash
}

private func continuumTestTCPEndpointResourceCallback(
    _ snapshot: OpaquePointer?,
    _ context: UnsafeMutableRawPointer?
) -> continuum_status {
    guard let snapshot, let context else {
        return CONTINUUM_STATUS_INVALID_ARGUMENT
    }
    let capture = Unmanaged<ContinuumTestTCPEndpointCapture>
        .fromOpaque(context)
        .takeUnretainedValue()
    var count = 0
    var status = continuum_remote_process_group_copy_tcp_endpoints(
        snapshot,
        nil,
        0,
        &count
    )
    guard status == CONTINUUM_STATUS_OK else {
        capture.status = status
        return status
    }
    var endpoints = Array(
        repeating: continuum_remote_tcp_endpoint_info(),
        count: count
    )
    status = endpoints.withUnsafeMutableBufferPointer { buffer in
        continuum_remote_process_group_copy_tcp_endpoints(
            snapshot,
            buffer.baseAddress,
            buffer.count,
            &count
        )
    }
    capture.status = status
    if status == CONTINUUM_STATUS_OK {
        capture.endpoints = endpoints
        if count > 0 {
            var undersized = Array(
                repeating: continuum_remote_tcp_endpoint_info(),
                count: count - 1
            )
            capture.undersizedStatus = undersized.withUnsafeMutableBufferPointer {
                buffer in
                var undersizedCount = 0
                return continuum_remote_process_group_copy_tcp_endpoints(
                    snapshot,
                    buffer.baseAddress,
                    buffer.count,
                    &undersizedCount
                )
            }
        }
    }
    return status
}

private func continuumTestAddressBytes(
    _ endpoint: continuum_remote_tcp_endpoint_info,
    local: Bool
) -> Data {
    var endpoint = endpoint
    let length = Int(
        local ? endpoint.local_address_length : endpoint.remote_address_length
    )
    if local {
        return withUnsafeBytes(of: &endpoint.local_address) {
            Data($0.prefix(length))
        }
    }
    return withUnsafeBytes(of: &endpoint.remote_address) {
        Data($0.prefix(length))
    }
}

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

    func testBootstrapReportsOnlyRealAppStateBeforeSafepointSignal() {
        var detected: UInt8 = 0
        XCTAssertEqual(
            continuum_remote_process_has_app_state_zone(getpid(), &detected),
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(detected, 0)

        guard let allocation = continuum_bootstrap_allocate_app_state(16) else {
            return XCTFail("Bootstrap did not allocate tagged app state")
        }
        allocation.storeBytes(of: UInt64(0xC01DCAFE), as: UInt64.self)
        XCTAssertEqual(
            continuum_remote_process_has_app_state_zone(getpid(), &detected),
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(detected, 1)

        free(allocation)
        XCTAssertEqual(
            continuum_remote_process_has_app_state_zone(getpid(), &detected),
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(detected, 0)
    }

    func testBootstrapPreparesOneSuspendedOrdinaryPthread() {
        var report = continuum_bootstrap_pthread_report()
        XCTAssertEqual(
            continuum_bootstrap_prepare_suspended_pthreads(
                &report,
                MemoryLayout.size(ofValue: report),
                1
            ),
            0
        )
        XCTAssertEqual(report.version, 3)
        XCTAssertEqual(report.requested_count, 1)
        XCTAssertEqual(report.created_count, 1)
        XCTAssertEqual(report.error_code, 0)
        XCTAssertNotEqual(report.primary_pthread_address, 0)
        XCTAssertNotEqual(report.primary_mach_thread_port, 0)
        XCTAssertNotEqual(report.primary_stack_base_address, 0)
        XCTAssertGreaterThan(report.primary_stack_length, 0)
        XCTAssertNotEqual(report.primary_stack_region_address, 0)
        XCTAssertGreaterThan(report.primary_stack_region_length, 0)
        XCTAssertNotEqual(report.primary_pthread_region_address, 0)
        XCTAssertGreaterThan(report.primary_pthread_region_length, 0)
        XCTAssertNotEqual(report.pthread_addresses.0, 0)
        XCTAssertNotEqual(report.mach_thread_ports.0, 0)
        XCTAssertNotEqual(report.stack_base_addresses.0, 0)
        XCTAssertGreaterThan(report.stack_lengths.0, 0)
        XCTAssertNotEqual(report.stack_region_addresses.0, 0)
        XCTAssertGreaterThan(report.stack_region_lengths.0, 0)
        XCTAssertNotEqual(report.pthread_region_addresses.0, 0)
        XCTAssertGreaterThan(report.pthread_region_lengths.0, 0)

        let pthreadAddress = report.pthread_addresses.0
        let stackBase = report.stack_base_addresses.0
        let (stackEnd, stackOverflow) = stackBase.addingReportingOverflow(
            report.stack_lengths.0
        )
        let stackRegionBase = report.stack_region_addresses.0
        let (stackRegionEnd, stackRegionOverflow) =
            stackRegionBase.addingReportingOverflow(
                report.stack_region_lengths.0
            )
        let pthreadRegionBase = report.pthread_region_addresses.0
        let (pthreadRegionEnd, pthreadRegionOverflow) =
            pthreadRegionBase.addingReportingOverflow(
                report.pthread_region_lengths.0
            )
        XCTAssertFalse(stackOverflow)
        XCTAssertFalse(stackRegionOverflow)
        XCTAssertFalse(pthreadRegionOverflow)
        XCTAssertGreaterThanOrEqual(stackBase, stackRegionBase)
        XCTAssertLessThanOrEqual(stackEnd, stackRegionEnd)
        XCTAssertGreaterThanOrEqual(pthreadAddress, pthreadRegionBase)
        XCTAssertLessThan(pthreadAddress, pthreadRegionEnd)
        XCTAssertEqual(stackEnd, pthreadAddress)

        let (primaryStackEnd, primaryStackOverflow) =
            report.primary_stack_base_address.addingReportingOverflow(
                report.primary_stack_length
            )
        let (primaryStackRegionEnd, primaryRegionOverflow) =
            report.primary_stack_region_address.addingReportingOverflow(
                report.primary_stack_region_length
            )
        XCTAssertFalse(primaryStackOverflow)
        XCTAssertFalse(primaryRegionOverflow)
        XCTAssertGreaterThanOrEqual(
            report.primary_stack_base_address,
            report.primary_stack_region_address
        )
        XCTAssertLessThanOrEqual(primaryStackEnd, primaryStackRegionEnd)

        let machThread = mach_port_t(report.mach_thread_ports.0)
        XCTAssertEqual(thread_resume(machThread), KERN_SUCCESS)
        guard let pthread = pthread_t(
            bitPattern: UInt(report.pthread_addresses.0)
        ) else {
            return XCTFail("Bootstrap returned an invalid pthread address")
        }
        XCTAssertEqual(pthread_join(pthread, nil), 0)

        var primaryOnly = continuum_bootstrap_pthread_report()
        XCTAssertEqual(
            continuum_bootstrap_prepare_suspended_pthreads(
                &primaryOnly,
                MemoryLayout.size(ofValue: primaryOnly),
                0
            ),
            0
        )
        XCTAssertEqual(primaryOnly.version, 3)
        XCTAssertEqual(primaryOnly.requested_count, 0)
        XCTAssertEqual(primaryOnly.created_count, 0)
        XCTAssertNotEqual(primaryOnly.primary_pthread_address, 0)
    }

    func testRemotePthreadBootstrapRejectsInvalidArguments() {
        var report = continuum_remote_pthread_bootstrap_report()
        report.version = 99
        XCTAssertEqual(
            continuum_remote_session_prepare_suspended_pthreads(
                nil,
                1,
                &report
            ),
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
        XCTAssertEqual(report.version, 0)
        XCTAssertEqual(
            continuum_remote_session_prepare_suspended_pthreads(nil, 0, nil),
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
        var byte: UInt8 = 0
        var restoreReport = continuum_remote_restore_report()
        XCTAssertEqual(
            continuum_remote_session_write_prepared_pthread_stack(
                nil,
                nil,
                0,
                &byte,
                1,
                &restoreReport
            ),
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
        XCTAssertEqual(restoreReport.bytes_written, 0)
    }

    func testExactPthreadPlanCopiesOnlyStacksAtMatchingAddresses() {
        var replacement = continuum_remote_pthread_bootstrap_report()
        replacement.version = 3
        replacement.requested_count = 1
        replacement.created_count = 1
        replacement.primary_pthread_address = 0x1000_5000
        replacement.primary_thread_identifier = 10
        replacement.primary_thread_handle = 0x1000_50E0
        replacement.primary_stack_base_address = 0x2000_0000
        replacement.primary_stack_length = 0x8000
        replacement.primary_stack_region_address = 0x2000_0000
        replacement.primary_stack_region_length = 0x8000
        replacement.primary_pthread_region_address = 0x1000_0000
        replacement.primary_pthread_region_length = 0x10000
        replacement.pthread_addresses.0 = 0x3008_3000
        replacement.thread_identifiers.0 = 20
        replacement.thread_handles.0 = 0x3008_30E0
        replacement.stack_base_addresses.0 = 0x3000_0000
        replacement.stack_lengths.0 = 0x83000
        replacement.stack_region_addresses.0 = 0x3000_0000
        replacement.stack_region_lengths.0 = 0x88000
        replacement.pthread_region_addresses.0 = 0x3000_0000
        replacement.pthread_region_lengths.0 = 0x88000

        var saved = [
            continuum_saved_pthread_geometry(
                saved_thread_identifier: 200,
                pthread_address: 0x3008_3000,
                stack_pointer: 0x3004_0000,
                stack_region_address: 0x3000_0000,
                stack_region_length: 0x88000,
                pthread_region_address: 0x3000_0000,
                pthread_region_length: 0x88000
            ),
            continuum_saved_pthread_geometry(
                saved_thread_identifier: 100,
                pthread_address: 0x1000_5000,
                stack_pointer: 0x2000_4000,
                stack_region_address: 0x2000_0000,
                stack_region_length: 0x8000,
                pthread_region_address: 0x1000_0000,
                pthread_region_length: 0x10000
            )
        ]
        var plan = continuum_pthread_reconstruction_plan()
        let status = saved.withUnsafeBufferPointer { savedBuffer in
            continuum_plan_exact_pthread_reconstruction(
                savedBuffer.baseAddress,
                savedBuffer.count,
                &replacement,
                &plan
            )
        }
        XCTAssertEqual(status, CONTINUUM_STATUS_OK)
        XCTAssertEqual(plan.entry_count, 2)
        XCTAssertEqual(plan.primary_saved_thread_identifier, 100)
        XCTAssertEqual(plan.stack_copy_bytes, 0x8B000)
        XCTAssertEqual(plan.preserved_pthread_bytes, 0x15000)
        XCTAssertEqual(plan.entries.0.saved_thread_identifier, 200)
        XCTAssertEqual(plan.entries.0.replacement_thread_identifier, 20)
        XCTAssertEqual(plan.entries.0.stack_copy_address, 0x3000_0000)
        XCTAssertEqual(plan.entries.0.stack_copy_length, 0x83000)
        XCTAssertEqual(
            plan.entries.0.preserved_pthread_address,
            0x3008_3000
        )
        XCTAssertEqual(plan.entries.0.preserved_pthread_length, 0x5000)
        XCTAssertEqual(plan.entries.0.is_primary, 0)
        XCTAssertEqual(plan.entries.1.saved_thread_identifier, 100)
        XCTAssertEqual(plan.entries.1.replacement_thread_identifier, 10)
        XCTAssertEqual(plan.entries.1.stack_copy_address, 0x2000_0000)
        XCTAssertEqual(plan.entries.1.stack_copy_length, 0x8000)
        XCTAssertEqual(
            plan.entries.1.preserved_pthread_address,
            0x1000_0000
        )
        XCTAssertEqual(plan.entries.1.preserved_pthread_length, 0x10000)
        XCTAssertEqual(plan.entries.1.is_primary, 1)

        saved[0].stack_region_address += 0x1000
        let mismatchStatus = saved.withUnsafeBufferPointer { savedBuffer in
            continuum_plan_exact_pthread_reconstruction(
                savedBuffer.baseAddress,
                savedBuffer.count,
                &replacement,
                &plan
            )
        }
        XCTAssertEqual(
            mismatchStatus,
            CONTINUUM_STATUS_VALIDATION_FAILED
        )
        XCTAssertEqual(plan.entry_count, 0)

        saved[0].stack_region_address = 0x2FFF_F000
        saved[0].stack_region_length = 0x89000
        replacement.stack_region_addresses.0 = 0x2FFF_F000
        replacement.stack_region_lengths.0 = 0x89000
        let overlappingStatus = saved.withUnsafeBufferPointer { savedBuffer in
            continuum_plan_exact_pthread_reconstruction(
                savedBuffer.baseAddress,
                savedBuffer.count,
                &replacement,
                &plan
            )
        }
        XCTAssertEqual(
            overlappingStatus,
            CONTINUUM_STATUS_VALIDATION_FAILED
        )
        XCTAssertEqual(plan.entry_count, 0)
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

    func testColdRestorerCreatesAProcessSuspendedBeforeMain() {
        let executable = strdup("/usr/bin/true")!
        let argument = strdup("true")!
        let environment = strdup("PATH=/usr/bin:/bin")!
        let bootstrapStop = strdup("CONTINUUM_BOOTSTRAP_STOP=1")!
        let bootstrapDescriptor = strdup(
            "CONTINUUM_BOOTSTRAP_DESCRIPTOR_FD=202"
        )!
        let directory = strdup("/private/tmp")!
        defer {
            free(executable)
            free(argument)
            free(environment)
            free(bootstrapStop)
            free(bootstrapDescriptor)
            free(directory)
        }

        let arguments: [UnsafePointer<CChar>?] = [UnsafePointer(argument), nil]
        let environmentEntries: [UnsafePointer<CChar>?] = [
            UnsafePointer(environment),
            UnsafePointer(bootstrapStop),
            UnsafePointer(bootstrapDescriptor),
            nil
        ]
        var processID: Int32 = 0
        let status = arguments.withUnsafeBufferPointer { argumentBuffer in
            environmentEntries.withUnsafeBufferPointer { environmentBuffer in
                continuum_spawn_process_suspended(
                    executable,
                    argumentBuffer.baseAddress,
                    environmentBuffer.baseAddress,
                    directory,
                    &processID
                )
            }
        }
        XCTAssertEqual(status, CONTINUUM_STATUS_OK)
        XCTAssertGreaterThan(processID, 0)
        guard processID > 0 else { return }
        defer {
            kill(processID, SIGKILL)
            var terminationStatus: Int32 = 0
            waitpid(processID, &terminationStatus, 0)
        }

        var processInfo = proc_bsdinfo()
        XCTAssertEqual(
            proc_pidinfo(
                processID,
                PROC_PIDTBSDINFO,
                0,
                &processInfo,
                Int32(MemoryLayout<proc_bsdinfo>.size)
            ),
            Int32(MemoryLayout<proc_bsdinfo>.size)
        )
        XCTAssertEqual(processInfo.pbi_status, UInt32(SSTOP))
    }

    func testSuspendedSpawnRemapsDescriptorsBeforeMain() {
        var bootstrapPair = [Int32](repeating: -1, count: 2)
        var resourcePair = [Int32](repeating: -1, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &bootstrapPair), 0)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &resourcePair), 0)
        guard bootstrapPair.allSatisfy({ $0 >= 0 }),
              resourcePair.allSatisfy({ $0 >= 0 }) else {
            return XCTFail("Expected controller-owned socket pairs")
        }
        defer {
            bootstrapPair.forEach { Darwin.close($0) }
            resourcePair.forEach { Darwin.close($0) }
        }
        for descriptor in bootstrapPair + resourcePair {
            XCTAssertEqual(fcntl(descriptor, F_SETFD, FD_CLOEXEC), 0)
        }

        let executable = strdup("/usr/bin/true")!
        let argument = strdup("true")!
        let environment = strdup("PATH=/usr/bin:/bin")!
        let directory = strdup("/private/tmp")!
        defer {
            free(executable)
            free(argument)
            free(environment)
            free(directory)
        }
        let arguments: [UnsafePointer<CChar>?] = [UnsafePointer(argument), nil]
        let environmentEntries: [UnsafePointer<CChar>?] = [
            UnsafePointer(environment), nil
        ]
        let targetDescriptor: Int32 = 200
        var remap = continuum_spawn_descriptor_remap()
        remap.source_descriptor = resourcePair[0]
        remap.target_descriptor = targetDescriptor
        var processID: Int32 = 0
        let status = arguments.withUnsafeBufferPointer { argumentBuffer in
            environmentEntries.withUnsafeBufferPointer { environmentBuffer in
                withUnsafePointer(to: &remap) { remapPointer in
                    continuum_spawn_process_suspended_with_inherited_descriptor_and_remaps(
                        executable,
                        argumentBuffer.baseAddress,
                        environmentBuffer.baseAddress,
                        directory,
                        bootstrapPair[0],
                        remapPointer,
                        1,
                        &processID
                    )
                }
            }
        }
        XCTAssertEqual(status, CONTINUUM_STATUS_OK)
        XCTAssertGreaterThan(processID, 0)
        guard processID > 0 else { return }
        defer {
            kill(processID, SIGKILL)
            var terminationStatus: Int32 = 0
            waitpid(processID, &terminationStatus, 0)
        }

        var descriptors = Array(repeating: proc_fdinfo(), count: 256)
        let returnedBytes = descriptors.withUnsafeMutableBytes { buffer in
            proc_pidinfo(
                processID,
                PROC_PIDLISTFDS,
                0,
                buffer.baseAddress,
                Int32(buffer.count)
            )
        }
        XCTAssertGreaterThan(returnedBytes, 0)
        let descriptorCount = Int(returnedBytes)
            / MemoryLayout<proc_fdinfo>.stride
        let childDescriptors = Set(
            descriptors.prefix(descriptorCount).map(\.proc_fd)
        )
        XCTAssertTrue(childDescriptors.contains(bootstrapPair[0]))
        XCTAssertTrue(childDescriptors.contains(targetDescriptor))
        XCTAssertFalse(childDescriptors.contains(resourcePair[0]))

        var socketInfo = socket_fdinfo()
        XCTAssertEqual(
            proc_pidfdinfo(
                processID,
                targetDescriptor,
                PROC_PIDFDSOCKETINFO,
                &socketInfo,
                Int32(MemoryLayout<socket_fdinfo>.size)
            ),
            Int32(MemoryLayout<socket_fdinfo>.size)
        )
    }

    func testSuspendedSpawnRejectsInvalidDescriptorRemaps() {
        var bootstrapPair = [Int32](repeating: -1, count: 2)
        var resourcePair = [Int32](repeating: -1, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &bootstrapPair), 0)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &resourcePair), 0)
        guard bootstrapPair.allSatisfy({ $0 >= 0 }),
              resourcePair.allSatisfy({ $0 >= 0 }) else {
            return XCTFail("Expected controller-owned socket pairs")
        }
        defer {
            bootstrapPair.forEach { Darwin.close($0) }
            resourcePair.forEach { Darwin.close($0) }
        }

        let executable = strdup("/usr/bin/true")!
        let argument = strdup("true")!
        let directory = strdup("/private/tmp")!
        defer {
            free(executable)
            free(argument)
            free(directory)
        }
        let arguments: [UnsafePointer<CChar>?] = [UnsafePointer(argument), nil]
        var first = continuum_spawn_descriptor_remap()
        first.source_descriptor = resourcePair[0]
        first.target_descriptor = 200
        var second = continuum_spawn_descriptor_remap()
        second.source_descriptor = resourcePair[1]
        second.target_descriptor = 200
        let duplicateTargets = [first, second]
        var processID: Int32 = 123
        let duplicateStatus = arguments.withUnsafeBufferPointer {
            argumentBuffer in
            duplicateTargets.withUnsafeBufferPointer { remapBuffer in
                continuum_spawn_process_suspended_with_inherited_descriptor_and_remaps_system_aslr(
                    executable,
                    argumentBuffer.baseAddress,
                    nil,
                    directory,
                    bootstrapPair[0],
                    remapBuffer.baseAddress,
                    remapBuffer.count,
                    &processID
                )
            }
        }
        XCTAssertEqual(duplicateStatus, CONTINUUM_STATUS_INVALID_ARGUMENT)
        XCTAssertEqual(processID, 0)

        first.target_descriptor = bootstrapPair[0]
        processID = 123
        let bootstrapCollisionStatus = arguments.withUnsafeBufferPointer {
            argumentBuffer in
            withUnsafePointer(to: &first) { remapPointer in
                continuum_spawn_process_suspended_with_inherited_descriptor_and_remaps(
                    executable,
                    argumentBuffer.baseAddress,
                    nil,
                    directory,
                    bootstrapPair[0],
                    remapPointer,
                    1,
                    &processID
                )
            }
        }
        XCTAssertEqual(
            bootstrapCollisionStatus,
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
        XCTAssertEqual(processID, 0)
    }

    func testSuspendedSpawnAppliesSupportedProcessTopologyAndRejectsControllingTTY() {
        var bootstrapPair = [Int32](repeating: -1, count: 2)
        var ptyMaster: Int32 = -1
        var ptySlave: Int32 = -1
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &bootstrapPair), 0)
        XCTAssertEqual(openpty(&ptyMaster, &ptySlave, nil, nil, nil), 0)
        guard bootstrapPair.allSatisfy({ $0 >= 0 }),
              ptyMaster >= 0, ptySlave >= 0 else {
            return XCTFail("Expected controller-owned bootstrap and PTY pairs")
        }
        defer {
            bootstrapPair.forEach { Darwin.close($0) }
            Darwin.close(ptyMaster)
            Darwin.close(ptySlave)
        }

        let executable = strdup("/usr/bin/true")!
        let argument = strdup("true")!
        let directory = strdup("/private/tmp")!
        defer {
            free(executable)
            free(argument)
            free(directory)
        }
        let arguments: [UnsafePointer<CChar>?] = [UnsafePointer(argument), nil]
        var remap = continuum_spawn_descriptor_remap(
            source_descriptor: ptySlave,
            target_descriptor: 200
        )
        var children: [Int32] = []
        defer {
            for child in children.reversed() {
                kill(child, SIGKILL)
                var status: Int32 = 0
                waitpid(child, &status, 0)
            }
        }

        func spawn(
            topology: inout continuum_spawn_process_topology,
            remapCount: Int = 0
        ) -> (continuum_status, Int32) {
            var processID: Int32 = 0
            let status = arguments.withUnsafeBufferPointer { argumentBuffer in
                withUnsafePointer(to: &topology) { topologyPointer in
                    withUnsafePointer(to: &remap) { remapPointer in
                        continuum_spawn_process_suspended_with_inherited_descriptor_remaps_and_topology_system_aslr(
                            executable,
                            argumentBuffer.baseAddress,
                            nil,
                            directory,
                            bootstrapPair[0],
                            remapCount == 0 ? nil : remapPointer,
                            remapCount,
                            topologyPointer,
                            &processID
                        )
                    }
                }
            }
            if status == CONTINUUM_STATUS_OK {
                children.append(processID)
            }
            return (status, processID)
        }

        var sessionLeader = continuum_spawn_process_topology(
            structure_size: UInt32(
                MemoryLayout<continuum_spawn_process_topology>.size
            ),
            create_session: 1,
            process_group_policy: CONTINUUM_SPAWN_PROCESS_GROUP_CREATE,
            process_group_id: 0,
            controlling_terminal_descriptor: -1
        )
        let (sessionStatus, sessionPID) = spawn(
            topology: &sessionLeader,
            remapCount: 1
        )
        XCTAssertEqual(sessionStatus, CONTINUUM_STATUS_OK)
        guard sessionStatus == CONTINUUM_STATUS_OK else { return }
        XCTAssertEqual(getsid(sessionPID), sessionPID)
        XCTAssertEqual(getpgid(sessionPID), sessionPID)

        var crossSessionJoin = continuum_spawn_process_topology(
            structure_size: UInt32(
                MemoryLayout<continuum_spawn_process_topology>.size
            ),
            create_session: 0,
            process_group_policy: CONTINUUM_SPAWN_PROCESS_GROUP_JOIN,
            process_group_id: sessionPID,
            controlling_terminal_descriptor: -1
        )
        let (crossSessionStatus, crossSessionPID) = spawn(
            topology: &crossSessionJoin
        )
        XCTAssertEqual(crossSessionStatus, CONTINUUM_STATUS_SPAWN_FAILED)
        XCTAssertEqual(crossSessionPID, 0)

        var groupLeader = continuum_spawn_process_topology(
            structure_size: UInt32(
                MemoryLayout<continuum_spawn_process_topology>.size
            ),
            create_session: 0,
            process_group_policy: CONTINUUM_SPAWN_PROCESS_GROUP_CREATE,
            process_group_id: 0,
            controlling_terminal_descriptor: -1
        )
        let (groupStatus, groupPID) = spawn(topology: &groupLeader)
        XCTAssertEqual(groupStatus, CONTINUUM_STATUS_OK)
        guard groupStatus == CONTINUUM_STATUS_OK else { return }
        XCTAssertEqual(getpgid(groupPID), groupPID)
        XCTAssertEqual(getsid(groupPID), getsid(getpid()))

        var groupJoin = continuum_spawn_process_topology(
            structure_size: UInt32(
                MemoryLayout<continuum_spawn_process_topology>.size
            ),
            create_session: 0,
            process_group_policy: CONTINUUM_SPAWN_PROCESS_GROUP_JOIN,
            process_group_id: groupPID,
            controlling_terminal_descriptor: -1
        )
        let (joinStatus, joinedPID) = spawn(topology: &groupJoin)
        XCTAssertEqual(joinStatus, CONTINUUM_STATUS_OK)
        guard joinStatus == CONTINUUM_STATUS_OK else { return }
        XCTAssertEqual(getpgid(joinedPID), groupPID)
        XCTAssertEqual(getsid(joinedPID), getsid(groupPID))

        var controllingTTY = sessionLeader
        controllingTTY.controlling_terminal_descriptor = 200
        let (ttyStatus, ttyPID) = spawn(
            topology: &controllingTTY,
            remapCount: 1
        )
        XCTAssertEqual(ttyStatus, CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR)
        XCTAssertEqual(ttyPID, 0)

        errno = 0
        XCTAssertEqual(tcgetpgrp(ptySlave), -1)
        XCTAssertEqual(errno, ENOTTY)
    }

    func testBrokeredPairPreservesParentSessionTTYAndConstructorGates() throws {
        let productsURL = Bundle(for: ContinuumRuntimeTests.self).bundleURL
            .deletingLastPathComponent()
        let targetURL = productsURL.appendingPathComponent(
            "ContinuumExternalTarget"
        )
        let bootstrapURL = productsURL.appendingPathComponent(
            "libContinuumBootstrap.dylib"
        )
        XCTAssertTrue(FileManager.default.fileExists(atPath: targetURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: bootstrapURL.path))

        var master: Int32 = -1
        var slave: Int32 = -1
        XCTAssertEqual(openpty(&master, &slave, nil, nil, nil), 0)
        guard master >= 0, slave >= 0 else {
            return XCTFail("Expected a controller-owned PTY")
        }
        defer {
            Darwin.close(master)
            Darwin.close(slave)
        }

        let executable = strdup(targetURL.path)!
        let bootstrap = strdup(bootstrapURL.path)!
        let argument0 = strdup("ContinuumExternalTarget")!
        let argument1 = strdup("--continuum-idle-child")!
        let environment = strdup("PATH=/usr/bin:/bin")!
        let bootstrapStop = strdup("CONTINUUM_BOOTSTRAP_STOP=1")!
        let bootstrapDescriptor = strdup(
            "CONTINUUM_BOOTSTRAP_DESCRIPTOR_FD=202"
        )!
        let directory = strdup("/private/tmp")!
        defer {
            free(executable)
            free(bootstrap)
            free(argument0)
            free(argument1)
            free(environment)
            free(bootstrapStop)
            free(bootstrapDescriptor)
            free(directory)
        }
        let arguments: [UnsafePointer<CChar>?] = [
            UnsafePointer(argument0), UnsafePointer(argument1), nil
        ]
        let environmentEntries: [UnsafePointer<CChar>?] = [
            UnsafePointer(environment),
            UnsafePointer(bootstrapStop),
            UnsafePointer(bootstrapDescriptor),
            nil
        ]
        let rootTarget: Int32 = 200
        let childTarget: Int32 = 201
        func descriptorPlan() -> Int32 {
            var path = Array("/private/tmp/continuum-broker-plan-XXXXXX\0".utf8)
            let descriptor = path.withUnsafeMutableBufferPointer { buffer in
                mkstemp(UnsafeMutablePointer<CChar>(OpaquePointer(buffer.baseAddress)))
            }
            guard descriptor >= 0 else { return -1 }
            path.withUnsafeBufferPointer { buffer in
                _ = unlink(UnsafePointer<CChar>(OpaquePointer(buffer.baseAddress)))
            }
            let plan = Array("CONTINUUM_FD_PLAN_V1 0\n".utf8)
            let written = plan.withUnsafeBytes { bytes in
                Darwin.write(descriptor, bytes.baseAddress, bytes.count)
            }
            guard written == plan.count, lseek(descriptor, 0, SEEK_SET) == 0 else {
                Darwin.close(descriptor)
                return -1
            }
            return descriptor
        }
        let rootPlan = descriptorPlan()
        let childPlan = descriptorPlan()
        guard rootPlan >= 0, childPlan >= 0 else {
            if rootPlan >= 0 { Darwin.close(rootPlan) }
            if childPlan >= 0 { Darwin.close(childPlan) }
            return XCTFail("Expected private bootstrap descriptor plans")
        }
        defer {
            Darwin.close(rootPlan)
            Darwin.close(childPlan)
        }
        var rootRemaps = [
            continuum_spawn_descriptor_remap(
                source_descriptor: slave,
                target_descriptor: rootTarget
            ),
            continuum_spawn_descriptor_remap(
                source_descriptor: rootPlan,
                target_descriptor: 202
            ),
        ]
        var childRemaps = [
            continuum_spawn_descriptor_remap(
                source_descriptor: slave,
                target_descriptor: childTarget
            ),
            continuum_spawn_descriptor_remap(
                source_descriptor: childPlan,
                target_descriptor: 202
            ),
        ]
        let rootCapturedPID: Int32 = 40001
        let childCapturedPID: Int32 = 40002
        func preparePair() -> (continuum_status, OpaquePointer?) {
            var preparedPair: OpaquePointer?
            let status = arguments.withUnsafeBufferPointer { argumentBuffer in
                environmentEntries.withUnsafeBufferPointer { environmentBuffer in
                    rootRemaps.withUnsafeBufferPointer { rootRemapBuffer in
                        childRemaps.withUnsafeBufferPointer { childRemapBuffer in
                            var root = continuum_brokered_process_spec()
                            root.structure_size = UInt32(
                                MemoryLayout<continuum_brokered_process_spec>.size
                            )
                            root.captured_process_id = rootCapturedPID
                            root.captured_process_group_id = rootCapturedPID
                            root.foreground_process_group_id = rootCapturedPID
                            root.executable_path = UnsafePointer(executable)
                            root.arguments = argumentBuffer.baseAddress
                            root.environment = environmentBuffer.baseAddress
                            root.working_directory = UnsafePointer(directory)
                            root.descriptor_remaps = rootRemapBuffer.baseAddress
                            root.descriptor_remap_count = rootRemapBuffer.count
                            root.topology = continuum_spawn_process_topology(
                                structure_size: UInt32(
                                    MemoryLayout<continuum_spawn_process_topology>.size
                                ),
                                create_session: 1,
                                process_group_policy: CONTINUUM_SPAWN_PROCESS_GROUP_CREATE,
                                process_group_id: 0,
                                controlling_terminal_descriptor: rootTarget
                            )
                            root.disable_aslr = 0

                            var child = continuum_brokered_process_spec()
                            child.structure_size = root.structure_size
                            child.captured_process_id = childCapturedPID
                            child.captured_process_group_id = rootCapturedPID
                            child.foreground_process_group_id = rootCapturedPID
                            child.executable_path = UnsafePointer(executable)
                            child.arguments = argumentBuffer.baseAddress
                            child.environment = environmentBuffer.baseAddress
                            child.working_directory = UnsafePointer(directory)
                            child.descriptor_remaps = childRemapBuffer.baseAddress
                            child.descriptor_remap_count = childRemapBuffer.count
                            child.topology = continuum_spawn_process_topology(
                                structure_size: UInt32(
                                    MemoryLayout<continuum_spawn_process_topology>.size
                                ),
                                create_session: 0,
                                process_group_policy: CONTINUUM_SPAWN_PROCESS_GROUP_JOIN,
                                process_group_id: rootCapturedPID,
                                controlling_terminal_descriptor: -1
                            )
                            child.disable_aslr = 0
                            return continuum_brokered_pair_prepare(
                                bootstrap,
                                &root,
                                &child,
                                &preparedPair
                            )
                        }
                    }
                }
            }
            return (status, preparedPair)
        }
        let (prepareStatus, preparedPair) = preparePair()
        XCTAssertEqual(prepareStatus, CONTINUUM_STATUS_OK)
        guard let pair = preparedPair else {
            return XCTFail("Expected broker pair")
        }
        var shouldAbort = true
        defer {
            if shouldAbort {
                _ = continuum_brokered_pair_abort(pair, 2_000)
            }
        }
        var rootPID: Int32 = 0
        var childPID: Int32 = 0
        XCTAssertEqual(
            continuum_brokered_pair_process_identifiers(
                pair, &rootPID, &childPID
            ),
            CONTINUUM_STATUS_OK
        )
        XCTAssertGreaterThan(rootPID, 0)
        XCTAssertGreaterThan(childPID, 0)
        var rootInfo = proc_bsdinfo()
        XCTAssertEqual(
            proc_pidinfo(
                rootPID,
                PROC_PIDTBSDINFO,
                0,
                &rootInfo,
                Int32(MemoryLayout<proc_bsdinfo>.size)
            ),
            Int32(MemoryLayout<proc_bsdinfo>.size)
        )
        var childInfo = proc_bsdinfo()
        XCTAssertEqual(
            proc_pidinfo(
                childPID,
                PROC_PIDTBSDINFO,
                0,
                &childInfo,
                Int32(MemoryLayout<proc_bsdinfo>.size)
            ),
            Int32(MemoryLayout<proc_bsdinfo>.size)
        )
        XCTAssertEqual(Int32(childInfo.pbi_ppid), rootPID)
        XCTAssertEqual(getsid(rootPID), rootPID)
        XCTAssertEqual(getsid(childPID), rootPID)
        XCTAssertEqual(getpgid(rootPID), rootPID)
        XCTAssertEqual(getpgid(childPID), rootPID)
        XCTAssertNotEqual(rootInfo.pbi_flags & UInt32(PROC_FLAG_CONTROLT), 0)
        XCTAssertEqual(Int32(rootInfo.e_tpgid), rootPID)
        XCTAssertEqual(Int32(childInfo.e_tpgid), rootPID)

        for (pid, descriptor) in [(rootPID, rootTarget), (childPID, childTarget)] {
            var descriptors = Array(repeating: proc_fdinfo(), count: 256)
            let bytes = descriptors.withUnsafeMutableBytes { buffer in
                proc_pidinfo(
                    pid,
                    PROC_PIDLISTFDS,
                    0,
                    buffer.baseAddress,
                    Int32(buffer.count)
                )
            }
            XCTAssertGreaterThan(bytes, 0)
            let count = Int(bytes) / MemoryLayout<proc_fdinfo>.stride
            XCTAssertTrue(
                Set(descriptors.prefix(count).map(\.proc_fd)).contains(descriptor)
            )
        }

        for pid in [rootPID, childPID] {
            let prefix = "continuum-external-target-\(pid)-"
            let names = try FileManager.default.contentsOfDirectory(
                atPath: "/private/tmp"
            )
            XCTAssertFalse(names.contains { $0.hasPrefix(prefix) })
        }
        XCTAssertEqual(
            continuum_brokered_pair_abort(pair, 2_000),
            CONTINUUM_STATUS_OK
        )
        shouldAbort = false
        XCTAssertEqual(kill(rootPID, 0), -1)
        XCTAssertEqual(kill(childPID, 0), -1)

        var releaseMaster: Int32 = -1
        var releaseSlave: Int32 = -1
        XCTAssertEqual(
            openpty(&releaseMaster, &releaseSlave, nil, nil, nil),
            0
        )
        guard releaseMaster >= 0, releaseSlave >= 0 else {
            return XCTFail("Expected a second controller-owned PTY")
        }
        defer {
            Darwin.close(releaseMaster)
            Darwin.close(releaseSlave)
        }
        rootRemaps[0].source_descriptor = releaseSlave
        childRemaps[0].source_descriptor = releaseSlave
        let (releasePrepareStatus, releasePair) = preparePair()
        XCTAssertEqual(releasePrepareStatus, CONTINUUM_STATUS_OK)
        guard let releasePair else {
            return XCTFail("Expected a second broker pair")
        }
        var releasedRoot: Int32 = 0
        var releasedChild: Int32 = 0
        XCTAssertEqual(
            continuum_brokered_pair_process_identifiers(
                releasePair, &releasedRoot, &releasedChild
            ),
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(
            continuum_brokered_pair_advance_to_entry_stops(
                releasePair,
                5_000
            ),
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(kill(releasedRoot, 0), 0)
        XCTAssertEqual(kill(releasedChild, 0), 0)
        var rootSession: OpaquePointer?
        var childSession: OpaquePointer?
        XCTAssertEqual(
            continuum_remote_session_open(releasedRoot, &rootSession),
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(
            continuum_remote_session_open(releasedChild, &childSession),
            CONTINUUM_STATUS_OK
        )
        guard let rootSession, let childSession else {
            _ = continuum_brokered_pair_abort(releasePair, 2_000)
            return XCTFail("Expected broker-authorized remote sessions")
        }
        defer {
            continuum_remote_session_destroy(childSession)
            continuum_remote_session_destroy(rootSession)
        }
        XCTAssertEqual(
            continuum_brokered_pair_authorize_remote_session(
                releasePair,
                rootSession,
                CONTINUUM_BROKERED_PROCESS_ROOT
            ),
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(
            continuum_brokered_pair_authorize_remote_session(
                releasePair,
                childSession,
                CONTINUUM_BROKERED_PROCESS_CHILD
            ),
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(
            continuum_release_entry_stopped_child(releasedChild),
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(
            continuum_brokered_pair_note_released_process(
                releasePair,
                releasedChild
            ),
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(
            continuum_release_entry_stopped_child(releasedRoot),
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(
            continuum_brokered_pair_note_released_process(
                releasePair,
                releasedRoot
            ),
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(
            continuum_brokered_pair_finish(releasePair),
            CONTINUUM_STATUS_OK
        )
        kill(releasedChild, SIGKILL)
        kill(releasedRoot, SIGKILL)
        var releasedRootStatus: Int32 = 0
        waitpid(releasedRoot, &releasedRootStatus, 0)
        let childDeadline = Date().addingTimeInterval(2)
        while kill(releasedChild, 0) == 0 && Date() < childDeadline {
            usleep(1_000)
        }
        XCTAssertEqual(kill(releasedChild, 0), -1)

        var abortMaster: Int32 = -1
        var abortSlave: Int32 = -1
        XCTAssertEqual(openpty(&abortMaster, &abortSlave, nil, nil, nil), 0)
        guard abortMaster >= 0, abortSlave >= 0 else {
            return XCTFail("Expected an abort-path controller-owned PTY")
        }
        defer {
            Darwin.close(abortMaster)
            Darwin.close(abortSlave)
        }
        rootRemaps[0].source_descriptor = abortSlave
        childRemaps[0].source_descriptor = abortSlave
        let (abortPrepareStatus, abortPair) = preparePair()
        XCTAssertEqual(abortPrepareStatus, CONTINUUM_STATUS_OK)
        guard let abortPair else {
            return XCTFail("Expected an advance-then-abort broker pair")
        }
        var abortedRoot: Int32 = 0
        var abortedChild: Int32 = 0
        XCTAssertEqual(
            continuum_brokered_pair_process_identifiers(
                abortPair,
                &abortedRoot,
                &abortedChild
            ),
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(
            continuum_brokered_pair_advance_to_entry_stops(abortPair, 5_000),
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(
            continuum_brokered_pair_abort(abortPair, 2_000),
            CONTINUUM_STATUS_OK
        )
        let abortDeadline = Date().addingTimeInterval(2)
        while (kill(abortedRoot, 0) == 0 || kill(abortedChild, 0) == 0)
                && Date() < abortDeadline {
            usleep(1_000)
        }
        XCTAssertEqual(kill(abortedRoot, 0), -1)
        XCTAssertEqual(kill(abortedChild, 0), -1)
    }

    func testBootstrapV2ReplaysExactPipeFlagsAtExistingDescriptor() {
        var endpoints: [Int32] = [-1, -1]
        XCTAssertEqual(Darwin.pipe(&endpoints), 0)
        guard endpoints[0] >= 0, endpoints[1] >= 0 else {
            return XCTFail("Expected a pipe pair")
        }
        defer {
            Darwin.close(endpoints[0])
            Darwin.close(endpoints[1])
        }

        let target = fcntl(endpoints[0], F_DUPFD_CLOEXEC, 300)
        XCTAssertGreaterThanOrEqual(target, 300)
        guard target >= 300 else { return }
        defer { Darwin.close(target) }
        XCTAssertEqual(fcntl(target, F_SETFD, 0), 0)
        let initialStatus = fcntl(target, F_GETFL)
        XCTAssertGreaterThanOrEqual(initialStatus, 0)
        guard initialStatus >= 0 else { return }
        let desiredStatus = (initialStatus & O_ACCMODE) | O_NONBLOCK

        var temporaryPath = Array(
            "/private/tmp/continuum-v2-pipe-plan-XXXXXX\0".utf8
        )
        let planDescriptor = temporaryPath.withUnsafeMutableBufferPointer {
            buffer in
            mkstemp(
                UnsafeMutablePointer<CChar>(OpaquePointer(buffer.baseAddress))
            )
        }
        XCTAssertGreaterThanOrEqual(planDescriptor, 0)
        guard planDescriptor >= 0 else { return }
        temporaryPath.withUnsafeBufferPointer { buffer in
            _ = unlink(UnsafePointer<CChar>(OpaquePointer(buffer.baseAddress)))
        }
        let plan = Array(
            "CONTINUUM_FD_PLAN_V2 0 1\n"
                .appending("PIPE \(target) \(FD_CLOEXEC) \(desiredStatus)\n")
                .utf8
        )
        let written = plan.withUnsafeBytes { bytes in
            Darwin.write(planDescriptor, bytes.baseAddress, bytes.count)
        }
        XCTAssertEqual(written, plan.count)
        XCTAssertEqual(lseek(planDescriptor, 0, SEEK_SET), 0)

        var restoredCount: UInt32 = 0
        let reportDescriptor = continuum_bootstrap_apply_descriptor_plan(
            planDescriptor,
            &restoredCount
        )
        XCTAssertGreaterThanOrEqual(reportDescriptor, 0)
        guard reportDescriptor >= 0 else { return }
        defer { Darwin.close(reportDescriptor) }

        XCTAssertEqual(restoredCount, 1)
        var metadata = stat()
        XCTAssertEqual(fstat(target, &metadata), 0)
        XCTAssertEqual(metadata.st_mode & S_IFMT, S_IFIFO)
        XCTAssertEqual(fcntl(target, F_GETFD), FD_CLOEXEC)
        XCTAssertEqual(fcntl(target, F_GETFL), desiredStatus)
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
        var layoutInfo = continuum_remote_process_layout_info()
        XCTAssertEqual(
            continuum_remote_session_inspect_process_layout(nil, &layoutInfo),
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
        XCTAssertEqual(
            continuum_remote_process_group_live_status(nil),
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )

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
        var requiredLength = 0
        XCTAssertEqual(
            continuum_remote_process_group_copy_member_region_bytes(
                nil, 0, 0, nil, 0, &requiredLength
            ),
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
        var byte: UInt8 = 0
        XCTAssertEqual(
            continuum_remote_process_group_copy_member_region_bytes_range(
                nil, 0, 0, 0, &byte, 1
            ),
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
        XCTAssertEqual(
            continuum_remote_process_group_member_thread_count(nil, 0),
            0
        )
        var threadInfo = continuum_remote_thread_state_info()
        XCTAssertEqual(
            continuum_remote_process_group_copy_member_thread_info(
                nil, 0, 0, &threadInfo
            ),
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
        XCTAssertEqual(
            continuum_remote_process_group_copy_member_thread_general_state(
                nil, 0, 0, nil, 0, &requiredLength
            ),
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
        XCTAssertEqual(
            continuum_remote_process_group_copy_member_thread_vector_state(
                nil, 0, 0, nil, 0, &requiredLength
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
        let invalidRoots: [Int32] = [1]
        XCTAssertEqual(
            invalidRoots.withUnsafeBufferPointer { roots in
                continuum_remote_process_group_capture_roots(
                    roots.baseAddress,
                    roots.count,
                    1_024,
                    &snapshot,
                    &info
                )
            },
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
        let selfRoots: [Int32] = [getpid()]
        XCTAssertEqual(
            selfRoots.withUnsafeBufferPointer { roots in
                continuum_remote_process_group_capture_roots(
                    roots.baseAddress,
                    roots.count,
                    1_024,
                    &snapshot,
                    &info
                )
            },
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
        XCTAssertEqual(
            continuum_remote_process_group_capture_roots(
                nil,
                0,
                1_024,
                &snapshot,
                &info
            ),
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
        let validLookingRoots: [Int32] = [2]
        XCTAssertEqual(
            validLookingRoots.withUnsafeBufferPointer { roots in
                continuum_remote_process_group_capture_roots_with_resources(
                    roots.baseAddress,
                    roots.count,
                    1_024,
                    nil,
                    nil,
                    &snapshot,
                    &info
                )
            },
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
        var endpointCount = 0
        XCTAssertEqual(
            continuum_remote_process_group_copy_tcp_endpoints(
                nil,
                nil,
                0,
                &endpointCount
            ),
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
        var ptySafepoint = continuum_remote_pty_safepoint_status()
        XCTAssertEqual(
            continuum_remote_process_group_copy_pty_safepoint_status(
                nil,
                "/tmp/missing-bootstrap",
                &ptySafepoint
            ),
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
    }

    func testPTYSafepointRequiresEmptyQueuesWithoutConsumingInput() throws {
        let productsURL = Bundle(for: ContinuumRuntimeTests.self).bundleURL
            .deletingLastPathComponent()
        let targetURL = productsURL.appendingPathComponent(
            "ContinuumGUIExternalTarget"
        )
        let bootstrapURL = productsURL.appendingPathComponent(
            "libContinuumBootstrap.dylib"
        )
        XCTAssertTrue(FileManager.default.isExecutableFile(atPath: targetURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: bootstrapURL.path))

        var master: Int32 = -1
        var slave: Int32 = -1
        XCTAssertEqual(openpty(&master, &slave, nil, nil, nil), 0)
        guard master >= 0, slave >= 0 else {
            return XCTFail("Expected a PTY pair")
        }
        defer {
            if master >= 0 { Darwin.close(master) }
            if slave >= 0 { Darwin.close(slave) }
        }
        var attributes = termios()
        XCTAssertEqual(tcgetattr(slave, &attributes), 0)
        cfmakeraw(&attributes)
        XCTAssertEqual(tcsetattr(slave, TCSANOW, &attributes), 0)

        let process = Process()
        process.executableURL = targetURL
        var environment = ProcessInfo.processInfo.environment
        let observationURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("continuum-pty-safepoint-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: observationURL) }
        environment["DYLD_INSERT_LIBRARIES"] = bootstrapURL.path
        environment["CONTINUUM_ENABLE_CHECKPOINT_SAFEPOINTS"] = "1"
        environment["CONTINUUM_GUI_PROOF_OBSERVATION_PATH"] = observationURL.path
        process.environment = environment
        let slaveHandle = FileHandle(
            fileDescriptor: slave,
            closeOnDealloc: false
        )
        process.standardInput = slaveHandle
        process.standardOutput = slaveHandle
        process.standardError = slaveHandle
        try process.run()
        defer {
            _ = kill(process.processIdentifier, SIGUSR1)
            if process.isRunning {
                process.terminate()
                process.waitUntilExit()
            }
        }

        let readyDeadline = Date().addingTimeInterval(5)
        var observed = ""
        while Date() < readyDeadline
            && !observed.contains("ready") {
            observed = (try? String(
                contentsOf: observationURL,
                encoding: .utf8
            )) ?? ""
            usleep(10_000)
        }
        XCTAssertTrue(observed.contains("ready"))
        XCTAssertTrue(process.isRunning)
        var hasBootstrap: UInt8 = 0
        XCTAssertEqual(
            bootstrapURL.path.withCString { path in
                continuum_remote_process_has_bootstrap(
                    process.processIdentifier,
                    path,
                    &hasBootstrap
                )
            },
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(hasBootstrap, 1)

        func captureAtSafepoint() -> OpaquePointer? {
            guard kill(process.processIdentifier, SIGUSR2) == 0 else {
                return nil
            }
            for _ in 0..<40 {
                usleep(25_000)
                var snapshot: OpaquePointer?
                var info = continuum_remote_process_group_snapshot_info()
                let status = continuum_remote_process_group_capture(
                    process.processIdentifier,
                    1024 * 1024 * 1024,
                    &snapshot,
                    &info
                )
                guard status == CONTINUUM_STATUS_OK, let snapshot else {
                    continue
                }
                var statusReport = continuum_remote_pty_safepoint_status()
                let safepointStatus = bootstrapURL.path.withCString { path in
                    continuum_remote_process_group_copy_pty_safepoint_status(
                        snapshot,
                        path,
                        &statusReport
                    )
                }
                if safepointStatus == CONTINUUM_STATUS_OK {
                    return snapshot
                }
                continuum_remote_process_group_snapshot_destroy(snapshot)
            }
            return nil
        }

        guard let cleanSnapshot = captureAtSafepoint() else {
            return XCTFail("Expected a clean PTY safepoint snapshot")
        }
        var cleanStatus = continuum_remote_pty_safepoint_status()
        XCTAssertEqual(
            bootstrapURL.path.withCString { path in
                continuum_remote_process_group_copy_pty_safepoint_status(
                    cleanSnapshot,
                    path,
                    &cleanStatus
                )
            },
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(cleanStatus.process_count, 1)
        XCTAssertGreaterThanOrEqual(cleanStatus.pty_descriptor_count, 3)
        XCTAssertEqual(cleanStatus.queue_state_known, 1)
        XCTAssertEqual(cleanStatus.all_queues_zero, 1)

        XCTAssertEqual(kill(process.processIdentifier, SIGUSR1), 0)
        usleep(50_000)
        var staleStatus = continuum_remote_pty_safepoint_status()
        XCTAssertEqual(
            bootstrapURL.path.withCString { path in
                continuum_remote_process_group_copy_pty_safepoint_status(
                    cleanSnapshot,
                    path,
                    &staleStatus
                )
            },
            CONTINUUM_STATUS_VALIDATION_FAILED
        )
        continuum_remote_process_group_snapshot_destroy(cleanSnapshot)

        var queuedByte: UInt8 = 0x51
        XCTAssertEqual(Darwin.write(master, &queuedByte, 1), 1)
        guard let queuedSnapshot = captureAtSafepoint() else {
            return XCTFail("Expected a queued PTY safepoint snapshot")
        }
        var queuedStatus = continuum_remote_pty_safepoint_status()
        XCTAssertEqual(
            bootstrapURL.path.withCString { path in
                continuum_remote_process_group_copy_pty_safepoint_status(
                    queuedSnapshot,
                    path,
                    &queuedStatus
                )
            },
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(queuedStatus.queue_state_known, 1)
        XCTAssertEqual(queuedStatus.all_queues_zero, 0)

        let slaveFlags = fcntl(slave, F_GETFL)
        XCTAssertGreaterThanOrEqual(slaveFlags, 0)
        XCTAssertEqual(fcntl(slave, F_SETFL, slaveFlags | O_NONBLOCK), 0)
        var observedQueuedByte: UInt8 = 0
        XCTAssertEqual(Darwin.read(slave, &observedQueuedByte, 1), 1)
        XCTAssertEqual(observedQueuedByte, queuedByte)
        XCTAssertEqual(kill(process.processIdentifier, SIGUSR1), 0)
        continuum_remote_process_group_snapshot_destroy(queuedSnapshot)
    }

    func testCLISafepointCoordinatorPublishesWithoutRunLoop() throws {
        let productsURL = Bundle(for: ContinuumRuntimeTests.self).bundleURL
            .deletingLastPathComponent()
        let targetURL = productsURL.appendingPathComponent(
            "ContinuumExternalTarget"
        )
        let bootstrapURL = productsURL.appendingPathComponent(
            "libContinuumBootstrap.dylib"
        )
        XCTAssertTrue(FileManager.default.isExecutableFile(atPath: targetURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: bootstrapURL.path))

        var master: Int32 = -1
        var slave: Int32 = -1
        XCTAssertEqual(openpty(&master, &slave, nil, nil, nil), 0)
        guard master >= 0, slave >= 0 else {
            return XCTFail("Expected a PTY pair")
        }
        defer {
            Darwin.close(master)
            Darwin.close(slave)
        }

        let process = Process()
        process.executableURL = targetURL
        process.arguments = ["--continuum-idle-child"]
        var environment = ProcessInfo.processInfo.environment
        environment["DYLD_INSERT_LIBRARIES"] = bootstrapURL.path
        environment["CONTINUUM_ENABLE_CHECKPOINT_SAFEPOINTS"] = "1"
        process.environment = environment
        let slaveHandle = FileHandle(
            fileDescriptor: slave,
            closeOnDealloc: false
        )
        process.standardInput = slaveHandle
        process.standardOutput = slaveHandle
        process.standardError = slaveHandle
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
            _ = bootstrapURL.path.withCString { path in
                continuum_remote_process_has_bootstrap(
                    process.processIdentifier,
                    path,
                    &hasBootstrap
                )
            }
            if hasBootstrap == 0 { usleep(10_000) }
        } while hasBootstrap == 0 && Date() < bootstrapDeadline
        XCTAssertEqual(hasBootstrap, 1)
        usleep(100_000)
        XCTAssertTrue(process.isRunning)
        XCTAssertEqual(kill(process.processIdentifier, SIGUSR2), 0)

        var capturedSnapshot: OpaquePointer?
        var capturedStatus = continuum_remote_pty_safepoint_status()
        for _ in 0..<80 where capturedSnapshot == nil {
            usleep(25_000)
            var snapshot: OpaquePointer?
            var information = continuum_remote_process_group_snapshot_info()
            let captureStatus = continuum_remote_process_group_capture(
                process.processIdentifier,
                1024 * 1024 * 1024,
                &snapshot,
                &information
            )
            guard captureStatus == CONTINUUM_STATUS_OK, let snapshot else {
                continue
            }
            let safepointStatus = bootstrapURL.path.withCString { path in
                continuum_remote_process_group_copy_pty_safepoint_status(
                    snapshot,
                    path,
                    &capturedStatus
                )
            }
            if safepointStatus == CONTINUUM_STATUS_OK {
                capturedSnapshot = snapshot
            } else {
                continuum_remote_process_group_snapshot_destroy(snapshot)
            }
        }
        guard let capturedSnapshot else {
            return XCTFail("Expected the CLI coordinator to publish a safepoint")
        }
        XCTAssertEqual(capturedStatus.process_count, 1)
        XCTAssertGreaterThanOrEqual(capturedStatus.pty_descriptor_count, 3)
        XCTAssertEqual(capturedStatus.queue_state_known, 1)
        XCTAssertEqual(kill(process.processIdentifier, SIGUSR1), 0)
        continuum_remote_process_group_snapshot_destroy(capturedSnapshot)
    }

    func testProcessForestCapturesTwoIndependentRootsWithResources() throws {
        let targetURL = Bundle(for: ContinuumRuntimeTests.self).bundleURL
            .deletingLastPathComponent()
            .appendingPathComponent("ContinuumExternalTarget")
        let first = Process()
        first.executableURL = targetURL
        let firstInput = Pipe()
        let firstOutput = Pipe()
        first.standardInput = firstInput
        first.standardOutput = firstOutput
        try first.run()
        let readyData = firstOutput.fileHandleForReading.availableData
        XCTAssertTrue(
            String(decoding: readyData, as: UTF8.self).contains("\"ready\"")
        )

        let second = Process()
        second.executableURL = targetURL
        second.arguments = ["--continuum-idle-child"]
        try second.run()
        defer {
            if first.isRunning { first.terminate() }
            if second.isRunning { second.terminate() }
            first.waitUntilExit()
            second.waitUntilExit()
        }

        // Repeating one root proves overlapping input is deduplicated.
        let roots = [
            first.processIdentifier,
            second.processIdentifier,
            first.processIdentifier
        ]
        var snapshot: OpaquePointer?
        var info = continuum_remote_process_group_snapshot_info()
        let status = roots.withUnsafeBufferPointer { buffer in
            continuum_remote_process_group_capture_roots(
                buffer.baseAddress,
                buffer.count,
                512 * 1_024 * 1_024,
                &snapshot,
                &info
            )
        }
        XCTAssertEqual(status, CONTINUUM_STATUS_OK)
        guard let snapshot else {
            return XCTFail("Expected a coherent two-root process forest")
        }
        XCTAssertEqual(info.process_count, 3)
        XCTAssertEqual(continuum_remote_process_group_member_count(snapshot), 3)

        let expectedRoots = Set([
            first.processIdentifier,
            second.processIdentifier
        ])
        var capturedProcessIDs = Set<Int32>()
        var memberInfos: [continuum_remote_process_group_member_info] = []
        for index in 0..<3 {
            var member = continuum_remote_process_group_member_info()
            XCTAssertEqual(
                continuum_remote_process_group_copy_member_info(
                    snapshot,
                    index,
                    &member
                ),
                CONTINUUM_STATUS_OK
            )
            capturedProcessIDs.insert(member.process_id)
            memberInfos.append(member)
        }
        XCTAssertTrue(expectedRoots.isSubset(of: capturedProcessIDs))
        XCTAssertEqual(Set(memberInfos.prefix(2).map(\.process_id)), expectedRoots)
        for root in memberInfos.prefix(2) {
            XCTAssertEqual(root.parent_process_id, getpid())
        }
        for helper in memberInfos.suffix(1) {
            XCTAssertTrue(expectedRoots.contains(helper.parent_process_id))
        }
        continuum_remote_process_group_snapshot_destroy(snapshot)

        var resourceSnapshot: OpaquePointer?
        var resourceInfo = continuum_remote_process_group_snapshot_info()
        var callbackCount: Int32 = 0
        let resourceStatus = roots.withUnsafeBufferPointer { buffer in
            withUnsafeMutablePointer(to: &callbackCount) { context in
                continuum_remote_process_group_capture_roots_with_resources(
                    buffer.baseAddress,
                    buffer.count,
                    512 * 1_024 * 1_024,
                    continuumTestProcessForestResourceCallback,
                    UnsafeMutableRawPointer(context),
                    &resourceSnapshot,
                    &resourceInfo
                )
            }
        }
        XCTAssertEqual(resourceStatus, CONTINUUM_STATUS_OK)
        XCTAssertEqual(callbackCount, 1)
        XCTAssertEqual(resourceInfo.process_count, 3)
        XCTAssertEqual(
            continuum_remote_process_group_member_count(resourceSnapshot),
            3
        )
        continuum_remote_process_group_snapshot_destroy(resourceSnapshot)
    }

    func testProcessForestExportsReverseMatchedLocalTCPEndpoints() throws {
        let targetURL = Bundle(for: ContinuumRuntimeTests.self).bundleURL
            .deletingLastPathComponent()
            .appendingPathComponent("ContinuumExternalTarget")

        var listener = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(listener, 0)
        guard listener >= 0 else { return }
        defer {
            if listener >= 0 { Darwin.close(listener) }
        }
        var listenerAddress = sockaddr_in()
        listenerAddress.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        listenerAddress.sin_family = sa_family_t(AF_INET)
        listenerAddress.sin_addr.s_addr = inet_addr("127.0.0.1")
        var reuseAddress: Int32 = 1
        XCTAssertEqual(
            setsockopt(
                listener,
                SOL_SOCKET,
                SO_REUSEADDR,
                &reuseAddress,
                socklen_t(MemoryLayout<Int32>.size)
            ),
            0
        )
        XCTAssertEqual(
            setsockopt(
                listener,
                SOL_SOCKET,
                SO_REUSEPORT,
                &reuseAddress,
                socklen_t(MemoryLayout<Int32>.size)
            ),
            0
        )
        XCTAssertEqual(
            withUnsafePointer(to: &listenerAddress) { address in
                address.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.bind(
                        listener,
                        $0,
                        socklen_t(MemoryLayout<sockaddr_in>.size)
                    )
                }
            },
            0
        )
        XCTAssertEqual(Darwin.listen(listener, 1), 0)
        var listenerAddressLength = socklen_t(MemoryLayout<sockaddr_in>.size)
        XCTAssertEqual(
            withUnsafeMutablePointer(to: &listenerAddress) { address in
                address.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.getsockname(listener, $0, &listenerAddressLength)
                }
            },
            0
        )

        let clientDescriptor = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(clientDescriptor, 0)
        guard clientDescriptor >= 0 else { return }
        XCTAssertEqual(
            setsockopt(
                clientDescriptor,
                SOL_SOCKET,
                SO_REUSEADDR,
                &reuseAddress,
                socklen_t(MemoryLayout<Int32>.size)
            ),
            0
        )
        XCTAssertEqual(
            setsockopt(
                clientDescriptor,
                SOL_SOCKET,
                SO_REUSEPORT,
                &reuseAddress,
                socklen_t(MemoryLayout<Int32>.size)
            ),
            0
        )
        XCTAssertEqual(
            withUnsafePointer(to: &listenerAddress) { address in
                address.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(
                        clientDescriptor,
                        $0,
                        socklen_t(MemoryLayout<sockaddr_in>.size)
                    )
                }
            },
            0
        )
        let serverDescriptor = Darwin.accept(listener, nil, nil)
        XCTAssertGreaterThanOrEqual(serverDescriptor, 0)
        guard serverDescriptor >= 0 else {
            Darwin.close(clientDescriptor)
            return
        }
        XCTAssertEqual(fcntl(serverDescriptor, F_SETFD, FD_CLOEXEC), 0)
        XCTAssertEqual(fcntl(clientDescriptor, F_SETFD, FD_CLOEXEC), 0)

        let serverInput = FileHandle(
            fileDescriptor: serverDescriptor,
            closeOnDealloc: true
        )
        let clientInput = FileHandle(
            fileDescriptor: clientDescriptor,
            closeOnDealloc: true
        )
        let server = Process()
        let serverOutput = Pipe()
        server.executableURL = targetURL
        server.arguments = ["--continuum-helper"]
        server.standardInput = serverInput
        server.standardOutput = serverOutput
        try server.run()
        let client = Process()
        let clientOutput = Pipe()
        client.executableURL = targetURL
        client.arguments = ["--continuum-helper"]
        client.standardInput = clientInput
        client.standardOutput = clientOutput
        try client.run()
        defer {
            if server.isRunning { server.terminate() }
            if client.isRunning { client.terminate() }
            server.waitUntilExit()
            client.waitUntilExit()
        }

        XCTAssertTrue(
            String(
                decoding: serverOutput.fileHandleForReading.availableData,
                as: UTF8.self
            ).contains("\"ready\"")
        )
        XCTAssertTrue(
            String(
                decoding: clientOutput.fileHandleForReading.availableData,
                as: UTF8.self
            ).contains("\"ready\"")
        )

        let roots = [server.processIdentifier, client.processIdentifier]
        let capture = ContinuumTestTCPEndpointCapture()
        var snapshot: OpaquePointer?
        var info = continuum_remote_process_group_snapshot_info()
        let status = roots.withUnsafeBufferPointer { buffer in
            continuum_remote_process_group_capture_roots_with_resources(
                buffer.baseAddress,
                buffer.count,
                512 * 1_024 * 1_024,
                continuumTestTCPEndpointResourceCallback,
                Unmanaged.passUnretained(capture).toOpaque(),
                &snapshot,
                &info
            )
        }
        XCTAssertEqual(status, CONTINUUM_STATUS_OK)
        XCTAssertEqual(capture.status, CONTINUUM_STATUS_OK)
        guard snapshot != nil else {
            return XCTFail("Expected a captured two-process socket forest")
        }
        defer {
            if let snapshot {
                continuum_remote_process_group_snapshot_destroy(snapshot)
            }
        }

        let processIDs = Set(roots)
        let endpoints = capture.endpoints.filter {
            processIDs.contains($0.process_id)
        }
        XCTAssertEqual(info.process_count, 2)
        // Foundation may retain both the source descriptor and its stdin dup;
        // every owned fd is intentionally exported rather than deduplicated.
        XCTAssertGreaterThanOrEqual(endpoints.count, 2)
        XCTAssertEqual(Set(endpoints.map(\.process_id)), processIDs)
        for processID in processIDs {
            let descriptors = endpoints
                .filter { $0.process_id == processID }
                .map(\.file_descriptor)
            XCTAssertEqual(Set(descriptors).count, descriptors.count)
        }
        guard
            let serverEndpoint = endpoints.first(where: {
                $0.process_id == server.processIdentifier
            }),
            let clientEndpoint = endpoints.first(where: {
                $0.process_id == client.processIdentifier
            })
        else {
            return XCTFail("Expected one established endpoint per root")
        }
        var savedServerEndpoint = serverEndpoint
        var savedClientEndpoint = clientEndpoint

        XCTAssertGreaterThanOrEqual(serverEndpoint.file_descriptor, 0)
        XCTAssertGreaterThanOrEqual(clientEndpoint.file_descriptor, 0)
        XCTAssertEqual(serverEndpoint.domain, AF_INET)
        XCTAssertEqual(clientEndpoint.domain, AF_INET)
        XCTAssertEqual(serverEndpoint.socket_type, clientEndpoint.socket_type)
        XCTAssertEqual(serverEndpoint.protocol, clientEndpoint.protocol)
        XCTAssertEqual(serverEndpoint.tcp_state, clientEndpoint.tcp_state)
        XCTAssertEqual(serverEndpoint.receive_shutdown, 0)
        XCTAssertEqual(serverEndpoint.send_shutdown, 0)
        XCTAssertEqual(clientEndpoint.receive_shutdown, 0)
        XCTAssertEqual(clientEndpoint.send_shutdown, 0)
        XCTAssertEqual(serverEndpoint.receive_queue_bytes, 0)
        XCTAssertEqual(serverEndpoint.send_queue_bytes, 0)
        XCTAssertEqual(clientEndpoint.receive_queue_bytes, 0)
        XCTAssertEqual(clientEndpoint.send_queue_bytes, 0)
        XCTAssertLessThanOrEqual(
            Int(serverEndpoint.local_address_length),
            Int(CONTINUUM_REMOTE_SOCKET_ADDRESS_MAX)
        )
        XCTAssertLessThanOrEqual(
            Int(clientEndpoint.remote_address_length),
            Int(CONTINUUM_REMOTE_SOCKET_ADDRESS_MAX)
        )
        XCTAssertEqual(
            continuumTestAddressBytes(serverEndpoint, local: true),
            continuumTestAddressBytes(clientEndpoint, local: false)
        )
        XCTAssertEqual(
            continuumTestAddressBytes(serverEndpoint, local: false),
            continuumTestAddressBytes(clientEndpoint, local: true)
        )
        XCTAssertEqual(capture.undersizedStatus, CONTINUUM_STATUS_RANGE_ERROR)

        continuum_remote_process_group_snapshot_destroy(snapshot)
        snapshot = nil
        serverInput.closeFile()
        clientInput.closeFile()
        Darwin.close(listener)
        listener = -1
        XCTAssertEqual(kill(server.processIdentifier, SIGKILL), 0)
        XCTAssertEqual(kill(client.processIdentifier, SIGKILL), 0)
        server.waitUntilExit()
        client.waitUntilExit()

        var nonemptyEndpoint = savedServerEndpoint
        nonemptyEndpoint.receive_queue_bytes = 1
        var rejectedFirst: Int32 = 123
        var rejectedSecond: Int32 = 456
        XCTAssertEqual(
            continuum_recreate_closed_loopback_tcp_pair(
                &nonemptyEndpoint,
                &savedClientEndpoint,
                &rejectedFirst,
                &rejectedSecond
            ),
            CONTINUUM_STATUS_VALIDATION_FAILED
        )
        XCTAssertEqual(rejectedFirst, -1)
        XCTAssertEqual(rejectedSecond, -1)

        var recreatedFirst: Int32 = -1
        var recreatedSecond: Int32 = -1
        XCTAssertEqual(
            continuum_recreate_closed_loopback_tcp_pair(
                &savedServerEndpoint,
                &savedClientEndpoint,
                &recreatedFirst,
                &recreatedSecond
            ),
            CONTINUUM_STATUS_OK
        )
        XCTAssertGreaterThanOrEqual(recreatedFirst, 0)
        XCTAssertGreaterThanOrEqual(recreatedSecond, 0)
        guard recreatedFirst >= 0, recreatedSecond >= 0 else { return }
        defer {
            Darwin.close(recreatedFirst)
            Darwin.close(recreatedSecond)
        }
        XCTAssertNotEqual(fcntl(recreatedFirst, F_GETFD) & FD_CLOEXEC, 0)
        XCTAssertNotEqual(fcntl(recreatedSecond, F_GETFD) & FD_CLOEXEC, 0)

        var sent: UInt8 = 0xA5
        XCTAssertEqual(Darwin.write(recreatedSecond, &sent, 1), 1)
        var received: UInt8 = 0
        XCTAssertEqual(Darwin.read(recreatedFirst, &received, 1), 1)
        XCTAssertEqual(received, sent)
    }

    func testDescriptorGraphExportsPipePeersAndAliases() throws {
        let channel = Pipe()
        let process = Process()
        process.executableURL = Bundle(for: ContinuumRuntimeTests.self).bundleURL
            .deletingLastPathComponent()
            .appendingPathComponent("ContinuumExternalTarget")
        process.arguments = ["--continuum-idle-child"]
        process.standardInput = channel.fileHandleForReading
        process.standardOutput = channel.fileHandleForWriting
        process.standardError = channel.fileHandleForWriting
        try process.run()
        defer {
            if process.isRunning { process.terminate() }
            process.waitUntilExit()
        }
        let capture = ContinuumTestDescriptorGraphCapture()
        var snapshot: OpaquePointer?
        var info = continuum_remote_process_group_snapshot_info()
        XCTAssertEqual(
            continuum_remote_process_group_capture_with_resources(
                process.processIdentifier,
                512 * 1_024 * 1_024,
                continuumTestDescriptorGraphResourceCallback,
                Unmanaged.passUnretained(capture).toOpaque(),
                &snapshot,
                &info
            ),
            CONTINUUM_STATUS_OK
        )
        defer {
            if let snapshot {
                continuum_remote_process_group_snapshot_destroy(snapshot)
            }
        }
        XCTAssertEqual(capture.status, CONTINUUM_STATUS_OK)
        XCTAssertEqual(capture.undersizedStatus, CONTINUUM_STATUS_RANGE_ERROR)
        XCTAssertEqual(capture.sockets.count, 0)
        XCTAssertEqual(capture.kqueues.count, 0)
        XCTAssertEqual(capture.registrations.count, 0)
        XCTAssertEqual(capture.pipes.count, 2)
        XCTAssertGreaterThanOrEqual(capture.handles.count, 3)
        XCTAssertTrue(capture.handles.allSatisfy { $0.descriptor_flags == -1 })

        let pipeIdentities = Set(capture.pipes.map(\.resource_identity))
        XCTAssertEqual(pipeIdentities.count, 2)
        for pipe in capture.pipes {
            XCTAssertEqual(pipe.queued_bytes, 0)
            XCTAssertGreaterThan(pipe.capacity, 0)
            XCTAssertTrue(pipeIdentities.contains(pipe.peer_identity))
        }
        let standardOutputHandles = capture.handles.filter {
            $0.process_id == process.processIdentifier
                && ($0.file_descriptor == STDOUT_FILENO
                    || $0.file_descriptor == STDERR_FILENO)
        }
        XCTAssertEqual(standardOutputHandles.count, 2)
        XCTAssertEqual(
            Set(standardOutputHandles.map(\.resource_identity)).count,
            1
        )
    }

    func testRecreatesClosedEmptyReciprocalPipePair() {
        var measuredDescriptors = [Int32](repeating: -1, count: 2)
        XCTAssertEqual(
            measuredDescriptors.withUnsafeMutableBufferPointer {
                pipe($0.baseAddress!)
            },
            0
        )
        guard measuredDescriptors.allSatisfy({ $0 >= 0 }) else {
            return XCTFail("Expected a pipe for measuring the host capacity")
        }
        var measuredStat = stat()
        XCTAssertEqual(fstat(measuredDescriptors[0], &measuredStat), 0)
        Darwin.close(measuredDescriptors[0])
        Darwin.close(measuredDescriptors[1])
        let capacity = UInt64(measuredStat.st_blksize)
        XCTAssertGreaterThan(capacity, 0)

        var first = continuum_remote_pipe_resource_info()
        first.resource_identity = 0x1111
        first.peer_identity = 0x2222
        first.capacity = capacity
        var second = continuum_remote_pipe_resource_info()
        second.resource_identity = 0x2222
        second.peer_identity = 0x1111
        second.capacity = capacity

        var recreatedRead: Int32 = -1
        var recreatedWrite: Int32 = -1
        XCTAssertEqual(
            continuum_recreate_closed_empty_pipe_pair(
                &first,
                &second,
                &recreatedRead,
                &recreatedWrite
            ),
            CONTINUUM_STATUS_OK
        )
        guard recreatedRead >= 0, recreatedWrite >= 0 else {
            return XCTFail("Expected a recreated pipe pair")
        }
        defer {
            Darwin.close(recreatedRead)
            Darwin.close(recreatedWrite)
        }
        XCTAssertNotEqual(recreatedRead, recreatedWrite)
        XCTAssertNotEqual(fcntl(recreatedRead, F_GETFD) & FD_CLOEXEC, 0)
        XCTAssertNotEqual(fcntl(recreatedWrite, F_GETFD) & FD_CLOEXEC, 0)

        var readStat = stat()
        var writeStat = stat()
        XCTAssertEqual(fstat(recreatedRead, &readStat), 0)
        XCTAssertEqual(fstat(recreatedWrite, &writeStat), 0)
        XCTAssertEqual(readStat.st_mode & S_IFMT, S_IFIFO)
        XCTAssertEqual(writeStat.st_mode & S_IFMT, S_IFIFO)
        XCTAssertEqual(UInt64(readStat.st_blksize), capacity)
        XCTAssertEqual(UInt64(writeStat.st_blksize), capacity)

        var sent: UInt8 = 0xC7
        XCTAssertEqual(Darwin.write(recreatedWrite, &sent, 1), 1)
        var received: UInt8 = 0
        XCTAssertEqual(Darwin.read(recreatedRead, &received, 1), 1)
        XCTAssertEqual(received, sent)
    }

    func testClosedEmptyPipeRecreationRejectsStaleMetadataWithoutLeaks() {
        func openDescriptors() -> Set<Int32> {
            var descriptors = Array(repeating: proc_fdinfo(), count: 4096)
            let bytes = descriptors.withUnsafeMutableBytes { buffer in
                proc_pidinfo(
                    getpid(),
                    PROC_PIDLISTFDS,
                    0,
                    buffer.baseAddress,
                    Int32(buffer.count)
                )
            }
            XCTAssertGreaterThanOrEqual(bytes, 0)
            let count = max(0, Int(bytes)) / MemoryLayout<proc_fdinfo>.stride
            return Set(descriptors.prefix(count).map(\.proc_fd))
        }

        var measuredDescriptors = [Int32](repeating: -1, count: 2)
        XCTAssertEqual(
            measuredDescriptors.withUnsafeMutableBufferPointer {
                pipe($0.baseAddress!)
            },
            0
        )
        guard measuredDescriptors.allSatisfy({ $0 >= 0 }) else {
            return XCTFail("Expected a pipe for measuring the host capacity")
        }
        var measuredStat = stat()
        XCTAssertEqual(fstat(measuredDescriptors[0], &measuredStat), 0)
        Darwin.close(measuredDescriptors[0])
        Darwin.close(measuredDescriptors[1])
        let capacity = UInt64(measuredStat.st_blksize)

        var first = continuum_remote_pipe_resource_info()
        first.resource_identity = 0x3333
        first.peer_identity = 0x4444
        first.capacity = capacity
        var second = continuum_remote_pipe_resource_info()
        second.resource_identity = 0x4444
        second.peer_identity = 0x3333
        second.capacity = capacity

        var rejectedFirst: Int32 = 123
        var rejectedSecond: Int32 = 456
        var nonreciprocal = second
        nonreciprocal.peer_identity = 0x5555
        let descriptorsBeforeMetadataRejection = openDescriptors()
        XCTAssertEqual(
            continuum_recreate_closed_empty_pipe_pair(
                &first,
                &nonreciprocal,
                &rejectedFirst,
                &rejectedSecond
            ),
            CONTINUUM_STATUS_VALIDATION_FAILED
        )
        XCTAssertEqual(rejectedFirst, -1)
        XCTAssertEqual(rejectedSecond, -1)
        XCTAssertEqual(openDescriptors(), descriptorsBeforeMetadataRejection)

        var nonempty = first
        nonempty.queued_bytes = 1
        XCTAssertEqual(
            continuum_recreate_closed_empty_pipe_pair(
                &nonempty,
                &second,
                &rejectedFirst,
                &rejectedSecond
            ),
            CONTINUUM_STATUS_VALIDATION_FAILED
        )
        XCTAssertEqual(rejectedFirst, -1)
        XCTAssertEqual(rejectedSecond, -1)

        var incompatible = second
        incompatible.capacity &+= 1
        XCTAssertEqual(
            continuum_recreate_closed_empty_pipe_pair(
                &first,
                &incompatible,
                &rejectedFirst,
                &rejectedSecond
            ),
            CONTINUUM_STATUS_VALIDATION_FAILED
        )
        XCTAssertEqual(rejectedFirst, -1)
        XCTAssertEqual(rejectedSecond, -1)

        first.capacity &+= 1
        second.capacity &+= 1
        let descriptorsBeforeCapacityRejection = openDescriptors()
        XCTAssertEqual(
            continuum_recreate_closed_empty_pipe_pair(
                &first,
                &second,
                &rejectedFirst,
                &rejectedSecond
            ),
            CONTINUUM_STATUS_VALIDATION_FAILED
        )
        XCTAssertEqual(rejectedFirst, -1)
        XCTAssertEqual(rejectedSecond, -1)
        XCTAssertEqual(openDescriptors(), descriptorsBeforeCapacityRejection)
    }

    func testProcessForestExportsAndRecreatesClosedPTYPair() throws {
        let targetURL = Bundle(for: ContinuumRuntimeTests.self).bundleURL
            .deletingLastPathComponent()
            .appendingPathComponent("ContinuumExternalTarget")

        var originalMaster: Int32 = -1
        var originalSlave: Int32 = -1
        var originalAttributes = termios()
        var originalWindow = winsize(
            ws_row: 44,
            ws_col: 132,
            ws_xpixel: 0,
            ws_ypixel: 0
        )
        XCTAssertEqual(
            openpty(
                &originalMaster,
                &originalSlave,
                nil,
                nil,
                &originalWindow
            ),
            0
        )
        guard originalMaster >= 0, originalSlave >= 0 else {
            return XCTFail("Expected an open PTY pair")
        }
        XCTAssertEqual(tcgetattr(originalSlave, &originalAttributes), 0)
        cfmakeraw(&originalAttributes)
        XCTAssertEqual(tcsetattr(originalSlave, TCSANOW, &originalAttributes), 0)
        XCTAssertEqual(
            ioctl(originalSlave, TIOCSWINSZ, &originalWindow),
            0
        )

        let helper = Process()
        let slaveHandle = FileHandle(
            fileDescriptor: originalSlave,
            closeOnDealloc: false
        )
        helper.executableURL = targetURL
        helper.arguments = ["--continuum-helper"]
        helper.standardInput = slaveHandle
        helper.standardOutput = slaveHandle
        helper.standardError = slaveHandle
        try helper.run()
        slaveHandle.closeFile()
        originalSlave = -1
        defer {
            if helper.isRunning {
                helper.terminate()
                helper.waitUntilExit()
            }
            if originalMaster >= 0 { Darwin.close(originalMaster) }
            if originalSlave >= 0 { Darwin.close(originalSlave) }
        }

        var readyBytes = Array(repeating: UInt8(0), count: 256)
        let readyCount = Darwin.read(
            originalMaster,
            &readyBytes,
            readyBytes.count
        )
        XCTAssertGreaterThan(readyCount, 0)
        if readyCount > 0 {
            XCTAssertTrue(
                String(decoding: readyBytes.prefix(readyCount), as: UTF8.self)
                    .contains("\"ready\"")
            )
        }

        let capture = ContinuumTestPTYDescriptorCapture()
        var snapshot: OpaquePointer?
        var info = continuum_remote_process_group_snapshot_info()
        XCTAssertEqual(
            continuum_remote_process_group_capture_with_resources(
                helper.processIdentifier,
                512 * 1_024 * 1_024,
                continuumTestPTYDescriptorResourceCallback,
                Unmanaged.passUnretained(capture).toOpaque(),
                &snapshot,
                &info
            ),
            CONTINUUM_STATUS_OK
        )
        XCTAssertEqual(capture.status, CONTINUUM_STATUS_OK)
        XCTAssertEqual(capture.undersizedStatus, CONTINUUM_STATUS_RANGE_ERROR)
        guard let snapshot else {
            return XCTFail("Expected a captured PTY helper")
        }
        continuum_remote_process_group_snapshot_destroy(snapshot)

        let helperDescriptors = capture.descriptors.filter {
            $0.process_id == helper.processIdentifier
        }
        XCTAssertGreaterThanOrEqual(helperDescriptors.count, 3)
        XCTAssertTrue(helperDescriptors.allSatisfy {
            $0.role == CONTINUUM_REMOTE_PTY_ROLE_SLAVE
        })
        XCTAssertEqual(Set(helperDescriptors.map(\.alias_identity)).count, 1)
        XCTAssertEqual(Set(helperDescriptors.map(\.tty_index)).count, 1)
        XCTAssertTrue(helperDescriptors.allSatisfy {
            $0.terminal_attributes_known != 0 && $0.window_size_known != 0
        })
        XCTAssertTrue(helperDescriptors.allSatisfy {
            $0.input_queue_known == 0 && $0.output_queue_known == 0
        })
        guard var savedSlave = helperDescriptors.first else {
            return XCTFail("Expected a saved PTY slave descriptor")
        }

        helper.terminate()
        helper.waitUntilExit()
        Darwin.close(originalMaster)
        originalMaster = -1

        var savedMaster = savedSlave
        savedMaster.file_descriptor = savedSlave.file_descriptor + 100
        savedMaster.role = CONTINUUM_REMOTE_PTY_ROLE_MASTER
        savedMaster.alias_identity = continuumTestPTYAlias(
            ttyIndex: savedMaster.tty_index,
            role: CONTINUUM_REMOTE_PTY_ROLE_MASTER
        )

        var invalidMaster = savedMaster
        invalidMaster.tty_index &+= 1
        var rejectedMaster: Int32 = 123
        var rejectedSlave: Int32 = 456
        XCTAssertEqual(
            continuum_recreate_closed_pty_pair(
                &invalidMaster,
                &savedSlave,
                &rejectedMaster,
                &rejectedSlave
            ),
            CONTINUUM_STATUS_INVALID_ARGUMENT
        )
        XCTAssertEqual(rejectedMaster, -1)
        XCTAssertEqual(rejectedSlave, -1)

        var nonemptySlave = savedSlave
        nonemptySlave.input_queue_known = 1
        nonemptySlave.input_queue_bytes = 1
        XCTAssertEqual(
            continuum_recreate_closed_pty_pair(
                &savedMaster,
                &nonemptySlave,
                &rejectedMaster,
                &rejectedSlave
            ),
            CONTINUUM_STATUS_VALIDATION_FAILED
        )

        var derivedMaster: Int32 = -1
        var derivedSlave: Int32 = -1
        XCTAssertEqual(
            continuum_recreate_closed_pty_from_slave(
                &savedSlave,
                &derivedMaster,
                &derivedSlave
            ),
            CONTINUUM_STATUS_OK
        )
        XCTAssertGreaterThanOrEqual(derivedMaster, 0)
        XCTAssertGreaterThanOrEqual(derivedSlave, 0)
        if derivedMaster >= 0 { Darwin.close(derivedMaster) }
        if derivedSlave >= 0 { Darwin.close(derivedSlave) }

        var recreatedMaster: Int32 = -1
        var recreatedSlave: Int32 = -1
        XCTAssertEqual(
            continuum_recreate_closed_pty_pair(
                &savedMaster,
                &savedSlave,
                &recreatedMaster,
                &recreatedSlave
            ),
            CONTINUUM_STATUS_OK
        )
        guard recreatedMaster >= 0, recreatedSlave >= 0 else {
            return XCTFail("Expected a recreated PTY pair")
        }
        defer {
            Darwin.close(recreatedMaster)
            Darwin.close(recreatedSlave)
        }
        XCTAssertNotEqual(fcntl(recreatedMaster, F_GETFD) & FD_CLOEXEC, 0)
        XCTAssertNotEqual(fcntl(recreatedSlave, F_GETFD) & FD_CLOEXEC, 0)

        var recreatedAttributes = termios()
        var recreatedWindow = winsize()
        XCTAssertEqual(tcgetattr(recreatedSlave, &recreatedAttributes), 0)
        XCTAssertEqual(ioctl(recreatedSlave, TIOCGWINSZ, &recreatedWindow), 0)
        XCTAssertEqual(
            withUnsafeBytes(of: savedSlave.terminal_attributes) { Data($0) },
            withUnsafeBytes(of: recreatedAttributes) { Data($0) }
        )
        XCTAssertEqual(recreatedWindow.ws_row, savedSlave.window_size.ws_row)
        XCTAssertEqual(recreatedWindow.ws_col, savedSlave.window_size.ws_col)

        var slaveByte: UInt8 = 0x51
        XCTAssertEqual(Darwin.write(recreatedSlave, &slaveByte, 1), 1)
        var masterByte: UInt8 = 0
        XCTAssertEqual(Darwin.read(recreatedMaster, &masterByte, 1), 1)
        XCTAssertEqual(masterByte, slaveByte)

        var masterByteToSend: UInt8 = 0xA7
        XCTAssertEqual(Darwin.write(recreatedMaster, &masterByteToSend, 1), 1)
        var slaveByteReceived: UInt8 = 0
        XCTAssertEqual(Darwin.read(recreatedSlave, &slaveByteReceived, 1), 1)
        XCTAssertEqual(slaveByteReceived, masterByteToSend)
    }

    func testRemoteSelfSessionCapturesThreadEvidenceAndRestoresArenaBytes() {
        let workerStarted = DispatchSemaphore(value: 0)
        let workerRelease = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            workerStarted.signal()
            workerRelease.wait()
        }
        XCTAssertEqual(workerStarted.wait(timeout: .now() + 2), .success)
        defer { workerRelease.signal() }

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
        XCTAssertGreaterThan(first.thread_handle, 0)
        XCTAssertGreaterThan(first.pthread_object_address, 0)
        XCTAssertEqual(
            first.origin,
            CONTINUUM_REMOTE_THREAD_ORIGIN_PTHREAD
        )
        XCTAssertGreaterThan(first.general_state_length, 0)
        XCTAssertGreaterThan(first.vector_state_length, 0)
        var foundWorkqueue = false
        for index in 0..<threadCount {
            var info = continuum_remote_thread_state_info()
            XCTAssertEqual(
                continuum_remote_thread_snapshot_info(threads, index, &info),
                CONTINUUM_STATUS_OK
            )
            if info.origin == CONTINUUM_REMOTE_THREAD_ORIGIN_WORKQUEUE {
                foundWorkqueue = true
            }
        }
        XCTAssertTrue(
            foundWorkqueue,
            "Expected the blocked DispatchQueue worker to be classified"
        )

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
            CONTINUUM_STATUS_PROCESS_TREE_CHANGED,
            CONTINUUM_STATUS_SPAWN_FAILED
        ]

        for status in statuses {
            let message = String(cString: continuum_status_string(status))
            XCTAssertFalse(message.isEmpty)
            XCTAssertNotEqual(message, "unknown status")
        }
    }
}
