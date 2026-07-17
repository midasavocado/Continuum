import ContinuumCore
import ContinuumRuntime
import ContinuumStore
import CryptoKit
import Darwin
import Foundation

/// Connects the process-group Mach proof to the shipping app as an explicitly
/// experimental, hot-only backend. The C snapshot owns live task ports and is
/// therefore valid only while this service and the exact original processes
/// remain alive.
public actor HotProcessCheckpointService: CheckpointCapturing {
    public nonisolated var supportsFunctionalRestore: Bool { true }

    private let maximumCapturedBytes: UInt64
    private let maximumRetainedSnapshots: Int
    private let usesInjectedSafepoints: Bool
    private let bootstrapLibraryPath: String?
    private let fileCheckpointStore: APFSLocalFileCheckpointStore?
    private var handles: [SnapshotID: HotProcessSnapshotHandle] = [:]
    private var retentionOrder: [SnapshotID] = []

    public init(
        maximumCapturedBytes: UInt64 = UInt64(ContinuumConstants.defaultHotMemoryBudgetBytes),
        maximumRetainedSnapshots: Int = 8,
        usesInjectedSafepoints: Bool = false,
        bootstrapLibraryURL: URL? = nil,
        fileCheckpointRootURL: URL? = nil
    ) {
        self.maximumCapturedBytes = maximumCapturedBytes
        self.maximumRetainedSnapshots = max(maximumRetainedSnapshots, 2)
        self.usesInjectedSafepoints = usesInjectedSafepoints
        self.bootstrapLibraryPath = bootstrapLibraryURL?.standardizedFileURL.path
            ?? Bundle.main.privateFrameworksURL?
                .appendingPathComponent("libContinuumBootstrap.dylib")
                .standardizedFileURL.path
        if let fileCheckpointRootURL {
            // Hot file roots cannot outlive their in-memory task snapshots.
            // Clear leftovers from a prior Continuum process before arming.
            try? FileManager.default.removeItem(at: fileCheckpointRootURL)
            self.fileCheckpointStore = try? APFSLocalFileCheckpointStore(
                rootURL: fileCheckpointRootURL
            )
        } else {
            self.fileCheckpointStore = nil
        }
    }

    public func capture(
        app: AppIdentity,
        processIdentifiers: [Int32],
        kind: SnapshotKind,
        branchID: BranchID
    ) async throws -> SnapshotCapture {
        guard let rootProcessIdentifier = processIdentifiers.first,
              rootProcessIdentifier > 0 else {
            throw ContinuumError.runtimeUnsupported(
                "Continuum could not identify the root process for this app."
            )
        }

        let snapshotID = UUID()
        var safepointProcessIdentifiers: [Int32] = []
        if usesInjectedSafepoints {
            guard let bootstrapLibraryPath else {
                throw ContinuumError.runtimeUnsupported(
                    "Continuum's checkpoint bootstrap is missing."
                )
            }
            let captureMembers = Self.captureMembers(
                rootedAt: Set(processIdentifiers)
            )
            guard !captureMembers.isEmpty else {
                throw ContinuumError.runtimeUnsupported(
                    "Continuum could not discover the app's process group."
                )
            }
            for processIdentifier in captureMembers {
                var hasBootstrap: UInt8 = 0
                let preflight = bootstrapLibraryPath.withCString {
                    continuum_remote_process_has_bootstrap(
                        processIdentifier,
                        $0,
                        &hasBootstrap
                    )
                }
                guard preflight == CONTINUUM_STATUS_OK, hasBootstrap != 0 else {
                    throw ContinuumError.runtimeUnsupported(
                        "Continuum did not change or restart process \(processIdentifier), so no false snapshot was created. Every helper must be armed before launch."
                    )
                }
            }
            for processIdentifier in captureMembers {
                guard kill(processIdentifier, SIGUSR2) == 0 else {
                    throw ContinuumError.runtimeUnsupported(
                        "Continuum could not request process \(processIdentifier)'s capture safepoint."
                    )
                }
                safepointProcessIdentifiers.append(processIdentifier)
            }
            var pendingSafepoints = Set(captureMembers)
            let deadline = ContinuousClock.now + .seconds(2)
            while !pendingSafepoints.isEmpty, ContinuousClock.now < deadline {
                for processIdentifier in Array(pendingSafepoints) {
                    var isActive: UInt8 = 0
                    let status = bootstrapLibraryPath.withCString {
                        continuum_remote_process_safepoint_is_active(
                            processIdentifier,
                            $0,
                            &isActive
                        )
                    }
                    guard status == CONTINUUM_STATUS_OK else {
                        throw ContinuumError.runtimeUnsupported(
                            "Continuum could not authenticate process \(processIdentifier)'s checkpoint boundary: \(statusDescription(status))."
                        )
                    }
                    if isActive != 0 {
                        pendingSafepoints.remove(processIdentifier)
                    }
                }
                if !pendingSafepoints.isEmpty { usleep(10_000) }
            }
            guard pendingSafepoints.isEmpty else {
                throw ContinuumError.runtimeUnsupported(
                    "The app and its helpers did not reach a checkpoint boundary within two seconds."
                )
            }
        }
        defer {
            for processIdentifier in safepointProcessIdentifiers {
                _ = kill(processIdentifier, SIGUSR1)
            }
        }
        var rawSnapshot: OpaquePointer?
        var info = continuum_remote_process_group_snapshot_info()
        let resourceBox = HotResourceInventoryCallbackBox(
            fileCheckpointStore: fileCheckpointStore,
            captureSnapshotID: snapshotID,
            descriptorBootstrapLibraryPath: usesInjectedSafepoints
                ? bootstrapLibraryPath
                : nil
        )
        let resourceContext = Unmanaged.passUnretained(resourceBox).toOpaque()
        let roots = UnsafeMutablePointer<Int32>.allocate(
            capacity: processIdentifiers.count
        )
        roots.initialize(from: processIdentifiers, count: processIdentifiers.count)
        defer {
            roots.deinitialize(count: processIdentifiers.count)
            roots.deallocate()
        }
        let status = continuum_remote_process_group_capture_roots_with_resources(
            roots,
            processIdentifiers.count,
            maximumCapturedBytes,
            continuumCaptureHotResourceInventory,
            resourceContext,
            &rawSnapshot,
            &info
        )
        guard status == CONTINUUM_STATUS_OK, let rawSnapshot else {
            if let failureDescription = resourceBox.failureDescription {
                throw ContinuumError.runtimeUnsupported(failureDescription)
            }
            throw captureError(status: status, appName: app.displayName)
        }
        var ptySafepointStatus: continuum_remote_pty_safepoint_status?
        if usesInjectedSafepoints {
            guard let bootstrapLibraryPath else {
                continuum_remote_process_group_snapshot_destroy(rawSnapshot)
                throw ContinuumError.runtimeUnsupported(
                    "Continuum's checkpoint bootstrap is missing."
                )
            }
            var report = continuum_remote_pty_safepoint_status()
            let reportStatus = bootstrapLibraryPath.withCString {
                continuum_remote_process_group_copy_pty_safepoint_status(
                    rawSnapshot,
                    $0,
                    &report
                )
            }
            guard reportStatus == CONTINUUM_STATUS_OK,
                  report.process_count
                    == continuum_remote_process_group_member_count(rawSnapshot),
                  report.queue_state_known != 0,
                  report.all_queues_zero != 0 else {
                continuum_remote_process_group_snapshot_destroy(rawSnapshot)
                throw ContinuumError.runtimeUnsupported(
                    "The app and its helpers did not reach one coherent checkpoint boundary with empty terminal queues. Try the snapshot again."
                )
            }
            ptySafepointStatus = report
            for processIdentifier in safepointProcessIdentifiers {
                _ = kill(processIdentifier, SIGUSR1)
            }
            safepointProcessIdentifiers.removeAll(keepingCapacity: true)
        }

        guard let writableVnodes = resourceBox.inventory else {
            continuum_remote_process_group_snapshot_destroy(rawSnapshot)
            throw ContinuumError.runtimeUnsupported(
                "The coherent resource callback returned without a writable-file inventory."
            )
        }
        guard let rawTCPEndpoints = resourceBox.tcpEndpoints else {
            continuum_remote_process_group_snapshot_destroy(rawSnapshot)
            throw ContinuumError.runtimeUnsupported(
                "The coherent resource callback returned without a TCP endpoint inventory."
            )
        }
        guard let rawPTYDescriptors = resourceBox.ptyDescriptors else {
            continuum_remote_process_group_snapshot_destroy(rawSnapshot)
            throw ContinuumError.runtimeUnsupported(
                "The coherent resource callback returned without a PTY descriptor inventory."
            )
        }
        guard let rawDescriptorGraph = resourceBox.descriptorGraph else {
            continuum_remote_process_group_snapshot_destroy(rawSnapshot)
            throw ContinuumError.runtimeUnsupported(
                "The coherent resource callback returned without a descriptor graph."
            )
        }
        let establishedTCPEndpoints: [DurableTCPEndpoint]
        let ptyDescriptors: [DurablePTYDescriptor]
        let descriptorGraph: DurableDescriptorGraph
        do {
            establishedTCPEndpoints = try durableTCPEndpoints(
                from: rawTCPEndpoints
            )
            ptyDescriptors = try durablePTYDescriptors(
                from: rawPTYDescriptors,
                queuesCertifiedEmpty: ptySafepointStatus?.all_queues_zero != 0
            )
            descriptorGraph = try durableDescriptorGraph(from: rawDescriptorGraph)
        } catch {
            continuum_remote_process_group_snapshot_destroy(rawSnapshot)
            throw error
        }
        let members: [HotProcessMember]
        do {
            members = try groupMembers(in: rawSnapshot)
        } catch {
            continuum_remote_process_group_snapshot_destroy(rawSnapshot)
            throw error
        }
        guard !members.isEmpty,
              members.contains(where: { $0.processIdentifier == rootProcessIdentifier }) else {
            continuum_remote_process_group_snapshot_destroy(rawSnapshot)
            throw ContinuumError.runtimeUnsupported(
                "The runtime did not capture the selected app's root process."
            )
        }
        let handle = HotProcessSnapshotHandle(
            pointer: rawSnapshot,
            rootProcessIdentifier: rootProcessIdentifier,
            processIdentifiers: members.map(\.processIdentifier),
            writableVnodes: writableVnodes,
            snapshotID: snapshotID,
            appID: app.id,
            kind: kind,
            fileCheckpointStore: fileCheckpointStore
        )
        do {

            let capturedAt = Date.now
            let checkpoint = CheckpointRecord(
                capturedAt: capturedAt,
                monotonicNanoseconds: clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW),
                processIdentifiers: members.map(\.processIdentifier).sorted(),
                memoryRegionCount: Int(info.captured_region_count),
                threadCount: Int(info.thread_count),
                validation: .valid
            )
            let snapshot = SnapshotRecord(
                id: snapshotID,
                name: SnapshotNaming.automaticName(
                    appName: app.displayName,
                    date: capturedAt,
                    kind: kind
                ),
                kind: kind,
                app: app,
                checkpoint: checkpoint,
                branchID: branchID,
                createdAt: capturedAt,
                availability: .experimentalHot,
                logicalBytes: clampedInt64(info.captured_bytes),
                uniqueBytes: clampedInt64(info.captured_bytes),
                hotMemoryBytes: clampedInt64(info.captured_bytes),
                isPinned: kind != .automatic,
                localFileCoverage: .unchanged,
                allowsKeepingCurrentFiles: true,
                resourceCoverage: Self.experimentalResourceCoverage(
                    writableVnodeCount: writableVnodes.count
                ),
                coldRestoreCertified: coldRestoreCertified(
                    in: rawSnapshot,
                    ptyDescriptors: ptyDescriptors,
                    descriptorGraph: descriptorGraph
                )
            )

            let manifest = HotProcessManifest(
                formatVersion: 1,
                rootProcessIdentifier: rootProcessIdentifier,
                processIdentifiers: members.map(\.processIdentifier).sorted(),
                capturedBytes: info.captured_bytes,
                capturedRegionCount: info.captured_region_count,
                excludedRegionCount: info.excluded_region_count,
                threadCount: info.thread_count,
                writableVnodes: writableVnodes,
                resourceCoverage: Self.experimentalResourceCoverage(
                    writableVnodeCount: writableVnodes.count
                )
            )
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let manifestData = try encoder.encode(manifest)

            retain(handle, for: snapshotID)
            var artifacts = try durableArtifacts(
                snapshot: rawSnapshot,
                checkpoint: checkpoint,
                rootProcessIdentifier: rootProcessIdentifier,
                rootProcessIdentifiers: processIdentifiers,
                app: app,
                snapshotID: snapshotID,
                writableVnodes: writableVnodes,
                establishedTCPEndpoints: establishedTCPEndpoints,
                ptyDescriptors: ptyDescriptors,
                descriptorGraph: descriptorGraph
            )
            artifacts.append(
                CapturedArtifact(
                    kind: .metadata,
                    logicalName: "live-checkpoint-manifest.json",
                    data: manifestData
                )
            )
            return SnapshotCapture(
                snapshot: snapshot,
                artifacts: artifacts
            )
        } catch {
            // `handle` owns and destroys the C snapshot when this scope exits.
            throw error
        }
    }

    public func restore(
        snapshot: SnapshotRecord,
        artifacts: [CapturedArtifact]
    ) async -> RestoreResult {
        guard snapshot.availability == .experimentalHot else {
            return .failed("This snapshot is not available to the live restore engine.")
        }
        guard let handle = handles[snapshot.id] else {
            return .failed(
                "The hot process state expired because Continuum or the captured app was relaunched."
            )
        }

        var report = continuum_remote_process_group_restore_report()
        let resourceBox = HotResourceInventoryCallbackBox(
            expectedInventory: handle.writableVnodes,
            fileCheckpointStore: nil
        )
        let resourceContext = Unmanaged.passUnretained(resourceBox).toOpaque()
        let status = continuum_remote_process_group_restore_with_resources(
            handle.pointer,
            continuumValidateHotResourceInventory,
            resourceContext,
            &report
        )
        guard status == CONTINUUM_STATUS_OK else {
            if let failureDescription = resourceBox.failureDescription {
                return .failed(failureDescription)
            }
            return .failed(restoreFailureDescription(status: status, report: report))
        }
        guard report.memory_readback_verified != 0,
              report.processes_restored > 0,
              report.thread_states_restored > 0 else {
            return .failed(
                "The runtime returned without validating restored memory, processes, and thread state."
            )
        }
        if usesInjectedSafepoints {
            // Release a main-thread capture safepoint and any temporary
            // job-control stop left by the controller.
            for _ in 0..<3 {
                for processIdentifier in handle.processIdentifiers {
                    _ = kill(processIdentifier, SIGUSR1)
                    _ = kill(processIdentifier, SIGCONT)
                }
                usleep(10_000)
            }
        }
        return .experimentalHot
    }

    public func currentRestoreAvailability(
        for snapshot: SnapshotRecord
    ) async -> RestoreAvailability {
        guard snapshot.availability == .experimentalHot else {
            return snapshot.availability
        }
        guard let handle = handles[snapshot.id] else {
            return snapshot.isColdRestoreCertified
                ? .replayRequired
                : .unavailable
        }
        guard continuum_remote_process_group_live_status(handle.pointer)
                == CONTINUUM_STATUS_OK else {
            expire(snapshot.id)
            return snapshot.isColdRestoreCertified
                ? .replayRequired
                : .unavailable
        }
        return .experimentalHot
    }

    private func expire(_ snapshotID: SnapshotID) {
        handles.removeValue(forKey: snapshotID)
        retentionOrder.removeAll { $0 == snapshotID }
    }

    private func coldRestoreCertified(
        in snapshot: OpaquePointer,
        ptyDescriptors: [DurablePTYDescriptor],
        descriptorGraph: DurableDescriptorGraph
    ) -> Bool {
        guard continuum_remote_process_group_member_count(snapshot) > 0 else {
            return false
        }
        var capturedProcessIdentifiers: Set<Int32> = []
        for memberIndex in 0..<continuum_remote_process_group_member_count(snapshot) {
            var member = continuum_remote_process_group_member_info()
            guard continuum_remote_process_group_copy_member_info(
                snapshot,
                memberIndex,
                &member
            ) == CONTINUUM_STATUS_OK else {
                return false
            }
            capturedProcessIdentifiers.insert(member.process_id)
            guard let launch = try? launchContract(
                snapshot: snapshot,
                memberIndex: memberIndex
            ), launch.addressSpacePolicy == .continuumDeterministic else {
                return false
            }
            let regionCount = continuum_remote_process_group_member_region_count(
                snapshot,
                memberIndex
            )
            var hasReconstructableMemory = false
            for regionIndex in 0..<regionCount {
                var region = continuum_remote_process_region_info()
                guard continuum_remote_process_group_copy_member_region_info(
                    snapshot,
                    memberIndex,
                    regionIndex,
                    &region
                ) == CONTINUUM_STATUS_OK else {
                    return false
                }
                guard region.preserves_live_derived_graphics == 0 else {
                    return false
                }
                hasReconstructableMemory = hasReconstructableMemory
                    || region.length > 0
            }
            guard hasReconstructableMemory else { return false }

            let threadCount = continuum_remote_process_group_member_thread_count(
                snapshot,
                memberIndex
            )
            var pthreadCount = 0
            for threadIndex in 0..<threadCount {
                var thread = continuum_remote_thread_state_info()
                guard continuum_remote_process_group_copy_member_thread_info(
                    snapshot,
                    memberIndex,
                    threadIndex,
                    &thread
                ) == CONTINUUM_STATUS_OK else {
                    return false
                }
                switch thread.origin {
                case CONTINUUM_REMOTE_THREAD_ORIGIN_PTHREAD:
                    pthreadCount += 1
                    guard thread.pthread_object_address != 0,
                          thread.stack_pointer != 0 else {
                        return false
                    }
                case CONTINUUM_REMOTE_THREAD_ORIGIN_WORKQUEUE:
                    guard thread.preserves_kernel_continuation != 0 else {
                        return false
                    }
                case CONTINUUM_REMOTE_THREAD_ORIGIN_RAW_MACH:
                    break
                default:
                    return false
                }
            }
            guard pthreadCount > 0 else { return false }
        }
        guard ptyDescriptors.allSatisfy({ descriptor in
            descriptor.inputQueueBytes == 0
                && descriptor.outputQueueBytes == 0
        }) else {
            return false
        }
        guard descriptorGraph.handles.allSatisfy({
            $0.descriptorFlags >= 0
        }) else {
            return false
        }
        let socketIDs = Set(descriptorGraph.sockets.map(\.id))
        let pipeIDs = Set(descriptorGraph.pipes.map(\.id))
        let kqueueIDs = Set(descriptorGraph.kqueues.map(\.id))
        let allResourceIDs = socketIDs.union(pipeIDs).union(kqueueIDs)
        guard socketIDs.count == descriptorGraph.sockets.count,
              pipeIDs.count == descriptorGraph.pipes.count,
              kqueueIDs.count == descriptorGraph.kqueues.count,
              allResourceIDs.count == socketIDs.count + pipeIDs.count
                + kqueueIDs.count,
              descriptorGraph.handles.allSatisfy({
                  allResourceIDs.contains($0.resourceID)
              }) else {
            return false
        }
        let pipeByID = Dictionary(
            uniqueKeysWithValues: descriptorGraph.pipes.map { ($0.id, $0) }
        )
        let pipeHandles = descriptorGraph.handles.filter {
            pipeByID[$0.resourceID] != nil
        }
        let socketByID = Dictionary(
            uniqueKeysWithValues: descriptorGraph.sockets.map { ($0.id, $0) }
        )
        let socketHandles = descriptorGraph.handles.filter {
            socketByID[$0.resourceID] != nil
        }
        let kqueueByID = Dictionary(
            uniqueKeysWithValues: descriptorGraph.kqueues.map { ($0.id, $0) }
        )
        let kqueueHandles = descriptorGraph.handles.filter {
            kqueueByID[$0.resourceID] != nil
        }
        let handlesBySocket = Dictionary(
            grouping: socketHandles,
            by: \.resourceID
        )
        let supportedStatusMask = O_ACCMODE | O_NONBLOCK | O_ASYNC
        let listenerAddresses = descriptorGraph.sockets.compactMap {
            $0.kind == .tcpListener ? $0.localAddress : nil
        }
        guard Set(listenerAddresses).count == listenerAddresses.count else {
            return false
        }
        guard descriptorGraph.sockets.allSatisfy({ socket in
            let common = (socket.domain == AF_INET || socket.domain == AF_INET6)
                && socket.type == SOCK_STREAM
                && socket.protocol == IPPROTO_TCP
                && socket.receiveQueueBytes == 0
                && socket.sendQueueBytes == 0
                && socket.localAddress != nil
                && socket.externalPath == nil
                && handlesBySocket[socket.id]?.isEmpty == false
            guard common else { return false }
            if socket.kind == .tcpListener {
                let optionNames = socket.options.map(\.name)
                return socket.remoteAddress == nil
                    && socket.peerResourceID == nil
                    && socket.listenerResourceID == nil
                    && socket.backlog.map { $0 > 0 } == true
                    && Set(optionNames) == Set([
                        SO_REUSEADDR, SO_REUSEPORT, SO_RCVBUF, SO_SNDBUF,
                    ])
                    && optionNames.count == 4
            }
            guard socket.kind == .tcpConnected,
                  let peerID = socket.peerResourceID,
                  let peer = socketByID[peerID] else { return false }
            let listenerIsValid = socket.listenerResourceID.map { listenerID in
                socketByID[listenerID]?.kind == .tcpListener
                    && socketByID[listenerID]?.localAddress == socket.localAddress
                    && peer.listenerResourceID == nil
            } ?? true
            return socket.remoteAddress != nil
                && peerID != socket.id
                && peer.peerResourceID == socket.id
                && peer.localAddress == socket.remoteAddress
                && peer.remoteAddress == socket.localAddress
                && listenerIsValid
                && socket.options.count == 4
                && Set(socket.options.map(\.name)) == Set([
                    SO_REUSEADDR, SO_REUSEPORT, SO_RCVBUF, SO_SNDBUF,
                ])
                && socket.tcpNoDelay != nil
        }), socketHandles.allSatisfy({ handle in
            capturedProcessIdentifiers.contains(handle.processIdentifier)
                && handle.fileDescriptor >= 0
                && (handle.descriptorFlags == 0
                    || handle.descriptorFlags == FD_CLOEXEC)
                && handle.statusFlags & O_ACCMODE == O_RDWR
                && handle.statusFlags & ~supportedStatusMask == 0
                && handlesBySocket[handle.resourceID]?.allSatisfy({
                    $0.statusFlags == handle.statusFlags
                }) == true
        }) else {
            return false
        }
        let handlesByPipe = Dictionary(grouping: pipeHandles, by: \.resourceID)
        guard descriptorGraph.pipes.allSatisfy({ pipe in
            pipe.queuedBytes == 0
                && pipe.peerResourceID != pipe.id
                && pipeByID[pipe.peerResourceID]?.peerResourceID == pipe.id
                && handlesByPipe[pipe.id]?.isEmpty == false
        }), pipeHandles.allSatisfy({ handle in
            capturedProcessIdentifiers.contains(handle.processIdentifier)
                && handle.fileDescriptor >= 0
                && (handle.descriptorFlags == 0
                    || handle.descriptorFlags == FD_CLOEXEC)
                && (handle.statusFlags & O_ACCMODE == O_RDONLY
                    || handle.statusFlags & O_ACCMODE == O_WRONLY)
                && handle.statusFlags & ~supportedStatusMask == 0
                && handlesByPipe[handle.resourceID]?.allSatisfy({
                    $0.statusFlags == handle.statusFlags
                }) == true
        }) else {
            return false
        }
        guard coldKqueuesCertified(
            descriptorGraph.kqueues,
            handles: kqueueHandles,
            allHandles: descriptorGraph.handles,
            pipes: pipeByID,
            sockets: socketByID,
            capturedProcessIdentifiers: capturedProcessIdentifiers
        ) else {
            return false
        }
        return true
    }

    private func coldKqueuesCertified(
        _ queues: [DurableKqueueResource],
        handles: [DurableDescriptorHandle],
        allHandles: [DurableDescriptorHandle],
        pipes: [UUID: DurablePipeResource],
        sockets: [UUID: DurableSocketResource],
        capturedProcessIdentifiers: Set<Int32>
    ) -> Bool {
        let handlesByResource = Dictionary(grouping: handles, by: \.resourceID)
        let supportedFlags: UInt16 = 0x01BD
        let registrationsByProcess = Dictionary(grouping: queues) {
            $0.processIdentifier
        }
        guard registrationsByProcess.values.allSatisfy({ processQueues in
            processQueues.reduce(0) { count, queue in
                count + queue.registrations.count
            } <= 1_024
        }) else {
            return false
        }
        for queue in queues {
            guard queue.state & ~0x0002 == 0x0010,
                  capturedProcessIdentifiers.contains(queue.processIdentifier),
                  let queueHandles = handlesByResource[queue.id],
                  queueHandles.count == 1,
                  let handle = queueHandles.first,
                  handle.processIdentifier == queue.processIdentifier,
                  handle.fileDescriptor >= 0,
                  handle.statusFlags == O_RDWR,
                  handle.descriptorFlags
                    & ~(FD_CLOEXEC | FD_CLOFORK) == 0 else {
                return false
            }
            for registration in queue.registrations {
                guard registration.status == 0,
                      registration.qos == 0,
                      registration.flags & ~supportedFlags == 0,
                      registration.flags & 0x0042 == 0 else {
                    return false
                }
                switch registration.filter {
                case Int16(EVFILT_USER):
                    guard registration.fflags & 0xFF00_0000 == 0,
                          registration.savedFflags & 0xFF00_0000 == 0 else {
                        return false
                    }
                case Int16(EVFILT_READ):
                    guard registration.ident <= UInt64(Int32.max),
                          registration.fflags & ~UInt32(NOTE_LOWAT) == 0,
                          registration.savedFflags & ~UInt32(NOTE_LOWAT) == 0,
                          registration.data == 0,
                          registration.savedData >= 0,
                          let referenced = allHandles.first(where: {
                            $0.processIdentifier == queue.processIdentifier
                                && $0.fileDescriptor
                                    == Int32(registration.ident)
                          }),
                          pipes[referenced.resourceID]?.queuedBytes == 0
                            || sockets[referenced.resourceID]?.receiveQueueBytes == 0
                    else {
                        return false
                    }
                default:
                    return false
                }
            }
        }
        return true
    }

    private func retain(_ handle: HotProcessSnapshotHandle, for snapshotID: SnapshotID) {
        handles[snapshotID] = handle
        retentionOrder.removeAll { $0 == snapshotID }
        retentionOrder.append(snapshotID)

        while retentionOrder.count > maximumRetainedSnapshots {
            let expiredID = retentionOrder.removeFirst()
            handles.removeValue(forKey: expiredID)
        }
    }

    private func durableArtifacts(
        snapshot: OpaquePointer,
        checkpoint: CheckpointRecord,
        rootProcessIdentifier: Int32,
        rootProcessIdentifiers: [Int32],
        app: AppIdentity,
        snapshotID: SnapshotID,
        writableVnodes: [HotWritableVnode],
        establishedTCPEndpoints: [DurableTCPEndpoint],
        ptyDescriptors: [DurablePTYDescriptor],
        descriptorGraph: DurableDescriptorGraph
    ) throws -> [CapturedArtifact] {
        let chunkSize = 1_024 * 1_024
        var artifacts: [CapturedArtifact] = []
        var processImages: [DurableProcessImage] = []
        // Files are deliberately outside the rewind boundary. Descriptor
        // metadata is retained so a cold process can reconnect to the current
        // files, but no file bytes are copied into the durable image.
        let filePayloads: [LocalFileCheckpointPayload] = []
        let memberCount = continuum_remote_process_group_member_count(snapshot)

        for memberIndex in 0..<memberCount {
            var member = continuum_remote_process_group_member_info()
            try requireRuntimeOK(
                continuum_remote_process_group_copy_member_info(
                    snapshot, memberIndex, &member
                ),
                operation: "export process metadata"
            )

            var regions: [DurableMemoryRegion] = []
            let regionCount = continuum_remote_process_group_member_region_count(
                snapshot, memberIndex
            )
            for regionIndex in 0..<regionCount {
                var region = continuum_remote_process_region_info()
                try requireRuntimeOK(
                    continuum_remote_process_group_copy_member_region_info(
                        snapshot, memberIndex, regionIndex, &region
                    ),
                    operation: "export memory-region metadata"
                )
                var references: [DurableChunkReference] = []
                var offset: UInt64 = 0
                while offset < region.length {
                    let length = Int(min(UInt64(chunkSize), region.length - offset))
                    var data = Data(count: length)
                    let status = data.withUnsafeMutableBytes { buffer in
                        continuum_remote_process_group_copy_member_region_bytes_range(
                            snapshot,
                            memberIndex,
                            regionIndex,
                            offset,
                            buffer.baseAddress,
                            buffer.count
                        )
                    }
                    try requireRuntimeOK(status, operation: "export memory bytes")
                    let hash = Self.sha256(data)
                    let logicalName = String(
                        format: "memory/%d/%016llx/%016llx.bin",
                        member.process_id,
                        region.address,
                        offset
                    )
                    artifacts.append(CapturedArtifact(
                        kind: .memoryPage,
                        logicalName: logicalName,
                        data: data
                    ))
                    references.append(DurableChunkReference(
                        hash: hash,
                        artifactName: logicalName,
                        logicalBytes: UInt64(length),
                        storedBytes: 0,
                        compression: .none
                    ))
                    offset += UInt64(length)
                }
                regions.append(DurableMemoryRegion(
                    address: region.address,
                    length: region.length,
                    protection: region.protection,
                    maximumProtection: region.maximum_protection,
                    inheritance: region.inheritance,
                    shareMode: region.share_mode,
                    userTag: region.user_tag,
                    isAppOwnedState: region.is_app_owned_state != 0,
                    preservesLiveDerivedGraphics:
                        region.preserves_live_derived_graphics != 0,
                    chunks: references
                ))
            }

            var threads: [DurableThreadImage] = []
            let threadCount = continuum_remote_process_group_member_thread_count(
                snapshot, memberIndex
            )
            for threadIndex in 0..<threadCount {
                var thread = continuum_remote_thread_state_info()
                try requireRuntimeOK(
                    continuum_remote_process_group_copy_member_thread_info(
                        snapshot, memberIndex, threadIndex, &thread
                    ),
                    operation: "export thread metadata"
                )
                let general = try copyThreadState(
                    snapshot: snapshot,
                    memberIndex: memberIndex,
                    threadIndex: threadIndex,
                    length: thread.general_state_length,
                    vector: false
                )
                let vector = try copyThreadState(
                    snapshot: snapshot,
                    memberIndex: memberIndex,
                    threadIndex: threadIndex,
                    length: thread.vector_state_length,
                    vector: true
                )
                let generalName = "threads/\(member.process_id)/\(thread.thread_identifier)-general.bin"
                let vectorName = "threads/\(member.process_id)/\(thread.thread_identifier)-vector.bin"
                artifacts.append(CapturedArtifact(
                    kind: .threadState,
                    logicalName: generalName,
                    data: general
                ))
                artifacts.append(CapturedArtifact(
                    kind: .threadState,
                    logicalName: vectorName,
                    data: vector
                ))
                let stackPointer = thread.stack_pointer == 0
                    ? nil
                    : thread.stack_pointer
                let pthreadObjectAddress = thread.pthread_object_address == 0
                    ? nil
                    : thread.pthread_object_address
                let origin: DurableThreadOrigin
                switch thread.origin {
                case CONTINUUM_REMOTE_THREAD_ORIGIN_RAW_MACH:
                    origin = .rawMach
                case CONTINUUM_REMOTE_THREAD_ORIGIN_PTHREAD:
                    origin = .pthread
                case CONTINUUM_REMOTE_THREAD_ORIGIN_WORKQUEUE:
                    origin = .workqueue
                default:
                    origin = .unknown
                }
                let pthreadRegion = regions.first { region in
                    guard let pthreadObjectAddress else { return false }
                    let (end, overflow) = region.address
                        .addingReportingOverflow(region.length)
                    return !overflow
                        && pthreadObjectAddress >= region.address
                        && pthreadObjectAddress < end
                }
                let stackRegion = regions.first { region in
                    guard let stackPointer else { return false }
                    let (end, overflow) = region.address
                        .addingReportingOverflow(region.length)
                    return !overflow
                        && stackPointer >= region.address
                        && stackPointer < end
                }
                threads.append(DurableThreadImage(
                    threadIdentifier: thread.thread_identifier,
                    threadHandle: thread.thread_handle,
                    pthreadObjectAddress: pthreadObjectAddress,
                    origin: origin,
                    dispatchQueueAddress: thread.dispatch_queue_address,
                    stackPointer: stackPointer,
                    stackRegionAddress: stackRegion?.address,
                    stackRegionLength: stackRegion?.length,
                    pthreadRegionAddress: pthreadRegion?.address,
                    pthreadRegionLength: pthreadRegion?.length,
                    isUserspaceSafepoint:
                        thread.is_userspace_safepoint != 0,
                    preservesKernelContinuation:
                        thread.preserves_kernel_continuation != 0,
                    generalStateFlavor: thread.general_state_flavor,
                    generalState: DurableChunkReference(
                        hash: Self.sha256(general),
                        artifactName: generalName,
                        logicalBytes: UInt64(general.count),
                        storedBytes: 0,
                        compression: .none
                    ),
                    vectorStateFlavor: thread.vector_state_flavor,
                    vectorState: DurableChunkReference(
                        hash: Self.sha256(vector),
                        artifactName: vectorName,
                        logicalBytes: UInt64(vector.count),
                        storedBytes: 0,
                        compression: .none
                    )
                ))
            }

            processImages.append(DurableProcessImage(
                processIdentifier: member.process_id,
                parentProcessIdentifier: member.parent_process_id,
                executableDevice: member.executable_device,
                executableInode: member.executable_inode,
                vmLayoutHash: member.vm_layout_hash,
                immutableLayoutDigest: Self.hexDigest(
                    member.immutable_layout_digest
                ),
                launchContract: try launchContract(
                    snapshot: snapshot,
                    memberIndex: memberIndex
                ),
                topology: Self.processTopology(
                    processIdentifier: member.process_id
                ),
                regions: regions,
                threads: threads
            ))
        }
        var writableFiles: [DurableFileImage] = []
        writableFiles.reserveCapacity(filePayloads.count)
        for (fileIndex, payload) in filePayloads.enumerated() {
            guard payload.entry.byteCount >= 0,
                  UInt64(payload.data.count) == UInt64(payload.entry.byteCount) else {
                throw ContinuumError.integrityFailure(
                    "The coherent file clone changed while its durable root was exported."
                )
            }
            var references: [DurableChunkReference] = []
            var offset = 0
            while offset < payload.data.count {
                let length = min(chunkSize, payload.data.count - offset)
                let block = payload.data.subdata(in: offset..<(offset + length))
                let logicalName = String(
                    format: "files/%08d/%016llx.bin",
                    fileIndex,
                    UInt64(offset)
                )
                artifacts.append(CapturedArtifact(
                    kind: .fileBlock,
                    logicalName: logicalName,
                    data: block
                ))
                references.append(DurableChunkReference(
                    hash: Self.sha256(block),
                    artifactName: logicalName,
                    logicalBytes: UInt64(length),
                    storedBytes: 0,
                    compression: .none
                ))
                offset += length
            }
            writableFiles.append(DurableFileImage(
                originalPath: payload.entry.originalPath,
                device: payload.entry.device,
                inode: payload.entry.inode,
                byteCount: UInt64(payload.entry.byteCount),
                mode: payload.entry.mode,
                chunks: references
            ))
        }
        let writableFileDescriptors = writableVnodes.map { vnode in
            DurableWritableFileDescriptor(
                processIdentifier: vnode.processIdentifier,
                fileDescriptor: vnode.fileDescriptor,
                openFlags: vnode.openFlags,
                offset: vnode.offset,
                device: vnode.device,
                inode: vnode.inode,
                mode: vnode.mode,
                originalPath: vnode.path
            )
        }
        let image = DurableCheckpointImage(
            checkpointID: checkpoint.id,
            createdAt: checkpoint.capturedAt,
            architecture: "arm64",
            operatingSystemBuild: try currentOperatingSystemBuild(),
            pageSize: UInt64(getpagesize()),
            rootProcessIdentifier: rootProcessIdentifier,
            rootProcessIdentifiers: rootProcessIdentifiers,
            app: app,
            members: processImages,
            writableFiles: writableFiles,
            writableFileDescriptors: writableFileDescriptors,
            establishedTCPEndpoints: establishedTCPEndpoints,
            ptyDescriptors: ptyDescriptors,
            descriptorGraph: descriptorGraph
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        artifacts.append(CapturedArtifact(
            kind: .metadata,
            logicalName: "durable-checkpoint-v3.json",
            data: try encoder.encode(image)
        ))
        return artifacts
    }

    private func durableTCPEndpoints(
        from endpoints: [continuum_remote_tcp_endpoint_info]
    ) throws -> [DurableTCPEndpoint] {
        return try endpoints.map { endpoint in
            var localAddress = endpoint.local_address
            var remoteAddress = endpoint.remote_address
            let localCapacity = MemoryLayout.size(ofValue: localAddress)
            let remoteCapacity = MemoryLayout.size(ofValue: remoteAddress)
            guard endpoint.local_address_length <= localCapacity,
                  endpoint.remote_address_length <= remoteCapacity else {
                throw ContinuumError.runtimeUnsupported(
                    "The runtime exported an invalid native TCP address length."
                )
            }
            let localBytes = withUnsafeBytes(of: &localAddress) { bytes in
                Array(bytes.prefix(Int(endpoint.local_address_length)))
            }
            let remoteBytes = withUnsafeBytes(of: &remoteAddress) { bytes in
                Array(bytes.prefix(Int(endpoint.remote_address_length)))
            }
            return DurableTCPEndpoint(
                processIdentifier: endpoint.process_id,
                fileDescriptor: endpoint.file_descriptor,
                domain: endpoint.domain,
                socketType: endpoint.socket_type,
                socketProtocol: endpoint.protocol,
                tcpState: endpoint.tcp_state,
                socketState: endpoint.socket_state,
                localAddressLength: endpoint.local_address_length,
                remoteAddressLength: endpoint.remote_address_length,
                localAddress: localBytes,
                remoteAddress: remoteBytes,
                receiveQueueBytes: endpoint.receive_queue_bytes,
                sendQueueBytes: endpoint.send_queue_bytes,
                receiveShutdown: endpoint.receive_shutdown != 0,
                sendShutdown: endpoint.send_shutdown != 0
            )
        }
    }

    private func durableDescriptorGraph(
        from graph: HotRawDescriptorGraph
    ) throws -> DurableDescriptorGraph {
        let socketIDs = Dictionary(
            uniqueKeysWithValues: graph.sockets.map {
                ($0.resource_identity, UUID())
            }
        )
        let pipeIDs = Dictionary(
            uniqueKeysWithValues: graph.pipes.map {
                ($0.resource_identity, UUID())
            }
        )
        let kqueueIDs = Dictionary(
            uniqueKeysWithValues: graph.kqueues.map {
                ($0.resource_identity, UUID())
            }
        )
        let rawSocketsByIdentity = Dictionary(
            uniqueKeysWithValues: graph.sockets.map {
                ($0.resource_identity, $0)
            }
        )

        let handles = try graph.handles.map { handle in
            let resourceID: UUID?
            switch handle.resource_kind {
            case CONTINUUM_REMOTE_DESCRIPTOR_RESOURCE_SOCKET:
                resourceID = socketIDs[handle.resource_identity]
            case CONTINUUM_REMOTE_DESCRIPTOR_RESOURCE_PIPE:
                resourceID = pipeIDs[handle.resource_identity]
            case CONTINUUM_REMOTE_DESCRIPTOR_RESOURCE_KQUEUE:
                resourceID = kqueueIDs[handle.resource_identity]
            default:
                resourceID = nil
            }
            guard let resourceID else {
                throw ContinuumError.runtimeUnsupported(
                    "The runtime exported a descriptor with no matching resource."
                )
            }
            return DurableDescriptorHandle(
                resourceID: resourceID,
                processIdentifier: handle.process_id,
                fileDescriptor: handle.file_descriptor,
                descriptorFlags: handle.descriptor_flags,
                statusFlags: handle.status_flags
            )
        }

        let sockets = try graph.sockets.map { socket in
            guard let id = socketIDs[socket.resource_identity] else {
                throw ContinuumError.runtimeUnsupported(
                    "The runtime exported an unidentified socket resource."
                )
            }
            let kind: DurableSocketKind
            switch socket.kind {
            case CONTINUUM_REMOTE_SOCKET_TCP_LISTENER:
                kind = .tcpListener
            case CONTINUUM_REMOTE_SOCKET_TCP_CONNECTED:
                kind = .tcpConnected
            case CONTINUUM_REMOTE_SOCKET_UNIX_LISTENER:
                kind = .unixListener
            case CONTINUUM_REMOTE_SOCKET_UNIX_CONNECTED:
                kind = .unixConnected
            default:
                throw ContinuumError.runtimeUnsupported(
                    "The runtime exported an unsupported socket kind."
                )
            }
            var local = socket.local_address
            var remote = socket.remote_address
            let localCapacity = MemoryLayout.size(ofValue: local)
            let remoteCapacity = MemoryLayout.size(ofValue: remote)
            guard socket.local_address_length <= localCapacity,
                  socket.remote_address_length <= remoteCapacity else {
                throw ContinuumError.runtimeUnsupported(
                    "The runtime exported an invalid socket address length."
                )
            }
            let localData = withUnsafeBytes(of: &local) {
                Data($0.prefix(Int(socket.local_address_length)))
            }
            let remoteData = withUnsafeBytes(of: &remote) {
                Data($0.prefix(Int(socket.remote_address_length)))
            }
            let externalPath: String?
            if kind == .unixConnected, socket.peer_identity == 0,
               remoteData.count > 2 {
                externalPath = String(
                    decoding: remoteData.dropFirst(2).prefix { $0 != 0 },
                    as: UTF8.self
                )
            } else {
                externalPath = nil
            }
            var options: [DurableSocketOption] = []
            func option(_ name: Int32, _ value: Int32) -> DurableSocketOption {
                var nativeValue = value
                return withUnsafeBytes(of: &nativeValue) {
                    DurableSocketOption(
                        level: SOL_SOCKET,
                        name: name,
                        value: Data($0)
                    )
                }
            }
            if kind == .tcpListener {
                let allowedOptions = SO_ACCEPTCONN | SO_REUSEADDR | SO_REUSEPORT
                guard socket.socket_options & ~allowedOptions == 0,
                      socket.linger_ticks == 0,
                      socket.receive_low_water_bytes == 1,
                      socket.send_low_water_bytes == 2_048,
                      socket.receive_timeout_ticks == 0,
                      socket.send_timeout_ticks == 0,
                      socket.receive_buffer_bytes > 0,
                      socket.send_buffer_bytes > 0 else {
                    throw ContinuumError.runtimeUnsupported(
                        "A TCP listener uses socket options Continuum cannot reproduce exactly."
                    )
                }
                options = [
                    option(
                        SO_REUSEADDR,
                        socket.socket_options & SO_REUSEADDR == 0 ? 0 : 1
                    ),
                    option(
                        SO_REUSEPORT,
                        socket.socket_options & SO_REUSEPORT == 0 ? 0 : 1
                    ),
                    option(SO_RCVBUF, socket.receive_buffer_bytes),
                    option(SO_SNDBUF, socket.send_buffer_bytes),
                ]
            } else if kind == .tcpConnected {
                // XNU tcp_var.h: TF_NOOPT 0x00008 and TF_NOPUSH 0x01000
                // correspond to observable TCP_NOOPT/TCP_NOPUSH settings that
                // this first listener slice does not replay.
                guard socket.tcp_flags & (0x00008 | 0x01000) == 0 else {
                    throw ContinuumError.runtimeUnsupported(
                        "A connected TCP socket uses protocol options Continuum cannot reproduce exactly."
                    )
                }
                let expectedInheritedOptions: Int32
                if socket.listener_identity == 0 {
                    expectedInheritedOptions = 0
                } else if let listener = rawSocketsByIdentity[
                    socket.listener_identity
                ] {
                    expectedInheritedOptions = listener.socket_options
                        & (SO_REUSEADDR | SO_REUSEPORT)
                } else {
                    throw ContinuumError.runtimeUnsupported(
                        "A connected TCP socket references a missing listener."
                    )
                }
                guard socket.socket_options == expectedInheritedOptions else {
                    throw ContinuumError.runtimeUnsupported(
                        "A connected TCP socket uses options Continuum cannot reproduce exactly."
                    )
                }
                guard socket.linger_ticks == 0,
                      socket.receive_low_water_bytes == 1,
                      socket.send_low_water_bytes == 2_048,
                      socket.receive_timeout_ticks == 0,
                      socket.send_timeout_ticks == 0,
                      socket.receive_buffer_bytes > 0,
                      socket.send_buffer_bytes > 0 else {
                    throw ContinuumError.runtimeUnsupported(
                        "A connected TCP socket uses tuning Continuum cannot reproduce exactly."
                    )
                }
                options = [
                    option(
                        SO_REUSEADDR,
                        socket.socket_options & SO_REUSEADDR == 0 ? 0 : 1
                    ),
                    option(
                        SO_REUSEPORT,
                        socket.socket_options & SO_REUSEPORT == 0 ? 0 : 1
                    ),
                    option(SO_RCVBUF, socket.receive_buffer_bytes),
                    option(SO_SNDBUF, socket.send_buffer_bytes),
                ]
            }
            return DurableSocketResource(
                id: id,
                kind: kind,
                domain: socket.domain,
                type: socket.socket_type,
                protocol: socket.protocol,
                localAddress: localData.isEmpty ? nil : localData,
                remoteAddress: remoteData.isEmpty ? nil : remoteData,
                backlog: kind == .tcpListener || kind == .unixListener
                    ? socket.backlog
                    : nil,
                receiveQueueBytes: socket.receive_queue_bytes,
                sendQueueBytes: socket.send_queue_bytes,
                receiveShutdown: socket.receive_shutdown != 0,
                sendShutdown: socket.send_shutdown != 0,
                peerResourceID: socket.peer_identity == 0
                    ? nil
                    : socketIDs[socket.peer_identity],
                listenerResourceID: socket.listener_identity == 0
                    ? nil
                    : socketIDs[socket.listener_identity],
                externalPath: externalPath,
                options: options,
                tcpNoDelay: kind == .tcpConnected
                    ? socket.tcp_no_delay != 0
                    : nil
            )
        }

        let pipes = try graph.pipes.map { pipe in
            guard let id = pipeIDs[pipe.resource_identity],
                  let peerID = pipeIDs[pipe.peer_identity] else {
                throw ContinuumError.runtimeUnsupported(
                    "The runtime exported a pipe with no captured peer."
                )
            }
            return DurablePipeResource(
                id: id,
                peerResourceID: peerID,
                capacity: pipe.capacity,
                queuedBytes: pipe.queued_bytes,
                status: pipe.status
            )
        }

        let kqueues = try graph.kqueues.map { kqueue in
            guard let id = kqueueIDs[kqueue.resource_identity],
                  kqueue.registration_start <= graph.registrations.count,
                  kqueue.registration_count
                    <= graph.registrations.count - Int(kqueue.registration_start)
            else {
                throw ContinuumError.runtimeUnsupported(
                    "The runtime exported an invalid kqueue registration range."
                )
            }
            let start = Int(kqueue.registration_start)
            let end = start + Int(kqueue.registration_count)
            let registrations = graph.registrations[start..<end].map {
                DurableKqueueRegistration(
                    ident: $0.ident,
                    filter: $0.filter,
                    flags: $0.flags,
                    fflags: $0.fflags,
                    data: $0.data,
                    udata: $0.udata,
                    qos: $0.qos,
                    savedData: $0.saved_data,
                    savedFflags: $0.saved_fflags,
                    status: $0.status
                )
            }
            return DurableKqueueResource(
                id: id,
                processIdentifier: kqueue.process_id,
                state: kqueue.state,
                registrations: registrations
            )
        }
        return DurableDescriptorGraph(
            handles: handles,
            sockets: sockets,
            pipes: pipes,
            kqueues: kqueues
        )
    }

    private func durablePTYDescriptors(
        from descriptors: [continuum_remote_pty_descriptor_info],
        queuesCertifiedEmpty: Bool
    ) throws -> [DurablePTYDescriptor] {
        try descriptors.map { descriptor in
            let role: DurablePTYRole
            switch descriptor.role {
            case CONTINUUM_REMOTE_PTY_ROLE_MASTER:
                role = .master
            case CONTINUUM_REMOTE_PTY_ROLE_SLAVE:
                role = .slave
            default:
                throw ContinuumError.runtimeUnsupported(
                    "The runtime exported a PTY descriptor with no endpoint role."
                )
            }
            var attributes = descriptor.terminal_attributes
            var windowSize = descriptor.window_size
            return DurablePTYDescriptor(
                processIdentifier: descriptor.process_id,
                fileDescriptor: descriptor.file_descriptor,
                openFlags: descriptor.open_flags,
                role: role,
                device: descriptor.device,
                inode: descriptor.inode,
                rawDevice: descriptor.raw_device,
                deviceMajor: descriptor.device_major,
                deviceMinor: descriptor.device_minor,
                ttyIndex: descriptor.tty_index,
                aliasIdentity: descriptor.alias_identity,
                inputQueueBytes: queuesCertifiedEmpty
                    ? 0
                    : descriptor.input_queue_known == 0
                        ? nil
                        : descriptor.input_queue_bytes,
                outputQueueBytes: queuesCertifiedEmpty
                    ? 0
                    : descriptor.output_queue_known == 0
                        ? nil
                        : descriptor.output_queue_bytes,
                terminalAttributes: descriptor.terminal_attributes_known == 0
                    ? nil
                    : withUnsafeBytes(of: &attributes) { Array($0) },
                windowSize: descriptor.window_size_known == 0
                    ? nil
                    : withUnsafeBytes(of: &windowSize) { Array($0) }
            )
        }
    }

    private static func processTopology(
        processIdentifier: Int32
    ) -> DurableProcessTopology? {
        var info = proc_bsdinfo()
        let byteCount = proc_pidinfo(
            processIdentifier,
            PROC_PIDTBSDINFO,
            0,
            &info,
            Int32(MemoryLayout<proc_bsdinfo>.size)
        )
        guard byteCount == MemoryLayout<proc_bsdinfo>.size else { return nil }
        return DurableProcessTopology(
            processGroupIdentifier: Int32(bitPattern: info.pbi_pgid),
            sessionIdentifier: getsid(processIdentifier),
            controllingTerminalDevice: info.e_tdev,
            foregroundProcessGroupIdentifier: Int32(bitPattern: info.e_tpgid)
        )
    }

    private func launchContract(
        snapshot: OpaquePointer,
        memberIndex: Int
    ) throws -> DurableLaunchContract {
        var procargsLength = 0
        try requireRuntimeOK(
            continuum_remote_process_group_copy_member_procargs(
                snapshot, memberIndex, nil, 0, &procargsLength
            ),
            operation: "measure process launch arguments"
        )
        var procargs = Data(count: procargsLength)
        let procargsStatus = procargs.withUnsafeMutableBytes { bytes in
            continuum_remote_process_group_copy_member_procargs(
                snapshot,
                memberIndex,
                bytes.baseAddress,
                bytes.count,
                &procargsLength
            )
        }
        try requireRuntimeOK(procargsStatus, operation: "capture process launch arguments")
        if procargsLength < procargs.count {
            procargs.removeSubrange(procargsLength..<procargs.count)
        }

        var directoryLength = 0
        try requireRuntimeOK(
            continuum_remote_process_group_copy_member_working_directory(
                snapshot, memberIndex, nil, 0, &directoryLength
            ),
            operation: "measure process working directory"
        )
        var directory = Data(count: directoryLength)
        let directoryStatus = directory.withUnsafeMutableBytes { bytes in
            continuum_remote_process_group_copy_member_working_directory(
                snapshot,
                memberIndex,
                bytes.baseAddress,
                bytes.count,
                &directoryLength
            )
        }
        try requireRuntimeOK(directoryStatus, operation: "capture process working directory")

        let parsed = try Self.parseProcargs(procargs)
        let workingDirectory = directory.withUnsafeBytes { bytes -> String? in
            guard let base = bytes.baseAddress?.assumingMemoryBound(to: CChar.self) else {
                return nil
            }
            return String(validatingCString: base)
        }
        guard let workingDirectory else {
            throw ContinuumError.runtimeUnsupported(
                "The runtime captured an invalid process working directory."
            )
        }
        return DurableLaunchContract(
            executablePath: parsed.executablePath,
            arguments: parsed.arguments,
            environment: parsed.environment,
            workingDirectory: workingDirectory,
            addressSpacePolicy: parsed.environment.contains(
                "CONTINUUM_DETERMINISTIC_ADDRESS_SPACE=1"
            ) ? .continuumDeterministic : .systemASLR
        )
    }

    private static func parseProcargs(
        _ data: Data
    ) throws -> (executablePath: String, arguments: [String], environment: [String]) {
        guard data.count >= MemoryLayout<Int32>.size else {
            throw ContinuumError.runtimeUnsupported("The process launch payload was truncated.")
        }
        let argumentCount = data.withUnsafeBytes { bytes in
            Int(bytes.loadUnaligned(as: Int32.self))
        }
        guard argumentCount >= 0 else {
            throw ContinuumError.runtimeUnsupported("The process launch argument count was invalid.")
        }

        var offset = MemoryLayout<Int32>.size
        func nextString() -> String? {
            guard offset < data.count else { return nil }
            let start = offset
            while offset < data.count, data[offset] != 0 { offset += 1 }
            guard offset < data.count else { return nil }
            let value = String(data: data[start..<offset], encoding: .utf8)
            offset += 1
            return value
        }

        guard let executablePath = nextString(), !executablePath.isEmpty else {
            throw ContinuumError.runtimeUnsupported("The process executable path was missing.")
        }
        while offset < data.count, data[offset] == 0 { offset += 1 }

        var arguments: [String] = []
        arguments.reserveCapacity(argumentCount)
        for _ in 0..<argumentCount {
            guard let argument = nextString() else {
                throw ContinuumError.runtimeUnsupported("The process argument vector was truncated.")
            }
            arguments.append(argument)
        }
        while offset < data.count, data[offset] == 0 { offset += 1 }

        var environment: [String] = []
        while offset < data.count {
            guard let entry = nextString() else { break }
            if entry.isEmpty { break }
            environment.append(entry)
        }
        return (executablePath, arguments, environment)
    }

    private func copyThreadState(
        snapshot: OpaquePointer,
        memberIndex: Int,
        threadIndex: Int,
        length: Int,
        vector: Bool
    ) throws -> Data {
        var data = Data(count: length)
        var requiredLength = 0
        let status = data.withUnsafeMutableBytes { buffer in
            if vector {
                continuum_remote_process_group_copy_member_thread_vector_state(
                    snapshot, memberIndex, threadIndex,
                    buffer.baseAddress, buffer.count, &requiredLength
                )
            } else {
                continuum_remote_process_group_copy_member_thread_general_state(
                    snapshot, memberIndex, threadIndex,
                    buffer.baseAddress, buffer.count, &requiredLength
                )
            }
        }
        try requireRuntimeOK(status, operation: "export thread registers")
        guard requiredLength == length else {
            throw ContinuumError.runtimeUnsupported(
                "The runtime exported an incomplete thread register bank."
            )
        }
        return data
    }

    private func requireRuntimeOK(
        _ status: continuum_status,
        operation: String
    ) throws {
        guard status == CONTINUUM_STATUS_OK else {
            throw ContinuumError.runtimeUnsupported(
                "Could not \(operation): \(statusDescription(status))."
            )
        }
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func hexDigest(_ digest: continuum_sha256_digest) -> String {
        var copy = digest
        return withUnsafeBytes(of: &copy) { bytes in
            bytes.map { String(format: "%02x", $0) }.joined()
        }
    }

    private func groupMembers(
        in snapshot: OpaquePointer
    ) throws -> [HotProcessMember] {
        let count = continuum_remote_process_group_member_count(snapshot)
        var members: [HotProcessMember] = []
        members.reserveCapacity(count)

        for index in 0..<count {
            var info = continuum_remote_process_group_member_info()
            let status = continuum_remote_process_group_copy_member_info(
                snapshot,
                index,
                &info
            )
            guard status == CONTINUUM_STATUS_OK else {
                throw ContinuumError.runtimeUnsupported(
                    "The runtime could not inspect captured process \(index): \(statusDescription(status))."
                )
            }
            members.append(HotProcessMember(
                processIdentifier: info.process_id,
                parentProcessIdentifier: info.parent_process_id
            ))
        }
        return members
    }

    private static func captureMembers(rootedAt roots: Set<Int32>) -> [Int32] {
        guard !roots.isEmpty else { return [] }
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL]
        var byteCount = 0
        guard sysctl(&mib, u_int(mib.count), nil, &byteCount, nil, 0) == 0,
              byteCount >= MemoryLayout<kinfo_proc>.stride else {
            return []
        }

        let capacity = byteCount / MemoryLayout<kinfo_proc>.stride
        var processes = [kinfo_proc](repeating: kinfo_proc(), count: capacity)
        guard sysctl(&mib, u_int(mib.count), &processes, &byteCount, nil, 0) == 0 else {
            return []
        }

        let count = min(capacity, byteCount / MemoryLayout<kinfo_proc>.stride)
        let parentByProcess = Dictionary(uniqueKeysWithValues: processes.prefix(count).map {
            ($0.kp_proc.p_pid, $0.kp_eproc.e_ppid)
        })
        guard roots.allSatisfy({ parentByProcess[$0] != nil }) else { return [] }

        var members = roots
        var changed = true
        while changed {
            changed = false
            for (processIdentifier, parentProcessIdentifier) in parentByProcess
            where members.contains(parentProcessIdentifier) {
                changed = members.insert(processIdentifier).inserted || changed
            }
        }

        return members.sorted { lhs, rhs in
            func depth(of processIdentifier: Int32) -> Int {
                var current = processIdentifier
                var visited: Set<Int32> = []
                var result = 0
                while let parent = parentByProcess[current],
                      members.contains(parent),
                      visited.insert(current).inserted {
                    result += 1
                    current = parent
                }
                return result
            }
            let lhsDepth = depth(of: lhs)
            let rhsDepth = depth(of: rhs)
            return lhsDepth == rhsDepth ? lhs < rhs : lhsDepth < rhsDepth
        }
    }

    private func captureError(
        status: continuum_status,
        appName: String
    ) -> ContinuumError {
        let detail: String
        switch status {
        case CONTINUUM_STATUS_ACCESS_DENIED:
            detail = "macOS denied task access to \(appName). Its signing or protection policy blocks the current research runtime."
        case CONTINUUM_STATUS_SNAPSHOT_BUDGET_EXCEEDED:
            detail = "\(appName)'s writable memory exceeds the \(ByteCountFormatter.string(fromByteCount: Int64(maximumCapturedBytes), countStyle: .memory)) hot-snapshot limit."
        case CONTINUUM_STATUS_UNSUPPORTED_DESCRIPTOR:
            detail = "\(appName) owns a descriptor type the resource guard cannot safely preserve yet."
        default:
            detail = "Hot process capture failed: \(statusDescription(status))."
        }
        return .runtimeUnsupported(detail)
    }

    private func restoreFailureDescription(
        status: continuum_status,
        report: continuum_remote_process_group_restore_report
    ) -> String {
        let guardMessage: String
        switch status {
        case CONTINUUM_STATUS_DESCRIPTOR_TABLE_CHANGED:
            guardMessage = "The app's file descriptors or sockets changed."
        case CONTINUUM_STATUS_MACH_NAMESPACE_CHANGED:
            guardMessage = "The app's Mach/XPC namespace changed."
        case CONTINUUM_STATUS_THREAD_SET_CHANGED:
            guardMessage = "The app created or removed threads."
        case CONTINUUM_STATUS_PROCESS_TREE_CHANGED:
            guardMessage = "The app's helper-process tree changed."
        case CONTINUUM_STATUS_REGION_MAPPING_CHANGED:
            guardMessage = "The app's memory layout changed."
        case CONTINUUM_STATUS_TARGET_EXITED:
            guardMessage = "The captured app exited."
        default:
            guardMessage = "The hot restore failed: \(statusDescription(status))."
        }

        if report.rollback_attempted != 0 {
            return guardMessage + (report.rollback_verified != 0
                ? " Continuum restored the pre-attempt safety state."
                : " The emergency rollback could not be verified; keep the app paused and close it.")
        }
        return guardMessage + " No memory was changed."
    }

    private func statusDescription(_ status: continuum_status) -> String {
        continuum_status_string(status).map(String.init(cString:)) ?? "status \(status.rawValue)"
    }

    private func clampedInt64(_ value: UInt64) -> Int64 {
        value > UInt64(Int64.max) ? Int64.max : Int64(value)
    }

    private static func experimentalResourceCoverage(
        writableVnodeCount: Int
    ) -> [ResourceCoverage] {[
        ResourceCoverage(
            domain: .memory,
            mode: .restored,
            detail: "Readable+writable private/COW memory is restored with readback validation."
        ),
        ResourceCoverage(
            domain: .threads,
            mode: .restored,
            detail: "ARM64 general and vector thread state is restored for the unchanged thread set."
        ),
        ResourceCoverage(
            domain: .localFiles,
            mode: .unavailable,
            detail: "Continuum never rewinds file contents. \(writableVnodeCount) writable open file descriptor\(writableVnodeCount == 1 ? "" : "s") are tracked only so the app can reconnect to current files."
        ),
        ResourceCoverage(
            domain: .descriptors,
            mode: .guarded,
            detail: "Descriptor topology and vnode identity must remain unchanged."
        ),
        ResourceCoverage(
            domain: .sockets,
            mode: .guarded,
            detail: "Socket identity and buffer counts are checked, not recreated."
        ),
        ResourceCoverage(
            domain: .machIPC,
            mode: .guarded,
            detail: "Every saved Mach name/right/object must remain valid. Additive XPC rights are allowed; queued messages are not replayed."
        ),
        ResourceCoverage(
            domain: .windowServer,
            mode: .unavailable,
            detail: "WindowServer state is not rebuilt in this checkpoint."
        ),
        ResourceCoverage(
            domain: .graphicsGPU,
            mode: .unavailable,
            detail: "Core Animation, Metal, and OpenGL resources are not rebuilt yet."
        ),
        ResourceCoverage(
            domain: .audioDevices,
            mode: .unavailable,
            detail: "Audio and device resources are not reopened yet."
        ),
        ResourceCoverage(
            domain: .clocksRandomInput,
            mode: .unavailable,
            detail: "Clock, randomness, and input events are not replayed yet."
        ),
    ]}
}

private final class HotProcessSnapshotHandle: @unchecked Sendable {
    let pointer: OpaquePointer
    let rootProcessIdentifier: Int32
    let processIdentifiers: [Int32]
    let writableVnodes: [HotWritableVnode]
    let snapshotID: SnapshotID
    let appID: String
    let kind: SnapshotKind
    let fileCheckpointStore: APFSLocalFileCheckpointStore?

    init(
        pointer: OpaquePointer,
        rootProcessIdentifier: Int32,
        processIdentifiers: [Int32],
        writableVnodes: [HotWritableVnode],
        snapshotID: SnapshotID,
        appID: String,
        kind: SnapshotKind,
        fileCheckpointStore: APFSLocalFileCheckpointStore?
    ) {
        self.pointer = pointer
        self.rootProcessIdentifier = rootProcessIdentifier
        self.processIdentifiers = processIdentifiers
        self.writableVnodes = writableVnodes
        self.snapshotID = snapshotID
        self.appID = appID
        self.kind = kind
        self.fileCheckpointStore = fileCheckpointStore
    }

    deinit {
        continuum_remote_process_group_snapshot_destroy(pointer)
        try? fileCheckpointStore?.deleteCoherently(snapshotID: snapshotID)
    }
}

private struct HotProcessMember: Sendable {
    let processIdentifier: Int32
    let parentProcessIdentifier: Int32
}

private struct HotProcessManifest: Codable, Sendable {
    let formatVersion: Int
    let rootProcessIdentifier: Int32
    let processIdentifiers: [Int32]
    let capturedBytes: UInt64
    let capturedRegionCount: UInt64
    let excludedRegionCount: UInt64
    let threadCount: UInt64
    let writableVnodes: [HotWritableVnode]
    let resourceCoverage: [ResourceCoverage]
}

private struct HotWritableVnode: Codable, Hashable, Sendable, Comparable {
    let processIdentifier: Int32
    let fileDescriptor: Int32
    let openFlags: UInt32
    let offset: Int64
    let device: UInt64
    let inode: UInt64
    let byteCount: UInt64
    let mode: UInt32
    let path: String

    static func < (lhs: Self, rhs: Self) -> Bool {
        if lhs.processIdentifier != rhs.processIdentifier {
            return lhs.processIdentifier < rhs.processIdentifier
        }
        if lhs.fileDescriptor != rhs.fileDescriptor {
            return lhs.fileDescriptor < rhs.fileDescriptor
        }
        return lhs.path < rhs.path
    }
}

private struct HotRawDescriptorGraph {
    let handles: [continuum_remote_descriptor_handle_info]
    let sockets: [continuum_remote_socket_resource_info]
    let pipes: [continuum_remote_pipe_resource_info]
    let kqueues: [continuum_remote_kqueue_resource_info]
    let registrations: [continuum_remote_kqueue_registration_info]
}

private final class HotResourceInventoryCallbackBox: @unchecked Sendable {
    let expectedInventory: [HotWritableVnode]?
    let fileCheckpointStore: APFSLocalFileCheckpointStore?
    let captureSnapshotID: SnapshotID?
    let restoreSnapshotID: SnapshotID?
    let rollbackSnapshotID: SnapshotID?
    let descriptorBootstrapLibraryPath: String?
    var inventory: [HotWritableVnode]?
    var tcpEndpoints: [continuum_remote_tcp_endpoint_info]?
    var ptyDescriptors: [continuum_remote_pty_descriptor_info]?
    var descriptorGraph: HotRawDescriptorGraph?
    var failureDescription: String?

    init(
        expectedInventory: [HotWritableVnode]? = nil,
        fileCheckpointStore: APFSLocalFileCheckpointStore? = nil,
        captureSnapshotID: SnapshotID? = nil,
        restoreSnapshotID: SnapshotID? = nil,
        rollbackSnapshotID: SnapshotID? = nil,
        descriptorBootstrapLibraryPath: String? = nil
    ) {
        self.expectedInventory = expectedInventory
        self.fileCheckpointStore = fileCheckpointStore
        self.captureSnapshotID = captureSnapshotID
        self.restoreSnapshotID = restoreSnapshotID
        self.rollbackSnapshotID = rollbackSnapshotID
        self.descriptorBootstrapLibraryPath = descriptorBootstrapLibraryPath
    }

    func capture(from snapshot: OpaquePointer) -> continuum_status {
        var count = 0
        var status = continuum_remote_process_group_copy_writable_vnodes(
            snapshot,
            nil,
            0,
            &count
        )
        if ProcessInfo.processInfo.environment["CONTINUUM_CAPTURE_TRACE"] != nil {
            fputs("continuum resources phase=writable-count status=\(status.rawValue) count=\(count)\n", stderr)
        }
        guard status == CONTINUUM_STATUS_OK else { return status }

        var rawEntries = Array(
            repeating: continuum_remote_writable_vnode_info(),
            count: count
        )
        var returnedCount = count
        status = rawEntries.withUnsafeMutableBufferPointer { buffer in
            continuum_remote_process_group_copy_writable_vnodes(
                snapshot,
                buffer.baseAddress,
                buffer.count,
                &returnedCount
            )
        }
        if ProcessInfo.processInfo.environment["CONTINUUM_CAPTURE_TRACE"] != nil {
            fputs("continuum resources phase=writable-copy status=\(status.rawValue) returned=\(returnedCount)\n", stderr)
        }
        guard status == CONTINUUM_STATUS_OK, returnedCount == count else {
            return status == CONTINUUM_STATUS_OK
                ? CONTINUUM_STATUS_VALIDATION_FAILED
                : status
        }

        let captured = rawEntries.map(Self.convert).sorted()
        inventory = captured
        if let expectedInventory,
           !Self.hasMatchingStableIdentity(captured, expectedInventory) {
            return CONTINUUM_STATUS_DESCRIPTOR_TABLE_CHANGED
        }

        var endpointCount = 0
        status = continuum_remote_process_group_copy_tcp_endpoints(
            snapshot,
            nil,
            0,
            &endpointCount
        )
        if ProcessInfo.processInfo.environment["CONTINUUM_CAPTURE_TRACE"] != nil {
            fputs("continuum resources phase=tcp-count status=\(status.rawValue) count=\(endpointCount)\n", stderr)
        }
        guard status == CONTINUUM_STATUS_OK else { return status }
        var capturedEndpoints = Array(
            repeating: continuum_remote_tcp_endpoint_info(),
            count: endpointCount
        )
        var returnedEndpointCount = endpointCount
        status = capturedEndpoints.withUnsafeMutableBufferPointer { buffer in
            continuum_remote_process_group_copy_tcp_endpoints(
                snapshot,
                buffer.baseAddress,
                buffer.count,
                &returnedEndpointCount
            )
        }
        guard status == CONTINUUM_STATUS_OK,
              returnedEndpointCount == endpointCount else {
            return status == CONTINUUM_STATUS_OK
                ? CONTINUUM_STATUS_VALIDATION_FAILED
                : status
        }
        tcpEndpoints = capturedEndpoints

        var ptyDescriptorCount = 0
        status = continuum_remote_process_group_copy_pty_descriptors(
            snapshot,
            nil,
            0,
            &ptyDescriptorCount
        )
        if ProcessInfo.processInfo.environment["CONTINUUM_CAPTURE_TRACE"] != nil {
            fputs("continuum resources phase=pty-count status=\(status.rawValue) count=\(ptyDescriptorCount)\n", stderr)
        }
        guard status == CONTINUUM_STATUS_OK else { return status }
        var capturedPTYDescriptors = Array(
            repeating: continuum_remote_pty_descriptor_info(),
            count: ptyDescriptorCount
        )
        var returnedPTYDescriptorCount = ptyDescriptorCount
        status = capturedPTYDescriptors.withUnsafeMutableBufferPointer { buffer in
            continuum_remote_process_group_copy_pty_descriptors(
                snapshot,
                buffer.baseAddress,
                buffer.count,
                &returnedPTYDescriptorCount
            )
        }
        guard status == CONTINUUM_STATUS_OK,
              returnedPTYDescriptorCount == ptyDescriptorCount else {
            return status == CONTINUUM_STATUS_OK
                ? CONTINUUM_STATUS_VALIDATION_FAILED
                : status
        }
        ptyDescriptors = capturedPTYDescriptors

        var rawGraph: OpaquePointer?
        if let descriptorBootstrapLibraryPath {
            status = descriptorBootstrapLibraryPath.withCString {
                continuum_remote_process_group_capture_descriptor_graph_authenticated(
                    snapshot,
                    $0,
                    &rawGraph
                )
            }
        } else {
            status = continuum_remote_process_group_capture_descriptor_graph(
                snapshot,
                &rawGraph
            )
        }
        if ProcessInfo.processInfo.environment["CONTINUUM_CAPTURE_TRACE"] != nil {
            fputs("continuum resources phase=descriptor-graph status=\(status.rawValue)\n", stderr)
        }
        guard status == CONTINUUM_STATUS_OK, let rawGraph else {
            return status == CONTINUUM_STATUS_OK
                ? CONTINUUM_STATUS_VALIDATION_FAILED
                : status
        }
        defer { continuum_remote_descriptor_graph_destroy(rawGraph) }

        var handles = Array(
            repeating: continuum_remote_descriptor_handle_info(),
            count: continuum_remote_descriptor_graph_handle_count(rawGraph)
        )
        var sockets = Array(
            repeating: continuum_remote_socket_resource_info(),
            count: continuum_remote_descriptor_graph_socket_count(rawGraph)
        )
        var pipes = Array(
            repeating: continuum_remote_pipe_resource_info(),
            count: continuum_remote_descriptor_graph_pipe_count(rawGraph)
        )
        var kqueues = Array(
            repeating: continuum_remote_kqueue_resource_info(),
            count: continuum_remote_descriptor_graph_kqueue_count(rawGraph)
        )
        var registrations = Array(
            repeating: continuum_remote_kqueue_registration_info(),
            count: continuum_remote_descriptor_graph_kqueue_registration_count(rawGraph)
        )
        status = handles.withUnsafeMutableBufferPointer {
            continuum_remote_descriptor_graph_copy_handles(
                rawGraph, $0.baseAddress, $0.count
            )
        }
        if status == CONTINUUM_STATUS_OK {
            status = sockets.withUnsafeMutableBufferPointer {
                continuum_remote_descriptor_graph_copy_sockets(
                    rawGraph, $0.baseAddress, $0.count
                )
            }
        }
        if status == CONTINUUM_STATUS_OK {
            status = pipes.withUnsafeMutableBufferPointer {
                continuum_remote_descriptor_graph_copy_pipes(
                    rawGraph, $0.baseAddress, $0.count
                )
            }
        }
        if status == CONTINUUM_STATUS_OK {
            status = kqueues.withUnsafeMutableBufferPointer {
                continuum_remote_descriptor_graph_copy_kqueues(
                    rawGraph, $0.baseAddress, $0.count
                )
            }
        }
        if status == CONTINUUM_STATUS_OK {
            status = registrations.withUnsafeMutableBufferPointer {
                continuum_remote_descriptor_graph_copy_kqueue_registrations(
                    rawGraph, $0.baseAddress, $0.count
                )
            }
        }
        guard status == CONTINUUM_STATUS_OK else { return status }
        descriptorGraph = HotRawDescriptorGraph(
            handles: handles,
            sockets: sockets,
            pipes: pipes,
            kqueues: kqueues,
            registrations: registrations
        )

        let files = Array(Set(captured.map(\.path)))
            .map { URL(fileURLWithPath: $0) }
            .sorted { $0.path < $1.path }
        if let fileCheckpointStore, let captureSnapshotID {
            do {
                _ = try fileCheckpointStore.captureCoherently(
                    snapshotID: captureSnapshotID,
                    files: files
                )
            } catch {
                failureDescription = "The coherent open-file checkpoint failed: \(error.localizedDescription)"
                return CONTINUUM_STATUS_VALIDATION_FAILED
            }
        }
        if let fileCheckpointStore, let restoreSnapshotID {
            do {
                _ = try fileCheckpointStore.restoreCoherently(
                    snapshotID: restoreSnapshotID
                )
            } catch {
                if let rollbackSnapshotID {
                    _ = try? fileCheckpointStore.restoreCoherently(
                        snapshotID: rollbackSnapshotID
                    )
                }
                failureDescription = "Open-file restoration failed and the process memory safety cut was reapplied: \(error.localizedDescription)"
                return CONTINUUM_STATUS_VALIDATION_FAILED
            }
        }
        return CONTINUUM_STATUS_OK
    }

    private static func hasMatchingStableIdentity(
        _ current: [HotWritableVnode],
        _ saved: [HotWritableVnode]
    ) -> Bool {
        guard current.count == saved.count else { return false }
        return zip(current, saved).allSatisfy { current, saved in
            current.processIdentifier == saved.processIdentifier
                && current.fileDescriptor == saved.fileDescriptor
                && current.openFlags == saved.openFlags
                && current.device == saved.device
                && current.inode == saved.inode
                && current.mode == saved.mode
                && current.path == saved.path
        }
    }

    private static func convert(
        _ rawValue: continuum_remote_writable_vnode_info
    ) -> HotWritableVnode {
        var rawValue = rawValue
        let path = withUnsafePointer(to: &rawValue.path) { pathPointer in
            pathPointer.withMemoryRebound(
                to: CChar.self,
                capacity: Int(CONTINUUM_REMOTE_PATH_MAX)
            ) {
                String(cString: $0)
            }
        }
        return HotWritableVnode(
            processIdentifier: rawValue.process_id,
            fileDescriptor: rawValue.file_descriptor,
            openFlags: rawValue.open_flags,
            offset: rawValue.offset,
            device: rawValue.device,
            inode: rawValue.inode,
            byteCount: rawValue.byte_count,
            mode: rawValue.mode,
            path: path
        )
    }
}

private func continuumCaptureHotResourceInventory(
    _ snapshot: OpaquePointer?,
    _ context: UnsafeMutableRawPointer?
) -> continuum_status {
    guard let snapshot, let context else {
        return CONTINUUM_STATUS_INVALID_ARGUMENT
    }
    let box = Unmanaged<HotResourceInventoryCallbackBox>
        .fromOpaque(context)
        .takeUnretainedValue()
    return box.capture(from: snapshot)
}

private func continuumValidateHotResourceInventory(
    _ snapshot: OpaquePointer?,
    _ context: UnsafeMutableRawPointer?
) -> continuum_status {
    continuumCaptureHotResourceInventory(snapshot, context)
}
