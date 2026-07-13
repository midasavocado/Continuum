import ContinuumCore
import ContinuumRuntime
import ContinuumStore
import ContinuumSystem
import Darwin
import Dispatch
import Foundation

enum ExternalHotProof {
    static let minimumCycleCount = 100
    private static let fullProcessCycleCount = 1
    private static let fullProcessCaptureBudget: UInt64 = 1_024 * 1_024 * 1_024

    static func run(targetPath: String, cycles: Int) async throws {
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
        guard let helperPID = ready.helperProcessIdentifier,
            helperPID > 0,
            let helperAddress = ready.helperAddress,
            let helperLength = ready.helperLength,
            helperLength > 0,
            ready.helperState == "A",
            ready.helperValid == nil
        else {
            throw ExternalHotProofFailure.protocolViolation(
                "ready handshake did not identify the target helper"
            )
        }
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
                checkedB.valid == true && checkedB.helperValid == true,
                "target warm-up \(pass) did not validate group state B"
            )
            let warmA = try target.send(command: "mutate", state: "A")
            try require(
                warmA.state == "A",
                "target warm-up \(pass) did not return to state A"
            )
            let checkedA = try target.send(command: "validate", state: "A")
            try require(
                checkedA.valid == true && checkedA.helperValid == true,
                "target warm-up \(pass) did not validate group state A"
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

        var helperSession: OpaquePointer?
        try check(
            continuum_remote_session_open(helperPID, &helperSession),
            operation: "open helper task session for PID \(helperPID)"
        )
        guard let helperSession else {
            throw ExternalHotProofFailure.invariant(
                "runtime returned a nil helper session"
            )
        }
        defer { continuum_remote_session_destroy(helperSession) }

        try check(
            continuum_remote_session_register_region(session, address, UInt64(length)),
            operation: "register target arena"
        )
        try check(
            continuum_remote_session_register_region(
                helperSession,
                helperAddress,
                UInt64(helperLength)
            ),
            operation: "register helper arena"
        )

        let stateA = try capture(session: session, expectedAddress: address, expectedLength: length)
        try require(stateA.digest == ready.digest, "captured A bytes differ from target handshake")
        let helperStateA = try capture(
            session: helperSession,
            expectedAddress: helperAddress,
            expectedLength: helperLength
        )
        try require(
            helperStateA.digest == ready.helperDigest,
            "captured helper A bytes differ from its handshake"
        )

        let mutated = try target.send(command: "mutate", state: "B")
        try require(mutated.event == "mutated", "target did not acknowledge mutation to B")
        try require(mutated.state == "B", "target did not enter state B")
        usleep(100_000)

        let safetyB = try capture(session: session, expectedAddress: address, expectedLength: length)
        let helperSafetyB = try capture(
            session: helperSession,
            expectedAddress: helperAddress,
            expectedLength: helperLength
        )
        try require(stateA.bytes != safetyB.bytes, "target mutation did not change captured bytes")
        try require(safetyB.digest == mutated.digest, "captured safety B differs from target state")
        try require(
            stateA.descriptor.thread_set_hash == safetyB.descriptor.thread_set_hash,
            "target thread set changed between A and safety B captures"
        )
        // Stage both group images through the already validated arena restore
        // primitive while the protocol loops remain parked. This changes real
        // target-owned state without adding allocator mappings between cuts.
        try restore(stateA, into: session, label: "staging root A", cycle: 0)
        try restore(
            helperStateA,
            into: helperSession,
            label: "staging helper A",
            cycle: 0
        )
        var resourceStateA = try captureResources(session: session)
        let processStateAStart = DispatchTime.now().uptimeNanoseconds
        let processStateA = try captureProcessGroup(rootProcessID: targetPID)
        try verifyDurableExportSurface(processStateA)
        progress(
            "process-group A snapshot: \(milliseconds(since: processStateAStart)) ms"
        )
        defer {
            continuum_remote_process_group_snapshot_destroy(processStateA.snapshot)
        }

        try restore(safetyB, into: session, label: "staging root B", cycle: 0)
        try restore(
            helperSafetyB,
            into: helperSession,
            label: "staging helper B",
            cycle: 0
        )
        var resourceSafetyB = try captureResources(session: session)
        let processSafetyBStart = DispatchTime.now().uptimeNanoseconds
        let processSafetyB = try captureProcessGroup(rootProcessID: targetPID)
        progress(
            "process-group B snapshot: \(milliseconds(since: processSafetyBStart)) ms"
        )
        defer {
            continuum_remote_process_group_snapshot_destroy(processSafetyB.snapshot)
        }
        try require(
            processStateA.info.process_count == processSafetyB.info.process_count,
            "target process count changed between group captures"
        )
        try require(
            processStateA.info.process_count >= 2,
            "group capture did not include the target helper"
        )
        try require(
            processStateA.members.contains { $0.processID == targetPID }
                && processStateA.members.contains {
                    $0.processID == helperPID && $0.parentProcessID == targetPID
                },
            "group capture did not preserve the root/helper parent edge"
        )
        for memberA in processStateA.members {
            guard let memberB = processSafetyB.members.first(where: {
                $0.processID == memberA.processID
            }) else {
                throw ExternalHotProofFailure.invariant(
                    "process \(memberA.processID) was missing from group state B"
                )
            }
            if memberA.vmLayoutHash != memberB.vmLayoutHash {
                let difference = try processGroupLayoutDifference(
                    processStateA,
                    member: memberA,
                    processSafetyB,
                    member: memberB
                )
                throw ExternalHotProofFailure.invariant(
                    "\(memberA.processID == targetPID ? "root" : "helper") process "
                        + "\(memberA.processID) VM layout changed between A and B "
                        + "(A=\(String(memberA.vmLayoutHash, radix: 16)), "
                        + "B=\(String(memberB.vmLayoutHash, radix: 16)); "
                        + difference + ")"
                )
            }
            try require(
                memberA.threadSetHash == memberB.threadSetHash,
                "process \(memberA.processID) thread set changed between A and B"
            )
            try require(
                memberA.descriptorTableHash == memberB.descriptorTableHash,
                "process \(memberA.processID) descriptors changed between A and B"
            )
            try require(
                memberA.machSpaceHash == memberB.machSpaceHash,
                "process \(memberA.processID) Mach namespace changed between A and B"
            )
        }
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
            try restoreProcessGroup(processStateA, label: "A", cycle: cycle)
            try validateCapturedArena(
                session: session,
                expectedAddress: address,
                expectedLength: length,
                digest: stateA.digest,
                label: "root A"
            )
            try validateCapturedArena(
                session: helperSession,
                expectedAddress: helperAddress,
                expectedLength: helperLength,
                digest: stateA.digest,
                label: "helper A"
            )

            try restoreProcessGroup(processSafetyB, label: "B", cycle: cycle)
            try validateGroup(
                target: target,
                expected: "B",
                digest: safetyB.digest,
                cycle: cycle
            )
        }

        for cycle in 1...cycles {
            try restore(stateA, into: session, label: "A", cycle: cycle)
            try validate(target: target, expected: "A", digest: stateA.digest, cycle: cycle)

            try restore(safetyB, into: session, label: "B", cycle: cycle)
            try validate(target: target, expected: "B", digest: safetyB.digest, cycle: cycle)
        }

        let durableImage = try await verifyShippingHotBackend(
            target: target,
            targetPID: targetPID,
            helperPID: helperPID,
            rootStateA: stateA,
            helperStateA: helperStateA,
            rootSession: session,
            helperSession: helperSession,
            expectedStateB: safetyB.digest
        )

        let opened = try target.send(command: "open-resource")
        try require(
            opened.event == "resource-opened",
            "target did not open the descriptor-change probe"
        )
        try verifyDescriptorMutationIsRejected(
            processSafetyB
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
        try verifySuspendedColdReplacement(
            durableImage,
            originalRootProcessID: targetPID,
            savedArena: stateA
        )
        let coldMemory = try await verifyDurableRootMemoryReconstruction(
            targetPath: targetPath
        )

        print("external-hot-proof: PASS")
        print("  target binary:       \(target.executablePath)")
        print("  target PIDs:         root=\(targetPID), helper=\(helperPID)")
        print("  registered arena:    0x\(String(address, radix: 16)) + \(length) bytes")
        print("  captured threads:    A=\(stateA.threadCount), B=\(safetyB.threadCount)")
        print("  captured processes:  \(processStateA.info.process_count)")
        print("  full VM regions:     \(processStateA.info.captured_region_count)")
        print("  full captured bytes: \(processStateA.info.captured_bytes)")
        print("  excluded VM regions: \(processStateA.info.excluded_region_count)")
        print(
            "  kernel resources:    \(resourceSummary(resourceStateA))"
        )
        print("  resource A->B gate:  unchanged")
        print("  additive Mach rights: accepted; saved rights remained identity-valid")
        print("  additive descendant: accepted; captured process identities remained valid")
        print("  coherent open files: root + helper APFS bytes restored")
        print("  descriptor mutation: rejected before memory write")
        print("  app backend adapter: captured + restored live snapshot state")
        print("  cold replacement:    deterministic layout + saved arena bytes, stopped before main")
        print(
            "  cold full memory:     \(coldMemory.reconstructedRegionCount) regions, "
                + "\(coldMemory.reconstructedChunkCount) encrypted chunks, "
                + "\(coldMemory.reconstructedBytes) bytes"
        )
        print(
            "  cold thread state:    \(coldMemory.reconstructedThreadCount) thread, "
                + "\(coldMemory.reconstructedThreadStateBytes) bytes, replacement ID "
                + "\(coldMemory.replacementThreadIdentifier)"
        )
        print(
            "  cold file descriptors: \(coldMemory.reconstructedFileDescriptorCount) reopened"
        )
        print(
            "  cold local files:      \(coldMemory.reconstructedFileCount) file, "
                + "\(coldMemory.reconstructedFileBytes) bytes restored + rolled back"
        )
        print("  restore cycles:      \(fullProcessCycleCount) process-group + \(cycles) arena-only")
        print(
            "  verified restores:   \((fullProcessCycleCount + cycles) * 2) (target-owned validation)"
        )
        print("  safety state B was captured before the first rewind and restored last")
    }

    private static func verifyShippingHotBackend(
        target: ExternalTargetProcess,
        targetPID: Int32,
        helperPID: Int32,
        rootStateA: RemoteCapture,
        helperStateA: RemoteCapture,
        rootSession: OpaquePointer,
        helperSession: OpaquePointer,
        expectedStateB: String
    ) async throws -> DurableCheckpointImage {
        let fileCheckpointRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                "continuum-shipping-hot-proof-\(UUID().uuidString)",
                isDirectory: true
            )
        defer { try? FileManager.default.removeItem(at: fileCheckpointRoot) }
        let service = HotProcessCheckpointService(
            maximumCapturedBytes: fullProcessCaptureBudget,
            maximumRetainedSnapshots: 2,
            fileCheckpointRootURL: fileCheckpointRoot
        )
        let app = AppIdentity(
            bundleIdentifier: nil,
            displayName: "Continuum External Target",
            bundleURL: nil,
            executableURL: URL(fileURLWithPath: target.executablePath),
            version: "proof",
            signingIdentifier: nil,
            teamIdentifier: nil,
            isApplePlatformBinary: false
        )
        let capture = try await service.capture(
            app: app,
            processIdentifiers: [targetPID, helperPID],
            kind: .beforeRewind,
            branchID: UUID()
        )
        let durableStoreRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                "continuum-durable-proof-\(UUID().uuidString)",
                isDirectory: true
            )
        defer { try? FileManager.default.removeItem(at: durableStoreRoot) }
        let durableKey = Data(repeating: 0x5A, count: 32)
        let durableStore = try EncryptedSnapshotStore(
            rootURL: durableStoreRoot,
            encryptionKey: durableKey
        )
        let saved = try await durableStore.save(capture)
        let reopenedStore = try EncryptedSnapshotStore(
            rootURL: durableStoreRoot,
            encryptionKey: durableKey
        )
        let durableManifest = try await reopenedStore.artifact(
            for: saved.id,
            logicalName: "durable-checkpoint-v3.json"
        )
        let durableImage = try JSONDecoder().decode(
            DurableCheckpointImage.self,
            from: durableManifest.data
        )
        try require(
            durableImage.members.count == 2
                && durableImage.members.allSatisfy {
                    !$0.regions.isEmpty && !$0.threads.isEmpty
                },
            "reopened durable checkpoint omitted process memory or registers"
        )
        try require(
            durableImage.members.allSatisfy { member in
                guard let launch = member.launchContract else { return false }
                return FileManager.default.isExecutableFile(
                    atPath: launch.executablePath
                )
                    && !launch.arguments.isEmpty
                    && launch.arguments[0].contains("ContinuumExternalTarget")
                    && launch.environment.contains { $0.hasPrefix("PATH=") }
                    && !launch.workingDirectory.isEmpty
            },
            "reopened durable checkpoint omitted the process relaunch contract"
        )
        try require(
            !durableImage.writableFileDescriptors.isEmpty
                && durableImage.writableFiles.allSatisfy { file in
                    file.chunks.reduce(UInt64(0)) {
                        $0 + $1.logicalBytes
                    } == file.byteCount
                }
                && durableImage.writableFileDescriptors.allSatisfy { descriptor in
                    durableImage.writableFiles.contains { file in
                        file.originalPath == descriptor.originalPath
                            && file.device == descriptor.device
                            && file.inode == descriptor.inode
                            && file.mode == descriptor.mode
                    }
                },
            "reopened durable checkpoint omitted coherent file bytes or descriptor ownership"
        )
        let durableMemoryChunks = durableImage.members.reduce(into: 0) {
            total, member in
            total += member.regions.reduce(0) { $0 + $1.chunks.count }
        }
        progress(
            "durable image reopened: \(durableImage.members.count) processes, "
                + "\(durableMemoryChunks) memory chunks"
        )
        try require(
            capture.snapshot.availability == .experimentalHot,
            "shipping backend did not publish live restore availability"
        )
        try require(
            capture.snapshot.resourceCoverage?.count == ResourceDomain.allCases.count,
            "shipping backend omitted a resource coverage domain"
        )
        try require(
            !capture.snapshot.hasCompleteResourceCoverage,
            "live snapshot incorrectly claimed complete resource reconstruction"
        )
        let fileCoverage = capture.snapshot.resourceCoverage?.first {
            $0.domain == .localFiles
        }
        try require(
            fileCoverage?.mode == .guarded,
            "shipping backend did not run coherent writable-file inventory"
        )
        let liveAvailability = await service.currentRestoreAvailability(
            for: capture.snapshot
        )
        try require(
            liveAvailability == .experimentalHot,
            "shipping backend expired its live snapshot immediately"
        )

        let addedMachRights = try target.send(command: "add-mach-port")
        try require(
            addedMachRights.valid == true && addedMachRights.helperValid == true,
            "target did not add the root/helper Mach-right probe"
        )
        let addedChild = try target.send(command: "add-child")
        try require(
            addedChild.valid == true,
            "target did not add the descendant-tree probe"
        )
        let changedFiles = try target.send(command: "mutate-file", state: "A")
        try require(
            changedFiles.valid == true && changedFiles.helperValid == true,
            "target did not mutate both stable open files"
        )
        try restore(rootStateA, into: rootSession, label: "adapter staging root A", cycle: 0)
        try restore(helperStateA, into: helperSession, label: "adapter staging helper A", cycle: 0)

        let result = await service.restore(
            snapshot: capture.snapshot,
            artifacts: capture.artifacts
        )
        try require(
            result == .experimentalHot,
            "shipping backend restore returned \(String(describing: result))"
        )
        try validateGroup(
            target: target,
            expected: "B",
            digest: expectedStateB,
            cycle: 0
        )
        let restoredFiles = try target.send(command: "validate-file", state: "B")
        try require(
            restoredFiles.valid == true && restoredFiles.helperValid == true,
            "shipping backend did not restore both open files from APFS clones"
        )
        return durableImage
    }

    private static func verifySuspendedColdReplacement(
        _ image: DurableCheckpointImage,
        originalRootProcessID: Int32,
        savedArena: RemoteCapture
    ) throws {
        guard let root = image.members.first(where: {
            $0.processIdentifier == originalRootProcessID
        }), let launch = root.launchContract else {
            throw ExternalHotProofFailure.invariant(
                "durable image did not retain the root launch contract"
            )
        }

        var controlledEnvironment = launch.environment.filter {
            !$0.hasPrefix("DYLD_SHARED_REGION=")
        }
        controlledEnvironment.append("DYLD_SHARED_REGION=private")
        controlledEnvironment.append("CONTINUUM_DETERMINISTIC_ADDRESS_SPACE=1")

        func inspectReplacementLayout(reconstructArena: Bool) throws -> UInt64 {
            var replacementProcessID: Int32 = 0
            let status = withCStringArray(launch.arguments) { arguments in
                withCStringArray(controlledEnvironment) { environment in
                    launch.executablePath.withCString { executable in
                        launch.workingDirectory.withCString { directory in
                            continuum_spawn_process_suspended(
                                executable,
                                arguments,
                                environment,
                                directory,
                                &replacementProcessID
                            )
                        }
                    }
                }
            }
            try check(status, operation: "spawn suspended cold replacement")
            guard replacementProcessID > 0 else {
                throw ExternalHotProofFailure.invariant(
                    "cold replacement returned an invalid process identifier"
                )
            }
            defer {
                kill(replacementProcessID, SIGKILL)
                var terminationStatus: Int32 = 0
                waitpid(replacementProcessID, &terminationStatus, 0)
            }

            var processInfo = proc_bsdinfo()
            try require(
                proc_pidinfo(
                    replacementProcessID,
                    PROC_PIDTBSDINFO,
                    0,
                    &processInfo,
                    Int32(MemoryLayout<proc_bsdinfo>.size)
                ) == Int32(MemoryLayout<proc_bsdinfo>.size),
                "cold replacement could not be inspected"
            )
            try require(
                processInfo.pbi_status == UInt32(SSTOP),
                "cold replacement ran target code before reconstruction"
            )

            var executablePath = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
            let pathLength = proc_pidpath(
                replacementProcessID,
                &executablePath,
                UInt32(executablePath.count)
            )
            try require(pathLength > 0, "cold replacement executable path was unavailable")
            let reportedPath = String(
                decoding: executablePath.prefix { $0 != 0 }.map {
                    UInt8(bitPattern: $0)
                },
                as: UTF8.self
            )
            let canonicalReportedPath = URL(fileURLWithPath: reportedPath)
                .resolvingSymlinksInPath().standardizedFileURL.path
            let canonicalLaunchPath = URL(fileURLWithPath: launch.executablePath)
                .resolvingSymlinksInPath().standardizedFileURL.path
            try require(
                canonicalReportedPath == canonicalLaunchPath,
                "cold replacement launched a different executable"
            )

            var session: OpaquePointer?
            try check(
                continuum_remote_session_open(replacementProcessID, &session),
                operation: "open suspended replacement task"
            )
            guard let session else {
                throw ExternalHotProofFailure.invariant(
                    "cold replacement returned no task session"
                )
            }
            defer { continuum_remote_session_destroy(session) }

            var layoutInfo = continuum_remote_process_layout_info()
            try check(
                continuum_remote_session_inspect_process_layout(
                    session,
                    &layoutInfo
                ),
                operation: "inspect suspended replacement VM layout"
            )
            try require(layoutInfo.region_count > 0, "cold replacement had no VM regions")

            if reconstructArena {
                var region = continuum_remote_process_region_info()
                region.address = savedArena.descriptor.address
                region.length = savedArena.descriptor.length
                region.protection = savedArena.descriptor.protection
                region.maximum_protection = savedArena.descriptor.maximum_protection
                region.inheritance = Int32(bitPattern: VM_INHERIT_COPY)
                region.share_mode = savedArena.descriptor.share_mode
                region.user_tag = 0
                var report = continuum_remote_restore_report()
                let reconstructionStatus = savedArena.bytes.withUnsafeBytes { bytes in
                    continuum_remote_session_reconstruct_region(
                        session,
                        &region,
                        bytes.baseAddress,
                        bytes.count,
                        &report
                    )
                }
                guard reconstructionStatus == CONTINUUM_STATUS_OK else {
                    throw ExternalHotProofFailure.invariant(
                        "cold arena reconstruction failed at stage "
                            + "\(report.reconstruction_stage), Mach "
                            + "\(report.mach_result): "
                            + runtimeStatusDescription(reconstructionStatus)
                    )
                }
                try require(
                    report.bytes_written == savedArena.bytes.count
                        && report.readback_verified != 0,
                    "cold replacement did not verify reconstructed arena bytes"
                )
                try require(
                    report.max_protection_verified != 0
                        || (report.reconstruction_stage
                            == CONTINUUM_RECONSTRUCTION_STAGE_MAX_PROTECT.rawValue
                            && report.mach_result == KERN_PROTECTION_FAILURE),
                    "cold replacement hid an unexpected maximum-protection result"
                )
            }
            return layoutInfo.layout_hash
        }

        let firstLayoutHash = try inspectReplacementLayout(reconstructArena: true)
        let secondLayoutHash = try inspectReplacementLayout(reconstructArena: false)
        try require(
            firstLayoutHash == secondLayoutHash,
            "controlled cold replacements did not receive a deterministic VM layout"
        )
    }

    private static func verifyDurableRootMemoryReconstruction(
        targetPath: String
    ) async throws -> ColdProcessPreparation {
        guard let bootstrapLibraryPath = ProcessInfo.processInfo.environment[
            "CONTINUUM_BOOTSTRAP_LIBRARY_PATH"
        ], FileManager.default.fileExists(atPath: bootstrapLibraryPath) else {
            throw ExternalHotProofFailure.invariant(
                "cold proof bootstrap library is missing"
            )
        }
        let coldProofRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                "continuum-cold-file-proof-\(UUID().uuidString)",
                isDirectory: true
            )
        try FileManager.default.createDirectory(
            at: coldProofRoot,
            withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: coldProofRoot) }
        let coldFileURL = coldProofRoot.appendingPathComponent("state.bin")
        let coldFileCheckpointRoot = coldProofRoot.appendingPathComponent(
            "hot-file-root",
            isDirectory: true
        )
        let coldFileSafetyRoot = coldProofRoot.appendingPathComponent(
            "cold-file-transactions",
            isDirectory: true
        )
        let savedFileBytes = Data("continuum-cold-saved-A".utf8)
        let futureFileBytes = Data("continuum-cold-future-B-and-more".utf8)
        try savedFileBytes.write(to: coldFileURL)
        let originalFileInode = try fileInode(coldFileURL)
        var environment = ProcessInfo.processInfo.environment.map {
            "\($0.key)=\($0.value)"
        }.filter {
            !$0.hasPrefix("DYLD_SHARED_REGION=")
                && !$0.hasPrefix("CONTINUUM_DETERMINISTIC_ADDRESS_SPACE=")
                && !$0.hasPrefix("CONTINUUM_BOOTSTRAP_STOP=")
                && !$0.hasPrefix("DYLD_INSERT_LIBRARIES=")
                && !$0.hasPrefix("MallocLargeCache=")
        }
        environment.append("DYLD_SHARED_REGION=private")
        environment.append("CONTINUUM_DETERMINISTIC_ADDRESS_SPACE=1")
        environment.append("CONTINUUM_BOOTSTRAP_STOP=1")
        environment.append("MallocLargeCache=0")
        environment.append("DYLD_INSERT_LIBRARIES=\(bootstrapLibraryPath)")
        let arguments = [
            targetPath,
            "--continuum-cold-child",
            coldFileURL.path
        ]

        var originalProcessIdentifier: Int32 = 0
        let spawnStatus = withCStringArray(arguments) { argumentEntries in
            withCStringArray(environment) { environmentEntries in
                targetPath.withCString { executable in
                    "/private/tmp".withCString { directory in
                        continuum_spawn_process_suspended(
                            executable,
                            argumentEntries,
                            environmentEntries,
                            directory,
                            &originalProcessIdentifier
                        )
                    }
                }
            }
        }
        try check(spawnStatus, operation: "spawn deterministic durable target")
        var originalWasReaped = false
        defer {
            if !originalWasReaped {
                kill(originalProcessIdentifier, SIGKILL)
                var status: Int32 = 0
                waitpid(originalProcessIdentifier, &status, 0)
            }
        }
        try check(
            continuum_advance_process_to_bootstrap_stop(
                originalProcessIdentifier,
                5_000
            ),
            operation: "reach deterministic target pre-main bootstrap"
        )
        try require(
            kill(originalProcessIdentifier, SIGCONT) == 0,
            "deterministic durable target could not resume"
        )
        usleep(100_000)

        let service = HotProcessCheckpointService(
            maximumCapturedBytes: fullProcessCaptureBudget,
            maximumRetainedSnapshots: 2,
            fileCheckpointRootURL: coldFileCheckpointRoot
        )
        let app = AppIdentity(
            bundleIdentifier: nil,
            displayName: "Continuum Deterministic Target",
            bundleURL: nil,
            executableURL: URL(fileURLWithPath: targetPath),
            version: "proof",
            signingIdentifier: nil,
            teamIdentifier: nil,
            isApplePlatformBinary: false
        )
        let capture = try await service.capture(
            app: app,
            processIdentifiers: [originalProcessIdentifier],
            kind: .manual,
            branchID: UUID()
        )
        try replaceFileBytesPreservingInode(
            at: coldFileURL,
            with: futureFileBytes
        )
        let storeRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                "continuum-cold-memory-proof-\(UUID().uuidString)",
                isDirectory: true
            )
        defer { try? FileManager.default.removeItem(at: storeRoot) }
        let store = try EncryptedSnapshotStore(
            rootURL: storeRoot,
            encryptionKey: Data(repeating: 0xC7, count: 32)
        )
        let saved = try await store.save(capture)

        kill(originalProcessIdentifier, SIGKILL)
        var originalStatus: Int32 = 0
        waitpid(originalProcessIdentifier, &originalStatus, 0)
        originalWasReaped = true

        let restorer = ColdProcessRestorer(
            bootstrapLibraryURL: URL(fileURLWithPath: bootstrapLibraryPath),
            fileSafetyRootURL: coldFileSafetyRoot
        )
        let preparation = try await restorer.prepareRootProcess(
            from: saved.id,
            repository: store
        )
        try require(
            preparation.capturedProcessIdentifier == originalProcessIdentifier,
            "cold restorer selected the wrong durable process image"
        )
        try require(
            preparation.reconstructedRegionCount > 0
                && preparation.reconstructedChunkCount > 0
                && preparation.reconstructedBytes
                    == UInt64(capture.snapshot.logicalBytes),
            "cold restorer did not populate the complete durable memory image"
        )
        try require(
            preparation.reconstructedThreadCount == 1
                && preparation.reconstructedThreadStateBytes > 0
                && preparation.replacementThreadIdentifier > 0,
            "cold restorer did not reconstruct and verify the saved thread state"
        )
        try require(
            preparation.reconstructedFileDescriptorCount > 0,
            "cold restorer did not reconstruct the root process's writable descriptors"
        )
        let preparedFileBytes = try Data(contentsOf: coldFileURL)
        let preparedFileInode = try fileInode(coldFileURL)
        try require(
            preparation.reconstructedFileCount == 1
                && preparation.reconstructedFileBytes
                    == UInt64(savedFileBytes.count)
                && preparedFileBytes == savedFileBytes
                && preparedFileInode == originalFileInode,
            "cold restorer did not install the saved local file bytes in place"
        )
        let transactionRoots = try FileManager.default.contentsOfDirectory(
            at: coldFileSafetyRoot,
            includingPropertiesForKeys: nil
        )
        try require(
            transactionRoots.count == 1
                && FileManager.default.fileExists(
                    atPath: transactionRoots[0]
                        .appendingPathComponent("ColdFileTransaction.json").path
                ),
            "cold restorer did not durably journal its file rollback"
        )
        try await restorer.discard(preparation.id)
        let rolledBackFileBytes = try Data(contentsOf: coldFileURL)
        let rolledBackFileInode = try fileInode(coldFileURL)
        try require(
            rolledBackFileBytes == futureFileBytes
                && rolledBackFileInode == originalFileInode,
            "discarding cold preparation did not restore the abandoned current file bytes"
        )
        let remainingTransactions = try FileManager.default.contentsOfDirectory(
            at: coldFileSafetyRoot,
            includingPropertiesForKeys: nil
        )
        try require(
            remainingTransactions.isEmpty,
            "successful cold rollback left a stale durable transaction journal"
        )
        return preparation
    }

    private static func fileInode(_ url: URL) throws -> UInt64 {
        let attributes = try FileManager.default.attributesOfItem(
            atPath: url.path
        )
        guard let inode = attributes[.systemFileNumber] as? NSNumber else {
            throw ExternalHotProofFailure.invariant(
                "proof file inode is unavailable"
            )
        }
        return inode.uint64Value
    }

    private static func replaceFileBytesPreservingInode(
        at url: URL,
        with data: Data
    ) throws {
        let descriptor = url.path.withCString {
            Darwin.open($0, O_WRONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw ExternalHotProofFailure.invariant(
                "proof file could not be opened"
            )
        }
        defer { Darwin.close(descriptor) }
        guard ftruncate(descriptor, off_t(data.count)) == 0 else {
            throw ExternalHotProofFailure.invariant(
                "proof file could not be resized"
            )
        }
        var offset = 0
        while offset < data.count {
            let written = data.withUnsafeBytes { bytes in
                pwrite(
                    descriptor,
                    bytes.baseAddress?.advanced(by: offset),
                    data.count - offset,
                    off_t(offset)
                )
            }
            guard written > 0 else {
                throw ExternalHotProofFailure.invariant(
                    "proof file write failed"
                )
            }
            offset += written
        }
        guard fsync(descriptor) == 0 else {
            throw ExternalHotProofFailure.invariant(
                "proof file sync failed"
            )
        }
    }

    private static func withCStringArray<Result>(
        _ strings: [String],
        _ body: (UnsafePointer<UnsafePointer<CChar>?>?) throws -> Result
    ) rethrows -> Result {
        let allocated: [UnsafeMutablePointer<CChar>?] = strings.map { value in
            value.withCString { strdup($0) }
        }
        defer { allocated.forEach { free($0) } }
        var pointers: [UnsafePointer<CChar>?] = allocated.map { pointer in
            pointer.map { UnsafePointer<CChar>($0) }
        }
        pointers.append(nil)
        return try pointers.withUnsafeBufferPointer { buffer in
            try body(buffer.baseAddress)
        }
    }

    private static func verifyDescriptorMutationIsRejected(
        _ capture: RemoteProcessGroupCapture
    ) throws {
        var report = continuum_remote_process_group_restore_report()
        let status = continuum_remote_process_group_restore(
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

    private static func verifyDurableExportSurface(
        _ capture: RemoteProcessGroupCapture
    ) throws {
        for memberIndex in 0..<continuum_remote_process_group_member_count(
            capture.snapshot
        ) {
            let regionCount = continuum_remote_process_group_member_region_count(
                capture.snapshot,
                memberIndex
            )
            try require(regionCount > 0, "durable export found no memory regions")

            var smallestRegionIndex = 0
            var smallestRegionLength = UInt64.max
            for regionIndex in 0..<regionCount {
                var region = continuum_remote_process_region_info()
                try check(
                    continuum_remote_process_group_copy_member_region_info(
                        capture.snapshot,
                        memberIndex,
                        regionIndex,
                        &region
                    ),
                    operation: "inspect durable region export"
                )
                var requiredLength = 0
                try check(
                    continuum_remote_process_group_copy_member_region_bytes(
                        capture.snapshot,
                        memberIndex,
                        regionIndex,
                        nil,
                        0,
                        &requiredLength
                    ),
                    operation: "size durable region export"
                )
                try require(
                    UInt64(requiredLength) == region.length,
                    "durable region byte length disagreed with metadata"
                )
                if region.length < smallestRegionLength {
                    smallestRegionLength = region.length
                    smallestRegionIndex = regionIndex
                }
            }

            var regionBytes = Data(count: Int(smallestRegionLength))
            var copiedRegionLength = 0
            let regionStatus = regionBytes.withUnsafeMutableBytes { buffer in
                continuum_remote_process_group_copy_member_region_bytes(
                    capture.snapshot,
                    memberIndex,
                    smallestRegionIndex,
                    buffer.baseAddress,
                    buffer.count,
                    &copiedRegionLength
                )
            }
            try check(regionStatus, operation: "copy durable region bytes")
            try require(
                copiedRegionLength == regionBytes.count,
                "durable region export returned a short copy"
            )

            let threadCount = continuum_remote_process_group_member_thread_count(
                capture.snapshot,
                memberIndex
            )
            try require(threadCount > 0, "durable export found no thread states")
            for threadIndex in 0..<threadCount {
                var thread = continuum_remote_thread_state_info()
                try check(
                    continuum_remote_process_group_copy_member_thread_info(
                        capture.snapshot,
                        memberIndex,
                        threadIndex,
                        &thread
                    ),
                    operation: "inspect durable thread export"
                )
                try require(
                    thread.general_state_length > 0 && thread.vector_state_length > 0,
                    "durable thread export omitted a register bank"
                )
                var general = Data(count: thread.general_state_length)
                var requiredGeneral = 0
                let generalStatus = general.withUnsafeMutableBytes { buffer in
                    continuum_remote_process_group_copy_member_thread_general_state(
                        capture.snapshot,
                        memberIndex,
                        threadIndex,
                        buffer.baseAddress,
                        buffer.count,
                        &requiredGeneral
                    )
                }
                try check(generalStatus, operation: "copy durable general registers")
                try require(requiredGeneral == general.count, "general register copy was short")

                var vector = Data(count: thread.vector_state_length)
                var requiredVector = 0
                let vectorStatus = vector.withUnsafeMutableBytes { buffer in
                    continuum_remote_process_group_copy_member_thread_vector_state(
                        capture.snapshot,
                        memberIndex,
                        threadIndex,
                        buffer.baseAddress,
                        buffer.count,
                        &requiredVector
                    )
                }
                try check(vectorStatus, operation: "copy durable vector registers")
                try require(requiredVector == vector.count, "vector register copy was short")
            }
        }
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

    private static func captureProcessGroup(
        rootProcessID: Int32
    ) throws -> RemoteProcessGroupCapture {
        var snapshot: OpaquePointer?
        var info = continuum_remote_process_group_snapshot_info()
        try check(
            continuum_remote_process_group_capture(
                rootProcessID,
                fullProcessCaptureBudget,
                &snapshot,
                &info
            ),
            operation: "capture external process group"
        )
        guard let snapshot else {
            throw ExternalHotProofFailure.invariant(
                "runtime returned a nil process-group snapshot"
            )
        }
        do {
            try require(info.process_count > 0, "group capture had no processes")
            try require(info.captured_region_count > 0, "group capture had no regions")
            try require(info.captured_bytes > 0, "group capture had no bytes")
            try require(info.thread_count > 0, "group capture had no threads")

            let count = continuum_remote_process_group_member_count(snapshot)
            try require(count == info.process_count, "group member count disagreed with info")
            var members: [RemoteProcessGroupMember] = []
            for index in 0..<count {
                var member = continuum_remote_process_group_member_info()
                try check(
                    continuum_remote_process_group_copy_member_info(
                        snapshot,
                        index,
                        &member
                    ),
                    operation: "inspect process-group member \(index)"
                )
                try require(member.captured_bytes > 0, "group member had no bytes")
                try require(member.thread_count > 0, "group member had no threads")
                members.append(RemoteProcessGroupMember(
                    snapshotIndex: index,
                    processID: member.process_id,
                    parentProcessID: member.parent_process_id,
                    capturedBytes: member.captured_bytes,
                    threadCount: member.thread_count,
                    vmLayoutHash: member.vm_layout_hash,
                    threadSetHash: member.thread_set_hash,
                    descriptorTableHash: member.descriptor_table_hash,
                    machSpaceHash: member.mach_space_hash
                ))
            }
            return RemoteProcessGroupCapture(
                snapshot: snapshot,
                info: info,
                members: members
            )
        } catch {
            continuum_remote_process_group_snapshot_destroy(snapshot)
            throw error
        }
    }

    private static func restoreProcessGroup(
        _ capture: RemoteProcessGroupCapture,
        label: String,
        cycle: Int
    ) throws {
        let started = DispatchTime.now().uptimeNanoseconds
        var report = continuum_remote_process_group_restore_report()
        try check(
            continuum_remote_process_group_restore(capture.snapshot, &report),
            operation: "restore process group \(label) on cycle \(cycle)"
        )
        try require(
            report.processes_restored == capture.info.process_count,
            "group restore \(label) missed a process"
        )
        try require(
            report.thread_states_restored == capture.info.thread_count,
            "group restore \(label) missed a thread"
        )
        try require(
            report.memory_readback_verified == 1,
            "group restore \(label) lacked readback verification"
        )
        try require(
            report.rollback_attempted == 0,
            "group restore \(label) unexpectedly needed rollback"
        )
        progress(
            "process-group restore \(label) cycle \(cycle): "
                + "\(milliseconds(since: started)) ms, "
                + "\(report.bytes_written) dirty bytes"
        )
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

    private static func processGroupLayoutDifference(
        _ left: RemoteProcessGroupCapture,
        member leftMember: RemoteProcessGroupMember,
        _ right: RemoteProcessGroupCapture,
        member rightMember: RemoteProcessGroupMember
    ) throws -> String {
        func regions(
            _ capture: RemoteProcessGroupCapture,
            member: RemoteProcessGroupMember
        ) throws -> [continuum_remote_process_region_info] {
            let count = continuum_remote_process_group_member_region_count(
                capture.snapshot,
                member.snapshotIndex
            )
            var result: [continuum_remote_process_region_info] = []
            for regionIndex in 0..<count {
                var info = continuum_remote_process_region_info()
                try check(
                    continuum_remote_process_group_copy_member_region_info(
                        capture.snapshot,
                        member.snapshotIndex,
                        regionIndex,
                        &info
                    ),
                    operation: "inspect group region \(regionIndex)"
                )
                result.append(info)
            }
            return result
        }

        let leftRegions = try regions(left, member: leftMember)
        let rightRegions = try regions(right, member: rightMember)
        let count = max(leftRegions.count, rightRegions.count)
        for index in 0..<count {
            let a = index < leftRegions.count ? leftRegions[index] : nil
            let b = index < rightRegions.count ? rightRegions[index] : nil
            guard a?.address != b?.address
                || a?.length != b?.length
                || a?.protection != b?.protection
                || a?.maximum_protection != b?.maximum_protection
                || a?.inheritance != b?.inheritance
                || canonicalShareMode(a?.share_mode) != canonicalShareMode(b?.share_mode)
                || a?.user_tag != b?.user_tag
            else { continue }
            let aText = a.map {
                "A=\($0.length)b/p\($0.protection)/m\($0.maximum_protection)"
                    + "/i\($0.inheritance)/s\($0.share_mode)/tag\($0.user_tag)"
            } ?? "A=missing"
            let bText = b.map {
                "B=\($0.length)b/p\($0.protection)/m\($0.maximum_protection)"
                    + "/i\($0.inheritance)/s\($0.share_mode)/tag\($0.user_tag)"
            } ?? "B=missing"
            let address = a?.address ?? b?.address ?? 0
            return "region \(index) at 0x\(String(address, radix: 16)) \(aText) \(bText)"
        }
        return "eligible regions match; an excluded mapping changed"
    }

    private static func canonicalShareMode(_ mode: UInt32?) -> UInt32? {
        guard let mode else { return nil }
        return mode == UInt32(SM_PRIVATE) || mode == UInt32(SM_COW) ? 1 : mode
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
        let reply = try target.send(command: "validate-root", state: expected)
        try require(reply.event == "validated", "target did not validate cycle \(cycle)")
        try require(reply.valid == true, "target rejected state \(expected) on cycle \(cycle)")
        try require(reply.state == expected, "target observed the wrong state on cycle \(cycle)")
        try require(
            reply.digest == digest,
            "target digest differed after restoring \(expected) on cycle \(cycle)"
        )
    }

    private static func validateCapturedArena(
        session: OpaquePointer,
        expectedAddress: UInt64,
        expectedLength: Int,
        digest: String,
        label: String
    ) throws {
        let captured = try capture(
            session: session,
            expectedAddress: expectedAddress,
            expectedLength: expectedLength
        )
        try require(
            captured.digest == digest,
            "\(label) arena digest differed after process-group restore"
        )
    }

    private static func validateGroup(
        target: ExternalTargetProcess,
        expected: String,
        digest: String,
        cycle: Int
    ) throws {
        let reply = try target.send(command: "validate", state: expected)
        try require(reply.event == "validated", "target did not validate group cycle \(cycle)")
        try require(reply.valid == true, "target root rejected state \(expected)")
        try require(reply.helperValid == true, "target helper rejected state \(expected)")
        try require(reply.state == expected, "target root observed the wrong group state")
        try require(reply.helperState == expected, "target helper observed the wrong group state")
        try require(reply.digest == digest, "target root digest differed after group restore")
        try require(reply.helperDigest == digest, "target helper digest differed after group restore")
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

private struct RemoteProcessGroupCapture {
    let snapshot: OpaquePointer
    let info: continuum_remote_process_group_snapshot_info
    let members: [RemoteProcessGroupMember]
}

private struct RemoteProcessGroupMember {
    let snapshotIndex: Int
    let processID: Int32
    let parentProcessID: Int32
    let capturedBytes: UInt64
    let threadCount: UInt64
    let vmLayoutHash: UInt64
    let threadSetHash: UInt64
    let descriptorTableHash: UInt64
    let machSpaceHash: UInt64
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
    let helperProcessIdentifier: Int32?
    let helperAddress: UInt64?
    let helperLength: Int?
    let helperState: String?
    let helperDigest: String?
    let helperValid: Bool?
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
