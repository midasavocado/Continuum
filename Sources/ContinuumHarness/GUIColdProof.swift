import ContinuumCore
import ContinuumRuntime
import ContinuumStore
import ContinuumSystem
import CoreGraphics
import Darwin
import Foundation

enum GUIColdProof {
    private static let captureBudget: UInt64 = 2 * 1_024 * 1_024 * 1_024

    static func run(targetPath: String) async throws {
        guard FileManager.default.isExecutableFile(atPath: targetPath) else {
            throw HarnessFailure.usage("GUI proof target is not executable: \(targetPath)")
        }
        guard let bootstrapPath = ProcessInfo.processInfo.environment[
            "CONTINUUM_BOOTSTRAP_LIBRARY_PATH"
        ], FileManager.default.fileExists(atPath: bootstrapPath) else {
            throw HarnessFailure.usage(
                "CONTINUUM_BOOTSTRAP_LIBRARY_PATH must name the built bootstrap dylib"
            )
        }

        let proofRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("continuum-gui-cold-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: proofRoot,
            withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: proofRoot) }
        let observationURL = proofRoot.appendingPathComponent("observations.log")

        let original = Process()
        original.executableURL = URL(fileURLWithPath: targetPath)
        original.currentDirectoryURL = proofRoot
        original.standardOutput = FileHandle.nullDevice
        original.standardError = FileHandle.standardError
        var environment = ProcessInfo.processInfo.environment
        environment["DYLD_SHARED_REGION"] = "private"
        environment["CONTINUUM_DETERMINISTIC_ADDRESS_SPACE"] = "1"
        environment["CONTINUUM_ENABLE_CHECKPOINT_SAFEPOINTS"] = "1"
        environment["MallocLargeCache"] = "0"
        environment["DYLD_INSERT_LIBRARIES"] = bootstrapPath
        environment["CONTINUUM_GUI_PROOF_OBSERVATION_PATH"] = observationURL.path
        original.environment = environment
        try original.run()
        let originalPID = original.processIdentifier
        var originalReaped = false
        defer {
            if !originalReaped {
                kill(originalPID, SIGKILL)
                original.waitUntilExit()
            }
        }

        let ready = try await waitForObservation(
            event: "ready",
            processIdentifier: originalPID,
            at: observationURL
        )
        let lateReady = try await waitForObservation(
            event: "late-ready",
            processIdentifier: originalPID,
            counter: 500,
            at: observationURL
        )
        try await waitForWindow(
            processIdentifier: originalPID,
            titleSuffix: "111 / 500"
        )

        guard kill(originalPID, SIGWINCH) == 0 else {
            throw GUIColdProofError.failure("could not prime the GUI proof state")
        }
        let saved = try await waitForObservation(
            event: "mutated",
            processIdentifier: originalPID,
            counter: 222,
            at: observationURL
        )
        let lateSaved = try await waitForObservation(
            event: "late-mutated",
            processIdentifier: originalPID,
            counter: 510,
            at: observationURL
        )
        try await waitForWindow(
            processIdentifier: originalPID,
            titleSuffix: "222 / 510"
        )

        let service = HotProcessCheckpointService(
            maximumCapturedBytes: captureBudget,
            maximumRetainedSnapshots: 2,
            usesInjectedSafepoints: true,
            bootstrapLibraryURL: URL(fileURLWithPath: bootstrapPath)
        )
        let app = AppIdentity(
            bundleIdentifier: nil,
            displayName: "Continuum GUI Proof",
            bundleURL: nil,
            executableURL: URL(fileURLWithPath: targetPath),
            version: "proof",
            signingIdentifier: nil,
            teamIdentifier: nil,
            isApplePlatformBinary: false
        )
        let capture = try await service.capture(
            app: app,
            processIdentifiers: [originalPID],
            kind: .manual,
            branchID: UUID()
        )
        let store = try EncryptedSnapshotStore(
            rootURL: proofRoot.appendingPathComponent("store"),
            encryptionKey: Data(repeating: 0x47, count: 32)
        )
        let snapshot = try await store.save(capture)

        guard kill(originalPID, SIGWINCH) == 0 else {
            throw GUIColdProofError.failure("could not mutate the live GUI target")
        }
        _ = try await waitForObservation(
            event: "mutated",
            processIdentifier: originalPID,
            counter: 333,
            at: observationURL
        )
        _ = try await waitForObservation(
            event: "late-mutated",
            processIdentifier: originalPID,
            counter: 520,
            at: observationURL
        )
        try await waitForWindow(
            processIdentifier: originalPID,
            titleSuffix: "333 / 520"
        )

        // Build and validate the stopped replacement before destroying the
        // live app. The consumer restore path uses this ordering so a corrupt
        // checkpoint cannot close the user's current process first.
        let restorer = ColdProcessRestorer(
            bootstrapLibraryURL: URL(fileURLWithPath: bootstrapPath)
        )
        let preparation = try await restorer.prepareRootProcess(
            from: snapshot.id,
            repository: store
        )
        guard preparation.replacementProcessIdentifier != originalPID,
              processExists(originalPID) else {
            throw GUIColdProofError.failure(
                "preflight did not preserve the original GUI process"
            )
        }

        kill(originalPID, SIGKILL)
        original.waitUntilExit()
        originalReaped = true
        guard !processExists(originalPID) else {
            throw GUIColdProofError.failure("the original GUI process did not exit")
        }
        try await waitForWindowAbsence(processIdentifier: originalPID)

        let commit = try await restorer.commit(preparation.id)
        let replacementPID = commit.processIdentifier
        var replacementReaped = false
        defer {
            if !replacementReaped {
                kill(replacementPID, SIGKILL)
                var status: Int32 = 0
                waitpid(replacementPID, &status, 0)
            }
        }
        guard replacementPID != originalPID, processExists(replacementPID) else {
            throw GUIColdProofError.failure(
                "cold restore did not create a live replacement PID"
            )
        }
        let replacementLateReady = try await waitForObservation(
            event: "late-ready",
            processIdentifier: replacementPID,
            counter: 500,
            at: observationURL
        )
        try await waitForWindow(
            processIdentifier: replacementPID,
            titleSuffix: "222 / 510"
        )

        guard kill(replacementPID, SIGWINCH) == 0 else {
            throw GUIColdProofError.failure(
                "the restored GUI process did not accept input"
            )
        }
        let mutated = try await waitForObservation(
            event: "mutated",
            processIdentifier: replacementPID,
            counter: 333,
            at: observationURL
        )
        let lateMutated = try await waitForObservation(
            event: "late-mutated",
            processIdentifier: replacementPID,
            counter: 520,
            at: observationURL
        )
        try await waitForWindow(
            processIdentifier: replacementPID,
            titleSuffix: "333 / 520"
        )
        guard ready.address == saved.address,
              saved.address == mutated.address,
              lateReady.address == lateSaved.address,
              lateSaved.address == replacementLateReady.address,
              replacementLateReady.address == lateMutated.address,
              ready.counter == 111,
              saved.counter == 222,
              mutated.counter == 333,
              lateReady.counter == 500,
              lateSaved.counter == 510,
              lateMutated.counter == 520,
              commit.retainedFileCount == 0,
              commit.retainedFileBytes == 0 else {
            throw GUIColdProofError.failure(
                "replacement state or process-only file policy did not validate"
            )
        }

        kill(replacementPID, SIGKILL)
        var replacementStatus: Int32 = 0
        waitpid(replacementPID, &replacementStatus, 0)
        replacementReaped = true
        print("gui-cold-proof: PASS")
        print("  original PID:    \(originalPID) (exited)")
        print("  replacement PID: \(replacementPID)")
        print("  preflight:       replacement validated before original exit")
        print("  restored RAM:    0x\(String(saved.address, radix: 16)) = 222")
        print("  late-run-loop RAM: 0x\(String(lateSaved.address, radix: 16)) = 510")
        print("  divergent future: 333 discarded with the original PID")
        print("  live mutation:   333 after restore")
        print("  WindowServer:    new functional window owned by replacement")
        print("  local files:     unchanged by restore")
    }

    private struct Observation {
        let event: String
        let processIdentifier: Int32
        let address: UInt64
        let counter: UInt64
    }

    private static func observations(at url: URL) -> [Observation] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else {
            return []
        }
        return text.split(separator: "\n").compactMap { line in
            let fields = line.split(separator: " ")
            guard fields.count == 4,
                  let processIdentifier = Int32(fields[1]),
                  let address = UInt64(fields[2]),
                  let counter = UInt64(fields[3]) else { return nil }
            return Observation(
                event: String(fields[0]),
                processIdentifier: processIdentifier,
                address: address,
                counter: counter
            )
        }
    }

    private static func waitForObservation(
        event: String,
        processIdentifier: Int32,
        counter: UInt64? = nil,
        at url: URL
    ) async throws -> Observation {
        for _ in 0..<100 {
            if let observation = observations(at: url).last(where: {
                $0.event == event
                    && $0.processIdentifier == processIdentifier
                    && (counter == nil || $0.counter == counter)
            }) {
                return observation
            }
            if !processExists(processIdentifier) {
                throw GUIColdProofError.failure(
                    "GUI process \(processIdentifier) exited before \(event)"
                )
            }
            try await Task.sleep(for: .milliseconds(50))
        }
        throw GUIColdProofError.failure(
            "GUI process \(processIdentifier) did not report \(event)"
        )
    }

    private static func windowTitles(processIdentifier: Int32) -> [String] {
        let options: CGWindowListOption = [.optionOnScreenOnly, .excludeDesktopElements]
        guard let windows = CGWindowListCopyWindowInfo(options, kCGNullWindowID)
                as? [[String: Any]] else { return [] }
        return windows.compactMap { window in
            guard (window[kCGWindowOwnerPID as String] as? NSNumber)?.int32Value
                    == processIdentifier,
                  (window[kCGWindowLayer as String] as? NSNumber)?.intValue == 0 else {
                return nil
            }
            return window[kCGWindowName as String] as? String
        }
    }

    private static func waitForWindow(
        processIdentifier: Int32,
        titleSuffix: String
    ) async throws {
        for _ in 0..<100 {
            if windowTitles(processIdentifier: processIdentifier).contains(where: {
                $0.hasSuffix(titleSuffix)
            }) { return }
            if !processExists(processIdentifier) {
                throw GUIColdProofError.failure(
                    "GUI process \(processIdentifier) exited before drawing its window"
                )
            }
            try await Task.sleep(for: .milliseconds(50))
        }
        throw GUIColdProofError.failure(
            "WindowServer did not show \(titleSuffix) for PID \(processIdentifier)"
        )
    }

    private static func waitForWindowAbsence(
        processIdentifier: Int32
    ) async throws {
        for _ in 0..<100 {
            if windowTitles(processIdentifier: processIdentifier).isEmpty {
                return
            }
            try await Task.sleep(for: .milliseconds(50))
        }
        throw GUIColdProofError.failure(
            "the original WindowServer record survived process exit"
        )
    }

    private static func processExists(_ processIdentifier: Int32) -> Bool {
        kill(processIdentifier, 0) == 0 || errno == EPERM
    }

}

private enum GUIColdProofError: LocalizedError {
    case failure(String)

    var errorDescription: String? {
        switch self {
        case let .failure(message): message
        }
    }
}
