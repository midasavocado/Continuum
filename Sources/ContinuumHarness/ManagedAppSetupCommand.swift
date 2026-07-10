import ContinuumCore
import ContinuumSystem
import Foundation

enum ManagedAppSetupCommand {
    static func run(
        targetPath: String,
        rootPath: String?,
        checkOnly: Bool
    ) async throws {
        let targetURL = URL(
            fileURLWithPath: NSString(string: targetPath).expandingTildeInPath
        ).standardizedFileURL
        let inventory = MacAppInventoryService(applicationDirectories: [])
        guard let app = await inventory.application(at: targetURL) else {
            throw ManagedAppSetupFailure(
                "No runnable .app bundle or executable was found at \(targetURL.path)."
            )
        }

        let rootURL = rootPath.map {
            URL(fileURLWithPath: NSString(string: $0).expandingTildeInPath)
                .standardizedFileURL
        }
        let coordinator = MacAppSetupCoordinator(rootDirectory: rootURL)
        try await coordinator.recoverInterruptedSetups()

        let record = if checkOnly {
            try await coordinator.probe(app)
        } else {
            try await coordinator.setup(app)
        }

        print("generic-managed-setup: \(stateTitle(record.state))")
        print("  target:                \(record.app.displayName)")
        print("  source:                \(record.sourceURL.path)")
        if let managedBundleURL = record.managedBundleURL {
            print("  managed copy:          \(managedBundleURL.path)")
        }
        if let validation = record.validation {
            print("  source unchanged:      \(yesNo(validation.sourceUnchanged))")
            print("  original verified:     \(yesNo(validation.originalCloneVerified))")
            print("  managed signature:     \(yesNo(validation.managedSignatureValid))")
            print("  attach entitlement:    \(yesNo(validation.managedAttachEntitlementValid))")
            print("  restore certified:     \(yesNo(validation.restoreCertificationPassed))")
            print("  detail:                \(validation.detail)")
        }

        switch record.state {
        case .discovered:
            if checkOnly {
                print("  next:                  rerun without --check-only to prepare it")
            }
        case .prepared:
            print("  result:                managed target prepared for runtime certification")
        case let .blocked(blockers):
            for blocker in blockers {
                print("  blocked:               \(blocker.summary)")
            }
            throw ManagedAppSetupFailure(
                "This target cannot use the current generic managed-copy route."
            )
        case let .failed(detail):
            throw ManagedAppSetupFailure(detail)
        case .stale:
            throw ManagedAppSetupFailure("The source changed; run setup again for the current build.")
        case .preparing:
            throw ManagedAppSetupFailure("Setup is still in progress.")
        case .rolledBack:
            throw ManagedAppSetupFailure("This target's managed setup was removed.")
        }
    }

    private static func stateTitle(_ state: AppSetupState) -> String {
        switch state {
        case .discovered: "ELIGIBLE"
        case .preparing: "IN PROGRESS"
        case .prepared: "PREPARED"
        case .stale: "STALE"
        case .blocked: "BLOCKED"
        case .rolledBack: "REMOVED"
        case .failed: "FAILED"
        }
    }

    private static func yesNo(_ value: Bool) -> String {
        value ? "yes" : "no"
    }
}

private struct ManagedAppSetupFailure: LocalizedError {
    let message: String

    init(_ message: String) {
        self.message = message
    }

    var errorDescription: String? { message }
}
