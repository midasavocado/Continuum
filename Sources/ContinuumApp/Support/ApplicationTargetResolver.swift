import ContinuumCore
import ContinuumSystem
import Foundation

protocol ApplicationTargetResolving: Sendable {
    func application(at url: URL) async -> AppIdentity?
}

// Keep URL-to-target resolution out of ContinuumCore's inventory contract.
// The app uses this richer macOS surface only for an explicit Add Target action.
extension MacAppInventoryService: ApplicationTargetResolving {}
