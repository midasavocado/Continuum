import Foundation
import ContinuumCore

struct AppSetupProbeResult: Sendable {
    let identity: AppIdentity
    let fingerprint: AppFingerprint
    let blockers: [AppSetupBlocker]
    let isSigned: Bool
    let isAdHocSigned: Bool
    let signatureValid: Bool
    let hasAttachEntitlement: Bool
}

protocol AppSetupProbing: Sendable {
    func inspect(bundleURL: URL, declaredIdentity: AppIdentity?) throws -> AppSetupProbeResult
}

protocol AppSetupFileSystem: Sendable {
    func itemExists(at url: URL) -> Bool
    func createDirectory(at url: URL) throws
    func removeItemIfPresent(at url: URL) throws
    func cloneOrCopyItem(at sourceURL: URL, to destinationURL: URL) throws -> AppSetupCopyMethod
    func exchangeItems(at firstURL: URL, and secondURL: URL) throws
    func readData(at url: URL) throws -> Data
    func writeDataAtomically(_ data: Data, to url: URL) throws
}

protocol AppSetupRootProviding: Sendable {
    var rootDirectory: URL { get }
}

protocol ManagedBundleSigning: Sendable {
    func sign(bundleURL: URL, entitlementsURL: URL) throws
}

struct AppSetupCommandResult: Sendable {
    let terminationStatus: Int32
    let standardOutput: Data
    let standardError: Data
}

protocol AppSetupCommandRunning: Sendable {
    func run(executableURL: URL, arguments: [String]) throws -> AppSetupCommandResult
}

struct FixedAppSetupRoot: AppSetupRootProviding {
    let rootDirectory: URL
}
