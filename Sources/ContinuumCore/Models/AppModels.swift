import Foundation

public struct AppIdentity: Codable, Hashable, Identifiable, Sendable {
    public var id: String { bundleIdentifier ?? executableURL.path }

    public let bundleIdentifier: String?
    public let displayName: String
    public let bundleURL: URL?
    public let executableURL: URL
    public let version: String?
    public let signingIdentifier: String?
    public let teamIdentifier: String?
    public let isApplePlatformBinary: Bool

    public init(
        bundleIdentifier: String?,
        displayName: String,
        bundleURL: URL?,
        executableURL: URL,
        version: String?,
        signingIdentifier: String?,
        teamIdentifier: String?,
        isApplePlatformBinary: Bool
    ) {
        self.bundleIdentifier = bundleIdentifier
        self.displayName = displayName
        self.bundleURL = bundleURL
        self.executableURL = executableURL
        self.version = version
        self.signingIdentifier = signingIdentifier
        self.teamIdentifier = teamIdentifier
        self.isApplePlatformBinary = isApplePlatformBinary
    }
}

public struct ProcessDescriptor: Codable, Hashable, Identifiable, Sendable {
    public var id: Int32 { processIdentifier }

    public let processIdentifier: Int32
    public let parentProcessIdentifier: Int32
    public let app: AppIdentity
    public let isFrontmost: Bool
    public let isTerminated: Bool

    public init(
        processIdentifier: Int32,
        parentProcessIdentifier: Int32,
        app: AppIdentity,
        isFrontmost: Bool,
        isTerminated: Bool
    ) {
        self.processIdentifier = processIdentifier
        self.parentProcessIdentifier = parentProcessIdentifier
        self.app = app
        self.isFrontmost = isFrontmost
        self.isTerminated = isTerminated
    }
}

public enum CaptureScope: String, Codable, CaseIterable, Sendable {
    case frontmostApp
    case selectedApps
    case allArmedApps
}

public struct CaptureSession: Codable, Hashable, Identifiable, Sendable {
    public let id: CaptureSessionID
    public var scope: CaptureScope
    public var appIDs: Set<String>
    public var activeBranchID: BranchID
    public var startedAt: Date
    public var diskBudgetBytes: Int64
    public var hotMemoryBudgetBytes: Int64

    public init(
        id: CaptureSessionID = UUID(),
        scope: CaptureScope,
        appIDs: Set<String>,
        activeBranchID: BranchID,
        startedAt: Date = .now,
        diskBudgetBytes: Int64 = ContinuumConstants.defaultDiskBudgetBytes,
        hotMemoryBudgetBytes: Int64 = ContinuumConstants.defaultHotMemoryBudgetBytes
    ) {
        self.id = id
        self.scope = scope
        self.appIDs = appIDs
        self.activeBranchID = activeBranchID
        self.startedAt = startedAt
        self.diskBudgetBytes = diskBudgetBytes
        self.hotMemoryBudgetBytes = hotMemoryBudgetBytes
    }
}
