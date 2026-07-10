import Foundation

public enum CompatibilityTier: String, Codable, CaseIterable, Sendable {
    case directPlugin
    case launchInjection
    case managedInstrumentation
    case protectedBridge
    case unsupported

    public var displayName: String {
        switch self {
        case .directPlugin: "Direct"
        case .launchInjection: "Launch injection"
        case .managedInstrumentation: "Managed instrumentation"
        case .protectedBridge: "Protected bridge"
        case .unsupported: "Not rewindable"
        }
    }
}

public struct CompatibilityReport: Codable, Hashable, Identifiable, Sendable {
    public var id: String { app.id }

    public let app: AppIdentity
    public let tier: CompatibilityTier
    public let canCaptureNow: Bool
    public let canRestoreNow: Bool
    public let explanation: String
    public let inspectedAt: Date

    public init(
        app: AppIdentity,
        tier: CompatibilityTier,
        canCaptureNow: Bool,
        canRestoreNow: Bool,
        explanation: String,
        inspectedAt: Date = .now
    ) {
        self.app = app
        self.tier = tier
        self.canCaptureNow = canCaptureNow
        self.canRestoreNow = canRestoreNow
        self.explanation = explanation
        self.inspectedAt = inspectedAt
    }
}

public enum PermissionKind: String, Codable, CaseIterable, Identifiable, Sendable {
    case accessibility
    case screenRecording
    case automation
    case fullDiskAccess

    public var id: String { rawValue }
}

public enum PermissionState: String, Codable, Sendable {
    case granted
    case denied
    case notRequested
    case requiresSystemSettings
    case unknown
}

public struct PermissionStatus: Codable, Hashable, Identifiable, Sendable {
    public var id: PermissionKind { kind }
    public let kind: PermissionKind
    public var state: PermissionState
    public var detail: String

    public init(kind: PermissionKind, state: PermissionState, detail: String) {
        self.kind = kind
        self.state = state
        self.detail = detail
    }
}
