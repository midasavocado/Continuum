import Foundation

public typealias AppSetupID = UUID

public enum AppSetupRoute: String, Codable, Sendable {
    case managedCopy
}

public enum AppSetupStage: String, Codable, Sendable {
    case probing
    case creatingWorkspace
    case cloningOriginal
    case cloningManaged
    case instrumenting
    case signing
    case validating
    case rollingBack
}

public enum AppSetupBlocker: Codable, Hashable, Sendable {
    case applePlatformBinary
    case sandboxIdentityBound
    case appStoreReceiptOrDRM
    case signedIdentityBound
    case restrictedEntitlements([String])
    case nestedCodeUnsupported
    case invalidBundle(String)
}

public enum AppSetupState: Codable, Hashable, Sendable {
    case discovered
    case preparing(AppSetupStage)
    case prepared
    case stale
    case blocked([AppSetupBlocker])
    case rolledBack
    case failed(String)
}

public enum AppSetupCopyMethod: String, Codable, Sendable {
    case apfsClone
    case fileCopy
}

public struct AppFingerprint: Codable, Hashable, Sendable {
    public let bundleIdentifier: String?
    public let bundleVersion: String?
    public let executableSHA256: String
    public let infoPlistSHA256: String
    public let bundleContentSHA256: String
    public let signingIdentifier: String?
    public let teamIdentifier: String?
    public let isAdHocSigned: Bool

    public init(
        bundleIdentifier: String?,
        bundleVersion: String?,
        executableSHA256: String,
        infoPlistSHA256: String,
        bundleContentSHA256: String,
        signingIdentifier: String?,
        teamIdentifier: String?,
        isAdHocSigned: Bool
    ) {
        self.bundleIdentifier = bundleIdentifier
        self.bundleVersion = bundleVersion
        self.executableSHA256 = executableSHA256
        self.infoPlistSHA256 = infoPlistSHA256
        self.bundleContentSHA256 = bundleContentSHA256
        self.signingIdentifier = signingIdentifier
        self.teamIdentifier = teamIdentifier
        self.isAdHocSigned = isAdHocSigned
    }
}

public struct AppSetupValidation: Codable, Hashable, Sendable {
    public let sourceUnchanged: Bool
    public let originalCloneVerified: Bool
    public let instrumentationMarkerValid: Bool
    public let managedSignatureValid: Bool
    public let managedAttachEntitlementValid: Bool
    public let restoreCertificationPassed: Bool
    public let checkedAt: Date
    public let detail: String

    public init(
        sourceUnchanged: Bool,
        originalCloneVerified: Bool,
        instrumentationMarkerValid: Bool,
        managedSignatureValid: Bool,
        managedAttachEntitlementValid: Bool,
        restoreCertificationPassed: Bool,
        checkedAt: Date,
        detail: String
    ) {
        self.sourceUnchanged = sourceUnchanged
        self.originalCloneVerified = originalCloneVerified
        self.instrumentationMarkerValid = instrumentationMarkerValid
        self.managedSignatureValid = managedSignatureValid
        self.managedAttachEntitlementValid = managedAttachEntitlementValid
        self.restoreCertificationPassed = restoreCertificationPassed
        self.checkedAt = checkedAt
        self.detail = detail
    }
}

public enum AppSetupError: Error, LocalizedError, Sendable {
    case recordNotFound(AppSetupID)
    case blocked([AppSetupBlocker])
    case invalidBundle(String)
    case validationFailed(String)
    case operationFailed(String)

    public var errorDescription: String? {
        switch self {
        case .recordNotFound(let id):
            "No app setup record exists for \(id.uuidString)."
        case .blocked(let blockers):
            "This app cannot use the managed-copy setup: \(blockers.map(\.summary).joined(separator: "; "))."
        case .invalidBundle(let detail):
            "The app bundle is invalid: \(detail)"
        case .validationFailed(let detail):
            "Managed-copy validation failed: \(detail)"
        case .operationFailed(let detail):
            "App setup failed: \(detail)"
        }
    }
}

public extension AppSetupBlocker {
    var summary: String {
        switch self {
        case .applePlatformBinary:
            "Apple platform binaries are protected"
        case .sandboxIdentityBound:
            "the app sandbox binds this bundle to its signing identity"
        case .appStoreReceiptOrDRM:
            "an App Store receipt or encrypted executable was detected"
        case .signedIdentityBound:
            "the vendor signing identity must remain intact"
        case .restrictedEntitlements(let entitlements):
            "restricted entitlements: \(entitlements.joined(separator: ", "))"
        case .nestedCodeUnsupported:
            "nested code is not safely supported by this setup provider"
        case .invalidBundle(let detail):
            detail
        }
    }
}

public struct AppSetupRecord: Codable, Hashable, Identifiable, Sendable {
    public let id: AppSetupID
    public var app: AppIdentity
    public let sourceURL: URL
    public var sourceFingerprint: AppFingerprint?
    public let route: AppSetupRoute
    public var state: AppSetupState
    public var originalCloneURL: URL?
    public var managedBundleURL: URL?
    public var originalCopyMethod: AppSetupCopyMethod?
    public var managedCopyMethod: AppSetupCopyMethod?
    public var managedFingerprint: AppFingerprint?
    public var validation: AppSetupValidation?
    public let createdAt: Date
    public var updatedAt: Date

    public init(
        id: AppSetupID = UUID(),
        app: AppIdentity,
        sourceURL: URL,
        sourceFingerprint: AppFingerprint?,
        route: AppSetupRoute = .managedCopy,
        state: AppSetupState,
        originalCloneURL: URL? = nil,
        managedBundleURL: URL? = nil,
        originalCopyMethod: AppSetupCopyMethod? = nil,
        managedCopyMethod: AppSetupCopyMethod? = nil,
        managedFingerprint: AppFingerprint? = nil,
        validation: AppSetupValidation? = nil,
        createdAt: Date = .now,
        updatedAt: Date = .now
    ) {
        self.id = id
        self.app = app
        self.sourceURL = sourceURL
        self.sourceFingerprint = sourceFingerprint
        self.route = route
        self.state = state
        self.originalCloneURL = originalCloneURL
        self.managedBundleURL = managedBundleURL
        self.originalCopyMethod = originalCopyMethod
        self.managedCopyMethod = managedCopyMethod
        self.managedFingerprint = managedFingerprint
        self.validation = validation
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}
