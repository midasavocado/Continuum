import Foundation
import Security
import ContinuumCore

struct CodeSignatureMetadata: Sendable {
    let signingIdentifier: String?
    let teamIdentifier: String?
    let isApplePlatformBinary: Bool
    let isSigned: Bool
    let isAdHocSigned: Bool
    let usesHardenedRuntime: Bool
    let enforcesLibraryValidation: Bool
    let disablesLibraryValidation: Bool
    let isSandboxed: Bool

    static let unsigned = CodeSignatureMetadata(
        signingIdentifier: nil,
        teamIdentifier: nil,
        isApplePlatformBinary: false,
        isSigned: false,
        isAdHocSigned: false,
        usesHardenedRuntime: false,
        enforcesLibraryValidation: false,
        disablesLibraryValidation: false,
        isSandboxed: false
    )
}

struct InspectedAppBundle: Sendable {
    let identity: AppIdentity
    let signature: CodeSignatureMetadata
}

struct AppBundleInspector: Sendable {
    func inspect(bundleURL: URL) -> InspectedAppBundle? {
        let standardizedBundleURL = bundleURL.standardizedFileURL
        guard standardizedBundleURL.pathExtension.lowercased() == "app" else {
            return nil
        }

        let plistURL = standardizedBundleURL
            .appendingPathComponent("Contents", isDirectory: true)
            .appendingPathComponent("Info.plist", isDirectory: false)

        guard
            let data = try? Data(contentsOf: plistURL, options: [.mappedIfSafe]),
            let rawPlist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
            let plist = rawPlist as? [String: Any],
            let executableName = nonemptyString(plist["CFBundleExecutable"])
        else {
            return nil
        }

        let executableURL = standardizedBundleURL
            .appendingPathComponent("Contents", isDirectory: true)
            .appendingPathComponent("MacOS", isDirectory: true)
            .appendingPathComponent(executableName, isDirectory: false)
        let signature = signatureMetadata(for: standardizedBundleURL)
        let displayName = nonemptyString(plist["CFBundleDisplayName"])
            ?? nonemptyString(plist["CFBundleName"])
            ?? standardizedBundleURL.deletingPathExtension().lastPathComponent
        let version = nonemptyString(plist["CFBundleShortVersionString"])
            ?? nonemptyString(plist["CFBundleVersion"])

        let identity = AppIdentity(
            bundleIdentifier: nonemptyString(plist["CFBundleIdentifier"]),
            displayName: displayName,
            bundleURL: standardizedBundleURL,
            executableURL: executableURL,
            version: version,
            signingIdentifier: signature.signingIdentifier,
            teamIdentifier: signature.teamIdentifier,
            isApplePlatformBinary: signature.isApplePlatformBinary
                || standardizedBundleURL.path.hasPrefix("/System/Applications/")
        )

        return InspectedAppBundle(identity: identity, signature: signature)
    }

    func signatureMetadata(for codeURL: URL) -> CodeSignatureMetadata {
        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(
            codeURL.standardizedFileURL as CFURL,
            SecCSFlags(),
            &staticCode
        )
        guard createStatus == errSecSuccess, let staticCode else {
            return .unsigned
        }

        var rawInformation: CFDictionary?
        let informationFlags = SecCSFlags(rawValue: kSecCSSigningInformation)
        let informationStatus = SecCodeCopySigningInformation(
            staticCode,
            informationFlags,
            &rawInformation
        )
        guard
            informationStatus == errSecSuccess,
            let information = rawInformation as? [CFString: Any]
        else {
            return .unsigned
        }

        let signatureFlags = (information[kSecCodeInfoFlags] as? NSNumber)?.uint32Value ?? 0
        let entitlements = information[kSecCodeInfoEntitlementsDict] as? [String: Any] ?? [:]
        let signingIdentifier = information[kSecCodeInfoIdentifier] as? String
        let isAdHoc = signatureFlags & CodeSignatureFlag.adHoc != 0

        return CodeSignatureMetadata(
            signingIdentifier: signingIdentifier,
            teamIdentifier: information[kSecCodeInfoTeamIdentifier] as? String,
            isApplePlatformBinary: information[kSecCodeInfoPlatformIdentifier] != nil,
            isSigned: signingIdentifier != nil || isAdHoc,
            isAdHocSigned: isAdHoc,
            usesHardenedRuntime: signatureFlags & CodeSignatureFlag.hardenedRuntime != 0,
            enforcesLibraryValidation: signatureFlags & CodeSignatureFlag.libraryValidation != 0,
            disablesLibraryValidation: entitlements["com.apple.security.cs.disable-library-validation"] as? Bool == true,
            isSandboxed: entitlements["com.apple.security.app-sandbox"] as? Bool == true
        )
    }

    /// Security.framework does not import `SecCodeSignatureFlags` cases into Swift.
    /// These values are the public constants declared in Security/CSCommon.h.
    private enum CodeSignatureFlag {
        static let adHoc: UInt32 = 0x0002
        static let libraryValidation: UInt32 = 0x2000
        static let hardenedRuntime: UInt32 = 0x10000
    }

    private func nonemptyString(_ value: Any?) -> String? {
        guard let string = value as? String else { return nil }
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
