import CryptoKit
import Foundation
import Security
import ContinuumCore

struct MacAppSetupProbe: AppSetupProbing {
    private var fileManager: FileManager { .default }

    func inspect(bundleURL: URL, declaredIdentity: AppIdentity?) throws -> AppSetupProbeResult {
        let bundleURL = bundleURL.standardizedFileURL
        guard bundleURL.pathExtension.lowercased() == "app" else {
            throw AppSetupError.invalidBundle("\(bundleURL.lastPathComponent) is not a .app bundle.")
        }

        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: bundleURL.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw AppSetupError.invalidBundle("The bundle does not exist or is not a directory.")
        }

        let contentsURL = bundleURL.appendingPathComponent("Contents", isDirectory: true)
        let infoPlistURL = contentsURL.appendingPathComponent("Info.plist", isDirectory: false)
        let plistData: Data
        let plist: [String: Any]
        do {
            plistData = try Data(contentsOf: infoPlistURL, options: [.mappedIfSafe])
            let rawPlist = try PropertyListSerialization.propertyList(from: plistData, options: [], format: nil)
            guard let dictionary = rawPlist as? [String: Any] else {
                throw AppSetupError.invalidBundle("Info.plist is not a dictionary.")
            }
            plist = dictionary
        } catch let error as AppSetupError {
            throw error
        } catch {
            throw AppSetupError.invalidBundle("Info.plist could not be read: \(error.localizedDescription)")
        }

        guard let executableName = nonemptyString(plist["CFBundleExecutable"]) else {
            throw AppSetupError.invalidBundle("Info.plist does not declare CFBundleExecutable.")
        }
        let executableURL = contentsURL
            .appendingPathComponent("MacOS", isDirectory: true)
            .appendingPathComponent(executableName, isDirectory: false)
        guard fileManager.isExecutableFile(atPath: executableURL.path) else {
            throw AppSetupError.invalidBundle("The declared main executable is missing or not executable.")
        }

        let signature = signatureFacts(for: bundleURL)
        let identity = AppIdentity(
            bundleIdentifier: nonemptyString(plist["CFBundleIdentifier"]),
            displayName: nonemptyString(plist["CFBundleDisplayName"])
                ?? nonemptyString(plist["CFBundleName"])
                ?? bundleURL.deletingPathExtension().lastPathComponent,
            bundleURL: bundleURL,
            executableURL: executableURL,
            version: nonemptyString(plist["CFBundleShortVersionString"])
                ?? nonemptyString(plist["CFBundleVersion"]),
            signingIdentifier: signature.signingIdentifier,
            teamIdentifier: signature.teamIdentifier,
            isApplePlatformBinary: declaredIdentity?.isApplePlatformBinary == true
                || signature.isApplePlatformBinary
                || bundleURL.path.hasPrefix("/System/Applications/")
        )

        var blockers: [AppSetupBlocker] = []
        if identity.isApplePlatformBinary {
            blockers.append(.applePlatformBinary)
        }
        if signature.isSandboxed {
            blockers.append(.sandboxIdentityBound)
        }
        if hasAppStoreReceipt(bundleURL: bundleURL)
            || MachOEncryptionDetector.isEncrypted(executableURL: executableURL) {
            blockers.append(.appStoreReceiptOrDRM)
        }
        if signature.isAdHocSigned && !signature.signatureValid {
            blockers.append(.invalidBundle("The existing ad-hoc signature is invalid."))
        }
        let restrictedEntitlements = signature.entitlements.keys
            .filter { !Self.transferableEntitlements.contains($0) && $0 != "com.apple.security.app-sandbox" }
            .sorted()
        if !restrictedEntitlements.isEmpty {
            blockers.append(.restrictedEntitlements(restrictedEntitlements))
        }
        if containsUnsupportedNestedCode(bundleURL: bundleURL) {
            blockers.append(.nestedCodeUnsupported)
        }

        return AppSetupProbeResult(
            identity: identity,
            fingerprint: try fingerprint(
                bundleURL: bundleURL,
                executableURL: executableURL,
                infoPlistURL: infoPlistURL,
                plist: plist,
                signature: signature
            ),
            blockers: blockers,
            isSigned: signature.isSigned,
            isAdHocSigned: signature.isAdHocSigned,
            signatureValid: signature.signatureValid,
            hasAttachEntitlement: signature.entitlements["com.apple.security.get-task-allow"] as? Bool == true
        )
    }

    private func fingerprint(
        bundleURL: URL,
        executableURL: URL,
        infoPlistURL: URL,
        plist: [String: Any],
        signature: SignatureFacts
    ) throws -> AppFingerprint {
        AppFingerprint(
            bundleIdentifier: nonemptyString(plist["CFBundleIdentifier"]),
            bundleVersion: nonemptyString(plist["CFBundleShortVersionString"])
                ?? nonemptyString(plist["CFBundleVersion"]),
            executableSHA256: try hashFile(at: executableURL),
            infoPlistSHA256: try hashFile(at: infoPlistURL),
            bundleContentSHA256: try hashDirectory(at: bundleURL),
            signingIdentifier: signature.signingIdentifier,
            teamIdentifier: signature.teamIdentifier,
            isAdHocSigned: signature.isAdHocSigned
        )
    }

    private func signatureFacts(for bundleURL: URL) -> SignatureFacts {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(bundleURL as CFURL, SecCSFlags(), &staticCode) == errSecSuccess,
              let staticCode else {
            return .unsigned
        }

        var rawInformation: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &rawInformation
        ) == errSecSuccess,
              let information = rawInformation as? [CFString: Any] else {
            return .unsigned
        }

        let flags = (information[kSecCodeInfoFlags] as? NSNumber)?.uint32Value ?? 0
        let entitlements = information[kSecCodeInfoEntitlementsDict] as? [String: Any] ?? [:]
        let validityFlags = SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures)
        let validity = SecStaticCodeCheckValidity(staticCode, validityFlags, nil) == errSecSuccess
        let signingIdentifier = information[kSecCodeInfoIdentifier] as? String
        let isAdHocSigned = flags & SignatureFlag.adHoc != 0

        return SignatureFacts(
            signingIdentifier: signingIdentifier,
            teamIdentifier: information[kSecCodeInfoTeamIdentifier] as? String,
            isApplePlatformBinary: information[kSecCodeInfoPlatformIdentifier] != nil,
            isSigned: signingIdentifier != nil || isAdHocSigned,
            isAdHocSigned: isAdHocSigned,
            signatureValid: validity,
            isSandboxed: entitlements["com.apple.security.app-sandbox"] as? Bool == true,
            entitlements: entitlements
        )
    }

    private func hasAppStoreReceipt(bundleURL: URL) -> Bool {
        fileManager.fileExists(
            atPath: bundleURL
                .appendingPathComponent("Contents", isDirectory: true)
                .appendingPathComponent("_MASReceipt", isDirectory: true)
                .appendingPathComponent("receipt", isDirectory: false)
                .path
        )
    }

    private func containsUnsupportedNestedCode(bundleURL: URL) -> Bool {
        guard let enumerator = fileManager.enumerator(
            at: bundleURL,
            includingPropertiesForKeys: [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey],
            options: [.skipsHiddenFiles]
        ) else {
            return true
        }

        let nestedBundleExtensions: Set<String> = ["app", "appex", "xpc", "framework", "plugin", "bundle"]
        while let itemURL = enumerator.nextObject() as? URL {
            let relativePath = relativePath(of: itemURL, below: bundleURL)
            let pathExtension = itemURL.pathExtension.lowercased()
            if nestedBundleExtensions.contains(pathExtension) || pathExtension == "dylib" {
                return true
            }

            let codeDirectories = ["Contents/Frameworks/", "Contents/XPCServices/", "Contents/PlugIns/", "Contents/Library/LoginItems/"]
            if codeDirectories.contains(where: { relativePath.hasPrefix($0) }) {
                return true
            }
        }
        return false
    }

    private func hashFile(at url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }

        var hasher = SHA256()
        while true {
            let data = try handle.read(upToCount: 1_048_576) ?? Data()
            if data.isEmpty { break }
            hasher.update(data: data)
        }
        return Self.hexDigest(hasher.finalize())
    }

    private func hashDirectory(at rootURL: URL) throws -> String {
        var pendingDirectories = [rootURL]
        var entries: [URL] = []
        while let directory = pendingDirectories.popLast() {
            let children = try fileManager.contentsOfDirectory(
                at: directory,
                includingPropertiesForKeys: [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey],
                options: []
            )
            for child in children {
                entries.append(child)
                let values = try child.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
                if values.isDirectory == true && values.isSymbolicLink != true {
                    pendingDirectories.append(child)
                }
            }
        }

        var hasher = SHA256()
        for entry in entries.sorted(by: { relativePath(of: $0, below: rootURL) < relativePath(of: $1, below: rootURL) }) {
            let relative = relativePath(of: entry, below: rootURL)
            let values = try entry.resourceValues(forKeys: [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey])
            let attributes = try fileManager.attributesOfItem(atPath: entry.path)
            let permissions = (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? 0

            if values.isSymbolicLink == true {
                update(&hasher, with: "L\u{0}\(relative)\u{0}\(try fileManager.destinationOfSymbolicLink(atPath: entry.path))\u{0}\(permissions)\u{0}")
            } else if values.isDirectory == true {
                update(&hasher, with: "D\u{0}\(relative)\u{0}\(permissions)\u{0}")
            } else if values.isRegularFile == true {
                update(&hasher, with: "F\u{0}\(relative)\u{0}\(permissions)\u{0}\(try hashFile(at: entry))\u{0}")
            } else {
                update(&hasher, with: "O\u{0}\(relative)\u{0}\(permissions)\u{0}")
            }
        }
        return Self.hexDigest(hasher.finalize())
    }

    private func update(_ hasher: inout SHA256, with string: String) {
        hasher.update(data: Data(string.utf8))
    }

    private func relativePath(of url: URL, below root: URL) -> String {
        let prefix = root.standardizedFileURL.path + "/"
        let path = url.standardizedFileURL.path
        return path.hasPrefix(prefix) ? String(path.dropFirst(prefix.count)) : path
    }

    private func nonemptyString(_ value: Any?) -> String? {
        guard let string = value as? String else { return nil }
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    private static func hexDigest<D: Sequence>(_ digest: D) -> String where D.Element == UInt8 {
        digest.map { String(format: "%02x", $0) }.joined()
    }

    private static let transferableEntitlements: Set<String> = [
        "com.apple.security.get-task-allow",
        "com.apple.security.cs.allow-jit",
        "com.apple.security.cs.allow-unsigned-executable-memory",
        "com.apple.security.cs.disable-executable-page-protection",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.debugger"
    ]

    private enum SignatureFlag {
        static let adHoc: UInt32 = 0x0002
    }
}

private struct SignatureFacts: @unchecked Sendable {
    let signingIdentifier: String?
    let teamIdentifier: String?
    let isApplePlatformBinary: Bool
    let isSigned: Bool
    let isAdHocSigned: Bool
    let signatureValid: Bool
    let isSandboxed: Bool
    let entitlements: [String: Any]

    static let unsigned = SignatureFacts(
        signingIdentifier: nil,
        teamIdentifier: nil,
        isApplePlatformBinary: false,
        isSigned: false,
        isAdHocSigned: false,
        signatureValid: false,
        isSandboxed: false,
        entitlements: [:]
    )
}

private enum MachOEncryptionDetector {
    private static let mhMagic: UInt32 = 0xfeedface
    private static let mhMagic64: UInt32 = 0xfeedfacf
    private static let fatMagic: UInt32 = 0xcafebabe
    private static let fatMagic64: UInt32 = 0xcafebabf
    private static let encryptionInfo: UInt32 = 0x21
    private static let encryptionInfo64: UInt32 = 0x2c

    static func isEncrypted(executableURL: URL) -> Bool {
        guard let data = try? Data(contentsOf: executableURL, options: [.mappedIfSafe]), data.count >= 4 else {
            return false
        }

        if uint32(data, at: 0, endian: .big) == fatMagic {
            return encryptedFatSlices(data, is64Bit: false)
        }
        if uint32(data, at: 0, endian: .big) == fatMagic64 {
            return encryptedFatSlices(data, is64Bit: true)
        }
        return encryptedThinSlice(data, offset: 0)
    }

    private static func encryptedFatSlices(_ data: Data, is64Bit: Bool) -> Bool {
        guard let count = uint32(data, at: 4, endian: .big) else { return false }
        let stride = is64Bit ? 32 : 20
        for index in 0..<Int(count) {
            let archOffset = 8 + index * stride
            let sliceOffset: UInt64?
            if is64Bit {
                sliceOffset = uint64(data, at: archOffset + 8, endian: .big)
            } else {
                sliceOffset = uint32(data, at: archOffset + 8, endian: .big).map(UInt64.init)
            }
            if let sliceOffset, sliceOffset <= UInt64(Int.max), encryptedThinSlice(data, offset: Int(sliceOffset)) {
                return true
            }
        }
        return false
    }

    private static func encryptedThinSlice(_ data: Data, offset: Int) -> Bool {
        let littleMagic = uint32(data, at: offset, endian: .little)
        let endian: Endian
        let headerSize: Int
        switch littleMagic {
        case mhMagic:
            endian = .little
            headerSize = 28
        case mhMagic64:
            endian = .little
            headerSize = 32
        default:
            let bigMagic = uint32(data, at: offset, endian: .big)
            if bigMagic == mhMagic {
                endian = .big
                headerSize = 28
            } else if bigMagic == mhMagic64 {
                endian = .big
                headerSize = 32
            } else {
                return false
            }
        }

        guard let commandCount = uint32(data, at: offset + 16, endian: endian) else { return false }
        var commandOffset = offset + headerSize
        for _ in 0..<Int(commandCount) {
            guard let command = uint32(data, at: commandOffset, endian: endian),
                  let commandSize = uint32(data, at: commandOffset + 4, endian: endian),
                  commandSize >= 8,
                  commandOffset + Int(commandSize) <= data.count else {
                return false
            }
            if command == encryptionInfo || command == encryptionInfo64 {
                return (uint32(data, at: commandOffset + 16, endian: endian) ?? 0) != 0
            }
            commandOffset += Int(commandSize)
        }
        return false
    }

    private static func uint32(_ data: Data, at offset: Int, endian: Endian) -> UInt32? {
        guard offset >= 0, offset + 4 <= data.count else { return nil }
        let value = data[offset..<(offset + 4)].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        return endian == .big ? value : value.byteSwapped
    }

    private static func uint64(_ data: Data, at offset: Int, endian: Endian) -> UInt64? {
        guard offset >= 0, offset + 8 <= data.count else { return nil }
        let value = data[offset..<(offset + 8)].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        return endian == .big ? value : value.byteSwapped
    }

    private enum Endian {
        case little
        case big
    }
}
