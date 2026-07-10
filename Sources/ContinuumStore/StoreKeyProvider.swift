import CryptoKit
import Foundation
import Security

public protocol SnapshotStoreKeyProviding: Sendable {
    func loadOrCreateKey() throws -> Data
}

public struct FixedSnapshotStoreKeyProvider: SnapshotStoreKeyProviding {
    private let keyData: Data

    public init(keyData: Data) {
        self.keyData = keyData
    }

    public func loadOrCreateKey() throws -> Data {
        guard keyData.count == 32 else {
            throw SnapshotStoreError.invalidKeyLength
        }
        return keyData
    }
}

public struct KeychainSnapshotStoreKeyProvider: SnapshotStoreKeyProviding {
    public let service: String
    public let account: String

    public init(
        service: String = "com.continuum.snapshot-store",
        account: String = "local-encryption-key"
    ) {
        self.service = service
        self.account = account
    }

    public func loadOrCreateKey() throws -> Data {
        if let existing = try readKey() {
            guard existing.count == 32 else {
                throw SnapshotStoreError.invalidKeyLength
            }
            return existing
        }

        var bytes = Data(count: 32)
        let randomStatus = bytes.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
        }
        guard randomStatus == errSecSuccess else {
            throw SnapshotStoreError.keychain(randomStatus)
        }

        let addQuery: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData: bytes
        ]
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus == errSecDuplicateItem, let racedKey = try readKey() {
            return racedKey
        }
        guard addStatus == errSecSuccess else {
            throw SnapshotStoreError.keychain(addStatus)
        }
        return bytes
    }

    private func readKey() throws -> Data? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = result as? Data else {
            throw SnapshotStoreError.keychain(status)
        }
        return data
    }
}

extension SymmetricKey {
    init(validating data: Data) throws {
        guard data.count == 32 else {
            throw SnapshotStoreError.invalidKeyLength
        }
        self.init(data: data)
    }
}
