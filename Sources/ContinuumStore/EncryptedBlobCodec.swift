import CryptoKit
import Foundation

struct EncryptedBlobCodec: Sendable {
    private enum Compression: UInt8 {
        case none = 0
        case lzfse = 1
    }

    private static let magic = Data([0x43, 0x54, 0x4D, 0x42]) // CTMB
    private static let version: UInt8 = 1
    private static let headerSize = 14

    let key: SymmetricKey

    func seal(_ plaintext: Data) throws -> Data {
        let compressed = try? (plaintext as NSData).compressed(using: .lzfse) as Data
        let shouldCompress = compressed.map { $0.count < plaintext.count } ?? false
        let compression: Compression = shouldCompress ? .lzfse : .none
        let payload = shouldCompress ? compressed! : plaintext
        let header = Self.header(compression: compression, originalSize: UInt64(plaintext.count))
        let box = try AES.GCM.seal(payload, using: key, authenticating: header)
        guard let combined = box.combined else {
            throw SnapshotStoreError.corruptData("AES-GCM did not produce a combined sealed box")
        }
        return header + combined
    }

    func open(_ blob: Data) throws -> Data {
        guard blob.count > Self.headerSize else {
            throw SnapshotStoreError.corruptData("encrypted blob is truncated")
        }
        let header = blob.prefix(Self.headerSize)
        guard header.prefix(Self.magic.count) == Self.magic else {
            throw SnapshotStoreError.corruptData("encrypted blob has an unknown magic value")
        }
        guard header[4] == Self.version else {
            throw SnapshotStoreError.corruptData("encrypted blob version is unsupported")
        }
        guard let compression = Compression(rawValue: header[5]) else {
            throw SnapshotStoreError.corruptData("encrypted blob compression is unsupported")
        }
        let expectedSize = header[6..<14].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }

        do {
            let sealedBox = try AES.GCM.SealedBox(combined: blob.dropFirst(Self.headerSize))
            let payload = try AES.GCM.open(sealedBox, using: key, authenticating: header)
            let plaintext: Data
            switch compression {
            case .none:
                plaintext = payload
            case .lzfse:
                plaintext = try (payload as NSData).decompressed(using: .lzfse) as Data
            }
            guard UInt64(plaintext.count) == expectedSize else {
                throw SnapshotStoreError.corruptData("decompressed blob size does not match its header")
            }
            return plaintext
        } catch let error as SnapshotStoreError {
            throw error
        } catch {
            throw SnapshotStoreError.decryptionFailed
        }
    }

    private static func header(compression: Compression, originalSize: UInt64) -> Data {
        var data = magic
        data.append(version)
        data.append(compression.rawValue)
        withUnsafeBytes(of: originalSize.bigEndian) { data.append(contentsOf: $0) }
        return data
    }
}
