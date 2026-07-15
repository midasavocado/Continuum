import Darwin
import Foundation
import ContinuumCore

struct LocalAppSetupFileSystem: AppSetupFileSystem {
    private var fileManager: FileManager { .default }

    func itemExists(at url: URL) -> Bool {
        fileManager.fileExists(atPath: url.path)
    }

    func createDirectory(at url: URL) throws {
        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
    }

    func removeItemIfPresent(at url: URL) throws {
        guard itemExists(at: url) else { return }
        try fileManager.removeItem(at: url)
    }

    func cloneOrCopyItem(at sourceURL: URL, to destinationURL: URL) throws -> AppSetupCopyMethod {
        try removeItemIfPresent(at: destinationURL)

        let cloneStatus: Int32 = sourceURL.withUnsafeFileSystemRepresentation { sourcePath in
            destinationURL.withUnsafeFileSystemRepresentation { destinationPath in
                guard let sourcePath, let destinationPath else { return Int32(-1) }
                return clonefile(sourcePath, destinationPath, 0)
            }
        }
        if cloneStatus == 0 {
            return .apfsClone
        }

        // clonefile can leave a partial destination on failure. Never copy on top of it.
        try removeItemIfPresent(at: destinationURL)
        try fileManager.copyItem(at: sourceURL, to: destinationURL)
        return .fileCopy
    }

    func exchangeItems(at firstURL: URL, and secondURL: URL) throws {
        let status: Int32 = firstURL.withUnsafeFileSystemRepresentation { firstPath in
            secondURL.withUnsafeFileSystemRepresentation { secondPath in
                guard let firstPath, let secondPath else { return Int32(-1) }
                return renameatx_np(
                    AT_FDCWD,
                    firstPath,
                    AT_FDCWD,
                    secondPath,
                    UInt32(RENAME_SWAP)
                )
            }
        }
        guard status == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        try synchronizeDirectory(at: firstURL.deletingLastPathComponent())
    }

    func readData(at url: URL) throws -> Data {
        try Data(contentsOf: url, options: [.mappedIfSafe])
    }

    func writeDataAtomically(_ data: Data, to url: URL) throws {
        let parent = url.deletingLastPathComponent()
        try createDirectory(at: parent)

        let temporaryURL = parent.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp")
        guard fileManager.createFile(atPath: temporaryURL.path, contents: nil) else {
            throw AppSetupError.operationFailed("Could not create an atomic journal file at \(temporaryURL.path).")
        }

        do {
            let handle = try FileHandle(forWritingTo: temporaryURL)
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()

            let renameStatus: Int32 = temporaryURL.withUnsafeFileSystemRepresentation { temporaryPath in
                url.withUnsafeFileSystemRepresentation { destinationPath in
                    guard let temporaryPath, let destinationPath else { return Int32(-1) }
                    return Darwin.rename(temporaryPath, destinationPath)
                }
            }
            guard renameStatus == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }

            try synchronizeDirectory(at: parent)
        } catch {
            try? removeItemIfPresent(at: temporaryURL)
            throw error
        }
    }

    private func synchronizeDirectory(at url: URL) throws {
        let descriptor: Int32 = url.withUnsafeFileSystemRepresentation { path in
            guard let path else { return Int32(-1) }
            return Darwin.open(path, O_RDONLY)
        }
        guard descriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        defer { Darwin.close(descriptor) }
        guard Darwin.fsync(descriptor) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }
}
