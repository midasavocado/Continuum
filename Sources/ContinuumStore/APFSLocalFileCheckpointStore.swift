import Darwin
import Foundation

public struct LocalFileCheckpointEntry: Codable, Hashable, Sendable {
    public let originalPath: String
    public let cloneRelativePath: String
    public let device: UInt64
    public let inode: UInt64
    public let byteCount: Int64
    public let mode: UInt32
}

public struct LocalFileCheckpointManifest: Codable, Hashable, Sendable {
    public let snapshotID: UUID
    public let createdAt: Date
    public let entries: [LocalFileCheckpointEntry]
}

public struct LocalFileRestoreReport: Equatable, Sendable {
    public let restoredFileCount: Int
    public let restoredBytes: Int64
}

public enum LocalFileCheckpointError: Error, LocalizedError, Equatable, Sendable {
    case duplicateSnapshot(UUID)
    case snapshotNotFound(UUID)
    case unsupportedFile(String)
    case cloneFailed(path: String, code: Int32)
    case fileIdentityChanged(String)
    case io(path: String, code: Int32)

    public var errorDescription: String? {
        switch self {
        case .duplicateSnapshot(let id):
            "Local file checkpoint \(id) already exists."
        case .snapshotNotFound(let id):
            "Local file checkpoint \(id) was not found."
        case .unsupportedFile(let path):
            "Continuum can only clone regular local files in this checkpoint: \(path)"
        case .cloneFailed(let path, let code):
            "APFS could not create a copy-on-write clone for \(path) (errno \(code))."
        case .fileIdentityChanged(let path):
            "The live file at \(path) no longer has the captured inode identity."
        case .io(let path, let code):
            "Local file checkpoint I/O failed for \(path) (errno \(code))."
        }
    }
}

/// Per-app hot file roots. Capture uses APFS COW clones; restore writes bytes
/// back through the existing vnode so already-open descriptors keep their
/// identity. Namespace operations and cross-process writer certification sit
/// above this byte-preservation layer.
public actor APFSLocalFileCheckpointStore {
    private let rootURL: URL

    public init(rootURL: URL, fileManager: FileManager = .default) throws {
        self.rootURL = rootURL.standardizedFileURL
        try fileManager.createDirectory(
            at: self.rootURL,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    }

    public func capture(
        snapshotID: UUID,
        files: [URL]
    ) throws -> LocalFileCheckpointManifest {
        try captureCoherently(snapshotID: snapshotID, files: files)
    }

    /// Synchronous entry point for a ContinuumRuntime resource callback. The
    /// caller is responsible for serializing calls and keeping the target group
    /// suspended for the duration of this operation.
    public nonisolated func captureCoherently(
        snapshotID: UUID,
        files: [URL]
    ) throws -> LocalFileCheckpointManifest {
        let fileManager = FileManager.default
        let destination = Self.snapshotURL(rootURL: rootURL, id: snapshotID)
        guard !fileManager.fileExists(atPath: destination.path) else {
            throw LocalFileCheckpointError.duplicateSnapshot(snapshotID)
        }

        let staging = rootURL.appendingPathComponent(
            ".\(snapshotID.uuidString.lowercased()).\(UUID().uuidString).tmp",
            isDirectory: true
        )
        try fileManager.createDirectory(
            at: staging,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )

        do {
            let filesDirectory = staging.appendingPathComponent("files", isDirectory: true)
            try fileManager.createDirectory(
                at: filesDirectory,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700]
            )

            let uniqueFiles = Dictionary(
                files.map { ($0.standardizedFileURL.path, $0.standardizedFileURL) },
                uniquingKeysWith: { first, _ in first }
            ).values.sorted { $0.path < $1.path }

            var entries: [LocalFileCheckpointEntry] = []
            entries.reserveCapacity(uniqueFiles.count)
            for (index, source) in uniqueFiles.enumerated() {
                let sourceStat = try Self.regularFileStat(at: source)
                let relativePath = String(format: "files/%08d.clone", index)
                let clone = staging.appendingPathComponent(relativePath)
                let cloneResult = source.path.withCString { sourcePath in
                    clone.path.withCString { destinationPath in
                        Darwin.clonefile(
                            sourcePath,
                            destinationPath,
                            UInt32(CLONE_NOFOLLOW | CLONE_ACL)
                        )
                    }
                }
                guard cloneResult == 0 else {
                    throw LocalFileCheckpointError.cloneFailed(
                        path: source.path,
                        code: errno
                    )
                }
                entries.append(
                    LocalFileCheckpointEntry(
                        originalPath: source.path,
                        cloneRelativePath: relativePath,
                        device: UInt64(sourceStat.st_dev),
                        inode: UInt64(sourceStat.st_ino),
                        byteCount: Int64(sourceStat.st_size),
                        mode: UInt32(sourceStat.st_mode)
                    )
                )
            }

            let manifest = LocalFileCheckpointManifest(
                snapshotID: snapshotID,
                createdAt: .now,
                entries: entries
            )
            let encoded = try JSONEncoder().encode(manifest)
            try AtomicFileWriter.write(
                encoded,
                to: staging.appendingPathComponent("manifest.json")
            )
            try fileManager.moveItem(at: staging, to: destination)
            Self.synchronizeDirectory(rootURL)
            return manifest
        } catch {
            try? fileManager.removeItem(at: staging)
            throw error
        }
    }

    public func manifest(snapshotID: UUID) throws -> LocalFileCheckpointManifest {
        try manifestCoherently(snapshotID: snapshotID)
    }

    public nonisolated func manifestCoherently(
        snapshotID: UUID
    ) throws -> LocalFileCheckpointManifest {
        let fileManager = FileManager.default
        let url = Self.snapshotURL(rootURL: rootURL, id: snapshotID)
            .appendingPathComponent("manifest.json")
        guard fileManager.fileExists(atPath: url.path) else {
            throw LocalFileCheckpointError.snapshotNotFound(snapshotID)
        }
        return try JSONDecoder().decode(
            LocalFileCheckpointManifest.self,
            from: Data(contentsOf: url)
        )
    }

    public func restore(snapshotID: UUID) throws -> LocalFileRestoreReport {
        try restoreCoherently(snapshotID: snapshotID)
    }

    public nonisolated func restoreCoherently(
        snapshotID: UUID
    ) throws -> LocalFileRestoreReport {
        let manifest = try manifestCoherently(snapshotID: snapshotID)
        let snapshotRoot = Self.snapshotURL(rootURL: rootURL, id: snapshotID)
        var restoredBytes: Int64 = 0

        for entry in manifest.entries {
            let liveURL = URL(fileURLWithPath: entry.originalPath)
            let liveStat = try Self.regularFileStat(at: liveURL)
            guard UInt64(liveStat.st_dev) == entry.device,
                UInt64(liveStat.st_ino) == entry.inode
            else {
                throw LocalFileCheckpointError.fileIdentityChanged(entry.originalPath)
            }

            let cloneURL = snapshotRoot.appendingPathComponent(entry.cloneRelativePath)
            try Self.restoreBytes(
                from: cloneURL,
                to: liveURL,
                expectedBytes: entry.byteCount
            )
            restoredBytes += entry.byteCount
        }

        return LocalFileRestoreReport(
            restoredFileCount: manifest.entries.count,
            restoredBytes: restoredBytes
        )
    }

    public func delete(snapshotID: UUID) throws {
        try deleteCoherently(snapshotID: snapshotID)
    }

    public nonisolated func deleteCoherently(snapshotID: UUID) throws {
        let fileManager = FileManager.default
        let url = Self.snapshotURL(rootURL: rootURL, id: snapshotID)
        guard fileManager.fileExists(atPath: url.path) else {
            throw LocalFileCheckpointError.snapshotNotFound(snapshotID)
        }
        try fileManager.removeItem(at: url)
        Self.synchronizeDirectory(rootURL)
    }

    private static func restoreBytes(
        from source: URL,
        to destination: URL,
        expectedBytes: Int64
    ) throws {
        let sourceFD = source.path.withCString { Darwin.open($0, O_RDONLY | O_CLOEXEC) }
        guard sourceFD >= 0 else {
            throw LocalFileCheckpointError.io(path: source.path, code: errno)
        }
        defer { _ = Darwin.close(sourceFD) }

        let destinationFD = destination.path.withCString {
            Darwin.open($0, O_WRONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard destinationFD >= 0 else {
            throw LocalFileCheckpointError.io(path: destination.path, code: errno)
        }
        defer { _ = Darwin.close(destinationFD) }

        guard Darwin.ftruncate(destinationFD, off_t(expectedBytes)) == 0 else {
            throw LocalFileCheckpointError.io(path: destination.path, code: errno)
        }

        var buffer = [UInt8](repeating: 0, count: 1024 * 1024)
        var offset: Int64 = 0
        while offset < expectedBytes {
            let requested = min(buffer.count, Int(expectedBytes - offset))
            let readCount = buffer.withUnsafeMutableBytes {
                Darwin.pread(sourceFD, $0.baseAddress, requested, off_t(offset))
            }
            guard readCount > 0 else {
                throw LocalFileCheckpointError.io(path: source.path, code: errno)
            }

            var written = 0
            while written < readCount {
                let writeCount = buffer.withUnsafeBytes {
                    Darwin.pwrite(
                        destinationFD,
                        $0.baseAddress?.advanced(by: written),
                        readCount - written,
                        off_t(offset + Int64(written))
                    )
                }
                guard writeCount > 0 else {
                    throw LocalFileCheckpointError.io(path: destination.path, code: errno)
                }
                written += writeCount
            }
            offset += Int64(readCount)
        }

        guard Darwin.fsync(destinationFD) == 0 else {
            throw LocalFileCheckpointError.io(path: destination.path, code: errno)
        }
    }

    private static func regularFileStat(at url: URL) throws -> stat {
        var value = stat()
        let result = url.path.withCString { Darwin.lstat($0, &value) }
        guard result == 0, (value.st_mode & S_IFMT) == S_IFREG else {
            throw LocalFileCheckpointError.unsupportedFile(url.path)
        }
        return value
    }

    private static func snapshotURL(rootURL: URL, id: UUID) -> URL {
        rootURL.appendingPathComponent(id.uuidString.lowercased(), isDirectory: true)
    }

    private static func synchronizeDirectory(_ directory: URL) {
        let descriptor = directory.path.withCString {
            Darwin.open($0, O_RDONLY | O_CLOEXEC)
        }
        guard descriptor >= 0 else { return }
        _ = Darwin.fsync(descriptor)
        _ = Darwin.close(descriptor)
    }
}
