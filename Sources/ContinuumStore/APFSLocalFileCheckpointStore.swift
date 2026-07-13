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

public struct LocalFileCheckpointPayload: Hashable, Sendable {
    public let entry: LocalFileCheckpointEntry
    public let data: Data
}

/// Saved bytes plus the vnode identity they are allowed to replace. Writing
/// through the existing vnode preserves descriptors held by a stopped process.
public struct LocalFileReplacement: Hashable, Sendable {
    public let originalPath: String
    public let device: UInt64
    public let inode: UInt64
    public let mode: UInt32
    public let data: Data

    public init(
        originalPath: String,
        device: UInt64,
        inode: UInt64,
        mode: UInt32,
        data: Data
    ) {
        self.originalPath = originalPath
        self.device = device
        self.inode = inode
        self.mode = mode
        self.data = data
    }
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

    /// Reads the immutable APFS clones captured while the process group was
    /// suspended so they can enter encrypted content-addressed storage.
    public nonisolated func payloadsCoherently(
        snapshotID: UUID
    ) throws -> [LocalFileCheckpointPayload] {
        let manifest = try manifestCoherently(snapshotID: snapshotID)
        let snapshotRoot = Self.snapshotURL(rootURL: rootURL, id: snapshotID)
        return try manifest.entries.map { entry in
            let cloneURL = snapshotRoot.appendingPathComponent(
                entry.cloneRelativePath,
                isDirectory: false
            )
            let cloneStat = try Self.regularFileStat(at: cloneURL)
            guard cloneStat.st_size == entry.byteCount else {
                throw LocalFileCheckpointError.io(path: cloneURL.path, code: EIO)
            }
            let data = try Data(contentsOf: cloneURL, options: [.mappedIfSafe])
            guard data.count == Int(entry.byteCount) else {
                throw LocalFileCheckpointError.io(path: cloneURL.path, code: EIO)
            }
            return LocalFileCheckpointPayload(
                entry: entry,
                data: data
            )
        }
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

    /// Replaces bytes in already-existing regular files without replacing
    /// their vnodes. Callers create a safety checkpoint first and restore it if
    /// any later phase fails.
    public nonisolated func replaceCoherently(
        _ replacements: [LocalFileReplacement]
    ) throws -> LocalFileRestoreReport {
        var restoredBytes: Int64 = 0
        var seenPaths: Set<String> = []
        for replacement in replacements {
            guard replacement.originalPath.hasPrefix("/"),
                  seenPaths.insert(replacement.originalPath).inserted,
                  replacement.data.count <= Int(Int64.max) else {
                throw LocalFileCheckpointError.unsupportedFile(
                    replacement.originalPath
                )
            }
            let liveURL = URL(fileURLWithPath: replacement.originalPath)
            let liveStat = try Self.regularFileStat(at: liveURL)
            guard UInt64(liveStat.st_dev) == replacement.device,
                  UInt64(liveStat.st_ino) == replacement.inode,
                  (UInt32(liveStat.st_mode) & (UInt32(S_IFMT) | 0o7777))
                    == (replacement.mode & (UInt32(S_IFMT) | 0o7777)) else {
                throw LocalFileCheckpointError.fileIdentityChanged(
                    replacement.originalPath
                )
            }
            try Self.restoreBytes(replacement.data, to: liveURL)
            restoredBytes += Int64(replacement.data.count)
        }
        return LocalFileRestoreReport(
            restoredFileCount: replacements.count,
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

    private static func restoreBytes(
        _ source: Data,
        to destination: URL
    ) throws {
        let destinationFD = destination.path.withCString {
            Darwin.open($0, O_WRONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard destinationFD >= 0 else {
            throw LocalFileCheckpointError.io(path: destination.path, code: errno)
        }
        defer { _ = Darwin.close(destinationFD) }

        guard Darwin.ftruncate(destinationFD, off_t(source.count)) == 0 else {
            throw LocalFileCheckpointError.io(path: destination.path, code: errno)
        }
        var offset = 0
        while offset < source.count {
            let written = source.withUnsafeBytes { bytes in
                Darwin.pwrite(
                    destinationFD,
                    bytes.baseAddress?.advanced(by: offset),
                    source.count - offset,
                    off_t(offset)
                )
            }
            guard written > 0 else {
                throw LocalFileCheckpointError.io(
                    path: destination.path,
                    code: errno
                )
            }
            offset += written
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
