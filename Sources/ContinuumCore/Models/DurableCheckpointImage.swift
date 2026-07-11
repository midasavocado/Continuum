import Foundation

/// Versioned, pointer-free description of a process-tree checkpoint. Large
/// byte ranges live in encrypted content-addressed chunks referenced here.
public struct DurableCheckpointImage: Codable, Hashable, Sendable {
    public static let currentFormatVersion = 1

    public let formatVersion: Int
    public let checkpointID: CheckpointID
    public let createdAt: Date
    public let architecture: String
    public let operatingSystemBuild: String
    public let pageSize: UInt64
    public let rootProcessIdentifier: Int32
    public let app: AppIdentity
    public let members: [DurableProcessImage]
    public let writableFiles: [DurableFileImage]

    public init(
        formatVersion: Int = Self.currentFormatVersion,
        checkpointID: CheckpointID,
        createdAt: Date,
        architecture: String,
        operatingSystemBuild: String,
        pageSize: UInt64,
        rootProcessIdentifier: Int32,
        app: AppIdentity,
        members: [DurableProcessImage],
        writableFiles: [DurableFileImage]
    ) {
        self.formatVersion = formatVersion
        self.checkpointID = checkpointID
        self.createdAt = createdAt
        self.architecture = architecture
        self.operatingSystemBuild = operatingSystemBuild
        self.pageSize = pageSize
        self.rootProcessIdentifier = rootProcessIdentifier
        self.app = app
        self.members = members
        self.writableFiles = writableFiles
    }
}

public struct DurableProcessImage: Codable, Hashable, Sendable {
    public let processIdentifier: Int32
    public let parentProcessIdentifier: Int32
    public let executableDevice: UInt64
    public let executableInode: UInt64
    public let vmLayoutHash: UInt64
    public let regions: [DurableMemoryRegion]
    public let threads: [DurableThreadImage]

    public init(
        processIdentifier: Int32,
        parentProcessIdentifier: Int32,
        executableDevice: UInt64,
        executableInode: UInt64,
        vmLayoutHash: UInt64,
        regions: [DurableMemoryRegion],
        threads: [DurableThreadImage]
    ) {
        self.processIdentifier = processIdentifier
        self.parentProcessIdentifier = parentProcessIdentifier
        self.executableDevice = executableDevice
        self.executableInode = executableInode
        self.vmLayoutHash = vmLayoutHash
        self.regions = regions
        self.threads = threads
    }
}

public struct DurableMemoryRegion: Codable, Hashable, Sendable {
    public let address: UInt64
    public let length: UInt64
    public let protection: Int32
    public let maximumProtection: Int32
    public let inheritance: Int32
    public let shareMode: UInt32
    public let userTag: UInt32
    public let chunks: [DurableChunkReference]
}

public struct DurableThreadImage: Codable, Hashable, Sendable {
    public let threadIdentifier: UInt64
    public let generalStateFlavor: UInt32
    public let generalState: DurableChunkReference
    public let vectorStateFlavor: UInt32
    public let vectorState: DurableChunkReference
}

public struct DurableFileImage: Codable, Hashable, Sendable {
    public let originalPath: String
    public let device: UInt64
    public let inode: UInt64
    public let byteCount: UInt64
    public let chunks: [DurableChunkReference]
}

public struct DurableChunkReference: Codable, Hashable, Sendable {
    public let hash: String
    public let logicalBytes: UInt64
    public let storedBytes: UInt64
    public let compression: DurableChunkCompression

    public init(
        hash: String,
        logicalBytes: UInt64,
        storedBytes: UInt64,
        compression: DurableChunkCompression
    ) {
        self.hash = hash
        self.logicalBytes = logicalBytes
        self.storedBytes = storedBytes
        self.compression = compression
    }
}

public enum DurableChunkCompression: String, Codable, Hashable, Sendable {
    case none
    case lzfse
}
