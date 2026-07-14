import Foundation

/// Versioned, pointer-free description of a process-tree checkpoint. Large
/// byte ranges live in encrypted content-addressed chunks referenced here.
public struct DurableCheckpointImage: Codable, Hashable, Sendable {
    public static let currentFormatVersion = 4

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
    public let writableFileDescriptors: [DurableWritableFileDescriptor]

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
        writableFiles: [DurableFileImage],
        writableFileDescriptors: [DurableWritableFileDescriptor] = []
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
        self.writableFileDescriptors = writableFileDescriptors
    }
}

public struct DurableProcessImage: Codable, Hashable, Sendable {
    public let processIdentifier: Int32
    public let parentProcessIdentifier: Int32
    public let executableDevice: UInt64
    public let executableInode: UInt64
    public let vmLayoutHash: UInt64
    public let immutableLayoutDigest: String?
    public let launchContract: DurableLaunchContract?
    public let regions: [DurableMemoryRegion]
    public let threads: [DurableThreadImage]

    public init(
        processIdentifier: Int32,
        parentProcessIdentifier: Int32,
        executableDevice: UInt64,
        executableInode: UInt64,
        vmLayoutHash: UInt64,
        immutableLayoutDigest: String? = nil,
        launchContract: DurableLaunchContract? = nil,
        regions: [DurableMemoryRegion],
        threads: [DurableThreadImage]
    ) {
        self.processIdentifier = processIdentifier
        self.parentProcessIdentifier = parentProcessIdentifier
        self.executableDevice = executableDevice
        self.executableInode = executableInode
        self.vmLayoutHash = vmLayoutHash
        self.immutableLayoutDigest = immutableLayoutDigest
        self.launchContract = launchContract
        self.regions = regions
        self.threads = threads
    }
}

/// The process attributes required to recreate a fresh suspended shell before
/// the restorer replaces its address space and thread state.
public struct DurableLaunchContract: Codable, Hashable, Sendable {
    public let executablePath: String
    public let arguments: [String]
    public let environment: [String]
    public let workingDirectory: String
    public let addressSpacePolicy: DurableAddressSpacePolicy?

    public init(
        executablePath: String,
        arguments: [String],
        environment: [String],
        workingDirectory: String,
        addressSpacePolicy: DurableAddressSpacePolicy? = nil
    ) {
        self.executablePath = executablePath
        self.arguments = arguments
        self.environment = environment
        self.workingDirectory = workingDirectory
        self.addressSpacePolicy = addressSpacePolicy
    }
}

public enum DurableAddressSpacePolicy: String, Codable, Hashable, Sendable {
    case systemASLR
    case continuumDeterministic
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

    public init(
        address: UInt64,
        length: UInt64,
        protection: Int32,
        maximumProtection: Int32,
        inheritance: Int32,
        shareMode: UInt32,
        userTag: UInt32,
        chunks: [DurableChunkReference]
    ) {
        self.address = address
        self.length = length
        self.protection = protection
        self.maximumProtection = maximumProtection
        self.inheritance = inheritance
        self.shareMode = shareMode
        self.userTag = userTag
        self.chunks = chunks
    }
}

public enum DurableThreadOrigin: String, Codable, Hashable, Sendable {
    case rawMach
    case pthread
    case workqueue
    case unknown
}

public struct DurableThreadImage: Codable, Hashable, Sendable {
    public let threadIdentifier: UInt64
    public let threadHandle: UInt64?
    public let pthreadObjectAddress: UInt64?
    public let origin: DurableThreadOrigin?
    public let dispatchQueueAddress: UInt64?
    public let stackPointer: UInt64?
    public let stackRegionAddress: UInt64?
    public let stackRegionLength: UInt64?
    public let pthreadRegionAddress: UInt64?
    public let pthreadRegionLength: UInt64?
    public let isUserspaceSafepoint: Bool?
    public let preservesKernelContinuation: Bool?
    public let generalStateFlavor: UInt32
    public let generalState: DurableChunkReference
    public let vectorStateFlavor: UInt32
    public let vectorState: DurableChunkReference

    public init(
        threadIdentifier: UInt64,
        threadHandle: UInt64? = nil,
        pthreadObjectAddress: UInt64? = nil,
        origin: DurableThreadOrigin? = nil,
        dispatchQueueAddress: UInt64? = nil,
        stackPointer: UInt64? = nil,
        stackRegionAddress: UInt64? = nil,
        stackRegionLength: UInt64? = nil,
        pthreadRegionAddress: UInt64? = nil,
        pthreadRegionLength: UInt64? = nil,
        isUserspaceSafepoint: Bool? = nil,
        preservesKernelContinuation: Bool? = nil,
        generalStateFlavor: UInt32,
        generalState: DurableChunkReference,
        vectorStateFlavor: UInt32,
        vectorState: DurableChunkReference
    ) {
        self.threadIdentifier = threadIdentifier
        self.threadHandle = threadHandle
        self.pthreadObjectAddress = pthreadObjectAddress
        self.origin = origin
        self.dispatchQueueAddress = dispatchQueueAddress
        self.stackPointer = stackPointer
        self.stackRegionAddress = stackRegionAddress
        self.stackRegionLength = stackRegionLength
        self.pthreadRegionAddress = pthreadRegionAddress
        self.pthreadRegionLength = pthreadRegionLength
        self.isUserspaceSafepoint = isUserspaceSafepoint
        self.preservesKernelContinuation = preservesKernelContinuation
        self.generalStateFlavor = generalStateFlavor
        self.generalState = generalState
        self.vectorStateFlavor = vectorStateFlavor
        self.vectorState = vectorState
    }
}

public struct DurableFileImage: Codable, Hashable, Sendable {
    public let originalPath: String
    public let device: UInt64
    public let inode: UInt64
    public let byteCount: UInt64
    public let mode: UInt32
    public let chunks: [DurableChunkReference]

    public init(
        originalPath: String,
        device: UInt64,
        inode: UInt64,
        byteCount: UInt64,
        mode: UInt32,
        chunks: [DurableChunkReference]
    ) {
        self.originalPath = originalPath
        self.device = device
        self.inode = inode
        self.byteCount = byteCount
        self.mode = mode
        self.chunks = chunks
    }
}

/// Stable descriptor metadata needed to reconnect a regular file before a
/// cold replacement is allowed to execute. Non-vnode descriptors are rejected
/// by the runtime resource gate and never represented as restorable here.
public struct DurableWritableFileDescriptor: Codable, Hashable, Sendable {
    public let processIdentifier: Int32
    public let fileDescriptor: Int32
    public let openFlags: UInt32
    public let offset: Int64
    public let device: UInt64
    public let inode: UInt64
    public let mode: UInt32
    public let originalPath: String

    public init(
        processIdentifier: Int32,
        fileDescriptor: Int32,
        openFlags: UInt32,
        offset: Int64,
        device: UInt64,
        inode: UInt64,
        mode: UInt32,
        originalPath: String
    ) {
        self.processIdentifier = processIdentifier
        self.fileDescriptor = fileDescriptor
        self.openFlags = openFlags
        self.offset = offset
        self.device = device
        self.inode = inode
        self.mode = mode
        self.originalPath = originalPath
    }
}

public struct DurableChunkReference: Codable, Hashable, Sendable {
    public let hash: String
    public let artifactName: String?
    public let logicalBytes: UInt64
    public let storedBytes: UInt64
    public let compression: DurableChunkCompression

    public init(
        hash: String,
        artifactName: String? = nil,
        logicalBytes: UInt64,
        storedBytes: UInt64,
        compression: DurableChunkCompression
    ) {
        self.hash = hash
        self.artifactName = artifactName
        self.logicalBytes = logicalBytes
        self.storedBytes = storedBytes
        self.compression = compression
    }
}

public enum DurableChunkCompression: String, Codable, Hashable, Sendable {
    case none
    case lzfse
}
