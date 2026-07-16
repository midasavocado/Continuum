import Foundation

/// Versioned, pointer-free description of a process-tree checkpoint. Large
/// byte ranges live in encrypted content-addressed chunks referenced here.
public struct DurableCheckpointImage: Codable, Hashable, Sendable {
    public static let currentFormatVersion = 5

    public let formatVersion: Int
    public let checkpointID: CheckpointID
    public let createdAt: Date
    public let architecture: String
    public let operatingSystemBuild: String
    public let pageSize: UInt64
    public let rootProcessIdentifier: Int32
    public let rootProcessIdentifiers: [Int32]?
    public let app: AppIdentity
    public let members: [DurableProcessImage]
    public let writableFiles: [DurableFileImage]
    public let writableFileDescriptors: [DurableWritableFileDescriptor]
    public let establishedTCPEndpoints: [DurableTCPEndpoint]?
    public let ptyDescriptors: [DurablePTYDescriptor]?
    public let descriptorGraph: DurableDescriptorGraph?

    public init(
        formatVersion: Int = Self.currentFormatVersion,
        checkpointID: CheckpointID,
        createdAt: Date,
        architecture: String,
        operatingSystemBuild: String,
        pageSize: UInt64,
        rootProcessIdentifier: Int32,
        rootProcessIdentifiers: [Int32]? = nil,
        app: AppIdentity,
        members: [DurableProcessImage],
        writableFiles: [DurableFileImage],
        writableFileDescriptors: [DurableWritableFileDescriptor] = [],
        establishedTCPEndpoints: [DurableTCPEndpoint]? = nil,
        ptyDescriptors: [DurablePTYDescriptor]? = nil,
        descriptorGraph: DurableDescriptorGraph? = nil
    ) {
        self.formatVersion = formatVersion
        self.checkpointID = checkpointID
        self.createdAt = createdAt
        self.architecture = architecture
        self.operatingSystemBuild = operatingSystemBuild
        self.pageSize = pageSize
        self.rootProcessIdentifier = rootProcessIdentifier
        self.rootProcessIdentifiers = rootProcessIdentifiers
        self.app = app
        self.members = members
        self.writableFiles = writableFiles
        self.writableFileDescriptors = writableFileDescriptors
        self.establishedTCPEndpoints = establishedTCPEndpoints
        self.ptyDescriptors = ptyDescriptors
        self.descriptorGraph = descriptorGraph
    }
}

/// A normalized description of descriptor ownership and kernel resources.
/// Multiple handles may reference the same resource ID, preserving `dup` aliasing
/// without serializing the same underlying socket, pipe, or kqueue more than once.
public struct DurableDescriptorGraph: Codable, Hashable, Sendable {
    public let handles: [DurableDescriptorHandle]
    public let sockets: [DurableSocketResource]
    public let pipes: [DurablePipeResource]
    public let kqueues: [DurableKqueueResource]

    public init(
        handles: [DurableDescriptorHandle],
        sockets: [DurableSocketResource],
        pipes: [DurablePipeResource],
        kqueues: [DurableKqueueResource]
    ) {
        self.handles = handles
        self.sockets = sockets
        self.pipes = pipes
        self.kqueues = kqueues
    }
}

public struct DurableDescriptorHandle: Codable, Hashable, Sendable {
    public let resourceID: UUID
    public let processIdentifier: Int32
    public let fileDescriptor: Int32
    public let descriptorFlags: Int32
    public let statusFlags: Int32

    public init(
        resourceID: UUID,
        processIdentifier: Int32,
        fileDescriptor: Int32,
        descriptorFlags: Int32,
        statusFlags: Int32
    ) {
        self.resourceID = resourceID
        self.processIdentifier = processIdentifier
        self.fileDescriptor = fileDescriptor
        self.descriptorFlags = descriptorFlags
        self.statusFlags = statusFlags
    }
}

public enum DurableSocketKind: String, Codable, Hashable, Sendable {
    case tcpListener
    case tcpConnected
    case unixListener
    case unixConnected
}

public struct DurableSocketOption: Codable, Hashable, Sendable {
    public let level: Int32
    public let name: Int32
    public let value: Data

    public init(level: Int32, name: Int32, value: Data) {
        self.level = level
        self.name = name
        self.value = value
    }
}

public struct DurableSocketResource: Codable, Hashable, Sendable {
    public let id: UUID
    public let kind: DurableSocketKind
    public let domain: Int32
    public let type: Int32
    public let `protocol`: Int32
    public let localAddress: Data?
    public let remoteAddress: Data?
    public let backlog: Int32?
    public let receiveQueueBytes: UInt64
    public let sendQueueBytes: UInt64
    public let receiveShutdown: Bool
    public let sendShutdown: Bool
    public let peerResourceID: UUID?
    public let listenerResourceID: UUID?
    public let externalPath: String?
    public let options: [DurableSocketOption]

    public init(
        id: UUID,
        kind: DurableSocketKind,
        domain: Int32,
        type: Int32,
        protocol: Int32,
        localAddress: Data? = nil,
        remoteAddress: Data? = nil,
        backlog: Int32? = nil,
        receiveQueueBytes: UInt64,
        sendQueueBytes: UInt64,
        receiveShutdown: Bool,
        sendShutdown: Bool,
        peerResourceID: UUID? = nil,
        listenerResourceID: UUID? = nil,
        externalPath: String? = nil,
        options: [DurableSocketOption] = []
    ) {
        self.id = id
        self.kind = kind
        self.domain = domain
        self.type = type
        self.protocol = `protocol`
        self.localAddress = localAddress
        self.remoteAddress = remoteAddress
        self.backlog = backlog
        self.receiveQueueBytes = receiveQueueBytes
        self.sendQueueBytes = sendQueueBytes
        self.receiveShutdown = receiveShutdown
        self.sendShutdown = sendShutdown
        self.peerResourceID = peerResourceID
        self.listenerResourceID = listenerResourceID
        self.externalPath = externalPath
        self.options = options
    }
}

public struct DurablePipeResource: Codable, Hashable, Sendable {
    public let id: UUID
    public let peerResourceID: UUID
    public let capacity: UInt64
    public let queuedBytes: UInt64
    public let status: UInt32
    public let payload: DurableChunkReference?

    public init(
        id: UUID,
        peerResourceID: UUID,
        capacity: UInt64,
        queuedBytes: UInt64,
        status: UInt32,
        payload: DurableChunkReference? = nil
    ) {
        self.id = id
        self.peerResourceID = peerResourceID
        self.capacity = capacity
        self.queuedBytes = queuedBytes
        self.status = status
        self.payload = payload
    }
}

public struct DurableKqueueResource: Codable, Hashable, Sendable {
    public let id: UUID
    public let processIdentifier: Int32
    public let registrations: [DurableKqueueRegistration]

    public init(
        id: UUID,
        processIdentifier: Int32,
        registrations: [DurableKqueueRegistration]
    ) {
        self.id = id
        self.processIdentifier = processIdentifier
        self.registrations = registrations
    }
}

public struct DurableKqueueRegistration: Codable, Hashable, Sendable {
    public let ident: UInt64
    public let filter: Int16
    public let flags: UInt16
    public let fflags: UInt32
    public let data: Int64
    public let udata: UInt64
    public let qos: UInt32
    public let savedData: Int64
    public let status: UInt32

    public init(
        ident: UInt64,
        filter: Int16,
        flags: UInt16,
        fflags: UInt32,
        data: Int64,
        udata: UInt64,
        qos: UInt32,
        savedData: Int64,
        status: UInt32
    ) {
        self.ident = ident
        self.filter = filter
        self.flags = flags
        self.fflags = fflags
        self.data = data
        self.udata = udata
        self.qos = qos
        self.savedData = savedData
        self.status = status
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
    public let topology: DurableProcessTopology?
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
        topology: DurableProcessTopology? = nil,
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
        self.topology = topology
        self.regions = regions
        self.threads = threads
    }
}

public struct DurableProcessTopology: Codable, Hashable, Sendable {
    public let processGroupIdentifier: Int32
    public let sessionIdentifier: Int32
    public let controllingTerminalDevice: UInt32
    public let foregroundProcessGroupIdentifier: Int32

    public init(
        processGroupIdentifier: Int32,
        sessionIdentifier: Int32,
        controllingTerminalDevice: UInt32,
        foregroundProcessGroupIdentifier: Int32
    ) {
        self.processGroupIdentifier = processGroupIdentifier
        self.sessionIdentifier = sessionIdentifier
        self.controllingTerminalDevice = controllingTerminalDevice
        self.foregroundProcessGroupIdentifier = foregroundProcessGroupIdentifier
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
    public let isAppOwnedState: Bool?
    public let preservesLiveDerivedGraphics: Bool?
    public let chunks: [DurableChunkReference]

    public init(
        address: UInt64,
        length: UInt64,
        protection: Int32,
        maximumProtection: Int32,
        inheritance: Int32,
        shareMode: UInt32,
        userTag: UInt32,
        isAppOwnedState: Bool? = nil,
        preservesLiveDerivedGraphics: Bool? = nil,
        chunks: [DurableChunkReference]
    ) {
        self.address = address
        self.length = length
        self.protection = protection
        self.maximumProtection = maximumProtection
        self.inheritance = inheritance
        self.shareMode = shareMode
        self.userTag = userTag
        self.isAppOwnedState = isAppOwnedState
        self.preservesLiveDerivedGraphics = preservesLiveDerivedGraphics
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

/// Pointer-free metadata for one established TCP descriptor captured while
/// its owning process forest was coherently suspended. Native sockaddr bytes
/// are preserved verbatim so a future restorer can pair local peers without
/// depending on kernel-private socket objects.
public struct DurableTCPEndpoint: Codable, Hashable, Sendable {
    public let processIdentifier: Int32
    public let fileDescriptor: Int32
    public let domain: Int32
    public let socketType: Int32
    public let socketProtocol: Int32
    public let tcpState: Int32
    public let socketState: UInt32
    public let localAddressLength: UInt32
    public let remoteAddressLength: UInt32
    public let localAddress: [UInt8]
    public let remoteAddress: [UInt8]
    public let receiveQueueBytes: UInt64
    public let sendQueueBytes: UInt64
    public let receiveShutdown: Bool
    public let sendShutdown: Bool

    public init(
        processIdentifier: Int32,
        fileDescriptor: Int32,
        domain: Int32,
        socketType: Int32,
        socketProtocol: Int32,
        tcpState: Int32,
        socketState: UInt32,
        localAddressLength: UInt32,
        remoteAddressLength: UInt32,
        localAddress: [UInt8],
        remoteAddress: [UInt8],
        receiveQueueBytes: UInt64,
        sendQueueBytes: UInt64,
        receiveShutdown: Bool,
        sendShutdown: Bool
    ) {
        self.processIdentifier = processIdentifier
        self.fileDescriptor = fileDescriptor
        self.domain = domain
        self.socketType = socketType
        self.socketProtocol = socketProtocol
        self.tcpState = tcpState
        self.socketState = socketState
        self.localAddressLength = localAddressLength
        self.remoteAddressLength = remoteAddressLength
        self.localAddress = localAddress
        self.remoteAddress = remoteAddress
        self.receiveQueueBytes = receiveQueueBytes
        self.sendQueueBytes = sendQueueBytes
        self.receiveShutdown = receiveShutdown
        self.sendShutdown = sendShutdown
    }
}

public enum DurablePTYRole: String, Codable, Hashable, Sendable {
    case master
    case slave
}

/// Pointer-free PTY descriptor metadata captured at the same frozen resource
/// cut as process RAM. Native termios/winsize bytes are valid only for the
/// matching macOS build already pinned by `DurableCheckpointImage`.
public struct DurablePTYDescriptor: Codable, Hashable, Sendable {
    public let processIdentifier: Int32
    public let fileDescriptor: Int32
    public let openFlags: UInt32
    public let role: DurablePTYRole
    public let device: UInt64
    public let inode: UInt64
    public let rawDevice: UInt64
    public let deviceMajor: UInt32
    public let deviceMinor: UInt32
    public let ttyIndex: UInt32
    public let aliasIdentity: UInt64
    public let inputQueueBytes: UInt64?
    public let outputQueueBytes: UInt64?
    public let terminalAttributes: [UInt8]?
    public let windowSize: [UInt8]?

    public init(
        processIdentifier: Int32,
        fileDescriptor: Int32,
        openFlags: UInt32,
        role: DurablePTYRole,
        device: UInt64,
        inode: UInt64,
        rawDevice: UInt64,
        deviceMajor: UInt32,
        deviceMinor: UInt32,
        ttyIndex: UInt32,
        aliasIdentity: UInt64,
        inputQueueBytes: UInt64? = nil,
        outputQueueBytes: UInt64? = nil,
        terminalAttributes: [UInt8]? = nil,
        windowSize: [UInt8]? = nil
    ) {
        self.processIdentifier = processIdentifier
        self.fileDescriptor = fileDescriptor
        self.openFlags = openFlags
        self.role = role
        self.device = device
        self.inode = inode
        self.rawDevice = rawDevice
        self.deviceMajor = deviceMajor
        self.deviceMinor = deviceMinor
        self.ttyIndex = ttyIndex
        self.aliasIdentity = aliasIdentity
        self.inputQueueBytes = inputQueueBytes
        self.outputQueueBytes = outputQueueBytes
        self.terminalAttributes = terminalAttributes
        self.windowSize = windowSize
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
