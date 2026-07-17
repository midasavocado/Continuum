import AppKit
import Darwin
import Foundation
import ContinuumCore

public struct MacAppInventoryService: AppInventoryProviding, Sendable {
    private let applicationDirectories: [URL]
    private let includesSpotlightApplications: Bool

    public init(applicationDirectories: [URL]? = nil) {
        self.applicationDirectories = applicationDirectories ?? Self.defaultApplicationDirectories
        self.includesSpotlightApplications = applicationDirectories == nil
    }

    public func runningApplications() async -> [ProcessDescriptor] {
        let visibleWindowOwners = await Task.detached(priority: .utility) {
            Self.visibleWindowOwnerProcessIdentifiers()
        }.value

        let seeds = await MainActor.run {
            NSWorkspace.shared.runningApplications.compactMap { application -> RunningApplicationSeed? in
                guard
                    !application.isTerminated,
                    let executableURL = application.executableURL,
                    application.activationPolicy != .prohibited
                        || visibleWindowOwners.contains(application.processIdentifier)
                else {
                    return nil
                }

                return RunningApplicationSeed(
                    processIdentifier: application.processIdentifier,
                    bundleIdentifier: application.bundleIdentifier,
                    displayName: application.localizedName,
                    bundleURL: application.bundleURL,
                    executableURL: executableURL,
                    isFrontmost: application.isActive,
                    isTerminated: application.isTerminated
                )
            }
        }

        let inspector = AppBundleInspector()
        let processParents = Self.processParentMap()
        return seeds.map { seed in
            let inspected = seed.bundleURL.flatMap { inspector.inspect(bundleURL: $0) }
            let app: AppIdentity
            if let inspected {
                app = inspected.identity
            } else {
                let fallbackSignature = inspector.signatureMetadata(for: seed.executableURL)
                app = AppIdentity(
                    bundleIdentifier: seed.bundleIdentifier,
                    displayName: seed.displayName ?? seed.executableURL.deletingPathExtension().lastPathComponent,
                    bundleURL: seed.bundleURL,
                    executableURL: seed.executableURL,
                    version: nil,
                    signingIdentifier: fallbackSignature.signingIdentifier,
                    teamIdentifier: fallbackSignature.teamIdentifier,
                    isApplePlatformBinary: fallbackSignature.isApplePlatformBinary
                )
            }

            return ProcessDescriptor(
                processIdentifier: seed.processIdentifier,
                parentProcessIdentifier: processParents[seed.processIdentifier] ?? 0,
                app: app,
                isFrontmost: seed.isFrontmost,
                isTerminated: seed.isTerminated
            )
        }
        .sorted { left, right in
            if left.isFrontmost != right.isFrontmost { return left.isFrontmost }
            return left.app.displayName.localizedCaseInsensitiveCompare(right.app.displayName) == .orderedAscending
        }
    }

    public func installedApplications() async -> [AppIdentity] {
        let directories = applicationDirectories
        let includesSpotlightApplications = includesSpotlightApplications
        return await Task.detached(priority: .utility) {
            let inspector = AppBundleInspector()
            var seenPaths = Set<String>()
            var apps: [AppIdentity] = []

            var bundleURLs = Self.applicationBundleURLs(in: directories)
            if includesSpotlightApplications {
                bundleURLs.append(contentsOf: Self.spotlightApplicationBundleURLs())
            }

            for bundleURL in bundleURLs {
                let path = bundleURL.standardizedFileURL.path
                guard seenPaths.insert(path).inserted,
                      let app = inspector.inspect(bundleURL: bundleURL)?.identity else {
                    continue
                }
                apps.append(app)
            }

            return apps.sorted {
                let nameOrder = $0.displayName.localizedCaseInsensitiveCompare($1.displayName)
                if nameOrder != .orderedSame { return nameOrder == .orderedAscending }
                return $0.executableURL.path < $1.executableURL.path
            }
        }.value
    }

    public func frontmostApplication() async -> ProcessDescriptor? {
        let seed = await MainActor.run { () -> RunningApplicationSeed? in
            guard
                let application = NSWorkspace.shared.frontmostApplication,
                let executableURL = application.executableURL
            else {
                return nil
            }

            return RunningApplicationSeed(
                processIdentifier: application.processIdentifier,
                bundleIdentifier: application.bundleIdentifier,
                displayName: application.localizedName,
                bundleURL: application.bundleURL,
                executableURL: executableURL,
                isFrontmost: true,
                isTerminated: application.isTerminated
            )
        }

        guard let seed else { return nil }
        let inspector = AppBundleInspector()
        let signature = inspector.signatureMetadata(for: seed.bundleURL ?? seed.executableURL)
        let app = seed.bundleURL.flatMap { inspector.inspect(bundleURL: $0)?.identity } ?? AppIdentity(
            bundleIdentifier: seed.bundleIdentifier,
            displayName: seed.displayName ?? seed.executableURL.deletingPathExtension().lastPathComponent,
            bundleURL: seed.bundleURL,
            executableURL: seed.executableURL,
            version: nil,
            signingIdentifier: signature.signingIdentifier,
            teamIdentifier: signature.teamIdentifier,
            isApplePlatformBinary: signature.isApplePlatformBinary
        )

        return ProcessDescriptor(
            processIdentifier: seed.processIdentifier,
            parentProcessIdentifier: Self.parentProcessIdentifier(for: seed.processIdentifier),
            app: app,
            isFrontmost: true,
            isTerminated: seed.isTerminated
        )
    }

    public func application(at url: URL) async -> AppIdentity? {
        await Task.detached(priority: .utility) {
            let inspector = AppBundleInspector()
            let standardizedURL = url.standardizedFileURL

            if let bundleURL = Self.enclosingApplicationBundleURL(for: standardizedURL),
               let identity = inspector.inspect(bundleURL: bundleURL)?.identity {
                return identity
            }

            guard FileManager.default.isExecutableFile(atPath: standardizedURL.path) else {
                return nil
            }

            let signature = inspector.signatureMetadata(for: standardizedURL)
            return AppIdentity(
                bundleIdentifier: nil,
                displayName: standardizedURL.deletingPathExtension().lastPathComponent,
                bundleURL: nil,
                executableURL: standardizedURL,
                version: nil,
                signingIdentifier: signature.signingIdentifier,
                teamIdentifier: signature.teamIdentifier,
                isApplePlatformBinary: signature.isApplePlatformBinary
            )
        }.value
    }

    public func compatibility(for app: AppIdentity) async -> CompatibilityReport {
        AppCompatibilityClassifier().report(for: app)
    }

    public func processIdentifiers(inTreeRootedAt rootProcessIdentifier: Int32) async -> [Int32] {
        await Task.detached(priority: .utility) {
            let parents = Self.processParentMap()
            var result: [Int32] = [rootProcessIdentifier]
            var frontier: [Int32] = [rootProcessIdentifier]
            var seen: Set<Int32> = [rootProcessIdentifier]

            while let parent = frontier.popLast() {
                let children = parents.compactMap { process, recordedParent in
                    recordedParent == parent ? process : nil
                }
                for child in children where seen.insert(child).inserted {
                    result.append(child)
                    frontier.append(child)
                }
            }

            return result.sorted()
        }.value
    }

    /// Returns the process-tree roots needed for one coherent capture. Besides
    /// the selected app, this follows established loopback TCP, connected Unix
    /// socket, and pipe peers owned by the same user, then lifts each peer to
    /// the top of its launchd-owned tree.
    /// The runtime expands every returned root to its descendants at the cut.
    public func captureRootProcessIdentifiers(
        rootedAt rootProcessIdentifier: Int32
    ) async -> [Int32] {
        await Task.detached(priority: .utility) {
            let parents = Self.processParentMap()
            let userIdentifiers = Self.processUserIdentifierMap()
            let sessions = Self.processSessionIdentifierMap(
                processIdentifiers: parents.keys
            )
            guard let selectedUserIdentifier = userIdentifiers[rootProcessIdentifier] else {
                return [rootProcessIdentifier]
            }

            return Self.dependencyRoots(
                rootProcessIdentifier: rootProcessIdentifier,
                selectedUserIdentifier: selectedUserIdentifier,
                parents: parents,
                userIdentifiers: userIdentifiers,
                sessions: sessions,
                connections: Self.establishedLoopbackConnections(),
                kernelPeers: Self.kernelPeerEndpoints(
                    processIdentifiers: parents.keys
                )
            )
        }.value
    }

    /// Resolves the session leader behind a terminal-emulator window without
    /// treating the emulator itself as authoritative application state.
    public func terminalWorkloadRootProcessIdentifier(
        descendedFrom presentationProcessIdentifier: Int32,
        ttyPath: String
    ) async -> Int32? {
        await Task.detached(priority: .utility) {
            var terminalStatus = stat()
            guard ttyPath.withCString({ lstat($0, &terminalStatus) }) == 0 else {
                return nil
            }
            let terminalDevice = UInt32(truncatingIfNeeded: terminalStatus.st_rdev)
            let parents = Self.processParentMap()
            let descendants = Self.descendants(
                of: [presentationProcessIdentifier],
                parents: parents
            ).subtracting([presentationProcessIdentifier])
            let sessions = Dictionary(uniqueKeysWithValues: descendants.compactMap {
                processIdentifier -> (Int32, Int32)? in
                let sessionIdentifier = getsid(processIdentifier)
                return sessionIdentifier > 0
                    ? (processIdentifier, sessionIdentifier)
                    : nil
            })
            let terminalState = Self.processTerminalStateMap()
            return Self.terminalWorkloadRoot(
                descendants: descendants,
                sessions: sessions,
                terminalDevices: terminalState.mapValues(\.terminalDevice),
                processGroups: terminalState.mapValues(\.processGroup),
                foregroundProcessGroups: terminalState.mapValues(\.foregroundProcessGroup),
                selectedTerminalDevice: terminalDevice
            )
        }.value
    }

    static func terminalWorkloadRoot(
        descendants: Set<Int32>,
        sessions: [Int32: Int32],
        terminalDevices: [Int32: UInt32],
        processGroups: [Int32: Int32] = [:],
        foregroundProcessGroups: [Int32: Int32] = [:],
        selectedTerminalDevice: UInt32
    ) -> Int32? {
        let matchingProcesses = descendants.filter {
            terminalDevices[$0] == selectedTerminalDevice
        }
        let sessionLeaders = matchingProcesses.filter {
            sessions[$0] == $0
        }
        if sessionLeaders.count == 1 {
            return sessionLeaders.first
        }
        let matchingSessions = Set(matchingProcesses.compactMap { sessions[$0] })
        let descendedLeaders = matchingSessions.filter { descendants.contains($0) }
        if descendedLeaders.count == 1 {
            return descendedLeaders.first
        }

        // A foreground job identifies the active session, but it is not a
        // restorable tree root: the shell/session leader owns that job and any
        // other process groups in the selected tab.
        let foregroundGroups = Set(matchingProcesses.compactMap {
            foregroundProcessGroups[$0]
        }.filter { $0 > 0 })
        guard foregroundGroups.count == 1,
              let foregroundGroup = foregroundGroups.first else {
            return nil
        }
        let foregroundSessions = Set(matchingProcesses.compactMap {
            processGroups[$0] == foregroundGroup ? sessions[$0] : nil
        })
        let foregroundSessionLeaders = foregroundSessions.filter {
            descendants.contains($0)
        }
        return foregroundSessionLeaders.count == 1
            ? foregroundSessionLeaders.first
            : nil
    }

    static func dependencyRoots(
        rootProcessIdentifier: Int32,
        selectedUserIdentifier: UInt32,
        parents: [Int32: Int32],
        userIdentifiers: [Int32: UInt32],
        sessions: [Int32: Int32] = [:],
        connections: [LoopbackConnection],
        kernelPeers: [KernelPeerEndpoint] = []
    ) -> [Int32] {
        var roots: Set<Int32> = [rootProcessIdentifier]
        var changed = true
        while changed {
            changed = false
            let members = Self.descendants(of: roots, parents: parents)
            var peerProcessIdentifiers = Set<Int32>()

            for connection in connections where members.contains(connection.processIdentifier) {
                guard let peer = connections.first(where: {
                    $0.processIdentifier != connection.processIdentifier
                        && $0.localEndpoint == connection.remoteEndpoint
                        && $0.remoteEndpoint == connection.localEndpoint
                }) else {
                    continue
                }
                peerProcessIdentifiers.insert(peer.processIdentifier)
            }

            for endpoint in kernelPeers where members.contains(endpoint.processIdentifier) {
                let candidates = Set(kernelPeers.lazy.filter {
                    $0.kind == endpoint.kind
                        && $0.processIdentifier != endpoint.processIdentifier
                        && $0.localHandle == endpoint.peerHandle
                        && $0.peerHandle == endpoint.localHandle
                }.map(\.processIdentifier))
                guard candidates.count == 1, let peer = candidates.first else {
                    continue
                }
                peerProcessIdentifiers.insert(peer)
            }

            for peerProcessIdentifier in peerProcessIdentifiers
            where !members.contains(peerProcessIdentifier)
                && userIdentifiers[peerProcessIdentifier] == selectedUserIdentifier {
                let peerRoot = Self.sameUserTreeRoot(
                    for: peerProcessIdentifier,
                    selectedUserIdentifier: selectedUserIdentifier,
                    parents: parents,
                    userIdentifiers: userIdentifiers,
                    sessions: sessions
                )
                if roots.insert(peerRoot).inserted {
                    changed = true
                }
            }
        }

        return [rootProcessIdentifier]
            + roots.filter { $0 != rootProcessIdentifier }.sorted()
    }

    private static var defaultApplicationDirectories: [URL] {
        let userApplications = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Applications", isDirectory: true)
        return [
            URL(fileURLWithPath: "/Applications", isDirectory: true),
            userApplications,
            URL(fileURLWithPath: "/System/Applications", isDirectory: true)
        ]
    }

    private static func applicationBundleURLs(in directories: [URL]) -> [URL] {
        var results: [URL] = []
        let keys: Set<URLResourceKey> = [.isDirectoryKey, .isPackageKey, .isSymbolicLinkKey]

        for directory in directories {
            if directory.pathExtension.lowercased() == "app" {
                results.append(directory)
                continue
            }

            // FileManager's recursive enumerator intentionally does not follow
            // symlinks. Modern macOS exposes apps such as Safari as a top-level
            // symlink into a cryptex, so inspect top-level package entries first.
            if let topLevelNames = try? FileManager.default.contentsOfDirectory(atPath: directory.path) {
                results.append(contentsOf: topLevelNames.compactMap { name in
                    guard !name.hasPrefix("."),
                          URL(fileURLWithPath: name).pathExtension.lowercased() == "app" else {
                        return nil
                    }
                    return directory.appendingPathComponent(name, isDirectory: true)
                })
            }

            guard let enumerator = FileManager.default.enumerator(
                at: directory,
                includingPropertiesForKeys: Array(keys),
                options: [.skipsHiddenFiles],
                errorHandler: { _, _ in true }
            ) else {
                continue
            }

            for case let url as URL in enumerator {
                if url.pathExtension.lowercased() == "app" {
                    results.append(url)
                    enumerator.skipDescendants()
                }
            }
        }

        return results
    }

    private static func spotlightApplicationBundleURLs() -> [URL] {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/mdfind")
        process.arguments = ["kMDItemContentType == \"com.apple.application-bundle\""]
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
        } catch {
            return []
        }

        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { return [] }

        return String(decoding: data, as: UTF8.self)
            .split(whereSeparator: \.isNewline)
            .map(String.init)
            .filter(isTopLevelApplicationBundlePath)
            .map { URL(fileURLWithPath: $0, isDirectory: true) }
    }

    private static func isTopLevelApplicationBundlePath(_ path: String) -> Bool {
        guard path.hasSuffix(".app") else { return false }

        let components = URL(fileURLWithPath: path).pathComponents.dropLast()
        return !components.contains { $0.lowercased().hasSuffix(".app") }
    }

    private static func enclosingApplicationBundleURL(for url: URL) -> URL? {
        var candidate = url
        while candidate.path != "/" {
            if candidate.pathExtension.lowercased() == "app" {
                return candidate
            }
            candidate.deleteLastPathComponent()
        }
        return nil
    }

    private static func visibleWindowOwnerProcessIdentifiers() -> Set<Int32> {
        let options: CGWindowListOption = [.optionOnScreenOnly, .excludeDesktopElements]
        guard let windows = CGWindowListCopyWindowInfo(options, kCGNullWindowID)
            as? [[CFString: Any]] else {
            return []
        }

        return Set(windows.compactMap { window in
            guard let processIdentifier = window[kCGWindowOwnerPID] as? NSNumber,
                  let layer = window[kCGWindowLayer] as? NSNumber,
                  layer.intValue == 0 else {
                return nil
            }
            return processIdentifier.int32Value
        })
    }

    private static func parentProcessIdentifier(for processIdentifier: Int32) -> Int32 {
        processParentMap()[processIdentifier] ?? 0
    }

    private static func processParentMap() -> [Int32: Int32] {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL]
        var byteCount = 0
        guard sysctl(&mib, u_int(mib.count), nil, &byteCount, nil, 0) == 0,
              byteCount >= MemoryLayout<kinfo_proc>.stride else {
            return [:]
        }

        let count = byteCount / MemoryLayout<kinfo_proc>.stride
        var processes = [kinfo_proc](repeating: kinfo_proc(), count: count)
        guard sysctl(&mib, u_int(mib.count), &processes, &byteCount, nil, 0) == 0 else {
            return [:]
        }

        let actualCount = min(count, byteCount / MemoryLayout<kinfo_proc>.stride)
        return Dictionary(uniqueKeysWithValues: processes.prefix(actualCount).map {
            ($0.kp_proc.p_pid, $0.kp_eproc.e_ppid)
        })
    }

    private static func processUserIdentifierMap() -> [Int32: UInt32] {
        let processIdentifiers = processParentMap().keys
        return Dictionary(uniqueKeysWithValues: processIdentifiers.compactMap { processIdentifier in
            var info = proc_bsdinfo()
            let byteCount = proc_pidinfo(
                processIdentifier,
                PROC_PIDTBSDINFO,
                0,
                &info,
                Int32(MemoryLayout<proc_bsdinfo>.size)
            )
            guard byteCount == MemoryLayout<proc_bsdinfo>.size else { return nil }
            return (processIdentifier, info.pbi_uid)
        })
    }

    private static func kernelPeerEndpoints<S: Sequence>(
        processIdentifiers: S
    ) -> [KernelPeerEndpoint] where S.Element == Int32 {
        var endpoints = Set<KernelPeerEndpoint>()
        for processIdentifier in processIdentifiers {
            let requiredBytes = proc_pidinfo(
                processIdentifier,
                PROC_PIDLISTFDS,
                0,
                nil,
                0
            )
            guard requiredBytes > 0 else { continue }
            let extraCapacity = 16 * MemoryLayout<proc_fdinfo>.stride
            var descriptors = [proc_fdinfo](
                repeating: proc_fdinfo(),
                count: (Int(requiredBytes) + extraCapacity)
                    / MemoryLayout<proc_fdinfo>.stride
            )
            let returnedBytes = descriptors.withUnsafeMutableBytes { buffer in
                proc_pidinfo(
                    processIdentifier,
                    PROC_PIDLISTFDS,
                    0,
                    buffer.baseAddress,
                    Int32(buffer.count)
                )
            }
            guard returnedBytes > 0,
                  returnedBytes % Int32(MemoryLayout<proc_fdinfo>.stride) == 0 else {
                continue
            }

            let descriptorCount = Int(returnedBytes)
                / MemoryLayout<proc_fdinfo>.stride
            for descriptor in descriptors.prefix(descriptorCount) {
                switch descriptor.proc_fdtype {
                case UInt32(PROX_FDTYPE_SOCKET):
                    var info = socket_fdinfo()
                    let bytes = proc_pidfdinfo(
                        processIdentifier,
                        descriptor.proc_fd,
                        PROC_PIDFDSOCKETINFO,
                        &info,
                        Int32(MemoryLayout<socket_fdinfo>.size)
                    )
                    let unixInfo = info.psi.soi_proto.pri_un
                    guard bytes == MemoryLayout<socket_fdinfo>.size,
                          info.psi.soi_family == AF_UNIX,
                          info.psi.soi_kind == SOCKINFO_UN,
                          info.psi.soi_state & Int16(SOI_S_ISCONNECTED) != 0,
                          info.psi.soi_so != 0,
                          unixInfo.unsi_conn_so != 0 else {
                        continue
                    }
                    endpoints.insert(
                        KernelPeerEndpoint(
                            processIdentifier: processIdentifier,
                            kind: .unixSocket,
                            localHandle: info.psi.soi_so,
                            peerHandle: unixInfo.unsi_conn_so
                        )
                    )
                case UInt32(PROX_FDTYPE_PIPE):
                    var info = pipe_fdinfo()
                    let bytes = proc_pidfdinfo(
                        processIdentifier,
                        descriptor.proc_fd,
                        PROC_PIDFDPIPEINFO,
                        &info,
                        Int32(MemoryLayout<pipe_fdinfo>.size)
                    )
                    guard bytes == MemoryLayout<pipe_fdinfo>.size,
                          info.pipeinfo.pipe_handle != 0,
                          info.pipeinfo.pipe_peerhandle != 0 else {
                        continue
                    }
                    endpoints.insert(
                        KernelPeerEndpoint(
                            processIdentifier: processIdentifier,
                            kind: .pipe,
                            localHandle: info.pipeinfo.pipe_handle,
                            peerHandle: info.pipeinfo.pipe_peerhandle
                        )
                    )
                default:
                    continue
                }
            }
        }
        return endpoints.sorted {
            if $0.processIdentifier != $1.processIdentifier {
                return $0.processIdentifier < $1.processIdentifier
            }
            if $0.kind != $1.kind { return $0.kind.rawValue < $1.kind.rawValue }
            if $0.localHandle != $1.localHandle { return $0.localHandle < $1.localHandle }
            return $0.peerHandle < $1.peerHandle
        }
    }

    private static func processSessionIdentifierMap<S: Sequence>(
        processIdentifiers: S
    ) -> [Int32: Int32] where S.Element == Int32 {
        Dictionary(uniqueKeysWithValues: processIdentifiers.compactMap {
            processIdentifier in
            let sessionIdentifier = getsid(processIdentifier)
            return sessionIdentifier > 0
                ? (processIdentifier, sessionIdentifier)
                : nil
        })
    }

    private static func processTerminalStateMap() -> [Int32: (
        terminalDevice: UInt32,
        processGroup: Int32,
        foregroundProcessGroup: Int32
    )] {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL]
        var byteCount = 0
        guard sysctl(&mib, u_int(mib.count), nil, &byteCount, nil, 0) == 0,
              byteCount >= MemoryLayout<kinfo_proc>.stride else {
            return [:]
        }
        let capacity = byteCount / MemoryLayout<kinfo_proc>.stride
        var processes = [kinfo_proc](repeating: kinfo_proc(), count: capacity)
        guard sysctl(&mib, u_int(mib.count), &processes, &byteCount, nil, 0) == 0 else {
            return [:]
        }
        let count = min(capacity, byteCount / MemoryLayout<kinfo_proc>.stride)
        return Dictionary(uniqueKeysWithValues: processes.prefix(count).map {
            (
                $0.kp_proc.p_pid,
                (
                    terminalDevice: UInt32(truncatingIfNeeded: $0.kp_eproc.e_tdev),
                    processGroup: $0.kp_eproc.e_pgid,
                    foregroundProcessGroup: $0.kp_eproc.e_tpgid
                )
            )
        })
    }

    private static func descendants(
        of roots: Set<Int32>,
        parents: [Int32: Int32]
    ) -> Set<Int32> {
        var result = roots
        var changed = true
        while changed {
            changed = false
            for (processIdentifier, parentProcessIdentifier) in parents
            where result.contains(parentProcessIdentifier) && result.insert(processIdentifier).inserted {
                changed = true
            }
        }
        return result
    }

    private static func sameUserTreeRoot(
        for processIdentifier: Int32,
        selectedUserIdentifier: UInt32,
        parents: [Int32: Int32],
        userIdentifiers: [Int32: UInt32],
        sessions: [Int32: Int32]
    ) -> Int32 {
        var candidate = processIdentifier
        let sessionIdentifier = sessions[processIdentifier]
        while let parent = parents[candidate],
              parent > 1,
              userIdentifiers[parent] == selectedUserIdentifier,
              sessionIdentifier == nil || sessions[parent] == sessionIdentifier {
            candidate = parent
        }
        return candidate
    }

    static func parseLoopbackConnections(_ output: String) -> [LoopbackConnection] {
        var currentProcessIdentifier: Int32?
        var connections: [LoopbackConnection] = []
        for line in output.split(whereSeparator: \.isNewline) {
            guard let prefix = line.first else { continue }
            let value = String(line.dropFirst())
            switch prefix {
            case "p":
                currentProcessIdentifier = Int32(value)
            case "n":
                guard let currentProcessIdentifier,
                      let arrow = value.range(of: "->") else { continue }
                let local = String(value[..<arrow.lowerBound])
                let remote = String(value[arrow.upperBound...])
                guard isLoopbackEndpoint(local), isLoopbackEndpoint(remote) else { continue }
                connections.append(
                    LoopbackConnection(
                        processIdentifier: currentProcessIdentifier,
                        localEndpoint: local,
                        remoteEndpoint: remote
                    )
                )
            default:
                continue
            }
        }
        return connections
    }

    private static func establishedLoopbackConnections() -> [LoopbackConnection] {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        process.arguments = ["-nP", "-a", "-iTCP", "-sTCP:ESTABLISHED", "-Fpn"]
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else { return [] }
            return parseLoopbackConnections(
                String(decoding: data, as: UTF8.self)
            )
        } catch {
            return []
        }
    }

    private static func isLoopbackEndpoint(_ endpoint: String) -> Bool {
        endpoint.hasPrefix("127.") || endpoint.hasPrefix("[::1]:")
    }
}

struct LoopbackConnection: Hashable, Sendable {
    let processIdentifier: Int32
    let localEndpoint: String
    let remoteEndpoint: String
}

struct KernelPeerEndpoint: Hashable, Sendable {
    enum Kind: UInt8, Hashable, Sendable {
        case unixSocket
        case pipe
    }

    let processIdentifier: Int32
    let kind: Kind
    let localHandle: UInt64
    let peerHandle: UInt64
}

private struct RunningApplicationSeed: Sendable {
    let processIdentifier: Int32
    let bundleIdentifier: String?
    let displayName: String?
    let bundleURL: URL?
    let executableURL: URL
    let isFrontmost: Bool
    let isTerminated: Bool
}
