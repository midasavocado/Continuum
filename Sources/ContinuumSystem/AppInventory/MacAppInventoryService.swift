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
