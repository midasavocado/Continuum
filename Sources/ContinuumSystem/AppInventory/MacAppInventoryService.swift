import AppKit
import Darwin
import Foundation
import ContinuumCore

public struct MacAppInventoryService: AppInventoryProviding, Sendable {
    private let applicationDirectories: [URL]

    public init(applicationDirectories: [URL]? = nil) {
        self.applicationDirectories = applicationDirectories ?? Self.defaultApplicationDirectories
    }

    public func runningApplications() async -> [ProcessDescriptor] {
        let seeds = await MainActor.run {
            NSWorkspace.shared.runningApplications.compactMap { application -> RunningApplicationSeed? in
                guard
                    application.activationPolicy != .prohibited,
                    !application.isTerminated,
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
        return await Task.detached(priority: .utility) {
            let inspector = AppBundleInspector()
            var seenPaths = Set<String>()
            var apps: [AppIdentity] = []

            for bundleURL in Self.applicationBundleURLs(in: directories) {
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
