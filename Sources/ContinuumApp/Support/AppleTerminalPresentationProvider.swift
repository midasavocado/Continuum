import AppKit
import ContinuumCore
import CryptoKit
import Foundation

enum AppleTerminalPresentationProvider {
    static let bundleIdentifier = "com.apple.Terminal"

    @MainActor
    static func openRewindableSession() throws {
        guard let bootstrapURL = Bundle.main.privateFrameworksURL?
                .appendingPathComponent("libContinuumBootstrap.dylib"),
              FileManager.default.fileExists(atPath: bootstrapURL.path) else {
            throw ContinuumError.runtimeUnsupported(
                "Continuum's checkpoint runtime is missing."
            )
        }
        let shellURL = try prepareManagedShell()
        let managedExecURL = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Helpers/ContinuumManagedExec")
        guard FileManager.default.isExecutableFile(atPath: managedExecURL.path) else {
            throw ContinuumError.runtimeUnsupported(
                "Continuum's managed command helper is missing."
            )
        }
        let inheritedPath = ProcessInfo.processInfo.environment["PATH"]
            ?? "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        let originalPath = effectiveOriginalPath(inheritedPath: inheritedPath)
        let wrappers = try prepareCommandWrappers(
            managedExecURL: managedExecURL,
            originalPath: originalPath,
            fallbackDirectories: []
        )
        let environment = [
            "CONTINUUM_ENABLE_CHECKPOINT_SAFEPOINTS=1",
            "CONTINUUM_DETERMINISTIC_ADDRESS_SPACE=1",
            "DYLD_SHARED_REGION=private",
            "MallocLargeCache=0",
            "PROMPT=Continuum %~ %# "
        ] + terminalPathEnvironment(wrappers: wrappers, originalPath: originalPath) + [
            "DYLD_INSERT_LIBRARIES=\(bootstrapURL.path)"
        ]
        let command = "exec /usr/bin/env "
            + environment.map(shellQuote).joined(separator: " ")
            + " \(shellQuote(shellURL.path)) -d -f"
        try runTerminalScript(command)
    }

    @MainActor
    static func selectedTTYPath() throws -> String {
        let source = "tell application \"Terminal\" to get tty of selected tab of front window"
        guard let script = NSAppleScript(source: source) else {
            throw ContinuumError.runtimeUnsupported(
                "Continuum could not prepare Terminal automation."
            )
        }
        var details: NSDictionary?
        let result = script.executeAndReturnError(&details)
        guard let path = result.stringValue,
              path.hasPrefix("/dev/tty") else {
            let message = details?[NSAppleScript.errorMessage] as? String
                ?? "Terminal did not expose the selected tab's TTY."
            throw ContinuumError.runtimeUnsupported(message)
        }
        return path
    }

    @MainActor
    static func openRelay(socketPath: String) throws {
        let relayURL = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Helpers/ContinuumTerminalRelay")
        guard FileManager.default.isExecutableFile(atPath: relayURL.path) else {
            throw ContinuumError.runtimeUnsupported(
                "Continuum's Terminal relay helper is missing."
            )
        }
        let command = "exec \(shellQuote(relayURL.path)) --socket \(shellQuote(socketPath))"
        try runTerminalScript(command)
    }

    @MainActor
    private static func runTerminalScript(_ command: String) throws {
        let source = "tell application \"Terminal\" to do script \(appleScriptLiteral(command))"
        guard let script = NSAppleScript(source: source) else {
            throw ContinuumError.runtimeUnsupported(
                "Continuum could not prepare the Terminal relay command."
            )
        }
        var details: NSDictionary?
        _ = script.executeAndReturnError(&details)
        if let details {
            let message = details[NSAppleScript.errorMessage] as? String
                ?? "Terminal did not open the restored session."
            throw ContinuumError.runtimeUnsupported(message)
        }
    }

    private static func prepareManagedShell() throws -> URL {
        let source = URL(fileURLWithPath: "/bin/zsh")
        let base = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        ).appendingPathComponent("Continuum/Terminal", isDirectory: true)
        return try prepareManagedShell(source: source, base: base, signer: signManagedShell)
    }

    static func prepareManagedShell(
        source: URL,
        base: URL,
        signer: (URL) throws -> Void
    ) throws -> URL {
        try FileManager.default.createDirectory(
            at: base,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: NSNumber(value: 0o700)]
        )
        let temporary = base.appendingPathComponent(".ContinuumZsh-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: temporary) }
        try FileManager.default.copyItem(at: source, to: temporary)

        let sourceBytes = try Data(contentsOf: temporary, options: .mappedIfSafe)
        let identity = SHA256.hash(data: sourceBytes)
            .map { String(format: "%02x", $0) }
            .joined()
        let destination = base.appendingPathComponent("ContinuumZsh-\(identity)")
        if FileManager.default.fileExists(atPath: destination.path) {
            return destination
        }

        try signer(temporary)
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: 0o500)],
            ofItemAtPath: temporary.path
        )

        do {
            try FileManager.default.moveItem(at: temporary, to: destination)
        } catch let error as CocoaError where error.code == .fileWriteFileExists {
            // Another preparation installed these same source bytes first.
            return destination
        }
        return destination
    }

    private static func signManagedShell(_ shell: URL) throws {
        let signer = Process()
        signer.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        signer.arguments = ["--force", "--sign", "-", shell.path]
        let errorPipe = Pipe()
        signer.standardError = errorPipe
        try signer.run()
        signer.waitUntilExit()
        guard signer.terminationStatus == 0 else {
            let detail = String(
                data: errorPipe.fileHandleForReading.readDataToEndOfFile(),
                encoding: .utf8
            )?.trimmingCharacters(in: .whitespacesAndNewlines)
            throw ContinuumError.runtimeUnsupported(
                detail?.isEmpty == false
                    ? detail!
                    : "Continuum could not prepare its private shell copy."
            )
        }
    }

    static func prepareCommandWrappers(
        managedExecURL: URL,
        originalPath: String,
        base providedBase: URL? = nil,
        fallbackDirectories: [String] = ["/opt/homebrew/bin", "/usr/local/bin"]
    ) throws -> URL {
        let base = try providedBase ?? FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        ).appendingPathComponent("Continuum/Terminal", isDirectory: true)
        let wrappers = base.appendingPathComponent("CommandWrappers", isDirectory: true)
        try? FileManager.default.removeItem(at: wrappers)
        try FileManager.default.createDirectory(
            at: wrappers,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: NSNumber(value: 0o700)]
        )

        var searchDirectories: [String] = []
        var seenDirectories: Set<String> = []
        for directory in originalPath.split(separator: ":").map(String.init)
            + fallbackDirectories
        where seenDirectories.insert(directory).inserted {
            searchDirectories.append(directory)
        }
        let serviceWrapper = wrappers.appendingPathComponent("continuum-with-service")
        let serviceScript = "#!/bin/zsh\nexec \(shellQuote(managedExecURL.path)) --continuum-with-service \"$@\"\n"
        try serviceScript.write(to: serviceWrapper, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: 0o700)],
            ofItemAtPath: serviceWrapper.path
        )

        var installedNames: Set<String> = [serviceWrapper.lastPathComponent]
        for directory in searchDirectories {
            guard let entries = try? FileManager.default.contentsOfDirectory(
                at: URL(fileURLWithPath: directory, isDirectory: true),
                includingPropertiesForKeys: nil
            ) else { continue }
            for entry in entries.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
                let name = entry.lastPathComponent
                guard !name.isEmpty,
                      !name.contains("/"),
                      !installedNames.contains(name),
                      FileManager.default.isExecutableFile(atPath: entry.path) else {
                    continue
                }
                let source = entry.resolvingSymlinksInPath()
                guard isMachOExecutable(source) else { continue }
                let script = "#!/bin/zsh\nexec \(shellQuote(managedExecURL.path)) \(shellQuote(source.path)) \"$@\"\n"
                let destination = wrappers.appendingPathComponent(name)
                try script.write(to: destination, atomically: true, encoding: .utf8)
                try FileManager.default.setAttributes(
                    [.posixPermissions: NSNumber(value: 0o700)],
                    ofItemAtPath: destination.path
                )
                installedNames.insert(name)
            }
        }
        return wrappers
    }

    static func effectiveOriginalPath(
        inheritedPath: String,
        fallbackDirectories: [String] = ["/opt/homebrew/bin", "/usr/local/bin"]
    ) -> String {
        var seen: Set<String> = []
        return (inheritedPath.split(separator: ":").map(String.init) + fallbackDirectories)
            .filter { $0.hasPrefix("/") && seen.insert($0).inserted }
            .joined(separator: ":")
    }

    static func terminalPathEnvironment(wrappers: URL, originalPath: String) -> [String] {
        [
            "CONTINUUM_ORIGINAL_PATH=\(originalPath)",
            "PATH=\(wrappers.path):\(originalPath)"
        ]
    }

    private static func isMachOExecutable(_ url: URL) -> Bool {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return false }
        defer { try? handle.close() }
        guard let data = try? handle.read(upToCount: 4),
              data.count == 4 else { return false }
        let magic = data.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
        return [
            UInt32(MH_MAGIC), UInt32(MH_CIGAM),
            UInt32(MH_MAGIC_64), UInt32(MH_CIGAM_64),
            UInt32(FAT_MAGIC), UInt32(FAT_CIGAM),
            UInt32(FAT_MAGIC_64), UInt32(FAT_CIGAM_64)
        ].contains(magic)
    }

    private static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private static func appleScriptLiteral(_ value: String) -> String {
        let escaped = value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        return "\"\(escaped)\""
    }
}
