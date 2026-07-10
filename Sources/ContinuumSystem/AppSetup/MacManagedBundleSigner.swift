import Foundation
import ContinuumCore

struct FoundationAppSetupCommandRunner: AppSetupCommandRunning {
    func run(executableURL: URL, arguments: [String]) throws -> AppSetupCommandResult {
        let process = Process()
        let standardOutput = Pipe()
        let standardError = Pipe()
        process.executableURL = executableURL
        process.arguments = arguments
        process.standardOutput = standardOutput
        process.standardError = standardError

        try process.run()
        process.waitUntilExit()

        return AppSetupCommandResult(
            terminationStatus: process.terminationStatus,
            standardOutput: standardOutput.fileHandleForReading.readDataToEndOfFile(),
            standardError: standardError.fileHandleForReading.readDataToEndOfFile()
        )
    }
}

struct MacManagedBundleSigner: ManagedBundleSigning {
    private let runner: any AppSetupCommandRunning

    init(runner: any AppSetupCommandRunning = FoundationAppSetupCommandRunner()) {
        self.runner = runner
    }

    func sign(bundleURL: URL, entitlementsURL: URL) throws {
        let arguments = [
            "--force",
            "--sign", "-",
            "--entitlements", entitlementsURL.path,
            bundleURL.path
        ]
        let result = try runner.run(
            executableURL: URL(fileURLWithPath: "/usr/bin/codesign"),
            arguments: arguments
        )
        guard result.terminationStatus == 0 else {
            let detail = String(data: result.standardError, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines)
            throw AppSetupError.operationFailed(
                detail.flatMap { $0.isEmpty ? nil : $0 }
                    ?? "codesign exited with status \(result.terminationStatus)."
            )
        }
    }
}
