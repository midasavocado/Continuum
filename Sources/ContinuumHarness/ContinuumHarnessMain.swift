import Darwin
import Foundation

@main
struct ContinuumHarnessMain {
    static func main() async {
        do {
            let command = try HarnessCommand.parse(CommandLine.arguments.dropFirst())

            switch command {
            case .inspect:
                try RuntimeProof.inspect()
            case .memoryProof:
                try RuntimeProof.runMemoryProof()
            case let .descriptorFlagsProof(target, bootstrap):
                try RuntimeProof.runDescriptorFlagsProof(
                    targetPath: target,
                    bootstrapPath: bootstrap
                )
            case .transactionProof:
                try await TransactionProof.run()
            case let .externalHotProof(target, cycles):
                try await ExternalHotProof.run(targetPath: target, cycles: cycles)
            case let .guiColdProof(target):
                try await GUIColdProof.run(targetPath: target)
            case let .setupApp(target, root, checkOnly):
                try await ManagedAppSetupCommand.run(
                    targetPath: target,
                    rootPath: root,
                    checkOnly: checkOnly
                )
            case .help:
                print(HarnessCommand.usage)
            }
        } catch {
            writeToStandardError("ContinuumHarness: \(error.localizedDescription)\n")
            writeToStandardError("\n\(HarnessCommand.usage)\n")
            exit(EXIT_FAILURE)
        }
    }

    private static func writeToStandardError(_ message: String) {
        guard let data = message.data(using: .utf8) else { return }
        FileHandle.standardError.write(data)
    }
}

private enum HarnessCommand: Equatable {
    case inspect
    case memoryProof
    case descriptorFlagsProof(target: String, bootstrap: String)
    case transactionProof
    case externalHotProof(target: String, cycles: Int)
    case guiColdProof(target: String)
    case setupApp(target: String, root: String?, checkOnly: Bool)
    case help

    static let usage = """
    Usage: ContinuumHarness <command>

      inspect            Print this process's VM-region and thread inventory.
      memory-proof       Checkpoint, mutate, and restore a tracked memory region.
      descriptor-flags-proof --target <path> --bootstrap <dylib>
                         Prove authenticated descriptor flags at a CLI safepoint.
      transaction-proof  Prove durable manual snapshots and rewind branching.
      external-hot-proof --target <path> [--cycles <n>]
                         Rewind the included cooperative proof target at least 100 times.
      gui-cold-proof --target <path>
                         Kill and cold-restore a real AppKit window into a new PID.
      setup-app --target <path> [--root <path>] [--check-only]
                         Run the same generic managed-copy setup used by the app.
      help               Show this help.
    """

    static func parse(_ arguments: ArraySlice<String>) throws -> Self {
        guard let name = arguments.first else { return .help }

        if name == "external-hot-proof" {
            return try parseExternalHotProof(arguments.dropFirst())
        }
        if name == "descriptor-flags-proof" {
            return try parseDescriptorFlagsProof(arguments.dropFirst())
        }
        if name == "gui-cold-proof" {
            return try parseGUIColdProof(arguments.dropFirst())
        }
        if name == "setup-app" {
            return try parseSetupApp(arguments.dropFirst())
        }

        guard arguments.dropFirst().isEmpty else {
            throw HarnessFailure.usage("Unexpected argument: \(arguments.dropFirst().first!)")
        }

        return switch name {
        case "inspect": .inspect
        case "memory-proof": .memoryProof
        case "transaction-proof": .transactionProof
        case "help", "--help", "-h": .help
        default: throw HarnessFailure.usage("Unknown command: \(name)")
        }
    }

    private static func parseDescriptorFlagsProof(
        _ arguments: ArraySlice<String>
    ) throws -> Self {
        let values = Array(arguments)
        var target: String?
        var bootstrap: String?
        var index = 0
        while index < values.count {
            let option = values[index]
            index += 1
            guard index < values.count else {
                throw HarnessFailure.usage("\(option) requires a path")
            }
            switch option {
            case "--target" where target == nil:
                target = values[index]
            case "--bootstrap" where bootstrap == nil:
                bootstrap = values[index]
            default:
                throw HarnessFailure.usage(
                    "Unknown or repeated descriptor-flags-proof option: \(option)"
                )
            }
            index += 1
        }
        guard let target, let bootstrap else {
            throw HarnessFailure.usage(
                "descriptor-flags-proof requires --target and --bootstrap"
            )
        }
        return .descriptorFlagsProof(target: target, bootstrap: bootstrap)
    }

    private static func parseGUIColdProof(
        _ arguments: ArraySlice<String>
    ) throws -> Self {
        let values = Array(arguments)
        guard values.count == 2, values[0] == "--target" else {
            throw HarnessFailure.usage(
                "gui-cold-proof requires --target <path>"
            )
        }
        return .guiColdProof(target: values[1])
    }

    private static func parseExternalHotProof(_ arguments: ArraySlice<String>) throws -> Self {
        let values = Array(arguments)
        var target: String?
        var cycles = ExternalHotProof.minimumCycleCount
        var index = 0

        while index < values.count {
            let option = values[index]
            switch option {
            case "--target":
                guard target == nil else {
                    throw HarnessFailure.usage("--target may only be specified once")
                }
                index += 1
                guard index < values.count else {
                    throw HarnessFailure.usage("--target requires an executable path")
                }
                target = values[index]
            case "--cycles":
                index += 1
                guard index < values.count, let parsed = Int(values[index]) else {
                    throw HarnessFailure.usage("--cycles requires an integer")
                }
                cycles = parsed
            default:
                throw HarnessFailure.usage("Unknown external-hot-proof option: \(option)")
            }
            index += 1
        }

        guard let target else {
            throw HarnessFailure.usage("external-hot-proof requires --target <path>")
        }
        guard cycles >= ExternalHotProof.minimumCycleCount else {
            throw HarnessFailure.usage(
                "--cycles must be at least \(ExternalHotProof.minimumCycleCount)"
            )
        }
        return .externalHotProof(target: target, cycles: cycles)
    }

    private static func parseSetupApp(_ arguments: ArraySlice<String>) throws -> Self {
        let values = Array(arguments)
        var target: String?
        var root: String?
        var checkOnly = false
        var index = 0

        while index < values.count {
            switch values[index] {
            case "--target":
                index += 1
                guard index < values.count, target == nil else {
                    throw HarnessFailure.usage("--target requires one app or executable path")
                }
                target = values[index]
            case "--root":
                index += 1
                guard index < values.count, root == nil else {
                    throw HarnessFailure.usage("--root requires one setup-storage path")
                }
                root = values[index]
            case "--check-only":
                guard !checkOnly else {
                    throw HarnessFailure.usage("--check-only may only be specified once")
                }
                checkOnly = true
            default:
                throw HarnessFailure.usage("Unknown setup-app option: \(values[index])")
            }
            index += 1
        }

        guard let target else {
            throw HarnessFailure.usage("setup-app requires --target <path>")
        }
        return .setupApp(target: target, root: root, checkOnly: checkOnly)
    }
}
