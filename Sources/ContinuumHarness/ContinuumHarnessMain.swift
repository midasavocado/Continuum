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
            case .transactionProof:
                try await TransactionProof.run()
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
    case transactionProof
    case help

    static let usage = """
    Usage: ContinuumHarness <command>

      inspect            Print this process's VM-region and thread inventory.
      memory-proof       Checkpoint, mutate, and restore a tracked memory region.
      transaction-proof  Prove durable manual snapshots and rewind branching.
      help               Show this help.
    """

    static func parse(_ arguments: ArraySlice<String>) throws -> Self {
        guard let name = arguments.first else { return .help }
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
}
