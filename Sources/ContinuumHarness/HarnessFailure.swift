import Foundation

enum HarnessFailure: LocalizedError {
    case usage(String)
    case runtime(operation: String, status: String)
    case invariant(String)

    var errorDescription: String? {
        switch self {
        case let .usage(message):
            message
        case let .runtime(operation, status):
            "Runtime operation '\(operation)' failed with status \(status)."
        case let .invariant(message):
            "Proof failed: \(message)"
        }
    }
}
