import Darwin
import Foundation

@main
struct ContinuumExternalTargetMain {
    static func main() {
        do {
            try TargetServer().run()
        } catch {
            let message = "ContinuumExternalTarget: \(error.localizedDescription)\n"
            FileHandle.standardError.write(Data(message.utf8))
            exit(EXIT_FAILURE)
        }
    }
}

private final class TargetServer {
    private let pageSize: Int
    private let arena: UnsafeMutableRawPointer
    private let encoder: JSONEncoder
    private let decoder = JSONDecoder()

    init() throws {
        pageSize = Int(sysconf(_SC_PAGESIZE))
        guard pageSize > 0 else {
            throw TargetFailure("could not determine the host page size")
        }

        let allocation = mmap(
            nil,
            pageSize,
            PROT_READ | PROT_WRITE,
            MAP_ANON | MAP_PRIVATE,
            -1,
            0
        )
        guard allocation != MAP_FAILED, let allocation else {
            throw TargetFailure("private page mapping failed with errno \(errno)")
        }
        arena = allocation

        encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        write(.a)
    }

    deinit {
        arena.initializeMemory(as: UInt8.self, repeating: 0, count: pageSize)
        munmap(arena, pageSize)
    }

    func run() throws {
        try send(reply(event: "ready", command: nil))

        while let line = readLine(strippingNewline: true) {
            guard let data = line.data(using: .utf8) else {
                try send(.error("command was not UTF-8"))
                continue
            }

            let command: TargetCommand
            do {
                command = try decoder.decode(TargetCommand.self, from: data)
            } catch {
                try send(.error("invalid command JSON: \(error.localizedDescription)"))
                continue
            }

            switch command.command {
            case "describe":
                try send(reply(event: "described", command: command.command))
            case "mutate":
                guard let requested = ArenaState(rawValue: command.state ?? "") else {
                    try send(.error("mutate requires state A or B", command: command.command))
                    continue
                }
                write(requested)
                try send(reply(event: "mutated", command: command.command))
            case "validate":
                guard let expected = ArenaState(rawValue: command.state ?? "") else {
                    try send(.error("validate requires state A or B", command: command.command))
                    continue
                }
                let actual = currentState()
                let matches = validate(expected)
                try send(TargetReply(
                    protocolVersion: 1,
                    event: "validated",
                    command: command.command,
                    processIdentifier: getpid(),
                    address: UInt64(UInt(bitPattern: arena)),
                    length: pageSize,
                    state: actual?.rawValue ?? "unknown",
                    counter: currentCounter(),
                    digest: digest(currentBytes()),
                    expectedState: expected.rawValue,
                    valid: matches,
                    error: matches ? nil : "arena bytes do not match state \(expected.rawValue)"
                ))
            case "exit":
                try send(reply(event: "exiting", command: command.command))
                return
            default:
                try send(.error("unknown command: \(command.command)", command: command.command))
            }
        }
    }

    private func write(_ state: ArenaState) {
        let bytes = expectedBytes(for: state)
        bytes.withUnsafeBytes { source in
            arena.copyMemory(from: source.baseAddress!, byteCount: pageSize)
        }
    }

    private func validate(_ state: ArenaState) -> Bool {
        currentBytes() == expectedBytes(for: state)
    }

    private func currentState() -> ArenaState? {
        if validate(.a) { return .a }
        if validate(.b) { return .b }
        return nil
    }

    private func currentCounter() -> UInt64 {
        currentBytes().withUnsafeBytes { bytes in
            bytes.loadUnaligned(fromByteOffset: 16, as: UInt64.self).littleEndian
        }
    }

    private func currentBytes() -> Data {
        Data(bytes: arena, count: pageSize)
    }

    private func expectedBytes(for state: ArenaState) -> Data {
        var bytes = Data(count: pageSize)
        let multiplier: Int = state == .a ? 31 : 73
        let offset: Int = state == .a ? 17 : 91
        for index in bytes.indices {
            bytes[index] = UInt8(truncatingIfNeeded: index &* multiplier &+ offset)
        }

        bytes.replaceSubrange(0..<8, with: Data("CTMSTATE".utf8))
        bytes[8] = state == .a ? 0x41 : 0x42
        var counter = (state == .a ? UInt64(111) : UInt64(222)).littleEndian
        withUnsafeBytes(of: &counter) { counterBytes in
            bytes.replaceSubrange(16..<24, with: counterBytes)
        }
        return bytes
    }

    private func reply(event: String, command: String?) -> TargetReply {
        let bytes = currentBytes()
        return TargetReply(
            protocolVersion: 1,
            event: event,
            command: command,
            processIdentifier: getpid(),
            address: UInt64(UInt(bitPattern: arena)),
            length: pageSize,
            state: currentState()?.rawValue ?? "unknown",
            counter: currentCounter(),
            digest: digest(bytes),
            expectedState: nil,
            valid: nil,
            error: nil
        )
    }

    private func digest(_ data: Data) -> String {
        var value: UInt64 = 0xcbf29ce484222325
        for byte in data {
            value ^= UInt64(byte)
            value &*= 0x100000001b3
        }
        return String(format: "%016llx", value)
    }

    private func send(_ reply: TargetReply) throws {
        var data = try encoder.encode(reply)
        data.append(0x0A)
        try FileHandle.standardOutput.write(contentsOf: data)
    }
}

private enum ArenaState: String {
    case a = "A"
    case b = "B"
}

private struct TargetCommand: Codable {
    let command: String
    let state: String?
}

private struct TargetReply: Codable {
    let protocolVersion: Int?
    let event: String
    let command: String?
    let processIdentifier: Int32?
    let address: UInt64?
    let length: Int?
    let state: String?
    let counter: UInt64?
    let digest: String?
    let expectedState: String?
    let valid: Bool?
    let error: String?

    static func error(_ message: String, command: String? = nil) -> Self {
        TargetReply(
            protocolVersion: 1,
            event: "error",
            command: command,
            processIdentifier: getpid(),
            address: nil,
            length: nil,
            state: nil,
            counter: nil,
            digest: nil,
            expectedState: nil,
            valid: false,
            error: message
        )
    }
}

private struct TargetFailure: LocalizedError {
    let message: String

    init(_ message: String) {
        self.message = message
    }

    var errorDescription: String? { message }
}
