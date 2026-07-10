import Foundation

public enum ExternalEffectKind: String, Codable, CaseIterable, Sendable {
    case networkRequest
    case sentMessage
    case upload
    case purchase
    case cloudMutation
    case exportedFile
    case unknown
}

public struct ExternalEffect: Codable, Hashable, Identifiable, Sendable {
    public let id: UUID
    public let occurredAt: Date
    public let destination: String
    public let kind: ExternalEffectKind
    public let summary: String

    public init(
        id: UUID = UUID(),
        occurredAt: Date = .now,
        destination: String,
        kind: ExternalEffectKind,
        summary: String
    ) {
        self.id = id
        self.occurredAt = occurredAt
        self.destination = destination
        self.kind = kind
        self.summary = summary
    }
}

public enum RestoreResult: Sendable, Equatable {
    case exactLocal
    case exactLocalWithOnlineWarning([ExternalEffect])
    case failed(String)
}
