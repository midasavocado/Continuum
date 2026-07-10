import ContinuumSystem
import Foundation
import Observation

enum TimelineArrowStep: Int, CaseIterable, Codable, Identifiable, Sendable {
    case oneHundredMilliseconds = 100
    case twoHundredFiftyMilliseconds = 250
    case oneSecond = 1_000
    case fiveSeconds = 5_000

    var id: Int { rawValue }
    var milliseconds: Int { rawValue }

    var displayName: String {
        switch self {
        case .oneHundredMilliseconds: "100 ms"
        case .twoHundredFiftyMilliseconds: "250 ms"
        case .oneSecond: "1 second"
        case .fiveSeconds: "5 seconds"
        }
    }
}

enum ActiveCheckpointInterval: Int, CaseIterable, Codable, Identifiable, Sendable {
    case fiftyMilliseconds = 50
    case oneHundredMilliseconds = 100
    case twoHundredFiftyMilliseconds = 250
    case fiveHundredMilliseconds = 500

    var id: Int { rawValue }
    var milliseconds: Int { rawValue }
    var displayName: String { "\(rawValue) ms" }
}

enum GameCheckpointInterval: Int, CaseIterable, Codable, Identifiable, Sendable {
    case fiftyMilliseconds = 50
    case oneHundredMilliseconds = 100
    case twoHundredFiftyMilliseconds = 250

    var id: Int { rawValue }
    var milliseconds: Int { rawValue }
    var displayName: String { "\(rawValue) ms" }
}

enum IdleCheckpointInterval: Int, CaseIterable, Codable, Identifiable, Sendable {
    case oneSecond = 1_000
    case twoSeconds = 2_000
    case fiveSeconds = 5_000

    var id: Int { rawValue }
    var milliseconds: Int { rawValue }

    var displayName: String {
        switch self {
        case .oneSecond: "1 second"
        case .twoSeconds: "2 seconds"
        case .fiveSeconds: "5 seconds"
        }
    }
}

@MainActor
@Observable
final class ContinuumPreferences {
    static let rewindShortcutDidChangeNotification = Notification.Name(
        "ContinuumPreferences.rewindShortcutDidChange"
    )
    static let previousRewindShortcutPresetUserInfoKey = "previousRewindShortcutPreset"

    enum Keys {
        static let rewindShortcutPreset = "continuum.interaction.rewindShortcutPreset"
        static let timelineArrowStepMilliseconds = "continuum.interaction.timelineArrowStepMilliseconds"
        static let activeCheckpointIntervalMilliseconds = "continuum.capture.activeIntervalMilliseconds"
        static let gameCheckpointIntervalMilliseconds = "continuum.capture.gameIntervalMilliseconds"
        static let idleCheckpointIntervalMilliseconds = "continuum.capture.idleIntervalMilliseconds"
        static let hotHistorySeconds = "continuum.storage.hotSeconds"
        static let rollingHistoryMinutes = "continuum.storage.rollingMinutes"

        // This is also used by onboarding. Keep one canonical key so the two
        // surfaces cannot silently disagree about the selected budget.
        static let diskBudgetGigabytes = "continuum.storageBudgetGigabytes"

        static let legacyDiskBudgetGigabytes = "continuum.storage.budgetGigabytes"
    }

    static let hotHistoryRange = 30...600
    static let rollingHistoryRange = 5...240
    static let diskBudgetRange = 5...500

    @ObservationIgnored private let defaults: UserDefaults

    var rewindShortcutPreset: RewindShortcutPreset {
        didSet {
            guard rewindShortcutPreset != oldValue else { return }
            defaults.set(rewindShortcutPreset.rawValue, forKey: Keys.rewindShortcutPreset)
            NotificationCenter.default.post(
                name: Self.rewindShortcutDidChangeNotification,
                object: self,
                userInfo: [Self.previousRewindShortcutPresetUserInfoKey: oldValue.rawValue]
            )
        }
    }

    var timelineArrowStep: TimelineArrowStep {
        didSet {
            guard timelineArrowStep != oldValue else { return }
            defaults.set(timelineArrowStep.rawValue, forKey: Keys.timelineArrowStepMilliseconds)
        }
    }

    var activeCheckpointInterval: ActiveCheckpointInterval {
        didSet {
            guard activeCheckpointInterval != oldValue else { return }
            defaults.set(
                activeCheckpointInterval.rawValue,
                forKey: Keys.activeCheckpointIntervalMilliseconds
            )
        }
    }

    var gameCheckpointInterval: GameCheckpointInterval {
        didSet {
            guard gameCheckpointInterval != oldValue else { return }
            defaults.set(
                gameCheckpointInterval.rawValue,
                forKey: Keys.gameCheckpointIntervalMilliseconds
            )
        }
    }

    var idleCheckpointInterval: IdleCheckpointInterval {
        didSet {
            guard idleCheckpointInterval != oldValue else { return }
            defaults.set(
                idleCheckpointInterval.rawValue,
                forKey: Keys.idleCheckpointIntervalMilliseconds
            )
        }
    }

    var hotHistorySeconds: Int {
        didSet {
            let normalized = hotHistorySeconds.clamped(to: Self.hotHistoryRange)
            if hotHistorySeconds != normalized {
                hotHistorySeconds = normalized
            }
            guard normalized != oldValue else { return }
            defaults.set(normalized, forKey: Keys.hotHistorySeconds)
        }
    }

    var rollingHistoryMinutes: Int {
        didSet {
            let normalized = rollingHistoryMinutes.clamped(to: Self.rollingHistoryRange)
            if rollingHistoryMinutes != normalized {
                rollingHistoryMinutes = normalized
            }
            guard normalized != oldValue else { return }
            defaults.set(normalized, forKey: Keys.rollingHistoryMinutes)
        }
    }

    var diskBudgetGigabytes: Int {
        didSet {
            let normalized = diskBudgetGigabytes.clamped(to: Self.diskBudgetRange)
            if diskBudgetGigabytes != normalized {
                diskBudgetGigabytes = normalized
            }
            guard normalized != oldValue else { return }
            defaults.set(normalized, forKey: Keys.diskBudgetGigabytes)
        }
    }

    var rewindShortcut: GlobalShortcut {
        rewindShortcutPreset.shortcut
    }

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults

        if defaults.object(forKey: Keys.diskBudgetGigabytes) == nil,
           let legacyBudget = defaults.object(forKey: Keys.legacyDiskBudgetGigabytes) as? Int {
            defaults.set(legacyBudget, forKey: Keys.diskBudgetGigabytes)
            defaults.removeObject(forKey: Keys.legacyDiskBudgetGigabytes)
        }

        rewindShortcutPreset = Self.enumValue(
            RewindShortcutPreset.self,
            storedString: defaults.string(forKey: Keys.rewindShortcutPreset),
            fallback: .controlOptionCommandR
        )
        timelineArrowStep = Self.enumValue(
            TimelineArrowStep.self,
            storedInteger: defaults.object(forKey: Keys.timelineArrowStepMilliseconds) as? Int,
            fallback: .oneSecond
        )
        activeCheckpointInterval = Self.enumValue(
            ActiveCheckpointInterval.self,
            storedInteger: defaults.object(forKey: Keys.activeCheckpointIntervalMilliseconds) as? Int,
            fallback: .oneHundredMilliseconds
        )
        gameCheckpointInterval = Self.enumValue(
            GameCheckpointInterval.self,
            storedInteger: defaults.object(forKey: Keys.gameCheckpointIntervalMilliseconds) as? Int,
            fallback: .fiftyMilliseconds
        )
        idleCheckpointInterval = Self.enumValue(
            IdleCheckpointInterval.self,
            storedInteger: defaults.object(forKey: Keys.idleCheckpointIntervalMilliseconds) as? Int,
            fallback: .oneSecond
        )
        hotHistorySeconds = Self.integer(
            defaults,
            key: Keys.hotHistorySeconds,
            fallback: 90,
            range: Self.hotHistoryRange
        )
        rollingHistoryMinutes = Self.integer(
            defaults,
            key: Keys.rollingHistoryMinutes,
            fallback: 30,
            range: Self.rollingHistoryRange
        )
        diskBudgetGigabytes = Self.integer(
            defaults,
            key: Keys.diskBudgetGigabytes,
            fallback: 20,
            range: Self.diskBudgetRange
        )
    }

    private static func enumValue<T: RawRepresentable>(
        _ type: T.Type,
        storedString: String?,
        fallback: T
    ) -> T where T.RawValue == String {
        guard let storedString, let value = T(rawValue: storedString) else { return fallback }
        return value
    }

    private static func enumValue<T: RawRepresentable>(
        _ type: T.Type,
        storedInteger: Int?,
        fallback: T
    ) -> T where T.RawValue == Int {
        guard let storedInteger, let value = T(rawValue: storedInteger) else { return fallback }
        return value
    }

    private static func integer(
        _ defaults: UserDefaults,
        key: String,
        fallback: Int,
        range: ClosedRange<Int>
    ) -> Int {
        guard let stored = defaults.object(forKey: key) as? Int else { return fallback }
        return stored.clamped(to: range)
    }
}

private extension Comparable {
    func clamped(to range: ClosedRange<Self>) -> Self {
        min(max(self, range.lowerBound), range.upperBound)
    }
}
