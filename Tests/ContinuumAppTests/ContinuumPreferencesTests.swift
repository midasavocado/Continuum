import Foundation
import Testing
@testable import ContinuumApp
import ContinuumSystem

@Suite("Continuum preferences", .serialized)
struct ContinuumPreferencesTests {
    @Test("Consumer defaults match the product contract")
    @MainActor
    func productDefaults() {
        let (defaults, suiteName) = makeDefaults()
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let preferences = ContinuumPreferences(defaults: defaults)

        #expect(preferences.rewindShortcutPreset == .controlOptionCommandR)
        #expect(preferences.rewindShortcut == .rewind)
        #expect(preferences.timelineArrowStep == .oneSecond)
        #expect(preferences.activeCheckpointInterval == .oneHundredMilliseconds)
        #expect(preferences.gameCheckpointInterval == .fiftyMilliseconds)
        #expect(preferences.idleCheckpointInterval == .oneSecond)
        #expect(preferences.hotHistorySeconds == 90)
        #expect(preferences.rollingHistoryMinutes == 30)
        #expect(preferences.diskBudgetGigabytes == 20)
    }

    @Test("Typed values persist across preference store instances")
    @MainActor
    func persistence() {
        let (defaults, suiteName) = makeDefaults()
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let original = ContinuumPreferences(defaults: defaults)
        original.rewindShortcutPreset = .controlShiftCommandR
        original.timelineArrowStep = .twoHundredFiftyMilliseconds
        original.activeCheckpointInterval = .fiveHundredMilliseconds
        original.gameCheckpointInterval = .twoHundredFiftyMilliseconds
        original.idleCheckpointInterval = .fiveSeconds
        original.hotHistorySeconds = 180
        original.rollingHistoryMinutes = 60
        original.diskBudgetGigabytes = 75

        let restored = ContinuumPreferences(defaults: defaults)

        #expect(restored.rewindShortcutPreset == .controlShiftCommandR)
        #expect(restored.timelineArrowStep == .twoHundredFiftyMilliseconds)
        #expect(restored.activeCheckpointInterval == .fiveHundredMilliseconds)
        #expect(restored.gameCheckpointInterval == .twoHundredFiftyMilliseconds)
        #expect(restored.idleCheckpointInterval == .fiveSeconds)
        #expect(restored.hotHistorySeconds == 180)
        #expect(restored.rollingHistoryMinutes == 60)
        #expect(restored.diskBudgetGigabytes == 75)
    }

    @Test("Legacy storage budget migrates to the onboarding key")
    @MainActor
    func legacyBudgetMigration() {
        let (defaults, suiteName) = makeDefaults()
        defer { defaults.removePersistentDomain(forName: suiteName) }
        defaults.set(45, forKey: ContinuumPreferences.Keys.legacyDiskBudgetGigabytes)

        let preferences = ContinuumPreferences(defaults: defaults)

        #expect(preferences.diskBudgetGigabytes == 45)
        #expect(defaults.integer(forKey: ContinuumPreferences.Keys.diskBudgetGigabytes) == 45)
        #expect(defaults.object(forKey: ContinuumPreferences.Keys.legacyDiskBudgetGigabytes) == nil)
    }

    @Test("Out-of-range retention values are clamped and persisted")
    @MainActor
    func clampsRetention() {
        let (defaults, suiteName) = makeDefaults()
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let preferences = ContinuumPreferences(defaults: defaults)

        preferences.hotHistorySeconds = 9_999
        preferences.rollingHistoryMinutes = -10
        preferences.diskBudgetGigabytes = 1_000

        #expect(preferences.hotHistorySeconds == ContinuumPreferences.hotHistoryRange.upperBound)
        #expect(preferences.rollingHistoryMinutes == ContinuumPreferences.rollingHistoryRange.lowerBound)
        #expect(preferences.diskBudgetGigabytes == ContinuumPreferences.diskBudgetRange.upperBound)
        #expect(
            defaults.integer(forKey: ContinuumPreferences.Keys.hotHistorySeconds)
                == ContinuumPreferences.hotHistoryRange.upperBound
        )
        #expect(
            defaults.integer(forKey: ContinuumPreferences.Keys.rollingHistoryMinutes)
                == ContinuumPreferences.rollingHistoryRange.lowerBound
        )
        #expect(
            defaults.integer(forKey: ContinuumPreferences.Keys.diskBudgetGigabytes)
                == ContinuumPreferences.diskBudgetRange.upperBound
        )
    }

    private func makeDefaults() -> (UserDefaults, String) {
        let suiteName = "ContinuumPreferencesTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        return (defaults, suiteName)
    }
}
