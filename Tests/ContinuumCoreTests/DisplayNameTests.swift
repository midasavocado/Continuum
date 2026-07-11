import XCTest
@testable import ContinuumCore

final class DisplayNameTests: XCTestCase {
    func testSnapshotKindDisplayNamesAreConsumerFacing() {
        XCTAssertEqual(SnapshotKind.manual.displayName, "Manual")
        XCTAssertEqual(SnapshotKind.beforeRewind.displayName, "Before Rewind")
        XCTAssertEqual(SnapshotKind.crashRecovery.displayName, "Crash Recovery")
        XCTAssertEqual(SnapshotKind.automatic.displayName, "Automatic")
    }

    func testRestoreAvailabilityDisplayNamesAreConsumerFacing() {
        XCTAssertEqual(RestoreAvailability.instant.displayName, "Instant")
        XCTAssertEqual(RestoreAvailability.experimentalHot.displayName, "Experimental Hot")
        XCTAssertEqual(RestoreAvailability.replayRequired.displayName, "Replay required")
        XCTAssertEqual(RestoreAvailability.unavailable.displayName, "Unavailable")
    }

    func testCompatibilityTierDisplayNamesAreConsumerFacing() {
        XCTAssertEqual(CompatibilityTier.directPlugin.displayName, "Direct")
        XCTAssertEqual(CompatibilityTier.launchInjection.displayName, "Launch injection")
        XCTAssertEqual(CompatibilityTier.managedInstrumentation.displayName, "Managed instrumentation")
        XCTAssertEqual(CompatibilityTier.protectedBridge.displayName, "Protected bridge")
        XCTAssertEqual(CompatibilityTier.unsupported.displayName, "Not rewindable")
    }

    func testEveryCaseHasANonemptyUniqueDisplayName() {
        assertUniqueNonempty(SnapshotKind.allCases.map(\.displayName))
        assertUniqueNonempty(RestoreAvailability.allCases.map(\.displayName))
        assertUniqueNonempty(CompatibilityTier.allCases.map(\.displayName))
    }

    func testNavigationAndFilterTitlesAreConsumerFacing() {
        XCTAssertEqual(ContinuumSection.allCases.map(\.title), [
            "Restore", "Snapshots", "Branches", "Apps", "Storage",
        ])
        XCTAssertEqual(SnapshotFilter.allCases.map(\.title), [
            "All", "Manual", "Before Rewind", "Crash Recovery",
        ])
        assertUniqueNonempty(ContinuumSection.allCases.map(\.systemImage))
    }

    private func assertUniqueNonempty(
        _ names: [String],
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertFalse(names.contains(where: { $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }), file: file, line: line)
        XCTAssertEqual(Set(names).count, names.count, file: file, line: line)
    }
}
