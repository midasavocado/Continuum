import ContinuumCore
import Foundation
import Testing
@testable import ContinuumApp

@Suite("Rewind timeline selection")
struct RewindTimelineSelectionTests {
    @Test("Newest saved moment is selected when the overlay opens")
    @MainActor
    func selectsNewestMoment() {
        let old = makeSnapshot(name: "Old", seconds: 10)
        let newest = makeSnapshot(name: "Newest", seconds: 30)
        let middle = makeSnapshot(name: "Middle", seconds: 20)
        let selection = RewindTimelineSelection()

        selection.prepare(
            snapshots: [middle, newest, old],
            stepMilliseconds: 1_000
        )

        #expect(selection.selectedSnapshotID == newest.id)
    }

    @Test("Left and Right honor the configured timeline step")
    @MainActor
    func arrowStep() {
        let zero = makeSnapshot(name: "Zero", seconds: 0)
        let half = makeSnapshot(name: "Half", seconds: 0.5)
        let onePointTwo = makeSnapshot(name: "One point two", seconds: 1.2)
        let newest = makeSnapshot(name: "Newest", seconds: 2.4)
        let selection = RewindTimelineSelection()
        selection.prepare(
            snapshots: [zero, half, onePointTwo, newest],
            stepMilliseconds: 1_000
        )

        selection.move(.backward)
        #expect(selection.selectedSnapshotID == onePointTwo.id)

        selection.move(.backward)
        #expect(selection.selectedSnapshotID == zero.id)

        selection.move(.forward)
        #expect(selection.selectedSnapshotID == onePointTwo.id)
    }

    @Test("Unavailable moments can be inspected but cannot be committed")
    @MainActor
    func unavailableCannotCommit() {
        let available = makeSnapshot(
            name: "Available",
            seconds: 10,
            availability: .instant
        )
        let unavailable = makeSnapshot(
            name: "Metadata only",
            seconds: 20,
            availability: .unavailable
        )
        let selection = RewindTimelineSelection()
        selection.prepare(
            snapshots: [available, unavailable],
            stepMilliseconds: 1_000
        )

        #expect(selection.selectedSnapshotID == unavailable.id)
        #expect(!selection.canCommit)

        selection.select(available.id)
        #expect(selection.canCommit)
    }

    @Test("Moments are ordered chronologically with stable name ordering for ties")
    @MainActor
    func chronologicalOrdering() {
        let late = makeSnapshot(name: "Late", seconds: 30)
        let tieB = makeSnapshot(name: "B moment", seconds: 10)
        let tieA = makeSnapshot(name: "A moment", seconds: 10)
        let selection = RewindTimelineSelection()

        selection.prepare(
            snapshots: [late, tieB, tieA],
            stepMilliseconds: 1_000
        )

        #expect(selection.snapshots.map(\.name) == ["A moment", "B moment", "Late"])
    }

    private func makeSnapshot(
        name: String,
        seconds: TimeInterval,
        availability: RestoreAvailability = .instant
    ) -> SnapshotRecord {
        let date = Date(timeIntervalSinceReferenceDate: seconds)
        let app = AppIdentity(
            bundleIdentifier: "com.example.fixture",
            displayName: "Fixture",
            bundleURL: URL(fileURLWithPath: "/Applications/Fixture.app"),
            executableURL: URL(fileURLWithPath: "/Applications/Fixture.app/Contents/MacOS/Fixture"),
            version: "1",
            signingIdentifier: "com.example.fixture",
            teamIdentifier: "EXAMPLE",
            isApplePlatformBinary: false
        )
        let checkpoint = CheckpointRecord(
            capturedAt: date,
            monotonicNanoseconds: UInt64(max(seconds, 0) * 1_000_000_000),
            processIdentifiers: [42],
            memoryRegionCount: 2,
            threadCount: 1,
            validation: .valid
        )
        return SnapshotRecord(
            name: name,
            kind: .manual,
            app: app,
            checkpoint: checkpoint,
            branchID: UUID(),
            createdAt: date,
            availability: availability
        )
    }
}
