import Testing
@testable import ContinuumSystem
import ContinuumCore

@Suite("Cold process restore routing")
struct ColdProcessRestorerTests {
    @Test("Two independent roots use generic forest routing")
    func independentRootsDoNotUseBrokeredPair() {
        let roots = [
            makeProcess(processIdentifier: 100, parentProcessIdentifier: 1),
            makeProcess(processIdentifier: 200, parentProcessIdentifier: 1),
        ]

        #expect(!ColdProcessRestorer.shouldUseBrokeredPair(
            roots,
            rootProcessIdentifier: 100
        ))
    }

    @Test("A root and its direct child preserve pair routing")
    func directChildUsesBrokeredPair() {
        let pair = [
            makeProcess(processIdentifier: 100, parentProcessIdentifier: 1),
            makeProcess(processIdentifier: 200, parentProcessIdentifier: 100),
        ]

        #expect(ColdProcessRestorer.shouldUseBrokeredPair(
            pair,
            rootProcessIdentifier: 100
        ))
    }

    private func makeProcess(
        processIdentifier: Int32,
        parentProcessIdentifier: Int32
    ) -> DurableProcessImage {
        DurableProcessImage(
            processIdentifier: processIdentifier,
            parentProcessIdentifier: parentProcessIdentifier,
            executableDevice: 0,
            executableInode: 0,
            vmLayoutHash: 0,
            regions: [],
            threads: []
        )
    }
}
