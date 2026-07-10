import ContinuumSystem

protocol ProcessTreeProviding: Sendable {
    func processIdentifiers(inTreeRootedAt rootProcessIdentifier: Int32) async -> [Int32]
}

// MacAppInventoryService can see command-line/helper descendants that
// NSWorkspace does not expose as applications. Keep that richer System surface
// available without widening ContinuumCore's UI-neutral inventory protocol.
extension MacAppInventoryService: ProcessTreeProviding {}
