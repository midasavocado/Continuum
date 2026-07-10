import ContinuumCore

enum ProcessGroupResolver {
    static func identifiers(
        rootedAt root: ProcessDescriptor,
        among processes: [ProcessDescriptor]
    ) -> [Int32] {
        let liveProcesses = processes.filter { !$0.isTerminated }
        var childrenByParent: [Int32: [Int32]] = [:]

        for process in liveProcesses {
            childrenByParent[process.parentProcessIdentifier, default: []]
                .append(process.processIdentifier)
        }

        var pending = [root.processIdentifier]
        var included = Set<Int32>()

        while let processIdentifier = pending.popLast() {
            guard included.insert(processIdentifier).inserted else { continue }
            pending.append(contentsOf: childrenByParent[processIdentifier, default: []])
        }

        return included.sorted()
    }

    static func identifiers(
        for snapshot: SnapshotRecord,
        among processes: [ProcessDescriptor]
    ) -> [Int32]? {
        guard let root = root(for: snapshot, among: processes) else { return nil }
        return identifiers(rootedAt: root, among: processes)
    }

    static func root(
        for snapshot: SnapshotRecord,
        among processes: [ProcessDescriptor]
    ) -> ProcessDescriptor? {
        let liveProcesses = processes.filter { !$0.isTerminated }
        let priorIdentifiers = Set(snapshot.checkpoint.processIdentifiers)
        let matchingProcesses = liveProcesses.filter { $0.app.id == snapshot.app.id }

        return matchingProcesses.first(where: {
            priorIdentifiers.contains($0.processIdentifier)
        }) ?? matchingProcesses.first(where: \.isFrontmost)
            ?? rootProcess(in: matchingProcesses)
    }

    private static func rootProcess(in candidates: [ProcessDescriptor]) -> ProcessDescriptor? {
        let candidateIdentifiers = Set(candidates.map(\.processIdentifier))
        return candidates.first(where: {
            !candidateIdentifiers.contains($0.parentProcessIdentifier)
        }) ?? candidates.min(by: { $0.processIdentifier < $1.processIdentifier })
    }
}
