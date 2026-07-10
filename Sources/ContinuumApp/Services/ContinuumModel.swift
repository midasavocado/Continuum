import Foundation
import Observation
import ContinuumCore

@MainActor
@Observable
final class ContinuumModel {
    private static let onboardingDefaultsKey = "continuum.onboarding.completed"

    @ObservationIgnored private let repository: any SnapshotRepository
    @ObservationIgnored private let inventory: any AppInventoryProviding
    @ObservationIgnored private let permissionProvider: any PermissionProviding
    @ObservationIgnored private let checkpointCapturer: any CheckpointCapturing
    @ObservationIgnored private let defaults: UserDefaults

    private(set) var snapshots: [SnapshotRecord] = []
    private(set) var branches: [BranchRecord] = []
    private(set) var appReports: [CompatibilityReport] = []
    private(set) var runningProcesses: [ProcessDescriptor] = []
    private(set) var installedApps: [AppIdentity] = []
    private(set) var permissionStatuses: [PermissionStatus] = []

    var selectedSnapshotID: SnapshotID?
    var selectedBranchID: BranchID?
    var selectedSection: ContinuumSection = .timeline
    var snapshotFilter: SnapshotFilter = .all

    private(set) var isLoading = false
    private(set) var isPerformingAction = false
    var presentedError: String?
    var onlineWarning: [ExternalEffect]?
    private(set) var rewindPhase: RewindPhase = .idle
    private(set) var storageMetrics = StorageMetrics()
    private(set) var onboardingResetGeneration = 0

    var isOnboardingComplete: Bool {
        didSet {
            defaults.set(isOnboardingComplete, forKey: Self.onboardingDefaultsKey)
        }
    }

    @ObservationIgnored private var activeProvisional: ProvisionalRewind?
    @ObservationIgnored private var pendingTargetSnapshotID: SnapshotID?
    @ObservationIgnored private var lastRewindCommit: RewindCommit?

    init(
        repository: any SnapshotRepository,
        inventory: any AppInventoryProviding,
        permissionProvider: any PermissionProviding,
        checkpointCapturer: any CheckpointCapturing,
        defaults: UserDefaults = .standard
    ) {
        self.repository = repository
        self.inventory = inventory
        self.permissionProvider = permissionProvider
        self.checkpointCapturer = checkpointCapturer
        self.defaults = defaults
        self.isOnboardingComplete = defaults.bool(forKey: Self.onboardingDefaultsKey)
    }

    var filteredSnapshots: [SnapshotRecord] {
        snapshots.filter(snapshotFilter.includes)
    }

    var selectedSnapshot: SnapshotRecord? {
        guard let selectedSnapshotID else { return nil }
        return snapshots.first { $0.id == selectedSnapshotID }
    }

    var selectedBranch: BranchRecord? {
        guard let selectedBranchID else { return nil }
        return branches.first { $0.id == selectedBranchID }
    }

    var canUndoRewind: Bool {
        guard let lastRewindCommit else { return false }
        return snapshots.contains { $0.id == lastRewindCommit.safetySnapshotID }
            && activeProvisional == nil
    }

    func load() async {
        await refresh()
    }

    func refresh() async {
        guard !isLoading, !isPerformingAction else { return }
        isLoading = true
        presentedError = nil
        defer { isLoading = false }

        do {
            try await refreshAllState()
        } catch {
            presentedError = ErrorPresentation.message(for: error)
        }
    }

    func saveManualSnapshot() async {
        await performAction {
            try await self.ensureIndexIsLoaded()

            guard let frontmost = await self.inventory.frontmostApplication() else {
                throw ContinuumError.noFrontmostApplication
            }
            if frontmost.app.bundleIdentifier == Bundle.main.bundleIdentifier {
                throw ContinuumError.runtimeUnsupported(
                    "Continuum will not record its own control window. Switch to the app you want to inspect and press the Save Snapshot shortcut."
                )
            }

            var processes = await self.inventory.runningApplications()
            if !processes.contains(where: { $0.processIdentifier == frontmost.processIdentifier }) {
                processes.append(frontmost)
            }

            let processIdentifiers = await self.processIdentifiers(
                rootedAt: frontmost,
                among: processes
            )
            // The first snapshot bootstraps the Main branch in repositories
            // whose empty index intentionally has no branch record yet.
            let branchID = self.branchIDForNewCapture()
            let capture = try await self.checkpointCapturer.capture(
                app: frontmost.app,
                processIdentifiers: processIdentifiers,
                kind: .manual,
                branchID: branchID
            )
            let namedCapture = SnapshotCaptureNaming.applyingAutomaticName(to: capture)
            let savedSnapshot = try await self.repository.save(namedCapture)

            try await self.refreshIndex()
            self.runningProcesses = processes.sorted(by: Self.processSort)
            self.selectedSnapshotID = savedSnapshot.id
            self.selectedSection = .snapshots
        }
    }

    func beginRewind() async {
        await performAction {
            guard let targetID = self.selectedSnapshotID else {
                throw CoordinationError.noSnapshotSelected
            }
            try await self.performBeginRewind(target: targetID)
        }
    }

    func commitRewind(target targetSnapshotID: SnapshotID) async {
        await performAction {
            try await self.performCommitRewind(target: targetSnapshotID)
        }
    }

    func cancelRewind() async {
        await performAction {
            try await self.performCancelRewind()
        }
    }

    func undoRewind() async {
        await performAction {
            guard let commit = self.lastRewindCommit else {
                throw CoordinationError.rewindNotActive
            }

            let safetySnapshotID = commit.safetySnapshotID
            guard self.snapshots.contains(where: { $0.id == safetySnapshotID }) else {
                throw CoordinationError.safetySnapshotMissing
            }

            self.selectedSnapshotID = safetySnapshotID
            try await self.performBeginRewind(target: safetySnapshotID)
            try await self.performCommitRewind(target: safetySnapshotID)
        }
    }

    func rename(snapshotID: SnapshotID, to name: String) async {
        await performAction {
            let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmedName.isEmpty else {
                throw CoordinationError.snapshotNameEmpty
            }

            try await self.repository.renameSnapshot(snapshotID, to: trimmedName)
            try await self.refreshIndex()
            self.selectedSnapshotID = snapshotID
        }
    }

    func updateNote(snapshotID: SnapshotID, note: String) async {
        await performAction {
            try await self.repository.updateNote(snapshotID, note: note)
            try await self.refreshIndex()
            self.selectedSnapshotID = snapshotID
        }
    }

    func delete(snapshotID: SnapshotID) async {
        await performAction {
            if self.activeProvisional?.safetySnapshotID == snapshotID
                || self.pendingTargetSnapshotID == snapshotID {
                throw CoordinationError.snapshotUsedByActiveRewind
            }

            try await self.repository.deleteSnapshot(snapshotID)
            if self.selectedSnapshotID == snapshotID {
                self.selectedSnapshotID = nil
            }
            try await self.refreshIndex()
        }
    }

    func deleteAllSnapshotData() async {
        await performAction {
            guard self.activeProvisional == nil else {
                throw CoordinationError.rewindAlreadyActive
            }

            try await self.repository.deleteAllSnapshots()
            self.selectedSnapshotID = nil
            self.selectedBranchID = nil
            self.lastRewindCommit = nil
            self.onlineWarning = nil
            self.rewindPhase = .idle
            try await self.refreshIndex()
        }
    }

    func selectBranch(_ branchID: BranchID) async {
        await performAction {
            guard self.activeProvisional == nil else {
                throw CoordinationError.rewindAlreadyActive
            }
            guard self.branches.contains(where: { $0.id == branchID }) else {
                throw ContinuumError.branchNotFound
            }

            try await self.repository.switchBranch(to: branchID)
            try await self.refreshIndex()
            self.selectedBranchID = branchID
            self.selectedSnapshotID = self.branches
                .first(where: { $0.id == branchID })?
                .tipSnapshotID
        }
    }

    func requestPermission(_ permission: PermissionKind) async {
        await performAction {
            let status = await self.permissionProvider.request(permission)
            self.upsertPermissionStatus(status)
        }
    }

    func openSystemSettings(for permission: PermissionKind) async {
        await permissionProvider.openSystemSettings(for: permission)
    }

    func completeOnboarding() {
        isOnboardingComplete = true
    }

    func restartOnboarding() {
        onboardingResetGeneration += 1
        isOnboardingComplete = false
    }

    func dismissError() {
        presentedError = nil
    }

    func dismissOnlineWarning() {
        onlineWarning = nil
    }

    private func performBeginRewind(target targetSnapshotID: SnapshotID) async throws {
        guard activeProvisional == nil else {
            throw CoordinationError.rewindAlreadyActive
        }

        try await ensureIndexIsLoaded()
        guard let target = snapshots.first(where: { $0.id == targetSnapshotID }) else {
            throw ContinuumError.snapshotNotFound
        }
        guard target.availability != .unavailable else {
            throw ContinuumError.restoreUnavailable(
                "Continuum recorded metadata for this moment, but no restorable application state."
            )
        }

        rewindPhase = .capturingSafetySnapshot
        let processes = await inventory.runningApplications()
        guard let rootProcess = ProcessGroupResolver.root(for: target, among: processes) else {
            throw CoordinationError.appNotRunning(target.app.displayName)
        }
        let processIdentifiers = await self.processIdentifiers(
            rootedAt: rootProcess,
            among: processes
        )

        let sourceBranchID = try activeBranchID()
        let safetyCapture = try await checkpointCapturer.capture(
            app: target.app,
            processIdentifiers: processIdentifiers,
            kind: .beforeRewind,
            branchID: sourceBranchID
        )
        guard safetyCapture.snapshot.availability != .unavailable else {
            throw ContinuumError.restoreUnavailable(
                "Continuum could not create a restorable safety snapshot, so rewind did not begin."
            )
        }

        let namedSafetyCapture = SnapshotCaptureNaming.applyingAutomaticName(to: safetyCapture)

        // Transaction ordering is intentional: the safety state is durably
        // recorded before any caller is allowed to preview or restore the past.
        let provisional = try await repository.beginRewind(
            safetyCapture: namedSafetyCapture,
            sourceBranchID: sourceBranchID
        )

        activeProvisional = provisional
        pendingTargetSnapshotID = targetSnapshotID
        selectedSnapshotID = targetSnapshotID
        runningProcesses = processes.sorted(by: Self.processSort)
        rewindPhase = .previewing(provisional.id)
        try await refreshIndex()
    }

    private func performCommitRewind(target targetSnapshotID: SnapshotID) async throws {
        guard let provisional = activeProvisional else {
            throw CoordinationError.rewindNotActive
        }
        guard pendingTargetSnapshotID == targetSnapshotID else {
            throw ContinuumError.snapshotNotFound
        }
        guard let target = snapshots.first(where: { $0.id == targetSnapshotID }) else {
            throw ContinuumError.snapshotNotFound
        }

        rewindPhase = .restoring(targetSnapshotID)
        let artifacts = try await repository.artifacts(for: targetSnapshotID)
        let restoreResult = await checkpointCapturer.restore(
            snapshot: target,
            artifacts: artifacts
        )

        let warningEffects: [ExternalEffect]
        switch restoreResult {
        case .exactLocal:
            warningEffects = target.externalEffects
        case let .exactLocalWithOnlineWarning(effects):
            warningEffects = effects.isEmpty ? target.externalEffects : effects
        case let .failed(detail):
            rewindPhase = .failed(detail)
            throw ContinuumError.restoreUnavailable(detail)
        }

        // Store branch history only after the real application restore succeeds.
        let commit: RewindCommit
        do {
            commit = try await repository.commitRewind(
                provisional.id,
                targetSnapshotID: targetSnapshotID
            )
        } catch {
            await restoreSafetyAfterCommitFailure(provisional: provisional)
            throw error
        }

        activeProvisional = nil
        pendingTargetSnapshotID = nil
        lastRewindCommit = commit
        onlineWarning = warningEffects.isEmpty ? nil : warningEffects
        rewindPhase = .completed(targetSnapshotID)
        try await refreshIndex()
        selectedSnapshotID = targetSnapshotID
        selectedBranchID = commit.activeBranchID
    }

    private func performCancelRewind() async throws {
        guard let provisional = activeProvisional else {
            throw CoordinationError.rewindNotActive
        }

        if !snapshots.contains(where: { $0.id == provisional.safetySnapshotID }) {
            try await refreshIndex()
        }
        guard let safetySnapshot = snapshots.first(where: {
            $0.id == provisional.safetySnapshotID
        }) else {
            throw CoordinationError.safetySnapshotMissing
        }

        let artifacts = try await repository.artifacts(for: safetySnapshot.id)
        let result = await checkpointCapturer.restore(
            snapshot: safetySnapshot,
            artifacts: artifacts
        )

        switch result {
        case .exactLocal:
            onlineWarning = nil
        case let .exactLocalWithOnlineWarning(effects):
            onlineWarning = effects.isEmpty ? nil : effects
        case let .failed(detail):
            rewindPhase = .failed(detail)
            throw CoordinationError.cancellationValidationFailed(detail)
        }

        // Only a successful exact-local restore validates the original state;
        // the provisional record is deliberately retained on any failure above.
        try await repository.cancelRewind(provisional.id)
        activeProvisional = nil
        pendingTargetSnapshotID = nil
        rewindPhase = .idle
        try await refreshIndex()
    }

    private func restoreSafetyAfterCommitFailure(
        provisional: ProvisionalRewind
    ) async {
        do {
            let index = try await repository.loadIndex()
            guard index.provisionalRewinds.contains(where: { $0.id == provisional.id }),
                  let safetySnapshot = index.snapshots.first(where: {
                      $0.id == provisional.safetySnapshotID
                  }) else {
                apply(index: index)
                return
            }

            let artifacts = try await repository.artifacts(for: safetySnapshot.id)
            let result = await checkpointCapturer.restore(
                snapshot: safetySnapshot,
                artifacts: artifacts
            )

            switch result {
            case .exactLocal, .exactLocalWithOnlineWarning:
                try await repository.cancelRewind(provisional.id)
                activeProvisional = nil
                pendingTargetSnapshotID = nil
                rewindPhase = .idle
                try await refreshIndex()
            case let .failed(detail):
                rewindPhase = .failed(
                    "Timeline commit failed, and restoring the safety snapshot also failed: \(detail)"
                )
            }
        } catch {
            rewindPhase = .failed(
                "Timeline commit failed. The safety snapshot was retained for recovery."
            )
        }
    }

    private func performAction(
        _ operation: @MainActor () async throws -> Void
    ) async {
        guard !isPerformingAction else {
            presentedError = ContinuumError.transactionInProgress.localizedDescription
            return
        }

        isPerformingAction = true
        presentedError = nil
        defer { isPerformingAction = false }

        do {
            try await operation()
        } catch {
            presentedError = ErrorPresentation.message(for: error)
            if activeProvisional == nil,
               case .capturingSafetySnapshot = rewindPhase {
                rewindPhase = .idle
            }
        }
    }

    private func refreshAllState() async throws {
        let repository = repository
        let inventory = inventory
        let permissionProvider = permissionProvider

        async let index = repository.loadIndex()
        async let processes = inventory.runningApplications()
        async let applications = inventory.installedApplications()
        async let permissions = permissionProvider.statuses()

        let (loadedIndex, loadedProcesses, loadedApplications, loadedPermissions) =
            try await (index, processes, applications, permissions)

        apply(index: loadedIndex)
        runningProcesses = loadedProcesses.sorted(by: Self.processSort)
        installedApps = loadedApplications.sorted(by: Self.appSort)
        permissionStatuses = loadedPermissions.sorted {
            $0.kind.rawValue < $1.kind.rawValue
        }
        appReports = await compatibilityReports(
            installedApps: loadedApplications,
            runningProcesses: loadedProcesses
        )

        if activeProvisional == nil,
           let storedProvisional = loadedIndex.provisionalRewinds.first {
            activeProvisional = storedProvisional
            rewindPhase = .previewing(storedProvisional.id)
        }
    }

    private func refreshIndex() async throws {
        let index = try await repository.loadIndex()
        apply(index: index)
    }

    private func ensureIndexIsLoaded() async throws {
        if branches.isEmpty {
            try await refreshIndex()
        }
    }

    private func apply(index: StoreIndex) {
        snapshots = index.snapshots.sorted {
            if $0.createdAt == $1.createdAt { return $0.name < $1.name }
            return $0.createdAt > $1.createdAt
        }
        branches = index.branches.sorted {
            if $0.createdAt == $1.createdAt { return $0.name < $1.name }
            return $0.createdAt < $1.createdAt
        }

        if let activeBranch = branches.first(where: \.isActive) {
            selectedBranchID = activeBranch.id
        } else if selectedBranchID == nil
                    || !branches.contains(where: { $0.id == selectedBranchID }) {
            selectedBranchID = branches.first?.id
        }

        if let selectedSnapshotID,
           !snapshots.contains(where: { $0.id == selectedSnapshotID }) {
            self.selectedSnapshotID = nil
        }
        if selectedSnapshotID == nil,
           let selectedBranchID,
           let tip = branches.first(where: { $0.id == selectedBranchID })?.tipSnapshotID {
            selectedSnapshotID = tip
        }
        if selectedSnapshotID == nil {
            selectedSnapshotID = snapshots.first?.id
        }

        storageMetrics = StorageMetrics(
            logicalBytes: snapshots.reduce(0) { $0 + max($1.logicalBytes, 0) },
            physicalBytes: snapshots.reduce(0) { $0 + max($1.uniqueBytes, 0) },
            pinnedBytes: snapshots.reduce(0) {
                $0 + ($1.isPinned ? max($1.uniqueBytes, 0) : 0)
            },
            budgetBytes: ContinuumConstants.defaultDiskBudgetBytes
        )
    }

    private func compatibilityReports(
        installedApps: [AppIdentity],
        runningProcesses: [ProcessDescriptor]
    ) async -> [CompatibilityReport] {
        var appsByID: [String: AppIdentity] = [:]
        for app in installedApps {
            appsByID[app.id] = app
        }
        for process in runningProcesses where !process.isTerminated {
            appsByID[process.app.id] = process.app
        }

        let provider = inventory
        return await withTaskGroup(of: CompatibilityReport.self) { group in
            for app in appsByID.values {
                group.addTask {
                    await provider.compatibility(for: app)
                }
            }

            var reports: [CompatibilityReport] = []
            for await report in group {
                reports.append(report)
            }
            return reports.sorted {
                $0.app.displayName.localizedCaseInsensitiveCompare(
                    $1.app.displayName
                ) == .orderedAscending
            }
        }
    }

    private func processIdentifiers(
        rootedAt root: ProcessDescriptor,
        among processes: [ProcessDescriptor]
    ) async -> [Int32] {
        if let processTreeProvider = inventory as? any ProcessTreeProviding {
            let identifiers = await processTreeProvider.processIdentifiers(
                inTreeRootedAt: root.processIdentifier
            )
            if !identifiers.isEmpty {
                return identifiers
            }
        }

        return ProcessGroupResolver.identifiers(rootedAt: root, among: processes)
    }

    private func activeBranchID() throws -> BranchID {
        if let branch = branches.first(where: \.isActive) {
            return branch.id
        }
        if let selectedBranchID,
           branches.contains(where: { $0.id == selectedBranchID }) {
            return selectedBranchID
        }
        if let branch = branches.first {
            return branch.id
        }
        throw CoordinationError.noActiveBranch
    }

    private func branchIDForNewCapture() -> BranchID {
        if let branch = branches.first(where: \.isActive) {
            return branch.id
        }
        if let selectedBranchID,
           branches.contains(where: { $0.id == selectedBranchID }) {
            return selectedBranchID
        }
        return branches.first?.id ?? UUID()
    }

    private func upsertPermissionStatus(_ status: PermissionStatus) {
        if let index = permissionStatuses.firstIndex(where: { $0.kind == status.kind }) {
            permissionStatuses[index] = status
        } else {
            permissionStatuses.append(status)
        }
        permissionStatuses.sort { $0.kind.rawValue < $1.kind.rawValue }
    }

    private static func processSort(
        _ lhs: ProcessDescriptor,
        _ rhs: ProcessDescriptor
    ) -> Bool {
        let comparison = lhs.app.displayName.localizedCaseInsensitiveCompare(
            rhs.app.displayName
        )
        if comparison == .orderedSame {
            return lhs.processIdentifier < rhs.processIdentifier
        }
        return comparison == .orderedAscending
    }

    private static func appSort(_ lhs: AppIdentity, _ rhs: AppIdentity) -> Bool {
        lhs.displayName.localizedCaseInsensitiveCompare(rhs.displayName)
            == .orderedAscending
    }
}
