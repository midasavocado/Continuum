import Foundation
import Observation
import ContinuumCore

enum AppSetupOperation: String, Sendable {
    case checking
    case settingUp
    case rechecking
    case removing

    var title: String {
        switch self {
        case .checking: "Checking setup…"
        case .settingUp: "Setting up managed copy…"
        case .rechecking: "Rechecking setup…"
        case .removing: "Removing setup…"
        }
    }
}

@MainActor
@Observable
final class ContinuumModel {
    private static let onboardingDefaultsKey = "continuum.onboarding.completed"
    private static let explicitApplicationPathsKey = "continuum.apps.explicitTargetPaths"

    @ObservationIgnored private let repository: any SnapshotRepository
    @ObservationIgnored private let inventory: any AppInventoryProviding
    @ObservationIgnored private let permissionProvider: any PermissionProviding
    @ObservationIgnored private let checkpointCapturer: any CheckpointCapturing
    @ObservationIgnored private let appSetupCoordinator: any AppSetupCoordinating
    @ObservationIgnored private let defaults: UserDefaults

    private(set) var snapshots: [SnapshotRecord] = []
    private(set) var branches: [BranchRecord] = []
    private(set) var appReports: [CompatibilityReport] = []
    private(set) var runningProcesses: [ProcessDescriptor] = []
    private(set) var installedApps: [AppIdentity] = []
    private(set) var permissionStatuses: [PermissionStatus] = []
    private(set) var setupRecords: [AppSetupRecord] = []
    private(set) var setupOperations: [String: AppSetupOperation] = [:]
    private(set) var isBatchSetupInProgress = false

    var selectedSnapshotID: SnapshotID?
    var selectedBranchID: BranchID?
    var selectedSection: ContinuumSection = .timeline
    var snapshotFilter: SnapshotFilter = .all

    private(set) var isLoading = false
    private(set) var isPerformingAction = false
    private(set) var isRefreshingPermissions = false
    private(set) var requestingPermission: PermissionKind?
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
        appSetupCoordinator: any AppSetupCoordinating,
        defaults: UserDefaults = .standard
    ) {
        self.repository = repository
        self.inventory = inventory
        self.permissionProvider = permissionProvider
        self.checkpointCapturer = checkpointCapturer
        self.appSetupCoordinator = appSetupCoordinator
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

    var canCaptureFunctionalState: Bool {
        checkpointCapturer.supportsFunctionalRestore
    }

    var appSetupIssueCount: Int {
        let recordsBySource = Dictionary(
            setupRecords.map { ($0.sourceURL.standardizedFileURL.path, $0) },
            uniquingKeysWith: { current, candidate in
                candidate.updatedAt > current.updatedAt ? candidate : current
            }
        )
        let reportsBySource = Dictionary(
            appReports.map { (Self.sourceKey(for: $0.app), $0) },
            uniquingKeysWith: { current, _ in current }
        )

        return installedApps.reduce(into: 0) { count, app in
            let key = Self.sourceKey(for: app)
            if let record = recordsBySource[key] {
                switch record.state {
                case .prepared, .blocked:
                    break
                case .discovered, .preparing, .stale, .rolledBack, .failed:
                    count += 1
                }
            } else if !app.isApplePlatformBinary,
                      reportsBySource[key]?.tier != .protectedBridge,
                      reportsBySource[key]?.tier != .unsupported {
                count += 1
            }
        }
    }

    func load() async {
        guard !isLoading, !isPerformingAction else { return }
        isLoading = true
        presentedError = nil
        defer { isLoading = false }

        do {
            try await appSetupCoordinator.recoverInterruptedSetups()
            try await refreshAllState()
        } catch {
            presentedError = ErrorPresentation.message(for: error)
        }
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
            guard self.checkpointCapturer.supportsFunctionalRestore else {
                throw ContinuumError.runtimeUnsupported(
                    "No app has a certified rewind engine in this build, so Continuum will not create a snapshot that only looks usable."
                )
            }
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
            try Self.validatePublishedAvailability(capture.snapshot)
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

    func addApplicationTarget(at url: URL) async {
        guard !isPerformingAction else {
            presentedError = ContinuumError.transactionInProgress.localizedDescription
            return
        }
        guard let resolver = inventory as? any ApplicationTargetResolving else {
            presentedError = "This build cannot inspect an app or executable selected from disk."
            return
        }

        let standardizedURL = url.standardizedFileURL
        guard let app = await resolver.application(at: standardizedURL) else {
            presentedError = "Continuum could not find a runnable macOS app or executable at \(standardizedURL.path)."
            return
        }

        persistExplicitApplicationURL(standardizedURL)
        upsertInstalledApplication(app)
        upsertCompatibilityReport(await inventory.compatibility(for: app))
        await checkSetup(for: app)
    }

    func checkSetup(for app: AppIdentity) async {
        await performSetupAction(for: app, operation: .checking) {
            try await self.appSetupCoordinator.probe(app)
        }
    }

    func setUpManagedCopy(for app: AppIdentity) async {
        await performSetupAction(for: app, operation: .settingUp) {
            try await self.appSetupCoordinator.setup(app)
        }
    }

    func recheckSetup(_ record: AppSetupRecord) async {
        await performSetupAction(for: record.app, operation: .rechecking) {
            try await self.appSetupCoordinator.revalidate(record.id)
        }
    }

    func removeSetup(_ record: AppSetupRecord) async {
        let app = record.app
        let key = Self.sourceKey(for: app)
        guard !isPerformingAction, setupOperations[key] == nil else {
            presentedError = ContinuumError.transactionInProgress.localizedDescription
            return
        }

        isPerformingAction = true
        setupOperations[key] = .removing
        presentedError = nil
        defer {
            setupOperations[key] = nil
            isPerformingAction = false
        }

        do {
            try await appSetupCoordinator.rollback(record.id)
            setupRecords.removeAll { $0.id == record.id }
            setupRecords = try await appSetupCoordinator.records()
                .sorted(by: Self.setupRecordSort)
        } catch {
            presentedError = ErrorPresentation.message(for: error)
            if let refreshedRecords = try? await appSetupCoordinator.records() {
                setupRecords = refreshedRecords.sorted(by: Self.setupRecordSort)
            }
        }
    }

    func setUpEligibleApps() async {
        guard !isPerformingAction, !isBatchSetupInProgress else {
            presentedError = ContinuumError.transactionInProgress.localizedDescription
            return
        }

        isPerformingAction = true
        isBatchSetupInProgress = true
        presentedError = nil
        defer {
            setupOperations.removeAll()
            isBatchSetupInProgress = false
            isPerformingAction = false
        }

        var failures: [String] = []
        for app in installedApps.sorted(by: Self.appSort) {
            let key = Self.sourceKey(for: app)
            var record = setupRecord(for: app)

            if let record {
                switch record.state {
                case .prepared, .blocked, .preparing, .stale, .failed, .rolledBack:
                    continue
                case .discovered:
                    break
                }
            } else {
                setupOperations[key] = .checking
                do {
                    let probed = try await appSetupCoordinator.probe(app)
                    upsertSetupRecord(probed)
                    record = probed
                } catch {
                    failures.append("\(app.displayName): \(ErrorPresentation.message(for: error))")
                    setupOperations[key] = nil
                    continue
                }
            }

            guard let record, case .discovered = record.state else {
                setupOperations[key] = nil
                continue
            }

            setupOperations[key] = .settingUp
            do {
                upsertSetupRecord(try await appSetupCoordinator.setup(app))
            } catch {
                failures.append("\(app.displayName): \(ErrorPresentation.message(for: error))")
            }
            setupOperations[key] = nil
        }

        do {
            setupRecords = try await appSetupCoordinator.records()
                .sorted(by: Self.setupRecordSort)
        } catch {
            failures.append(ErrorPresentation.message(for: error))
        }

        if !failures.isEmpty {
            let shown = failures.prefix(3).joined(separator: "\n")
            let remaining = max(failures.count - 3, 0)
            presentedError = remaining == 0
                ? shown
                : "\(shown)\n…and \(remaining) more setup issue\(remaining == 1 ? "" : "s")."
        }
    }

    func setupRecord(for app: AppIdentity) -> AppSetupRecord? {
        let key = Self.sourceKey(for: app)
        return setupRecords
            .filter { $0.sourceURL.standardizedFileURL.path == key }
            .max { $0.updatedAt < $1.updatedAt }
    }

    func setupOperation(for app: AppIdentity) -> AppSetupOperation? {
        setupOperations[Self.sourceKey(for: app)]
    }

    func requestPermission(_ permission: PermissionKind) async {
        guard requestingPermission == nil, !isRefreshingPermissions else { return }
        requestingPermission = permission
        defer { requestingPermission = nil }

        let status = await permissionProvider.request(permission)
        upsertPermissionStatus(status)
    }

    func refreshPermissions() async {
        guard !isRefreshingPermissions, requestingPermission == nil else { return }
        isRefreshingPermissions = true
        defer { isRefreshingPermissions = false }

        let statuses = await permissionProvider.statuses()
        permissionStatuses = statuses.sorted {
            $0.kind.rawValue < $1.kind.rawValue
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
        try Self.validatePublishedAvailability(safetyCapture.snapshot)
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
        case .experimentalHot:
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
        case .experimentalHot:
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
                await apply(index: index)
                return
            }

            let artifacts = try await repository.artifacts(for: safetySnapshot.id)
            let result = await checkpointCapturer.restore(
                snapshot: safetySnapshot,
                artifacts: artifacts
            )

            switch result {
            case .exactLocal, .experimentalHot, .exactLocalWithOnlineWarning:
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

    private func performSetupAction(
        for app: AppIdentity,
        operation: AppSetupOperation,
        _ action: @MainActor () async throws -> AppSetupRecord
    ) async {
        let key = Self.sourceKey(for: app)
        guard !isPerformingAction, setupOperations[key] == nil else {
            presentedError = ContinuumError.transactionInProgress.localizedDescription
            return
        }

        isPerformingAction = true
        setupOperations[key] = operation
        presentedError = nil
        defer {
            setupOperations[key] = nil
            isPerformingAction = false
        }

        do {
            upsertSetupRecord(try await action())
        } catch {
            presentedError = ErrorPresentation.message(for: error)
            if let refreshedRecords = try? await appSetupCoordinator.records() {
                setupRecords = refreshedRecords.sorted(by: Self.setupRecordSort)
            }
        }
    }

    private func refreshAllState() async throws {
        let repository = repository
        let inventory = inventory
        let permissionProvider = permissionProvider
        let appSetupCoordinator = appSetupCoordinator

        async let index = repository.loadIndex()
        async let processes = inventory.runningApplications()
        async let applications = inventory.installedApplications()
        async let permissions = permissionProvider.statuses()
        async let setups = appSetupCoordinator.records()

        let (
            loadedIndex,
            loadedProcesses,
            discoveredApplications,
            loadedPermissions,
            loadedSetups
        ) = try await (index, processes, applications, permissions, setups)

        let explicitApplications = await resolveExplicitApplications()
        let loadedApplications = Self.mergingApplications(
            discoveredApplications + explicitApplications + loadedSetups.map(\.app)
        )

        await apply(index: loadedIndex)
        runningProcesses = loadedProcesses.sorted(by: Self.processSort)
        installedApps = loadedApplications.sorted(by: Self.appSort)
        setupRecords = loadedSetups.sorted(by: Self.setupRecordSort)
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

    private func resolveExplicitApplications() async -> [AppIdentity] {
        guard let resolver = inventory as? any ApplicationTargetResolving else {
            return []
        }

        let paths = defaults.stringArray(
            forKey: Self.explicitApplicationPathsKey
        ) ?? []

        return await withTaskGroup(of: AppIdentity?.self) { group in
            for path in paths {
                group.addTask {
                    await resolver.application(at: URL(fileURLWithPath: path))
                }
            }

            var applications: [AppIdentity] = []
            for await application in group {
                if let application {
                    applications.append(application)
                }
            }
            return applications
        }
    }

    private func persistExplicitApplicationURL(_ url: URL) {
        var paths = defaults.stringArray(
            forKey: Self.explicitApplicationPathsKey
        ) ?? []
        let path = url.standardizedFileURL.path
        if !paths.contains(path) {
            paths.append(path)
            defaults.set(paths.sorted(), forKey: Self.explicitApplicationPathsKey)
        }
    }

    private func upsertInstalledApplication(_ app: AppIdentity) {
        let key = Self.sourceKey(for: app)
        installedApps.removeAll { Self.sourceKey(for: $0) == key }
        installedApps.append(app)
        installedApps.sort(by: Self.appSort)
    }

    private func upsertCompatibilityReport(_ report: CompatibilityReport) {
        let key = Self.sourceKey(for: report.app)
        appReports.removeAll { Self.sourceKey(for: $0.app) == key }
        appReports.append(report)
        appReports.sort {
            $0.app.displayName.localizedCaseInsensitiveCompare(
                $1.app.displayName
            ) == .orderedAscending
        }
    }

    private func upsertSetupRecord(_ record: AppSetupRecord) {
        setupRecords.removeAll { $0.id == record.id }
        setupRecords.append(record)
        setupRecords.sort(by: Self.setupRecordSort)
    }

    private func refreshIndex() async throws {
        let index = try await repository.loadIndex()
        await apply(index: index)
    }

    private func ensureIndexIsLoaded() async throws {
        if branches.isEmpty {
            try await refreshIndex()
        }
    }

    private func apply(index: StoreIndex) async {
        var liveSnapshots: [SnapshotRecord] = []
        liveSnapshots.reserveCapacity(index.snapshots.count)
        for var snapshot in index.snapshots {
            snapshot.availability = await checkpointCapturer.currentRestoreAvailability(
                for: snapshot
            )
            liveSnapshots.append(snapshot)
        }

        snapshots = liveSnapshots.sorted {
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
                return [root.processIdentifier]
                    + identifiers.filter { $0 != root.processIdentifier }.sorted()
            }
        }

        let identifiers = ProcessGroupResolver.identifiers(rootedAt: root, among: processes)
        return [root.processIdentifier]
            + identifiers.filter { $0 != root.processIdentifier }.sorted()
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
        let nameOrder = lhs.displayName.localizedCaseInsensitiveCompare(rhs.displayName)
        if nameOrder != .orderedSame {
            return nameOrder == .orderedAscending
        }
        return sourceKey(for: lhs) < sourceKey(for: rhs)
    }

    private static func setupRecordSort(
        _ lhs: AppSetupRecord,
        _ rhs: AppSetupRecord
    ) -> Bool {
        let nameOrder = lhs.app.displayName.localizedCaseInsensitiveCompare(
            rhs.app.displayName
        )
        if nameOrder != .orderedSame {
            return nameOrder == .orderedAscending
        }
        return lhs.updatedAt > rhs.updatedAt
    }

    private static func validatePublishedAvailability(
        _ snapshot: SnapshotRecord
    ) throws {
        switch snapshot.availability {
        case .instant, .replayRequired:
            guard snapshot.hasCompleteResourceCoverage else {
                throw ContinuumError.integrityFailure(
                    "The checkpoint backend claimed exact restoration without complete resource reconstruction evidence."
                )
            }
        case .experimentalHot, .unavailable:
            break
        }
    }

    private static func sourceKey(for app: AppIdentity) -> String {
        (app.bundleURL ?? app.executableURL).standardizedFileURL.path
    }

    private static func mergingApplications(_ applications: [AppIdentity]) -> [AppIdentity] {
        var bySource: [String: AppIdentity] = [:]
        for application in applications {
            bySource[sourceKey(for: application)] = application
        }
        return Array(bySource.values)
    }
}
