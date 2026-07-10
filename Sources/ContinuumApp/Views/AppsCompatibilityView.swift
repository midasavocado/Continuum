import AppKit
import ContinuumCore
import SwiftUI

struct AppsCompatibilityView: View {
    let reports: [CompatibilityReport]
    let setupRecords: [AppSetupRecord]
    let runningProcesses: [ProcessDescriptor]
    let isBatchSetupInProgress: Bool
    let setupOperation: (AppIdentity) -> AppSetupOperation?
    let onCheckSetup: (AppIdentity) -> Void
    let onSetupManagedCopy: (AppIdentity) -> Void
    let onRecheckSetup: (AppSetupRecord) -> Void
    let onRemoveSetup: (AppSetupRecord) -> Void
    let onSetupEligibleApps: () -> Void
    let onAddTarget: (URL) -> Void

    @State private var searchText = ""
    @State private var selectedEntryID: String?
    @State private var isConfirmingBatchSetup = false

    private var entries: [AppSetupEntry] {
        AppSetupEntry.merging(reports: reports, setupRecords: setupRecords)
    }

    private var filteredEntries: [AppSetupEntry] {
        entries
            .filter {
                searchText.isEmpty
                    || $0.app.displayName.localizedStandardContains(searchText)
                    || $0.sourceURL.path.localizedStandardContains(searchText)
            }
            .sorted {
                if $0.status.sortOrder != $1.status.sortOrder {
                    return $0.status.sortOrder < $1.status.sortOrder
                }
                return $0.app.displayName.localizedStandardCompare(
                    $1.app.displayName
                ) == .orderedAscending
            }
    }

    private var selectedEntry: AppSetupEntry? {
        entries.first { $0.id == selectedEntryID }
    }

    private var batchCandidateCount: Int {
        entries.filter(\.canJoinBatchSetup).count
    }

    var body: some View {
        VStack(spacing: 0) {
            summary
                .padding(20)
            Divider()

            HSplitView {
                entryList
                    .frame(minWidth: 320, idealWidth: 360)

                if let selectedEntry {
                    AppSetupDetailView(
                        entry: selectedEntry,
                        isRunning: isRunning(selectedEntry.app),
                        operation: setupOperation(selectedEntry.app),
                        isBatchSetupInProgress: isBatchSetupInProgress,
                        onCheckSetup: { onCheckSetup(selectedEntry.app) },
                        onSetupManagedCopy: { onSetupManagedCopy(selectedEntry.app) },
                        onRecheckSetup: {
                            guard let record = selectedEntry.record else { return }
                            onRecheckSetup(record)
                        },
                        onRemoveSetup: {
                            guard let record = selectedEntry.record else { return }
                            onRemoveSetup(record)
                        }
                    )
                    .frame(minWidth: 430, maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    ContentUnavailableView {
                        Label("Choose an app", systemImage: "app.badge.checkmark")
                    } description: {
                        Text("Check an app, prepare a reversible managed copy, and see any macOS protection that prevents setup.")
                    }
                    .frame(minWidth: 430, maxWidth: .infinity, maxHeight: .infinity)
                }
            }
        }
        .navigationTitle("Apps")
        .searchable(text: $searchText, prompt: "Search apps and executables")
        .onAppear(perform: ensureSelection)
        .onChange(of: filteredEntries.map(\.id)) { _, _ in ensureSelection() }
        .confirmationDialog(
            "Prepare every eligible app bundle?",
            isPresented: $isConfirmingBatchSetup,
            titleVisibility: .visible
        ) {
            Button("Set Up Eligible Apps", action: onSetupEligibleApps)
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Continuum will inspect all unreviewed targets and create verified Original.app and Managed.app copies for each eligible bundle. This can use substantial disk space. Selected source apps remain untouched.")
        }
    }

    private var summary: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                MetricTile(
                    title: "Managed Copies",
                    value: entries.filter { $0.status == .prepared }.count.formatted(),
                    detail: "Prepared, not rewind-certified",
                    systemImage: "checkmark.seal.fill",
                    tint: .green
                )
                MetricTile(
                    title: "Needs Attention",
                    value: entries.filter { $0.status == .needsAttention }.count.formatted(),
                    detail: "Check or refresh setup",
                    systemImage: "wrench.adjustable.fill",
                    tint: .orange
                )
                MetricTile(
                    title: "Protected",
                    value: entries.filter { $0.status == .protected }.count.formatted(),
                    detail: "macOS or app identity blocks setup",
                    systemImage: "lock.shield.fill",
                    tint: .secondary
                )
            }

            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Setup only creates a reversible managed copy.")
                        .font(.subheadline.weight(.medium))
                    Text("It never edits the app you selected, and prepared does not mean rewind-certified.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Button {
                    chooseTarget()
                } label: {
                    Label("Add Target…", systemImage: "plus")
                }
                .disabled(isBatchSetupInProgress)

                Button {
                    isConfirmingBatchSetup = true
                } label: {
                    if isBatchSetupInProgress {
                        Label {
                            Text("Setting Up…")
                        } icon: {
                            ProgressView()
                                .controlSize(.small)
                        }
                    } else {
                        Label(
                            "Set Up Eligible Apps",
                            systemImage: "square.stack.3d.up.badge.automatic"
                        )
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(isBatchSetupInProgress || batchCandidateCount == 0)
                .help(
                    batchCandidateCount == 0
                        ? "No unchecked or eligible apps are waiting for setup."
                        : "Checks unreviewed targets and prepares only the app bundles that prove eligible, one at a time."
                )
            }
        }
    }

    @ViewBuilder
    private var entryList: some View {
        if filteredEntries.isEmpty {
            if searchText.isEmpty {
                ContentUnavailableView {
                    Label("No apps found", systemImage: "app.dashed")
                } description: {
                    Text("Add any .app bundle or runnable executable from disk. Standalone executables are inspected and may report that the managed-copy route needs an app bundle.")
                } actions: {
                    Button("Add Target…", action: chooseTarget)
                }
            } else {
                ContentUnavailableView.search(text: searchText)
            }
        } else {
            List(selection: $selectedEntryID) {
                ForEach(filteredEntries) { entry in
                    HStack(spacing: 10) {
                        AppBundleIcon(app: entry.app, size: 30)

                        VStack(alignment: .leading, spacing: 3) {
                            Text(entry.app.displayName)
                                .fontWeight(.medium)
                                .lineLimit(1)
                            Text(entry.secondaryStatus)
                                .font(.caption)
                                .foregroundStyle(entry.status.tint)
                                .lineLimit(1)
                        }

                        Spacer(minLength: 8)
                        if let operation = setupOperation(entry.app) {
                            ProgressView()
                                .controlSize(.small)
                                .help(operation.title)
                        } else {
                            Image(systemName: entry.status.symbol)
                                .foregroundStyle(entry.status.tint)
                        }
                    }
                    .padding(.vertical, 4)
                    .tag(entry.id)
                }
            }
            .listStyle(.inset)
        }
    }

    private func ensureSelection() {
        if let selectedEntryID,
           filteredEntries.contains(where: { $0.id == selectedEntryID }) {
            return
        }
        selectedEntryID = filteredEntries.first?.id
    }

    private func isRunning(_ app: AppIdentity) -> Bool {
        let sourcePath = AppSetupEntry.sourceURL(for: app).standardizedFileURL.path
        return runningProcesses.contains {
            !$0.isTerminated
                && (AppSetupEntry.sourceURL(for: $0.app).standardizedFileURL.path == sourcePath
                    || $0.app.id == app.id)
        }
    }

    private func chooseTarget() {
        let panel = NSOpenPanel()
        panel.title = "Add a Continuum Target"
        panel.message = "Choose any macOS .app bundle or runnable executable. Continuum checks it first; only eligible app bundles can use the current managed-copy route."
        panel.prompt = "Check Setup"
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.treatsFilePackagesAsDirectories = false
        panel.allowsMultipleSelection = false
        panel.resolvesAliases = true
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            onAddTarget(url)
        }
    }
}

private struct AppSetupDetailView: View {
    let entry: AppSetupEntry
    let isRunning: Bool
    let operation: AppSetupOperation?
    let isBatchSetupInProgress: Bool
    let onCheckSetup: () -> Void
    let onSetupManagedCopy: () -> Void
    let onRecheckSetup: () -> Void
    let onRemoveSetup: () -> Void

    @State private var isConfirmingRemoval = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header
                stateCard
                setupFacts
                actionBar
            }
            .padding(24)
            .frame(maxWidth: 760, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .confirmationDialog(
            "Remove Continuum setup for \(entry.app.displayName)?",
            isPresented: $isConfirmingRemoval
        ) {
            Button("Remove Managed Copy", role: .destructive, action: onRemoveSetup)
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Continuum deletes its managed copy and original backup, then keeps a small removal receipt. The selected source app remains untouched.")
        }
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 14) {
            AppBundleIcon(app: entry.app, size: 48)

            VStack(alignment: .leading, spacing: 4) {
                Text(entry.app.displayName)
                    .font(.title.weight(.semibold))
                Text(entry.app.version.map { "Version \($0)" } ?? entry.sourceURL.lastPathComponent)
                    .foregroundStyle(.secondary)
            }

            Spacer()
            StatusBadge(
                title: entry.status.title,
                systemImage: entry.status.symbol,
                tint: entry.status.tint
            )
        }
    }

    private var stateCard: some View {
        SurfaceCard {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: stateSymbol)
                    .font(.title2)
                    .foregroundStyle(entry.status.tint)
                    .frame(width: 28)

                VStack(alignment: .leading, spacing: 7) {
                    Text(stateTitle)
                        .font(.headline)
                    Text(stateDetail)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)

                    if case let .blocked(blockers) = entry.record?.state {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(Array(blockers.enumerated()), id: \.offset) { _, blocker in
                                Label(blocker.explanation, systemImage: "lock.fill")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .padding(.top, 2)
                    }

                    if let validation = entry.record?.validation,
                       !validation.detail.isEmpty {
                        Text(validation.detail)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .padding(.top, 2)
                    }
                }
                Spacer(minLength: 0)
            }
        }
    }

    private var setupFacts: some View {
        SurfaceCard {
            VStack(alignment: .leading, spacing: 10) {
                Text("Setup details")
                    .font(.headline)
                factRow("Source", entry.sourceURL.path)
                factRow("Running", isRunning ? "Yes" : "No")
                factRow("Method", "Reversible managed copy")

                if let record = entry.record {
                    factRow("Last checked", record.updatedAt.formatted(date: .abbreviated, time: .shortened))
                    factRow("Original backup", record.originalCloneURL?.path ?? "Not created")
                    factRow("Managed copy", record.managedBundleURL?.path ?? "Not created")
                    factRow(
                        "Source unchanged",
                        record.validation?.sourceUnchanged == true ? "Verified" : "Not yet verified"
                    )
                    factRow(
                        "Attach entitlement",
                        record.validation?.managedAttachEntitlementValid == true
                            ? "Verified on managed copy"
                            : "Not yet verified"
                    )
                    factRow(
                        "Rewind certification",
                        record.validation?.restoreCertificationPassed == true
                            ? "Passed"
                            : "Not passed — rewind remains disabled"
                    )
                } else {
                    factRow("Last checked", "Never")
                    factRow("Rewind certification", "Not passed — rewind remains disabled")
                }
            }
        }
    }

    @ViewBuilder
    private var actionBar: some View {
        HStack(spacing: 10) {
            if let operation {
                ProgressView()
                    .controlSize(.small)
                Text(operation.title)
                    .font(.subheadline.weight(.medium))
            } else {
                switch entry.record?.state {
                case nil, .rolledBack:
                    Button("Check Setup", action: onCheckSetup)
                        .buttonStyle(.borderedProminent)

                case .discovered:
                    Button("Set Up Managed Copy", action: onSetupManagedCopy)
                        .buttonStyle(.borderedProminent)

                case .preparing:
                    ProgressView()
                        .controlSize(.small)
                    Text("Recovering setup…")

                case .prepared, .stale:
                    Button("Recheck Setup", action: onRecheckSetup)
                        .buttonStyle(.borderedProminent)
                    Button("Remove Setup…", role: .destructive) {
                        isConfirmingRemoval = true
                    }

                case .blocked, .failed:
                    Button("Check Again", action: onCheckSetup)
                        .buttonStyle(.borderedProminent)
                    Button("Remove Setup…", role: .destructive) {
                        isConfirmingRemoval = true
                    }
                }
            }

            Spacer()

            if entry.status == .prepared {
                Label("Prepared, not rewind-certified", systemImage: "info.circle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .disabled(isBatchSetupInProgress && operation == nil)
    }

    private var stateTitle: String {
        switch entry.record?.state {
        case nil: "Ready to check"
        case .discovered: "Managed-copy setup is available"
        case let .preparing(stage): stage.title
        case .prepared: "Managed copy prepared"
        case .stale: "Setup needs to be refreshed"
        case .blocked: "Setup is protected"
        case .rolledBack: "Setup was safely removed"
        case .failed: "Setup needs attention"
        }
    }

    private var stateDetail: String {
        switch entry.record?.state {
        case nil:
            "Continuum has not changed anything. Check Setup performs a read-only compatibility probe."
        case .discovered:
            "Continuum can clone the source into its private workspace, preserve a verified original, and prepare a separately signed managed copy."
        case let .preparing(stage):
            "Continuum is \(stage.progressDescription). The selected source remains untouched."
        case .prepared:
            "The attach-enabled managed copy passed source, clone, marker, and signature checks. Functional rewind stays disabled until restore certification passes."
        case .stale:
            "The source app changed after setup. Recheck it before using the managed copy."
        case .blocked:
            "Continuum stopped before making an unsafe copy. The blockers below come from the same generic setup probe used for every app."
        case .rolledBack:
            "Continuum removed its managed artifacts without changing the selected source."
        case let .failed(detail):
            detail
        }
    }

    private var stateSymbol: String {
        switch entry.record?.state {
        case nil, .discovered: "checklist"
        case .preparing: "gearshape.2.fill"
        case .prepared: "checkmark.seal.fill"
        case .stale: "arrow.triangle.2.circlepath"
        case .blocked: "lock.shield.fill"
        case .rolledBack: "arrow.uturn.backward.circle.fill"
        case .failed: "exclamationmark.triangle.fill"
        }
    }

    private func factRow(_ title: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 16) {
            Text(title)
                .foregroundStyle(.secondary)
                .frame(width: 130, alignment: .leading)
            Text(value)
                .fontWeight(.medium)
                .textSelection(.enabled)
                .lineLimit(2)
                .truncationMode(.middle)
            Spacer(minLength: 0)
        }
        .font(.subheadline)
    }
}

private struct AppBundleIcon: View {
    let app: AppIdentity
    let size: CGFloat

    var body: some View {
        Image(nsImage: icon)
            .resizable()
            .scaledToFit()
            .frame(width: size, height: size)
            .accessibilityHidden(true)
    }

    private var icon: NSImage {
        NSWorkspace.shared.icon(
            forFile: (app.bundleURL ?? app.executableURL).standardizedFileURL.path
        )
    }
}

private struct AppSetupEntry: Identifiable {
    let id: String
    let app: AppIdentity
    let report: CompatibilityReport?
    let record: AppSetupRecord?

    var sourceURL: URL {
        record?.sourceURL ?? Self.sourceURL(for: app)
    }

    var status: AppSetupDisplayStatus {
        if let record {
            switch record.state {
            case .prepared: return .prepared
            case .blocked: return .protected
            case .discovered, .preparing, .stale, .rolledBack, .failed:
                return .needsAttention
            }
        }

        if app.isApplePlatformBinary
            || report?.tier == .protectedBridge
            || report?.tier == .unsupported {
            return .protected
        }
        return .needsAttention
    }

    var secondaryStatus: String {
        switch record?.state {
        case nil: status == .protected ? "Check protection" : "Not checked"
        case .discovered: "Ready for managed setup"
        case let .preparing(stage): stage.title
        case .prepared: "Managed copy verified"
        case .stale: "Source changed"
        case .blocked: "Setup blocked"
        case .rolledBack: "Setup removed"
        case .failed: "Setup failed"
        }
    }

    var canJoinBatchSetup: Bool {
        guard status == .needsAttention else { return false }
        switch record?.state {
        case nil, .discovered: return true
        case .preparing, .prepared, .stale, .blocked, .rolledBack, .failed:
            return false
        }
    }

    static func merging(
        reports: [CompatibilityReport],
        setupRecords: [AppSetupRecord]
    ) -> [AppSetupEntry] {
        var recordsBySource: [String: AppSetupRecord] = [:]
        for record in setupRecords {
            let key = record.sourceURL.standardizedFileURL.path
            if let current = recordsBySource[key], current.updatedAt >= record.updatedAt {
                continue
            }
            recordsBySource[key] = record
        }

        var entriesBySource: [String: AppSetupEntry] = [:]
        for report in reports {
            let key = sourceURL(for: report.app).standardizedFileURL.path
            entriesBySource[key] = AppSetupEntry(
                id: key,
                app: report.app,
                report: report,
                record: recordsBySource.removeValue(forKey: key)
            )
        }

        for (key, record) in recordsBySource {
            entriesBySource[key] = AppSetupEntry(
                id: key,
                app: record.app,
                report: nil,
                record: record
            )
        }

        return Array(entriesBySource.values)
    }

    static func sourceURL(for app: AppIdentity) -> URL {
        app.bundleURL ?? app.executableURL
    }
}

private enum AppSetupDisplayStatus: Equatable {
    case prepared
    case needsAttention
    case protected

    var title: String {
        switch self {
        case .prepared: "Managed Copy Prepared"
        case .needsAttention: "Needs Attention"
        case .protected: "Protected"
        }
    }

    var symbol: String {
        switch self {
        case .prepared: "checkmark.seal.fill"
        case .needsAttention: "wrench.adjustable.fill"
        case .protected: "lock.shield.fill"
        }
    }

    var tint: Color {
        switch self {
        case .prepared: .green
        case .needsAttention: .orange
        case .protected: .secondary
        }
    }

    var sortOrder: Int {
        switch self {
        case .prepared: 0
        case .needsAttention: 1
        case .protected: 2
        }
    }
}

private extension AppSetupStage {
    var title: String {
        switch self {
        case .probing: "Checking app structure"
        case .creatingWorkspace: "Creating private workspace"
        case .cloningOriginal: "Preserving untouched original"
        case .cloningManaged: "Creating managed copy"
        case .instrumenting: "Preparing attach-enabled copy"
        case .signing: "Signing managed copy"
        case .validating: "Validating every artifact"
        case .rollingBack: "Rolling back safely"
        }
    }

    var progressDescription: String {
        switch self {
        case .probing: "checking the app bundle"
        case .creatingWorkspace: "creating a private setup workspace"
        case .cloningOriginal: "preserving a byte-verified original"
        case .cloningManaged: "cloning a separate managed working copy"
        case .instrumenting: "adding only the managed attach entitlement"
        case .signing: "signing the managed app bundle"
        case .validating: "verifying the source, clones, marker, entitlements, and signature"
        case .rollingBack: "removing partial managed artifacts"
        }
    }
}

private extension AppSetupBlocker {
    var explanation: String {
        switch self {
        case .applePlatformBinary:
            "Apple platform binary: SIP and authenticated-root protections prevent reversible managed re-signing."
        case .sandboxIdentityBound:
            "Sandbox identity: the app container and access are bound to its current signing identity."
        case .appStoreReceiptOrDRM:
            "App Store receipt or DRM: a managed signature could invalidate the app's licensed identity."
        case .signedIdentityBound:
            "Signed identity: the app relies on services that are bound to its original signature."
        case let .restrictedEntitlements(entitlements):
            "Restricted entitlements: \(entitlements.sorted().joined(separator: ", "))."
        case .nestedCodeUnsupported:
            "Nested code: the full bundle could not be re-signed and verified as one reversible unit."
        case let .invalidBundle(detail):
            "Invalid target: \(detail)"
        }
    }
}
