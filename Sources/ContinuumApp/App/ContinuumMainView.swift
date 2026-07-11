import ContinuumCore
import SwiftUI

struct ContinuumMainView: View {
    @Bindable var model: ContinuumModel

    var body: some View {
        NavigationSplitView {
            ContinuumSidebarView(
                selection: $model.selectedSection,
                snapshotCount: model.snapshots.count,
                appTargetCount: model.setupRecords.count
            )
            .navigationSplitViewColumnWidth(min: 190, ideal: 220, max: 270)
        } detail: {
            detail
        }
        .toolbar {
            ToolbarItemGroup {
                Button {
                    Task { await model.refresh() }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .disabled(model.isLoading || model.isPerformingAction)

                if model.canCaptureRestorableState {
                    Button {
                        Task { await model.saveManualSnapshot() }
                    } label: {
                        Label("Save Snapshot", systemImage: "bookmark.fill")
                    }
                    .disabled(model.isPerformingAction)
                }
            }
        }
    }

    @ViewBuilder
    private var detail: some View {
        switch model.selectedSection {
        case .timeline:
            TimelineDashboardView(
                snapshots: model.snapshots,
                runningProcesses: model.runningProcesses,
                rewindPhase: model.rewindPhase,
                onlineWarning: model.onlineWarning,
                isPerformingAction: model.isPerformingAction,
                canCaptureRestorableState: model.canCaptureRestorableState,
                onSaveSnapshot: { Task { await model.saveManualSnapshot() } },
                onBeginRewind: { snapshot in
                    model.selectedSnapshotID = snapshot.id
                    Task { await model.beginRewind() }
                },
                onCommitRewind: { snapshot in
                    Task { await model.commitRewind(target: snapshot.id) }
                },
                onCancelRewind: { Task { await model.cancelRewind() } },
                onUndoRewind: { Task { await model.undoRewind() } }
            )

        case .snapshots:
            SnapshotLibraryView(
                snapshots: model.snapshots,
                selectedSnapshotID: $model.selectedSnapshotID,
                filter: $model.snapshotFilter,
                onRestore: { snapshot in
                    model.selectedSnapshotID = snapshot.id
                    model.selectedSection = .timeline
                    Task { await model.beginRewind() }
                },
                onDelete: { snapshot in
                    Task { await model.delete(snapshotID: snapshot.id) }
                },
                onUpdate: { snapshot, name, note in
                    Task {
                        if name != snapshot.name {
                            await model.rename(snapshotID: snapshot.id, to: name)
                        }
                        if note != snapshot.note {
                            await model.updateNote(snapshotID: snapshot.id, note: note)
                        }
                    }
                }
            )

        case .branches:
            BranchTreeView(
                branches: model.branches,
                snapshots: model.snapshots,
                selectedBranchID: $model.selectedBranchID
            )

        case .apps:
            AppsCompatibilityView(
                reports: model.appReports,
                setupRecords: model.setupRecords,
                runningProcesses: model.runningProcesses,
                isBatchSetupInProgress: model.isBatchSetupInProgress,
                setupOperation: { model.setupOperation(for: $0) },
                onCheckSetup: { app in
                    Task { await model.checkSetup(for: app) }
                },
                onSetupManagedCopy: { app in
                    Task { await model.setUpManagedCopy(for: app) }
                },
                onRecheckSetup: { record in
                    Task { await model.recheckSetup(record) }
                },
                onRemoveSetup: { record in
                    Task { await model.removeSetup(record) }
                },
                onSetupEligibleApps: {
                    Task { await model.setUpEligibleApps() }
                },
                onAddTarget: { url in
                    Task { await model.addApplicationTarget(at: url) }
                }
            )

        case .storage:
            StorageOverviewView(metrics: model.storageMetrics, snapshots: model.snapshots)
        }
    }
}
