import ContinuumCore
import SwiftUI

struct ContinuumRootView: View {
    @Bindable var model: ContinuumModel
    let lifecycle: AppLifecycleController

    @StateObject private var onboardingProgress: OnboardingProgress
    @AppStorage("continuum.storageBudgetGigabytes") private var storageBudgetGigabytes = 20

    init(model: ContinuumModel, lifecycle: AppLifecycleController) {
        self.model = model
        self.lifecycle = lifecycle
        _onboardingProgress = StateObject(
            wrappedValue: OnboardingProgress(resuming: OnboardingPersistence.load())
        )
    }

    var body: some View {
        Group {
            if model.isOnboardingComplete {
                ContinuumMainView(model: model)
            } else {
                onboarding
            }
        }
        .task {
            lifecycle.start(model: model)
            await model.load()
        }
        .onChange(of: onboardingProgress.resumeState) { _, newValue in
            OnboardingPersistence.save(newValue)
        }
        .onChange(of: model.onboardingResetGeneration) { _, _ in
            onboardingProgress.resetToStart()
        }
        .alert(
            "Continuum couldn’t finish that",
            isPresented: Binding(
                get: { model.presentedError != nil },
                set: { if !$0 { model.dismissError() } }
            )
        ) {
            Button("OK", role: .cancel) { model.dismissError() }
        } message: {
            Text(model.presentedError ?? "Unknown error")
        }
    }

    private var onboarding: some View {
        ContinuumOnboardingView(
            progress: onboardingProgress,
            storageBudgetGigabytes: $storageBudgetGigabytes,
            permissionStatuses: model.permissionStatuses,
            isRefreshingPermissions: model.isRefreshingPermissions,
            requestingPermission: model.requestingPermission,
            compatibilityReports: model.appReports,
            isScanningCompatibility: model.isLoading,
            freeDiskSpaceBytes: availableDiskSpace,
            actions: ContinuumOnboardingActions(
                requestPermission: { permission in
                    Task { await model.requestPermission(permission) }
                },
                openPermissionSettings: { permission in
                    Task { await model.openSystemSettings(for: permission) }
                },
                refreshPermissions: {
                    Task { await model.refreshPermissions() }
                },
                runCompatibilityScan: {
                    Task { await model.refresh() }
                },
                refreshStorage: {},
                skip: {
                    model.completeOnboarding()
                },
                finish: {
                    model.completeOnboarding()
                }
            )
        )
    }

    private var availableDiskSpace: Int64? {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let values = try? home.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
        return values?.volumeAvailableCapacityForImportantUsage
    }
}

private enum OnboardingPersistence {
    private static let key = "continuum.onboarding.resumeState"

    static func load(defaults: UserDefaults = .standard) -> OnboardingResumeState {
        guard let data = defaults.data(forKey: key),
              let state = try? JSONDecoder().decode(OnboardingResumeState.self, from: data) else {
            return .initial
        }
        return state
    }

    static func save(_ state: OnboardingResumeState, defaults: UserDefaults = .standard) {
        guard let data = try? JSONEncoder().encode(state) else { return }
        defaults.set(data, forKey: key)
    }
}
