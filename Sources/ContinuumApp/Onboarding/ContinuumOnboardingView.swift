import ContinuumCore
import SwiftUI

struct ContinuumOnboardingView: View {
    @ObservedObject var progress: OnboardingProgress
    @Binding private var storageBudgetGigabytes: Int

    let permissionStatuses: [PermissionStatus]
    let isRefreshingPermissions: Bool
    let requestingPermission: PermissionKind?
    let permissionError: OnboardingErrorState?
    let compatibilityReports: [CompatibilityReport]
    let isScanningCompatibility: Bool
    let compatibilityError: OnboardingErrorState?
    let freeDiskSpaceBytes: Int64?
    let storageReserveBytes: Int64
    let storageError: OnboardingErrorState?
    let actions: ContinuumOnboardingActions

    @State private var navigationDirection: NavigationDirection = .forward

    init(
        progress: OnboardingProgress,
        storageBudgetGigabytes: Binding<Int>,
        permissionStatuses: [PermissionStatus] = [],
        isRefreshingPermissions: Bool = false,
        requestingPermission: PermissionKind? = nil,
        permissionError: OnboardingErrorState? = nil,
        compatibilityReports: [CompatibilityReport] = [],
        isScanningCompatibility: Bool = false,
        compatibilityError: OnboardingErrorState? = nil,
        freeDiskSpaceBytes: Int64? = nil,
        storageReserveBytes: Int64 = 15_000_000_000,
        storageError: OnboardingErrorState? = nil,
        actions: ContinuumOnboardingActions = .init()
    ) {
        self.progress = progress
        _storageBudgetGigabytes = storageBudgetGigabytes
        self.permissionStatuses = permissionStatuses
        self.isRefreshingPermissions = isRefreshingPermissions
        self.requestingPermission = requestingPermission
        self.permissionError = permissionError
        self.compatibilityReports = compatibilityReports
        self.isScanningCompatibility = isScanningCompatibility
        self.compatibilityError = compatibilityError
        self.freeDiskSpaceBytes = freeDiskSpaceBytes
        self.storageReserveBytes = storageReserveBytes
        self.storageError = storageError
        self.actions = actions
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ZStack {
                currentPage
                    .id(progress.currentStep)
                    .transition(pageTransition)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .clipped()
            Divider()
            footer
        }
        .frame(minWidth: 760, idealWidth: 860, minHeight: 590, idealHeight: 680)
        .background(.ultraThinMaterial)
        .onAppear {
            progress.resume()
        }
    }

    private var header: some View {
        HStack(spacing: 16) {
            Label("Continuum", systemImage: "arrow.counterclockwise.circle.fill")
                .font(.headline)
                .accessibilityAddTraits(.isHeader)

            Spacer()

            OnboardingStepIndicator(
                currentStep: progress.currentStep,
                completedSteps: progress.completedSteps,
                select: { step in
                    navigate(
                        step.rawValue < progress.currentStep.rawValue ? .backward : .forward
                    ) {
                        progress.jump(to: step)
                    }
                }
            )

            Spacer()

            Text("Step \(progress.currentStep.rawValue + 1) of \(OnboardingStep.allCases.count)")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
                .accessibilityLabel("Step \(progress.currentStep.rawValue + 1) of \(OnboardingStep.allCases.count): \(progress.currentStep.title)")
        }
        .padding(.horizontal, 22)
        .frame(height: 52)
    }

    @ViewBuilder
    private var currentPage: some View {
        switch progress.currentStep {
        case .welcome:
            WelcomeOnboardingView()
        case .howRewindWorks:
            HowRewindWorksView()
        case .permissions:
            PermissionChecklistView(
                statuses: permissionStatuses,
                isRefreshing: isRefreshingPermissions,
                requestingPermission: requestingPermission,
                error: permissionError,
                request: actions.requestPermission,
                openSettings: actions.openPermissionSettings,
                refresh: actions.refreshPermissions
            )
        case .compatibility:
            CompatibilityScanView(
                reports: compatibilityReports,
                isScanning: isScanningCompatibility,
                error: compatibilityError,
                scan: actions.runCompatibilityScan
            )
        case .storage:
            StorageSetupView(
                selectedGigabytes: $storageBudgetGigabytes,
                freeDiskSpaceBytes: freeDiskSpaceBytes,
                reserveBytes: storageReserveBytes,
                error: storageError,
                refresh: actions.refreshStorage
            )
        case .demo:
            OnboardingDemoView(progress: progress)
        case .ready:
            ReadyOnboardingView(selectedStorageGigabytes: storageBudgetGigabytes)
        }
    }

    private var footer: some View {
        HStack(spacing: 12) {
            if progress.canGoBack {
                Button("Back") {
                    navigate(.backward, action: progress.goBack)
                }
                    .keyboardShortcut(.leftArrow, modifiers: [.command])
                    .accessibilityHint("Returns to \(progress.currentStep.previous?.title ?? "the previous step")")
            }

            Button("Skip for Now") {
                progress.skip()
                actions.skip()
            }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)
            .accessibilityHint("Opens the prototype now; setup can be restarted from Settings")

            Spacer()

            Button(primaryActionTitle, action: performPrimaryAction)
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
                .disabled(primaryActionIsDisabled)
                .accessibilityHint(primaryActionHint)
        }
        .padding(.horizontal, 22)
        .frame(height: 64)
    }

    private var primaryActionTitle: String {
        progress.isLastStep ? "Start Continuum" : "Continue"
    }

    private var primaryActionIsDisabled: Bool {
        switch progress.currentStep {
        case .compatibility:
            compatibilityReports.isEmpty || isScanningCompatibility
        case .demo:
            !progress.demoIsComplete
        default:
            false
        }
    }

    private var primaryActionHint: String {
        if progress.currentStep == .compatibility, compatibilityReports.isEmpty {
            return "Scan apps before continuing"
        }
        if progress.currentStep == .compatibility, isScanningCompatibility {
            return "Wait for the compatibility scan to finish"
        }
        if progress.currentStep == .demo && !progress.demoIsComplete {
            return "Complete the safe demo before continuing"
        }
        if progress.isLastStep {
            return "Finishes onboarding"
        }
        return "Continues to \(progress.currentStep.next?.title ?? "the next step")"
    }

    private func performPrimaryAction() {
        if progress.isLastStep {
            progress.finish()
            actions.finish()
        } else {
            navigate(.forward, action: progress.advance)
        }
    }

    private var pageTransition: AnyTransition {
        switch navigationDirection {
        case .forward:
            .asymmetric(
                insertion: .move(edge: .trailing).combined(with: .opacity),
                removal: .move(edge: .leading).combined(with: .opacity)
            )
        case .backward:
            .asymmetric(
                insertion: .move(edge: .leading).combined(with: .opacity),
                removal: .move(edge: .trailing).combined(with: .opacity)
            )
        }
    }

    private func navigate(_ direction: NavigationDirection, action: () -> Void) {
        navigationDirection = direction
        withAnimation(.snappy(duration: 0.32)) {
            action()
        }
    }
}

private enum NavigationDirection {
    case forward
    case backward
}
