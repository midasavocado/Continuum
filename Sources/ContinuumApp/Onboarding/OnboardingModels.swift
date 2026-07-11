import Combine
import ContinuumCore
import Foundation

private let onboardingDemoOriginalText = "Orbit: stable\nNext maneuver: raise apoapsis"

enum OnboardingStep: Int, CaseIterable, Codable, Identifiable {
    case welcome
    case howRewindWorks
    case permissions
    case compatibility
    case storage
    case demo
    case ready

    var id: Int { rawValue }

    var title: String {
        switch self {
        case .welcome: "Welcome"
        case .howRewindWorks: "How it works"
        case .permissions: "Permissions"
        case .compatibility: "Compatibility"
        case .storage: "Storage"
        case .demo: "Try it"
        case .ready: "Ready"
        }
    }

    var next: OnboardingStep? {
        Self(rawValue: rawValue + 1)
    }

    var previous: OnboardingStep? {
        Self(rawValue: rawValue - 1)
    }
}

enum OnboardingDemoPhase: String, Codable {
    case readyToSave
    case snapshotSaved
    case changed
    case rewound
    case undone
}

struct OnboardingResumeState: Codable, Equatable {
    var currentStep: OnboardingStep
    var completedSteps: Set<OnboardingStep>
    var isSkipped: Bool
    var demoPhase: OnboardingDemoPhase
    var demoText: String
    var beforeRewindText: String?

    static let initial = OnboardingResumeState(
        currentStep: .welcome,
        completedSteps: [],
        isSkipped: false,
        demoPhase: .readyToSave,
        demoText: onboardingDemoOriginalText,
        beforeRewindText: nil
    )
}

@MainActor
final class OnboardingProgress: ObservableObject {
    static let demoOriginalText = onboardingDemoOriginalText

    @Published var currentStep: OnboardingStep
    @Published private(set) var completedSteps: Set<OnboardingStep>
    @Published private(set) var isSkipped: Bool
    @Published var demoPhase: OnboardingDemoPhase
    @Published var demoText: String
    @Published private(set) var beforeRewindText: String?

    init(resuming state: OnboardingResumeState = .initial) {
        currentStep = state.currentStep
        completedSteps = state.completedSteps
        isSkipped = state.isSkipped
        demoPhase = state.demoPhase
        demoText = state.demoText
        beforeRewindText = state.beforeRewindText
    }

    var resumeState: OnboardingResumeState {
        OnboardingResumeState(
            currentStep: currentStep,
            completedSteps: completedSteps,
            isSkipped: isSkipped,
            demoPhase: demoPhase,
            demoText: demoText,
            beforeRewindText: beforeRewindText
        )
    }

    var canGoBack: Bool { currentStep.previous != nil }
    var isLastStep: Bool { currentStep == .ready }
    var demoIsComplete: Bool { demoPhase == .undone }

    func advance() {
        completedSteps.insert(currentStep)
        guard let next = currentStep.next else { return }
        currentStep = next
    }

    func goBack() {
        guard let previous = currentStep.previous else { return }
        currentStep = previous
    }

    func jump(to step: OnboardingStep) {
        guard step.rawValue <= furthestReachableStep.rawValue else { return }
        currentStep = step
    }

    func skip() {
        isSkipped = true
    }

    func resume() {
        isSkipped = false
    }

    func finish() {
        completedSteps.formUnion(OnboardingStep.allCases)
        isSkipped = false
    }

    func saveDemoSnapshot() {
        guard demoPhase == .readyToSave else { return }
        demoPhase = .snapshotSaved
    }

    func applyDemoChange() {
        guard demoPhase == .snapshotSaved else { return }
        demoText = "Orbit: unstable\nNext maneuver: absolutely panic"
        demoPhase = .changed
    }

    func acceptDemoEdit() {
        guard demoPhase == .snapshotSaved, demoText != Self.demoOriginalText else { return }
        demoPhase = .changed
    }

    func rewindDemo() {
        guard demoPhase == .changed else { return }
        demoText = Self.demoOriginalText
        beforeRewindText = nil
        demoPhase = .undone
    }

    func undoDemoRewind() {
        guard demoPhase == .rewound, let beforeRewindText else { return }
        demoText = beforeRewindText
        demoPhase = .undone
    }

    func resetDemo() {
        demoText = Self.demoOriginalText
        beforeRewindText = nil
        demoPhase = .readyToSave
    }

    func resetToStart() {
        let initial = OnboardingResumeState.initial
        currentStep = initial.currentStep
        completedSteps = initial.completedSteps
        isSkipped = initial.isSkipped
        demoPhase = initial.demoPhase
        demoText = initial.demoText
        beforeRewindText = initial.beforeRewindText
    }

    private var furthestReachableStep: OnboardingStep {
        let completedRawValue = completedSteps.map(\.rawValue).max() ?? -1
        return OnboardingStep(rawValue: min(completedRawValue + 1, OnboardingStep.ready.rawValue)) ?? .welcome
    }
}

struct ContinuumOnboardingActions {
    var requestPermission: (PermissionKind) -> Void
    var openPermissionSettings: (PermissionKind) -> Void
    var refreshPermissions: () -> Void
    var runCompatibilityScan: () -> Void
    var refreshStorage: () -> Void
    var skip: () -> Void
    var finish: () -> Void

    init(
        requestPermission: @escaping (PermissionKind) -> Void = { _ in },
        openPermissionSettings: @escaping (PermissionKind) -> Void = { _ in },
        refreshPermissions: @escaping () -> Void = {},
        runCompatibilityScan: @escaping () -> Void = {},
        refreshStorage: @escaping () -> Void = {},
        skip: @escaping () -> Void = {},
        finish: @escaping () -> Void = {}
    ) {
        self.requestPermission = requestPermission
        self.openPermissionSettings = openPermissionSettings
        self.refreshPermissions = refreshPermissions
        self.runCompatibilityScan = runCompatibilityScan
        self.refreshStorage = refreshStorage
        self.skip = skip
        self.finish = finish
    }
}

struct OnboardingErrorState: Equatable {
    let title: String
    let message: String
}

extension PermissionKind {
    var onboardingTitle: String {
        switch self {
        case .accessibility: "Accessibility"
        case .screenRecording: "Screen Recording"
        case .automation: "Automation"
        case .fullDiskAccess: "Full Disk Access"
        }
    }

    var onboardingSymbol: String {
        switch self {
        case .accessibility: "figure.arms.open"
        case .screenRecording: "rectangle.dashed.badge.record"
        case .automation: "gearshape.2"
        case .fullDiskAccess: "internaldrive"
        }
    }

    var onboardingRequirement: String {
        switch self {
        case .accessibility, .screenRecording: "Recommended"
        case .automation: "Per app"
        case .fullDiskAccess: "Optional"
        }
    }

    var onboardingPurpose: String {
        switch self {
        case .accessibility:
            "Helps Continuum identify windows and coordinate supported app controls."
        case .screenRecording:
            "Creates private timeline previews. Images never count as restored app state."
        case .automation:
            "Requested separately for an app only when a supported bridge actually uses it."
        case .fullDiskAccess:
            "May be needed later to version protected app files and databases."
        }
    }
}

extension PermissionState {
    var onboardingTitle: String {
        switch self {
        case .granted: "Allowed"
        case .denied: "Not allowed"
        case .notRequested: "Not set up"
        case .requiresSystemSettings: "Finish in Settings"
        case .unknown: "Checking"
        }
    }

    var onboardingSymbol: String {
        switch self {
        case .granted: "checkmark.circle.fill"
        case .denied: "xmark.circle.fill"
        case .notRequested: "circle.dashed"
        case .requiresSystemSettings: "gearshape.fill"
        case .unknown: "questionmark.circle"
        }
    }
}

extension CompatibilityTier {
    var onboardingTitle: String {
        switch self {
        case .directPlugin: "Direct-loader candidate"
        case .launchInjection: "Launch-runtime candidate"
        case .managedInstrumentation: "Instrumentation candidate"
        case .protectedBridge: "Bridge candidate"
        case .unsupported: "Not rewindable"
        }
    }

    var onboardingExplanation: String {
        switch self {
        case .directPlugin:
            "An existing extension loader may be useful, but no restore backend is certified for this route yet."
        case .launchInjection:
            "Its signature may permit launch-time research; restoration is not implemented yet."
        case .managedInstrumentation:
            "Requires a reversible app backup and setup. Updates must be checked again."
        case .protectedBridge:
            "Uses app automation. Only state that the bridge validates can be rewound."
        case .unsupported:
            "Protected, DRM, anti-cheat, or inaccessible state prevents an honest restore."
        }
    }
}
