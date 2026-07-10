import ContinuumCore
import SwiftUI

struct PermissionChecklistView: View {
    @Environment(\.scenePhase) private var scenePhase

    let statuses: [PermissionStatus]
    let isRefreshing: Bool
    let requestingPermission: PermissionKind?
    let error: OnboardingErrorState?
    let request: (PermissionKind) -> Void
    let openSettings: (PermissionKind) -> Void
    let refresh: () -> Void

    @AppStorage("continuum.permissions.accessibilityRequestAttempted")
    private var accessibilityRequestAttempted = false
    @AppStorage("continuum.permissions.screenRecordingRequestAttempted")
    private var screenRecordingRequestAttempted = false
    @State private var showsAdvancedPermissions = false

    private let recommendedKinds: [PermissionKind] = [
        .accessibility,
        .screenRecording
    ]

    var body: some View {
        OnboardingPage(
            title: "Two quick permissions",
            subtitle: "macOS shows the real permission dialogs. You can continue without either and change them later."
        ) {
            VStack(alignment: .leading, spacing: 14) {
                readinessSummary

                HStack(alignment: .top, spacing: 14) {
                    ForEach(recommendedKinds) { kind in
                        permissionTile(kind)
                            .frame(maxWidth: .infinity)
                    }
                }

                advancedPermissions

                if let error {
                    OnboardingCallout(
                        title: error.title,
                        message: error.message,
                        tone: .error,
                        retryTitle: "Try Again",
                        retry: refresh
                    )
                }

                HStack(spacing: 9) {
                    if isRefreshing {
                        ProgressView()
                            .controlSize(.small)
                        Text("Checking with macOS…")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }

                    Spacer()

                    Button("Check Again", systemImage: "arrow.clockwise", action: refresh)
                        .disabled(isRefreshing || requestingPermission != nil)
                        .accessibilityHint("Refreshes permission status from macOS")
                }
            }
        }
        .onChange(of: scenePhase) { _, phase in
            guard phase == .active else { return }
            refresh()
        }
        .onAppear(perform: refresh)
        .animation(.snappy(duration: 0.28), value: grantedRecommendedCount)
        .animation(.snappy(duration: 0.28), value: accessibilityRequestAttempted)
        .animation(.snappy(duration: 0.28), value: screenRecordingRequestAttempted)
        .animation(.snappy(duration: 0.28), value: showsAdvancedPermissions)
    }

    private var readinessSummary: some View {
        HStack(spacing: 12) {
            Image(systemName: grantedRecommendedCount == recommendedKinds.count
                ? "checkmark.shield.fill"
                : "hand.raised.fill")
                .font(.title2)
                .foregroundStyle(
                    grantedRecommendedCount == recommendedKinds.count
                        ? Color.green
                        : Color.accentColor
                )
                .frame(width: 42, height: 42)
                .background(Color.accentColor.opacity(0.1), in: Circle())
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 3) {
                Text(readinessTitle)
                    .font(.headline)
                Text(readinessMessage)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            Spacer(minLength: 12)

            Text("\(grantedRecommendedCount) of \(recommendedKinds.count) ready")
                .font(.callout.monospacedDigit().weight(.semibold))
                .foregroundStyle(grantedRecommendedCount == recommendedKinds.count ? .green : .secondary)
                .padding(.horizontal, 10)
                .padding(.vertical, 5)
                .background(.quaternary, in: Capsule())
        }
        .padding(14)
        .background(Color.accentColor.opacity(0.06), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .stroke(Color.accentColor.opacity(0.18), lineWidth: 1)
        }
        .accessibilityElement(children: .combine)
    }

    private func permissionTile(_ kind: PermissionKind) -> some View {
        let state = status(for: kind).state
        let isGranted = state == .granted
        let isChecking = state == .unknown
        let wasRequested = requestWasAttempted(for: kind)
        let isActive = requestingPermission == kind

        return VStack(alignment: .leading, spacing: 13) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: kind.onboardingSymbol)
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(.tint)
                    .frame(width: 38, height: 38)
                    .background(.tint.opacity(0.1), in: Circle())
                    .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: 4) {
                    Text(kind.onboardingTitle)
                        .font(.headline)

                    Label(
                        statusTitle(isGranted: isGranted, isChecking: isChecking),
                        systemImage: isGranted
                            ? "checkmark.circle.fill"
                            : (isChecking ? "clock" : "circle.dashed")
                    )
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(isGranted ? .green : .secondary)
                }
            }

            Text(kind.onboardingPurpose)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Spacer(minLength: 0)

            permissionAction(
                for: kind,
                isGranted: isGranted,
                isChecking: isChecking,
                wasRequested: wasRequested,
                isActive: isActive
            )
        }
        .padding(16)
        .frame(maxWidth: .infinity, minHeight: 188, alignment: .topLeading)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .stroke(isGranted ? Color.green.opacity(0.35) : Color.secondary.opacity(0.2), lineWidth: 1)
        }
        .accessibilityElement(children: .contain)
    }

    @ViewBuilder
    private func permissionAction(
        for kind: PermissionKind,
        isGranted: Bool,
        isChecking: Bool,
        wasRequested: Bool,
        isActive: Bool
    ) -> some View {
        if isGranted {
            Label("Ready", systemImage: "checkmark")
                .font(.callout.weight(.semibold))
                .foregroundStyle(.green)
                .frame(maxWidth: .infinity, minHeight: 22)
                .accessibilityLabel("\(kind.onboardingTitle) is ready")
        } else if isChecking {
            Label("Checking…", systemImage: "clock")
                .font(.callout.weight(.semibold))
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, minHeight: 22)
        } else if isActive {
            HStack(spacing: 8) {
                ProgressView()
                    .controlSize(.small)
                Text("Waiting for macOS…")
            }
            .font(.callout.weight(.semibold))
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, minHeight: 22)
        } else if wasRequested {
            Button("Open Settings", systemImage: "gearshape") {
                openSettings(kind)
            }
            .buttonStyle(.bordered)
            .controlSize(.large)
            .frame(maxWidth: .infinity)
            .accessibilityHint("Opens the \(kind.onboardingTitle) pane in System Settings")
        } else {
            Button {
                markRequestAttempted(for: kind)
                request(kind)
            } label: {
                Text("Allow \(kind.onboardingTitle)")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(isRefreshing || requestingPermission != nil)
            .accessibilityHint("Asks macOS for \(kind.onboardingTitle) permission")
        }
    }

    private var advancedPermissions: some View {
        OnboardingCard {
            DisclosureGroup(isExpanded: $showsAdvancedPermissions) {
                VStack(spacing: 12) {
                    Divider()

                    advancedPermissionRow(
                        kind: .automation,
                        detail: "Requested separately for each supported app, only when needed."
                    )

                    Divider()

                    advancedPermissionRow(
                        kind: .fullDiskAccess,
                        detail: "Optional for now. Continuum can’t verify this macOS setting.",
                        actionTitle: "Open Settings",
                        action: { openSettings(.fullDiskAccess) }
                    )
                }
                .padding(.top, 12)
            } label: {
                HStack(spacing: 10) {
                    Image(systemName: "slider.horizontal.3")
                        .foregroundStyle(.tint)
                        .accessibilityHidden(true)

                    VStack(alignment: .leading, spacing: 2) {
                        Text("More access")
                            .font(.headline)
                        Text("Only requested when a feature actually needs it")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    private func advancedPermissionRow(
        kind: PermissionKind,
        detail: String,
        actionTitle: String? = nil,
        action: (() -> Void)? = nil
    ) -> some View {
        HStack(spacing: 11) {
            Image(systemName: kind.onboardingSymbol)
                .foregroundStyle(.secondary)
                .frame(width: 24)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 7) {
                    Text(kind.onboardingTitle)
                        .font(.callout.weight(.semibold))
                    Text(kind.onboardingRequirement)
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(.quaternary, in: Capsule())
                }
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer(minLength: 10)

            if let actionTitle, let action {
                Button(actionTitle, action: action)
                    .controlSize(.small)
            }
        }
    }

    private func status(for kind: PermissionKind) -> PermissionStatus {
        statuses.first(where: { $0.kind == kind })
            ?? PermissionStatus(kind: kind, state: .unknown, detail: "Checking with macOS.")
    }

    private var grantedRecommendedCount: Int {
        recommendedKinds.filter { status(for: $0).state == .granted }.count
    }

    private var readinessTitle: String {
        if grantedRecommendedCount == recommendedKinds.count { return "You’re ready" }
        if grantedRecommendedCount == 1 { return "One permission to go" }
        return "Set up the useful parts"
    }

    private var readinessMessage: String {
        grantedRecommendedCount == recommendedKinds.count
            ? "Continuum can coordinate windows and make visual timeline previews."
            : "Grant both for the smoothest experience, or keep going and decide later."
    }

    private func statusTitle(isGranted: Bool, isChecking: Bool) -> String {
        if isGranted { return "Allowed" }
        if isChecking { return "Checking…" }
        return "Not yet allowed"
    }

    private func requestWasAttempted(for kind: PermissionKind) -> Bool {
        switch kind {
        case .accessibility:
            accessibilityRequestAttempted
        case .screenRecording:
            screenRecordingRequestAttempted
        case .automation, .fullDiskAccess:
            false
        }
    }

    private func markRequestAttempted(for kind: PermissionKind) {
        switch kind {
        case .accessibility:
            accessibilityRequestAttempted = true
        case .screenRecording:
            screenRecordingRequestAttempted = true
        case .automation, .fullDiskAccess:
            break
        }
    }
}
