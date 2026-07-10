import ContinuumCore
import SwiftUI

struct PermissionChecklistView: View {
    let statuses: [PermissionStatus]
    let isRefreshing: Bool
    let error: OnboardingErrorState?
    let request: (PermissionKind) -> Void
    let refresh: () -> Void

    var body: some View {
        OnboardingPage(
            title: "No broad access before it is useful",
            subtitle: "These permissions belong to future restore backends. The metadata-only prototype explains them but does not ask for them."
        ) {
            VStack(spacing: 10) {
                ForEach(PermissionKind.allCases) { kind in
                    permissionRow(kind)
                }
            }

            if let error {
                OnboardingCallout(
                    title: error.title,
                    message: error.message,
                    tone: .error,
                    retryTitle: "Retry",
                    retry: refresh
                )
            }

            HStack {
                if isRefreshing {
                    ProgressView()
                        .controlSize(.small)
                    Text("Checking permissions…")
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Button("Check Again", action: refresh)
                    .disabled(isRefreshing)
                    .accessibilityHint("Refreshes permission status from macOS")
            }

            Text("Nothing on this page opens a privacy prompt. Continuum will ask later only when a selected, certified feature needs access.")
                .font(.footnote)
                .foregroundStyle(.tertiary)
        }
    }

    private func permissionRow(_ kind: PermissionKind) -> some View {
        let status = statuses.first(where: { $0.kind == kind })
        let state = status?.state ?? .unknown

        return OnboardingCard {
            HStack(alignment: .center, spacing: 14) {
                Image(systemName: kind.onboardingSymbol)
                    .font(.title2)
                    .foregroundStyle(.tint)
                    .frame(width: 32)
                    .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Text(kind.onboardingTitle)
                            .font(.headline)
                        Text(kind.onboardingRequirement)
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, 7)
                            .padding(.vertical, 3)
                            .background(.quaternary, in: Capsule())
                    }
                    Text(kind.onboardingPurpose)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    if let detail = status?.detail, !detail.isEmpty {
                        Text(detail)
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                }

                Spacer(minLength: 12)

                VStack(alignment: .trailing, spacing: 7) {
                    Label(state.onboardingTitle, systemImage: state.onboardingSymbol)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(statusColor(state))
                    Text("Not requested")
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func statusColor(_ state: PermissionState) -> Color {
        switch state {
        case .granted: .green
        case .denied: .red
        case .requiresSystemSettings, .notRequested: .orange
        case .unknown: .secondary
        }
    }
}
