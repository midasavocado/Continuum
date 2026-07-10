import ContinuumCore
import SwiftUI

struct CompatibilityScanView: View {
    let reports: [CompatibilityReport]
    let isScanning: Bool
    let error: OnboardingErrorState?
    let scan: () -> Void

    var body: some View {
        OnboardingPage(
            title: "Map the restore research",
            subtitle: "Continuum performs a read-only scan for possible integration paths. A candidate is not a supported app."
        ) {
            if isScanning {
                OnboardingCard {
                    HStack(spacing: 14) {
                        ProgressView()
                            .controlSize(.regular)
                        VStack(alignment: .leading, spacing: 3) {
                            Text("Scanning apps…")
                                .font(.headline)
                            Text("Nothing is modified during this scan.")
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .accessibilityLabel("Scanning apps. Nothing is modified during this scan")
            } else if reports.isEmpty {
                OnboardingCard {
                    VStack(alignment: .leading, spacing: 12) {
                        Label("Ready to inspect this Mac", systemImage: "checklist")
                            .font(.headline)
                        Text("The scan is read-only. Setup is always a separate, explained step.")
                            .foregroundStyle(.secondary)
                        Button("Scan Apps", action: scan)
                            .buttonStyle(.borderedProminent)
                            .keyboardShortcut(.return, modifiers: [])
                            .accessibilityHint("Runs a read-only compatibility scan")
                    }
                }
            } else {
                summary

                VStack(spacing: 10) {
                    ForEach(sortedReports) { report in
                        reportRow(report)
                    }
                }

                HStack {
                    Spacer()
                    Button("Scan Again", action: scan)
                        .accessibilityHint("Refreshes compatibility results")
                }
            }

            if let error {
                OnboardingCallout(
                    title: error.title,
                    message: error.message,
                    tone: .error,
                    retryTitle: "Retry Scan",
                    retry: scan
                )
            }

            OnboardingCallout(
                title: "The promise is deliberately strict",
                message: "Capture-only apps are not called rewindable. Protected or unsupported apps never get a decorative Play From Here button."
            )
        }
    }

    private var sortedReports: [CompatibilityReport] {
        reports.sorted {
            if $0.canRestoreNow != $1.canRestoreNow { return $0.canRestoreNow }
            return $0.app.displayName.localizedCaseInsensitiveCompare($1.app.displayName) == .orderedAscending
        }
    }

    private var summary: some View {
        let rewindable = reports.filter(\.canRestoreNow).count
        let researchCandidates = reports.filter { !$0.canRestoreNow && $0.tier != .unsupported }.count

        return HStack(spacing: 14) {
            summaryMetric(value: rewindable, label: "Ready now", symbol: "checkmark.circle.fill", color: .green)
            summaryMetric(value: researchCandidates, label: "Research candidates", symbol: "hammer.fill", color: .orange)
            summaryMetric(value: reports.count - rewindable - researchCandidates, label: "Unavailable", symbol: "xmark.circle.fill", color: .secondary)
        }
    }

    private func summaryMetric(value: Int, label: String, symbol: String, color: Color) -> some View {
        OnboardingCard {
            HStack(spacing: 10) {
                Image(systemName: symbol)
                    .foregroundStyle(color)
                    .accessibilityHidden(true)
                Text("\(value)")
                    .font(.title2.bold())
                Text(label)
                    .foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(value) apps \(label)")
    }

    private func reportRow(_ report: CompatibilityReport) -> some View {
        let result = restoreResult(for: report)

        return OnboardingCard {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: "app.fill")
                    .font(.title2)
                    .foregroundStyle(.tint)
                    .frame(width: 32)
                    .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Text(report.app.displayName)
                            .font(.headline)
                        if let version = report.app.version, !version.isEmpty {
                            Text(version)
                                .font(.caption)
                                .foregroundStyle(.tertiary)
                        }
                    }
                    Text(report.tier.onboardingTitle)
                        .font(.subheadline.weight(.medium))
                    Text(report.tier.onboardingExplanation)
                        .foregroundStyle(.secondary)
                    if !report.explanation.isEmpty {
                        Text(report.explanation)
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                }

                Spacer(minLength: 12)

                Label(result.title, systemImage: result.symbol)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(result.color)
                    .fixedSize()
            }
        }
        .accessibilityElement(children: .combine)
    }

    private func restoreResult(for report: CompatibilityReport) -> (title: String, symbol: String, color: Color) {
        if report.canRestoreNow {
            return ("Ready to rewind", "checkmark.circle.fill", .green)
        }
        if report.canCaptureNow {
            return ("Capture only", "exclamationmark.circle.fill", .orange)
        }
        if report.tier == .unsupported {
            return ("Not rewindable", "xmark.circle.fill", .secondary)
        }
        return ("Research candidate", "hammer.fill", .orange)
    }
}
