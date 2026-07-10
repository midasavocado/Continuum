import SwiftUI

struct OnboardingPage<Content: View>: View {
    let title: String
    let subtitle: String
    @ViewBuilder let content: Content

    init(title: String, subtitle: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.subtitle = subtitle
        self.content = content()
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                VStack(alignment: .leading, spacing: 7) {
                    Text(title)
                        .font(.system(size: 30, weight: .semibold, design: .rounded))
                        .accessibilityAddTraits(.isHeader)

                    Text(subtitle)
                        .font(.title3)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                content
            }
            .frame(maxWidth: 760, alignment: .leading)
            .padding(.horizontal, 38)
            .padding(.vertical, 30)
            .frame(maxWidth: .infinity)
        }
    }
}

struct OnboardingCard<Content: View>: View {
    @ViewBuilder let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        content
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .stroke(.quaternary, lineWidth: 1)
            }
    }
}

struct OnboardingCallout: View {
    enum Tone {
        case information
        case warning
        case error

        var symbol: String {
            switch self {
            case .information: "info.circle.fill"
            case .warning: "exclamationmark.triangle.fill"
            case .error: "xmark.octagon.fill"
            }
        }

        var color: Color {
            switch self {
            case .information: .accentColor
            case .warning: .orange
            case .error: .red
            }
        }
    }

    let title: String
    let message: String
    var tone: Tone = .information
    var retryTitle: String?
    var retry: (() -> Void)?

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: tone.symbol)
                .font(.title3)
                .foregroundStyle(tone.color)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.headline)
                Text(message)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 12)

            if let retryTitle, let retry {
                Button(retryTitle, action: retry)
                    .accessibilityHint("Tries this step again")
            }
        }
        .padding(14)
        .background(tone.color.opacity(0.09), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}

struct ShortcutKeycaps: View {
    let keys: [String]

    var body: some View {
        HStack(spacing: 4) {
            ForEach(keys, id: \.self) { key in
                Text(key)
                    .font(.system(.body, design: .rounded, weight: .semibold))
                    .frame(minWidth: 27, minHeight: 27)
                    .padding(.horizontal, 3)
                    .background(.thickMaterial, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                    .overlay {
                        RoundedRectangle(cornerRadius: 6, style: .continuous)
                            .stroke(.tertiary, lineWidth: 1)
                    }
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(keys.joined(separator: " plus "))
    }
}

struct OnboardingStepIndicator: View {
    let currentStep: OnboardingStep
    let completedSteps: Set<OnboardingStep>
    let select: (OnboardingStep) -> Void

    var body: some View {
        HStack(spacing: 7) {
            ForEach(OnboardingStep.allCases) { step in
                Button {
                    select(step)
                } label: {
                    Circle()
                        .fill(fill(for: step))
                        .frame(width: step == currentStep ? 11 : 8, height: step == currentStep ? 11 : 8)
                        .frame(width: 22, height: 22)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .disabled(!isReachable(step))
                .accessibilityLabel(step.title)
                .accessibilityValue(accessibilityValue(for: step))
            }
        }
    }

    private func isReachable(_ step: OnboardingStep) -> Bool {
        step == currentStep || completedSteps.contains(step) || completedSteps.contains(step.previous ?? step)
    }

    private func fill(for step: OnboardingStep) -> Color {
        if step == currentStep { return .accentColor }
        if completedSteps.contains(step) { return .secondary }
        return .secondary.opacity(0.25)
    }

    private func accessibilityValue(for step: OnboardingStep) -> String {
        if step == currentStep { return "Current step" }
        if completedSteps.contains(step) { return "Completed" }
        return "Not completed"
    }
}
