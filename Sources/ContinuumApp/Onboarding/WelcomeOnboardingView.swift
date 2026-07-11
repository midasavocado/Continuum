import SwiftUI

struct WelcomeOnboardingView: View {
    var body: some View {
        OnboardingPage(
            title: "Build rewind without pretending.",
            subtitle: "Continuum captures a running Mac app, then restores that captured state later."
        ) {
            HStack(alignment: .top, spacing: 18) {
                feature(
                    symbol: "camera.fill",
                    title: "Inspect a moment",
                    detail: "Save encrypted process diagnostics for the frontmost app without modifying its bundle."
                )
                feature(
                    symbol: "arrow.counterclockwise",
                    title: "Prove restoration",
                    detail: "Restore is enabled only when Continuum captured real app state."
                )
                feature(
                    symbol: "arrow.counterclockwise",
                    title: "Keep every path",
                    detail: "The included demo shows the simple snapshot → restore flow."
                )
            }

            OnboardingCallout(
                title: "Your Mac rewinds. The internet does not.",
                message: "A future certified backend can restore local state, but it cannot unsend a message, reverse a purchase, or undo a server change.",
                tone: .warning
            )

            Label("History stays encrypted on this Mac.", systemImage: "lock.shield.fill")
                .font(.headline)
                .foregroundStyle(.secondary)
                .accessibilityLabel("Your history stays encrypted on this Mac")
        }
    }

    private func feature(symbol: String, title: String, detail: String) -> some View {
        OnboardingCard {
            VStack(alignment: .leading, spacing: 10) {
                Image(systemName: symbol)
                    .font(.system(size: 25, weight: .semibold))
                    .foregroundStyle(.tint)
                    .accessibilityHidden(true)
                Text(title)
                    .font(.headline)
                Text(detail)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityElement(children: .combine)
    }
}
