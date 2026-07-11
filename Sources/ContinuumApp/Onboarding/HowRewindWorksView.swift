import SwiftUI

struct HowRewindWorksView: View {
    private let stages = [
        ("1", "Save a snapshot", "Switch to an app and press the Snapshot shortcut."),
        ("2", "Restore it", "Choose that snapshot and press Restore. Continuum puts the live app back at that point.")
    ]

    var body: some View {
        OnboardingPage(
            title: "The restore contract",
            subtitle: "For now, Continuum does one thing: snapshot, then restore."
        ) {
            VStack(spacing: 11) {
                ForEach(stages, id: \.0) { stage in
                    OnboardingCard {
                        HStack(alignment: .top, spacing: 15) {
                            Text(stage.0)
                                .font(.title2.bold())
                                .foregroundStyle(.tint)
                                .frame(width: 28, alignment: .center)
                                .accessibilityHidden(true)

                            VStack(alignment: .leading, spacing: 4) {
                                Text(stage.1)
                                    .font(.headline)
                                Text(stage.2)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityLabel("Step \(stage.0). \(stage.1). \(stage.2)")
                }
            }

            OnboardingCallout(
                title: "No screenshot tricks",
                message: "A thumbnail can help identify a snapshot, but only captured app state enables Restore."
            )
        }
    }
}
