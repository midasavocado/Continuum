import SwiftUI

struct HowRewindWorksView: View {
    private let stages = [
        ("1", "Continuum saves checkpoints", "Only apps that pass a restore check are marked rewindable."),
        ("2", "You open Rewind", "Continuum freezes the app and first saves a Before Rewind snapshot."),
        ("3", "You choose a moment", "Play From Here restores validated local state and starts a new branch."),
        ("4", "Nothing is thrown away", "Undo Rewind returns to the future you left, after saving your new path too.")
    ]

    var body: some View {
        OnboardingPage(
            title: "The restore contract",
            subtitle: "These steps remain locked for an app until its backend proves every one of them."
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
                message: "A thumbnail can help you find a moment, but it is never treated as restorable state. If Continuum cannot validate a restore, Play From Here stays unavailable."
            )
        }
    }
}
