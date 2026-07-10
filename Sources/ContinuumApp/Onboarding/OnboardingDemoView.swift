import SwiftUI

struct OnboardingDemoView: View {
    @ObservedObject var progress: OnboardingProgress

    var body: some View {
        OnboardingPage(
            title: "Try a safe rewind",
            subtitle: "This little demo never touches another app. It shows exactly when snapshots and branches are created."
        ) {
            OnboardingCard {
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Label("Demo document", systemImage: "doc.text")
                            .font(.headline)
                        Spacer()
                        phaseLabel
                    }

                    TextEditor(text: $progress.demoText)
                        .font(.system(.body, design: .monospaced))
                        .frame(minHeight: 95)
                        .padding(8)
                        .background(.background.opacity(0.55), in: RoundedRectangle(cornerRadius: 9, style: .continuous))
                        .disabled(progress.demoPhase != .snapshotSaved)
                        .accessibilityLabel("Demo document text")
                        .accessibilityHint(progress.demoPhase == .snapshotSaved ? "You may edit the saved text" : "The demo controls this text for the current step")

                    HStack(spacing: 10) {
                        demoAction

                        if progress.demoPhase != .readyToSave {
                            Button("Start Over", action: progress.resetDemo)
                                .accessibilityHint("Resets only this onboarding demo")
                        }
                    }
                }
            }

            timeline

            OnboardingCallout(
                title: calloutTitle,
                message: calloutMessage,
                tone: progress.demoPhase == .changed ? .warning : .information
            )
        }
    }

    private var phaseLabel: some View {
        Text(phaseTitle)
            .font(.caption.weight(.semibold))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(.quaternary, in: Capsule())
            .accessibilityLabel("Demo status: \(phaseTitle)")
    }

    @ViewBuilder
    private var demoAction: some View {
        switch progress.demoPhase {
        case .readyToSave:
            Button("Save Snapshot", action: progress.saveDemoSnapshot)
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.return, modifiers: [])
                .accessibilityHint("Creates the demo's manual snapshot")
        case .snapshotSaved:
            HStack(spacing: 9) {
                Button("Use My Change", action: progress.acceptDemoEdit)
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.return, modifiers: [])
                    .disabled(progress.demoText == OnboardingProgress.demoOriginalText)
                    .accessibilityHint("Keeps your edited demo text as the future to rewind from")
                Button("Make a Sample Change", action: progress.applyDemoChange)
                    .accessibilityHint("Changes the demo document after the snapshot")
            }
        case .changed:
            Button("Rewind", action: progress.rewindDemo)
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.return, modifiers: [])
                .accessibilityHint("Automatically saves the current demo text, then restores the manual snapshot")
        case .rewound:
            Button("Undo Rewind", action: progress.undoDemoRewind)
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.return, modifiers: [])
                .accessibilityHint("Restores the automatically saved Before Rewind snapshot")
        case .undone:
            Label("Demo complete", systemImage: "checkmark.circle.fill")
                .font(.headline)
                .foregroundStyle(.green)
        }
    }

    private var timeline: some View {
        OnboardingCard {
            VStack(alignment: .leading, spacing: 12) {
                Text("Demo timeline")
                    .font(.headline)
                HStack(spacing: 8) {
                    timelineItem(
                        title: "Manual Snapshot",
                        isPresent: progress.demoPhase != .readyToSave,
                        symbol: "camera.fill"
                    )
                    Image(systemName: "arrow.right")
                        .foregroundStyle(.tertiary)
                        .accessibilityHidden(true)
                    timelineItem(
                        title: "Before Rewind",
                        isPresent: [.rewound, .undone].contains(progress.demoPhase),
                        symbol: "arrow.triangle.branch"
                    )
                    Image(systemName: "arrow.right")
                        .foregroundStyle(.tertiary)
                        .accessibilityHidden(true)
                    timelineItem(
                        title: "Undo available",
                        isPresent: progress.demoPhase == .undone,
                        symbol: "arrow.uturn.backward"
                    )
                }
            }
        }
    }

    private func timelineItem(title: String, isPresent: Bool, symbol: String) -> some View {
        Label(title, systemImage: isPresent ? symbol : "circle.dashed")
            .font(.caption.weight(.medium))
            .foregroundStyle(isPresent ? AnyShapeStyle(.tint) : AnyShapeStyle(.tertiary))
            .padding(.horizontal, 9)
            .padding(.vertical, 7)
            .background(.quaternary.opacity(isPresent ? 1 : 0.45), in: Capsule())
            .accessibilityValue(isPresent ? "Created" : "Not created yet")
    }

    private var phaseTitle: String {
        switch progress.demoPhase {
        case .readyToSave: "Ready"
        case .snapshotSaved: "Snapshot saved"
        case .changed: "Changed"
        case .rewound: "Rewound"
        case .undone: "Future restored"
        }
    }

    private var calloutTitle: String {
        switch progress.demoPhase {
        case .readyToSave: "First, save this moment"
        case .snapshotSaved: "Now change the future"
        case .changed: "Rewind is safe to try"
        case .rewound: "Continuum saved Before Rewind first"
        case .undone: "Both paths survived"
        }
    }

    private var calloutMessage: String {
        switch progress.demoPhase {
        case .readyToSave:
            "A manual snapshot is permanent until you delete it."
        case .snapshotSaved:
            "You can edit the text yourself, or use the sample change button."
        case .changed:
            "Rewind will preserve this changed version before restoring the manual snapshot."
        case .rewound:
            "The original text is back, and the changed version is waiting in an automatic safety snapshot."
        case .undone:
            "Undo Rewind restored the changed future. A future certified rewind follows the same preserve-first rule."
        }
    }
}
