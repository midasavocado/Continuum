import SwiftUI

struct ReadyOnboardingView: View {
    let selectedStorageGigabytes: Int

    var body: some View {
        OnboardingPage(
            title: "The prototype is ready",
            subtitle: "The shortcuts work anywhere. Restore remains visibly unavailable until real app state passes validation."
        ) {
            VStack(spacing: 11) {
                shortcutRow(
                    keys: ["⌃", "⌥", "⌘", "S"],
                    title: "Save Diagnostic Snapshot",
                    detail: "Permanently records encrypted process diagnostics for the frontmost app."
                )
                shortcutRow(
                    keys: ["⌃", "⌥", "⌘", "R"],
                    title: "Open Rewind Timeline",
                    detail: "Opens the floating keyboard timeline; Return works only on validated states."
                )
            }

            OnboardingCard {
                HStack(spacing: 14) {
                    Image(systemName: "internaldrive.fill")
                        .font(.title2)
                        .foregroundStyle(.tint)
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 3) {
                        Text("\(selectedStorageGigabytes) GB planned history budget")
                            .font(.headline)
                        Text("Change the shortcut, timeline step, and future capture targets in Continuum Settings.")
                            .foregroundStyle(.secondary)
                    }
                }
            }

            OnboardingCallout(
                title: "Expect Restore unavailable",
                message: "This build deliberately marks scanned apps unavailable until restore certification passes. It will not pretend a screenshot or metadata record is restored app state."
            )
        }
    }

    private func shortcutRow(keys: [String], title: String, detail: String) -> some View {
        OnboardingCard {
            HStack(spacing: 18) {
                ShortcutKeycaps(keys: keys)
                    .frame(width: 145, alignment: .leading)
                VStack(alignment: .leading, spacing: 3) {
                    Text(title)
                        .font(.headline)
                    Text(detail)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .accessibilityElement(children: .contain)
    }
}
