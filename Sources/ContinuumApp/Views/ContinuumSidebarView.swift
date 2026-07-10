import SwiftUI
import ContinuumCore

struct ContinuumSidebarView: View {
    @Binding var selection: ContinuumSection
    let snapshotCount: Int
    let appIssueCount: Int

    var body: some View {
        List(selection: $selection) {
            Section("Continuum") {
                ForEach(ContinuumSection.allCases) { section in
                    HStack(spacing: 10) {
                        Image(systemName: section.systemImage)
                            .foregroundStyle(.secondary)
                            .frame(width: 18)

                        Text(section.title)

                        Spacer(minLength: 8)

                        if let count = badgeCount(for: section), count > 0 {
                            Text(count, format: .number)
                                .font(.caption.monospacedDigit())
                                .foregroundStyle(.secondary)
                        }
                    }
                    .tag(section)
                }
            }
        }
        .listStyle(.sidebar)
        .navigationTitle("Continuum")
    }

    private func badgeCount(for section: ContinuumSection) -> Int? {
        switch section {
        case .snapshots: snapshotCount
        case .apps: appIssueCount
        default: nil
        }
    }
}
