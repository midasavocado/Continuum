import SwiftUI
import ContinuumCore

struct AppsCompatibilityView: View {
    let reports: [CompatibilityReport]
    let runningProcesses: [ProcessDescriptor]

    @State private var searchText = ""
    @State private var selectedAppID: String?

    private var filteredReports: [CompatibilityReport] {
        reports
            .filter { searchText.isEmpty || $0.app.displayName.localizedStandardContains(searchText) }
            .sorted {
                if $0.canRestoreNow != $1.canRestoreNow { return $0.canRestoreNow }
                return $0.app.displayName.localizedStandardCompare($1.app.displayName) == .orderedAscending
            }
    }

    private var selectedReport: CompatibilityReport? {
        reports.first { $0.id == selectedAppID }
    }

    var body: some View {
        VStack(spacing: 0) {
            summary
                .padding(20)
            Divider()

            HSplitView {
                reportList
                    .frame(minWidth: 320, idealWidth: 360)

                if let selectedReport {
                    AppCompatibilityDetailView(
                        report: selectedReport,
                        isRunning: runningProcesses.contains { $0.app.id == selectedReport.app.id && !$0.isTerminated }
                    )
                    .frame(minWidth: 400, maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    ContentUnavailableView {
                        Label("Choose an app", systemImage: "app.badge.checkmark")
                    } description: {
                        Text("Continuum explains exactly what it can capture and restore for each app.")
                    }
                    .frame(minWidth: 400, maxWidth: .infinity, maxHeight: .infinity)
                }
            }
        }
        .navigationTitle("Apps")
        .searchable(text: $searchText, prompt: "Search apps")
        .onAppear(perform: ensureSelection)
        .onChange(of: filteredReports.map(\.id)) { _, _ in ensureSelection() }
    }

    private var summary: some View {
        HStack(spacing: 12) {
            MetricTile(
                title: "Ready",
                value: reports.filter(\.canRestoreNow).count.formatted(),
                detail: "Full local restore available",
                systemImage: "checkmark.circle.fill",
                tint: .green
            )
            MetricTile(
                title: "Candidates",
                value: reports.filter { !$0.canRestoreNow && $0.tier != .unsupported }.count.formatted(),
                detail: "Backend research only",
                systemImage: "hammer.fill",
                tint: .orange
            )
            MetricTile(
                title: "Unavailable",
                value: reports.filter { $0.tier == .unsupported }.count.formatted(),
                detail: "No fake restore offered",
                systemImage: "nosign",
                tint: .secondary
            )
        }
    }

    @ViewBuilder
    private var reportList: some View {
        if filteredReports.isEmpty {
            ContentUnavailableView.search(text: searchText)
        } else {
            List(selection: $selectedAppID) {
                ForEach(filteredReports) { report in
                    HStack(spacing: 10) {
                        Image(systemName: "app.fill")
                            .foregroundStyle(.secondary)
                            .frame(width: 22)

                        VStack(alignment: .leading, spacing: 3) {
                            Text(report.app.displayName)
                                .fontWeight(.medium)
                                .lineLimit(1)
                            Text(report.continuumStatusTitle)
                                .font(.caption)
                                .foregroundStyle(report.continuumStatusTint)
                        }

                        Spacer()
                        Image(systemName: report.continuumStatusSymbol)
                            .foregroundStyle(report.continuumStatusTint)
                    }
                    .padding(.vertical, 4)
                    .tag(report.id)
                }
            }
            .listStyle(.inset)
        }
    }

    private func ensureSelection() {
        guard selectedReport == nil else { return }
        selectedAppID = filteredReports.first?.id
    }
}

private struct AppCompatibilityDetailView: View {
    let report: CompatibilityReport
    let isRunning: Bool

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                HStack(alignment: .top, spacing: 14) {
                    Image(systemName: "app.fill")
                        .font(.system(size: 28))
                        .foregroundStyle(.secondary)
                        .frame(width: 44, height: 44)
                        .background(.quaternary, in: RoundedRectangle(cornerRadius: 10))

                    VStack(alignment: .leading, spacing: 4) {
                        Text(report.app.displayName)
                            .font(.title.weight(.semibold))
                        Text(report.app.version.map { "Version \($0)" } ?? "Version unavailable")
                            .foregroundStyle(.secondary)
                    }

                    Spacer()
                    StatusBadge(
                        title: report.continuumStatusTitle,
                        systemImage: report.continuumStatusSymbol,
                        tint: report.continuumStatusTint
                    )
                }

                SurfaceCard {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("What Continuum knows")
                            .font(.headline)
                        Text(report.explanation)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                        Divider()
                        factRow("Capture", report.canCaptureNow ? "Available now" : "Unavailable")
                        factRow("Restore", report.canRestoreNow ? "Validated local restore" : "Not currently available")
                        factRow("Method", report.tier.displayName)
                        factRow("Running", isRunning ? "Yes" : "No")
                        factRow("Last checked", report.inspectedAt.formatted(date: .abbreviated, time: .shortened))
                    }
                }

                if !report.canRestoreNow {
                    SurfaceCard {
                        HStack(alignment: .top, spacing: 12) {
                            Image(systemName: report.tier == .unsupported ? "nosign" : "wrench.and.screwdriver.fill")
                                .font(.title2)
                                .foregroundStyle(report.tier == .unsupported ? Color.secondary : Color.orange)
                            VStack(alignment: .leading, spacing: 4) {
                                Text(report.tier == .unsupported ? "Restore stays disabled" : "Backend not implemented")
                                    .font(.headline)
                                Text(report.tier == .unsupported
                                     ? "Continuum may retain timeline context, but it will never label a picture as restored app state."
                                     : "This is a possible engineering route, not something setup can enable in the current build.")
                                    .font(.subheadline)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                        }
                    }
                }
            }
            .padding(24)
            .frame(maxWidth: 680, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .top)
        }
    }

    private func factRow(_ title: String, _ value: String) -> some View {
        HStack {
            Text(title).foregroundStyle(.secondary)
            Spacer()
            Text(value).fontWeight(.medium)
        }
        .font(.subheadline)
    }
}
