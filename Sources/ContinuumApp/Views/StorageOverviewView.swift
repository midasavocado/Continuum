import SwiftUI
import ContinuumCore

struct StorageOverviewView: View {
    let metrics: StorageMetrics
    let snapshots: [SnapshotRecord]

    private var deduplicatedBytes: Int64 {
        max(metrics.logicalBytes - metrics.physicalBytes, 0)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header
                usageCard
                metricGrid
                cadenceCard
                retentionCard
                permanentSnapshotsCard
            }
            .padding(24)
            .frame(maxWidth: 900, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .navigationTitle("Storage")
    }

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Encrypted prototype storage")
                    .font(.largeTitle.weight(.semibold))
                Text("Captured artifacts are compressed, encrypted, and shared by content hash.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            SettingsLink {
                Label("Storage Settings", systemImage: "gearshape")
            }
        }
    }

    private var usageCard: some View {
        SurfaceCard {
            HStack(spacing: 24) {
                Gauge(value: metrics.usageFraction) {
                    Text("Storage used")
                } currentValueLabel: {
                    Text(metrics.usageFraction, format: .percent.precision(.fractionLength(0)))
                        .font(.title2.weight(.semibold))
                }
                .gaugeStyle(.accessoryCircularCapacity)
                .tint(metrics.usageFraction > 0.9 ? .orange : .blue)
                .scaleEffect(1.25)
                .frame(width: 100, height: 100)

                VStack(alignment: .leading, spacing: 7) {
                    Text("\(continuumByteCount(metrics.physicalBytes)) of \(continuumByteCount(metrics.budgetBytes))")
                        .font(.title2.weight(.semibold))
                    Text("The selected budget is a target for the future rolling scheduler. This build records small metadata snapshots and does not enforce rolling retention yet.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    ProgressView(value: metrics.usageFraction)
                        .tint(metrics.usageFraction > 0.9 ? .orange : .blue)
                }
            }
        }
    }

    private var cadenceCard: some View {
        SurfaceCard {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Text("Planned checkpoint cadence")
                        .font(.headline)
                    Spacer()
                    StatusBadge(title: "Not active yet", systemImage: "hammer.fill", tint: .orange)
                }
                storageRow(
                    title: "Active apps",
                    value: "100 ms",
                    detail: "Ten checkpoint boundaries per second; only changed state would be stored."
                )
                Divider()
                storageRow(
                    title: "Games / high motion",
                    value: "50 ms",
                    detail: "Used only while frame-time, pause, and storage budgets remain healthy."
                )
                Divider()
                storageRow(
                    title: "Idle apps",
                    value: "1 second",
                    detail: "Backs off automatically when the app is not changing."
                )
            }
        }
    }

    private var metricGrid: some View {
        HStack(spacing: 12) {
            MetricTile(
                title: "On disk",
                value: continuumByteCount(metrics.physicalBytes),
                detail: "Compressed, encrypted state",
                systemImage: "internaldrive.fill",
                tint: .blue
            )
            MetricTile(
                title: "Space avoided",
                value: continuumByteCount(deduplicatedBytes),
                detail: "Shared unchanged data",
                systemImage: "square.stack.3d.down.right.fill",
                tint: .green
            )
            MetricTile(
                title: "Permanent",
                value: continuumByteCount(metrics.pinnedBytes),
                detail: "Manual and safety snapshots",
                systemImage: "pin.fill",
                tint: .indigo
            )
        }
    }

    private var retentionCard: some View {
        SurfaceCard {
            VStack(alignment: .leading, spacing: 14) {
                Text("Planned rolling history")
                    .font(.headline)
                storageRow(
                    title: "Hot history",
                    value: "90 seconds",
                    detail: "Up to \(continuumByteCount(ContinuumConstants.defaultHotMemoryBudgetBytes)) in memory for the fastest return."
                )
                Divider()
                storageRow(
                    title: "Warm history",
                    value: "30 minutes",
                    detail: "Oldest unpinned history is reclaimed first when the budget is reached."
                )
            }
        }
    }

    private var permanentSnapshotsCard: some View {
        SurfaceCard {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "lock.shield.fill")
                    .font(.title2)
                    .foregroundStyle(.indigo)
                VStack(alignment: .leading, spacing: 5) {
                    Text("\(snapshots.filter(\.isPinned).count) permanent snapshots")
                        .font(.headline)
                    Text("Manual metadata snapshots stay until you explicitly delete them. Before Rewind points begin only after exact restoration is certified.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
        }
    }

    private func storageRow(title: String, value: String, detail: String) -> some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title).fontWeight(.medium)
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Text(value)
                .font(.headline)
                .foregroundStyle(.secondary)
        }
    }
}
