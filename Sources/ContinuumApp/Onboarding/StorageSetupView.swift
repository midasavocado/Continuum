import SwiftUI

struct StorageSetupView: View {
    @Binding var selectedGigabytes: Int
    let freeDiskSpaceBytes: Int64?
    let reserveBytes: Int64
    let error: OnboardingErrorState?
    let refresh: () -> Void

    private let choices = [10, 20, 50, 100]

    var body: some View {
        OnboardingPage(
            title: "Choose a future history budget",
            subtitle: "This preference takes effect when a certified rolling checkpoint backend is installed. Metadata snapshots are tiny today."
        ) {
            OnboardingCard {
                VStack(alignment: .leading, spacing: 16) {
                    Text("Planned maximum disk use")
                        .font(.headline)

                    Picker("Planned maximum disk use", selection: $selectedGigabytes) {
                        ForEach(choices, id: \.self) { gigabytes in
                            Text("\(gigabytes) GB").tag(gigabytes)
                        }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .accessibilityLabel("Planned maximum disk use")
                    .accessibilityHint("Sets the future maximum storage Continuum may use for rolling history")

                    HStack(alignment: .firstTextBaseline) {
                        Text("20 GB")
                            .font(.title2.bold())
                        Text("Recommended default")
                            .foregroundStyle(.secondary)
                        Spacer()
                        if let freeDiskSpaceBytes {
                            Text("\(format(bytes: freeDiskSpaceBytes)) currently free")
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }

            OnboardingCallout(
                title: "The certified scheduler will keep a reserve",
                message: "When rolling capture is enabled, it will pause before free space falls below \(format(bytes: reserveBytes)). This policy is not active until a restore backend is certified.",
                tone: budgetExceedsSafeSpace ? .warning : .information
            )

            VStack(alignment: .leading, spacing: 9) {
                storageDetail(symbol: "memorychip", title: "Hot history target", detail: "Up to 90 seconds in memory after the exact runtime is certified.")
                storageDetail(symbol: "internaldrive", title: "Rolling history target", detail: "Older automatic moments will use this disk budget and expire oldest-first.")
                storageDetail(symbol: "pin.fill", title: "Metadata snapshots now", detail: "Manual diagnostics remain until you delete them from the library.")
            }

            if let error {
                OnboardingCallout(
                    title: error.title,
                    message: error.message,
                    tone: .error,
                    retryTitle: "Check Again",
                    retry: refresh
                )
            }

            HStack {
                Spacer()
                Button("Refresh Free Space", action: refresh)
                    .accessibilityHint("Checks the Mac's available disk space again")
            }
        }
    }

    private var budgetExceedsSafeSpace: Bool {
        guard let freeDiskSpaceBytes else { return false }
        let selectedBytes = Int64(selectedGigabytes) * 1_000_000_000
        return selectedBytes + reserveBytes > freeDiskSpaceBytes
    }

    private func storageDetail(symbol: String, title: String, detail: String) -> some View {
        HStack(alignment: .top, spacing: 11) {
            Image(systemName: symbol)
                .foregroundStyle(.tint)
                .frame(width: 24)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.headline)
                Text(detail)
                    .foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
    }

    private func format(bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }
}
