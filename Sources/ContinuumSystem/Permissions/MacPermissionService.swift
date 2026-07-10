import AppKit
@preconcurrency import ApplicationServices
import Foundation
import ContinuumCore

struct PermissionEnvironment: Sendable {
    let accessibilityPreflight: @Sendable () -> Bool
    let accessibilityRequest: @Sendable () -> Bool
    let screenRecordingPreflight: @Sendable () -> Bool
    let screenRecordingRequest: @Sendable () -> Bool
    let openURL: @MainActor @Sendable (URL) -> Void

    static let live = PermissionEnvironment(
        accessibilityPreflight: {
            AXIsProcessTrusted()
        },
        accessibilityRequest: {
            let promptKey = kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String
            return AXIsProcessTrustedWithOptions([promptKey: true] as CFDictionary)
        },
        screenRecordingPreflight: {
            CGPreflightScreenCaptureAccess()
        },
        screenRecordingRequest: {
            CGRequestScreenCaptureAccess()
        },
        openURL: { url in
            NSWorkspace.shared.open(url)
        }
    )
}

public struct MacPermissionService: PermissionProviding, Sendable {
    private let environment: PermissionEnvironment

    public init() {
        self.environment = .live
    }

    init(environment: PermissionEnvironment) {
        self.environment = environment
    }

    public func statuses() async -> [PermissionStatus] {
        PermissionKind.allCases.map(status(for:))
    }

    public func request(_ permission: PermissionKind) async -> PermissionStatus {
        switch permission {
        case .accessibility:
            let environment = environment
            let granted = await MainActor.run {
                environment.accessibilityRequest()
            }
            return accessibilityStatus(granted: granted)
        case .screenRecording:
            let environment = environment
            let granted = await MainActor.run {
                environment.screenRecordingRequest()
            }
            return screenRecordingStatus(granted: granted)
        case .automation:
            return PermissionStatus(
                kind: .automation,
                state: .unknown,
                detail: "macOS grants Automation per target app. Status becomes known when Continuum first exercises a specific integration."
            )
        case .fullDiskAccess:
            await openSystemSettings(for: .fullDiskAccess)
            return fullDiskAccessStatus
        }
    }

    public func openSystemSettings(for permission: PermissionKind) async {
        guard let url = Self.systemSettingsURL(for: permission) else { return }
        await environment.openURL(url)
    }

    public static func systemSettingsURL(for permission: PermissionKind) -> URL? {
        let anchor: String
        switch permission {
        case .accessibility:
            anchor = "Privacy_Accessibility"
        case .screenRecording:
            anchor = "Privacy_ScreenCapture"
        case .automation:
            anchor = "Privacy_Automation"
        case .fullDiskAccess:
            anchor = "Privacy_AllFiles"
        }
        return URL(string: "x-apple.systempreferences:com.apple.preference.security?\(anchor)")
    }

    private func status(for permission: PermissionKind) -> PermissionStatus {
        switch permission {
        case .accessibility:
            accessibilityStatus(granted: environment.accessibilityPreflight())
        case .screenRecording:
            screenRecordingStatus(granted: environment.screenRecordingPreflight())
        case .automation:
            PermissionStatus(
                kind: .automation,
                state: .unknown,
                detail: "Automation permission is target-specific and remains unknown until an integration is exercised."
            )
        case .fullDiskAccess:
            fullDiskAccessStatus
        }
    }

    private func accessibilityStatus(granted: Bool) -> PermissionStatus {
        PermissionStatus(
            kind: .accessibility,
            state: granted ? .granted : .denied,
            detail: granted
                ? "Continuum can identify and coordinate app windows."
                : "Accessibility is not granted. macOS does not distinguish a first request from a previous denial."
        )
    }

    private func screenRecordingStatus(granted: Bool) -> PermissionStatus {
        PermissionStatus(
            kind: .screenRecording,
            state: granted ? .granted : .denied,
            detail: granted
                ? "Continuum can render timeline previews."
                : "Screen Recording is not granted. It is used for previews, never as a substitute for restorable state."
        )
    }

    private var fullDiskAccessStatus: PermissionStatus {
        PermissionStatus(
            kind: .fullDiskAccess,
            state: .requiresSystemSettings,
            detail: "macOS provides no reliable preflight API for Full Disk Access. Confirm it in Privacy & Security settings."
        )
    }
}
