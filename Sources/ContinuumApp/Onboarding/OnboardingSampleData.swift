import ContinuumCore
import Foundation

enum OnboardingSampleData {
    static let permissions = PermissionKind.allCases.map { kind in
        PermissionStatus(
            kind: kind,
            state: kind == .screenRecording ? .notRequested : .granted,
            detail: kind == .screenRecording ? "Timeline thumbnails are currently off." : "Ready"
        )
    }

    static let compatibleApp = AppIdentity(
        bundleIdentifier: "com.example.ContinuumDemo",
        displayName: "Continuum Demo",
        bundleURL: URL(fileURLWithPath: "/Applications/Continuum Demo.app"),
        executableURL: URL(fileURLWithPath: "/Applications/Continuum Demo.app/Contents/MacOS/Continuum Demo"),
        version: "1.0",
        signingIdentifier: "com.example.ContinuumDemo",
        teamIdentifier: nil,
        isApplePlatformBinary: false
    )

    static let reports = [
        CompatibilityReport(
            app: compatibleApp,
            tier: .directPlugin,
            canCaptureNow: true,
            canRestoreNow: true,
            explanation: "Restore validation passed."
        )
    ]
}
