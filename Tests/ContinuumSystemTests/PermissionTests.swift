import Foundation
import Testing
@testable import ContinuumSystem
import ContinuumCore

@Suite("macOS permission reporting")
struct PermissionTests {
    @Test("Reports every permission without prompting")
    func reportsStatusShape() async {
        let environment = PermissionEnvironment(
            accessibilityPreflight: { true },
            accessibilityRequest: { Issue.record("Request closure must not run during preflight"); return false },
            screenRecordingPreflight: { false },
            screenRecordingRequest: { Issue.record("Request closure must not run during preflight"); return false },
            openURL: { _ in Issue.record("Settings must not open during preflight") }
        )
        let service = MacPermissionService(environment: environment)

        let statuses = await service.statuses()
        let byKind = Dictionary(uniqueKeysWithValues: statuses.map { ($0.kind, $0) })

        #expect(statuses.count == PermissionKind.allCases.count)
        #expect(byKind[.accessibility]?.state == .granted)
        #expect(byKind[.screenRecording]?.state == .denied)
        #expect(byKind[.automation]?.state == .unknown)
        #expect(byKind[.fullDiskAccess]?.state == .requiresSystemSettings)
    }

    @Test("Uses the privacy-pane deep links")
    func privacyDeepLinks() {
        #expect(MacPermissionService.systemSettingsURL(for: .accessibility)?.absoluteString.hasSuffix("Privacy_Accessibility") == true)
        #expect(MacPermissionService.systemSettingsURL(for: .screenRecording)?.absoluteString.hasSuffix("Privacy_ScreenCapture") == true)
        #expect(MacPermissionService.systemSettingsURL(for: .automation)?.absoluteString.hasSuffix("Privacy_Automation") == true)
        #expect(MacPermissionService.systemSettingsURL(for: .fullDiskAccess)?.absoluteString.hasSuffix("Privacy_AllFiles") == true)
    }

    @Test("Invokes the native request hooks for interactive permissions")
    func requestsInteractivePermissions() async {
        let environment = PermissionEnvironment(
            accessibilityPreflight: { false },
            accessibilityRequest: { true },
            screenRecordingPreflight: { false },
            screenRecordingRequest: { true },
            openURL: { _ in Issue.record("Interactive requests must not open Settings directly") }
        )
        let service = MacPermissionService(environment: environment)

        let accessibility = await service.request(.accessibility)
        let screenRecording = await service.request(.screenRecording)

        #expect(accessibility.state == .granted)
        #expect(screenRecording.state == .granted)
    }
}
