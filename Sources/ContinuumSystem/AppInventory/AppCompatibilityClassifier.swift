import Foundation
import ContinuumCore

struct PluginOpportunity: Sendable, Equatable {
    let directoryURL: URL
    let reason: String
}

struct PluginOpportunityDetector: Sendable {
    private static let candidateDirectoryNames: Set<String> = [
        "addons", "extensions", "gamedata", "mods", "plugins"
    ]

    func opportunity(for bundleURL: URL) -> PluginOpportunity? {
        let bundleURL = bundleURL.standardizedFileURL
        let roots = [
            bundleURL.deletingLastPathComponent(),
            bundleURL.appendingPathComponent("Contents", isDirectory: true),
            bundleURL
                .appendingPathComponent("Contents", isDirectory: true)
                .appendingPathComponent("Resources", isDirectory: true)
        ]

        for root in roots {
            guard let children = try? FileManager.default.contentsOfDirectory(
                at: root,
                includingPropertiesForKeys: [.isDirectoryKey],
                options: [.skipsHiddenFiles]
            ) else {
                continue
            }

            for child in children {
                guard
                    Self.candidateDirectoryNames.contains(child.lastPathComponent.lowercased()),
                    (try? child.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true
                else {
                    continue
                }

                return PluginOpportunity(
                    directoryURL: child,
                    reason: "A bundle-adjacent \(child.lastPathComponent) directory may provide an app-supported plug-in route."
                )
            }
        }

        return nil
    }
}

struct AppCompatibilityClassifier: Sendable {
    private let inspector: AppBundleInspector
    private let pluginDetector: PluginOpportunityDetector

    init(
        inspector: AppBundleInspector = AppBundleInspector(),
        pluginDetector: PluginOpportunityDetector = PluginOpportunityDetector()
    ) {
        self.inspector = inspector
        self.pluginDetector = pluginDetector
    }

    func report(for app: AppIdentity, inspectedAt: Date = .now) -> CompatibilityReport {
        guard
            let bundleURL = app.bundleURL,
            bundleURL.pathExtension.lowercased() == "app",
            FileManager.default.isExecutableFile(atPath: app.executableURL.path)
        else {
            return CompatibilityReport(
                app: app,
                tier: .unsupported,
                canCaptureNow: false,
                canRestoreNow: false,
                explanation: "Continuum could not verify a runnable macOS app bundle. Nothing will be modified.",
                inspectedAt: inspectedAt
            )
        }

        let signature = inspector.signatureMetadata(for: bundleURL)
        if app.isApplePlatformBinary || signature.isApplePlatformBinary || signature.isSandboxed {
            let protection = app.isApplePlatformBinary || signature.isApplePlatformBinary
                ? "macOS protects this platform app from general process instrumentation"
                : "this app is sandboxed and may lose identity-bound access if re-signed"
            return CompatibilityReport(
                app: app,
                tier: .protectedBridge,
                canCaptureNow: false,
                canRestoreNow: false,
                explanation: "A protected bridge is required because \(protection). Restore stays disabled until that bridge passes app-specific validation.",
                inspectedAt: inspectedAt
            )
        }

        if let opportunity = pluginDetector.opportunity(for: bundleURL) {
            return CompatibilityReport(
                app: app,
                tier: .directPlugin,
                canCaptureNow: false,
                canRestoreNow: false,
                explanation: "\(opportunity.reason) Continuum must probe and certify it before capture is enabled.",
                inspectedAt: inspectedAt
            )
        }

        if !signature.isSigned
            || signature.isAdHocSigned
            || signature.disablesLibraryValidation
            || (!signature.usesHardenedRuntime && !signature.enforcesLibraryValidation) {
            return CompatibilityReport(
                app: app,
                tier: .launchInjection,
                canCaptureNow: false,
                canRestoreNow: false,
                explanation: "The signature may allow launch-time runtime loading. Continuum still requires a reversible probe and restore certification before enabling rewind.",
                inspectedAt: inspectedAt
            )
        }

        return CompatibilityReport(
            app: app,
            tier: .managedInstrumentation,
            canCaptureNow: false,
            canRestoreNow: false,
            explanation: "The app requires backup-first managed instrumentation. Continuum will not alter it until signature, permissions, launch, and rollback checks all pass.",
            inspectedAt: inspectedAt
        )
    }
}
