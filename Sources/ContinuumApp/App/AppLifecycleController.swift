import ContinuumSystem
import Foundation

@MainActor
final class AppLifecycleController {
    private let preferences: ContinuumPreferences
    private let rewindOverlay: RewindOverlayController
    private var hotKeys: GlobalHotKeyService?
    private var shortcutObserver: NSObjectProtocol?
    private weak var model: ContinuumModel?

    init(preferences: ContinuumPreferences) {
        self.preferences = preferences
        self.rewindOverlay = RewindOverlayController(preferences: preferences)
    }

    func start(model: ContinuumModel) {
        self.model = model
        guard hotKeys == nil else { return }

        let service = GlobalHotKeyService(
            rewindShortcut: preferences.rewindShortcut,
            onSaveSnapshot: {
                Task { await model.saveManualSnapshot() }
            },
            onRewind: { [weak self, weak model] in
                guard let self, let model else { return }
                self.rewindOverlay.present(model: model)
            }
        )

        do {
            try service.start()
            hotKeys = service
            observeShortcutChanges()
        } catch {
            model.presentedError = error.localizedDescription
        }
    }

    func showRewindOverlay(model: ContinuumModel) {
        rewindOverlay.present(model: model)
    }

    private func observeShortcutChanges() {
        guard shortcutObserver == nil else { return }
        let previousPresetKey =
            ContinuumPreferences.previousRewindShortcutPresetUserInfoKey
        shortcutObserver = NotificationCenter.default.addObserver(
            forName: ContinuumPreferences.rewindShortcutDidChangeNotification,
            object: preferences,
            queue: .main
        ) { [weak self] notification in
            let previousRawValue = notification.userInfo?[previousPresetKey] as? String
            MainActor.assumeIsolated {
                self?.applyRewindShortcutChange(previousRawValue: previousRawValue)
            }
        }
    }

    private func applyRewindShortcutChange(previousRawValue: String?) {
        guard let hotKeys else { return }

        do {
            try hotKeys.updateRewindShortcut(preferences.rewindShortcut)
        } catch {
            if let previousRawValue,
               let previousPreset = RewindShortcutPreset(rawValue: previousRawValue) {
                preferences.rewindShortcutPreset = previousPreset
            }
            model?.presentedError = error.localizedDescription
        }
    }
}
