import Carbon
import Testing
@testable import ContinuumSystem

@Suite("Global shortcuts")
struct GlobalHotKeyTests {
    @Test("Snapshot and rewind use Control-Option-Command")
    @MainActor
    func shortcutDefinitions() {
        let expected: ShortcutModifiers = [.control, .option, .command]

        #expect(GlobalShortcut.saveSnapshot.keyCode == UInt32(kVK_ANSI_S))
        #expect(GlobalShortcut.saveSnapshot.modifiers == expected)
        #expect(GlobalShortcut.rewind.keyCode == UInt32(kVK_ANSI_R))
        #expect(GlobalShortcut.rewind.modifiers == expected)
    }

    @Test("Maps shortcut modifiers to Carbon without Input Monitoring")
    @MainActor
    func modifierMapping() {
        let mask = GlobalHotKeyService.carbonModifierMask(for: [.control, .option, .command])
        let expected = UInt32(controlKey) | UInt32(optionKey) | UInt32(cmdKey)

        #expect(mask == expected)
        #expect(mask & UInt32(shiftKey) == 0)
    }

    @Test("Rewind presets are distinct and retain a safety modifier")
    func rewindPresets() {
        let shortcuts = RewindShortcutPreset.allCases.map(\.shortcut)

        #expect(Set(shortcuts).count == RewindShortcutPreset.allCases.count)
        #expect(shortcuts.allSatisfy { shortcut in
            shortcut.modifiers.contains(.control)
                && shortcut.modifiers.contains(.command)
        })
        #expect(RewindShortcutPreset.controlOptionCommandR.shortcut == .rewind)
    }

    @Test("A configured rewind shortcut can be applied before registration")
    @MainActor
    func configureBeforeStart() throws {
        let service = GlobalHotKeyService(onSaveSnapshot: {}, onRewind: {})
        let configured = RewindShortcutPreset.controlOptionCommandLeftArrow.shortcut

        try service.updateRewindShortcut(configured)

        #expect(service.rewindShortcut == configured)
        #expect(service.isRunning == false)
    }
}
