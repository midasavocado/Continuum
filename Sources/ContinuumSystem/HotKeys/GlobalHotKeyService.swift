import Carbon
import Foundation

public struct ShortcutModifiers: OptionSet, Hashable, Sendable {
    public let rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    public static let command = ShortcutModifiers(rawValue: 1 << 0)
    public static let option = ShortcutModifiers(rawValue: 1 << 1)
    public static let control = ShortcutModifiers(rawValue: 1 << 2)
    public static let shift = ShortcutModifiers(rawValue: 1 << 3)
}

public struct GlobalShortcut: Hashable, Sendable {
    public let keyCode: UInt32
    public let modifiers: ShortcutModifiers

    public init(keyCode: UInt32, modifiers: ShortcutModifiers) {
        self.keyCode = keyCode
        self.modifiers = modifiers
    }

    public static let saveSnapshot = GlobalShortcut(
        keyCode: UInt32(kVK_ANSI_S),
        modifiers: [.command, .option, .control]
    )

    public static let rewind = GlobalShortcut(
        keyCode: UInt32(kVK_ANSI_R),
        modifiers: [.command, .option, .control]
    )
}

public enum RewindShortcutPreset: String, CaseIterable, Codable, Identifiable, Sendable {
    case controlOptionCommandR
    case controlShiftCommandR
    case controlOptionCommandLeftArrow
    case controlOptionCommandSpace

    public var id: String { rawValue }

    public var shortcut: GlobalShortcut {
        switch self {
        case .controlOptionCommandR:
            .rewind
        case .controlShiftCommandR:
            GlobalShortcut(
                keyCode: UInt32(kVK_ANSI_R),
                modifiers: [.command, .shift, .control]
            )
        case .controlOptionCommandLeftArrow:
            GlobalShortcut(
                keyCode: UInt32(kVK_LeftArrow),
                modifiers: [.command, .option, .control]
            )
        case .controlOptionCommandSpace:
            GlobalShortcut(
                keyCode: UInt32(kVK_Space),
                modifiers: [.command, .option, .control]
            )
        }
    }

    public var displayName: String {
        switch self {
        case .controlOptionCommandR:
            "⌃⌥⌘R"
        case .controlShiftCommandR:
            "⌃⇧⌘R"
        case .controlOptionCommandLeftArrow:
            "⌃⌥⌘←"
        case .controlOptionCommandSpace:
            "⌃⌥⌘Space"
        }
    }
}

public enum GlobalHotKeyError: Error, LocalizedError, Sendable {
    case installHandler(OSStatus)
    case registerShortcut(String, OSStatus)

    public var errorDescription: String? {
        switch self {
        case let .installHandler(status):
            "Could not install the global shortcut handler (OSStatus \(status))."
        case let .registerShortcut(name, status):
            "Could not register the \(name) shortcut (OSStatus \(status)). It may already be used by another app."
        }
    }
}

@MainActor
public final class GlobalHotKeyService {
    public typealias Callback = @MainActor @Sendable () -> Void

    public private(set) var isRunning = false
    public private(set) var rewindShortcut: GlobalShortcut

    private let onSaveSnapshot: Callback
    private let onRewind: Callback
    private var eventHandler: EventHandlerRef?
    private var registeredHotKeys: [UInt32: EventHotKeyRef] = [:]

    public init(
        rewindShortcut: GlobalShortcut = .rewind,
        onSaveSnapshot: @escaping Callback,
        onRewind: @escaping Callback
    ) {
        self.rewindShortcut = rewindShortcut
        self.onSaveSnapshot = onSaveSnapshot
        self.onRewind = onRewind
    }

    isolated deinit {
        for hotKey in registeredHotKeys.values {
            UnregisterEventHotKey(hotKey)
        }
        if let eventHandler {
            RemoveEventHandler(eventHandler)
        }
    }

    public func start() throws {
        guard !isRunning else { return }

        var eventType = EventTypeSpec(
            eventClass: OSType(kEventClassKeyboard),
            eventKind: UInt32(kEventHotKeyPressed)
        )
        let handlerStatus = InstallEventHandler(
            GetApplicationEventTarget(),
            continuumGlobalHotKeyHandler,
            1,
            &eventType,
            Unmanaged.passUnretained(self).toOpaque(),
            &eventHandler
        )
        guard handlerStatus == noErr else {
            throw GlobalHotKeyError.installHandler(handlerStatus)
        }

        do {
            try register(.saveSnapshot, id: 1, name: "Save Snapshot")
            try register(rewindShortcut, id: 2, name: "Rewind")
            isRunning = true
        } catch {
            unregisterAll()
            throw error
        }
    }

    public func stop() {
        unregisterAll()
    }

    /// Replaces the global rewind shortcut without restarting the service.
    /// If registration fails, Continuum restores the previous shortcut before
    /// returning the error.
    public func updateRewindShortcut(_ shortcut: GlobalShortcut) throws {
        guard shortcut != rewindShortcut else { return }

        guard isRunning else {
            rewindShortcut = shortcut
            return
        }

        let previousShortcut = rewindShortcut
        unregister(id: 2)

        do {
            try register(shortcut, id: 2, name: "Rewind")
            rewindShortcut = shortcut
        } catch {
            // Best-effort rollback keeps the working shortcut available if the
            // requested combination belongs to another app.
            try? register(previousShortcut, id: 2, name: "Rewind")
            throw error
        }
    }

    public static func carbonModifierMask(for modifiers: ShortcutModifiers) -> UInt32 {
        var result: UInt32 = 0
        if modifiers.contains(.command) { result |= UInt32(cmdKey) }
        if modifiers.contains(.option) { result |= UInt32(optionKey) }
        if modifiers.contains(.control) { result |= UInt32(controlKey) }
        if modifiers.contains(.shift) { result |= UInt32(shiftKey) }
        return result
    }

    fileprivate func handleHotKey(identifier: UInt32) {
        switch identifier {
        case 1:
            onSaveSnapshot()
        case 2:
            onRewind()
        default:
            break
        }
    }

    private func register(
        _ shortcut: GlobalShortcut,
        id: UInt32,
        name: String
    ) throws {
        var reference: EventHotKeyRef?
        let hotKeyID = EventHotKeyID(signature: Self.signature, id: id)
        let status = RegisterEventHotKey(
            shortcut.keyCode,
            Self.carbonModifierMask(for: shortcut.modifiers),
            hotKeyID,
            GetApplicationEventTarget(),
            0,
            &reference
        )
        guard status == noErr, let reference else {
            throw GlobalHotKeyError.registerShortcut(name, status)
        }
        registeredHotKeys[id] = reference
    }

    private func unregister(id: UInt32) {
        guard let hotKey = registeredHotKeys.removeValue(forKey: id) else { return }
        UnregisterEventHotKey(hotKey)
    }

    private func unregisterAll() {
        for hotKey in registeredHotKeys.values {
            UnregisterEventHotKey(hotKey)
        }
        registeredHotKeys.removeAll()

        if let eventHandler {
            RemoveEventHandler(eventHandler)
            self.eventHandler = nil
        }
        isRunning = false
    }

    private static let signature: OSType = 0x434E_544D // "CNTM"
}

private func continuumGlobalHotKeyHandler(
    _ nextHandler: EventHandlerCallRef?,
    _ event: EventRef?,
    _ userData: UnsafeMutableRawPointer?
) -> OSStatus {
    guard let event, let userData else { return OSStatus(eventNotHandledErr) }

    var hotKeyID = EventHotKeyID()
    let status = GetEventParameter(
        event,
        EventParamName(kEventParamDirectObject),
        EventParamType(typeEventHotKeyID),
        nil,
        MemoryLayout<EventHotKeyID>.size,
        nil,
        &hotKeyID
    )
    guard status == noErr else { return status }

    let service = Unmanaged<GlobalHotKeyService>.fromOpaque(userData).takeUnretainedValue()
    Task { @MainActor in
        service.handleHotKey(identifier: hotKeyID.id)
    }
    return noErr
}
