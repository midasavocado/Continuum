import AppKit
import Darwin
import Foundation

private let stateMagic: UInt64 = 0x434F4E5447554953
private nonisolated(unsafe) var mutationRequested: sig_atomic_t = 0

private func requestMutation(_ signalNumber: Int32) {
    _ = signalNumber
    mutationRequested = 1
}

private struct GUIState {
    var magic: UInt64
    var counter: UInt64
}

@MainActor
private final class AppDelegate: NSObject, NSApplicationDelegate {
    private let state: UnsafeMutablePointer<GUIState>
    private var window: NSWindow?
    private var label: NSTextField?
    private var timer: Timer?

    override init() {
        typealias AllocateState = @convention(c) (Int) -> UnsafeMutableRawPointer?
        let processHandle = dlopen(nil, RTLD_NOW)
        let symbol = processHandle.flatMap {
            dlsym($0, "continuum_bootstrap_allocate_app_state")
        }
        let allocate = symbol.map {
            unsafeBitCast($0, to: AllocateState.self)
        }
        guard let allocation = allocate?(MemoryLayout<GUIState>.stride) else {
            fatalError("could not allocate GUI proof state")
        }
        state = allocation.bindMemory(to: GUIState.self, capacity: 1)
        state.initialize(to: GUIState(magic: stateMagic, counter: 111))
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 520, height: 260),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.center()
        window.title = title

        let label = NSTextField(labelWithString: "")
        label.font = .monospacedSystemFont(ofSize: 30, weight: .semibold)
        label.alignment = .center
        label.frame = NSRect(x: 20, y: 90, width: 480, height: 60)
        window.contentView?.addSubview(label)

        self.window = window
        self.label = label
        refreshDerivedUI()
        window.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)

        timer = Timer.scheduledTimer(
            timeInterval: 0.1,
            target: self,
            selector: #selector(timerFired),
            userInfo: nil,
            repeats: true
        )
        writeObservation(event: "ready")
    }

    func applicationWillTerminate(_ notification: Notification) {
        timer?.invalidate()
    }

    private var title: String {
        "Continuum GUI Proof — \(state.pointee.counter)"
    }

    @objc private func timerFired() {
        if mutationRequested != 0 {
            mutationRequested = 0
            state.pointee.counter += 111
            writeObservation(event: "mutated")
        }
        refreshDerivedUI()
    }

    private func refreshDerivedUI() {
        guard state.pointee.magic == stateMagic else {
            writeObservation(event: "invalid-memory")
            return
        }
        window?.title = title
        label?.stringValue = "Saved RAM: \(state.pointee.counter)"
    }

    private func writeObservation(event: String) {
        guard let path = ProcessInfo.processInfo.environment[
            "CONTINUUM_GUI_PROOF_OBSERVATION_PATH"
        ] else { return }
        let address = UInt(bitPattern: state)
        let line = "\(event) \(getpid()) \(address) \(state.pointee.counter)\n"
        guard let bytes = line.data(using: .utf8) else { return }
        if !FileManager.default.fileExists(atPath: path) {
            FileManager.default.createFile(atPath: path, contents: nil)
        }
        guard let handle = try? FileHandle(forWritingTo: URL(fileURLWithPath: path)) else {
            return
        }
        defer { try? handle.close() }
        _ = try? handle.seekToEnd()
        try? handle.write(contentsOf: bytes)
    }
}

let application = NSApplication.shared
private let delegate = AppDelegate()
signal(SIGWINCH, requestMutation)
application.delegate = delegate
application.setActivationPolicy(.regular)
application.run()
