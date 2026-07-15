import AppKit
import ContinuumGUIStateSupport
import Darwin
import Foundation

private let stateMagic: UInt64 = 0x434F4E5447554953
private let lateStateMagic: UInt64 = 0x434F4E544C415445
private nonisolated(unsafe) var mutationRequested: sig_atomic_t = 0

private func requestMutation(_ signalNumber: Int32) {
    _ = signalNumber
    mutationRequested = 1
}

@MainActor
private final class AppDelegate: NSObject, NSApplicationDelegate {
    private let state: UnsafeMutablePointer<continuum_gui_state>
    private var lateState: UnsafeMutablePointer<continuum_gui_state>?
    private var lateStateObserver: CFRunLoopObserver?
    private var window: NSWindow?
    private var label: NSTextField?
    private var timer: Timer?

    override init() {
        guard let allocation = continuum_gui_state_create(stateMagic, 111) else {
            fatalError("could not allocate GUI proof state")
        }
        state = allocation
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
        lateStateObserver = CFRunLoopObserverCreateWithHandler(
            kCFAllocatorDefault,
            CFRunLoopActivity.beforeWaiting.rawValue,
            false,
            CFIndex.max
        ) { [weak self] _, _ in
            MainActor.assumeIsolated {
                self?.createLateState()
            }
        }
        if let lateStateObserver {
            CFRunLoopAddObserver(
                CFRunLoopGetMain(),
                lateStateObserver,
                .commonModes
            )
        }
        writeObservation(event: "ready")
    }

    func applicationWillTerminate(_ notification: Notification) {
        timer?.invalidate()
    }

    private var title: String {
        "Continuum GUI Proof — \(state.pointee.counter) / \(lateState?.pointee.counter ?? 0)"
    }

    private func createLateState() {
        guard lateState == nil else { return }
        guard let allocation = continuum_gui_state_create(lateStateMagic, 500) else {
            fatalError("could not allocate late GUI proof state")
        }
        lateState = allocation
        writeObservation(event: "late-ready", state: allocation)
        refreshDerivedUI()
    }

    @objc private func timerFired() {
        if mutationRequested != 0 {
            mutationRequested = 0
            state.pointee.counter += 111
            writeObservation(event: "mutated")
            if let lateState {
                lateState.pointee.counter += 10
                writeObservation(event: "late-mutated", state: lateState)
            }
        }
        refreshDerivedUI()
    }

    private func refreshDerivedUI() {
        guard state.pointee.magic == stateMagic else {
            writeObservation(event: "invalid-memory")
            return
        }
        if let lateState, lateState.pointee.magic != lateStateMagic {
            writeObservation(event: "invalid-late-memory")
            return
        }
        window?.title = title
        label?.stringValue = "Saved RAM: \(state.pointee.counter) / \(lateState?.pointee.counter ?? 0)"
    }

    private func writeObservation(
        event: String,
        state observedState: UnsafeMutablePointer<continuum_gui_state>? = nil
    ) {
        guard let path = ProcessInfo.processInfo.environment[
            "CONTINUUM_GUI_PROOF_OBSERVATION_PATH"
        ] else { return }
        let observedState = observedState ?? state
        let address = UInt(bitPattern: observedState)
        let line = "\(event) \(getpid()) \(address) \(observedState.pointee.counter)\n"
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
