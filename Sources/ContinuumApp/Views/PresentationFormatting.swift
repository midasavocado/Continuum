import SwiftUI
import ContinuumCore

extension SnapshotKind {
    var continuumSymbol: String {
        switch self {
        case .manual: "bookmark.fill"
        case .beforeRewind: "arrow.uturn.backward.circle.fill"
        case .crashRecovery: "cross.case.fill"
        case .automatic: "clock.fill"
        }
    }

    var continuumTint: Color {
        switch self {
        case .manual: .blue
        case .beforeRewind: .indigo
        case .crashRecovery: .orange
        case .automatic: .secondary
        }
    }
}

extension RestoreAvailability {
    var continuumSymbol: String {
        switch self {
        case .instant: "bolt.fill"
        case .experimentalHot: "checkmark.circle.fill"
        case .replayRequired: "play.circle.fill"
        case .unavailable: "nosign"
        }
    }

    var continuumTint: Color {
        switch self {
        case .instant: .green
        case .experimentalHot: .green
        case .replayRequired: .orange
        case .unavailable: .secondary
        }
    }
}

extension ResourceDomain {
    var displayName: String {
        switch self {
        case .memory: "Memory"
        case .threads: "Threads"
        case .localFiles: "Local files"
        case .descriptors: "Files and descriptors"
        case .sockets: "Network sockets"
        case .machIPC: "App connections"
        case .windowServer: "Windows"
        case .graphicsGPU: "Graphics and GPU"
        case .audioDevices: "Audio and devices"
        case .clocksRandomInput: "Time and input"
        }
    }
}

extension ResourceRestoreMode {
    var displayName: String {
        switch self {
        case .restored: "Restored"
        case .reconnected: "Reconnected"
        case .rebuilt: "Rebuilt"
        case .guarded: "Must stay unchanged"
        case .unavailable: "Not restored"
        }
    }

    var continuumTint: Color {
        switch self {
        case .restored, .reconnected, .rebuilt: .green
        case .guarded: .orange
        case .unavailable: .secondary
        }
    }
}

extension CompatibilityReport {
    var continuumStatusTitle: String {
        if canRestoreNow { return "Ready to rewind" }
        if canCaptureNow { return "Capture only" }
        if tier == .unsupported { return "Not rewindable" }
        return "Research candidate"
    }

    var continuumStatusSymbol: String {
        if canRestoreNow { return "checkmark.circle.fill" }
        if canCaptureNow { return "record.circle" }
        if tier == .unsupported { return "nosign" }
        return "hammer.fill"
    }

    var continuumStatusTint: Color {
        if canRestoreNow { return .green }
        if canCaptureNow { return .orange }
        if tier == .unsupported { return .secondary }
        return .yellow
    }
}

extension PermissionKind {
    var continuumTitle: String {
        switch self {
        case .accessibility: "Accessibility"
        case .screenRecording: "Screen Recording"
        case .automation: "Automation"
        case .fullDiskAccess: "Full Disk Access"
        }
    }

    var continuumSymbol: String {
        switch self {
        case .accessibility: "figure.arms.open"
        case .screenRecording: "rectangle.dashed.badge.record"
        case .automation: "gearshape.2"
        case .fullDiskAccess: "internaldrive"
        }
    }
}

extension PermissionState {
    var continuumTitle: String {
        switch self {
        case .granted: "Granted"
        case .denied: "Not granted"
        case .notRequested: "Not requested"
        case .requiresSystemSettings: "Check Settings"
        case .unknown: "As needed"
        }
    }

    var continuumTint: Color {
        switch self {
        case .granted: .green
        case .denied: .orange
        case .notRequested, .requiresSystemSettings: .blue
        case .unknown: .secondary
        }
    }
}

func continuumByteCount(_ bytes: Int64) -> String {
    ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
}
