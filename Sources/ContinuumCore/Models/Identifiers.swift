import Foundation

public typealias CaptureSessionID = UUID
public typealias CheckpointID = UUID
public typealias SnapshotID = UUID
public typealias BranchID = UUID
public typealias ProvisionalRewindID = UUID

public enum ContinuumConstants {
    public static let schemaVersion = 1
    public static let defaultDiskBudgetBytes: Int64 = 20 * 1_024 * 1_024 * 1_024
    public static let defaultHotMemoryBudgetBytes: Int64 = 2 * 1_024 * 1_024 * 1_024
    public static let defaultHotHistorySeconds: TimeInterval = 90
    public static let defaultRollingHistorySeconds: TimeInterval = 30 * 60
}
