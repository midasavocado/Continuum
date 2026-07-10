import Foundation
import ContinuumCore

public actor MacAppSetupCoordinator: AppSetupCoordinating {
    private let rootProvider: any AppSetupRootProviding
    private let fileSystem: any AppSetupFileSystem
    private let probeService: any AppSetupProbing
    private let signer: any ManagedBundleSigning
    private let now: @Sendable () -> Date

    public init(rootDirectory: URL? = nil) {
        self.rootProvider = FixedAppSetupRoot(
            rootDirectory: rootDirectory ?? Self.defaultRootDirectory()
        )
        self.fileSystem = LocalAppSetupFileSystem()
        self.probeService = MacAppSetupProbe()
        self.signer = MacManagedBundleSigner()
        self.now = { Date() }
    }

    init(
        rootProvider: any AppSetupRootProviding,
        fileSystem: any AppSetupFileSystem,
        probeService: any AppSetupProbing,
        signer: any ManagedBundleSigning,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.rootProvider = rootProvider
        self.fileSystem = fileSystem
        self.probeService = probeService
        self.signer = signer
        self.now = now
    }

    public func records() throws -> [AppSetupRecord] {
        try loadJournal().sorted {
            if $0.updatedAt != $1.updatedAt { return $0.updatedAt > $1.updatedAt }
            return $0.id.uuidString < $1.id.uuidString
        }
    }

    public func probe(_ app: AppIdentity) throws -> AppSetupRecord {
        let sourceURL = normalizedSourceURL(for: app)
        if let existing = try existingRecord(for: sourceURL) {
            switch existing.state {
            case .prepared, .stale:
                return try revalidate(existing.id)
            case .preparing:
                try recoverInterruptedSetups()
            default:
                break
            }
        }
        return try createProbeRecord(
            for: app,
            reusingExistingRecord: true,
            eligibleState: .discovered
        )
    }

    public func setup(_ app: AppIdentity) throws -> AppSetupRecord {
        let sourceURL = normalizedSourceURL(for: app)
        if let existing = try existingRecord(for: sourceURL) {
            switch existing.state {
            case .prepared:
                let revalidated = try revalidate(existing.id)
                if case .prepared = revalidated.state {
                    return revalidated
                }
            case .preparing:
                try recoverInterruptedSetups()
            default:
                break
            }
        }

        var record = try createProbeRecord(
            for: app,
            reusingExistingRecord: true,
            eligibleState: .preparing(.probing)
        )
        if case .blocked = record.state {
            return record
        }

        let workspaceURL = workspaceURL(for: record.id)
        let originalURL = workspaceURL.appendingPathComponent("Original.app", isDirectory: true)
        let managedURL = workspaceURL.appendingPathComponent("Managed.app", isDirectory: true)
        let entitlementsURL = workspaceURL.appendingPathComponent("ManagedAttach.entitlements", isDirectory: false)

        do {
            try transition(&record, to: .preparing(.creatingWorkspace))
            try fileSystem.removeItemIfPresent(at: workspaceURL)
            try fileSystem.createDirectory(at: workspaceURL)

            try transition(&record, to: .preparing(.cloningOriginal))
            record.originalCloneURL = originalURL
            try persist(record)
            record.originalCopyMethod = try fileSystem.cloneOrCopyItem(at: record.sourceURL, to: originalURL)

            let initialFingerprint = try requireSourceFingerprint(record)
            let sourceAfterOriginal = try probeService.inspect(
                bundleURL: record.sourceURL,
                declaredIdentity: record.app
            )
            let originalProbe = try probeService.inspect(bundleURL: originalURL, declaredIdentity: nil)
            guard sourceAfterOriginal.fingerprint == initialFingerprint,
                  originalProbe.fingerprint == initialFingerprint else {
                throw AppSetupError.validationFailed("The source changed while its verified original copy was being created.")
            }

            try transition(&record, to: .preparing(.cloningManaged))
            record.managedBundleURL = managedURL
            try persist(record)
            record.managedCopyMethod = try fileSystem.cloneOrCopyItem(at: originalURL, to: managedURL)
            let managedBeforeInstrumentation = try probeService.inspect(bundleURL: managedURL, declaredIdentity: nil)
            guard managedBeforeInstrumentation.fingerprint == initialFingerprint else {
                throw AppSetupError.validationFailed("The managed copy did not match the verified original before instrumentation.")
            }

            try transition(&record, to: .preparing(.instrumenting))
            try writeMarker(for: record, to: markerURL(in: managedURL))

            try transition(&record, to: .preparing(.signing))
            try writeAttachEntitlements(to: entitlementsURL)
            try signer.sign(bundleURL: managedURL, entitlementsURL: entitlementsURL)

            try transition(&record, to: .preparing(.validating))
            let result = try validatePreparedRecord(record)
            record.managedFingerprint = result.managedFingerprint
            record.validation = result.validation
            guard result.isPrepared else {
                throw AppSetupError.validationFailed(result.validation.detail)
            }

            record.state = .prepared
            record.updatedAt = now()
            try persist(record)
            return record
        } catch {
            let originalError = error
            do {
                record.state = .preparing(.rollingBack)
                record.updatedAt = now()
                try persist(record)
                try fileSystem.removeItemIfPresent(at: workspaceURL)
                record.originalCloneURL = nil
                record.managedBundleURL = nil
                record.originalCopyMethod = nil
                record.managedCopyMethod = nil
                record.managedFingerprint = nil
                record.state = .failed(originalError.localizedDescription)
                record.updatedAt = now()
                try persist(record)
            } catch {
                throw AppSetupError.operationFailed(
                    "\(originalError.localizedDescription) Automatic rollback also failed: \(error.localizedDescription)"
                )
            }
            throw originalError
        }
    }

    public func revalidate(_ setupID: AppSetupID) throws -> AppSetupRecord {
        var record = try record(withID: setupID)
        let currentSource: AppSetupProbeResult
        do {
            currentSource = try probeService.inspect(
                bundleURL: record.sourceURL,
                declaredIdentity: record.app
            )
        } catch {
            record.state = .stale
            record.updatedAt = now()
            record.validation = staleValidation(
                previous: record.validation,
                detail: "The source bundle can no longer be validated: \(error.localizedDescription)"
            )
            try persist(record)
            return record
        }

        guard currentSource.fingerprint == record.sourceFingerprint else {
            record.state = .stale
            record.updatedAt = now()
            record.validation = staleValidation(
                previous: record.validation,
                detail: "The source app changed after this managed copy was prepared. Set it up again for the new version."
            )
            try persist(record)
            return record
        }

        guard case .prepared = record.state else {
            return record
        }

        let result = try validatePreparedRecord(record)
        record.managedFingerprint = result.managedFingerprint
        record.validation = result.validation
        record.updatedAt = now()
        if result.isPrepared {
            try persist(record)
            return record
        }

        try fileSystem.removeItemIfPresent(at: workspaceURL(for: record.id))
        record.originalCloneURL = nil
        record.managedBundleURL = nil
        record.originalCopyMethod = nil
        record.managedCopyMethod = nil
        record.managedFingerprint = nil
        record.state = .failed(result.validation.detail)
        record.updatedAt = now()
        try persist(record)
        return record
    }

    public func rollback(_ setupID: AppSetupID) throws {
        var record = try record(withID: setupID)
        record.state = .preparing(.rollingBack)
        record.updatedAt = now()
        try persist(record)

        try fileSystem.removeItemIfPresent(at: workspaceURL(for: setupID))
        record.originalCloneURL = nil
        record.managedBundleURL = nil
        record.originalCopyMethod = nil
        record.managedCopyMethod = nil
        record.managedFingerprint = nil
        record.state = .rolledBack
        record.updatedAt = now()
        try persist(record)
    }

    public func recoverInterruptedSetups() throws {
        var journal = try loadJournal()
        for index in journal.indices {
            guard case .preparing = journal[index].state else { continue }
            try fileSystem.removeItemIfPresent(at: workspaceURL(for: journal[index].id))
            journal[index].originalCloneURL = nil
            journal[index].managedBundleURL = nil
            journal[index].originalCopyMethod = nil
            journal[index].managedCopyMethod = nil
            journal[index].managedFingerprint = nil
            journal[index].state = .rolledBack
            journal[index].updatedAt = now()
            try saveJournal(journal)
        }
    }

    private func createProbeRecord(
        for app: AppIdentity,
        reusingExistingRecord: Bool,
        eligibleState: AppSetupState
    ) throws -> AppSetupRecord {
        let sourceURL = normalizedSourceURL(for: app)
        let existing = reusingExistingRecord ? try existingRecord(for: sourceURL) : nil
        let timestamp = now()
        var record: AppSetupRecord
        do {
            let result = try probeService.inspect(bundleURL: sourceURL, declaredIdentity: app)
            record = AppSetupRecord(
                id: existing?.id ?? UUID(),
                app: result.identity,
                sourceURL: sourceURL,
                sourceFingerprint: result.fingerprint,
                state: result.blockers.isEmpty ? eligibleState : .blocked(result.blockers),
                createdAt: existing?.createdAt ?? timestamp,
                updatedAt: timestamp
            )
        } catch AppSetupError.invalidBundle(let detail) {
            record = AppSetupRecord(
                id: existing?.id ?? UUID(),
                app: app,
                sourceURL: sourceURL,
                sourceFingerprint: nil,
                state: .blocked([.invalidBundle(detail)]),
                createdAt: existing?.createdAt ?? timestamp,
                updatedAt: timestamp
            )
        }
        try persist(record)
        return record
    }

    private func normalizedSourceURL(for app: AppIdentity) -> URL {
        (app.bundleURL ?? app.executableURL)
            .resolvingSymlinksInPath()
            .standardizedFileURL
    }

    private func existingRecord(for sourceURL: URL) throws -> AppSetupRecord? {
        try loadJournal()
            .filter { $0.sourceURL.standardizedFileURL == sourceURL.standardizedFileURL }
            .max {
                if $0.updatedAt != $1.updatedAt { return $0.updatedAt < $1.updatedAt }
                return $0.id.uuidString < $1.id.uuidString
            }
    }

    private func validatePreparedRecord(_ record: AppSetupRecord) throws -> PreparedValidationResult {
        guard let originalURL = record.originalCloneURL,
              let managedURL = record.managedBundleURL,
              let expectedSource = record.sourceFingerprint else {
            throw AppSetupError.validationFailed("The setup journal is missing its verified copy paths or source fingerprint.")
        }

        let currentSource = try probeService.inspect(bundleURL: record.sourceURL, declaredIdentity: record.app)
        let original = try probeService.inspect(bundleURL: originalURL, declaredIdentity: nil)
        let managed = try probeService.inspect(bundleURL: managedURL, declaredIdentity: nil)
        let markerIsValid = try markerMatches(record, at: markerURL(in: managedURL))

        let sourceUnchanged = currentSource.fingerprint == expectedSource
        let originalVerified = original.fingerprint == expectedSource
        let signatureValid = managed.isSigned && managed.isAdHocSigned && managed.signatureValid
        let attachEntitlementValid = managed.hasAttachEntitlement
        let prepared = sourceUnchanged
            && originalVerified
            && markerIsValid
            && signatureValid
            && attachEntitlementValid

        let detail: String
        if prepared {
            detail = "The vendor source is unchanged. Original.app is verified, and Managed.app is ad-hoc signed with get-task-allow for the generic Mach controller. Functional rewind certification is still pending."
        } else {
            var failures: [String] = []
            if !sourceUnchanged { failures.append("source changed") }
            if !originalVerified { failures.append("Original.app no longer matches the source") }
            if !markerIsValid { failures.append("managed instrumentation marker is missing or invalid") }
            if !signatureValid { failures.append("managed ad-hoc signature is invalid") }
            if !attachEntitlementValid { failures.append("get-task-allow is missing") }
            detail = failures.joined(separator: "; ")
        }

        return PreparedValidationResult(
            validation: AppSetupValidation(
                sourceUnchanged: sourceUnchanged,
                originalCloneVerified: originalVerified,
                instrumentationMarkerValid: markerIsValid,
                managedSignatureValid: signatureValid,
                managedAttachEntitlementValid: attachEntitlementValid,
                restoreCertificationPassed: false,
                checkedAt: now(),
                detail: detail
            ),
            managedFingerprint: managed.fingerprint,
            isPrepared: prepared
        )
    }

    private func staleValidation(previous: AppSetupValidation?, detail: String) -> AppSetupValidation {
        AppSetupValidation(
            sourceUnchanged: false,
            originalCloneVerified: previous?.originalCloneVerified ?? false,
            instrumentationMarkerValid: previous?.instrumentationMarkerValid ?? false,
            managedSignatureValid: previous?.managedSignatureValid ?? false,
            managedAttachEntitlementValid: previous?.managedAttachEntitlementValid ?? false,
            restoreCertificationPassed: false,
            checkedAt: now(),
            detail: detail
        )
    }

    private func transition(_ record: inout AppSetupRecord, to state: AppSetupState) throws {
        record.state = state
        record.updatedAt = now()
        try persist(record)
    }

    private func requireSourceFingerprint(_ record: AppSetupRecord) throws -> AppFingerprint {
        guard let fingerprint = record.sourceFingerprint else {
            throw AppSetupError.validationFailed("The setup journal has no source fingerprint.")
        }
        return fingerprint
    }

    private func writeMarker(for record: AppSetupRecord, to url: URL) throws {
        let marker = ManagedSetupMarker(
            schemaVersion: 1,
            setupID: record.id,
            route: record.route,
            sourceBundleContentSHA256: try requireSourceFingerprint(record).bundleContentSHA256,
            createdAt: now()
        )
        try fileSystem.writeDataAtomically(try Self.encoder.encode(marker), to: url)
    }

    private func markerMatches(_ record: AppSetupRecord, at url: URL) throws -> Bool {
        guard fileSystem.itemExists(at: url),
              let marker = try? Self.decoder.decode(
                ManagedSetupMarker.self,
                from: fileSystem.readData(at: url)
              ),
              let fingerprint = record.sourceFingerprint else {
            return false
        }
        return marker.schemaVersion == 1
            && marker.setupID == record.id
            && marker.route == record.route
            && marker.sourceBundleContentSHA256 == fingerprint.bundleContentSHA256
    }

    private func writeAttachEntitlements(to url: URL) throws {
        let entitlements = ["com.apple.security.get-task-allow": true]
        let data = try PropertyListSerialization.data(
            fromPropertyList: entitlements,
            format: .xml,
            options: 0
        )
        try fileSystem.writeDataAtomically(data, to: url)
    }

    private func markerURL(in managedBundleURL: URL) -> URL {
        managedBundleURL
            .appendingPathComponent("Contents", isDirectory: true)
            .appendingPathComponent("Resources", isDirectory: true)
            .appendingPathComponent("Continuum", isDirectory: true)
            .appendingPathComponent("ManagedSetup.json", isDirectory: false)
    }

    private func workspaceURL(for id: AppSetupID) -> URL {
        rootProvider.rootDirectory
            .appendingPathComponent("Workspaces", isDirectory: true)
            .appendingPathComponent(id.uuidString, isDirectory: true)
    }

    private var journalURL: URL {
        rootProvider.rootDirectory.appendingPathComponent("SetupJournal.json", isDirectory: false)
    }

    private func record(withID id: AppSetupID) throws -> AppSetupRecord {
        guard let record = try loadJournal().first(where: { $0.id == id }) else {
            throw AppSetupError.recordNotFound(id)
        }
        return record
    }

    private func persist(_ record: AppSetupRecord) throws {
        var journal = try loadJournal()
        if let index = journal.firstIndex(where: { $0.id == record.id }) {
            journal[index] = record
        } else {
            journal.append(record)
        }
        try saveJournal(journal)
    }

    private func loadJournal() throws -> [AppSetupRecord] {
        guard fileSystem.itemExists(at: journalURL) else { return [] }
        do {
            return try Self.decoder.decode([AppSetupRecord].self, from: fileSystem.readData(at: journalURL))
        } catch {
            throw AppSetupError.operationFailed("The durable setup journal could not be decoded: \(error.localizedDescription)")
        }
    }

    private func saveJournal(_ records: [AppSetupRecord]) throws {
        do {
            try fileSystem.writeDataAtomically(try Self.encoder.encode(records), to: journalURL)
        } catch let error as AppSetupError {
            throw error
        } catch {
            throw AppSetupError.operationFailed("The durable setup journal could not be saved: \(error.localizedDescription)")
        }
    }

    private static func defaultRootDirectory() -> URL {
        let applicationSupport = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support")
        return applicationSupport
            .appendingPathComponent("Continuum", isDirectory: true)
            .appendingPathComponent("AppSetups", isDirectory: true)
    }

    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }()

    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()
}

private struct ManagedSetupMarker: Codable {
    let schemaVersion: Int
    let setupID: AppSetupID
    let route: AppSetupRoute
    let sourceBundleContentSHA256: String
    let createdAt: Date
}

private struct PreparedValidationResult {
    let validation: AppSetupValidation
    let managedFingerprint: AppFingerprint
    let isPrepared: Bool
}
