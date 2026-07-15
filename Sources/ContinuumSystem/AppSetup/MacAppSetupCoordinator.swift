import Darwin
import Foundation
import ContinuumCore

public actor MacAppSetupCoordinator: AppSetupCoordinating {
    private let rootProvider: any AppSetupRootProviding
    private let fileSystem: any AppSetupFileSystem
    private let probeService: any AppSetupProbing
    private let signer: any ManagedBundleSigning
    private let bootstrapLibraryURL: URL?
    private let now: @Sendable () -> Date

    public init(
        rootDirectory: URL? = nil,
        bootstrapLibraryURL: URL? = nil
    ) {
        self.rootProvider = FixedAppSetupRoot(
            rootDirectory: rootDirectory ?? Self.defaultRootDirectory()
        )
        self.fileSystem = LocalAppSetupFileSystem()
        self.probeService = MacAppSetupProbe()
        self.signer = MacManagedBundleSigner()
        self.bootstrapLibraryURL = bootstrapLibraryURL
        self.now = { Date() }
    }

    init(
        rootProvider: any AppSetupRootProviding,
        fileSystem: any AppSetupFileSystem,
        probeService: any AppSetupProbing,
        signer: any ManagedBundleSigning,
        bootstrapLibraryURL: URL? = nil,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.rootProvider = rootProvider
        self.fileSystem = fileSystem
        self.probeService = probeService
        self.signer = signer
        self.bootstrapLibraryURL = bootstrapLibraryURL
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
                if case .stale = revalidated.state {
                    try rollback(existing.id)
                }
            case .preparing:
                try recoverInterruptedSetups()
            case .stale:
                try rollback(existing.id)
            default:
                break
            }
        }

        guard !isBundleRunning(at: sourceURL) else {
            throw AppSetupError.operationFailed(
                "\(app.displayName) is running. Continuum will never replace a live app bundle; quit it normally, then run setup once."
            )
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
        let displacedOriginalURL = record.sourceURL
            .deletingLastPathComponent()
            .appendingPathComponent(".Continuum-\(record.id.uuidString)-Original.app", isDirectory: true)

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
            if let bootstrapLibraryURL {
                try embedBootstrap(
                    from: bootstrapLibraryURL,
                    in: managedURL
                )
            }
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

            try transition(&record, to: .preparing(.installingManaged))
            try fileSystem.removeItemIfPresent(at: displacedOriginalURL)
            record.displacedOriginalURL = displacedOriginalURL
            try persist(record)
            _ = try fileSystem.cloneOrCopyItem(at: managedURL, to: displacedOriginalURL)
            let stagedManaged = try probeService.inspect(
                bundleURL: displacedOriginalURL,
                declaredIdentity: nil
            )
            guard stagedManaged.fingerprint == result.managedFingerprint,
                  try markerMatches(record, at: markerURL(in: displacedOriginalURL)) else {
                throw AppSetupError.validationFailed(
                    "The launch-path staging copy did not match the validated managed app."
                )
            }
            guard !isBundleRunning(at: record.sourceURL) else {
                throw AppSetupError.operationFailed(
                    "\(record.app.displayName) launched while Continuum was preparing it. No bundle was replaced; quit it normally and try again."
                )
            }

            try fileSystem.exchangeItems(at: record.sourceURL, and: displacedOriginalURL)
            record.managedInstalledAtSource = true
            try persist(record)

            let installedResult = try validatePreparedRecord(record)
            record.managedFingerprint = installedResult.managedFingerprint
            record.validation = installedResult.validation
            guard installedResult.isPrepared else {
                throw AppSetupError.validationFailed(installedResult.validation.detail)
            }

            record.state = .prepared
            record.updatedAt = now()
            try persist(record)
            return record
        } catch {
            let originalError = error
            do {
                try restoreOriginalIfNeeded(&record)
                try transition(&record, to: .preparing(.rollingBack))
                try fileSystem.removeItemIfPresent(at: workspaceURL)
                record.originalCloneURL = nil
                record.managedBundleURL = nil
                record.displacedOriginalURL = nil
                record.managedInstalledAtSource = false
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

        let expectedInstalledFingerprint = record.managedFingerprint
        let sourceMatchesExpected = record.managedInstalledAtSource == true
            ? currentSource.fingerprint == expectedInstalledFingerprint
            : currentSource.fingerprint == record.sourceFingerprint
        guard sourceMatchesExpected else {
            record.state = .stale
            record.updatedAt = now()
            record.validation = staleValidation(
                previous: record.validation,
                detail: "The app at its launch path changed after Continuum prepared it. Continuum will not overwrite that newer app."
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
            if record.managedInstalledAtSource != true {
                record.state = .stale
                record.validation = AppSetupValidation(
                    sourceUnchanged: result.validation.sourceUnchanged,
                    originalCloneVerified: result.validation.originalCloneVerified,
                    instrumentationMarkerValid: result.validation.instrumentationMarkerValid,
                    managedSignatureValid: result.validation.managedSignatureValid,
                    managedAttachEntitlementValid: result.validation.managedAttachEntitlementValid,
                    restoreCertificationPassed: false,
                    checkedAt: now(),
                    detail: "The managed copy is valid but the normal app launch is not armed yet. Run setup while the app is quit."
                )
            }
            try persist(record)
            return record
        }

        try fileSystem.removeItemIfPresent(at: workspaceURL(for: record.id))
        record.originalCloneURL = nil
        record.managedBundleURL = nil
        record.displacedOriginalURL = nil
        record.managedInstalledAtSource = false
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
        try restoreOriginalIfNeeded(&record)
        try transition(&record, to: .preparing(.rollingBack))

        try fileSystem.removeItemIfPresent(at: workspaceURL(for: setupID))
        record.originalCloneURL = nil
        record.managedBundleURL = nil
        record.displacedOriginalURL = nil
        record.managedInstalledAtSource = false
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
            var record = journal[index]
            try restoreOriginalIfNeeded(&record)
            try fileSystem.removeItemIfPresent(at: workspaceURL(for: journal[index].id))
            record.originalCloneURL = nil
            record.managedBundleURL = nil
            record.displacedOriginalURL = nil
            record.managedInstalledAtSource = false
            record.originalCopyMethod = nil
            record.managedCopyMethod = nil
            record.managedFingerprint = nil
            record.state = .rolledBack
            record.updatedAt = now()
            journal[index] = record
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

    private func isBundleRunning(at bundleURL: URL) -> Bool {
        let estimatedCount = proc_listallpids(nil, 0)
        guard estimatedCount > 0 else { return false }
        var processIdentifiers = [Int32](
            repeating: 0,
            count: Int(estimatedCount) + 32
        )
        let byteCount = Int32(processIdentifiers.count * MemoryLayout<Int32>.stride)
        let processCount = processIdentifiers.withUnsafeMutableBytes { buffer in
            proc_listallpids(buffer.baseAddress, byteCount)
        }
        guard processCount > 0 else { return false }

        let bundlePrefix = bundleURL.resolvingSymlinksInPath().standardizedFileURL.path + "/"
        for processIdentifier in processIdentifiers.prefix(Int(processCount)) where processIdentifier > 0 {
            var pathBuffer = [CChar](repeating: 0, count: 4 * Int(PATH_MAX))
            let pathLength = proc_pidpath(
                processIdentifier,
                &pathBuffer,
                UInt32(pathBuffer.count)
            )
            guard pathLength > 0 else { continue }
            let bytes = pathBuffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
            let executablePath = URL(fileURLWithPath: String(decoding: bytes, as: UTF8.self))
                .resolvingSymlinksInPath()
                .standardizedFileURL
                .path
            if executablePath.hasPrefix(bundlePrefix) { return true }
        }
        return false
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

        let sourceUnchanged = record.managedInstalledAtSource == true
            ? currentSource.fingerprint == managed.fingerprint
            : currentSource.fingerprint == expectedSource
        let originalVerified = original.fingerprint == expectedSource
        let signatureValid = managed.isSigned && managed.isAdHocSigned && managed.signatureValid
        let attachEntitlementValid = managed.hasAttachEntitlement
        let bootstrapValid = try validateManagedBootstrap(in: managedURL)
        let installedMarkerValid: Bool
        if record.managedInstalledAtSource == true {
            installedMarkerValid = try markerMatches(
                record,
                at: markerURL(in: record.sourceURL)
            )
        } else {
            installedMarkerValid = true
        }
        let prepared = sourceUnchanged
            && originalVerified
            && markerIsValid
            && installedMarkerValid
            && signatureValid
            && attachEntitlementValid
            && bootstrapValid

        let detail: String
        if prepared {
            detail = record.managedInstalledAtSource == true
                ? "The verified vendor original is preserved, and the normal launch path now uses Continuum's signed checkpoint runtime. Functional rewind certification is still checked when a snapshot is saved."
                : "The vendor source is unchanged. Original.app is verified, and Managed.app is ad-hoc signed with get-task-allow for the generic Mach controller. Functional rewind certification is still pending."
        } else {
            var failures: [String] = []
            if !sourceUnchanged { failures.append("source changed") }
            if !originalVerified { failures.append("Original.app no longer matches the source") }
            if !markerIsValid { failures.append("managed instrumentation marker is missing or invalid") }
            if !installedMarkerValid { failures.append("the normal launch path is not armed") }
            if !signatureValid { failures.append("managed ad-hoc signature is invalid") }
            if !attachEntitlementValid { failures.append("get-task-allow is missing") }
            if !bootstrapValid { failures.append("checkpoint runtime or its launch configuration is missing") }
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

    private func restoreOriginalIfNeeded(_ record: inout AppSetupRecord) throws {
        guard let displacedOriginalURL = record.displacedOriginalURL else {
            record.managedInstalledAtSource = false
            return
        }

        let sourceIsManaged = (try? markerMatches(
            record,
            at: markerURL(in: record.sourceURL)
        )) == true
        if sourceIsManaged {
            guard !isBundleRunning(at: record.sourceURL) else {
                throw AppSetupError.operationFailed(
                    "\(record.app.displayName) is running. Continuum will not restore its vendor bundle until that process exits normally."
                )
            }
            guard fileSystem.itemExists(at: displacedOriginalURL) else {
                throw AppSetupError.operationFailed(
                    "The armed app is missing its preserved vendor bundle at \(displacedOriginalURL.path)."
                )
            }
            try transition(&record, to: .preparing(.restoringOriginal))
            try fileSystem.exchangeItems(at: record.sourceURL, and: displacedOriginalURL)
            let restored = try probeService.inspect(
                bundleURL: record.sourceURL,
                declaredIdentity: record.app
            )
            guard restored.fingerprint == record.sourceFingerprint else {
                try? fileSystem.exchangeItems(at: record.sourceURL, and: displacedOriginalURL)
                throw AppSetupError.validationFailed(
                    "The preserved vendor app did not match its verified setup fingerprint."
                )
            }
        }

        try fileSystem.removeItemIfPresent(at: displacedOriginalURL)
        record.displacedOriginalURL = nil
        record.managedInstalledAtSource = false
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
        let entitlements = [
            "com.apple.security.get-task-allow": true,
            "com.apple.security.cs.allow-dyld-environment-variables": true,
            "com.apple.security.cs.disable-library-validation": true
        ]
        let data = try PropertyListSerialization.data(
            fromPropertyList: entitlements,
            format: .xml,
            options: 0
        )
        try fileSystem.writeDataAtomically(data, to: url)
    }

    private func embedBootstrap(
        from sourceURL: URL,
        in managedBundleURL: URL
    ) throws {
        guard fileSystem.itemExists(at: sourceURL) else {
            throw AppSetupError.validationFailed(
                "Continuum's packaged checkpoint runtime is missing. Reinstall Continuum and try again."
            )
        }
        let embeddedURL = bootstrapURL(in: managedBundleURL)
        try fileSystem.createDirectory(at: embeddedURL.deletingLastPathComponent())
        _ = try fileSystem.cloneOrCopyItem(at: sourceURL, to: embeddedURL)

        let infoURL = managedBundleURL
            .appendingPathComponent("Contents", isDirectory: true)
            .appendingPathComponent("Info.plist", isDirectory: false)
        let plistData = try fileSystem.readData(at: infoURL)
        guard var plist = try PropertyListSerialization.propertyList(
            from: plistData,
            options: [],
            format: nil
        ) as? [String: Any] else {
            throw AppSetupError.validationFailed(
                "The managed app's Info.plist could not be updated."
            )
        }
        var environment = plist["LSEnvironment"] as? [String: String] ?? [:]
        environment["CONTINUUM_ENABLE_CHECKPOINT_SAFEPOINTS"] = "1"
        environment["CONTINUUM_DETERMINISTIC_ADDRESS_SPACE"] = "1"
        environment["DYLD_SHARED_REGION"] = "private"
        environment["MallocLargeCache"] = "0"
        var insertedLibraries = environment["DYLD_INSERT_LIBRARIES"]?
            .split(separator: ":")
            .map(String.init) ?? []
        insertedLibraries.removeAll { $0 == Self.embeddedBootstrapToken }
        insertedLibraries.append(Self.embeddedBootstrapToken)
        environment["DYLD_INSERT_LIBRARIES"] = insertedLibraries.joined(separator: ":")
        plist["LSEnvironment"] = environment
        let updatedData = try PropertyListSerialization.data(
            fromPropertyList: plist,
            format: .binary,
            options: 0
        )
        try fileSystem.writeDataAtomically(updatedData, to: infoURL)
    }

    private func validateManagedBootstrap(in managedBundleURL: URL) throws -> Bool {
        guard let bootstrapLibraryURL else { return true }
        let embeddedURL = bootstrapURL(in: managedBundleURL)
        guard fileSystem.itemExists(at: bootstrapLibraryURL),
              fileSystem.itemExists(at: embeddedURL),
              try fileSystem.readData(at: bootstrapLibraryURL)
                == fileSystem.readData(at: embeddedURL) else {
            return false
        }

        let infoURL = managedBundleURL
            .appendingPathComponent("Contents", isDirectory: true)
            .appendingPathComponent("Info.plist", isDirectory: false)
        guard let plist = try PropertyListSerialization.propertyList(
            from: fileSystem.readData(at: infoURL),
            options: [],
            format: nil
        ) as? [String: Any],
              let environment = plist["LSEnvironment"] as? [String: String],
              environment["CONTINUUM_ENABLE_CHECKPOINT_SAFEPOINTS"] == "1",
              environment["CONTINUUM_DETERMINISTIC_ADDRESS_SPACE"] == "1",
              environment["DYLD_SHARED_REGION"] == "private",
              environment["MallocLargeCache"] == "0" else {
            return false
        }
        let insertedLibraries = environment["DYLD_INSERT_LIBRARIES"]?
            .split(separator: ":")
            .map(String.init) ?? []
        return insertedLibraries.filter {
            $0 == Self.embeddedBootstrapToken
        }.count == 1
    }

    private func bootstrapURL(in managedBundleURL: URL) -> URL {
        managedBundleURL
            .appendingPathComponent("Contents", isDirectory: true)
            .appendingPathComponent("Frameworks", isDirectory: true)
            .appendingPathComponent("libContinuumBootstrap.dylib", isDirectory: false)
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

    private static let embeddedBootstrapToken =
        "@executable_path/../Frameworks/libContinuumBootstrap.dylib"
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
