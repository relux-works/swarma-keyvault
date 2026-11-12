import CryptoKit
import Darwin
import Foundation
import NamecoinArchiveABI

// PUBLIC immutable setup selected independently of any transaction request.
// Hash equality binds selected bytes; it is not adoption, code admission or
// owner consent. Actual Go Open validates the extended account and reserves
// its real gate before this adapter constructs native storage or shows review.
struct NativeNamecoinInitializationSelection {
    let selected: NativeArchiveSelection
    let pin: Data
    let profileSHA256: Data
    let plan: NativeJournalOperationPlan
    let reviewFrame: Data

    init(selectedAccountPin: Data, trustedCanonicalSelection: Data,
         trustedProfileSHA256: String, plan: NativeJournalOperationPlan) throws {
        guard plan.kind == .initialize else { throw NativeNamecoinArchiveFailure("policy_refused") }
        let profile: Data
        do { profile = try nativeArchiveUnhex(trustedProfileSHA256, count: 32) }
        catch { throw NativeNamecoinArchiveFailure("policy_refused") }
        guard !trustedCanonicalSelection.isEmpty, trustedCanonicalSelection.count <= 4 << 20 else {
            throw NativeNamecoinArchiveFailure("policy_refused")
        }
        let frozenProfile = nativeJournalOwnedPublicData(trustedCanonicalSelection)
        guard frozenProfile.count <= 4 << 20, Data(SHA256.hash(data: frozenProfile)) == profile else {
            throw NativeNamecoinArchiveFailure("policy_refused")
        }
        let selected: NativeArchiveSelection
        do { selected = try NativeArchiveSelection(canonicalJSON: frozenProfile, journal: plan.selection) }
        catch {
            let failure = NativeNamecoinArchiveFailure.map(error)
            throw NativeNamecoinArchiveFailure(failure.code == "account_mismatch" ? "account_mismatch" : "policy_refused")
        }
        guard !selectedAccountPin.isEmpty, selectedAccountPin.count <= 16384 else {
            throw NativeNamecoinArchiveFailure("account_mismatch")
        }
        let pin = nativeJournalOwnedPublicData(selectedAccountPin)
        guard !pin.isEmpty, pin.count <= 16384, Data(SHA256.hash(data: pin)) == selected.publicPin else {
            throw NativeNamecoinArchiveFailure("account_mismatch")
        }
        do {
            let object = try NativeArchiveJSON.decode(pin, maximum: 16384, canonical: true)
            let values = try object.fields(["schema", "group", "account", "account_xpub", "master_fingerprint", "account_path"])
            let texts = try values.map { try $0.text() }
            guard texts.allSatisfy({ $0.utf8.allSatisfy { (32...126).contains($0) } }),
                  texts[0] == "keyvault-namecoin-account-pin/1", texts[1] == selected.group,
                  texts[2] == selected.account, texts[5] == "m/84h/7h/0h",
                  (1...256).contains(texts[3].utf8.count),
                  texts[3].utf8.allSatisfy({ Data("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8).contains($0) }) else {
                throw NativeNamecoinArchiveFailure("account_mismatch")
            }
            _ = try nativeArchiveUnhex(texts[4], count: 4)
        } catch { throw NativeNamecoinArchiveFailure("account_mismatch") }
        // Public shape only. The actual Go account parser owns Base58Check,
        // version/depth/child/point checks and scalar+chain correspondence.
        let policy = try selected.policy.fields(["revision", "per_tx_fee_cap_atoms", "total_fee_cap_atoms", "min_fee_rate_atoms_per_kvb", "max_fee_rate_atoms_per_kvb", "dust_relay_fee_atoms_per_kvb", "created_at", "release_not_after", "final_confirmations", "release_mode"])
        guard ["two-stage", "all-four-before-release"].contains(try policy[9].text()) else {
            throw NativeNamecoinArchiveFailure("policy_refused")
        }
        self.selected = selected
        self.pin = pin
        profileSHA256 = nativeJournalOwnedPublicData(profile)
        self.plan = try NativeJournalOperationPlan(kind: .initialize, selection: plan.selection,
                                                   adoptionPlanDigest: plan.adoptionPlanDigest)
        var frame = Data("keyvault/namecoin-journal-initialization-review/1\0".utf8)
        frame.append(nativeJournalLP(self.plan.reviewFrame))
        frame.append(nativeJournalLP(selected.raw))
        frame.append(nativeJournalLP(pin))
        frame.append(profile)
        reviewFrame = frame
    }

    func verifyBinding(to journal: NativeJournalSelection) throws {
        guard journal.metadata == plan.selection.metadata, journal.sidecar == plan.selection.sidecar,
              journal.helperCDHash == plan.selection.helperCDHash,
              Data(SHA256.hash(data: selected.raw)) == profileSHA256,
              Data(SHA256.hash(data: pin)) == selected.publicPin else {
            throw NativeNamecoinArchiveFailure("adoption_required")
        }
        _ = try NativeArchiveSelection(canonicalJSON: selected.raw, journal: journal)
    }

    func snapshot() throws -> NamecoinReviewSnapshot {
        let journal = plan.selection
        var facts = try [
            NamecoinReviewFact(label: "Explicit journal operation", bytes: Data("INITIALIZE JOURNAL ONLY. Separate adoption sitting; no ECDSA, signing, reconciliation, reset, retry or paired-item change.".utf8)),
            NamecoinReviewFact(label: "Physical existing paired group", bytes: Data(journal.group.utf8)),
            NamecoinReviewFact(label: "Existing Nostr identity preserved", bytes: Data(journal.nostrAccount.utf8)),
            NamecoinReviewFact(label: "Existing Namecoin identity preserved", bytes: Data(journal.account.utf8)),
            NamecoinReviewFact(label: "Network and genesis", bytes: Data((selected.network + " / " + nativeArchiveHex(selected.genesis)).utf8)),
            NamecoinReviewFact(label: "Independent selected profile SHA256", bytes: profileSHA256),
            NamecoinReviewFact(label: "Complete selected public account pin", bytes: pin),
            NamecoinReviewFact(label: "Account pin SHA256", bytes: journal.publicPin),
            NamecoinReviewFact(label: "Qualified helper code pin", bytes: journal.helperCDHash),
            NamecoinReviewFact(label: "Reviewed adoption plan digest", bytes: plan.adoptionPlanDigest),
            NamecoinReviewFact(label: "Complete initialization plan frame", bytes: plan.reviewFrame),
            NamecoinReviewFact(label: "Exact new journal service and locator", bytes: Data((NativeJournalSelection.service + " / " + journal.locator).utf8)),
            NamecoinReviewFact(label: "Exact new anchor public metadata", bytes: journal.metadata),
            NamecoinReviewFact(label: "Complete linked existing-pair sidecar", bytes: journal.sidecar)
        ]
        // Preserve every byte; the existing independent aggregate/render/layout
        // bounds may refuse an oversized display, never truncate or hide facts.
        for offset in stride(from: 0, to: selected.raw.count, by: 262144) {
            facts.append(try NamecoinReviewFact(label: "Complete selected profile bytes " + String(offset / 262144 + 1),
                bytes: Data(selected.raw[offset..<min(offset + 262144, selected.raw.count)])))
        }
        return try NamecoinReviewSnapshot(operation: .journalInitialize, account: journal.account,
                                          feeAtoms: 0, frozenReviewFrame: reviewFrame, facts: facts)
    }
}

// Software single-use state, never a presence or erase acknowledgement. The
// typed entry's lexical withAccount boundary, not this state, orders private
// cleanup before the only C Close. No method below can release the real gate.
struct NativeInitializationLifecycle {
    enum Phase: Equatable { case opened, nativeRechecked, publicAbsent, completing, completed, refused, closed }
    private(set) var phase: Phase = .opened
    // Ordering only, never native review/presence/adoption authority. The real
    // bridge calls this after its actual code/binding/protected absence checks.
    mutating func nativeRechecked() throws {
        guard phase == .opened else { throw NativeNamecoinArchiveFailure("outcome_unknown") }
        phase = .nativeRechecked
    }
    func requireAbsenceQuery() throws {
        guard phase == .nativeRechecked || phase == .publicAbsent else {
            throw NativeNamecoinArchiveFailure("outcome_unknown")
        }
    }
    mutating func absenceReturned(_ raw: Int32) throws {
        do {
            try requireAbsenceQuery()
            if let error = NativeNamecoinArchiveFailure.abi(raw) { throw error }
            phase = .publicAbsent
        } catch {
            if phase != .closed { phase = .refused }
            throw error
        }
    }
    mutating func begin() throws {
        guard phase == .publicAbsent else {
            if phase != .closed { phase = .refused }
            throw NativeNamecoinArchiveFailure("outcome_unknown")
        }
        phase = .completing
    }
    mutating func returned(_ raw: Int32) throws {
        guard phase == .completing else { throw NativeNamecoinArchiveFailure("outcome_unknown") }
        phase = raw == 0 ? .completed : .refused
        if let error = NativeNamecoinArchiveFailure.abi(raw) { throw error }
    }
    func requireCompleted() throws {
        guard phase == .completed else { throw NativeNamecoinArchiveFailure("outcome_unknown") }
    }
    mutating func close() { phase = .closed }
}

// Public status/ownership checks do not acquire a gate or inspect any home.
enum NativeInitializationABI {
    static let maximumAnchor = 32768
    static func opened(_ raw: Int32, handle: UInt64) throws {
        guard raw == 0 || handle == 0 else { throw NativeNamecoinArchiveFailure("outcome_unknown") }
        if let error = NativeNamecoinArchiveFailure.abi(raw) { throw error }
        guard handle != 0, handle & (1 << 63) == 0 else { throw NativeNamecoinArchiveFailure("outcome_unknown") }
    }
    static func requireCallbacks(_ table: kv_nmc_init_callbacks_v1) throws {
        guard table.context != nil, table.require_absent != nil,
              table.create_initialized_anchor != nil, table.load_protected != nil else {
            throw NativeNamecoinArchiveFailure("invalid_request")
        }
    }
    static func closeResult(_ raw: Int32) -> NativeNamecoinArchiveFailure? {
        raw == 0 ? nil : NativeNamecoinArchiveFailure("outcome_unknown")
    }
    static func completeResult(_ raw: Int32, possibleCreate: Bool,
                               callbackFailed: Bool, completeReadback: Bool) -> NativeNamecoinArchiveFailure? {
        if raw == 0 { return callbackFailed || !possibleCreate || !completeReadback ? NativeNamecoinArchiveFailure("outcome_unknown") : nil }
        if possibleCreate { return NativeNamecoinArchiveFailure("outcome_unknown") }
        return NativeNamecoinArchiveFailure.abi(raw)
    }

    // Query NULL/cap0 or bounded copy only. Zero the written count before any
    // validation; short/wrong buffers receive no prefix and no secret length.
    static func loadShape(_ buffer: UnsafeMutablePointer<UInt8>?, capacity: size_t,
                          written: UnsafeMutablePointer<size_t>?) throws {
        if let written { written.pointee = 0 }
        guard written != nil, capacity <= size_t(maximumAnchor),
              (buffer == nil && capacity == 0) || (buffer != nil && capacity > 0) else {
            throw NativeNamecoinArchiveFailure("journal_unavailable")
        }
    }
    static func copyProtected(_ bytes: UnsafeRawBufferPointer, buffer: UnsafeMutablePointer<UInt8>?,
                              capacity: size_t, written: UnsafeMutablePointer<size_t>?) throws {
        try loadShape(buffer, capacity: capacity, written: written)
        guard bytes.count > 0, bytes.count <= maximumAnchor,
              let source = bytes.baseAddress, let written else {
            throw NativeNamecoinArchiveFailure("journal_unavailable")
        }
        if buffer == nil { written.pointee = size_t(bytes.count); return }
        guard capacity >= size_t(bytes.count), let buffer else {
            throw NativeNamecoinArchiveFailure("journal_unavailable")
        }
        buffer.update(from: source.assumingMemoryBound(to: UInt8.self), count: bytes.count)
        written.pointee = size_t(bytes.count)
    }
}

private final class NativeInitializationHandle {
    let value: UInt64
    private var ownership: NativeArchiveHandleOwnership
    private var failure: NativeNamecoinArchiveFailure?
    init(_ value: UInt64) throws { try NativeInitializationABI.opened(0, handle: value); self.value = value; ownership = try NativeArchiveHandleOwnership(value) }
    func close() throws {
        if let failure { throw failure }
        guard let value = ownership.takeForClose() else { return }
        // Consume ownership BEFORE the sole real call; never retry uncertainty.
        if let error = NativeInitializationABI.closeResult(kv_nmc_init_close_v1(value)) { failure = error; throw error }
    }
    deinit { try? close() }
}

// Only this real storage adapter supplies the imported C callbacks. There is no
// caller callback/provider, mock engine or private-output capability. Context is
// borrowed synchronously by Complete and never retained across the C call.
private final class NativeInitializationCallbacks {
    enum Phase: Equatable { case absentFirst, absentSecond, create, query, copy, complete, failed }
    private let storage: NativeNamecoinJournalStorage
    private var phase = Phase.absentFirst
    private var created: NativeSecretBytes?
    private var frozen: NativeFrozenJournalAnchor?
    private(set) var active = false
    private(set) var possibleCreate = false
    private(set) var failed = false
    private(set) var completeReadback = false
    init(storage: NativeNamecoinJournalStorage) { self.storage = storage }
    func begin() throws {
        guard !active, !failed, phase == .absentFirst else { throw NativeNamecoinArchiveFailure("outcome_unknown") }
        active = true
    }
    func clear() {
        active = false
        created?.clear(); created = nil
        frozen?.clear(); frozen = nil
    }
    deinit { clear() }
    private func refuse() -> Int32 { failed = true; phase = .failed; return -1 }
    func absent() -> Int32 {
        guard active, !failed, phase == .absentFirst || phase == .absentSecond else { return refuse() }
        let first = phase == .absentFirst
        if !first { possibleCreate = true } // Go already attempted public create.
        do { try storage.requireAbsentForExplicitInitialization() }
        catch { return refuse() }
        phase = first ? .absentSecond : .create
        return 0
    }
    func create(_ source: UnsafePointer<UInt8>?, count: size_t) -> Int32 {
        guard active, !failed, phase == .create, let source, count > 0,
              count <= size_t(NativeInitializationABI.maximumAnchor) else { return refuse() }
        possibleCreate = true
        do {
            let owned = try NativeSecretBytes(copying: UnsafeRawBufferPointer(start: source, count: Int(count)),
                                               maximum: NativeInitializationABI.maximumAnchor)
            defer { owned.clear() }
            try storage.createInitializedAnchor(owned)
            try owned.withBytes { created = try NativeSecretBytes(copying: $0, maximum: NativeInitializationABI.maximumAnchor) }
            phase = .query
            return 0
        } catch { return refuse() }
    }
    func load(_ buffer: UnsafeMutablePointer<UInt8>?, capacity: size_t, written: UnsafeMutablePointer<size_t>?) -> Int32 {
        if let written { written.pointee = 0 }
        guard active, !failed, let created else { return refuse() }
        do {
            try NativeInitializationABI.loadShape(buffer, capacity: capacity, written: written)
            if phase == .query {
                guard buffer == nil, capacity == 0 else { return refuse() }
                let actual = try storage.freezeExistingAnchorForReconciliation()
                var retained = false
                defer { if !retained { actual.clear() } }
                try actual.withBytes { bytes in
                    try created.withBytes { expected in
                        guard bytes.count == expected.count, let a = bytes.baseAddress, let b = expected.baseAddress,
                              timingsafe_bcmp(a, b, bytes.count) == 0 else { throw NativeJournalRefusal.unknown }
                    }
                    try NativeInitializationABI.copyProtected(bytes, buffer: buffer, capacity: capacity, written: written)
                }
                frozen = actual; retained = true; phase = .copy
                return 0
            }
            guard phase == .copy, buffer != nil, let frozen else { return refuse() }
            try storage.verifyFrozenAnchorUnchanged(frozen)
            try frozen.withBytes { bytes in
                // Actual native readback, copied only into Go's borrowed
                // allocation; the same finite byte-copy checks serve query.
                try NativeInitializationABI.copyProtected(bytes, buffer: buffer, capacity: capacity, written: written)
            }
            phase = .complete; completeReadback = true
            return 0
        } catch { return refuse() }
    }
}

// No raw account/anchor output, JSON, ACK, filesystem output or ECDSA result.
// This is only successful explicit initialization, not adoption/release evidence.
struct NativeNamecoinInitializationCompletion: Equatable {
    let operation = "initialize journal"
    let account: String
    let reviewSHA256: Data
    fileprivate init(account: String, reviewSHA256: Data) {
        self.account = account; self.reviewSHA256 = nativeJournalOwnedPublicData(reviewSHA256)
    }
}

// Single owner, synchronous Complete, no Sendable/async close/watchdog. In
// particular Complete19 never closes here: all account-source cleanup belongs
// to the typed entry's surrounding withAccount scope before finish/refusal.
final class NativeNamecoinInitializationArchiveBridge {
    let snapshot: NamecoinReviewSnapshot
    private let operation: NativeNamecoinInitializationSelection
    private let handle: NativeInitializationHandle
    private var storage: NativeNamecoinJournalStorage
    private var callbacks: NativeInitializationCallbacks?
    private var lifecycle = NativeInitializationLifecycle()
    private var failure: NativeNamecoinArchiveFailure?

    private init(operation: NativeNamecoinInitializationSelection, handle: NativeInitializationHandle,
                 storage: NativeNamecoinJournalStorage, snapshot: NamecoinReviewSnapshot) {
        self.operation = operation; self.handle = handle; self.storage = storage; self.snapshot = snapshot
    }
    static func open(_ operation: NativeNamecoinInitializationSelection) throws -> NativeNamecoinInitializationArchiveBridge {
        var pin = Array(operation.pin), config = Array(operation.selected.raw)
        var identifier: UInt64 = 0
        let code = pin.withUnsafeMutableBufferPointer { pin in
            config.withUnsafeMutableBufferPointer { config in
                kv_nmc_init_open_v1(pin.baseAddress, size_t(pin.count), config.baseAddress, size_t(config.count), &identifier)
            }
        }
        do {
            try NativeInitializationABI.opened(code, handle: identifier)
            guard Data(pin) == operation.pin, Data(config) == operation.selected.raw else { throw NativeNamecoinArchiveFailure("outcome_unknown") }
        } catch {
            // No native account borrow exists during Open. Only init Close can
            // inspect this operation's handle map; never call another domain.
            if identifier != 0 { _ = kv_nmc_init_close_v1(identifier) }
            throw NativeNamecoinArchiveFailure.map(error)
        }
        let handle = try NativeInitializationHandle(identifier)
        do {
            // Real C gate is retained BEFORE any native item/code/storage read.
            let storage = try admittedStorage(operation.plan.selection)
            try operation.verifyBinding(to: storage.selection)
            try requireAbsent(storage)
            return NativeNamecoinInitializationArchiveBridge(operation: operation, handle: handle,
                storage: storage, snapshot: try operation.snapshot())
        } catch {
            var refusal = NativeNamecoinArchiveFailure.map(error)
            do { try handle.close() } catch { refusal = NativeNamecoinArchiveFailure("outcome_unknown") }
            throw refusal
        }
    }
    deinit { callbacks?.clear(); try? handle.close() }

    private static func admittedStorage(_ selection: NativeJournalSelection) throws -> NativeNamecoinJournalStorage {
        do { return try NativeNamecoinJournalStorage(selection: selection) }
        catch NativeJournalRefusal.mismatch { throw NativeNamecoinArchiveFailure("helper_not_admitted") }
    }
    private static func requireAbsent(_ storage: NativeNamecoinJournalStorage) throws {
        do { try storage.requireAbsentForExplicitInitialization() }
        catch { throw NativeNamecoinArchiveFailure("journal_unavailable") }
    }

    func verifyAfterReview() throws {
        guard lifecycle.phase == .opened else { throw NativeNamecoinArchiveFailure("outcome_unknown") }
        try operation.verifyBinding(to: storage.selection)
        guard try operation.snapshot().digest == snapshot.digest else { throw NativeNamecoinArchiveFailure("adoption_required") }
        // Recheck actual running code, selected login Keychain, full public
        // metadata/sidecar and absence after the real fresh biometric review.
        // The adopted-pair digest is a frozen public input, not a native proof
        // of the vault's old-item ACL/adoption. Its qualified owner retains that
        // existing custody/preflight obligation; this helper never reads it.
        let fresh = try Self.admittedStorage(operation.plan.selection)
        try Self.requireAbsent(fresh)
        storage = fresh
        try lifecycle.nativeRechecked()
    }

    // Actual Go read-only public absence under the SAME retained gate. The
    // typed entry calls this immediately before withAccount, after native
    // review/fresh TouchID and the frozen code/binding/protected-state rechecks.
    // Query refusal/panic19 is latched; NEVER close here or inside a borrow.
    func checkPublicAbsenceBeforeBorrow() throws {
        do {
            if let failure { throw failure }
            try lifecycle.requireAbsenceQuery()
            try lifecycle.absenceReturned(kv_nmc_init_check_absent_v1(handle.value))
        } catch {
            let refusal = failure ?? NativeNamecoinArchiveFailure.map(error)
            failure = refusal
            throw refusal // Only the outer entry may Close after cleanup.
        }
    }

    // MUST be called only within the finite entry's existing withAccount borrow.
    // No catch/defer in this method calls Close, including C panic19/refusal.
    func completeBorrowing(_ account: UnsafeRawBufferPointer) throws {
        do {
            if let failure { throw failure }
            try lifecycle.begin()
            guard account.count == 64, let base = account.baseAddress else { throw NativeNamecoinArchiveFailure("invalid_request") }
            let context = NativeInitializationCallbacks(storage: storage)
            callbacks = context
            try context.begin()
            defer { context.clear() } // Native anchor copies clear while gate held.
            let code = try withExtendedLifetime(context) {
                var table = kv_nmc_init_callbacks_v1()
                table.context = Unmanaged.passUnretained(context).toOpaque()
                table.require_absent = { pointer in
                    guard let pointer else { return -1 }
                    return Unmanaged<NativeInitializationCallbacks>.fromOpaque(pointer).takeUnretainedValue().absent()
                }
                table.create_initialized_anchor = { pointer, bytes, count in
                    guard let pointer else { return -1 }
                    return Unmanaged<NativeInitializationCallbacks>.fromOpaque(pointer).takeUnretainedValue().create(bytes, count: count)
                }
                table.load_protected = { pointer, buffer, capacity, written in
                    if let written { written.pointee = 0 }
                    guard let pointer else { return -1 }
                    return Unmanaged<NativeInitializationCallbacks>.fromOpaque(pointer).takeUnretainedValue().load(buffer, capacity: capacity, written: written)
                }
                try NativeInitializationABI.requireCallbacks(table)
                return kv_nmc_init_complete_v1(handle.value,
                    UnsafeMutablePointer(mutating: base.assumingMemoryBound(to: UInt8.self)), size_t(account.count), &table)
            }
            if let error = NativeInitializationABI.completeResult(code, possibleCreate: context.possibleCreate,
                callbackFailed: context.failed, completeReadback: context.completeReadback) { throw error }
            try lifecycle.returned(code)
        } catch {
            let refusal = failure ?? NativeNamecoinArchiveFailure.map(error)
            failure = refusal
            throw refusal // Gate intentionally still retained, even on panic19.
        }
    }

    // Called only AFTER withAccount has fully unwound and cleared its account,
    // AES/intermediate buffers and scoped crypto objects, including on throw.
    func finishAndClose() throws -> NativeNamecoinInitializationCompletion {
        if let failure { throw failure }
        try lifecycle.requireCompleted()
        callbacks?.clear(); callbacks = nil
        lifecycle.close()
        try handle.close()
        return NativeNamecoinInitializationCompletion(account: operation.selected.account, reviewSHA256: snapshot.digest)
    }
    func refuseAndClose(_ error: Error) -> NativeNamecoinArchiveFailure {
        var refusal = failure ?? NativeNamecoinArchiveFailure.map(error)
        callbacks?.clear(); callbacks = nil
        lifecycle.close()
        do { try handle.close() } catch { refusal = NativeNamecoinArchiveFailure("outcome_unknown") }
        return refusal
    }
}
