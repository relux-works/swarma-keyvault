// Finite internal journal orchestration. Compile with the custody helper's
// existing review implementation and native storage source when linking the
// accepted Go archive. There is no public dispatcher or new C symbol here.
import CryptoKit
import Darwin
import Foundation
import LocalAuthentication

// Existing recovery-envelope representation, frozen by qualified local custody.
// No parser/dispatch accepts these fields from a public Namecoin endpoint. The
// expected binding is the existing recovery metadata/purpose binding, not a
// caller-selected substitute for the independently pinned account authority.
struct NativeJournalSealedAccount {
    private let blob: Data
    private let point: Data
    private let ciphertext: Data
    private let expectedBinding: Data

    init(enclaveBlob: Data, wrappingPoint: Data, ciphertext: Data, expectedBinding: Data) throws {
        guard (1...16384).contains(enclaveBlob.count), wrappingPoint.count == 65,
              ciphertext.count == 181, expectedBinding.count == 32 else { throw NativeJournalRefusal.mismatch }
        do {
            _ = try P256.KeyAgreement.PublicKey(x963Representation: wrappingPoint)
            _ = try P256.KeyAgreement.PublicKey(x963Representation: ciphertext.prefix(65))
        } catch { throw NativeJournalRefusal.mismatch }
        blob = nativeJournalOwnedPublicData(enclaveBlob)
        point = nativeJournalOwnedPublicData(wrappingPoint)
        self.ciphertext = nativeJournalOwnedPublicData(ciphertext)
        self.expectedBinding = nativeJournalOwnedPublicData(expectedBinding)
    }

    // Only finite initialize/reconcile below can use this primitive. It never
    // returns account bytes, serializes a private-key object or spawns a child.
    // CryptoKit private/shared/symmetric objects have lexical scope and no public
    // explicit zeroing API; owned raw buffers are cleared with memset_s. This is
    // not a guarantee that OS/library copies universally disappear from memory.
    fileprivate func withAccount(using context: LAContext,
                                 consume: (UnsafeRawBufferPointer) throws -> Void) throws {
        let wrappingKey: SecureEnclave.P256.KeyAgreement.PrivateKey
        do { wrappingKey = try recoveryLoad(blob, context) }
        catch { throw NativeJournalRefusal.authenticationRefused }
        guard wrappingKey.publicKey.x963Representation == point else { throw NativeJournalRefusal.mismatch }
        let ephemeral: P256.KeyAgreement.PublicKey
        do { ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: ciphertext.prefix(65)) }
        catch { throw NativeJournalRefusal.mismatch }
        let shared: SharedSecret
        do { shared = try wrappingKey.sharedSecretFromKeyAgreement(with: ephemeral) }
        catch { throw NativeJournalRefusal.authenticationRefused }
        let derived = shared.x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: ciphertext.prefix(65), outputByteCount: 32)
        // This owned material is a symmetric intermediate, not serialization of
        // a CryptoKit private-key object. No value becomes String or diagnostics.
        var material = derived.withUnsafeBytes { Data($0) }
        try material.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) in
            defer { if let base = raw.baseAddress, memset_s(base, raw.count, 0, raw.count) != 0 { fatalError("native clear failed") } }
            guard raw.count == 32 else { throw NativeJournalRefusal.operational }
            let aes = SymmetricKey(data: materialPrefix(raw, 0..<16))
            let nonce: AES.GCM.Nonce
            let box: AES.GCM.SealedBox
            var plain: Data
            do {
                nonce = try AES.GCM.Nonce(data: materialPrefix(raw, 16..<32))
                box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext.dropFirst(65).dropLast(16), tag: ciphertext.suffix(16))
                plain = try AES.GCM.open(box, using: aes)
            } catch { throw NativeJournalRefusal.mismatch }
            try plain.withUnsafeMutableBytes { (bytes: UnsafeMutableRawBufferPointer) in
                defer { if let base = bytes.baseAddress, memset_s(base, bytes.count, 0, bytes.count) != 0 { fatalError("native clear failed") } }
                guard bytes.count == 100, let base = bytes.baseAddress,
                      bytes[0] == 75, bytes[1] == 86, bytes[2] == 78, bytes[3] == 49 else { throw NativeJournalRefusal.mismatch }
                let matches = expectedBinding.withUnsafeBytes { expected in
                    timingsafe_bcmp(base.advanced(by: 4), expected.baseAddress!, 32) == 0
                }
                guard matches else { throw NativeJournalRefusal.mismatch }
                try consume(UnsafeRawBufferPointer(start: base.advanced(by: 36), count: 64))
            }
        }
    }
}

// The installed Foundation SDK makes UnsafeRawBufferPointer both
// ContiguousBytes and DataProtocol. Borrow its slices without copying secrets.
private func materialPrefix(_ raw: UnsafeMutableRawBufferPointer, _ range: Range<Int>) -> UnsafeRawBufferPointer {
    UnsafeRawBufferPointer(rebasing: raw[range])
}

extension NativeJournalOperationPlan {
    func snapshot() throws -> NamecoinReviewSnapshot {
        let action: NamecoinReviewOperation = kind == .initialize ? .journalInitialize : .reconcile
        let effects = kind == .initialize
            ? "Separate first-sitting initialization. Create only the selected new journal anchor and linked sidecar. Preserve the existing pair. No ECDSA."
            : "Authenticate existing journal/result only. No new attempt, initialization, reset, signature or paired-item mutation."
        let facts = try [
            NamecoinReviewFact(label: "Journal operation", bytes: Data(kind.rawValue.utf8)),
            NamecoinReviewFact(label: "Physical existing paired group", bytes: Data(selection.group.utf8)),
            NamecoinReviewFact(label: "Existing Nostr identity (preserved)", bytes: Data(selection.nostrAccount.utf8)),
            NamecoinReviewFact(label: "Existing Namecoin identity (preserved)", bytes: Data(selection.account.utf8)),
            NamecoinReviewFact(label: "Account public pin SHA256", bytes: selection.publicPin),
            NamecoinReviewFact(label: "Policy revision", bytes: Data(selection.policy.utf8)),
            NamecoinReviewFact(label: "Qualified helper code pin", bytes: selection.helperCDHash),
            NamecoinReviewFact(label: "New journal service", bytes: Data(NativeJournalSelection.service.utf8)),
            NamecoinReviewFact(label: "Exact journal account locator", bytes: Data(selection.locator.utf8)),
            NamecoinReviewFact(label: "Complete public linked sidecar", bytes: selection.sidecar),
            NamecoinReviewFact(label: "Exact native public metadata", bytes: selection.metadata),
            NamecoinReviewFact(label: "Reviewed adoption plan digest", bytes: adoptionPlanDigest),
            NamecoinReviewFact(label: "Finite effects and forbidden operations", bytes: Data(effects.utf8))
        ]
        return try NamecoinReviewSnapshot(operation: action, account: selection.account,
                                          feeAtoms: 0, frozenReviewFrame: reviewFrame, facts: facts)
    }
}

// Actual create/readback, not a prepare-success token. The synchronous linked
// engine action receives only this freshly unsealed borrowed account, must
// derive/verify selected account pins and construct genuine genesis, with no
// ECDSA operation in this path.
// It is intentionally not bound to guessed C exports before the generated header.
// Only the explicit first post-review adoption sitting may invoke this function;
// prepare/sign/reconcile never routes missing state into it. Return means only
// this native anchor phase completed, not full durable initialization/adoption;
// the engine must finish its filesystem/readback/receipt lifecycle under the gate.
@MainActor
func initializeNamecoinJournal(_ plan: NativeJournalOperationPlan,
                              storage: NativeNamecoinJournalStorage,
                              sealedAccount: NativeJournalSealedAccount,
                              constructGenesis: (UnsafeRawBufferPointer) throws -> NativeSecretBytes) async throws {
    guard plan.kind == .initialize, plan.selection.metadata == storage.selection.metadata else { throw NativeJournalRefusal.mismatch }
    try storage.requireAbsentForExplicitInitialization()
    let snapshot = try plan.snapshot()
    try await withNamecoinReviewedBiometrics(snapshot) { context in
        // This creates a new biometric context for this operation, never one
        // reused from adoption authorization or a later spend's owner consent.
        try sealedAccount.withAccount(using: context) { account in
            let genesis = try constructGenesis(account)
            defer { genesis.clear() }
            try storage.createInitializedAnchor(genesis)
        }
    }
}

// No write, new attempt, signature or automatic initialization is available to
// this orchestration path. The engine consumer authenticates the existing anchor
// against freshly unsealed retained authority and exact existing result state.
// It may not return anchor/key/account bytes, and cannot return a success boolean
// that substitutes for the real review/context/storage path.
@MainActor
func reconcileNamecoinJournal(_ plan: NativeJournalOperationPlan,
                             storage: NativeNamecoinJournalStorage,
                             sealedAccount: NativeJournalSealedAccount,
                             authenticateExisting: (UnsafeRawBufferPointer, UnsafeRawBufferPointer) throws -> Void) async throws {
    guard plan.kind == .reconcile, plan.selection.metadata == storage.selection.metadata else { throw NativeJournalRefusal.mismatch }
    // Freeze once before review; a missing anchor refuses. Readback after
    // confirmation is only a mismatch check, never a new authority snapshot.
    let frozen = try storage.freezeExistingAnchorForReconciliation()
    defer { frozen.clear() }
    let snapshot = try plan.snapshot()
    try await withNamecoinReviewedBiometrics(snapshot) { context in
        try storage.verifyFrozenAnchorUnchanged(frozen)
        try sealedAccount.withAccount(using: context) { account in
            try frozen.withBytes { anchor in try authenticateExisting(account, anchor) }
        }
    }
}

// Finite in-process archive operation only. No outer dispatcher, raw digest,
// generic unwrap callback or missing-state initialization is exposed here.
// The actual generated archive owns its kernel gate before native storage reads.
@MainActor
func performNamecoinArchiveOperation(_ operation: NativeNamecoinArchiveOperation,
                                    sealedAccount: NativeJournalSealedAccount) async throws -> Data {
    let bridge = try NativeNamecoinArchiveBridge.open(operation)
    do {
        try await withNamecoinReviewedBiometrics(bridge.snapshot) { context in
            try bridge.verifyFrozenAfterReview()
            try sealedAccount.withAccount(using: context) { account in
                try bridge.runBorrowing(account)
            }
        }
        // withAccount has cleared its owned account/intermediate source before
        // ACK copy and before C-close can release the gate. Secret journal copies
        // clear in finish/refusal before that same single close attempt.
        return try bridge.finishAndClose()
    } catch { throw bridge.refuseAndClose(error) }
}

// Explicit initialization only. The bridge opens the actual Go gate before
// native storage/review; ordinary sign/reconcile never reaches this entry.
// Crucially, both success and catch are OUTSIDE the complete withAccount call:
// all owned account/AES/intermediate buffers clear before the sole C Close.
@MainActor
func initializeNamecoinJournalUsingArchive(_ selection: NativeNamecoinInitializationSelection,
                                          sealedAccount: NativeJournalSealedAccount) async throws -> NativeNamecoinInitializationCompletion {
    let bridge = try NativeNamecoinInitializationArchiveBridge.open(selection)
    defer { withExtendedLifetime(bridge) {} }
    do {
        try await withNamecoinReviewedBiometrics(bridge.snapshot) { context in
            try bridge.verifyAfterReview()
            try bridge.checkPublicAbsenceBeforeBorrow()
            try sealedAccount.withAccount(using: context) { account in
                try bridge.completeBorrowing(account)
            }
        }
        return try bridge.finishAndClose()
    } catch { throw bridge.refuseAndClose(error) }
}
