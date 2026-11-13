import CryptoKit
import Foundation

// PUBLIC/sealed format and review building blocks only. No C call, input reader,
// key creation, store, presence operation or native-success assertion lives here.
// The actual Go engine must validate secp256k1, npub/xpub checksums and HASH160;
// structural equality here cannot authenticate parent strings or an engine.
enum RootGrantsStatus: Int32 {
    case success = 0, invalidArguments = 1, terminalRequired = 2
    case invalidWordNumber = 3, invalidWordCount = 4, invalidMnemonic = 5
    case invalidChecksum = 6, invalidDerivation = 7, retainedRecordMismatch = 8
    case publicPinMismatch = 9, operationUnavailable = 10, wrappingPolicyRefused = 11
    case invalidEnvelope = 12, bindingMismatch = 13, canceled = 14, timeout = 15
    case privateProtocolError = 16, limitExceeded = 17, unsupportedVersion = 18
    case unsupportedOperation = 19, inputCanceled = 20
    case codeNotAdmitted = 21, aclRefused = 22, lockUnavailable = 23, inventoryChanged = 24

    // Existing attach C calls remain 0..20. Grant-sign archive calls and private
    // frames use the separate 1..24 closed table below.
    static func closed(_ raw: Int32) -> Self {
        guard (0...20).contains(raw) else { return .privateProtocolError }
        return Self(rawValue: raw) ?? .privateProtocolError
    }
    static func helperClosed(_ raw: Int32) -> Self {
        guard (1...24).contains(raw) else { return .privateProtocolError }
        return Self(rawValue: raw) ?? .privateProtocolError
    }
    var code: String {
        switch self {
        case .success: return "success"
        case .invalidArguments: return "invalid_arguments"
        case .terminalRequired: return "terminal_required"
        case .invalidWordNumber: return "invalid_word_number"
        case .invalidWordCount: return "invalid_word_count"
        case .invalidMnemonic: return "invalid_mnemonic"
        case .invalidChecksum: return "invalid_checksum"
        case .invalidDerivation: return "invalid_derivation"
        case .retainedRecordMismatch: return "retained_record_mismatch"
        case .publicPinMismatch: return "public_pin_mismatch"
        case .operationUnavailable: return "operation_unavailable"
        case .wrappingPolicyRefused: return "wrapping_policy_refused"
        case .invalidEnvelope: return "invalid_envelope"
        case .bindingMismatch: return "binding_mismatch"
        case .canceled: return "canceled"
        case .timeout: return "timeout"
        case .privateProtocolError: return "private_protocol_error"
        case .limitExceeded: return "limit_exceeded"
        case .unsupportedVersion: return "unsupported_version"
        case .unsupportedOperation: return "unsupported_operation"
        case .inputCanceled: return "input_canceled"
        case .codeNotAdmitted: return "code_not_admitted"
        case .aclRefused: return "acl_refused"
        case .lockUnavailable: return "lock_unavailable"
        case .inventoryChanged: return "inventory_changed"
        }
    }
}
struct RootGrantsReviewError: Error, Equatable {
    let status: RootGrantsStatus
    var code: String { status.code }
    var message: String { "Root attachment public review refused" }
    static func fromStatus(_ raw: Int32) -> Self? {
        let status = RootGrantsStatus.closed(raw)
        return status == .success ? nil : Self(status: status)
    }
}
private func rootRequire(_ condition: Bool, _ status: RootGrantsStatus) throws {
    guard condition else { throw RootGrantsReviewError(status: status) }
}
private func rootOwned(_ data: Data) -> Data { data.withUnsafeBytes { Data($0) } }
private func rootHash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
private func rootMatch(_ value: String, _ pattern: String) -> Bool {
    value.range(of: pattern, options: .regularExpression) == (value.startIndex..<value.endIndex)
}
private func rootASCII(_ value: String) -> Bool { value.utf8.allSatisfy { (32...126).contains($0) } }
private func rootName(_ value: String) -> Bool { (1...40).contains(value.utf8.count) && rootMatch(value, "[a-z0-9-]+") }
private func rootHex(_ value: String, _ bytes: Int) -> Bool { value.utf8.count == bytes * 2 && rootMatch(value, "[a-f0-9]+") }
private func rootVersion(_ value: UInt64) -> Bool { (1...2147483647).contains(value) }
private func rootUTC(_ value: String) -> Bool {
    // Match Go's canonical UTC seconds, including Gregorian year0000. Locale,
    // leap-second normalization and DateFormatter rollover cannot alter a view.
    guard rootMatch(value, "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z") else { return false }
    let bytes = Array(value.utf8)
    func n(_ range: Range<Int>) -> Int { range.reduce(0) { $0 * 10 + Int(bytes[$1] - 48) } }
    let y = n(0..<4), m = n(5..<7), d = n(8..<10)
    guard (1...12).contains(m), n(11..<13) < 24, n(14..<16) < 60, n(17..<19) < 60 else { return false }
    let days = [31, (y % 400 == 0 || (y % 4 == 0 && y % 100 != 0)) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    return (1...days[m - 1]).contains(d)
}
private func rootJSON(_ bytes: Data, maximum: Int, status: RootGrantsStatus) throws -> NativeArchiveJSON {
    try rootRequire(!bytes.isEmpty, status)
    try rootRequire(bytes.count <= maximum, .limitExceeded)
    do { return try NativeArchiveJSON.decode(bytes, maximum: maximum, canonical: true) }
    catch let failure as RootGrantsReviewError { throw failure }
    catch { throw RootGrantsReviewError(status: status) }
}
private func rootFields(_ node: NativeArchiveJSON, _ names: [String], _ status: RootGrantsStatus) throws -> [NativeArchiveJSON] {
    do { return try node.fields(names) } catch { throw RootGrantsReviewError(status: status) }
}
private func rootCanonical(_ node: NativeArchiveJSON, _ status: RootGrantsStatus) throws -> Data {
    do { return rootOwned(try node.canonical()) } catch { throw RootGrantsReviewError(status: status) }
}
private func rootText(_ node: NativeArchiveJSON, _ status: RootGrantsStatus = .invalidArguments) throws -> String {
    do { let text = try node.text(); try rootRequire(rootASCII(text), status); return text }
    catch { throw RootGrantsReviewError(status: status) }
}
private func rootUInt(_ node: NativeArchiveJSON, _ status: RootGrantsStatus = .invalidArguments) throws -> UInt64 {
    do { return try node.uint() } catch { throw RootGrantsReviewError(status: status) }
}
private func rootBase64(_ node: NativeArchiveJSON, maximum: Int, status: RootGrantsStatus) throws -> Data {
    do { return rootOwned(try node.base64(maximum: maximum)) } catch { throw RootGrantsReviewError(status: status) }
}
private func rootP256(_ bytes: Data, fingerprint: String, status: RootGrantsStatus) throws {
    try rootRequire(bytes.count == 65 && rootHash(bytes) == fingerprint, status)
    do { _ = try P256.KeyAgreement.PublicKey(x963Representation: bytes) }
    catch { throw RootGrantsReviewError(status: status) }
}

struct RootGrantsPairPublic {
    static let keys = ["schema", "service", "version", "group_id", "metadata_sha256", "nostr_identity", "nostr_version", "nostr_public_key", "nostr_npub", "namecoin_identity", "namecoin_version", "namecoin_xpub", "namecoin_origin"]
    let schema, service, groupID, metadataHash: String
    let version: UInt64
    let nostrService, nostrPublicKey, npub, namecoinService, xpub, origin: String
    let nostrVersion, namecoinVersion: UInt64
    let canonicalBytes: Data
    var nostrAddress: String { "\(nostrService)/nostr@\(nostrVersion)" }
    var namecoinAddress: String { "\(namecoinService)/namecoin@\(namecoinVersion)" }
    fileprivate init(_ node: NativeArchiveJSON) throws {
        let s = RootGrantsStatus.retainedRecordMismatch
        let f = try rootFields(node, Self.keys, s)
        schema = try rootText(f[0], s); service = try rootText(f[1], s); version = try rootUInt(f[2], s)
        groupID = try rootText(f[3], s); metadataHash = try rootText(f[4], s)
        nostrService = try rootText(f[5], s); nostrVersion = try rootUInt(f[6], s)
        nostrPublicKey = try rootText(f[7], s); npub = try rootText(f[8], s)
        namecoinService = try rootText(f[9], s); namecoinVersion = try rootUInt(f[10], s)
        xpub = try rootText(f[11], s); origin = try rootText(f[12], s)
        try rootRequire(["keyvault-recovery/1", "keyvault-recovery/2"].contains(schema), s)
        try rootRequire([service, nostrService, namecoinService].allSatisfy(rootName) && [version, nostrVersion, namecoinVersion].allSatisfy(rootVersion), s)
        try rootRequire(nostrService == service && (schema != "keyvault-recovery/1" || namecoinService == service), s)
        try rootRequire(rootHex(groupID, 16) && rootHex(metadataHash, 32) && rootHex(nostrPublicKey, 32), s)
        try rootRequire(npub.utf8.count == 63 && rootMatch(npub, "npub1[023456789acdefghjklmnpqrstuvwxyz]+"), s)
        try rootRequire(xpub.utf8.count == 111 && rootMatch(xpub, "xpub[1-9A-HJ-NP-Za-km-z]+") && rootMatch(origin, "\\[[a-f0-9]{8}/84h/7h/0h\\]"), s)
        canonicalBytes = try rootCanonical(node, s)
    }
}

struct RootGrantsPublicRequest {
    static let profile = "namecoin-landlord-root/1"
    static let derivation = "bip85-hdseed-wif/1"
    static let path = "m/83696968h/2h/7h"
    let originalBytes, pairMetadata: Data
    let retainedWrappingPoints: [Data]
    let pair: RootGrantsPairPublic
    let service, created: String
    let version: UInt64
    let requestHash: String
    var rootAddress: String { "\(service)/root-grants@\(version)" }

    init(ownedBytes bytes: Data) throws {
        try rootRequire(bytes.count <= 262144, .limitExceeded)
        let owned = rootOwned(bytes)
        let node = try rootJSON(owned, maximum: 262144, status: .invalidArguments)
        let f = try rootFields(node, ["protocol", "engine", "profile", "mode", "pair_metadata", "pair", "service", "version", "created"], .invalidArguments)
        let protocolName = try rootText(f[0]), engine = try rootText(f[1]), profile = try rootText(f[2]), mode = try rootText(f[3])
        try rootRequire(!protocolName.isEmpty && !engine.isEmpty && !profile.isEmpty && !mode.isEmpty, .invalidArguments)
        try rootRequire(protocolName == "keyvault-root-grants-private/1" && engine == "namecoin-root-grants-engine/1" && profile == Self.profile, .unsupportedVersion)
        try rootRequire(mode == "attach", .unsupportedOperation)
        pairMetadata = try rootBase64(f[4], maximum: 32768, status: .retainedRecordMismatch)
        pair = try RootGrantsPairPublic(f[5]); service = try rootText(f[6]); version = try rootUInt(f[7]); created = try rootText(f[8])
        try rootRequire(rootName(service) && rootVersion(version) && rootUTC(created), .invalidArguments)
        retainedWrappingPoints = try Self.validateMetadata(pairMetadata, pair: pair)
        originalBytes = owned; requestHash = rootHash(owned)
    }

    private static func validateMetadata(_ raw: Data, pair: RootGrantsPairPublic) throws -> [Data] {
        let s = RootGrantsStatus.retainedRecordMismatch
        try rootRequire(rootHash(raw) == pair.metadataHash, s)
        let f = try rootFields(rootJSON(raw, maximum: 32768, status: s), ["schema", "group_id", "service", "version", "created", "nostr", "namecoin"], s)
        try rootRequire(rootText(f[0], s) == pair.schema && rootText(f[1], s) == pair.groupID && rootText(f[2], s) == pair.service && rootUInt(f[3], s) == pair.version && rootUTC(rootText(f[4], s)), s)
        let base = ["purpose", "version", "path", "algorithm", "presence", "public_key", "npub", "xpub", "origin", "wrapping_point", "wrapping_fingerprint"]
        func purpose(_ node: NativeArchiveJSON, service: String, name: String, version: UInt64, path: String, algorithm: String, presence: String, pins: [String]) throws -> Data {
            var fields = try rootFields(node, (pair.schema == "keyvault-recovery/2" ? ["service"] : []) + base, s)
            if pair.schema == "keyvault-recovery/2" { try rootRequire(rootText(fields.removeFirst(), s) == service, s) }
            try rootRequire(rootText(fields[0], s) == name && rootUInt(fields[1], s) == version && rootText(fields[2], s) == path && rootText(fields[3], s) == algorithm && rootText(fields[4], s) == presence, s)
            for i in 0..<4 { try rootRequire(rootText(fields[5 + i], s) == pins[i], s) }
            let point = try rootBase64(fields[9], maximum: 65, status: s)
            try rootP256(point, fingerprint: rootText(fields[10], s), status: s)
            return point
        }
        let n = try purpose(f[5], service: pair.nostrService, name: "nostr", version: pair.nostrVersion, path: "m/44'/1237'/0'/0/0", algorithm: "secp256k1-bip340", presence: "none", pins: [pair.nostrPublicKey, pair.npub, "", ""])
        let c = try purpose(f[6], service: pair.namecoinService, name: "namecoin", version: pair.namecoinVersion, path: "m/84'/7'/0'", algorithm: "bip32-secp256k1", presence: "biometry-any", pins: ["", "", pair.xpub, pair.origin])
        try rootRequire(n != c, s)
        return [rootOwned(n), rootOwned(c)]
    }
}

struct RootGrantsPreparationPublicView {
    let requestHash: String
    let originalBytes: Data
    let pair: RootGrantsPairPublic
    let publicKey, sealPublicKey, sealScript: String
    init(ownedBytes bytes: Data, request: RootGrantsPublicRequest) throws {
        try rootRequire(bytes.count <= 131072, .limitExceeded)
        let owned = rootOwned(bytes), s = RootGrantsStatus.publicPinMismatch
        let f = try rootFields(rootJSON(owned, maximum: 131072, status: s), ["root", "pair"], s)
        let root = try rootFields(f[0], ["profile", "derivation", "path", "algorithm", "public_key", "seal_public_key", "seal_script"], s)
        try rootRequire(rootText(root[0], s) == RootGrantsPublicRequest.profile && rootText(root[1], s) == RootGrantsPublicRequest.derivation && rootText(root[2], s) == RootGrantsPublicRequest.path && rootText(root[3], s) == "secp256k1-bip340+ecdsa", s)
        publicKey = try rootText(root[4], s); sealPublicKey = try rootText(root[5], s); sealScript = try rootText(root[6], s)
        try rootRequire(rootHex(publicKey, 32) && sealPublicKey == "02" + publicKey && rootMatch(sealScript, "76a914[a-f0-9]{40}88ac"), s)
        pair = try RootGrantsPairPublic(f[1])
        try rootRequire(pair.canonicalBytes == request.pair.canonicalBytes, s)
        originalBytes = owned; requestHash = request.requestHash
    }
}

// These public confirmations document exact text/byte comparisons ONLY. They
// cannot authorize wrap creation or establish actual UI/presence/store success.
struct RootGrantsPublicConfirmation {
    enum Stage: Equatable { case attachReviewed, storeReviewed }
    let stage: Stage
    let requestHash, snapshotHash: String
    fileprivate init(stage: Stage, requestHash: String, snapshotHash: String) {
        self.stage = stage; self.requestHash = requestHash; self.snapshotHash = snapshotHash
    }
}
private func rootRender(_ lines: [String], end: String) throws -> String {
    let text = (lines + [end]).joined(separator: "\n")
    try rootRequire(rootASCII(text.replacingOccurrences(of: "\n", with: "")) && text.utf8.count <= 1 << 20, .limitExceeded)
    return text
}

struct RootGrantsInitialReview {
    let request: RootGrantsPublicRequest
    let identities: [String]
    let text, snapshotHash: String
    init(request: RootGrantsPublicRequest) throws {
        self.request = request
        identities = [request.pair.nostrAddress, request.pair.namecoinAddress, request.rootAddress]
        text = try rootRender([
            "ATTACH ONLY - PUBLIC REVIEW",
            "Existing Nostr: \(identities[0])", "Existing Namecoin: \(identities[1])", "New root grants: \(identities[2])",
            "Retained pair: \(request.pair.service)/recovery@\(request.pair.version)",
            "Retained schema: \(request.pair.schema)", "Retained group: \(request.pair.groupID)",
            "Complete old metadata SHA256: \(request.pair.metadataHash)",
            "Old Nostr public key: \(request.pair.nostrPublicKey)", "Old Nostr npub: \(request.pair.npub)",
            "Old Namecoin xpub: \(request.pair.xpub)", "Old Namecoin origin: \(request.pair.origin)",
            "Root profile: \(RootGrantsPublicRequest.profile)", "Root derivation: \(RootGrantsPublicRequest.derivation)", "Root path: \(RootGrantsPublicRequest.path)",
            "Creation UTC: \(request.created)", "Original request SHA256: \(request.requestHash)",
            "Preserve both existing paired ciphertexts, metadata, identities and ACLs unchanged. Create only the distinct root item after all later checks.",
            "Retype all three full identities exactly, then ATTACH ROOT GRANTS.",
            "Complete canonical public request: \(String(decoding: request.originalBytes, as: UTF8.self))"
        ], end: "END OF COMPLETE ATTACH ONLY REVIEW")
        snapshotHash = rootHash(Data(text.utf8))
    }
    func confirmRetypes(_ entered: [String], attach: String, currentRequest: Data) throws -> RootGrantsPublicConfirmation {
        try rootRequire(currentRequest == request.originalBytes, .bindingMismatch)
        try rootRequire(entered == identities && attach == "ATTACH ROOT GRANTS", .canceled)
        return RootGrantsPublicConfirmation(stage: .attachReviewed, requestHash: request.requestHash, snapshotHash: snapshotHash)
    }
}

struct RootGrantsDerivedReview {
    let initial: RootGrantsInitialReview
    let preparation: RootGrantsPreparationPublicView
    let text, snapshotHash: String
    init(initial: RootGrantsInitialReview, attach: RootGrantsPublicConfirmation, preparation: RootGrantsPreparationPublicView) throws {
        try rootRequire(attach.stage == .attachReviewed && attach.requestHash == initial.request.requestHash && attach.snapshotHash == initial.snapshotHash, .operationUnavailable)
        try rootRequire(preparation.requestHash == initial.request.requestHash && preparation.pair.canonicalBytes == initial.request.pair.canonicalBytes, .publicPinMismatch)
        self.initial = initial; self.preparation = preparation
        text = try rootRender([initial.text, "Nostr pin: MATCH", "Namecoin account+origin: MATCH", "New root K: \(preparation.publicKey)",
            "Even-Y seal 02K: \(preparation.sealPublicKey)", "Exact P2PKH seal script: \(preparation.sealScript)",
            "Preparation SHA256: \(rootHash(preparation.originalBytes))", "Complete canonical public preparation: \(String(decoding: preparation.originalBytes, as: UTF8.self))",
            "MATCH is display only. Type STORE ROOT GRANTS for this exact root destination and unchanged preparation."
        ], end: "END OF COMPLETE MATCH AND STORE REVIEW")
        snapshotHash = rootHash(Data(text.utf8))
    }
    private func unchanged(_ request: Data, _ response: Data) throws {
        try rootRequire(request == initial.request.originalBytes && response == preparation.originalBytes, .bindingMismatch)
    }
    func confirmStore(_ entered: String, currentRequest: Data, currentPreparation: Data) throws -> RootGrantsPublicConfirmation {
        try unchanged(currentRequest, currentPreparation)
        try rootRequire(entered == "STORE ROOT GRANTS", .canceled)
        return RootGrantsPublicConfirmation(stage: .storeReviewed, requestHash: initial.request.requestHash, snapshotHash: snapshotHash)
    }
}

// Finite PUBLIC/SEALED response decoder, not an authenticity/store receipt.
// Actual Seal, native wrap provenance and ciphertext authenticity stay with the
// qualified engine/native/parent lifecycle. No decrypt/use method is provided.
struct RootGrantsSealedPublicView {
    let originalBytes, recordBytes, envelopeBytes: Data
    init(ownedBytes bytes: Data, request: RootGrantsPublicRequest, preparation: RootGrantsPreparationPublicView) throws {
        try rootRequire(bytes.count <= 131072, .limitExceeded)
        let owned = rootOwned(bytes), s = RootGrantsStatus.invalidEnvelope
        try rootRequire(preparation.requestHash == request.requestHash, .bindingMismatch)
        let fields = try rootFields(rootJSON(owned, maximum: 131072, status: s), ["record", "envelope"], s)
        let r = try rootFields(fields[0], ["schema", "service", "purpose", "version", "created", "profile", "derivation", "path", "algorithm", "presence", "public_key", "seal_public_key", "seal_script", "pair", "wrapping_point", "wrapping_fingerprint"], s)
        try rootRequire(rootText(r[0], s) == "keyvault-root-grants/1" && rootText(r[1], s) == request.service && rootText(r[2], s) == "root-grants" && rootUInt(r[3], s) == request.version && rootText(r[4], s) == request.created, s)
        try rootRequire(rootText(r[5], s) == RootGrantsPublicRequest.profile && rootText(r[6], s) == RootGrantsPublicRequest.derivation && rootText(r[7], s) == RootGrantsPublicRequest.path && rootText(r[8], s) == "secp256k1-bip340+ecdsa" && rootText(r[9], s) == "biometry-any-per-signature", s)
        try rootRequire(rootText(r[10], s) == preparation.publicKey && rootText(r[11], s) == preparation.sealPublicKey && rootText(r[12], s) == preparation.sealScript, s)
        let pair = try RootGrantsPairPublic(r[13])
        try rootRequire(pair.canonicalBytes == request.pair.canonicalBytes && preparation.pair.canonicalBytes == pair.canonicalBytes, s)
        let point = try rootBase64(r[14], maximum: 65, status: s), fingerprint = try rootText(r[15], s)
        try rootP256(point, fingerprint: fingerprint, status: s)
        try rootRequire(!request.retainedWrappingPoints.contains(point), s)
        let e = try rootFields(fields[1], ["schema", "algorithm", "enclave_blob", "point", "fingerprint", "ciphertext"], s)
        try rootRequire(rootText(e[0], s) == "keyvault-root-grants-ciphertext/1" && rootText(e[1], s) == "kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM", s)
        _ = try rootBase64(e[2], maximum: 16384, status: s)
        try rootRequire(rootBase64(e[3], maximum: 65, status: s) == point && rootText(e[4], s) == fingerprint, s)
        let ciphertext = try rootBase64(e[5], maximum: 149, status: s)
        try rootRequire(ciphertext.count == 149, s)
        do { _ = try P256.KeyAgreement.PublicKey(x963Representation: ciphertext.prefix(65)) }
        catch { throw RootGrantsReviewError(status: s) }
        originalBytes = owned; recordBytes = try rootCanonical(fields[0], s); envelopeBytes = try rootCanonical(fields[1], s)
    }
}
