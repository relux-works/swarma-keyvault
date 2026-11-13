import AppKit
import CryptoKit
import Darwin
import Dispatch
import Foundation
import LocalAuthentication
import NamecoinArchiveABI

private let rootSignV3Prefix = Data("swarma-grant-v3".utf8)

private func signV3Require(_ condition: Bool, _ status: RootGrantsStatus = .privateProtocolError) throws {
    guard condition else { throw RootGrantsReviewError(status: status) }
}

private func signV3Hex(_ bytes: Data) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

private func signV3DecodeHex(_ value: String, maximum: Int) throws -> Data {
	try signV3Require(value.utf8.count >= 2 && value.utf8.count <= maximum * 2 && value.utf8.count.isMultiple(of: 2) && value.utf8.allSatisfy {
        (48...57).contains($0) || (97...102).contains($0)
    })
	var output = Data(); output.reserveCapacity(value.utf8.count / 2)
    let source = Array(value.utf8)
    for index in stride(from: 0, to: source.count, by: 2) {
        func nibble(_ byte: UInt8) -> UInt8 { byte <= 57 ? byte - 48 : byte - 87 }
        output.append((nibble(source[index]) << 4) | nibble(source[index + 1]))
    }
    return output
}

private func signV3Hash(_ bytes: Data) -> Data { Data(SHA256.hash(data: bytes)) }

private func signV3ValidateRetainedPairMetadata(_ raw: Data, binding: NativeArchiveJSON) throws {
	let bound = try binding.fields([
		"schema", "service", "version", "group_id", "metadata_sha256", "nostr_identity", "nostr_version",
		"nostr_public_key", "nostr_npub", "namecoin_identity", "namecoin_version", "namecoin_xpub", "namecoin_origin"
	])
	let metadata = try NativeArchiveJSON.decode(raw, maximum: 32768, canonical: true)
	let record = try metadata.fields(["schema", "group_id", "service", "version", "created", "nostr", "namecoin"])
	let schema = try record[0].text()
	let groupID = try record[1].text()
	let retainedService = try record[2].text()
	let retainedVersion = try record[3].uint()
	let created = try record[4].text()
	let bindingService = try bound[1].text()
	let bindingVersion = try bound[2].uint()
	try signV3Require((schema == "keyvault-recovery/1" || schema == "keyvault-recovery/2") &&
					  groupID.utf8.count == 32 && groupID.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) &&
					  created.utf8.count == 20 && retainedService == bindingService && retainedVersion == bindingVersion,
					  .retainedRecordMismatch)
	let nostr = record[5]
	let namecoin = record[6]
	let nostrFields = try signV3RecoveryPurposeFields(nostr, schema: schema)
	let namecoinFields = try signV3RecoveryPurposeFields(namecoin, schema: schema)
	let nostrIdentity = schema == "keyvault-recovery/1" ? retainedService : try nostr.field("service").text()
	let namecoinIdentity = schema == "keyvault-recovery/1" ? retainedService : try namecoin.field("service").text()
	let metadataSHA256 = signV3Hex(signV3Hash(raw))
	try signV3Require(try bound[0].text() == schema && bound[1].text() == retainedService &&
					  bound[2].uint() == retainedVersion && bound[3].text() == groupID &&
					  bound[4].text() == metadataSHA256 && bound[5].text() == nostrIdentity &&
					  bound[6].uint() == nostrFields.version && bound[7].text() == nostrFields.publicKey &&
					  bound[8].text() == nostrFields.npub && bound[9].text() == namecoinIdentity &&
					  bound[10].uint() == namecoinFields.version && bound[11].text() == namecoinFields.xpub &&
					  bound[12].text() == namecoinFields.origin,
					  .retainedRecordMismatch)
}

private func signV3RecoveryPurposeFields(_ node: NativeArchiveJSON, schema: String) throws ->
		(version: UInt64, publicKey: String, npub: String, xpub: String, origin: String) {
	let names = schema == "keyvault-recovery/1"
		? ["purpose", "version", "path", "algorithm", "presence", "public_key", "npub", "xpub", "origin", "wrapping_point", "wrapping_fingerprint"]
		: ["service", "purpose", "version", "path", "algorithm", "presence", "public_key", "npub", "xpub", "origin", "wrapping_point", "wrapping_fingerprint"]
	_ = try node.fields(names)
	return (try node.field("version").uint(), try node.field("public_key").text(), try node.field("npub").text(),
			try node.field("xpub").text(), try node.field("origin").text())
}

struct RootGrantsSignV3Envelope {
    let blob, point, ciphertext: Data
}

private final class RootGrantsSignV3Context {
    private static let handleBit: UInt64 = 1 << 62
    private let cancellation: RootGrantsPrivateCancellation
    private let deadline: RootGrantsPrivateDeadline
    let handle: UInt64
    private var closed = false

    init(cancellation: RootGrantsPrivateCancellation) throws {
        self.cancellation = cancellation
        let startedAt = DispatchTime.now().uptimeNanoseconds
        let budget = try RootGrantsPrivateDeadline.boundedGrantSigningBudget(remaining: cancellation.remainingNanoseconds())
        deadline = RootGrantsPrivateDeadline(startedAt: startedAt, budget: budget)
        var opened: UInt64 = 0
        let code = kv_rg_sign_grant_v3_context_open_v1(budget, &opened)
        try RootGrantsArchiveBindings.signingStatus(code)
        guard opened & Self.handleBit != 0, opened & RootGrantsArchiveBindings.handleBit == 0,
              opened & ~(Self.handleBit | RootGrantsArchiveBindings.handleBit) != 0 else {
            throw RootGrantsReviewError(status: .privateProtocolError)
        }
        handle = opened
        do {
            try cancellation.setSigningCancellation { _ = kv_rg_sign_grant_v3_context_cancel_v1(opened) }
        } catch {
            _ = kv_rg_sign_grant_v3_context_close_v1(opened)
            throw error
        }
    }

    func remainingNanoseconds() throws -> UInt64 {
        try cancellation.check()
        return try deadline.remaining(at: DispatchTime.now().uptimeNanoseconds)
    }

    func close() {
        guard !closed else { return }
        closed = true
        try? cancellation.setSigningCancellation(nil)
        _ = kv_rg_sign_grant_v3_context_close_v1(handle)
    }
    deinit { close() }
}

struct RootGrantsSignV3Request {
    static let schema = "keyvault-root-grants-sign-request/2"
    static let operation = "review-sign-grant-v3"
    static let profile = "namecoin-landlord-root/1"
    static let offlinePolicy = "offline-document-review/1"
    static let originalBytes: Int = 262144

    let bytes: Data
    let reviewBytes: Data
    let display: String
    let grant, contract, authority, record: Data
    let ownerPrincipal, publicKey, messageSHA256: String
    let envelope: RootGrantsSignV3Envelope

    init(ownedBytes input: Data) throws {
        try signV3Require((1...Self.originalBytes).contains(input.count), .limitExceeded)
        let owned = input.withUnsafeBytes { Data($0) }
        let outer = try NativeArchiveJSON.decode(owned, maximum: Self.originalBytes, canonical: true)
        let outerFields = try outer.fields(["schema", "operation", "review", "envelope", "pair_metadata"])
        let requestSchema = try outerFields[0].text()
        let requestOperation = try outerFields[1].text()
        try signV3Require(requestSchema == Self.schema && requestOperation == Self.operation)
        let reviewNode = outerFields[2]
        let review = try reviewNode.fields([
			"operation", "profile", "observation_policy", "grant", "contract_bytes_base64", "authority", "record",
            "grant_bytes", "contract_bytes", "grant_sha256", "contract_sha256", "authority_sha256",
            "record_sha256", "message_sha256"
        ])
        let reviewOperation = try review[0].text()
        let reviewProfile = try review[1].text()
        let observationPolicy = try review[2].text()
        try signV3Require(reviewOperation == Self.operation && reviewProfile == Self.profile &&
                          observationPolicy == Self.offlinePolicy, .unsupportedOperation)
        grant = try review[3].canonical()
        contract = try review[4].base64(maximum: 65536)
		do {
			_ = try NativeArchiveJSON.decode(contract, maximum: 65536, canonical: true, escapeHTML: false)
		} catch {
			throw RootGrantsReviewError(status: .bindingMismatch)
		}
		authority = try review[5].canonical()
		record = try review[6].canonical()
        try signV3Require((1...65536).contains(grant.count) && (1...65536).contains(contract.count) &&
                          (1...32768).contains(authority.count) && (1...32768).contains(record.count), .limitExceeded)
        let grantLength = try review[7].uint()
        let contractLength = try review[8].uint()
        try signV3Require(grantLength == UInt64(grant.count) && contractLength == UInt64(contract.count), .bindingMismatch)
        let grantHash = try review[9].text()
        let contractHash = try review[10].text()
        let authorityHash = try review[11].text()
        let recordHash = try review[12].text()
        try signV3Require(grantHash == signV3Hex(signV3Hash(grant)) &&
                          contractHash == signV3Hex(signV3Hash(contract)) &&
                          authorityHash == signV3Hex(signV3Hash(authority)) &&
                          recordHash == signV3Hex(signV3Hash(record)), .bindingMismatch)
        var domainMessage = rootSignV3Prefix
        domainMessage.append(grant)
        let message = signV3Hash(domainMessage)
        let messageHash = try review[13].text()
        try signV3Require(messageHash == signV3Hex(message), .bindingMismatch)
        messageSHA256 = signV3Hex(message)

        let authorityNode = try NativeArchiveJSON.decode(authority, maximum: 32768, canonical: true)
        let authorityFields = try authorityNode.fields([
            "schema", "owner_principal", "landlord_name", "network", "genesis", "record", "operations",
            "agent_name", "agent_key", "grantee_key", "grantee_name", "scope", "not_before", "not_after",
            "max_grant_seconds", "max_budget_sat", "seal", "observation_policy"
        ])
        let authoritySchema = try authorityFields[0].text()
        let authorityObservation = try authorityFields[17].text()
        try signV3Require(authoritySchema == "namecoin-root-grants-authority/1" &&
                          authorityObservation == Self.offlinePolicy, .publicPinMismatch)
        ownerPrincipal = try authorityFields[1].text()
        let authorityRecord = try authorityFields[5].fields(["service", "version", "metadata_sha256", "public_key", "seal_script"])
        let rootRecord = try NativeArchiveJSON.decode(record, maximum: 32768, canonical: true)
        let rootFields = try rootRecord.fields([
            "schema", "service", "purpose", "version", "created", "profile", "derivation", "path", "algorithm",
            "presence", "public_key", "seal_public_key", "seal_script", "pair", "wrapping_point", "wrapping_fingerprint"
        ])
        let recordSchema = try rootFields[0].text()
        let purpose = try rootFields[2].text()
        let recordProfile = try rootFields[5].text()
        let derivation = try rootFields[6].text()
        let derivationPath = try rootFields[7].text()
        let algorithm = try rootFields[8].text()
        let presence = try rootFields[9].text()
        try signV3Require(recordSchema == "keyvault-root-grants/1" && purpose == "root-grants" &&
                          recordProfile == Self.profile && derivation == "bip85-hdseed-wif/1" &&
                          derivationPath == "m/83696968h/2h/7h" &&
                          algorithm == "secp256k1-bip340+ecdsa" && presence == "biometry-any-per-signature",
                          .publicPinMismatch)
        let service = try rootFields[1].text()
        let version = try rootFields[3].uint()
        publicKey = try rootFields[10].text()
        let sealPublicKey = try rootFields[11].text()
        let sealScript = try rootFields[12].text()
        let recordFingerprint = try rootFields[15].text()
        try signV3Require((1...2147483647).contains(version) && publicKey.utf8.count == 64 &&
                          publicKey.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) &&
                          sealPublicKey == "02" + publicKey && sealScript.utf8.count == 50, .publicPinMismatch)
        let authorityService = try authorityRecord[0].text()
        let authorityVersion = try authorityRecord[1].uint()
        let authorityMetadataHash = try authorityRecord[2].text()
        let authorityPublicKey = try authorityRecord[3].text()
        let authoritySealScript = try authorityRecord[4].text()
        try signV3Require(authorityService == service && authorityVersion == version &&
                          authorityMetadataHash == signV3Hex(signV3Hash(record)) &&
                          authorityPublicKey == publicKey && authoritySealScript == sealScript,
                          .publicPinMismatch)
		let pairMetadata: Data
		do {
			pairMetadata = try signV3DecodeHex(outerFields[4].text(), maximum: 32768)
				try signV3ValidateRetainedPairMetadata(pairMetadata, binding: rootFields[13])
		} catch let refusal as RootGrantsReviewError {
			throw refusal
		} catch {
			throw RootGrantsReviewError(status: .retainedRecordMismatch)
		}

        let envelopeFields = try outerFields[3].fields(["schema", "algorithm", "enclave_blob", "point", "fingerprint", "ciphertext"])
        let envelopeSchema = try envelopeFields[0].text()
        let envelopeAlgorithm = try envelopeFields[1].text()
        try signV3Require(envelopeSchema == "keyvault-root-grants-ciphertext/1" &&
                          envelopeAlgorithm == "kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM",
                          .invalidEnvelope)
        let blob = try envelopeFields[2].base64(maximum: 16384)
        let point = try envelopeFields[3].base64(maximum: 65)
        let ciphertext = try envelopeFields[5].base64(maximum: 149)
        let fingerprint = try envelopeFields[4].text()
        let recordPoint = try rootFields[14].base64(maximum: 65)
        try signV3Require((1...16384).contains(blob.count) && point.count == 65 && point == recordPoint &&
                          ciphertext.count == 149 && fingerprint == recordFingerprint &&
                          signV3Hex(signV3Hash(point)) == fingerprint,
                          .invalidEnvelope)
        envelope = RootGrantsSignV3Envelope(blob: blob, point: point, ciphertext: ciphertext)
		let reviewBytes = try reviewNode.canonical()
		guard let text = String(data: reviewBytes, encoding: .utf8),
		      let exactContract = String(data: contract, encoding: .utf8),
		      exactContract.utf8.allSatisfy({ (32...126).contains($0) }),
		      text.utf8.allSatisfy({ $0 == 10 || (32...126).contains($0) }),
              text.utf8.count <= 1 << 20 else { throw RootGrantsReviewError(status: .operationUnavailable) }
        self.reviewBytes = reviewBytes
		display = "REVIEW SIGN GRANT V3\n\n" + text + "\n\nExact canonical contract bytes (\(contract.count), SHA-256 \(contractHash)):\n" + exactContract +
			"\n\nNo chain observation is asserted. This operation signs only the displayed grant bytes."
        bytes = owned
    }
}

struct RootGrantsSignV3Attempt {
    enum Phase: Equatable { case created, reviewed, presencePending, presenceFresh, consumed, closed }
    private(set) var phase: Phase = .created

    mutating func confirmReview(_ entered: String) throws {
        guard phase == .created, entered == "SIGN GRANT V3" else {
            phase = .closed
            throw RootGrantsReviewError(status: .canceled)
        }
        phase = .reviewed
    }
    mutating func beginPresence() throws {
        guard phase == .reviewed else { phase = .closed; throw RootGrantsReviewError(status: .operationUnavailable) }
        phase = .presencePending
    }
    mutating func acceptFreshTouchID(_ accepted: Bool) throws {
        guard phase == .presencePending, accepted else {
            phase = .closed
            throw RootGrantsReviewError(status: accepted ? .privateProtocolError : .wrappingPolicyRefused)
        }
        phase = .presenceFresh
    }
    mutating func consumeForSigning() throws {
        guard phase == .presenceFresh else { phase = .closed; throw RootGrantsReviewError(status: .operationUnavailable) }
        phase = .consumed
    }
    mutating func close() { phase = .closed }
}

private func signV3Decrypt(_ request: RootGrantsSignV3Request, context: LAContext) throws -> Data {
    let key: SecureEnclave.P256.KeyAgreement.PrivateKey
    do { key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: request.envelope.blob, authenticationContext: context) }
    catch { throw RootGrantsReviewError(status: .wrappingPolicyRefused) }
    try signV3Require(key.publicKey.x963Representation == request.envelope.point, .invalidEnvelope)
    let ephemeral: P256.KeyAgreement.PublicKey
    do { ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: request.envelope.ciphertext.prefix(65)) }
    catch { throw RootGrantsReviewError(status: .invalidEnvelope) }
    let secret: SharedSecret
    do { secret = try key.sharedSecretFromKeyAgreement(with: ephemeral) }
    catch { throw RootGrantsReviewError(status: .wrappingPolicyRefused) }
    let derived = secret.x963DerivedSymmetricKey(using: SHA256.self,
        sharedInfo: request.envelope.ciphertext.prefix(65), outputByteCount: 32)
    var material = derived.withUnsafeBytes { Data($0) }
    defer { material.resetBytes(in: 0..<material.count) }
    let symmetric = SymmetricKey(data: material.prefix(16))
    let nonce: AES.GCM.Nonce
    do { nonce = try AES.GCM.Nonce(data: material.suffix(16)) }
    catch { throw RootGrantsReviewError(status: .invalidEnvelope) }
    let cipher = request.envelope.ciphertext
    let box: AES.GCM.SealedBox
    do { box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: cipher.dropFirst(65).dropLast(16), tag: cipher.suffix(16)) }
    catch { throw RootGrantsReviewError(status: .invalidEnvelope) }
    var plain: Data
    do { plain = try AES.GCM.open(box, using: symmetric) }
    catch { throw RootGrantsReviewError(status: .invalidEnvelope) }
    do {
        try signV3Require(plain.count == 68 && plain.prefix(4) == Data("KVG1".utf8), .invalidEnvelope)
        let metadataBinding = signV3Hash(Data("keyvault-root-grants/plaintext/1\0".utf8) + request.record)
        try signV3Require(plain.subdata(in: 4..<36) == metadataBinding, .bindingMismatch)
        return plain
    } catch {
        plain.resetBytes(in: 0..<plain.count)
        throw error
    }
}

private func signV3EvaluateTouchID(_ context: LAContext, cancellation: RootGrantsPrivateCancellation,
                                  transport: RootGrantsPrivateTransport, reason: String) throws -> Bool {
    let done = DispatchSemaphore(value: 0)
    let lock = NSLock()
    var accepted = false
    var finished = false
    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, _ in
        lock.lock(); accepted = success; finished = true; lock.unlock(); done.signal()
    }
    while done.wait(timeout: .now() + .milliseconds(100)) != .success {
        try cancellation.check()
        try transport.checkOutput()
    }
    lock.lock(); let result = accepted && finished; lock.unlock()
    try cancellation.check()
    try transport.checkOutput()
    return result
}

private func signV3Perform(_ original: Data, cancellation: RootGrantsPrivateCancellation,
                           transport: RootGrantsPrivateTransport) throws -> Data {
	let signingContext = try RootGrantsSignV3Context(cancellation: cancellation)
	defer { signingContext.close() }
    let request = try RootGrantsSignV3Request(ownedBytes: original)
    var attempt = RootGrantsSignV3Attempt()
    defer { attempt.close() }
    let entries = try RootGrantsNativeReview(text: request.display, labels: ["Type SIGN GRANT V3"],
        cancellation: cancellation, transport: transport, title: "Root grants: grant-v3 signature review").run()
    try attempt.confirmReview(entries.first ?? "")
    try cancellation.check()
    try transport.checkOutput()
    try attempt.beginPresence() // Consume the only presence phase before calling LocalAuthentication.

    let context = LAContext()
    context.localizedFallbackTitle = ""
    context.touchIDAuthenticationAllowableReuseDuration = 0
    defer { context.invalidate(); try? cancellation.setAuthenticationContext(nil) }
    do { try NativeNamecoinBiometryPolicy.requireTouchID(on: context) }
    catch { throw RootGrantsReviewError(status: .wrappingPolicyRefused) }
    try cancellation.setAuthenticationContext(context)
    try cancellation.check()
    let reason = "Touch ID confirms one root grants grant-v3 signature for \(request.ownerPrincipal)."
    let accepted = try signV3EvaluateTouchID(context, cancellation: cancellation, transport: transport, reason: reason)
    try attempt.acceptFreshTouchID(accepted)
    try cancellation.check()
    try transport.checkOutput()
	try transport.recheck(stage: 1, remainingNanoseconds: signingContext.remainingNanoseconds())
	try cancellation.check()
	try transport.checkOutput()
	_ = try signingContext.remainingNanoseconds()
	var policyRequest = Array(request.bytes)
	let policyRequestCount = policyRequest.count
	let policyStatus = policyRequest.withUnsafeMutableBufferPointer { requestBuffer in
		kv_rg_sign_grant_v3_policy_check_v1(signingContext.handle, requestBuffer.baseAddress,
			size_t(policyRequestCount))
	}
	try RootGrantsArchiveBindings.signingStatus(policyStatus)
	try cancellation.check()
	try transport.checkOutput()
	_ = try signingContext.remainingNanoseconds()
    try attempt.consumeForSigning()

    var plaintext = try signV3Decrypt(request, context: context)
    defer { plaintext.resetBytes(in: 0..<plaintext.count) }
    try cancellation.check()
    try transport.checkOutput()
    try transport.recheck(stage: 2, remainingNanoseconds: signingContext.remainingNanoseconds())
    try cancellation.check()
	_ = try signingContext.remainingNanoseconds()
    var signature = Data(repeating: 0, count: 64)
    defer { signature.resetBytes(in: 0..<signature.count) }
    var written: size_t = 0
	var requestBuffer = Array(request.bytes)
	let requestCount = requestBuffer.count
	let plaintextCount = plaintext.count
	let signatureCapacity = signature.count
	let code = requestBuffer.withUnsafeMutableBufferPointer { req in
        plaintext.withUnsafeMutableBytes { privateBytes in
            signature.withUnsafeMutableBytes { output in
				kv_rg_sign_grant_v3_v1(
					signingContext.handle,
					req.baseAddress, size_t(requestCount),
					privateBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), size_t(plaintextCount),
					output.baseAddress?.assumingMemoryBound(to: UInt8.self), size_t(signatureCapacity), &written)
            }
        }
    }
	try RootGrantsArchiveBindings.signingStatus(code)
    try signV3Require(written == 64, .privateProtocolError)
    try cancellation.check()
    try transport.checkOutput()
    // The linked engine independently recomputes and verifies the BIP-340 result.
    return Data(signature)
}

func rootGrantsSignGrantV3() -> Int32 {
    let deadline = RootGrantsPrivateDeadline(startedAt: DispatchTime.now().uptimeNanoseconds, budget: 120_000_000_000)
    let cancellation = RootGrantsPrivateCancellation(deadline: deadline)
    let queue = DispatchQueue(label: "keyvault.root-grant-v3-cancellation")
    signal(SIGTERM, SIG_IGN)
    signal(SIGPIPE, SIG_IGN)
    let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: queue)
    termination.setEventHandler { cancellation.cancel() }
    termination.resume()
    let timeout = DispatchSource.makeTimerSource(queue: queue)
    timeout.schedule(deadline: DispatchTime(uptimeNanoseconds: deadline.expiresAt))
    timeout.setEventHandler { cancellation.cancel(.timeout) }
    timeout.resume()
    defer { timeout.cancel() }
    let parent = getppid()
    guard parent > 1 else { termination.cancel(); return 1 }
    let parentExit = DispatchSource.makeProcessSource(identifier: parent, eventMask: .exit, queue: queue)
    parentExit.setEventHandler { cancellation.cancel(.privateProtocolError) }
    parentExit.resume()
    defer { termination.cancel(); parentExit.cancel(); _ = cancellation.finish() }
    guard getppid() == parent else { return 1 }
    let transport: RootGrantsPrivateTransport
    do { transport = try RootGrantsPrivateTransport(cancellation) }
    catch { return 1 }
    var request: Data?
    var payload: RootGrantsPrivateFrame.Payload
    do {
        request = try transport.request()
        guard let request else { throw RootGrantsReviewError(status: .privateProtocolError) }
        let signature = try autoreleasepool { try signV3Perform(request, cancellation: cancellation, transport: transport) }
        payload = .signature(signature)
    } catch {
        payload = .refusal((error as? RootGrantsReviewError)?.status ?? .privateProtocolError)
    }
    let cleanup = cancellation.finish()
    if cleanup != .success { payload = .refusal(cleanup) }
    do {
        try transport.write(payload, request: request)
        try transport.complete()
        return 0
    } catch { return 1 }
}
