import CryptoKit
import Darwin
import Dispatch
import Foundation
import LocalAuthentication
import NamecoinArchiveABI

private func trustCountersignRequire(_ condition: Bool, _ status: RootGrantsStatus = .privateProtocolError) throws {
    guard condition else { throw RootGrantsReviewError(status: status) }
}

private func trustCountersignHash(_ bytes: Data) -> Data { Data(SHA256.hash(data: bytes)) }

private func trustCountersignHex(_ bytes: Data) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

private func trustCountersignLowerHex(_ value: String, bytes: Int) -> Bool {
    value.utf8.count == bytes * 2 && value.utf8.allSatisfy {
        (48...57).contains($0) || (97...102).contains($0)
    }
}

struct RootGrantsTrustContractContextView {
    let ownerPrincipal: String
    let issuerKey: String
    let recordVersion: UInt64
    let recordSHA256: String
    let rootGeneration: UInt64
    let granteeName: String
    let authorityNotBefore: UInt64
    let authorityNotAfter: UInt64
    let maximumGrantSeconds: UInt64
    let sealTXID: String
    let sealVout: UInt64
}

struct RootGrantsTrustContractCountersignRequest {
    static let schema = "keyvault-root-grants-sign-request/2"
    static let operation = "review-sign-trust-contract-countersign"
    static let reviewProfile = "namecoin-landlord-root/1"
    static let contractProfile = "swarma-trust-contract/2"
    static let offlinePolicy = "offline-document-review/1"
    static let maximumBytes = 262_144
    static let maximumNestedObjectBytes = 32_768
    static let maximumReviewBytes = 262_144

    static func nonLIPBoundsStatus(contextBytes: Int, authorityBytes: Int, recordBytes: Int,
                                   reviewBytes: Int, requestBytes: Int) -> RootGrantsStatus? {
        let sizes = [contextBytes, authorityBytes, recordBytes, reviewBytes, requestBytes]
        guard sizes.allSatisfy({ $0 >= 0 }),
              contextBytes <= maximumNestedObjectBytes,
              authorityBytes <= maximumNestedObjectBytes,
              recordBytes <= maximumNestedObjectBytes,
              reviewBytes <= maximumReviewBytes,
              requestBytes <= maximumBytes else { return .limitExceeded }
        return nil
    }

    let bytes: Data
    let reviewBytes: Data
    let contract: RootGrantsTrustContractV2
    let contractSHA256: String
    let scopeText: Data
    let issuanceContext: Data
    let authority: Data
    let record: Data
    let pairMetadata: Data
    let envelope: RootGrantsSignV3Envelope
    let ownerPrincipal: String
    let issuerKey: String
    let context: RootGrantsTrustContractContextView
    let display: String

    init(ownedBytes input: Data) throws {
        try trustCountersignRequire(!input.isEmpty, .invalidArguments)
        try trustCountersignRequire(input.count <= Self.maximumBytes, .limitExceeded)
        let owned = input.withUnsafeBytes { Data($0) }
        let outer: NativeArchiveJSON
        do {
            outer = try NativeArchiveJSON.decode(owned, maximum: Self.maximumBytes, canonical: true,
                                                maximumArrayMembers: Self.maximumBytes,
                                                maximumObjectMembers: Self.maximumBytes, maximumDepth: 64)
        }
        catch { throw RootGrantsReviewError(status: .privateProtocolError) }
        let outerFields = try Self.fields(outer, ["schema", "operation", "review", "envelope", "pair_metadata"], .privateProtocolError)
        let schema = try Self.text(outerFields[0], .privateProtocolError)
        let operation = try Self.text(outerFields[1], .privateProtocolError)
        try trustCountersignRequire(schema == Self.schema, .unsupportedVersion)
        try trustCountersignRequire(operation == Self.operation, .unsupportedOperation)

        let reviewNode = outerFields[2]
        let review = try Self.fields(reviewNode, [
            "operation", "profile", "contract_profile", "contract_bytes_base64", "contract_bytes", "contract_sha256",
            "scope_text_bytes_base64", "scope_text_bytes", "scope_text_sha256", "issuance_context", "authority",
            "record", "authority_sha256", "record_sha256",
        ], .privateProtocolError)
        try trustCountersignRequire(try Self.text(review[0], .privateProtocolError) == Self.operation, .unsupportedOperation)
        try trustCountersignRequire(try Self.text(review[1], .privateProtocolError) == Self.reviewProfile, .unsupportedVersion)
        try trustCountersignRequire(try Self.text(review[2], .privateProtocolError) == Self.contractProfile, .unsupportedVersion)

        let contractBase64 = try Self.text(review[3], .privateProtocolError)
        let contractByteCount = try Self.number(review[4], .privateProtocolError)
        let contractHashText = try Self.text(review[5], .privateProtocolError)
        let scopeBase64 = try Self.text(review[6], .privateProtocolError)
        let scopeTextByteCount = try Self.number(review[7], .privateProtocolError)
        let scopeHash = try Self.text(review[8], .privateProtocolError)
        _ = try Self.fields(review[9], [
            "root_record", "root_generation", "landlord_name", "network", "genesis", "issuer_key", "agent_name",
            "agent_key", "grantee_key", "grantee_name", "not_before", "not_after", "max_grant_seconds",
            "max_budget_sat", "seal", "actions", "repos", "spend_budget", "derived_v3_scope",
        ], .privateProtocolError)
        _ = try Self.fields(review[10], [
            "schema", "owner_principal", "landlord_name", "network", "genesis", "record", "root_generation",
            "operations", "agent_name", "agent_key", "grantee_key", "grantee_name", "scope", "not_before",
            "not_after", "max_grant_seconds", "max_budget_sat", "seal", "approved_contract", "observation_policy",
        ], .privateProtocolError)
        _ = try Self.fields(review[11], [
            "schema", "service", "purpose", "version", "created", "profile", "derivation", "path", "algorithm",
            "presence", "public_key", "seal_public_key", "seal_script", "pair", "wrapping_point", "wrapping_fingerprint",
        ], .privateProtocolError)
        let authorityHashText = try Self.text(review[12], .privateProtocolError)
        let recordHashText = try Self.text(review[13], .privateProtocolError)
        try Self.validateContextCarrierTypes(contextNode: review[9], authorityNode: review[10], recordNode: review[11])
        let pairMetadataText = try Self.text(outerFields[4], .privateProtocolError)
        guard case .object = outerFields[3] else { throw RootGrantsReviewError(status: .privateProtocolError) }

        let contextBytes = try Self.canonical(review[9], status: .privateProtocolError)
        let authorityBytes = try Self.canonical(review[10], status: .privateProtocolError)
        let recordBytes = try Self.canonical(review[11], status: .privateProtocolError)
        let reviewBytes = try Self.canonical(reviewNode, status: .privateProtocolError)
        // The outer input was accepted only after exact canonical re-encoding, so these node encodings have the
        // same UTF-8 octets and lengths as their original canonical slices in the request.
        if let status = Self.nonLIPBoundsStatus(contextBytes: contextBytes.count, authorityBytes: authorityBytes.count,
                                                recordBytes: recordBytes.count, reviewBytes: reviewBytes.count,
                                                requestBytes: owned.count) {
            throw RootGrantsReviewError(status: status)
        }

        try Self.requireHashSpelling(contractHashText)
        try Self.requireHashSpelling(authorityHashText)
        try Self.requireHashSpelling(recordHashText)
        let contractFromBase64 = try Self.base64(contractBase64, maximum: Self.maximumBytes,
                                                 status: .privateProtocolError, allowEmpty: true)
        let scopeFromBase64 = try Self.base64(scopeBase64, maximum: Self.maximumBytes,
                                              status: .privateProtocolError, allowEmpty: true)
        try trustCountersignRequire(contractByteCount == UInt64(contractFromBase64.count), .bindingMismatch)
        try trustCountersignRequire(scopeTextByteCount == UInt64(scopeFromBase64.count), .bindingMismatch)

        let contract: RootGrantsTrustContractV2
        do { contract = try RootGrantsTrustContractV2(ownedBytes: contractFromBase64) }
        catch is RootGrantsTrustContractV2Failure { throw RootGrantsReviewError(status: .bindingMismatch) }
        catch { throw RootGrantsReviewError(status: .bindingMismatch) }
        if let refusal = contract.instanceRefusal() { throw RootGrantsReviewError(status: refusal.nativeStatus) }

        try trustCountersignRequire(trustCountersignLowerHex(scopeHash, bytes: 32) || scopeHash.isEmpty, .bindingMismatch)
        try trustCountersignRequire(scopeHash == contract.scopeTextSHA256, .bindingMismatch)
        if let refusal = RootGrantsTrustContractV2.validateScopeText(
            scopeFromBase64, reviewedHash: scopeHash, contractHash: contract.scopeTextSHA256
        ) {
            throw RootGrantsReviewError(status: refusal.nativeStatus)
        }

        let contractHash = try Self.checkedHash(contractHashText, bytes: contract.bytes)
        let authorityHash = try Self.checkedHash(authorityHashText, bytes: authorityBytes)
        let recordHash = try Self.checkedHash(recordHashText, bytes: recordBytes)
        let authorityNode = review[10]
        let recordNode = review[11]
        let contextNode = review[9]
        let contextView = try Self.validateContext(contextNode, authority: authorityNode, record: recordNode,
                                                   recordBytes: recordBytes, contract: contract)
        try trustCountersignRequire(authorityHash == trustCountersignHex(trustCountersignHash(authorityBytes)) &&
                                    recordHash == trustCountersignHex(trustCountersignHash(recordBytes)), .bindingMismatch)

        try trustCountersignRequire(pairMetadataText.utf8.count <= 65_536, .limitExceeded)
        let pairMetadata = try Self.decodeHex(pairMetadataText, maximum: 32_768)
        try trustCountersignRequire(!pairMetadata.isEmpty, .retainedRecordMismatch)
        do { try signV3ValidateRetainedPairMetadata(pairMetadata, binding: try recordNode.field("pair")) }
        catch { throw RootGrantsReviewError(status: .retainedRecordMismatch) }

        let envelope: RootGrantsSignV3Envelope
        do { envelope = try Self.validateEnvelope(outerFields[3], record: recordNode) }
        catch let refusal as RootGrantsReviewError { throw refusal }
        catch { throw RootGrantsReviewError(status: .invalidEnvelope) }

        let exactContract = String(decoding: contract.bytes, as: UTF8.self)
        let reviewText = String(decoding: reviewBytes, as: UTF8.self)
        let escapedScopeText = Self.escapedBytes(scopeFromBase64)
        let display = "REVIEW SIGN TRUST CONTRACT COUNTERSIGN\n\n" + reviewText +
            "\n\nExact canonical trust contract (\(contract.bytes.count) bytes, SHA-256 \(contractHash)):\n" + exactContract +
            "\n\nScope text (\(scopeFromBase64.count) original bytes, SHA-256 \(scopeHash.isEmpty ? "none" : scopeHash)):\n\"" +
            escapedScopeText + "\"\n\nFull issuer key: \(contextView.issuerKey)\n" +
            "Authority window: \(contextView.authorityNotBefore)..\(contextView.authorityNotAfter); " +
            "maximum grant duration: \(contextView.maximumGrantSeconds) seconds\n" +
            "Derived Grant v3 scope: [\(contract.derivedV3Scope.joined(separator: ", "))] " +
            "(empty means no v3 actions). Trust instruct/review are not Grant v3 effects; this root instance refuses spend. " +
            "The configured authority remains NOT_ISSUABLE; no issuance or chain state is asserted."
        try trustCountersignRequire(display.utf8.count <= 1 << 20 && display.utf8.allSatisfy { (32...126).contains($0) || $0 == 10 },
                                    .operationUnavailable)

        self.bytes = owned
        self.reviewBytes = reviewBytes
        self.contract = contract
        self.contractSHA256 = contractHash
        self.scopeText = scopeFromBase64
        self.issuanceContext = contextBytes
        self.authority = authorityBytes
        self.record = recordBytes
        self.pairMetadata = pairMetadata
        self.envelope = envelope
        self.ownerPrincipal = contextView.ownerPrincipal
        self.issuerKey = contextView.issuerKey
        self.context = contextView
        self.display = display
    }

    func signingWindowRefusal(now: UInt64) -> RootGrantsStatus? {
        guard now >= context.authorityNotBefore, now <= context.authorityNotAfter,
              now <= contract.notAfter, contract.notBefore >= context.authorityNotBefore,
              contract.notAfter <= context.authorityNotAfter,
              contract.notAfter - contract.notBefore <= context.maximumGrantSeconds else {
            return .bindingMismatch
        }
        return nil
    }

    func checkSigningWindow(now: UInt64) throws {
        if let refusal = signingWindowRefusal(now: now) { throw RootGrantsReviewError(status: refusal) }
    }

    static func localizedReason(ownerPrincipal: String) -> String {
        "Touch ID confirms one root trust contract countersignature for \(ownerPrincipal)."
    }

    private static func validateContext(_ contextNode: NativeArchiveJSON, authority authorityNode: NativeArchiveJSON,
                                        record recordNode: NativeArchiveJSON, recordBytes: Data,
                                        contract: RootGrantsTrustContractV2) throws -> RootGrantsTrustContractContextView {
        let contextFields = try fields(contextNode, [
            "root_record", "root_generation", "landlord_name", "network", "genesis", "issuer_key", "agent_name",
            "agent_key", "grantee_key", "grantee_name", "not_before", "not_after", "max_grant_seconds",
            "max_budget_sat", "seal", "actions", "repos", "spend_budget", "derived_v3_scope",
        ], .privateProtocolError)
        let authorityFields = try fields(authorityNode, [
            "schema", "owner_principal", "landlord_name", "network", "genesis", "record", "root_generation",
            "operations", "agent_name", "agent_key", "grantee_key", "grantee_name", "scope", "not_before",
            "not_after", "max_grant_seconds", "max_budget_sat", "seal", "approved_contract", "observation_policy",
        ], .privateProtocolError)
        let recordFields = try fields(recordNode, [
            "schema", "service", "purpose", "version", "created", "profile", "derivation", "path", "algorithm",
            "presence", "public_key", "seal_public_key", "seal_script", "pair", "wrapping_point", "wrapping_fingerprint",
        ], .privateProtocolError)
        _ = try text(recordFields[4], .privateProtocolError)

        let ownerPrincipal = try text(authorityFields[1], .privateProtocolError)
        let landlordName = try text(authorityFields[2], .privateProtocolError)
        let network = try text(authorityFields[3], .privateProtocolError)
        let genesis = try text(authorityFields[4], .privateProtocolError)
        let authorityRecord = try fields(authorityFields[5],
            ["service", "version", "metadata_sha256", "public_key", "seal_script"], .privateProtocolError)
        let authorityRootVersion = try number(authorityFields[6], .privateProtocolError)
        let authorityOperations = try strings(authorityFields[7], .privateProtocolError)
        let agentName = try text(authorityFields[8], .privateProtocolError)
        let agentKey = try text(authorityFields[9], .privateProtocolError)
        let granteeKey = try text(authorityFields[10], .privateProtocolError)
        let granteeName = try text(authorityFields[11], .privateProtocolError)
        let authorityScope = try strings(authorityFields[12], .privateProtocolError)
        let authorityNotBefore = try number(authorityFields[13], .privateProtocolError)
        let authorityNotAfter = try number(authorityFields[14], .privateProtocolError)
        let maximumGrantSeconds = try number(authorityFields[15], .privateProtocolError)
        let maximumBudget = try number(authorityFields[16], .privateProtocolError)
        let authoritySeal = try fields(authorityFields[17], ["txid", "vout"], .privateProtocolError)
        let authoritySealTXID = try text(authoritySeal[0], .privateProtocolError)
        let authoritySealVout = try number(authoritySeal[1], .privateProtocolError)
        let approved = try fields(authorityFields[18], ["profile", "contract_bytes_base64", "contract_sha256"], .privateProtocolError)
        let observationPolicy = try text(authorityFields[19], .privateProtocolError)

        let recordSchema = try text(recordFields[0], .privateProtocolError)
        let recordService = try text(recordFields[1], .privateProtocolError)
        let recordPurpose = try text(recordFields[2], .privateProtocolError)
        let recordVersion = try number(recordFields[3], .privateProtocolError)
        let recordProfile = try text(recordFields[5], .privateProtocolError)
        let derivation = try text(recordFields[6], .privateProtocolError)
        let derivationPath = try text(recordFields[7], .privateProtocolError)
        let algorithm = try text(recordFields[8], .privateProtocolError)
        let presence = try text(recordFields[9], .privateProtocolError)
        let issuerKey = try text(recordFields[10], .privateProtocolError)
        let sealPublicKey = try text(recordFields[11], .privateProtocolError)
        let sealScript = try text(recordFields[12], .privateProtocolError)
        let recordFingerprint = try text(recordFields[15], .privateProtocolError)
        let recordPoint = try base64(text(recordFields[14], .privateProtocolError),
                                     maximum: Self.maximumNestedObjectBytes,
                                     status: .privateProtocolError, allowEmpty: true)

        let contextRecord = try fields(contextFields[0], ["service", "version", "metadata_sha256", "public_key", "seal_script"], .privateProtocolError)
        let contextRootGeneration = try number(contextFields[1], .privateProtocolError)
        let contextLandlord = try text(contextFields[2], .privateProtocolError)
        let contextNetwork = try text(contextFields[3], .privateProtocolError)
        let contextGenesis = try text(contextFields[4], .privateProtocolError)
        let contextIssuer = try text(contextFields[5], .privateProtocolError)
        let contextAgentName = try text(contextFields[6], .privateProtocolError)
        let contextAgentKey = try text(contextFields[7], .privateProtocolError)
        let contextGranteeKey = try text(contextFields[8], .privateProtocolError)
        let contextGranteeName = try text(contextFields[9], .privateProtocolError)
        let contextNotBefore = try number(contextFields[10], .privateProtocolError)
        let contextNotAfter = try number(contextFields[11], .privateProtocolError)
        let contextMaxGrantSeconds = try number(contextFields[12], .privateProtocolError)
        let contextMaxBudget = try number(contextFields[13], .privateProtocolError)
        let contextSeal = try fields(contextFields[14], ["txid", "vout"], .privateProtocolError)
        let contextActions = try strings(contextFields[15], .privateProtocolError)
        let contextRepos = try strings(contextFields[16], .privateProtocolError)
        let contextSpendBudget = try number(contextFields[17], .privateProtocolError)
        let contextScope = try strings(contextFields[18], .privateProtocolError)

        try trustCountersignRequire(try text(authorityFields[0], .privateProtocolError) == "namecoin-root-grants-authority/2" &&
                                    observationPolicy == RootGrantsTrustContractCountersignRequest.offlinePolicy,
                                    .bindingMismatch)
        try trustCountersignRequire(Self.validOwnerPrincipal(ownerPrincipal) &&
                                    Self.validNetworkGenesis(network, genesis), .publicPinMismatch)
        try trustCountersignRequire(recordSchema == "keyvault-root-grants/1" && recordPurpose == "root-grants" &&
                                    recordProfile == RootGrantsTrustContractCountersignRequest.reviewProfile &&
                                    derivation == "bip85-hdseed-wif/1" && derivationPath == "m/83696968h/2h/7h" &&
                                    algorithm == "secp256k1-bip340+ecdsa" && presence == "biometry-any-per-signature" &&
                                    (1...2_147_483_647).contains(recordVersion) && TrustSecp256k1Key.isValidXOnly(issuerKey) &&
                                    sealPublicKey == "02" + issuerKey && trustCountersignLowerHex(sealScript, bytes: 25) &&
                                    recordPoint.count == 65 && trustCountersignLowerHex(recordFingerprint, bytes: 32) &&
                                    trustCountersignHex(trustCountersignHash(recordPoint)) == recordFingerprint,
                                    .publicPinMismatch)
        try trustCountersignRequire(authorityOperations == [Self.operation, "review-sign-grant-v3"] &&
                                    TrustSecp256k1Key.isValidXOnly(agentKey) && TrustSecp256k1Key.isValidXOnly(granteeKey) &&
                                    (granteeName.isEmpty || Self.validIDName(granteeName)) &&
                                    authorityNotAfter > authorityNotBefore && maximumGrantSeconds > 0 && maximumBudget == 0 &&
                                    trustCountersignLowerHex(authoritySealTXID, bytes: 32) &&
                                    authoritySealVout <= UInt64(UInt32.max),
                                    .bindingMismatch)

        let authorityRecordService = try text(authorityRecord[0], .privateProtocolError)
        let authorityRecordVersion = try number(authorityRecord[1], .privateProtocolError)
        let authorityRecordHash = try text(authorityRecord[2], .privateProtocolError)
        let authorityRecordKey = try text(authorityRecord[3], .privateProtocolError)
        let authoritySealScript = try text(authorityRecord[4], .privateProtocolError)
        let contextRecordService = try text(contextRecord[0], .privateProtocolError)
        let contextRecordVersion = try number(contextRecord[1], .privateProtocolError)
        let contextRecordHash = try text(contextRecord[2], .privateProtocolError)
        let contextRecordKey = try text(contextRecord[3], .privateProtocolError)
        let contextSealScript = try text(contextRecord[4], .privateProtocolError)
        let recordDigest = trustCountersignHex(trustCountersignHash(recordBytes))
        let sealTXID = authoritySealTXID
        let sealVout = authoritySealVout
        try trustCountersignRequire(authorityRecordService == recordService && authorityRecordVersion == recordVersion &&
                                    authorityRecordHash == recordDigest && authorityRecordKey == issuerKey &&
                                    authoritySealScript == sealScript && authorityRootVersion == recordVersion &&
                                    contextRootGeneration == recordVersion && contextRecordService == recordService &&
                                    contextRecordVersion == recordVersion && contextRecordHash == recordDigest &&
                                    contextRecordKey == issuerKey && contextSealScript == sealScript,
                                    .publicPinMismatch)

        let contextSealTXID = try text(contextSeal[0], .privateProtocolError)
        let contextSealVout = try number(contextSeal[1], .privateProtocolError)
        let authorityNotBeforeContext = try number(contextFields[10], .privateProtocolError)
        let authorityNotAfterContext = try number(contextFields[11], .privateProtocolError)
        try trustCountersignRequire(contextLandlord == landlordName && landlordName == contract.landlordName &&
                                    contextNetwork == network && network == contract.network && contextGenesis == genesis &&
                                    contextIssuer == issuerKey && contextAgentName == agentName && agentName == contract.agentName &&
                                    contextAgentKey == agentKey && contextGranteeKey == granteeKey && granteeKey == contract.granteeKey &&
                                    contextGranteeName == granteeName && contextNotBefore == authorityNotBeforeContext &&
                                    contextNotAfter == authorityNotAfterContext && contextNotBefore == authorityNotBefore &&
                                    contextNotAfter == authorityNotAfter && contextMaxGrantSeconds == maximumGrantSeconds &&
                                    contextMaxBudget == maximumBudget && contextSpendBudget == contract.spendBudget &&
                                    contextActions == contract.actions && contextRepos == contract.repos &&
                                    contextScope == contract.derivedV3Scope && authorityScope == contract.derivedV3Scope &&
                                    contextSealTXID == sealTXID && contextSealVout == sealVout &&
                                    sealVout <= UInt64(UInt32.max), .bindingMismatch)

        let approvedProfile = try text(approved[0], .privateProtocolError)
        let approvedBytes = try base64(text(approved[1], .privateProtocolError), maximum: 8192, status: .privateProtocolError)
        let approvedHash = try text(approved[2], .privateProtocolError)
        try trustCountersignRequire(approvedProfile == contract.profile && approvedBytes == contract.bytes &&
                                    approvedHash == trustCountersignHex(trustCountersignHash(contract.bytes)) &&
                                    contract.spendBudget == 0 && !contract.actions.contains("spend") &&
                                    contract.notBefore >= authorityNotBefore &&
                                    contract.notAfter <= authorityNotAfter &&
                                    contract.notAfter - contract.notBefore <= maximumGrantSeconds &&
                                    sealVout <= UInt64(UInt32.max), .bindingMismatch)

        return RootGrantsTrustContractContextView(ownerPrincipal: ownerPrincipal, issuerKey: issuerKey,
            recordVersion: recordVersion, recordSHA256: recordDigest, rootGeneration: contextRootGeneration,
            granteeName: granteeName, authorityNotBefore: authorityNotBefore, authorityNotAfter: authorityNotAfter,
            maximumGrantSeconds: maximumGrantSeconds, sealTXID: sealTXID, sealVout: sealVout)
    }

    private static func validateEnvelope(_ node: NativeArchiveJSON, record: NativeArchiveJSON) throws -> RootGrantsSignV3Envelope {
        let fields = try Self.fields(node, ["schema", "algorithm", "enclave_blob", "point", "fingerprint", "ciphertext"], .invalidEnvelope)
        let schema = try text(fields[0], .invalidEnvelope)
        let algorithm = try text(fields[1], .invalidEnvelope)
        try trustCountersignRequire(schema == "keyvault-root-grants-ciphertext/1" &&
                                    algorithm == "kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM",
                                    .invalidEnvelope)
        let blob = try base64(text(fields[2], .invalidEnvelope), maximum: 16_384, status: .privateProtocolError)
        let point = try base64(text(fields[3], .invalidEnvelope), maximum: 65, status: .privateProtocolError)
        let ciphertext = try base64(text(fields[5], .invalidEnvelope), maximum: 149, status: .privateProtocolError)
        let fingerprint = try text(fields[4], .invalidEnvelope)
        let recordPoint = try base64(text(try record.field("wrapping_point"), .invalidEnvelope), maximum: 65, status: .invalidEnvelope)
        let recordFingerprint = try text(try record.field("wrapping_fingerprint"), .invalidEnvelope)
        try trustCountersignRequire((1...16_384).contains(blob.count) && point.count == 65 && point == recordPoint &&
                                    ciphertext.count == 149 && fingerprint == recordFingerprint &&
                                    trustCountersignHex(trustCountersignHash(point)) == fingerprint, .invalidEnvelope)
        return RootGrantsSignV3Envelope(blob: blob, point: point, ciphertext: ciphertext)
    }

    private static func fields(_ node: NativeArchiveJSON, _ names: [String], _ status: RootGrantsStatus) throws -> [NativeArchiveJSON] {
        do { return try node.fields(names) }
        catch { throw RootGrantsReviewError(status: status) }
    }

    // Check canonical nested wire shapes and declared types before the C2 size gate;
    // the later context binder owns semantic pins and authority relationships.
    private static func validateContextCarrierTypes(contextNode: NativeArchiveJSON,
                                                    authorityNode: NativeArchiveJSON,
                                                    recordNode: NativeArchiveJSON) throws {
        let context = try fields(contextNode, [
            "root_record", "root_generation", "landlord_name", "network", "genesis", "issuer_key", "agent_name",
            "agent_key", "grantee_key", "grantee_name", "not_before", "not_after", "max_grant_seconds",
            "max_budget_sat", "seal", "actions", "repos", "spend_budget", "derived_v3_scope",
        ], .privateProtocolError)
        let authority = try fields(authorityNode, [
            "schema", "owner_principal", "landlord_name", "network", "genesis", "record", "root_generation",
            "operations", "agent_name", "agent_key", "grantee_key", "grantee_name", "scope", "not_before",
            "not_after", "max_grant_seconds", "max_budget_sat", "seal", "approved_contract", "observation_policy",
        ], .privateProtocolError)
        let record = try fields(recordNode, [
            "schema", "service", "purpose", "version", "created", "profile", "derivation", "path", "algorithm",
            "presence", "public_key", "seal_public_key", "seal_script", "pair", "wrapping_point", "wrapping_fingerprint",
        ], .privateProtocolError)

        func checkRecord(_ node: NativeArchiveJSON) throws {
            let fields = try Self.fields(node, ["service", "version", "metadata_sha256", "public_key", "seal_script"],
                                         .privateProtocolError)
            _ = try Self.text(fields[0], .privateProtocolError)
            _ = try Self.number(fields[1], .privateProtocolError)
            _ = try Self.text(fields[2], .privateProtocolError)
            _ = try Self.text(fields[3], .privateProtocolError)
            _ = try Self.text(fields[4], .privateProtocolError)
        }
        func checkSeal(_ node: NativeArchiveJSON) throws {
            let fields = try Self.fields(node, ["txid", "vout"], .privateProtocolError)
            _ = try Self.text(fields[0], .privateProtocolError)
            _ = try Self.number(fields[1], .privateProtocolError)
        }

        try checkRecord(context[0])
        _ = try number(context[1], .privateProtocolError)
        for index in [2, 3, 4, 5, 6, 7, 8, 9] { _ = try text(context[index], .privateProtocolError) }
        for index in [10, 11, 12, 13] { _ = try number(context[index], .privateProtocolError) }
        try checkSeal(context[14])
        _ = try strings(context[15], .privateProtocolError)
        _ = try strings(context[16], .privateProtocolError)
        _ = try number(context[17], .privateProtocolError)
        _ = try strings(context[18], .privateProtocolError)

        for index in [0, 1, 2, 3, 4] { _ = try text(authority[index], .privateProtocolError) }
        try checkRecord(authority[5])
        _ = try number(authority[6], .privateProtocolError)
        _ = try strings(authority[7], .privateProtocolError)
        for index in [8, 9, 10, 11] { _ = try text(authority[index], .privateProtocolError) }
        _ = try strings(authority[12], .privateProtocolError)
        for index in [13, 14, 15, 16] { _ = try number(authority[index], .privateProtocolError) }
        try checkSeal(authority[17])
        let approved = try fields(authority[18], ["profile", "contract_bytes_base64", "contract_sha256"],
                                  .privateProtocolError)
        for value in approved { _ = try text(value, .privateProtocolError) }
        _ = try text(authority[19], .privateProtocolError)

        for index in [0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 15] {
            _ = try text(record[index], .privateProtocolError)
        }
        _ = try number(record[3], .privateProtocolError)
        _ = try base64(text(record[14], .privateProtocolError), maximum: Self.maximumBytes,
                       status: .privateProtocolError, allowEmpty: true)
        let pair = try fields(record[13], [
            "schema", "service", "version", "group_id", "metadata_sha256", "nostr_identity", "nostr_version",
            "nostr_public_key", "nostr_npub", "namecoin_identity", "namecoin_version", "namecoin_xpub", "namecoin_origin",
        ], .privateProtocolError)
        for index in [0, 1, 3, 4, 5, 7, 8, 9, 11, 12] { _ = try text(pair[index], .privateProtocolError) }
        for index in [2, 6, 10] { _ = try number(pair[index], .privateProtocolError) }
    }

    private static func canonical(_ node: NativeArchiveJSON, status: RootGrantsStatus) throws -> Data {
        do { return try node.canonical() }
        catch { throw RootGrantsReviewError(status: status) }
    }

    private static func text(_ node: NativeArchiveJSON, _ status: RootGrantsStatus) throws -> String {
        guard case .string(let value) = node else { throw RootGrantsReviewError(status: status) }
        return value
    }

    private static func number(_ node: NativeArchiveJSON, _ status: RootGrantsStatus) throws -> UInt64 {
        guard case .number(let value) = node else { throw RootGrantsReviewError(status: status) }
        return value
    }

    private static func strings(_ node: NativeArchiveJSON, _ status: RootGrantsStatus) throws -> [String] {
        guard case .array(let values) = node else { throw RootGrantsReviewError(status: status) }
        return try values.map { try text($0, status) }
    }

    private static func octets(_ node: NativeArchiveJSON, maximum: Int, status: RootGrantsStatus) throws -> Data {
        guard case .array(let values) = node else { throw RootGrantsReviewError(status: status) }
        try trustCountersignRequire(values.count <= maximum, .limitExceeded)
        var result = Data(); result.reserveCapacity(values.count)
        for value in values {
            let number = try Self.number(value, status)
            try trustCountersignRequire(number <= 255, status)
            result.append(UInt8(number))
        }
        return result
    }

    private static func base64(_ value: String, maximum: Int, status: RootGrantsStatus, allowEmpty: Bool = false) throws -> Data {
        guard let bytes = Data(base64Encoded: value), bytes.count <= maximum,
              allowEmpty || !bytes.isEmpty, bytes.base64EncodedString() == value else {
            throw RootGrantsReviewError(status: status)
        }
        return bytes
    }

    private static func requireHashSpelling(_ hash: String) throws {
        try trustCountersignRequire(trustCountersignLowerHex(hash, bytes: 32), .privateProtocolError)
    }

    private static func checkedHash(_ hash: String, bytes: Data) throws -> String {
        try trustCountersignRequire(hash == trustCountersignHex(trustCountersignHash(bytes)), .bindingMismatch)
        return hash
    }

    private static func decodeHex(_ value: String, maximum: Int) throws -> Data {
        try trustCountersignRequire(value.utf8.count >= 2 && value.utf8.count <= maximum * 2 &&
                                    value.utf8.count.isMultiple(of: 2) &&
                                    value.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
                                    .retainedRecordMismatch)
        let bytes = Array(value.utf8)
        var result = Data(); result.reserveCapacity(bytes.count / 2)
        for index in stride(from: 0, to: bytes.count, by: 2) {
            func nibble(_ byte: UInt8) -> UInt8 { byte <= 57 ? byte - 48 : byte - 87 }
            result.append((nibble(bytes[index]) << 4) | nibble(bytes[index + 1]))
        }
        return result
    }

    private static func escapedBytes(_ bytes: Data) -> String {
        var result = ""
        for byte in bytes {
            if byte == 34 { result += "\\\"" }
            else if byte == 92 { result += "\\\\" }
            else if (32...126).contains(byte) { result.unicodeScalars.append(UnicodeScalar(byte)) }
            else { result += String(format: "\\x%02x", byte) }
        }
        return result
    }

    private static func validIDName(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard bytes.count >= 4, bytes.count <= 255,
              bytes[0...2].elementsEqual(Array("id/".utf8)) else { return false }
        return bytes.dropFirst(3).allSatisfy {
            (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95 || $0 == 46
        }
    }

    private static func validOwnerPrincipal(_ value: String) -> Bool {
        let prefix = "owner:id/"
        guard value.hasPrefix(prefix) else { return false }
        let label = Array(value.dropFirst(prefix.count).utf8)
        guard (1...63).contains(label.count), label.first != 45, label.last != 45 else { return false }
        for index in label.indices {
            let byte = label[index]
            guard (97...122).contains(byte) || (48...57).contains(byte) || byte == 45 else { return false }
            if byte == 45, index > label.startIndex, label[label.index(before: index)] == 45 { return false }
        }
        return true
    }

    private static func validNetworkGenesis(_ network: String, _ genesis: String) -> Bool {
        switch network {
        case "main": return genesis == "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770"
        case "regtest": return genesis == "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
        default: return false
        }
    }
}

struct RootGrantsTrustContractCountersignAttempt {
    enum Phase: Equatable { case created, reviewed, presencePending, presenceFresh, consumed, closed }
    private(set) var phase: Phase = .created

    mutating func confirmReview() throws {
        guard phase == .created else { phase = .closed; throw RootGrantsReviewError(status: .canceled) }
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

enum RootGrantsTrustContractCountersignReviewFlow {
    static func confirm(request: RootGrantsTrustContractCountersignRequest,
                        attempt: inout RootGrantsTrustContractCountersignAttempt,
                        using confirm: (String) throws -> Void) throws {
        guard attempt.phase == .created else {
            attempt.close()
            throw RootGrantsReviewError(status: .canceled)
        }
        do {
            try confirm(request.display)
            try confirm(request.display)
            try attempt.confirmReview()
        } catch {
            attempt.close()
            throw error
        }
    }
}

private final class RootGrantsTrustContractCountersignContext {
    private static let handleBit: UInt64 = 1 << 62
    private let cancellation: RootGrantsPrivateCancellation
    let handle: UInt64
    private var closed = false

    init(cancellation: RootGrantsPrivateCancellation) throws {
        self.cancellation = cancellation
        let budget = try RootGrantsPrivateDeadline.boundedGrantSigningBudget(remaining: cancellation.remainingNanoseconds())
        var opened: UInt64 = 0
        let code = kv_rg_sign_trust_contract_countersign_context_open_v1(budget, &opened)
        try RootGrantsArchiveBindings.signingStatus(code)
        guard opened & Self.handleBit != 0, opened & RootGrantsArchiveBindings.handleBit == 0,
              opened & ~(Self.handleBit | RootGrantsArchiveBindings.handleBit) != 0 else {
            throw RootGrantsReviewError(status: .privateProtocolError)
        }
        handle = opened
        do {
            try cancellation.setSigningCancellation { _ = kv_rg_sign_trust_contract_countersign_context_cancel_v1(opened) }
        } catch {
            _ = kv_rg_sign_trust_contract_countersign_context_close_v1(opened)
            throw error
        }
    }

    func remainingNanoseconds() throws -> UInt64 {
        try cancellation.remainingNanoseconds()
    }

    func policyCheck(request: Data) throws {
        var owned = Array(request)
        let count = owned.count
        let code = owned.withUnsafeMutableBufferPointer { buffer in
            kv_rg_sign_trust_contract_countersign_policy_check_v1(handle, buffer.baseAddress, size_t(count))
        }
        try RootGrantsArchiveBindings.signingStatus(code)
    }

    func sign(request: Data, plaintext: inout Data) throws -> Data {
        var requestBytes = Array(request)
        let requestCount = requestBytes.count
        let plaintextCount = plaintext.count
        var signature = Data(repeating: 0, count: 64)
        defer { signature.resetBytes(in: 0..<signature.count) }
        var written: size_t = 0
        let signatureCapacity = signature.count
        let code = requestBytes.withUnsafeMutableBufferPointer { requestBuffer in
            plaintext.withUnsafeMutableBytes { privateBytes in
                signature.withUnsafeMutableBytes { output in
                    kv_rg_sign_trust_contract_countersign_v1(
                        handle,
                        requestBuffer.baseAddress, size_t(requestCount),
                        privateBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), size_t(plaintextCount),
                        output.baseAddress?.assumingMemoryBound(to: UInt8.self), size_t(signatureCapacity), &written)
                }
            }
        }
        try RootGrantsArchiveBindings.signingStatus(code)
        try trustCountersignRequire(written == 64, .privateProtocolError)
        return Data(signature)
    }

    func closeAfterSigning() throws {
        guard !closed else { return }
        closed = true
        try? cancellation.setSigningCancellation(nil)
        let code = kv_rg_sign_trust_contract_countersign_context_close_v1(handle)
        guard code == 0 else { throw RootGrantsReviewError(status: .privateProtocolError) }
    }

    func closeIgnoringFailure() {
        guard !closed else { return }
        closed = true
        try? cancellation.setSigningCancellation(nil)
        _ = kv_rg_sign_trust_contract_countersign_context_close_v1(handle)
    }

    deinit { closeIgnoringFailure() }
}

private func trustCountersignEvaluateTouchID(_ context: LAContext, cancellation: RootGrantsPrivateCancellation,
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

private func trustCountersignDecrypt(_ request: RootGrantsTrustContractCountersignRequest,
                                     context: LAContext) throws -> Data {
    let key: SecureEnclave.P256.KeyAgreement.PrivateKey
    do { key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: request.envelope.blob, authenticationContext: context) }
    catch { throw RootGrantsReviewError(status: .wrappingPolicyRefused) }
    try trustCountersignRequire(key.publicKey.x963Representation == request.envelope.point, .invalidEnvelope)
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
    let cipher = request.envelope.ciphertext
    var plain: Data
    do { plain = try rootGrantsCountersignOpenCiphertext(cipher, material: material) }
    catch { throw RootGrantsReviewError(status: .invalidEnvelope) }
    do {
        try trustCountersignRequire(plain.count == 68 && plain.prefix(4) == Data("KVG1".utf8), .invalidEnvelope)
        let binding = trustCountersignHash(Data("keyvault-root-grants/plaintext/1\0".utf8) + request.record)
        try trustCountersignRequire(plain.subdata(in: 4..<36) == binding, .bindingMismatch)
        return plain
    } catch {
        plain.resetBytes(in: 0..<plain.count)
        throw error
    }
}

func rootGrantsTrustContractCountersignExecute(
    request: RootGrantsTrustContractCountersignRequest,
    now: () -> UInt64,
    checkCancellation: () throws -> Void,
    checkOutput: () throws -> Void,
    confirm: (String) throws -> Void,
    touchID: () throws -> Bool,
    recheck: (UInt8) throws -> Void,
    policyCheck: () throws -> Void,
    decrypt: () throws -> Data,
    sign: (inout Data) throws -> Data,
    afterReview: () throws -> Void = {},
    beforePresence: () throws -> Void = {},
    acceptPresence: (Bool) throws -> Void = { accepted in
        try trustCountersignRequire(accepted, .wrappingPolicyRefused)
    },
    beforeDecrypt: () throws -> Void = {}
) throws -> Data {
    func checkWindow() throws {
        try checkCancellation()
        try checkOutput()
        try request.checkSigningWindow(now: now())
    }

    try checkWindow()
    try confirm(request.display)
    try checkWindow()
    try confirm(request.display)
    try checkWindow()
    try afterReview()
    try beforePresence()

    let accepted = try touchID()
    try acceptPresence(accepted)
    try checkWindow()

    try recheck(1)
    try checkWindow()
    try policyCheck()
    try checkCancellation()
    try checkOutput()
    try beforeDecrypt()

    var plaintext = try decrypt()
    defer { plaintext.resetBytes(in: 0..<plaintext.count) }
    try checkWindow()

    try recheck(2)
    try checkWindow()
    return try sign(&plaintext)
}

private func trustCountersignPerform(_ original: Data, cancellation: RootGrantsPrivateCancellation,
                                    transport: RootGrantsPrivateTransport) throws -> Data {
    let request = try RootGrantsTrustContractCountersignRequest(ownedBytes: original)
    let now = UInt64(Date().timeIntervalSince1970)
    if let refusal = request.signingWindowRefusal(now: now) { throw RootGrantsReviewError(status: refusal) }
    let signingContext = try RootGrantsTrustContractCountersignContext(cancellation: cancellation)
    var attempt = RootGrantsTrustContractCountersignAttempt()
    defer { attempt.close() }
    var authentication: LAContext?
    defer { authentication?.invalidate(); try? cancellation.setAuthenticationContext(nil) }
    do {
        let signature = try rootGrantsTrustContractCountersignExecute(
            request: request,
            now: { UInt64(Date().timeIntervalSince1970) },
            checkCancellation: { try cancellation.check() },
            checkOutput: { try transport.checkOutput() },
            confirm: { text in
                try RootGrantsTerminalReview.confirm(text: text, cancellation: cancellation, transport: transport)
            },
            touchID: {
                let context = LAContext()
                context.localizedFallbackTitle = ""
                context.touchIDAuthenticationAllowableReuseDuration = 0
                do { try NativeNamecoinBiometryPolicy.requireTouchID(on: context) }
                catch { throw RootGrantsReviewError(status: .wrappingPolicyRefused) }
                try cancellation.setAuthenticationContext(context)
                authentication = context
                try cancellation.check()
                let reason = RootGrantsTrustContractCountersignRequest.localizedReason(ownerPrincipal: request.ownerPrincipal)
                return try trustCountersignEvaluateTouchID(context, cancellation: cancellation,
                                                           transport: transport, reason: reason)
            },
            recheck: { stage in
                try transport.recheck(stage: stage, remainingNanoseconds: signingContext.remainingNanoseconds())
            },
            policyCheck: { try signingContext.policyCheck(request: request.bytes) },
            decrypt: {
                guard let authentication else { throw RootGrantsReviewError(status: .operationUnavailable) }
                return try trustCountersignDecrypt(request, context: authentication)
            },
            sign: { plaintext in
                return try signingContext.sign(request: request.bytes, plaintext: &plaintext)
            },
            afterReview: { try attempt.confirmReview() },
            beforePresence: { try attempt.beginPresence() },
            acceptPresence: { try attempt.acceptFreshTouchID($0) },
            beforeDecrypt: { try attempt.consumeForSigning() })
        try cancellation.check()
        try transport.checkOutput()
        try signingContext.closeAfterSigning()
        return signature
    } catch {
        signingContext.closeIgnoringFailure()
        throw error
    }
}

func rootGrantsSignTrustContractCountersignV1() -> Int32 {
    let deadline = RootGrantsPrivateDeadline(startedAt: DispatchTime.now().uptimeNanoseconds, budget: 120_000_000_000)
    let cancellation = RootGrantsPrivateCancellation(deadline: deadline)
    let queue = DispatchQueue(label: "keyvault.root-grant-trust-countersign-cancellation")
    signal(SIGPIPE, SIG_IGN)
    let signals = RootGrantsSignV3SignalSetup.install(cancellation: cancellation, queue: queue)
    defer { signals.stop() }
    let timeout = DispatchSource.makeTimerSource(queue: queue)
    timeout.schedule(deadline: DispatchTime(uptimeNanoseconds: deadline.expiresAt))
    timeout.setEventHandler { cancellation.cancel(.timeout) }
    timeout.resume()
    defer { timeout.cancel() }
    let parent = getppid()
    guard parent > 1 else { return 1 }
    let parentExit = DispatchSource.makeProcessSource(identifier: parent, eventMask: .exit, queue: queue)
    parentExit.setEventHandler { cancellation.cancel(.privateProtocolError) }
    parentExit.resume()
    defer { parentExit.cancel(); _ = cancellation.finish() }
    guard getppid() == parent else { return 1 }
    let transport: RootGrantsPrivateTransport
    do { transport = try RootGrantsPrivateTransport(cancellation) }
    catch { return 1 }
    var request: Data?
    var payload: RootGrantsPrivateFrame.Payload
    do {
        request = try transport.request(overLimit: .limitExceeded)
        guard let request else { throw RootGrantsReviewError(status: .privateProtocolError) }
        let signature = try autoreleasepool {
            try trustCountersignPerform(request, cancellation: cancellation, transport: transport)
        }
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
