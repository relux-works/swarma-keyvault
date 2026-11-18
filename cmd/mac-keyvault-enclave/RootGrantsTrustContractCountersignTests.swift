import CryptoKit
import Foundation
import Testing
@testable import KeyvaultNativeCore

struct RootGrantsTrustContractCountersignTests {
    private static let granteeKey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

    private enum ExpiryStage: CaseIterable, Equatable {
        case firstConfirmation, secondConfirmation, touchID, firstRecheck, decrypt, secondRecheck
    }

    private struct SharedVectorFile: Decodable {
        let schema: String
        let vectors: [SharedVector]
    }

    private struct SharedVector: Decodable {
        let id: String
        let input: SharedVectorInput
        let expected: String
    }

    private struct SharedVectorInput: Decodable {
        let kind: String
        let bytes: String?
        let fixture: String?
        let mutations: [SharedVectorMutation]?
    }

    private struct SharedVectorMutation: Decodable {
        let op: String
        let path: [String]
        let member: String?
        let value: String?

        enum CodingKeys: String, CodingKey {
            case op, path, member, value
            case sourcePath = "source_path"
        }

        let sourcePath: [String]?
    }

    private struct CarrierVectorFile: Decodable {
        let schema: String
        let vectors: [CarrierVector]
    }

    private struct CarrierVector: Decodable {
        let id: String
        let expectedStatus: Int32
        let requestBase64: String
        let requestBytes: Int
        let requestSHA256: String

        enum CodingKeys: String, CodingKey {
            case id
            case expectedStatus = "expected_status"
            case requestBase64 = "request_base64"
            case requestBytes = "request_bytes"
            case requestSHA256 = "request_sha256"
        }
    }

    private struct C27ControlFile: Decodable {
        let schema: String
        let contractSHA256: String
        let baseRequestSHA256: String
        let baseRequestBytes: Int
        let requests: [C27Request]
        let contracts: [C27Contract]

        enum CodingKeys: String, CodingKey {
            case schema, requests, contracts
            case contractSHA256 = "contract_sha256"
            case baseRequestSHA256 = "base_request_sha256"
            case baseRequestBytes = "base_request_bytes"
        }
    }

    private struct C27Request: Decodable {
        let id: String
        let claim: String
        let expectedStatus: Int32
        let requestBase64: String
        let requestBytes: Int
        let requestSHA256: String
        let source: String?
        let sourceSHA256: String?

        enum CodingKeys: String, CodingKey {
            case id, claim, source
            case expectedStatus = "expected_status"
            case requestBase64 = "request_base64"
            case requestBytes = "request_bytes"
            case requestSHA256 = "request_sha256"
            case sourceSHA256 = "source_sha256"
        }
    }

    private struct C27Contract: Decodable {
        let id: String
        let claim: String
        let expected: String
        let expectedRule: Int
        let bytesBase64: String
        let bytes: Int
        let sha256: String

        enum CodingKeys: String, CodingKey {
            case id, claim, expected, bytes, sha256
            case expectedRule = "expected_rule"
            case bytesBase64 = "bytes_base64"
        }
    }

    @Test func everySharedCrossLanguageVectorReturnsItsExpectedCode() throws {
        let url = try #require(Bundle.module.url(forResource: "RootGrantsTrustContractVectors-19",
                                                 withExtension: "json"))
        let vectors = try JSONDecoder().decode(SharedVectorFile.self, from: Data(contentsOf: url))
        #expect(vectors.schema == "keyvault-root-grants-trust-conformance-vectors/1")
        #expect(vectors.vectors.count == 30)

        for vector in vectors.vectors {
            let observed: String
            switch vector.input.kind {
            case "contract":
                let bytes = try #require(vector.input.bytes, "missing contract input for \(vector.id)")
                observed = Self.contractFailure(Data(bytes.utf8))?.code.rawValue ?? "ACCEPT"
            case "countersign_request":
                let fixture = try #require(vector.input.fixture, "missing request fixture for \(vector.id)")
                #expect(fixture == "root-grants-sign-request-v2", "unknown request fixture for \(vector.id)")
                var node = try NativeArchiveJSON.decode(try Self.requestBytes(), maximum: 262_144, canonical: true)
                for mutation in vector.input.mutations ?? [] {
                    node = try Self.apply(mutation, to: node)
                }
                observed = Self.status(try node.canonical())?.code ?? "unexpected_error"
            default:
                Issue.record("unknown vector input kind \(vector.input.kind) for \(vector.id)")
                continue
            }
            #expect(observed == vector.expected, "\(vector.id): got \(observed), want \(vector.expected)")
        }
    }

    @Test func transferredCarrierBytesMatchNativeProductionParserStatuses() throws {
        let url = try #require(Bundle.module.url(forResource: "SHARED-CARRIER-VECTORS-22",
                                                 withExtension: "json"))
        let source = try Data(contentsOf: url)
        #expect(Self.sha256(source) == "cb85e9c1520634808a29c8b7c8f3eda0825eef861a3174275f5f9f7d9b4f2758")
        let file = try JSONDecoder().decode(CarrierVectorFile.self, from: source)
        #expect(file.schema == "keyvault-root-grants-carrier-byte-vectors/1")
        #expect(file.vectors.count == 13)

        var rows: [String] = []
        for vector in file.vectors {
            let bytes = try #require(Data(base64Encoded: vector.requestBase64), "bad request base64 for \(vector.id)")
            #expect(bytes.base64EncodedString() == vector.requestBase64, "noncanonical request base64 for \(vector.id)")
            #expect(bytes.count == vector.requestBytes, "byte count changed for \(vector.id)")
            #expect(Self.sha256(bytes) == vector.requestSHA256, "request bytes changed for \(vector.id)")

            let observed: Int32
            do {
                _ = try RootGrantsTrustContractCountersignRequest(ownedBytes: bytes)
                observed = RootGrantsStatus.success.rawValue
            } catch let failure as RootGrantsReviewError {
                observed = failure.status.rawValue
            } catch {
                Issue.record("unexpected parser error for \(vector.id): \(error)")
                observed = -1
            }
            let result = observed == vector.expectedStatus ? "PASS" : "FAIL"
            rows.append("\(vector.id): expected=\(vector.expectedStatus) observed=\(observed) \(result)")
            #expect(observed == vector.expectedStatus, "\(vector.id): got status \(observed), want \(vector.expectedStatus)")
        }
        print(rows.joined(separator: "\n"))
    }

    // Claim: both implementations consume the shared exact request bytes for all row-1 through row-7 C27 cases, including the four source-pinned requests, the paired 16/17 mixed fault, and approved-Base64/LIP precedence. This does not exercise signing or Keychain.
    @Test func contract27ExactRequestsMatchNativeParserStatuses() throws {
        let url = try #require(Bundle.module.url(forResource: "CONTRACT-27-CONTROLS", withExtension: "json"))
        let source = try Data(contentsOf: url)
        #expect(Self.sha256(source) == "34491b440d32838f8a25c30cf64513e5871a6aec7edf39c5fe07b433bb0c2870")
        let file = try JSONDecoder().decode(C27ControlFile.self, from: source)
        #expect(file.schema == "keyvault-root-grants-contract-27-controls/1")
        #expect(file.contractSHA256 == "d3efe6fad933ee7077c3209b13e3a166ae243fa2cba6a33213be17c1306e7086")
        #expect(file.baseRequestSHA256 == "b68391d1790c4f019b73b6339e88d42c09d2f53a77694f08e366663a2da5baea")
        #expect(file.baseRequestBytes == 8465)
        #expect(file.requests.count == 64)

        var seen = Set<String>()
        for vector in file.requests {
            #expect(!vector.id.isEmpty && !vector.claim.isEmpty, "missing C27 request id/claim")
            #expect(seen.insert(vector.id).inserted, "duplicate C27 request id \(vector.id)")
            let bytes = try #require(Data(base64Encoded: vector.requestBase64), "bad Base64 for \(vector.id)")
            #expect(bytes.base64EncodedString() == vector.requestBase64, "noncanonical request Base64 for \(vector.id)")
            #expect(bytes.count == vector.requestBytes, "request byte count changed for \(vector.id)")
            #expect(Self.sha256(bytes) == vector.requestSHA256, "request digest changed for \(vector.id)")
            if let source = vector.source {
                #expect(vector.sourceSHA256 == vector.requestSHA256, "source witness hash changed for \(source)")
            }
            let observed = Self.status(bytes)?.rawValue ?? -1
            #expect(observed == vector.expectedStatus,
                    "\(vector.id): got \(observed), want \(vector.expectedStatus); claim: \(vector.claim)")
        }
    }

    // Claim: the exact depth-65 trust/2 source witness is owned by delegate rule 9 / CONTRACT_DELEGATE and coarsens to status 13, while its valid-depth neighbor parses successfully. This tests the local LIP parser, not signing.
    @Test func contract27DepthWitnessAndValidNeighbor() throws {
        let url = try #require(Bundle.module.url(forResource: "CONTRACT-27-CONTROLS", withExtension: "json"))
        let file = try JSONDecoder().decode(C27ControlFile.self, from: Data(contentsOf: url))
        #expect(file.contracts.count == 2)
        for vector in file.contracts {
            #expect(!vector.id.isEmpty && !vector.claim.isEmpty, "missing C27 contract id/claim")
            let bytes = try #require(Data(base64Encoded: vector.bytesBase64), "bad contract Base64 for \(vector.id)")
            #expect(bytes.base64EncodedString() == vector.bytesBase64)
            #expect(bytes.count == vector.bytes)
            #expect(Self.sha256(bytes) == vector.sha256)
            let failure = Self.contractFailure(bytes)
            if vector.expected == "ACCEPT" {
                #expect(failure == nil, "\(vector.id): expected acceptance; claim: \(vector.claim)")
                #expect(vector.expectedRule == 0)
            } else {
                #expect(failure?.code.rawValue == vector.expected,
                        "\(vector.id): got \(String(describing: failure?.code.rawValue)), want \(vector.expected)")
                #expect(vector.expectedRule == 9)
                #expect(failure?.nativeStatus == .bindingMismatch,
                        "\(vector.id): local delegate error did not coarsen to native status 13")
            }
        }
    }

    private static func apply(_ mutation: SharedVectorMutation, to node: NativeArchiveJSON) throws -> NativeArchiveJSON {
        switch mutation.op {
        case "remove_member":
            let member = try #require(mutation.member)
            return try replacing(node, at: mutation.path) { target in
                guard case .object(let pairs) = target else { throw RootGrantsReviewError(status: .privateProtocolError) }
                let filtered = pairs.filter { $0.0 != member }
                guard filtered.count + 1 == pairs.count else { throw RootGrantsReviewError(status: .privateProtocolError) }
                return .object(filtered)
            }
        case "replace_string":
            let value = try #require(mutation.value)
            return try replacing(node, at: mutation.path) { target in
                guard case .string = target else { throw RootGrantsReviewError(status: .privateProtocolError) }
                return .string(value)
            }
        case "recompute_sha256":
            let sourcePath = try #require(mutation.sourcePath)
            let source = try Self.value(at: sourcePath, in: node)
            let digest = Self.sha256(try source.canonical())
            return try replacing(node, at: mutation.path) { target in
                guard case .string = target else { throw RootGrantsReviewError(status: .privateProtocolError) }
                return .string(digest)
            }
        default:
            throw RootGrantsReviewError(status: .privateProtocolError)
        }
    }

    private static func value(at path: [String], in node: NativeArchiveJSON) throws -> NativeArchiveJSON {
        guard let head = path.first else { return node }
        return try value(at: Array(path.dropFirst()), in: node.field(head))
    }

    private static func replacing(_ node: NativeArchiveJSON, at path: [String],
                                  with update: (NativeArchiveJSON) throws -> NativeArchiveJSON) throws -> NativeArchiveJSON {
        guard let head = path.first else { return try update(node) }
        guard case .object(let pairs) = node else { throw RootGrantsReviewError(status: .privateProtocolError) }
        var found = false
        var result: [(String, NativeArchiveJSON)] = []
        result.reserveCapacity(pairs.count)
        for (name, value) in pairs {
            if name == head {
                guard !found else { throw RootGrantsReviewError(status: .privateProtocolError) }
                found = true
                result.append((name, try replacing(value, at: Array(path.dropFirst()), with: update)))
            } else {
                result.append((name, value))
            }
        }
        guard found else { throw RootGrantsReviewError(status: .privateProtocolError) }
        return .object(result)
    }

    // Claim: a complete canonical carrier validates its byte/hash pairs and displays the exact ordered review object, full bindings, and byte-exact scope; an altered scope byte coarsens to status 13.
    @Test func validCarrierDisplaysAndBindsOriginalScopeBytes() throws {
        let scope = Data([65, 10, 255, 34, 92])
        let request = try Self.request(contractScope: scope, reviewScope: scope)
        #expect(request.contract.profile == "swarma-trust-contract/2")
        #expect(request.context.ownerPrincipal == "owner:id/example-owner")
        #expect(request.context.rootGeneration == request.context.recordVersion)
        #expect(request.signingWindowRefusal(now: 1_800_000_000) == nil) // Countersigning before not_before is allowed; readers enforce the window at use.
        #expect(RootGrantsTrustContractCountersignRequest.nonLIPBoundsStatus(
            contextBytes: request.issuanceContext.count, authorityBytes: request.authority.count,
            recordBytes: request.record.count, reviewBytes: request.reviewBytes.count,
            requestBytes: request.bytes.count) == nil,
            "valid fixture lengths: context=\(request.issuanceContext.count), authority=\(request.authority.count), record=\(request.record.count), review=\(request.reviewBytes.count), request=\(request.bytes.count)")
        #expect(request.display.contains(String(decoding: request.reviewBytes, as: UTF8.self)))
        #expect(request.display.contains("A\\x0a\\xff\\\"\\\\"))
        #expect(request.display.contains("Full issuer key: \(request.issuerKey)"))
        #expect(request.display.contains("NOT_ISSUABLE"))
        #expect(request.display.contains("empty means no v3 actions"))

        let changed = try Self.requestBytes(contractScope: scope, reviewScope: Data([65, 10, 254, 34, 92]))
        #expect(Self.status(changed) == .bindingMismatch)
    }

    @Test func expiryDuringEveryWaitRefusesBeforeSigning() throws {
        let cases: [(String, UInt64, RootGrantsTrustContractCountersignRequest)] = [
            ("contract end", 1_900_000_101, try Self.request()),
            ("shared authority and contract end", 2_000_000_001,
             try Self.request(contractNotAfter: 2_000_000_000, authorityNotAfter: 2_000_000_000)),
            ("authority not-before", 1_799_999_999,
             try Self.request(authorityNotBefore: 1_800_000_000)),
        ]
        for (boundary, expiredNow, request) in cases {
            for stage in ExpiryStage.allCases {
                var now: UInt64 = 1_800_000_000
                var confirmations = 0
                var presenceCalls = 0
                var signCalls = 0
                func expireIf(_ observed: ExpiryStage) {
                    if observed == stage { now = expiredNow }
                }

                var status: RootGrantsStatus?
                do {
                    _ = try rootGrantsTrustContractCountersignExecute(
                        request: request, now: { now }, checkCancellation: {}, checkOutput: {},
                        confirm: { _ in
                            confirmations += 1
                            expireIf(confirmations == 1 ? .firstConfirmation : .secondConfirmation)
                        },
                        touchID: {
                            presenceCalls += 1
                            expireIf(.touchID)
                            return true
                        },
                        recheck: { stageNumber in
                            expireIf(stageNumber == 1 ? .firstRecheck : .secondRecheck)
                        },
                        policyCheck: {},
                        decrypt: {
                            expireIf(.decrypt)
                            return Data("KVG1".utf8) + Data(repeating: 0, count: 64)
                        },
                        sign: { _ in signCalls += 1; return Data(repeating: 7, count: 64) })
                } catch let failure as RootGrantsReviewError {
                    status = failure.status
                } catch {
                    Issue.record("unexpected error for \(boundary) at \(stage): \(error)")
                }
                #expect(status == .bindingMismatch, "\(boundary) expired at \(stage), got \(String(describing: status))")
                #expect(signCalls == 0, "\(boundary) expired at \(stage), but signer ran")
            }
        }
    }

    @Test func signingWindowPositiveAndF6PreNotBeforeStillSign() throws {
        let cases: [(UInt64, RootGrantsTrustContractCountersignRequest)] = [
            (1_800_000_000, try Self.request()),
            (1_900_000_100, try Self.request()),
            (2_000_000_000, try Self.request(contractNotAfter: 2_000_000_000,
                                              authorityNotAfter: 2_000_000_000)),
            (1_800_000_000, try Self.request(authorityNotBefore: 1_800_000_000)),
        ]
        for (now, request) in cases {
            #expect(now < request.contract.notBefore || now == request.contract.notAfter)
            var signCalls = 0
            let signature = try rootGrantsTrustContractCountersignExecute(
                request: request, now: { now }, checkCancellation: {}, checkOutput: {},
                confirm: { _ in }, touchID: { true }, recheck: { _ in }, policyCheck: {},
                decrypt: { Data("KVG1".utf8) + Data(repeating: 0, count: 64) },
                sign: { _ in signCalls += 1; return Data(repeating: 9, count: 64) })
            #expect(signature.count == 64)
            #expect(signCalls == 1)
        }
    }

    @Test func eitherConfirmationRefusalStopsBeforePresenceAndSigning() throws {
        for refusalAt in [1, 2] {
            let request = try Self.request()
            var confirmations = 0
            var presenceCalls = 0
            var signCalls = 0
            var status: RootGrantsStatus?
            do {
                _ = try rootGrantsTrustContractCountersignExecute(
                    request: request, now: { 1_800_000_000 }, checkCancellation: {}, checkOutput: {},
                    confirm: { _ in
                        confirmations += 1
                        if confirmations == refusalAt { throw RootGrantsReviewError(status: .canceled) }
                    },
                    touchID: { presenceCalls += 1; return true }, recheck: { _ in }, policyCheck: {},
                    decrypt: { Data("KVG1".utf8) + Data(repeating: 0, count: 64) },
                    sign: { _ in signCalls += 1; return Data(repeating: 1, count: 64) })
            } catch let failure as RootGrantsReviewError {
                status = failure.status
            } catch {
                Issue.record("unexpected confirmation refusal error: \(error)")
            }
            #expect(status == .canceled)
            #expect(presenceCalls == 0, "confirmation \(refusalAt) refusal reached presence")
            #expect(signCalls == 0, "confirmation \(refusalAt) refusal reached signing")
        }
    }

    @Test func cancellationAndOutputRefusalsPrecedeExpiredWindowRefusal() throws {
        let request = try Self.request()
        for expected in [RootGrantsStatus.canceled, .timeout] {
            var now: UInt64 = 1_800_000_000
            var checks = 0
            var signCalls = 0
            var observed: RootGrantsStatus?
            do {
                _ = try rootGrantsTrustContractCountersignExecute(
                    request: request, now: { now },
                    checkCancellation: {
                        checks += 1
                        if expected == .canceled && checks == 2 {
                            throw RootGrantsReviewError(status: .canceled)
                        }
                    },
                    checkOutput: {
                        if expected == .timeout && checks == 2 {
                            throw RootGrantsReviewError(status: .timeout)
                        }
                    },
                    confirm: { _ in now = 1_900_000_101 }, touchID: { true }, recheck: { _ in },
                    policyCheck: {}, decrypt: { Data("KVG1".utf8) + Data(repeating: 0, count: 64) },
                    sign: { _ in signCalls += 1; return Data(repeating: 2, count: 64) })
            } catch let failure as RootGrantsReviewError {
                observed = failure.status
            } catch {
                Issue.record("unexpected precedence error: \(error)")
            }
            #expect(observed == expected)
            #expect(signCalls == 0)
        }
    }

    // Claim: each canonical nested length through 32768 passes the size gate and reaches a later status-13 refusal in this synthetic fixture; 32769 returns 17.
    @Test func nestedObjectBoundsAreInclusiveAndPrecedeLIP() throws {
        let cases: [(String, String, Int)] = [
            ("issuance_context", "landlord_name", 0),
            ("authority", "landlord_name", 1),
            ("record", "service", 2),
        ]
        for (objectName, fieldName, occurrence) in cases {
            for size in [32_767, 32_768, 32_769] {
                let bytes = try Self.requestBytesWithNestedObjectSize(objectName, fieldName: fieldName,
                                                                      occurrence: occurrence, targetBytes: size)
                let decoded = try NativeArchiveJSON.decode(bytes, maximum: 262_144, canonical: true,
                                                           maximumArrayMembers: 262_144)
                let review = try decoded.field("review")
                let nested = try review.field(objectName)
                #expect(try nested.canonical().count == size)
                let expected: RootGrantsStatus = size <= 32_768 ? .bindingMismatch : .limitExceeded
                #expect(Self.status(bytes) == expected, "\(objectName)=\(size) returned \(String(describing: Self.status(bytes)))")
            }
        }
    }

    // Claim: nonLIPBoundsStatus accepts inclusive review/request sizes and independently rejects each supplied overflow length.
    @Test func nonLIPBoundCalculationIsInclusivePerAxis() {
        for size in [262_143, 262_144] {
            #expect(RootGrantsTrustContractCountersignRequest.nonLIPBoundsStatus(
                contextBytes: 0, authorityBytes: 0, recordBytes: 0, reviewBytes: size,
                requestBytes: 262_144) == nil)
            #expect(RootGrantsTrustContractCountersignRequest.nonLIPBoundsStatus(
                contextBytes: 0, authorityBytes: 0, recordBytes: 0, reviewBytes: 1,
                requestBytes: size) == nil)
        }
        #expect(RootGrantsTrustContractCountersignRequest.nonLIPBoundsStatus(
            contextBytes: 0, authorityBytes: 0, recordBytes: 0, reviewBytes: 262_145,
            requestBytes: 262_144) == .limitExceeded)
        #expect(RootGrantsTrustContractCountersignRequest.nonLIPBoundsStatus(
            contextBytes: 0, authorityBytes: 0, recordBytes: 0, reviewBytes: 1,
            requestBytes: 262_145) == .limitExceeded)
        #expect(RootGrantsTrustContractCountersignRequest.nonLIPBoundsStatus(
            contextBytes: 32_768, authorityBytes: 32_768, recordBytes: 32_768,
            reviewBytes: 262_144, requestBytes: 262_145) == .limitExceeded)
    }

    // Claim: review byte counts are integer lengths of their Base64 byte values; malformed types map to 16 and mismatched counts to 13.
    @Test func reviewByteCountsAreIntegersAndMatchDecodedBytes() throws {
        let valid = try Self.requestBytes()
        #expect(Self.status(valid) == .success)
        let source = try #require(String(data: valid, encoding: .utf8))

        let contractCount = Self.contract().count
        let wrongContractCount = source.replacingOccurrences(
            of: "\"contract_bytes\":\(contractCount)",
            with: "\"contract_bytes\":\(contractCount + 1)")
        #expect(wrongContractCount != source)
        #expect(Self.status(Data(wrongContractCount.utf8)) == .bindingMismatch)

        let wrongScopeCount = source.replacingOccurrences(of: "\"scope_text_bytes\":0", with: "\"scope_text_bytes\":1")
        #expect(wrongScopeCount != source)
        #expect(Self.status(Data(wrongScopeCount.utf8)) == .bindingMismatch)

        let wrongContractType = source.replacingOccurrences(
            of: "\"contract_bytes\":\(contractCount)", with: "\"contract_bytes\":[]")
        #expect(wrongContractType != source)
        #expect(Self.status(Data(wrongContractType.utf8)) == .privateProtocolError)
    }

    // Claim: a valid request carrier is accepted, but canonical JSON with reordered outer members is private_protocol_error 16.
    @Test func malformedOuterCarrierRefusesBesideValidCarrier() throws {
        let bytes = try Self.requestBytes()
        _ = try RootGrantsTrustContractCountersignRequest(ownedBytes: bytes)
        let source = try #require(String(data: bytes, encoding: .utf8))
        let old = "{\"schema\":\"keyvault-root-grants-sign-request/2\",\"operation\":\"review-sign-trust-contract-countersign\",\"review\":"
        let new = "{\"operation\":\"review-sign-trust-contract-countersign\",\"schema\":\"keyvault-root-grants-sign-request/2\",\"review\":"
        let malformed = source.replacingOccurrences(of: old, with: new)
        #expect(malformed != source)
        #expect(Self.status(Data(malformed.utf8)) == .privateProtocolError)
    }

    // Claim: the closed helper and review literals preserve distinct version-18 and operation-19 refusals beside a valid request.
    @Test func wrongClosedLiteralsKeepTheirStatus() throws {
        let source = try #require(String(data: Self.requestBytes(), encoding: .utf8))
        let cases: [(String, RootGrantsStatus)] = [
            (source.replacingOccurrences(of: "keyvault-root-grants-sign-request/2", with: "keyvault-root-grants-sign-request/1"), .unsupportedVersion),
            (source.replacingOccurrences(of: "review-sign-trust-contract-countersign", with: "review-sign-grant-v3"), .unsupportedOperation),
            (source.replacingOccurrences(of: "namecoin-landlord-root/1", with: "namecoin-landlord-root/2"), .unsupportedVersion),
            (source.replacingOccurrences(of: "swarma-trust-contract/2", with: "swarma-trust-contract/1"), .unsupportedVersion),
        ]
        for (candidate, expected) in cases {
            #expect(Self.status(Data(candidate.utf8)) == expected)
        }
    }

    // Claim: a LIP rule-4 semantic fault keeps its parser classification internally and is coarsened to native status 13 before context or envelope use.
    @Test func malformedActionsCoarsenToBindingMismatch() throws {
        let bytes = try Self.requestBytes(actions: "[\"instruct\",\"unknown\"]")
        #expect(Self.status(bytes) == .bindingMismatch)
        let failure = try #require(Self.contractFailure(Self.contract(actions: "[\"instruct\",\"unknown\"]")))
        #expect(failure.code == .contractActions)
        #expect(failure.nativeStatus == .bindingMismatch)
    }

    // Claim: an 8193-byte inner contract maps to semantic status 13, while an over-limit outer carrier remains status 17.
    @Test func innerContractLimitKeepsNativeStatusDistinctFromCarrierLimit() throws {
        let empty = Self.contract(note: "")
        let overLimitNote = String(repeating: "x", count: 8192 - empty.count + 1)
        let overLimitContract = Self.contract(note: overLimitNote)
        #expect(overLimitContract.count == 8193)
        #expect(Self.contractFailure(overLimitContract)?.code == .contractEncoding)
        let overLimitRequest = try Self.requestBytes(note: overLimitNote)
        let innerStatus = Self.status(overLimitRequest)
        #expect(overLimitRequest.count < RootGrantsTrustContractCountersignRequest.maximumBytes)
        #expect(innerStatus == .bindingMismatch, "inner contract returned \(String(describing: innerStatus))")

        let overLimitCarrier = Data(repeating: 0, count: RootGrantsTrustContractCountersignRequest.maximumBytes + 1)
        #expect(Self.status(overLimitCarrier) == .limitExceeded)
    }

    // Claim: request bytes must match the contract's own scope-text hash; changing one byte refuses as status 13 without normalization.
    @Test func exactScopeTextMismatchCoarsensToBindingMismatch() throws {
        let contractScope = Data("scope\ntext".utf8)
        let wrongReviewScope = Data("scope\rtext".utf8)
        let bytes = try Self.requestBytes(contractScope: contractScope, reviewScope: wrongReviewScope)
        #expect(Self.status(bytes) == .bindingMismatch)
        #expect(RootGrantsTrustContractV2.validateScopeText(
            wrongReviewScope, reviewedHash: Self.sha256(contractScope), contractHash: Self.sha256(contractScope)
        )?.code == .scopeTextHashMismatch)
    }

    // Claim: successful review reaches one consumed attempt and rejects replay; native statuses 14–16 round-trip unchanged for parent UNKNOWN handling.
    @Test func oneShotReviewAndAmbiguousNativeStatusesArePreserved() throws {
        var attempt = RootGrantsTrustContractCountersignAttempt()
        var shown: [String] = []
        try RootGrantsTrustContractCountersignReviewFlow.confirm(request: Self.request(), attempt: &attempt) { shown.append($0) }
        #expect(shown.count == 2)
        #expect(shown[0] == shown[1])
        #expect(attempt.phase == .reviewed)
        try attempt.beginPresence()
        try attempt.acceptFreshTouchID(true)
        try attempt.consumeForSigning()
        #expect(attempt.phase == .consumed)
        #expect(throws: RootGrantsReviewError.self) { try attempt.beginPresence() }
        #expect(attempt.phase == .closed)

        for status in [RootGrantsStatus.canceled, .timeout, .privateProtocolError] {
            let frame = try RootGrantsPrivateFrame.response(.refusal(status))
            guard case .refusal(let observed) = try RootGrantsPrivateFrame.decodeResponse(frame) else {
                Issue.record("native refusal frame decoded as a non-refusal")
                continue
            }
            #expect(observed == status)
        }
        let oversized = Data(repeating: 0, count: RootGrantsTrustContractCountersignRequest.maximumBytes + 1)
        #expect(Self.status(oversized) == .limitExceeded)
    }

    // Claim: the purpose digest is SHA-256 of exact contract bytes and differs from the unchanged Grant v3 prefixed digest.
    @Test func purposeDigestDoesNotReuseGrantV3Domain() throws {
        let contract = Self.contract()
        let expected = Data(SHA256.hash(data: contract))
        #expect(RootGrantsTrustContractV2.countersignDigest(contract) == expected)
        #expect(RootGrantsTrustContractV2.countersignDigest(contract) !=
                Data(SHA256.hash(data: Data("swarma-grant-v3".utf8) + contract)))
        #expect(RootGrantsTrustContractCountersignRequest.localizedReason(ownerPrincipal: "owner:id/fixture-owner") ==
                "Touch ID confirms one root trust contract countersignature for owner:id/fixture-owner.")
    }

    private static func status(_ bytes: Data) -> RootGrantsStatus? {
        do { _ = try RootGrantsTrustContractCountersignRequest(ownedBytes: bytes); return .success }
        catch let refusal as RootGrantsReviewError { return refusal.status }
        catch { return nil }
    }

    private static func contractFailure(_ bytes: Data) -> RootGrantsTrustContractV2Failure? {
        do { _ = try RootGrantsTrustContractV2(ownedBytes: bytes); return nil }
        catch let failure as RootGrantsTrustContractV2Failure { return failure }
        catch { return nil }
    }

    private static func request(contractScope: Data = Data(), reviewScope: Data? = nil,
                                actions: String = "[\"instruct\",\"review\"]", note: String = "fixture",
                                contractNotBefore: UInt64 = 1_900_000_000,
                                contractNotAfter: UInt64 = 1_900_000_100,
                                authorityNotBefore: UInt64 = 1_599_999_980,
                                authorityNotAfter: UInt64 = 4_102_445_800) throws -> RootGrantsTrustContractCountersignRequest {
        try RootGrantsTrustContractCountersignRequest(ownedBytes: requestBytes(
            contractScope: contractScope, reviewScope: reviewScope, actions: actions, note: note,
            contractNotBefore: contractNotBefore, contractNotAfter: contractNotAfter,
            authorityNotBefore: authorityNotBefore, authorityNotAfter: authorityNotAfter))
    }

    private static func requestBytes(contractScope: Data = Data(), reviewScope: Data? = nil,
                                     actions: String = "[\"instruct\",\"review\"]",
                                     note: String = "fixture",
                                     contractNotBefore: UInt64 = 1_900_000_000,
                                     contractNotAfter: UInt64 = 1_900_000_100,
                                     authorityNotBefore: UInt64 = 1_599_999_980,
                                     authorityNotAfter: UInt64 = 4_102_445_800) throws -> Data {
        let fixtureURL = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("testdata/root-grants-sign-request-v2.json")
        let original = try Data(contentsOf: fixtureURL)
        let originalNode = try NativeArchiveJSON.decode(original, maximum: 262_144, canonical: true)
        let originalFields = try originalNode.fields(["schema", "operation", "review", "envelope", "pair_metadata"])
        let originalReview = originalFields[2]
        let authorityV1 = try originalReview.field("authority")
        let record = try originalReview.field("record")
        let envelope = originalFields[3]
        let pairMetadata = try originalFields[4].text()
        let service = try record.field("service").text()
        let recordVersion = try record.field("version").uint()
        let issuerKey = try record.field("public_key").text()
        let sealScript = try record.field("seal_script").text()
        let recordBytes = try record.canonical()
        let recordHash = sha256(recordBytes)
        let ownerPrincipal = try authorityV1.field("owner_principal").text()
        let landlordName = try authorityV1.field("landlord_name").text()
        let network = try authorityV1.field("network").text()
        let genesis = try authorityV1.field("genesis").text()
        let agentName = try authorityV1.field("agent_name").text()
        let agentKey = try authorityV1.field("agent_key").text()
        let seal = try authorityV1.field("seal")
        let notBefore = authorityNotBefore
        let notAfter = authorityNotAfter
        let maxGrantSeconds = authorityNotAfter - authorityNotBefore
        let granteeName = ""
        let scope = reviewScope ?? contractScope
        let contract = Self.contract(network: network, landlord: landlordName, agent: agentName,
                                     scopeHash: contractScope.isEmpty ? "" : sha256(contractScope),
                                     actions: actions, note: note, notBefore: contractNotBefore,
                                     notAfter: contractNotAfter)
        let contractHash = sha256(contract)
        let authorityRecord = Self.object([
            ("service", .string(service)), ("version", .number(recordVersion)),
            ("metadata_sha256", .string(recordHash)), ("public_key", .string(issuerKey)),
            ("seal_script", .string(sealScript)),
        ])
        let authority = Self.object([
            ("schema", .string("namecoin-root-grants-authority/2")),
            ("owner_principal", .string(ownerPrincipal)), ("landlord_name", .string(landlordName)),
            ("network", .string(network)), ("genesis", .string(genesis)), ("record", authorityRecord),
            ("root_generation", .number(recordVersion)),
            ("operations", .array([.string("review-sign-trust-contract-countersign"), .string("review-sign-grant-v3")])),
            ("agent_name", .string(agentName)), ("agent_key", .string(agentKey)),
            ("grantee_key", .string(granteeKey)), ("grantee_name", .string(granteeName)),
            ("scope", .array([])), ("not_before", .number(notBefore)), ("not_after", .number(notAfter)),
            ("max_grant_seconds", .number(maxGrantSeconds)), ("max_budget_sat", .number(0)), ("seal", seal),
            ("approved_contract", Self.object([
                ("profile", .string("swarma-trust-contract/2")),
                ("contract_bytes_base64", .string(contract.base64EncodedString())),
                ("contract_sha256", .string(contractHash)),
            ])),
            ("observation_policy", .string("offline-document-review/1")),
        ])
        let context = Self.object([
            ("root_record", authorityRecord), ("root_generation", .number(recordVersion)),
            ("landlord_name", .string(landlordName)), ("network", .string(network)), ("genesis", .string(genesis)),
            ("issuer_key", .string(issuerKey)), ("agent_name", .string(agentName)), ("agent_key", .string(agentKey)),
            ("grantee_key", .string(granteeKey)), ("grantee_name", .string(granteeName)),
            ("not_before", .number(notBefore)), ("not_after", .number(notAfter)),
            ("max_grant_seconds", .number(maxGrantSeconds)), ("max_budget_sat", .number(0)), ("seal", seal),
            ("actions", .array([.string("instruct"), .string("review")])), ("repos", .array([])),
            ("spend_budget", .number(0)), ("derived_v3_scope", .array([])),
        ])
        let review = Self.object([
            ("operation", .string("review-sign-trust-contract-countersign")),
            ("profile", .string("namecoin-landlord-root/1")),
            ("contract_profile", .string("swarma-trust-contract/2")),
            ("contract_bytes_base64", .string(contract.base64EncodedString())),
            ("contract_bytes", .number(UInt64(contract.count))), ("contract_sha256", .string(contractHash)),
            ("scope_text_bytes_base64", .string(scope.base64EncodedString())),
            ("scope_text_bytes", .number(UInt64(scope.count))),
            ("scope_text_sha256", .string(contractScope.isEmpty ? "" : sha256(contractScope))),
            ("issuance_context", context), ("authority", authority), ("record", record),
            ("authority_sha256", .string(sha256(try authority.canonical()))),
            ("record_sha256", .string(recordHash)),
        ])
        return try Self.object([
            ("schema", .string("keyvault-root-grants-sign-request/2")),
            ("operation", .string("review-sign-trust-contract-countersign")),
            ("review", review), ("envelope", envelope), ("pair_metadata", .string(pairMetadata)),
        ]).canonical()
    }

    private static func contract(network: String = "regtest", landlord: String = "id/example-landlord",
                                 agent: String = "id/example-agent", scopeHash: String = "",
                                 actions: String = "[\"instruct\",\"review\"]",
                                 note: String = "fixture", notBefore: UInt64 = 1_900_000_000,
                                 notAfter: UInt64 = 1_900_000_100) -> Data {
        Data(("{\"profile\":\"swarma-trust-contract/2\",\"network\":\"\(network)\",\"landlord_name\":\"\(landlord)\",\"agent_name\":\"\(agent)\",\"grantee_key\":\"\(granteeKey)\",\"actions\":\(actions),\"repos\":[],\"spend_budget\":0,\"not_before\":\(notBefore),\"not_after\":\(notAfter),\"scope_text_sha256\":\"\(scopeHash)\",\"parent_grant_id\":\"\",\"ordinal\":0,\"delegate\":{\"depth\":0,\"actions\":[],\"budget\":0,\"slots\":[],\"notaries\":[],\"checkpoint\":\"\"},\"note\":\"\(note)\"}").utf8)
    }

    private static func object(_ members: [(String, NativeArchiveJSON)]) -> NativeArchiveJSON {
        .object(members)
    }

    private static func sha256(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    private static func requestBytesWithNestedObjectSize(_ objectName: String, fieldName: String,
                                                           occurrence: Int, targetBytes: Int) throws -> Data {
        let validContractWithSemanticFault = try requestBytes(actions: "[\"instruct\",\"unknown\"]")
        let outer = try NativeArchiveJSON.decode(validContractWithSemanticFault, maximum: 262_144, canonical: true)
        let review = try outer.field("review")
        let nested = try review.field(objectName)
        let originalValue = try nested.field(fieldName).text()
        let originalBytes = try nested.canonical()
        let newValueCount = originalValue.utf8.count + targetBytes - originalBytes.count
        guard newValueCount >= 0 else { throw RootGrantsReviewError(status: .privateProtocolError) }
        let oldToken = "\"\(fieldName)\":\"\(originalValue)\""
        let newToken = "\"\(fieldName)\":\"\(String(repeating: "x", count: newValueCount))\""
        let source = try #require(String(data: validContractWithSemanticFault, encoding: .utf8))
        guard let changed = Self.replacingOccurrence(source, old: oldToken, with: newToken, occurrence: occurrence) else {
            throw RootGrantsReviewError(status: .privateProtocolError)
        }
        return Data(changed.utf8)
    }

    private static func replacingOccurrence(_ source: String, old: String, with replacement: String,
                                            occurrence: Int) -> String? {
        guard occurrence >= 0 else { return nil }
        var searchStart = source.startIndex
        var seen = 0
        while let range = source.range(of: old, range: searchStart..<source.endIndex) {
            if seen == occurrence { return source.replacingCharacters(in: range, with: replacement) }
            seen += 1
            searchStart = range.upperBound
        }
        return nil
    }
}
