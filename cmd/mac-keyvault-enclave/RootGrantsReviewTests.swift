// Swift Testing SOURCE only. PUBLIC source-provided canonical v1/v2 examples
// and public curve-point fixtures; no phrase/private key/input reader/owner UI,
// C/native call, sealing, key creation or store is executed or simulated as proof.
// These tests prove only their stated format/binding/comparison controls when
// actually run. Compilation, discovery, all tests and native proof are NOT_RUN.
import CryptoKit
import Foundation
import Testing
@testable import KeyvaultNativeCore

// Exact public source examples, not executed factory/derivation evidence.
private let rootFixtureV1 = Data(#"{"protocol":"keyvault-root-grants-private/1","engine":"namecoin-root-grants-engine/1","profile":"namecoin-landlord-root/1","mode":"attach","pair_metadata":"eyJzY2hlbWEiOiJrZXl2YXVsdC1yZWNvdmVyeS8xIiwiZ3JvdXBfaWQiOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInNlcnZpY2UiOiJ0ZXN0IiwidmVyc2lvbiI6MSwiY3JlYXRlZCI6IjIwMjYtMDEtMDJUMDM6MDQ6MDVaIiwibm9zdHIiOnsicHVycG9zZSI6Im5vc3RyIiwidmVyc2lvbiI6MiwicGF0aCI6Im0vNDQnLzEyMzcnLzAnLzAvMCIsImFsZ29yaXRobSI6InNlY3AyNTZrMS1iaXAzNDAiLCJwcmVzZW5jZSI6Im5vbmUiLCJwdWJsaWNfa2V5IjoiZDQxYjIyODk5NTQ5ZTFmM2QzMzVhMzEwMDJjZmQzODIxNzQwMDZlMTY2ZDNlNjU4ZTNhNWVlY2RiNjQ2MzU3MyIsIm5wdWIiOiJucHViMTZzZGo5enY0ZjhzbDg1ZTQ1dmdxOW43bnNndDVxcGhwdm1mN3ZrOHI1aGh2bWRqeHg0ZXM4cnE3NGgiLCJ4cHViIjoiIiwib3JpZ2luIjoiIiwid3JhcHBpbmdfcG9pbnQiOiJCR3NYMGZMaExFSkgrTHptNVdPa1FQSjNBMzJCTGVzem9QU2hPVVhZbU1LV1QrTkM0djRhZjV1TzUrdEtmQStlRml2T00xZHJNVjdPeTdaQWFEZS9VZlU9Iiwid3JhcHBpbmdfZmluZ2VycHJpbnQiOiI2OThiZWE2M2RjNDRhMzQ0NjYzZmYxNDI5YWVhMTA4NDJkZjI3YjZiOTkxZWYyNTg2NmIyYzZjMDJjZGNjNWJlIn0sIm5hbWVjb2luIjp7InB1cnBvc2UiOiJuYW1lY29pbiIsInZlcnNpb24iOjEsInBhdGgiOiJtLzg0Jy83Jy8wJyIsImFsZ29yaXRobSI6ImJpcDMyLXNlY3AyNTZrMSIsInByZXNlbmNlIjoiYmlvbWV0cnktYW55IiwicHVibGljX2tleSI6IiIsIm5wdWIiOiIiLCJ4cHViIjoieHB1YjZDQUJRRkhmWEpqM3RLQWJNRGlEaEtBa1pvR1YzUFgzTnQ1ZHNvMlVZOUh5bWY2a1hLaXd6ZTN5SlVGQnJwcXE3aURGeVY0RWdOdXhHNXRMdnhWU3FuWjNFa1F5SzRWclltUEZ6VXlCMWVzIiwib3JpZ2luIjoiWzU3NDcxYTY2Lzg0aC83aC8waF0iLCJ3cmFwcGluZ19wb2ludCI6IkJIenlleGlOQTA5K2lsSTRBd1MxR3NQQWlXbmlkL0liTmFZTFNQeEhacGw0QjNkVkVOdU8wRUFwUFpyR24zUXcyN3A5cmVZODZZSXBuZ1MzblNKNGM5RT0iLCJ3cmFwcGluZ19maW5nZXJwcmludCI6ImE5ZjMwMGViNTk2MGU4OTEzM2FmNzM2MjAxMWExZTI2ZjBlMmVhMmUzNmRjNDAyYTA0YWY2YzE5MmI4OTFhOGMifX0=","pair":{"schema":"keyvault-recovery/1","service":"test","version":1,"group_id":"00000000000000000000000000000000","metadata_sha256":"7b1e72bac729e8c1e8872ac2017e3f1ed236b5340010e183ca4475944fd2465c","nostr_identity":"test","nostr_version":2,"nostr_public_key":"d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573","nostr_npub":"npub16sdj9zv4f8sl85e45vgq9n7nsgt5qphpvmf7vk8r5hhvmdjxx4es8rq74h","namecoin_identity":"test","namecoin_version":1,"namecoin_xpub":"xpub6CABQFHfXJj3tKAbMDiDhKAkZoGV3PX3Nt5dso2UY9Hymf6kXKiwze3yJUFBrpqq7iDFyV4EgNuxG5tLvxVSqnZ3EkQyK4VrYmPFzUyB1es","namecoin_origin":"[57471a66/84h/7h/0h]"},"service":"example-root","version":1,"created":"2026-01-02T03:04:05Z"}"#.utf8)
private let rootFixtureV2 = Data(#"{"protocol":"keyvault-root-grants-private/1","engine":"namecoin-root-grants-engine/1","profile":"namecoin-landlord-root/1","mode":"attach","pair_metadata":"eyJzY2hlbWEiOiJrZXl2YXVsdC1yZWNvdmVyeS8yIiwiZ3JvdXBfaWQiOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInNlcnZpY2UiOiJ0ZXN0IiwidmVyc2lvbiI6MSwiY3JlYXRlZCI6IjIwMjYtMDEtMDJUMDM6MDQ6MDVaIiwibm9zdHIiOnsic2VydmljZSI6InRlc3QiLCJwdXJwb3NlIjoibm9zdHIiLCJ2ZXJzaW9uIjoyLCJwYXRoIjoibS80NCcvMTIzNycvMCcvMC8wIiwiYWxnb3JpdGhtIjoic2VjcDI1NmsxLWJpcDM0MCIsInByZXNlbmNlIjoibm9uZSIsInB1YmxpY19rZXkiOiJkNDFiMjI4OTk1NDllMWYzZDMzNWEzMTAwMmNmZDM4MjE3NDAwNmUxNjZkM2U2NThlM2E1ZWVjZGI2NDYzNTczIiwibnB1YiI6Im5wdWIxNnNkajl6djRmOHNsODVlNDV2Z3E5bjduc2d0NXFwaHB2bWY3dms4cjVoaHZtZGp4eDRlczhycTc0aCIsInhwdWIiOiIiLCJvcmlnaW4iOiIiLCJ3cmFwcGluZ19wb2ludCI6IkJHc1gwZkxoTEVKSCtMem01V09rUVBKM0EzMkJMZXN6b1BTaE9VWFltTUtXVCtOQzR2NGFmNXVPNSt0S2ZBK2VGaXZPTTFkck1WN095N1pBYURlL1VmVT0iLCJ3cmFwcGluZ19maW5nZXJwcmludCI6IjY5OGJlYTYzZGM0NGEzNDQ2NjNmZjE0MjlhZWExMDg0MmRmMjdiNmI5OTFlZjI1ODY2YjJjNmMwMmNkY2M1YmUifSwibmFtZWNvaW4iOnsic2VydmljZSI6ImV4YW1wbGUtd2FsbGV0IiwicHVycG9zZSI6Im5hbWVjb2luIiwidmVyc2lvbiI6MSwicGF0aCI6Im0vODQnLzcnLzAnIiwiYWxnb3JpdGhtIjoiYmlwMzItc2VjcDI1NmsxIiwicHJlc2VuY2UiOiJiaW9tZXRyeS1hbnkiLCJwdWJsaWNfa2V5IjoiIiwibnB1YiI6IiIsInhwdWIiOiJ4cHViNkNBQlFGSGZYSmozdEtBYk1EaURoS0FrWm9HVjNQWDNOdDVkc28yVVk5SHltZjZrWEtpd3plM3lKVUZCcnBxcTdpREZ5VjRFZ051eEc1dEx2eFZTcW5aM0VrUXlLNFZyWW1QRnpVeUIxZXMiLCJvcmlnaW4iOiJbNTc0NzFhNjYvODRoLzdoLzBoXSIsIndyYXBwaW5nX3BvaW50IjoiQkh6eWV4aU5BMDkraWxJNEF3UzFHc1BBaVduaWQvSWJOYVlMU1B4SFpwbDRCM2RWRU51TzBFQXBQWnJHbjNRdzI3cDlyZVk4NllJcG5nUzNuU0o0YzlFPSIsIndyYXBwaW5nX2ZpbmdlcnByaW50IjoiYTlmMzAwZWI1OTYwZTg5MTMzYWY3MzYyMDExYTFlMjZmMGUyZWEyZTM2ZGM0MDJhMDRhZjZjMTkyYjg5MWE4YyJ9fQ==","pair":{"schema":"keyvault-recovery/2","service":"test","version":1,"group_id":"00000000000000000000000000000000","metadata_sha256":"04efe3af4d04cfa8337f18ceff15a56a8457fe12cbb3d90ff5157ea29dd60c79","nostr_identity":"test","nostr_version":2,"nostr_public_key":"d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573","nostr_npub":"npub16sdj9zv4f8sl85e45vgq9n7nsgt5qphpvmf7vk8r5hhvmdjxx4es8rq74h","namecoin_identity":"example-wallet","namecoin_version":1,"namecoin_xpub":"xpub6CABQFHfXJj3tKAbMDiDhKAkZoGV3PX3Nt5dso2UY9Hymf6kXKiwze3yJUFBrpqq7iDFyV4EgNuxG5tLvxVSqnZ3EkQyK4VrYmPFzUyB1es","namecoin_origin":"[57471a66/84h/7h/0h]"},"service":"example-root","version":1,"created":"2026-01-02T03:04:05Z"}"#.utf8)

private func rootRefusal(_ status: RootGrantsStatus, _ body: () throws -> Void) {
    do { try body(); Issue.record("Expected exact fixed Root refusal") }
    catch let error as RootGrantsReviewError {
        #expect(error.status == status)
        #expect(error.message == "Root attachment public review refused")
    } catch { Issue.record("Unexpected type; diagnostics intentionally withheld") }
}
private func publicRootNode(_ bytes: Data) throws -> NativeArchiveJSON {
    try NativeArchiveJSON.decode(bytes, maximum: 262144, canonical: true)
}
private func rootReplacing(_ node: NativeArchiveJSON, _ key: String, _ value: NativeArchiveJSON?) throws -> NativeArchiveJSON {
    guard case .object(let fields) = node else { throw RootGrantsReviewError(status: .privateProtocolError) }
    return .object(fields.compactMap { name, old -> (String, NativeArchiveJSON)? in
        if name == key { return value.map { (name, $0) } }
        return (name, old)
    })
}
private func changedRoot(_ bytes: Data, _ key: String, _ value: NativeArchiveJSON?) throws -> Data {
    try rootReplacing(publicRootNode(bytes), key, value).canonical()
}
private let publicRootK = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
private let publicSealScript = "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"
private func publicPreparation(_ requestBytes: Data) throws -> Data {
    let pair = try publicRootNode(requestBytes).field("pair")
    return try NativeArchiveJSON.object([
        ("root", .object([
            ("profile", .string("namecoin-landlord-root/1")), ("derivation", .string("bip85-hdseed-wif/1")),
            ("path", .string("m/83696968h/2h/7h")), ("algorithm", .string("secp256k1-bip340+ecdsa")),
            ("public_key", .string(publicRootK)), ("seal_public_key", .string("02" + publicRootK)),
            ("seal_script", .string(publicSealScript))
        ])), ("pair", pair)
    ]).canonical()
}
private func rootReviews(_ bytes: Data = rootFixtureV2) throws -> (RootGrantsInitialReview, RootGrantsDerivedReview) {
    let request = try RootGrantsPublicRequest(ownedBytes: bytes)
    let initial = try RootGrantsInitialReview(request: request)
    let attach = try initial.confirmRetypes(initial.identities, attach: "ATTACH ROOT GRANTS", currentRequest: bytes)
    let preparation = try RootGrantsPreparationPublicView(ownedBytes: publicPreparation(bytes), request: request)
    return (initial, try RootGrantsDerivedReview(initial: initial, attach: attach, preparation: preparation))
}


// A third, fixed PUBLIC P-256 point, distinct from both retained public points.
// The envelope below is only a public shape marker, NOT authentic ECIES output.
private let publicNewWrap = Data([
    0x04, 0x5e, 0xcb, 0xe4, 0xd1, 0xa6, 0x33, 0x0a, 0x44, 0xc8, 0xf7, 0xef, 0x95, 0x1d, 0x4b, 0xf1, 0x65,
    0xe6, 0xc6, 0xb7, 0x21, 0xef, 0xad, 0xa9, 0x85, 0xfb, 0x41, 0x66, 0x1b, 0xc6, 0xe7, 0xfd, 0x6c,
    0x87, 0x34, 0x64, 0x0c, 0x49, 0x98, 0xff, 0x7e, 0x37, 0x4b, 0x06, 0xce, 0x1a, 0x64, 0xa2, 0xec,
    0xd8, 0x2a, 0xb0, 0x36, 0x38, 0x4f, 0xb8, 0x3d, 0x9a, 0x79, 0xb1, 0x27, 0xa2, 0x7d, 0x50, 0x32
])
private func publicSealedShape(_ request: RootGrantsPublicRequest, _ preparation: RootGrantsPreparationPublicView,
                               point: Data = publicNewWrap) throws -> Data {
    let fingerprint = SHA256.hash(data: point).map { String(format: "%02x", $0) }.joined()
    let record = NativeArchiveJSON.object([
        ("schema", .string("keyvault-root-grants/1")), ("service", .string(request.service)),
        ("purpose", .string("root-grants")), ("version", .number(request.version)), ("created", .string(request.created)),
        ("profile", .string(RootGrantsPublicRequest.profile)), ("derivation", .string(RootGrantsPublicRequest.derivation)),
        ("path", .string(RootGrantsPublicRequest.path)), ("algorithm", .string("secp256k1-bip340+ecdsa")),
        ("presence", .string("biometry-any-per-signature")), ("public_key", .string(preparation.publicKey)),
        ("seal_public_key", .string(preparation.sealPublicKey)), ("seal_script", .string(preparation.sealScript)),
        ("pair", try publicRootNode(request.pair.canonicalBytes)), ("wrapping_point", .string(point.base64EncodedString())),
        ("wrapping_fingerprint", .string(fingerprint))
    ])
    let envelope = NativeArchiveJSON.object([
        ("schema", .string("keyvault-root-grants-ciphertext/1")),
        ("algorithm", .string("kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM")),
        ("enclave_blob", .string(Data([1, 2, 3]).base64EncodedString())), ("point", .string(point.base64EncodedString())),
        ("fingerprint", .string(fingerprint)), ("ciphertext", .string((point + Data(repeating: 0, count: 84)).base64EncodedString()))
    ])
    return try NativeArchiveJSON.object([("record", record), ("envelope", envelope)]).canonical()
}
private func replacingMetadata(_ bytes: Data, _ metadata: NativeArchiveJSON) throws -> Data {
    let raw = try metadata.canonical(), node = try publicRootNode(bytes)
    let hash = SHA256.hash(data: raw).map { String(format: "%02x", $0) }.joined()
    let pair = try rootReplacing(node.field("pair"), "metadata_sha256", .string(hash))
    return try rootReplacing(rootReplacing(node, "pair", pair), "pair_metadata", .string(raw.base64EncodedString())).canonical()
}

struct RootGrantsReviewTests {
    // Both actual source forms must be admitted; v2 has a separate Namecoin
    // service. Exact metadata/pair bytes survive, with no cryptographic claim.
    @Test func bothCanonicalPublicForms() throws {
        for bytes in [rootFixtureV1, rootFixtureV2] {
            let request = try RootGrantsPublicRequest(ownedBytes: bytes)
            #expect(request.originalBytes == bytes)
            #expect(request.rootAddress == "example-root/root-grants@1")
            #expect(request.pair.nostrAddress == "test/nostr@2")
            #expect(request.pair.namecoinAddress == (bytes == rootFixtureV1 ? "test/namecoin@1" : "example-wallet/namecoin@1"))
            #expect(request.retainedWrappingPoints.count == 2)
        }
    }

    // Caller-owned NSMutableData mutations must not change decoded public input,
    // metadata or immutable render. No private buffer/crypto memory claim.
    @Test func requestAndReviewOwnTheirBytes() throws {
        let source = NSMutableData(data: rootFixtureV2)
        let request = try RootGrantsPublicRequest(ownedBytes: source as Data)
        let initial = try RootGrantsInitialReview(request: request)
        let frozen = initial.text
        source.resetBytes(in: NSRange(location: 0, length: source.length))
        #expect(request.originalBytes == rootFixtureV2)
        #expect(initial.text == frozen)
        #expect(request.pairMetadata.count > 0)
        var returned = request.originalBytes; returned[0] = 0
        #expect(request.originalBytes == rootFixtureV2)
    }

    // Complete facts/identities/pins/path/request and explicit end marker occur
    // in immutable text, without truncation. No native view/layout is invoked.
    @Test func completeInitialRendering() throws {
        let (initial, _) = try rootReviews()
        for fact in initial.identities + [initial.request.pair.metadataHash, initial.request.pair.nostrPublicKey,
                initial.request.pair.npub, initial.request.pair.xpub, initial.request.pair.origin,
                "m/83696968h/2h/7h", "bip85-hdseed-wif/1", "Preserve both existing paired ciphertexts",
                String(decoding: rootFixtureV2, as: UTF8.self)] {
            #expect(initial.text.contains(fact))
        }
        #expect(initial.text.hasSuffix("END OF COMPLETE ATTACH ONLY REVIEW"))
        #expect(initial.text.utf8.count < 1 << 20)
    }

    // Shape/syntax negatives paired with the two valid forms above. Each expects
    // its exact fixed class, rather than treating any thrown error as success.
    @Test func requestRepresentationRefusals() throws {
        for key in ["protocol", "engine", "profile", "mode", "pair_metadata", "pair", "service", "version", "created"] {
            rootRefusal(.invalidArguments) { _ = try RootGrantsPublicRequest(ownedBytes: changedRoot(rootFixtureV2, key, nil)) }
        }
        for bytes in [Data(), rootFixtureV2 + Data([10]), Data(" ".utf8) + rootFixtureV2,
                      Data(String(decoding: rootFixtureV2, as: UTF8.self).replacingOccurrences(of: "{\"protocol\":", with: "{\"Protocol\":").utf8),
                      Data("{\"protocol\":\"x\",".utf8) + rootFixtureV2.dropFirst()] {
            rootRefusal(.invalidArguments) { _ = try RootGrantsPublicRequest(ownedBytes: bytes) }
        }
        rootRefusal(.invalidArguments) { _ = try RootGrantsPublicRequest(ownedBytes: changedRoot(rootFixtureV2, "service", .null)) }
        let unknown = Data("{\"extra\":0,".utf8) + rootFixtureV2.dropFirst()
        rootRefusal(.invalidArguments) { _ = try RootGrantsPublicRequest(ownedBytes: unknown) }
        rootRefusal(.limitExceeded) { _ = try RootGrantsPublicRequest(ownedBytes: Data(repeating: 32, count: 262145)) }
    }

    // Semantic allowlist: unsupported fixed strings differ from malformed name,
    // time/version/control cases. These are public renderer checks, not Go crypto.
    @Test func requestSemanticRefusalsAndBoundaries() throws {
        for (key, value, status) in [("protocol", "other", RootGrantsStatus.unsupportedVersion),
                                    ("engine", "other", .unsupportedVersion), ("profile", "other", .unsupportedVersion),
                                    ("mode", "ATTACH", .unsupportedOperation), ("protocol", "", .invalidArguments),
                                    ("service", "Upper", .invalidArguments), ("service", "line\nbreak", .invalidArguments),
                                    ("service", "name\u{202e}", .invalidArguments), ("created", "2026-02-30T03:04:05Z", .invalidArguments)] {
            rootRefusal(status) { _ = try RootGrantsPublicRequest(ownedBytes: changedRoot(rootFixtureV2, key, .string(value))) }
        }
        for v in [UInt64(0), UInt64(2147483648)] {
            rootRefusal(.invalidArguments) { _ = try RootGrantsPublicRequest(ownedBytes: changedRoot(rootFixtureV2, "version", .number(v))) }
        }
        var valid = try changedRoot(rootFixtureV2, "service", .string(String(repeating: "a", count: 40)))
        valid = try changedRoot(valid, "version", .number(2147483647))
        let admitted = try RootGrantsPublicRequest(ownedBytes: valid)
        #expect(admitted.version == 2147483647)
        for timestamp in ["0000-02-29T00:00:00Z", "2000-02-29T23:59:59Z", "9999-12-31T23:59:59Z"] {
            let accepted = try RootGrantsPublicRequest(ownedBytes: changedRoot(rootFixtureV2, "created", .string(timestamp)))
            #expect(accepted.created == timestamp)
        }
        for timestamp in ["1900-02-29T00:00:00Z", "2026-01-02T24:00:00Z", "2026-01-02T03:04:60Z", "2026-01-02T03:04:05+00:00"] {
            rootRefusal(.invalidArguments) { _ = try RootGrantsPublicRequest(ownedBytes: changedRoot(rootFixtureV2, "created", .string(timestamp))) }
        }
        rootRefusal(.invalidArguments) { _ = try RootGrantsPublicRequest(ownedBytes: changedRoot(valid, "service", .string(String(repeating: "a", count: 41)))) }
    }

    // Wrong metadata hash/pins and schema aliases cannot reach a review. Valid
    // metadata crypto still requires actual GoOpen; these test string correlation.
    @Test func retainedMetadataAndPairRefusals() throws {
        for (key, value) in [("metadata_sha256", String(repeating: "0", count: 64)),
                             ("nostr_public_key", String(repeating: "1", count: 64)),
                             ("namecoin_origin", "[00000000/84h/7h/0h]"), ("schema", "keyvault-recovery/3")] {
            let node = try publicRootNode(rootFixtureV2)
            let pair = try rootReplacing(node.field("pair"), key, .string(value))
            let bytes = try rootReplacing(node, "pair", pair).canonical()
            rootRefusal(.retainedRecordMismatch) { _ = try RootGrantsPublicRequest(ownedBytes: bytes) }
        }
        rootRefusal(.retainedRecordMismatch) { _ = try RootGrantsPublicRequest(ownedBytes: changedRoot(rootFixtureV2, "pair_metadata", .string("AA=="))) }
    }

    // Exact three retypes + literal ATTACH bind public bytes only; misspellings,
    // case/whitespace, missing fields, cancellation and changed bytes refuse.
    @Test func initialRetypesAndAttach() throws {
        let (initial, _) = try rootReviews()
        let confirmation = try initial.confirmRetypes(initial.identities, attach: "ATTACH ROOT GRANTS", currentRequest: rootFixtureV2)
        #expect(confirmation.stage == .attachReviewed)
        #expect(confirmation.requestHash == initial.request.requestHash)
        for entered in [Array(initial.identities.prefix(2)), initial.identities + ["extra"], initial.identities.reversed().map { $0 }, ["misspelled", initial.identities[1], initial.identities[2]]] {
            rootRefusal(.canceled) { _ = try initial.confirmRetypes(entered, attach: "ATTACH ROOT GRANTS", currentRequest: rootFixtureV2) }
        }
        for literal in ["ATTACH", "attach root grants", " ATTACH ROOT GRANTS", "ATTACH ROOT GRANTS ", "", "CANCEL"] {
            rootRefusal(.canceled) { _ = try initial.confirmRetypes(initial.identities, attach: literal, currentRequest: rootFixtureV2) }
        }
        rootRefusal(.bindingMismatch) { _ = try initial.confirmRetypes(initial.identities, attach: "ATTACH ROOT GRANTS", currentRequest: rootFixtureV1) }
    }

    // Published public K/02K/script shape plus exact pair correlation. This does
    // not independently validate secp256k1 points or calculate HASH160 in Swift.
    @Test func preparationAndDerivedCompleteRendering() throws {
        for bytes in [rootFixtureV1, rootFixtureV2] {
            let (_, review) = try rootReviews(bytes)
            #expect(review.preparation.publicKey == publicRootK)
            #expect(review.preparation.sealPublicKey == "02" + publicRootK)
            for fact in [publicRootK, "02" + publicRootK, publicSealScript, review.initial.request.requestHash,
                         String(decoding: review.preparation.originalBytes, as: UTF8.self)] { #expect(review.text.contains(fact)) }
            #expect(review.text.hasSuffix("END OF COMPLETE MATCH AND STORE REVIEW"))
        }
    }

    // Canonical response field and fixed profile/pin controls reject without
    // claiming that a software response came from a qualified native engine.
    @Test func preparationRefusals() throws {
        let request = try RootGrantsPublicRequest(ownedBytes: rootFixtureV2), raw = try publicPreparation(rootFixtureV2)
        for (key, value) in [("profile", "other"), ("path", "m/83696968h/2h/8h"),
                             ("public_key", publicRootK.uppercased()), ("seal_public_key", "03" + publicRootK),
                             ("seal_script", "0014" + String(repeating: "0", count: 40))] {
            let node = try publicRootNode(raw), root = try rootReplacing(node.field("root"), key, .string(value))
            rootRefusal(.publicPinMismatch) { _ = try RootGrantsPreparationPublicView(ownedBytes: rootReplacing(node, "root", root).canonical(), request: request) }
        }
        rootRefusal(.publicPinMismatch) { _ = try RootGrantsPreparationPublicView(ownedBytes: raw + Data([10]), request: request) }
        rootRefusal(.publicPinMismatch) { _ = try RootGrantsPreparationPublicView(ownedBytes: publicPreparation(rootFixtureV1), request: request) }
        rootRefusal(.limitExceeded) { _ = try RootGrantsPreparationPublicView(ownedBytes: Data(repeating: 32, count: 131073), request: request) }
    }

    // MATCH is display only; only the full final literal binds these immutable
    // public bytes. No typed-MATCH token or native/private proof exists.
    @Test func fullStoreLiteralAndChangedAfterReview() throws {
        let (initial, review) = try rootReviews(), response = review.preparation.originalBytes
        let store = try review.confirmStore("STORE ROOT GRANTS", currentRequest: rootFixtureV2, currentPreparation: response)
        #expect(store.stage == .storeReviewed)
        #expect(store.snapshotHash == review.snapshotHash)
        #expect(review.text.contains("Nostr pin: MATCH"))
        #expect(review.text.contains("Namecoin account+origin: MATCH"))
        rootRefusal(.operationUnavailable) { _ = try RootGrantsDerivedReview(initial: initial, attach: store, preparation: review.preparation) }
        for literal in ["STORE", "MATCH", "store root grants", " STORE ROOT GRANTS", "STORE ROOT GRANTS ", "", "CANCEL"] {
            rootRefusal(.canceled) { _ = try review.confirmStore(literal, currentRequest: rootFixtureV2, currentPreparation: response) }
        }
        rootRefusal(.bindingMismatch) { _ = try review.confirmStore("STORE ROOT GRANTS", currentRequest: rootFixtureV1, currentPreparation: response) }
        rootRefusal(.bindingMismatch) { _ = try review.confirmStore("STORE ROOT GRANTS", currentRequest: rootFixtureV2, currentPreparation: response + Data([32])) }
    }

    // Archive statuses remain ROOT1..20; helper read refusals use the separate
    // extended table. Numeric20 is input_canceled, not a Namecoin journal error.
    @Test func closedRootStatuses() throws {
        let codes = ["success", "invalid_arguments", "terminal_required", "invalid_word_number", "invalid_word_count", "invalid_mnemonic", "invalid_checksum", "invalid_derivation", "retained_record_mismatch", "public_pin_mismatch", "operation_unavailable", "wrapping_policy_refused", "invalid_envelope", "binding_mismatch", "canceled", "timeout", "private_protocol_error", "limit_exceeded", "unsupported_version", "unsupported_operation", "input_canceled"]
        for (raw, code) in codes.enumerated() { #expect(RootGrantsStatus.closed(Int32(raw)).code == code) }
        for (offset, code) in ["code_not_admitted", "acl_refused", "lock_unavailable", "inventory_changed"].enumerated() {
            #expect(RootGrantsStatus.helperClosed(Int32(offset + 21)).code == code)
        }
        #expect(RootGrantsReviewError.fromStatus(0) == nil)
        #expect(RootGrantsReviewError.fromStatus(14)?.status == .canceled)
        #expect(RootGrantsReviewError.fromStatus(15)?.status == .timeout)
        #expect(RootGrantsReviewError.fromStatus(20)?.status == .inputCanceled)
        for raw in [Int32(-1), Int32(21), Int32(25), Int32.max] { #expect(RootGrantsReviewError.fromStatus(raw)?.status == .privateProtocolError) }
    }

    // All thirteen pair fields are required, ordered and typed; no alias or extra
    // field is admitted. The unmodified v1/v2 controls above prevent reject-all.
    @Test func closedPairRepresentation() throws {
        let node = try publicRootNode(rootFixtureV2), pair = try node.field("pair")
        for key in RootGrantsPairPublic.keys {
            for replacement in [Optional<NativeArchiveJSON>.none, .some(.null)] {
                let changed = try rootReplacing(node, "pair", rootReplacing(pair, key, replacement)).canonical()
                rootRefusal(.retainedRecordMismatch) { _ = try RootGrantsPublicRequest(ownedBytes: changed) }
            }
        }
        guard case .object(let fields) = pair else { Issue.record("Public fixture shape changed"); return }
        for altered in [NativeArchiveJSON.object(fields.reversed().map { $0 }),
                        .object(fields + [("extra", .number(0))])] {
            rootRefusal(.retainedRecordMismatch) { _ = try RootGrantsPublicRequest(ownedBytes: rootReplacing(node, "pair", altered).canonical()) }
        }
        let duplicate = NativeArchiveJSON.object(fields + [("schema", .string("keyvault-recovery/2"))])
        rootRefusal(.invalidArguments) { _ = try RootGrantsPublicRequest(ownedBytes: rootReplacing(node, "pair", duplicate).canonical()) }
    }

    // Recompute the PUBLIC metadata hash after each mutation so these negatives
    // exercise semantic pins/purpose/path/policy, rather than only a stale hash.
    @Test func retainedMetadataSemanticRefusals() throws {
        let request = try RootGrantsPublicRequest(ownedBytes: rootFixtureV2)
        let metadata = try publicRootNode(request.pairMetadata)
        for (purpose, key, value) in [("nostr", "service", "other"), ("nostr", "purpose", "namecoin"),
                                      ("nostr", "path", "m/44'/1237'/0'/0/1"), ("nostr", "presence", "biometry-any"),
                                      ("namecoin", "algorithm", "other"), ("namecoin", "path", "m/84'/7'/1'"),
                                      ("namecoin", "origin", "[00000000/84h/7h/0h]"),
                                      ("namecoin", "wrapping_fingerprint", String(repeating: "0", count: 64))] {
            let field = try rootReplacing(metadata.field(purpose), key, .string(value))
            let bytes = try replacingMetadata(rootFixtureV2, rootReplacing(metadata, purpose, field))
            rootRefusal(.retainedRecordMismatch) { _ = try RootGrantsPublicRequest(ownedBytes: bytes) }
        }
    }

    // Preparation owns its bytes and is bound to the COMPLETE request hash even
    // when a different request selects the very same retained pair. No C proof.
    @Test func preparationOwnershipAndRequestBinding() throws {
        let request = try RootGrantsPublicRequest(ownedBytes: rootFixtureV2)
        let raw = try publicPreparation(rootFixtureV2), source = NSMutableData(data: try publicPreparation(rootFixtureV2))
        let preparation = try RootGrantsPreparationPublicView(ownedBytes: source as Data, request: request)
        source.resetBytes(in: NSRange(location: 0, length: source.length))
        #expect(preparation.originalBytes == raw)
        #expect(preparation.requestHash == request.requestHash)
        let otherBytes = try changedRoot(rootFixtureV2, "service", .string("other-root"))
        let other = try RootGrantsPublicRequest(ownedBytes: otherBytes), initial = try RootGrantsInitialReview(request: other)
        let attached = try initial.confirmRetypes(initial.identities, attach: "ATTACH ROOT GRANTS", currentRequest: otherBytes)
        rootRefusal(.publicPinMismatch) { _ = try RootGrantsDerivedReview(initial: initial, attach: attached, preparation: preparation) }
        rootRefusal(.bindingMismatch) { _ = try RootGrantsSealedPublicView(ownedBytes: publicSealedShape(request, preparation), request: other, preparation: preparation) }
        let (_, review) = try rootReviews(), otherPreparation = try RootGrantsPreparationPublicView(ownedBytes: raw, request: other)
        let otherReview = try RootGrantsDerivedReview(initial: initial, attach: attached, preparation: otherPreparation)
        let otherStore = try otherReview.confirmStore("STORE ROOT GRANTS", currentRequest: otherBytes, currentPreparation: raw)
        #expect(otherStore.requestHash != review.initial.request.requestHash)
    }

    // Positive PUBLIC response-shape controls for both pair schemas. Opaque blob
    // and ciphertext are markers: acceptance is NOT sealing/native/store proof.
    @Test func sealedPublicShapeAndOwnership() throws {
        for bytes in [rootFixtureV1, rootFixtureV2] {
            let request = try RootGrantsPublicRequest(ownedBytes: bytes)
            let preparation = try RootGrantsPreparationPublicView(ownedBytes: publicPreparation(bytes), request: request)
            let raw = try publicSealedShape(request, preparation), source = NSMutableData(data: try publicSealedShape(request, preparation))
            let view = try RootGrantsSealedPublicView(ownedBytes: source as Data, request: request, preparation: preparation)
            source.resetBytes(in: NSRange(location: 0, length: source.length))
            #expect(view.originalBytes == raw)
            let node = try publicRootNode(raw)
            #expect(view.recordBytes == (try node.field("record").canonical()))
            #expect(view.envelopeBytes == (try node.field("envelope").canonical()))
        }
    }

    // Response binding/closed shape rejects before any consumer can regard the
    // bytes as a public completion. This does not authenticate an ECIES tag.
    @Test func sealedResponseRefusals() throws {
        let request = try RootGrantsPublicRequest(ownedBytes: rootFixtureV2)
        let preparation = try RootGrantsPreparationPublicView(ownedBytes: publicPreparation(rootFixtureV2), request: request)
        let raw = try publicSealedShape(request, preparation), node = try publicRootNode(raw)
        for (part, key, value) in [("record", "service", "other"), ("record", "purpose", "other"),
                                   ("record", "public_key", String(repeating: "0", count: 64)),
                                   ("record", "presence", "none"), ("record", "path", "m/0h"),
                                   ("record", "wrapping_fingerprint", String(repeating: "0", count: 64)),
                                   ("envelope", "schema", "other"), ("envelope", "algorithm", "other"),
                                   ("envelope", "enclave_blob", ""), ("envelope", "enclave_blob", "AA"),
                                   ("envelope", "ciphertext", Data(repeating: 0, count: 149).base64EncodedString()),
                                   ("envelope", "ciphertext", Data(repeating: 0, count: 150).base64EncodedString())] {
            let field = try rootReplacing(node.field(part), key, .string(value))
            rootRefusal(.invalidEnvelope) { _ = try RootGrantsSealedPublicView(ownedBytes: rootReplacing(node, part, field).canonical(), request: request, preparation: preparation) }
        }
        for part in ["record", "envelope"] {
            guard case .object(let fields) = try node.field(part) else { Issue.record("Public fixture shape changed"); return }
            for (key, _) in fields {
                let field = try rootReplacing(node.field(part), key, nil)
                // The record's complete pair field is required at this layer too.
                rootRefusal(.invalidEnvelope) { _ = try RootGrantsSealedPublicView(ownedBytes: rootReplacing(node, part, field).canonical(), request: request, preparation: preparation) }
            }
        }
        rootRefusal(.invalidEnvelope) { _ = try RootGrantsSealedPublicView(ownedBytes: publicSealedShape(request, preparation, point: request.retainedWrappingPoints[0]), request: request, preparation: preparation) }
        let extra = Data("{\"extra\":0,".utf8) + raw.dropFirst()
        let duplicate = Data("{\"record\":null,".utf8) + raw.dropFirst()
        for malformed in [extra, duplicate, try changedRoot(raw, "record", .null)] {
            rootRefusal(.invalidEnvelope) { _ = try RootGrantsSealedPublicView(ownedBytes: malformed, request: request, preparation: preparation) }
        }
        rootRefusal(.invalidEnvelope) { _ = try RootGrantsSealedPublicView(ownedBytes: raw + Data([10]), request: request, preparation: preparation) }
        rootRefusal(.limitExceeded) { _ = try RootGrantsSealedPublicView(ownedBytes: Data(repeating: 32, count: 131073), request: request, preparation: preparation) }
    }


    // Missing/null/aliased/extra preparation facts and reordered objects refuse;
    // the complete canonical preparation controls above remain admitted. No UI.
    @Test func closedPreparationRepresentation() throws {
        let request = try RootGrantsPublicRequest(ownedBytes: rootFixtureV2)
        let raw = try publicPreparation(rootFixtureV2), node = try publicRootNode(raw)
        let root = try node.field("root")
        guard case .object(let fields) = root else { Issue.record("Public fixture shape changed"); return }
        for (key, _) in fields {
            for value in [Optional<NativeArchiveJSON>.none, .some(.null)] {
                let modified = try rootReplacing(node, "root", rootReplacing(root, key, value)).canonical()
                rootRefusal(.publicPinMismatch) { _ = try RootGrantsPreparationPublicView(ownedBytes: modified, request: request) }
            }
        }
        for modified in [NativeArchiveJSON.object(fields + [("extra", .number(0))]),
                         .object(fields.reversed().map { $0 }),
                         .object(fields + [("profile", .string(RootGrantsPublicRequest.profile))])] {
            rootRefusal(.publicPinMismatch) { _ = try RootGrantsPreparationPublicView(ownedBytes: rootReplacing(node, "root", modified).canonical(), request: request) }
        }
        for key in ["root", "pair"] {
            rootRefusal(.publicPinMismatch) { _ = try RootGrantsPreparationPublicView(ownedBytes: changedRoot(raw, key, nil), request: request) }
        }
    }

}
