// PUBLIC actual-C plumbing test SOURCE. These tests may open the real public
// factory, copy BEFORE preparation and close. They never invoke C Prepare,
// C Seal, tty, owner UI, wrap/TouchID/Keychain or private material. Pure review
// fixtures do not pretend to be preparation returned by a live C session.
// Compilation, discovery and all test/native execution are NOT_RUN.
import CryptoKit
import Darwin
import Foundation
import NamecoinArchiveABI
import Testing
@testable import KeyvaultNativeCore

private let archiveRequestV1 = Data(#"{"protocol":"keyvault-root-grants-private/1","engine":"namecoin-root-grants-engine/1","profile":"namecoin-landlord-root/1","mode":"attach","pair_metadata":"eyJzY2hlbWEiOiJrZXl2YXVsdC1yZWNvdmVyeS8xIiwiZ3JvdXBfaWQiOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInNlcnZpY2UiOiJ0ZXN0IiwidmVyc2lvbiI6MSwiY3JlYXRlZCI6IjIwMjYtMDEtMDJUMDM6MDQ6MDVaIiwibm9zdHIiOnsicHVycG9zZSI6Im5vc3RyIiwidmVyc2lvbiI6MiwicGF0aCI6Im0vNDQnLzEyMzcnLzAnLzAvMCIsImFsZ29yaXRobSI6InNlY3AyNTZrMS1iaXAzNDAiLCJwcmVzZW5jZSI6Im5vbmUiLCJwdWJsaWNfa2V5IjoiZDQxYjIyODk5NTQ5ZTFmM2QzMzVhMzEwMDJjZmQzODIxNzQwMDZlMTY2ZDNlNjU4ZTNhNWVlY2RiNjQ2MzU3MyIsIm5wdWIiOiJucHViMTZzZGo5enY0ZjhzbDg1ZTQ1dmdxOW43bnNndDVxcGhwdm1mN3ZrOHI1aGh2bWRqeHg0ZXM4cnE3NGgiLCJ4cHViIjoiIiwib3JpZ2luIjoiIiwid3JhcHBpbmdfcG9pbnQiOiJCR3NYMGZMaExFSkgrTHptNVdPa1FQSjNBMzJCTGVzem9QU2hPVVhZbU1LV1QrTkM0djRhZjV1TzUrdEtmQStlRml2T00xZHJNVjdPeTdaQWFEZS9VZlU9Iiwid3JhcHBpbmdfZmluZ2VycHJpbnQiOiI2OThiZWE2M2RjNDRhMzQ0NjYzZmYxNDI5YWVhMTA4NDJkZjI3YjZiOTkxZWYyNTg2NmIyYzZjMDJjZGNjNWJlIn0sIm5hbWVjb2luIjp7InB1cnBvc2UiOiJuYW1lY29pbiIsInZlcnNpb24iOjEsInBhdGgiOiJtLzg0Jy83Jy8wJyIsImFsZ29yaXRobSI6ImJpcDMyLXNlY3AyNTZrMSIsInByZXNlbmNlIjoiYmlvbWV0cnktYW55IiwicHVibGljX2tleSI6IiIsIm5wdWIiOiIiLCJ4cHViIjoieHB1YjZDQUJRRkhmWEpqM3RLQWJNRGlEaEtBa1pvR1YzUFgzTnQ1ZHNvMlVZOUh5bWY2a1hLaXd6ZTN5SlVGQnJwcXE3aURGeVY0RWdOdXhHNXRMdnhWU3FuWjNFa1F5SzRWclltUEZ6VXlCMWVzIiwib3JpZ2luIjoiWzU3NDcxYTY2Lzg0aC83aC8waF0iLCJ3cmFwcGluZ19wb2ludCI6IkJIenlleGlOQTA5K2lsSTRBd1MxR3NQQWlXbmlkL0liTmFZTFNQeEhacGw0QjNkVkVOdU8wRUFwUFpyR24zUXcyN3A5cmVZODZZSXBuZ1MzblNKNGM5RT0iLCJ3cmFwcGluZ19maW5nZXJwcmludCI6ImE5ZjMwMGViNTk2MGU4OTEzM2FmNzM2MjAxMWExZTI2ZjBlMmVhMmUzNmRjNDAyYTA0YWY2YzE5MmI4OTFhOGMifX0=","pair":{"schema":"keyvault-recovery/1","service":"test","version":1,"group_id":"00000000000000000000000000000000","metadata_sha256":"7b1e72bac729e8c1e8872ac2017e3f1ed236b5340010e183ca4475944fd2465c","nostr_identity":"test","nostr_version":2,"nostr_public_key":"d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573","nostr_npub":"npub16sdj9zv4f8sl85e45vgq9n7nsgt5qphpvmf7vk8r5hhvmdjxx4es8rq74h","namecoin_identity":"test","namecoin_version":1,"namecoin_xpub":"xpub6CABQFHfXJj3tKAbMDiDhKAkZoGV3PX3Nt5dso2UY9Hymf6kXKiwze3yJUFBrpqq7iDFyV4EgNuxG5tLvxVSqnZ3EkQyK4VrYmPFzUyB1es","namecoin_origin":"[57471a66/84h/7h/0h]"},"service":"example-root","version":1,"created":"2026-01-02T03:04:05Z"}"#.utf8)
private let archiveRequestV2 = Data(#"{"protocol":"keyvault-root-grants-private/1","engine":"namecoin-root-grants-engine/1","profile":"namecoin-landlord-root/1","mode":"attach","pair_metadata":"eyJzY2hlbWEiOiJrZXl2YXVsdC1yZWNvdmVyeS8yIiwiZ3JvdXBfaWQiOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInNlcnZpY2UiOiJ0ZXN0IiwidmVyc2lvbiI6MSwiY3JlYXRlZCI6IjIwMjYtMDEtMDJUMDM6MDQ6MDVaIiwibm9zdHIiOnsic2VydmljZSI6InRlc3QiLCJwdXJwb3NlIjoibm9zdHIiLCJ2ZXJzaW9uIjoyLCJwYXRoIjoibS80NCcvMTIzNycvMCcvMC8wIiwiYWxnb3JpdGhtIjoic2VjcDI1NmsxLWJpcDM0MCIsInByZXNlbmNlIjoibm9uZSIsInB1YmxpY19rZXkiOiJkNDFiMjI4OTk1NDllMWYzZDMzNWEzMTAwMmNmZDM4MjE3NDAwNmUxNjZkM2U2NThlM2E1ZWVjZGI2NDYzNTczIiwibnB1YiI6Im5wdWIxNnNkajl6djRmOHNsODVlNDV2Z3E5bjduc2d0NXFwaHB2bWY3dms4cjVoaHZtZGp4eDRlczhycTc0aCIsInhwdWIiOiIiLCJvcmlnaW4iOiIiLCJ3cmFwcGluZ19wb2ludCI6IkJHc1gwZkxoTEVKSCtMem01V09rUVBKM0EzMkJMZXN6b1BTaE9VWFltTUtXVCtOQzR2NGFmNXVPNSt0S2ZBK2VGaXZPTTFkck1WN095N1pBYURlL1VmVT0iLCJ3cmFwcGluZ19maW5nZXJwcmludCI6IjY5OGJlYTYzZGM0NGEzNDQ2NjNmZjE0MjlhZWExMDg0MmRmMjdiNmI5OTFlZjI1ODY2YjJjNmMwMmNkY2M1YmUifSwibmFtZWNvaW4iOnsic2VydmljZSI6ImV4YW1wbGUtd2FsbGV0IiwicHVycG9zZSI6Im5hbWVjb2luIiwidmVyc2lvbiI6MSwicGF0aCI6Im0vODQnLzcnLzAnIiwiYWxnb3JpdGhtIjoiYmlwMzItc2VjcDI1NmsxIiwicHJlc2VuY2UiOiJiaW9tZXRyeS1hbnkiLCJwdWJsaWNfa2V5IjoiIiwibnB1YiI6IiIsInhwdWIiOiJ4cHViNkNBQlFGSGZYSmozdEtBYk1EaURoS0FrWm9HVjNQWDNOdDVkc28yVVk5SHltZjZrWEtpd3plM3lKVUZCcnBxcTdpREZ5VjRFZ051eEc1dEx2eFZTcW5aM0VrUXlLNFZyWW1QRnpVeUIxZXMiLCJvcmlnaW4iOiJbNTc0NzFhNjYvODRoLzdoLzBoXSIsIndyYXBwaW5nX3BvaW50IjoiQkh6eWV4aU5BMDkraWxJNEF3UzFHc1BBaVduaWQvSWJOYVlMU1B4SFpwbDRCM2RWRU51TzBFQXBQWnJHbjNRdzI3cDlyZVk4NllJcG5nUzNuU0o0YzlFPSIsIndyYXBwaW5nX2ZpbmdlcnByaW50IjoiYTlmMzAwZWI1OTYwZTg5MTMzYWY3MzYyMDExYTFlMjZmMGUyZWEyZTM2ZGM0MDJhMDRhZjZjMTkyYjg5MWE4YyJ9fQ==","pair":{"schema":"keyvault-recovery/2","service":"test","version":1,"group_id":"00000000000000000000000000000000","metadata_sha256":"04efe3af4d04cfa8337f18ceff15a56a8457fe12cbb3d90ff5157ea29dd60c79","nostr_identity":"test","nostr_version":2,"nostr_public_key":"d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573","nostr_npub":"npub16sdj9zv4f8sl85e45vgq9n7nsgt5qphpvmf7vk8r5hhvmdjxx4es8rq74h","namecoin_identity":"example-wallet","namecoin_version":1,"namecoin_xpub":"xpub6CABQFHfXJj3tKAbMDiDhKAkZoGV3PX3Nt5dso2UY9Hymf6kXKiwze3yJUFBrpqq7iDFyV4EgNuxG5tLvxVSqnZ3EkQyK4VrYmPFzUyB1es","namecoin_origin":"[57471a66/84h/7h/0h]"},"service":"example-root","version":1,"created":"2026-01-02T03:04:05Z"}"#.utf8)

private func archiveExpectRefusal(_ status: RootGrantsStatus, _ body: () throws -> Void) {
    do { try body(); Issue.record("Expected exact closed Root refusal") }
    catch let error as RootGrantsReviewError {
        #expect(error.status == status)
        #expect(error.message == "Root attachment public review refused")
    } catch { Issue.record("Unexpected error type; diagnostics withheld") }
}
private func archiveRawOpen(_ request: Data) -> (Int32, UInt64, Data) {
    var bytes = Array(request), handle: UInt64 = 999999
    let count = bytes.count
    let status = bytes.withUnsafeMutableBufferPointer {
        kv_rg_open_v1($0.baseAddress, size_t(count), &handle)
    }
    return (status, handle, Data(bytes))
}
private func archivePublicReviews(_ bytes: Data) throws -> (RootGrantsInitialReview, RootGrantsPublicConfirmation, RootGrantsDerivedReview, RootGrantsPublicConfirmation) {
    let request = try RootGrantsPublicRequest(ownedBytes: bytes)
    let initial = try RootGrantsInitialReview(request: request)
    let attach = try initial.confirmRetypes(initial.identities, attach: "ATTACH ROOT GRANTS", currentRequest: bytes)
    // PUBLIC shape fixture only. Never installed into the production wrapper.
    let k = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let pair = try NativeArchiveJSON.decode(request.pair.canonicalBytes, maximum: 32768, canonical: true)
    let response = try NativeArchiveJSON.object([
        ("root", .object([
            ("profile", .string(RootGrantsPublicRequest.profile)), ("derivation", .string(RootGrantsPublicRequest.derivation)),
            ("path", .string(RootGrantsPublicRequest.path)), ("algorithm", .string("secp256k1-bip340+ecdsa")),
            ("public_key", .string(k)), ("seal_public_key", .string("02" + k)),
            ("seal_script", .string("76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"))
        ])), ("pair", pair)
    ]).canonical()
    let preparation = try RootGrantsPreparationPublicView(ownedBytes: response, request: request)
    let derived = try RootGrantsDerivedReview(initial: initial, attach: attach, preparation: preparation)
    let store = try derived.confirmStore("STORE ROOT GRANTS", currentRequest: bytes, currentPreparation: response)
    return (initial, attach, derived, store)
}

struct RootGrantsArchiveBridgeTests {
    // Both actual public factory controls must succeed with unchanged borrowed
    // bytes and a Root-only handle. No Prepare/private lifecycle is invoked.
    @Test func actualCanonicalPublicOpenAndClose() throws {
        for bytes in [archiveRequestV1, archiveRequestV2] {
            let (status, handle, after) = archiveRawOpen(bytes)
            #expect(status == 0)
            #expect(handle & (UInt64(1) << 63) != 0)
            #expect(handle & ~(UInt64(1) << 63) != 0)
            #expect(after == bytes)
            defer { if status != 0, RootGrantsArchiveBindings.rootHandle(handle) { _ = kv_rg_close_v1(handle) } }
            guard status == 0, RootGrantsArchiveBindings.rootHandle(handle) else { continue }
            #expect(kv_rg_close_v1(handle) == 0)
            #expect(kv_rg_close_v1(handle) == 0) // Actual C tombstone idempotence.
        }
    }

    // Invalid inputs traverse actual C Open, not a mock. Each fixed status and
    // zero output handle is checked; valid v1/v2 controls above prevent reject-all.
    @Test func actualMalformedPublicOpenIsClosed() throws {
        let unknown = Data("{\"extra\":true,".utf8) + archiveRequestV1.dropFirst()
        let unsupported = Data(String(decoding: archiveRequestV1, as: UTF8.self)
            .replacingOccurrences(of: "keyvault-root-grants-private/1", with: "keyvault-root-grants-private/9").utf8)
        for (raw, expected) in [(Data(), Int32(1)), (Data("{".utf8), 1), (unknown, 1),
                                (archiveRequestV2 + Data([10]), 1), (unsupported, 18),
                                (Data(repeating: 32, count: 262145), 17)] {
            let (status, handle, after) = archiveRawOpen(raw)
            #expect(status == expected)
            #expect(handle == 0)
            #expect(after == raw)
            if RootGrantsArchiveBindings.rootHandle(handle) { _ = kv_rg_close_v1(handle) }
        }
    }

    // Real early query/copy and malformed-capacity controls cannot return output
    // or change canary bytes. Valid prepared short-capacity copying is NOT_RUN:
    // it needs real private preparation; Go export tests use a synthetic facade.
    @Test func actualEarlyCopiesAndCapacityRefusals() throws {
        for raw in [archiveRequestV1, archiveRequestV2] {
            let (status, handle, _) = archiveRawOpen(raw)
            #expect(status == 0)
            defer { if RootGrantsArchiveBindings.rootHandle(handle) { _ = kv_rg_close_v1(handle) } }
            guard status == 0, RootGrantsArchiveBindings.rootHandle(handle) else { continue }
            var written: size_t = 999999
            #expect(kv_rg_copy_public_v1(handle, nil, 0, &written) == 10)
            #expect(written == 0)
            written = 999999
            #expect(kv_rg_copy_sealed_v1(handle, nil, 0, &written) == 10)
            #expect(written == 0)
            var canary = [UInt8](repeating: 0xa5, count: 3)
            written = 999999
            let code = canary.withUnsafeMutableBufferPointer {
                kv_rg_copy_public_v1(handle, $0.baseAddress, 3, &written)
            }
            #expect(code == 10)
            #expect(written == 0)
            #expect(canary == [0xa5, 0xa5, 0xa5])
            written = 999999
            #expect(kv_rg_copy_public_v1(handle, nil, 131073, &written) == 17)
            #expect(written == 0)
            #expect(kv_rg_copy_public_v1(handle, nil, 1, &written) == 1)
            #expect(written == 0)
            #expect(kv_rg_copy_sealed_v1(handle, nil, 0, nil) == 1)
        }
    }

    // Zero, low-domain and unknown Root handles refuse without touching any
    // Namecoin state. No Prepare, Seal or invalid memory pointer is attempted.
    @Test func actualUnknownHandlesRefuseCopiesAndClose() {
        for handle in [UInt64(0), UInt64(63), (UInt64(1) << 63) | 999999] {
            var written: size_t = 888
            #expect(kv_rg_copy_public_v1(handle, nil, 0, &written) == 1)
            #expect(written == 0)
            written = 888
            #expect(kv_rg_copy_sealed_v1(handle, nil, 0, &written) == 1)
            #expect(written == 0)
            #expect(kv_rg_close_v1(handle) == 1)
        }
    }

    // A genuine wrapper Open owns immutable public review bytes and closes
    // idempotently. This observes return values, not a native cleanup-count proof.
    @Test func wrapperOwnsInitialBytesAndCloses() throws {
        for raw in [archiveRequestV1, archiveRequestV2] {
            let mutable = NSMutableData(data: raw)
            let session = try NativeRootGrantsArchiveSession(publicRequest: mutable as Data)
            defer { _ = session.close() }
            let rendered = session.initialReview.text
            mutable.resetBytes(in: NSRange(location: 0, length: mutable.length))
            #expect(session.initialReview.request.originalBytes == raw)
            #expect(session.initialReview.text == rendered)
            #expect(rendered.hasSuffix("END OF COMPLETE ATTACH ONLY REVIEW"))
            #expect(session.close() == .success)
            #expect(session.close() == .success)
        }
    }

    // Positive exact public comparisons plus changed/mismatched confirmations.
    // This calls the SAME guards used before C Prepare/Seal, never those private
    // operations. Public model confirmations are not genuine owner UI evidence.
    @Test func exactPublicReviewBindings() throws {
        for raw in [archiveRequestV1, archiveRequestV2] {
            let (initial, attach, review, store) = try archivePublicReviews(raw)
            try RootGrantsArchiveBindings.initial(attach, review: initial, currentRequest: raw)
            try RootGrantsArchiveBindings.store(store, review: review, currentRequest: raw,
                                                currentPreparation: review.preparation.originalBytes)
            archiveExpectRefusal(.operationUnavailable) {
                try RootGrantsArchiveBindings.initial(store, review: initial, currentRequest: raw)
            }
            archiveExpectRefusal(.operationUnavailable) {
                try RootGrantsArchiveBindings.store(attach, review: review, currentRequest: raw,
                                                    currentPreparation: review.preparation.originalBytes)
            }
            archiveExpectRefusal(.bindingMismatch) {
                try RootGrantsArchiveBindings.initial(attach, review: initial, currentRequest: raw + Data([32]))
            }
            archiveExpectRefusal(.bindingMismatch) {
                try RootGrantsArchiveBindings.store(store, review: review, currentRequest: raw,
                                                    currentPreparation: review.preparation.originalBytes + Data([32]))
            }
        }
        let (initial, _, review, _) = try archivePublicReviews(archiveRequestV1)
        let (_, otherAttach, _, otherStore) = try archivePublicReviews(archiveRequestV2)
        archiveExpectRefusal(.operationUnavailable) {
            try RootGrantsArchiveBindings.initial(otherAttach, review: initial, currentRequest: archiveRequestV1)
        }
        archiveExpectRefusal(.operationUnavailable) {
            try RootGrantsArchiveBindings.store(otherStore, review: review, currentRequest: archiveRequestV1,
                                                currentPreparation: review.preparation.originalBytes)
        }
    }

    // Public STORE cannot install a fabricated preparation into a genuine newly
    // opened wrapper. Refusal closes before C Seal, so no wrap/private action.
    @Test func earlySealCannotUsePublicModelAsAuthority() throws {
        let (_, _, review, store) = try archivePublicReviews(archiveRequestV2)
        let session = try NativeRootGrantsArchiveSession(publicRequest: archiveRequestV2)
        defer { _ = session.close() }
        let publicPoint = session.initialReview.request.retainedWrappingPoints[0]
        archiveExpectRefusal(.operationUnavailable) {
            _ = try session.sealAfterReviewedStore(store, currentRequest: archiveRequestV2,
                    currentPreparation: review.preparation.originalBytes, publicPoint: publicPoint,
                    sealedDeviceBlob: Data([1, 2, 3]))
        }
        #expect(session.close() == .success)
        #expect(session.close() == .success)
    }

    // Literal generated ROOT constants are compared with the frozen model. This
    // does not reinterpret Namecoin numeric meanings or simulate a C result.
    @Test func importedRootConstantsAndClosedStatuses() throws {
        let constants = [KV_RG_OK, KV_RG_INVALID_ARGUMENTS, KV_RG_TERMINAL_REQUIRED,
                         KV_RG_INVALID_WORD_NUMBER, KV_RG_INVALID_WORD_COUNT, KV_RG_INVALID_MNEMONIC,
                         KV_RG_INVALID_CHECKSUM, KV_RG_INVALID_DERIVATION, KV_RG_RETAINED_RECORD_MISMATCH,
                         KV_RG_PUBLIC_PIN_MISMATCH, KV_RG_OPERATION_UNAVAILABLE, KV_RG_WRAPPING_POLICY_REFUSED,
                         KV_RG_INVALID_ENVELOPE, KV_RG_BINDING_MISMATCH, KV_RG_CANCELED, KV_RG_TIMEOUT,
                         KV_RG_PRIVATE_PROTOCOL_ERROR, KV_RG_LIMIT_EXCEEDED, KV_RG_UNSUPPORTED_VERSION,
                         KV_RG_UNSUPPORTED_OPERATION, KV_RG_INPUT_CANCELED]
        for (value, imported) in constants.enumerated() {
            #expect(Int32(imported) == Int32(value))
            if value == 0 { try RootGrantsArchiveBindings.status(0) }
            else {
                archiveExpectRefusal(RootGrantsStatus.closed(Int32(value))) {
                    try RootGrantsArchiveBindings.status(Int32(value))
                }
            }
        }
        for unknown in [Int32(-1), Int32(21), Int32.max] {
            archiveExpectRefusal(.privateProtocolError) { try RootGrantsArchiveBindings.status(unknown) }
        }
    }

    // Bounded conversion and status/handle controls admit their valid forms.
    // Pure scalar tests cannot prove C allocation, copying or private lifetimes.
    @Test func boundedLengthsAndOpenDomain() throws {
        #expect(try RootGrantsArchiveBindings.length(1) == 1)
        #expect(try RootGrantsArchiveBindings.length(131072) == 131072)
        for count in [size_t(0), size_t(131073), size_t.max] {
            archiveExpectRefusal(.privateProtocolError) { _ = try RootGrantsArchiveBindings.length(count) }
        }
        let handle = (UInt64(1) << 63) | 1
        try RootGrantsArchiveBindings.opened(status: 0, handle: handle)
        for invalid in [UInt64(0), UInt64(1), UInt64(1) << 63] {
            archiveExpectRefusal(.privateProtocolError) { try RootGrantsArchiveBindings.opened(status: 0, handle: invalid) }
        }
        archiveExpectRefusal(.invalidArguments) { try RootGrantsArchiveBindings.opened(status: 1, handle: 0) }
        archiveExpectRefusal(.privateProtocolError) { try RootGrantsArchiveBindings.opened(status: 1, handle: handle) }
        archiveExpectRefusal(.privateProtocolError) { try RootGrantsArchiveBindings.opened(status: 999, handle: 0) }
    }

    // Only the exact PUBLIC point/blob sent by the eventual runtime may match a
    // response. The marker ciphertext below is not an actual Seal/authentication
    // control, and never enters a live session or a wrapping-key operation.
    @Test func sealedInputCorrelationIsExact() throws {
        let (_, _, review, _) = try archivePublicReviews(archiveRequestV2)
        let request = review.initial.request, preparation = review.preparation
        let pointHex = "045ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032"
        var point = Data()
        var index = pointHex.startIndex
        while index < pointHex.endIndex {
            let next = pointHex.index(index, offsetBy: 2)
            guard let byte = UInt8(pointHex[index..<next], radix: 16) else { Issue.record("Public fixture malformed"); return }
            point.append(byte); index = next
        }
        let blob = Data([1, 2, 3]), fingerprint = SHA256.hash(data: point).map { String(format: "%02x", $0) }.joined()
        let pair = try NativeArchiveJSON.decode(request.pair.canonicalBytes, maximum: 32768, canonical: true)
        let record = NativeArchiveJSON.object([
            ("schema", .string("keyvault-root-grants/1")), ("service", .string(request.service)), ("purpose", .string("root-grants")),
            ("version", .number(request.version)), ("created", .string(request.created)),
            ("profile", .string(RootGrantsPublicRequest.profile)), ("derivation", .string(RootGrantsPublicRequest.derivation)),
            ("path", .string(RootGrantsPublicRequest.path)), ("algorithm", .string("secp256k1-bip340+ecdsa")),
            ("presence", .string("biometry-any-per-signature")), ("public_key", .string(preparation.publicKey)),
            ("seal_public_key", .string(preparation.sealPublicKey)), ("seal_script", .string(preparation.sealScript)),
            ("pair", pair), ("wrapping_point", .string(point.base64EncodedString())), ("wrapping_fingerprint", .string(fingerprint))
        ])
        let envelope = NativeArchiveJSON.object([
            ("schema", .string("keyvault-root-grants-ciphertext/1")),
            ("algorithm", .string("kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM")),
            ("enclave_blob", .string(blob.base64EncodedString())), ("point", .string(point.base64EncodedString())),
            ("fingerprint", .string(fingerprint)), ("ciphertext", .string((point + Data(repeating: 0, count: 84)).base64EncodedString()))
        ])
        let raw = try NativeArchiveJSON.object([("record", record), ("envelope", envelope)]).canonical()
        let sealed = try RootGrantsSealedPublicView(ownedBytes: raw, request: request, preparation: preparation)
        try RootGrantsArchiveBindings.sealedInputs(sealed, point: point, blob: blob)
        archiveExpectRefusal(.bindingMismatch) {
            try RootGrantsArchiveBindings.sealedInputs(sealed, point: request.retainedWrappingPoints[0], blob: blob)
        }
        archiveExpectRefusal(.bindingMismatch) {
            try RootGrantsArchiveBindings.sealedInputs(sealed, point: point, blob: Data([1, 2, 4]))
        }
    }

}
