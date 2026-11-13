// Swift Testing SOURCE: public codecs, comparisons, disposable pipe fixtures
// and actual PUBLIC C Open/Close only. No C Prepare/Seal, owner UI, real tty,
// hardware key, LAContext or Keychain operation is invoked by these tests.
// These controls are not hardware/presence/terminal-restoration proof. NOT_RUN.
import Darwin
import Foundation
import LocalAuthentication
import Security
import Testing
@testable import KeyvaultNativeCore

private let privateRequestV1 = Data(#"{"protocol":"keyvault-root-grants-private/1","engine":"namecoin-root-grants-engine/1","profile":"namecoin-landlord-root/1","mode":"attach","pair_metadata":"eyJzY2hlbWEiOiJrZXl2YXVsdC1yZWNvdmVyeS8xIiwiZ3JvdXBfaWQiOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInNlcnZpY2UiOiJ0ZXN0IiwidmVyc2lvbiI6MSwiY3JlYXRlZCI6IjIwMjYtMDEtMDJUMDM6MDQ6MDVaIiwibm9zdHIiOnsicHVycG9zZSI6Im5vc3RyIiwidmVyc2lvbiI6MiwicGF0aCI6Im0vNDQnLzEyMzcnLzAnLzAvMCIsImFsZ29yaXRobSI6InNlY3AyNTZrMS1iaXAzNDAiLCJwcmVzZW5jZSI6Im5vbmUiLCJwdWJsaWNfa2V5IjoiZDQxYjIyODk5NTQ5ZTFmM2QzMzVhMzEwMDJjZmQzODIxNzQwMDZlMTY2ZDNlNjU4ZTNhNWVlY2RiNjQ2MzU3MyIsIm5wdWIiOiJucHViMTZzZGo5enY0ZjhzbDg1ZTQ1dmdxOW43bnNndDVxcGhwdm1mN3ZrOHI1aGh2bWRqeHg0ZXM4cnE3NGgiLCJ4cHViIjoiIiwib3JpZ2luIjoiIiwid3JhcHBpbmdfcG9pbnQiOiJCR3NYMGZMaExFSkgrTHptNVdPa1FQSjNBMzJCTGVzem9QU2hPVVhZbU1LV1QrTkM0djRhZjV1TzUrdEtmQStlRml2T00xZHJNVjdPeTdaQWFEZS9VZlU9Iiwid3JhcHBpbmdfZmluZ2VycHJpbnQiOiI2OThiZWE2M2RjNDRhMzQ0NjYzZmYxNDI5YWVhMTA4NDJkZjI3YjZiOTkxZWYyNTg2NmIyYzZjMDJjZGNjNWJlIn0sIm5hbWVjb2luIjp7InB1cnBvc2UiOiJuYW1lY29pbiIsInZlcnNpb24iOjEsInBhdGgiOiJtLzg0Jy83Jy8wJyIsImFsZ29yaXRobSI6ImJpcDMyLXNlY3AyNTZrMSIsInByZXNlbmNlIjoiYmlvbWV0cnktYW55IiwicHVibGljX2tleSI6IiIsIm5wdWIiOiIiLCJ4cHViIjoieHB1YjZDQUJRRkhmWEpqM3RLQWJNRGlEaEtBa1pvR1YzUFgzTnQ1ZHNvMlVZOUh5bWY2a1hLaXd6ZTN5SlVGQnJwcXE3aURGeVY0RWdOdXhHNXRMdnhWU3FuWjNFa1F5SzRWclltUEZ6VXlCMWVzIiwib3JpZ2luIjoiWzU3NDcxYTY2Lzg0aC83aC8waF0iLCJ3cmFwcGluZ19wb2ludCI6IkJIenlleGlOQTA5K2lsSTRBd1MxR3NQQWlXbmlkL0liTmFZTFNQeEhacGw0QjNkVkVOdU8wRUFwUFpyR24zUXcyN3A5cmVZODZZSXBuZ1MzblNKNGM5RT0iLCJ3cmFwcGluZ19maW5nZXJwcmludCI6ImE5ZjMwMGViNTk2MGU4OTEzM2FmNzM2MjAxMWExZTI2ZjBlMmVhMmUzNmRjNDAyYTA0YWY2YzE5MmI4OTFhOGMifX0=","pair":{"schema":"keyvault-recovery/1","service":"test","version":1,"group_id":"00000000000000000000000000000000","metadata_sha256":"7b1e72bac729e8c1e8872ac2017e3f1ed236b5340010e183ca4475944fd2465c","nostr_identity":"test","nostr_version":2,"nostr_public_key":"d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573","nostr_npub":"npub16sdj9zv4f8sl85e45vgq9n7nsgt5qphpvmf7vk8r5hhvmdjxx4es8rq74h","namecoin_identity":"test","namecoin_version":1,"namecoin_xpub":"xpub6CABQFHfXJj3tKAbMDiDhKAkZoGV3PX3Nt5dso2UY9Hymf6kXKiwze3yJUFBrpqq7iDFyV4EgNuxG5tLvxVSqnZ3EkQyK4VrYmPFzUyB1es","namecoin_origin":"[57471a66/84h/7h/0h]"},"service":"example-root","version":1,"created":"2026-01-02T03:04:05Z"}"#.utf8)
private let privateRequestV2 = Data(#"{"protocol":"keyvault-root-grants-private/1","engine":"namecoin-root-grants-engine/1","profile":"namecoin-landlord-root/1","mode":"attach","pair_metadata":"eyJzY2hlbWEiOiJrZXl2YXVsdC1yZWNvdmVyeS8yIiwiZ3JvdXBfaWQiOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInNlcnZpY2UiOiJ0ZXN0IiwidmVyc2lvbiI6MSwiY3JlYXRlZCI6IjIwMjYtMDEtMDJUMDM6MDQ6MDVaIiwibm9zdHIiOnsic2VydmljZSI6InRlc3QiLCJwdXJwb3NlIjoibm9zdHIiLCJ2ZXJzaW9uIjoyLCJwYXRoIjoibS80NCcvMTIzNycvMCcvMC8wIiwiYWxnb3JpdGhtIjoic2VjcDI1NmsxLWJpcDM0MCIsInByZXNlbmNlIjoibm9uZSIsInB1YmxpY19rZXkiOiJkNDFiMjI4OTk1NDllMWYzZDMzNWEzMTAwMmNmZDM4MjE3NDAwNmUxNjZkM2U2NThlM2E1ZWVjZGI2NDYzNTczIiwibnB1YiI6Im5wdWIxNnNkajl6djRmOHNsODVlNDV2Z3E5bjduc2d0NXFwaHB2bWY3dms4cjVoaHZtZGp4eDRlczhycTc0aCIsInhwdWIiOiIiLCJvcmlnaW4iOiIiLCJ3cmFwcGluZ19wb2ludCI6IkJHc1gwZkxoTEVKSCtMem01V09rUVBKM0EzMkJMZXN6b1BTaE9VWFltTUtXVCtOQzR2NGFmNXVPNSt0S2ZBK2VGaXZPTTFkck1WN095N1pBYURlL1VmVT0iLCJ3cmFwcGluZ19maW5nZXJwcmludCI6IjY5OGJlYTYzZGM0NGEzNDQ2NjNmZjE0MjlhZWExMDg0MmRmMjdiNmI5OTFlZjI1ODY2YjJjNmMwMmNkY2M1YmUifSwibmFtZWNvaW4iOnsic2VydmljZSI6ImV4YW1wbGUtd2FsbGV0IiwicHVycG9zZSI6Im5hbWVjb2luIiwidmVyc2lvbiI6MSwicGF0aCI6Im0vODQnLzcnLzAnIiwiYWxnb3JpdGhtIjoiYmlwMzItc2VjcDI1NmsxIiwicHJlc2VuY2UiOiJiaW9tZXRyeS1hbnkiLCJwdWJsaWNfa2V5IjoiIiwibnB1YiI6IiIsInhwdWIiOiJ4cHViNkNBQlFGSGZYSmozdEtBYk1EaURoS0FrWm9HVjNQWDNOdDVkc28yVVk5SHltZjZrWEtpd3plM3lKVUZCcnBxcTdpREZ5VjRFZ051eEc1dEx2eFZTcW5aM0VrUXlLNFZyWW1QRnpVeUIxZXMiLCJvcmlnaW4iOiJbNTc0NzFhNjYvODRoLzdoLzBoXSIsIndyYXBwaW5nX3BvaW50IjoiQkh6eWV4aU5BMDkraWxJNEF3UzFHc1BBaVduaWQvSWJOYVlMU1B4SFpwbDRCM2RWRU51TzBFQXBQWnJHbjNRdzI3cDlyZVk4NllJcG5nUzNuU0o0YzlFPSIsIndyYXBwaW5nX2ZpbmdlcnByaW50IjoiYTlmMzAwZWI1OTYwZTg5MTMzYWY3MzYyMDExYTFlMjZmMGUyZWEyZTM2ZGM0MDJhMDRhZjZjMTkyYjg5MWE4YyJ9fQ==","pair":{"schema":"keyvault-recovery/2","service":"test","version":1,"group_id":"00000000000000000000000000000000","metadata_sha256":"04efe3af4d04cfa8337f18ceff15a56a8457fe12cbb3d90ff5157ea29dd60c79","nostr_identity":"test","nostr_version":2,"nostr_public_key":"d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573","nostr_npub":"npub16sdj9zv4f8sl85e45vgq9n7nsgt5qphpvmf7vk8r5hhvmdjxx4es8rq74h","namecoin_identity":"example-wallet","namecoin_version":1,"namecoin_xpub":"xpub6CABQFHfXJj3tKAbMDiDhKAkZoGV3PX3Nt5dso2UY9Hymf6kXKiwze3yJUFBrpqq7iDFyV4EgNuxG5tLvxVSqnZ3EkQyK4VrYmPFzUyB1es","namecoin_origin":"[57471a66/84h/7h/0h]"},"service":"example-root","version":1,"created":"2026-01-02T03:04:05Z"}"#.utf8)

private func privateRefusal(_ expected: RootGrantsStatus, _ operation: () throws -> Void) {
    do { try operation(); Issue.record("Expected exact ROOT refusal") }
    catch let error as RootGrantsReviewError {
        #expect(error.status == expected)
        #expect(error.message == "Root attachment public review refused")
    } catch { Issue.record("Unexpected error type; details withheld") }
}
private func privateReviews(_ raw: Data) throws -> (RootGrantsInitialReview, RootGrantsDerivedReview) {
    let request = try RootGrantsPublicRequest(ownedBytes: raw), initial = try RootGrantsInitialReview(request: request)
    let attach = try RootGrantsPrivateConfirmation.attach(initial, lines: initial.identities + ["ATTACH ROOT GRANTS"])
    let k = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let pair = try NativeArchiveJSON.decode(request.pair.canonicalBytes, maximum: 32768, canonical: true)
    // PUBLIC shape fixture only; never injected into a live C session.
    let bytes = try NativeArchiveJSON.object([("root", .object([
        ("profile", .string(RootGrantsPublicRequest.profile)), ("derivation", .string(RootGrantsPublicRequest.derivation)),
        ("path", .string(RootGrantsPublicRequest.path)), ("algorithm", .string("secp256k1-bip340+ecdsa")),
        ("public_key", .string(k)), ("seal_public_key", .string("02" + k)),
        ("seal_script", .string("76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"))
    ])), ("pair", pair)]).canonical()
    let preparation = try RootGrantsPreparationPublicView(ownedBytes: bytes, request: request)
    return (initial, try RootGrantsDerivedReview(initial: initial, attach: attach, preparation: preparation))
}

struct RootGrantsPrivateTests {
    // Exact finite frame lengths/EOF, not canonical request/engine validity.
    @Test func requestFrameLimitsAndExactEOF() throws {
        for body in [privateRequestV1, privateRequestV2, Data([1]), Data(repeating: 65, count: 262144)] {
            let frame = RootGrantsPrivateFrame.word(UInt32(body.count)) + body
            #expect(try RootGrantsPrivateFrame.request(frame) == body)
            privateRefusal(.invalidArguments) { _ = try RootGrantsPrivateFrame.request(frame + Data([0])) }
            privateRefusal(.invalidArguments) { _ = try RootGrantsPrivateFrame.request(Data(frame.dropLast())) }
        }
        for frame in [Data(), Data([0, 0, 0]), RootGrantsPrivateFrame.word(0),
                      RootGrantsPrivateFrame.word(262145), Data([255, 255, 255, 255])] {
            privateRefusal(.invalidArguments) { _ = try RootGrantsPrivateFrame.request(frame) }
        }
    }

    // PUBLIC/SEALED frame shape and every literal refusal code; no authenticated
    // helper, authentic ciphertext, protected completion or store receipt proof.
    @Test func responseFramesAndClosedRefusals() throws {
        for bytes in [Data([1]), Data(repeating: 65, count: 131072)] {
            let frame = try RootGrantsPrivateFrame.response(.sealed(bytes))
            guard case .sealed(let decoded) = try RootGrantsPrivateFrame.decodeResponse(frame) else {
                Issue.record("Expected sealed public bytes"); return
            }
            #expect(decoded == bytes)
            privateRefusal(.privateProtocolError) { _ = try RootGrantsPrivateFrame.decodeResponse(frame + Data([0])) }
        }
        for raw in 1...20 {
            let status = RootGrantsStatus.closed(Int32(raw))
            let frame = try RootGrantsPrivateFrame.response(.refusal(status))
            #expect(frame == Data([1, 0, 0, 0, 4]) + RootGrantsPrivateFrame.word(UInt32(raw)))
            guard case .refusal(let decoded) = try RootGrantsPrivateFrame.decodeResponse(frame) else {
                Issue.record("Expected fixed refusal"); return
            }
            #expect(decoded == status)
        }
        let closed = try RootGrantsPrivateFrame.response(.refusal(.success))
        #expect(closed == Data([1, 0, 0, 0, 4, 0, 0, 0, 16]))
        for frame in [Data(), Data([2, 0, 0, 0, 1, 0]), Data([0, 0, 0, 0, 0]),
                      Data([1, 0, 0, 0, 3, 0, 0, 1]), Data([1, 0, 0, 0, 4, 0, 0, 0, 0]),
                      Data([1, 0, 0, 0, 4, 0, 0, 0, 21]), Data([1, 0, 0, 0, 4, 255, 255, 255, 255])] {
            privateRefusal(.privateProtocolError) { _ = try RootGrantsPrivateFrame.decodeResponse(frame) }
        }
        privateRefusal(.limitExceeded) { _ = try RootGrantsPrivateFrame.response(.sealed(Data())) }
        privateRefusal(.limitExceeded) { _ = try RootGrantsPrivateFrame.response(.sealed(Data(repeating: 65, count: 131073))) }
    }

    // Full literals only. MATCH is displayed, never typed or represented by a
    // prerequisite stage. EOF is distinct20; UI cancel remains14. No real UI.
    @Test func exactThreeRetypesAndFullLiterals() throws {
        for raw in [privateRequestV1, privateRequestV2] {
            let (initial, derived) = try privateReviews(raw)
            let attach = try RootGrantsPrivateConfirmation.attach(initial, lines: initial.identities + ["ATTACH ROOT GRANTS"])
            #expect(attach.stage == .attachReviewed)
            let store = try RootGrantsPrivateConfirmation.store(derived, line: "STORE ROOT GRANTS")
            #expect(store.stage == .storeReviewed)
            #expect(derived.text.contains("Nostr pin: MATCH"))
            #expect(derived.text.contains("Namecoin account+origin: MATCH"))
            for literal in ["ATTACH", "attach root grants", " ATTACH ROOT GRANTS", "ATTACH ROOT GRANTS ", "MATCH", ""] {
                privateRefusal(.canceled) { _ = try RootGrantsPrivateConfirmation.attach(initial, lines: initial.identities + [literal]) }
            }
            for literal in ["STORE", "MATCH", "store root grants", " STORE ROOT GRANTS", "STORE ROOT GRANTS ", ""] {
                privateRefusal(.canceled) { _ = try RootGrantsPrivateConfirmation.store(derived, line: literal) }
            }
            for entries in [Array(initial.identities.prefix(2)) + ["ATTACH ROOT GRANTS"],
                            ["wrong", initial.identities[1], initial.identities[2], "ATTACH ROOT GRANTS"]] {
                privateRefusal(.canceled) { _ = try RootGrantsPrivateConfirmation.attach(initial, lines: entries) }
            }
            privateRefusal(.inputCanceled) { _ = try RootGrantsPrivateConfirmation.attach(initial, lines: nil) }
            privateRefusal(.inputCanceled) { _ = try RootGrantsPrivateConfirmation.store(derived, line: nil) }
            privateRefusal(.canceled) { _ = try RootGrantsPrivateConfirmation.store(derived, line: String(repeating: "A", count: 129)) }
        }
    }

    // Request/preparation/public display stay complete and immutable. Public
    // fixture preparation never creates a live wrapper's prepared state.
    @Test func immutableDisplayAndChangedSourceRefusal() throws {
        let (initial, review) = try privateReviews(privateRequestV2)
        for text in initial.identities + [initial.request.pair.metadataHash, initial.request.pair.nostrPublicKey,
                     initial.request.pair.xpub, initial.request.pair.origin, review.preparation.publicKey,
                     review.preparation.sealPublicKey, review.preparation.sealScript, RootGrantsPublicRequest.path,
                     "Preserve both existing paired ciphertexts"] { #expect(review.text.contains(text)) }
        #expect(review.text.hasSuffix("END OF COMPLETE MATCH AND STORE REVIEW"))
        privateRefusal(.bindingMismatch) {
            _ = try review.confirmStore("STORE ROOT GRANTS", currentRequest: privateRequestV2 + Data([32]),
                                        currentPreparation: review.preparation.originalBytes)
        }
        privateRefusal(.bindingMismatch) {
            _ = try review.confirmStore("STORE ROOT GRANTS", currentRequest: privateRequestV2,
                                        currentPreparation: review.preparation.originalBytes + Data([32]))
        }
        let session = try NativeRootGrantsArchiveSession(publicRequest: privateRequestV2)
        defer { _ = session.close() }
        let store = try RootGrantsPrivateConfirmation.store(review, line: "STORE ROOT GRANTS")
        privateRefusal(.operationUnavailable) {
            try session.recheckBeforeWrap(store, currentRequest: privateRequestV2, currentPreparation: review.preparation.originalBytes)
        }
        #expect(session.close() == .success)
    }

    // Real PUBLIC Open/new-phase deadline query/Close; no Prepare or hardware.
    // This verifies the admitted new-phase10/zero query form only, not900s timing.
    @Test func actualOpenReviewProbeAndCancellation() throws {
        for raw in [privateRequestV1, privateRequestV2] {
            let cancellation = RootGrantsPrivateCancellation()
            let session = try NativeRootGrantsArchiveSession(publicRequest: raw)
            defer { _ = session.close() }
            try cancellation.publish(session)
            try session.checkReviewDeadline()
            try cancellation.check()
            cancellation.cancel()
            privateRefusal(.canceled) { try cancellation.check() }
            #expect(cancellation.finish() == .success)
            #expect(session.close() == .success)
        }
    }

    // A signal observed before Open publication closes the actual public handle
    // before any Prepare. No signal delivery, private read or terminal is used.
    @Test func cancellationBeforePublicationCannotLoseHandle() throws {
        let cancellation = RootGrantsPrivateCancellation()
        cancellation.cancel()
        let session = try NativeRootGrantsArchiveSession(publicRequest: privateRequestV1)
        defer { _ = session.close() }
        privateRefusal(.canceled) { try cancellation.publish(session) }
        #expect(session.close() == .success)
        #expect(cancellation.finish() == .success)
    }

    // Disposable real kernel pipes, no std-fd mutation or owner/application state.
    // This is OS classification source, not executed pipe/GUI/TTY qualification.
    @Test func actualAnonymousPipeIdentityControls() throws {
        var fds = [Int32](repeating: -1, count: 2)
        let result = fds.withUnsafeMutableBufferPointer { Darwin.pipe($0.baseAddress!) }
        #expect(result == 0)
        guard result == 0 else { return }
        defer { _ = Darwin.close(fds[0]); _ = Darwin.close(fds[1]) }
        let readIdentity = try RootGrantsPrivatePipes.identity(fds[0], writing: false)
        #expect(try RootGrantsPrivatePipes.identity(fds[0], writing: false) == readIdentity)
        _ = try RootGrantsPrivatePipes.identity(fds[1], writing: true)
        privateRefusal(.invalidArguments) { _ = try RootGrantsPrivatePipes.identity(fds[0], writing: true) }
        privateRefusal(.invalidArguments) { _ = try RootGrantsPrivatePipes.identity(-1, writing: false) }
    }

    // Named/unlinked FIFOs remain vnode descriptors and cannot masquerade as
    // anonymous pipes. Only new disposable PUBLIC fixture paths are modified.
    @Test func linkedAndUnlinkedFIFORefuse() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("public-fifo").path
        #expect(mkfifo(path, 0o600) == 0)
        let fd = Darwin.open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
        #expect(fd >= 0)
        guard fd >= 0 else { return }
        defer { _ = Darwin.close(fd) }
        let flags = fcntl(fd, F_GETFL)
        #expect(fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == 0)
        privateRefusal(.invalidArguments) { _ = try RootGrantsPrivatePipes.identity(fd, writing: false) }
        #expect(Darwin.unlink(path) == 0)
        privateRefusal(.invalidArguments) { _ = try RootGrantsPrivatePipes.identity(fd, writing: false) }
    }

    // Synthetic error classification only; generic/auth/hardware errors cannot
    // stand in for the REAL required silent ECDH refusal. No key is constructed.
    @Test func silentProbeRequiresKnownNoninteractiveDenial() {
        #expect(RootGrantsSilentProbe.refused(NSError(domain: NSOSStatusErrorDomain, code: Int(Security.errSecInteractionNotAllowed))))
        #expect(RootGrantsSilentProbe.refused(NSError(domain: LAError.errorDomain, code: LAError.Code.notInteractive.rawValue)))
        for error in [NSError(domain: NSOSStatusErrorDomain, code: Int(Security.errSecAuthFailed)),
                      NSError(domain: NSOSStatusErrorDomain, code: Int(Security.errSecNotAvailable)),
                      NSError(domain: "public-fixture", code: Int(Security.errSecInteractionNotAllowed))] {
            #expect(!RootGrantsSilentProbe.refused(error))
        }
    }
}

// Completion controls below use PUBLIC inert bytes and the production codec/state.
// They do not authenticate a real helper/PID, execute private C Prepare/Seal,
// qualify terminal cleanup, perform add/store or prove hardware behavior. NOT_RUN.
extension RootGrantsPrivateTests {
    // Literal vector independently calculated from the two explicit 20-byte
    // buffers and the written domain/BE32 framing. Neither is an engine record.
    @Test func completionIndependentDigestAndExactByteBinding() throws {
        let request = Data(#"{"public":"request"}"#.utf8)
        let sealed = Data(#"{"sealed":"fixture"}"#.utf8)
        let expected = "4b5647323c93c2c25db5772f9283ac282c0b83c7009d28ea7823ba6d3f934021ea490fd1"
        let ack = try RootGrantsPrivateAcknowledgement.bytes(request: request, sealed: sealed)
        #expect(ack.map { String(format: "%02x", $0) }.joined() == expected)
        #expect(ack.count == 36 && ack.prefix(4) == Data("KVG2".utf8))
        for changed in [request + Data([10]), Data(request.dropLast()), sealed] {
            #expect(try RootGrantsPrivateAcknowledgement.bytes(request: changed, sealed: sealed) != ack)
        }
        #expect(try RootGrantsPrivateAcknowledgement.bytes(request: request, sealed: sealed + Data([10])) != ack)
        #expect(try RootGrantsPrivateAcknowledgement.bytes(request: sealed, sealed: request) != ack)
        for (r, s) in [(Data(), sealed), (request, Data()),
                       (Data(repeating: 0, count: 262145), sealed), (request, Data(repeating: 0, count: 131073))] {
            privateRefusal(.privateProtocolError) { _ = try RootGrantsPrivateAcknowledgement.bytes(request: r, sealed: s) }
        }
        #expect(try RootGrantsPrivateAcknowledgement.bytes(request: Data(repeating: 0, count: 262144),
                                                          sealed: Data(repeating: 0, count: 131072)).count == 36)
    }

    // Both canonical request versions are genuinely decoded; the sealed body is
    // explicitly an inert transport fixture, never a validated sealed result.
    // Waiting state models liveness only; it cannot attest a real PID/code check.
    @Test func completionWaitsForExactACKThenEOFForBothRequests() throws {
        for original in [privateRequestV1, privateRequestV2] {
            let (initial, _) = try privateReviews(original)
            var request = initial.request.originalBytes
            let sealed = Data(#"{"sealed":"fixture"}"#.utf8)
            let ack = try RootGrantsPrivateAcknowledgement.bytes(request: request, sealed: sealed)
            var completion = RootGrantsPrivateCompletion()
            let frame = try completion.frame(request: request, payload: .sealed(sealed))
            #expect(frame == Data([0]) + RootGrantsPrivateFrame.word(UInt32(sealed.count)) + sealed)
            #expect(completion.phase == .awaitingAcknowledgement)
            request.append(10) // Frozen expected digest must not re-read caller bytes.
            try completion.acknowledge(ack)
            #expect(completion.phase == .awaitingEOF)
            try completion.endOfInput(trailing: Data())
            #expect(completion.phase == .complete)
            privateRefusal(.privateProtocolError) { _ = try completion.frame(request: original, payload: .sealed(sealed)) }
            #expect(completion.phase == .failed)
        }
    }

    // Missing/short/malformed/wrong/duplicate ACK must fail closed with no second
    // frame. These are pure parser/state effects, not I/O or native-failure proof.
    @Test func malformedACKAndMissingEOFConsumeTheAttempt() throws {
        let sealed = Data([1, 2, 3])
        let ack = try RootGrantsPrivateAcknowledgement.bytes(request: privateRequestV1, sealed: sealed)
        var wrong = ack; wrong[wrong.count - 1] ^= 1
        var prefix = ack; prefix[0] ^= 1
        for invalid in [Data(), Data(ack.prefix(35)), Data(ack.dropFirst()), wrong, prefix,
                        ack + Data([0]), ack + ack] {
            var completion = RootGrantsPrivateCompletion()
            _ = try completion.frame(request: privateRequestV1, payload: .sealed(sealed))
            privateRefusal(.privateProtocolError) { try completion.acknowledge(invalid) }
            #expect(completion.phase == .failed)
            privateRefusal(.privateProtocolError) { _ = try completion.frame(request: privateRequestV1, payload: .refusal(.canceled)) }
        }
        var missing = RootGrantsPrivateCompletion()
        _ = try missing.frame(request: privateRequestV1, payload: .sealed(sealed))
        privateRefusal(.privateProtocolError) { try missing.endOfInput(trailing: Data()) }
        #expect(missing.phase == .failed)
        for extra in [Data([0]), ack] {
            var trailing = RootGrantsPrivateCompletion()
            _ = try trailing.frame(request: privateRequestV1, payload: .sealed(sealed))
            try trailing.acknowledge(ack)
            privateRefusal(.privateProtocolError) { try trailing.endOfInput(trailing: extra) }
            #expect(trailing.phase == .failed)
        }
        var duplicate = RootGrantsPrivateCompletion()
        _ = try duplicate.frame(request: privateRequestV1, payload: .sealed(sealed))
        try duplicate.acknowledge(ack)
        privateRefusal(.privateProtocolError) { try duplicate.acknowledge(ack) }
    }

    // Every known refusal has EOF/no-ACK completion. No refusal or malformed
    // construction may open a retry/frame path. No actual process is launched.
    @Test func refusalRequiresEOFWithoutACKAndRemainsOneShot() throws {
        for raw in 1...20 {
            var completion = RootGrantsPrivateCompletion()
            let frame = try completion.frame(request: nil, payload: .refusal(.closed(Int32(raw))))
            #expect(frame == Data([1, 0, 0, 0, 4]) + RootGrantsPrivateFrame.word(UInt32(raw)))
            #expect(completion.phase == .awaitingEOF)
            try completion.endOfInput(trailing: Data())
            #expect(completion.phase == .complete)
        }
        var invalid = RootGrantsPrivateCompletion()
        _ = try invalid.frame(request: nil, payload: .refusal(.invalidArguments))
        privateRefusal(.privateProtocolError) { try invalid.endOfInput(trailing: Data([75])) }
        var forbiddenACK = RootGrantsPrivateCompletion()
        _ = try forbiddenACK.frame(request: nil, payload: .refusal(.canceled))
        privateRefusal(.privateProtocolError) { try forbiddenACK.acknowledge(Data(repeating: 0, count: 36)) }
        for body in [Data(), Data(repeating: 0, count: 131073)] {
            var failed = RootGrantsPrivateCompletion()
            privateRefusal(.limitExceeded) { _ = try failed.frame(request: privateRequestV1, payload: .sealed(body)) }
            #expect(failed.phase == .failed)
            privateRefusal(.privateProtocolError) { _ = try failed.frame(request: nil, payload: .refusal(.canceled)) }
        }
        var noRequest = RootGrantsPrivateCompletion()
        privateRefusal(.privateProtocolError) { _ = try noRequest.frame(request: nil, payload: .sealed(Data([1]))) }
        #expect(noRequest.phase == .failed)
    }

    // Explicit inert peer model for the post-ACK ordering regression. The real
    // Go parent still owns full bindings, actual PID/code and plan/add authority.
    // Model counters are not production receipts or evidence of native success.
    @Test func modeledParentReadsTrailingOutputOnlyAfterACKAndStdinClose() throws {
        for extra in [Data(), Data([0])] {
            var helper = RootGrantsPrivateCompletion()
            let body = Data([1, 2, 3]), request = privateRequestV2
            let frame = try helper.frame(request: request, payload: .sealed(body))
            let stdout = frame + extra
            var trace = ["frame"]
            guard case .sealed(let copied) = try RootGrantsPrivateFrame.decodeResponse(Data(stdout.prefix(frame.count))) else {
                Issue.record("Expected bounded public fixture frame"); return
            }
            #expect(copied == body && helper.phase == .awaitingAcknowledgement)
            trace += ["modeled-bindings", "modeled-live-pid"]
            let ack = try RootGrantsPrivateAcknowledgement.bytes(request: request, sealed: copied)
            try helper.acknowledge(ack); trace.append("ack")
            try helper.endOfInput(trailing: Data()); trace.append("stdin-close")
            #expect(helper.phase == .complete)
            trace.append("post-ack-stdout-read")
            let leftover = Data(stdout.dropFirst(frame.count))
            var modeledOwnedCompletions = 0
            let postACKRead = {
                guard leftover.isEmpty else { throw RootGrantsReviewError(status: .privateProtocolError) }
                modeledOwnedCompletions += 1
            }
            if extra.isEmpty {
                try postACKRead()
                #expect(modeledOwnedCompletions == 1)
            } else {
                privateRefusal(.privateProtocolError) { try postACKRead() }
                #expect(modeledOwnedCompletions == 0 && leftover == Data([0]))
            }
            #expect(trace == ["frame", "modeled-bindings", "modeled-live-pid", "ack", "stdin-close", "post-ack-stdout-read"])
        }
        // A frame-writing peer that has exited cannot receive the live-PID
        // check/ACK: the modeled parent has zero owned completions in this case.
        for peer in [(alive: false, exit: Int32(0)), (alive: true, exit: Int32(1))] {
            var helper = RootGrantsPrivateCompletion()
            let body = Data([1])
            _ = try helper.frame(request: privateRequestV1, payload: .sealed(body))
            var ackSent = false, ownedCompletions = 0
            if peer.alive {
                try helper.acknowledge(RootGrantsPrivateAcknowledgement.bytes(request: privateRequestV1, sealed: body))
                ackSent = true
                try helper.endOfInput(trailing: Data())
                if peer.exit == 0 { ownedCompletions = 1 }
            }
            #expect(ackSent == peer.alive)
            #expect(ownedCompletions == 0)
        }
    }

    // Fixed monotonic boundary controls in each actual public completion state. No sleep or
    // native/C clock is replaced, and no real900s/cancellation timing is proven.
    @Test func originalDeadlineSurvivesResponseACKAndEOFWithoutRenewal() throws {
        let start: UInt64 = 1_000
        let deadline = RootGrantsPrivateDeadline(startedAt: start)
        #expect(deadline.expiresAt == start + 900_000_000_000)
        let body = Data([1])
        let ack = try RootGrantsPrivateAcknowledgement.bytes(request: privateRequestV1, sealed: body)
        for phase in [RootGrantsPrivateCompletion.Phase.ready, .awaitingAcknowledgement, .awaitingEOF, .complete] {
            var completion = RootGrantsPrivateCompletion()
            try deadline.check(at: start)
            if phase != .ready { _ = try completion.frame(request: privateRequestV1, payload: .sealed(body)) }
            if phase == .awaitingEOF || phase == .complete { try completion.acknowledge(ack) }
            if phase == .complete { try completion.endOfInput(trailing: Data()) }
            #expect(completion.phase == phase)
            try deadline.check(at: start + 120_000_000_001) // No nested120s cap.
            try deadline.check(at: deadline.expiresAt - 1)
            privateRefusal(.timeout) { try deadline.check(at: deadline.expiresAt) }
            privateRefusal(.timeout) { try deadline.check(at: deadline.expiresAt + 1) }
            #expect(deadline.expiresAt == start + 900_000_000_000)
        }
        privateRefusal(.timeout) { try deadline.check(at: start - 1) }
    }

    // Actual PUBLIC C Open/Close only. After cleanup the outer cancellation path
    // must remain usable without querying closed C. No Prepare/Seal/UI/hardware.
    @Test func publicCloseThenCompletionCancellationKeepsClosedSession() throws {
        let cancellation = RootGrantsPrivateCancellation()
        let session = try NativeRootGrantsArchiveSession(publicRequest: privateRequestV1)
        defer { _ = session.close() }
        try cancellation.publish(session)
        #expect(cancellation.finish() == .success)
        try cancellation.check()
        cancellation.cancel(.timeout)
        privateRefusal(.timeout) { try cancellation.check() }
        #expect(cancellation.finish() == .success)
        #expect(session.close() == .success)
    }
}
