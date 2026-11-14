// Swift Testing SOURCE: public codecs, disposable pipe/PTY fixtures and actual
// PUBLIC C Open/Close only. PTY controls run the production terminal reader and
// verify cleanup; no helper, C Prepare/Seal, owner controlling tty, hardware
// key, LAContext or Keychain operation is invoked by these tests.
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
    let attach = try initial.confirm(currentRequest: raw)
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
    // Claim: both ordered helper checkpoints carry the original remaining
    // deadline and only fixed frames; parent refusals stay closed at 1..24.
    @Test func orderedVaultRecheckControlAndRefusalFrames() throws {
        let first = try RootGrantsPrivateControl.recheck(stage: 1, remainingNanoseconds: 7_000_000_000)
        let second = try RootGrantsPrivateControl.recheck(stage: 2, remainingNanoseconds: 6_000_000_000)
        #expect(first.first == 2 && second.first == 2)
        #expect(try RootGrantsPrivateFrame.number(Data(first.dropFirst().prefix(4))) == 12)
        #expect(first.suffix(4) == Data([75, 86, 82, 51]))
        #expect(second.suffix(4) == Data([75, 86, 82, 52]))
        privateRefusal(.privateProtocolError) { _ = try RootGrantsPrivateControl.recheck(stage: 2, remainingNanoseconds: 0) }
        privateRefusal(.privateProtocolError) { _ = try RootGrantsPrivateControl.recheck(stage: 3, remainingNanoseconds: 1) }
        try RootGrantsPrivateControl.response(status: 0, length: 0, payload: Data())
        for raw in 21...24 {
            do {
                try RootGrantsPrivateControl.response(status: 1, length: 4,
                    payload: RootGrantsPrivateFrame.word(UInt32(raw)))
                Issue.record("Expected parent vault refusal")
            } catch let error as RootGrantsReviewError {
                #expect(error.status == RootGrantsStatus.helperClosed(Int32(raw)))
            }
        }
        privateRefusal(.privateProtocolError) {
            try RootGrantsPrivateControl.response(status: 1, length: 4, payload: RootGrantsPrivateFrame.word(25))
        }
    }

    // Claim: native cancellation reaches an already-open helper signing
    // context; deadline checks use the same monotonic budget.
    @Test func cancellationPropagatesToSigningContext() throws {
        let start = DispatchTime.now().uptimeNanoseconds
        let deadline = RootGrantsPrivateDeadline(startedAt: start, budget: 500_000_000_000)
        let cancellation = RootGrantsPrivateCancellation(deadline: deadline)
        var cancelled = 0
        try cancellation.setSigningCancellation { cancelled += 1 }
        cancellation.cancel(.timeout)
        #expect(cancelled == 1)
        privateRefusal(.timeout) { try cancellation.check() }
        try cancellation.setSigningCancellation(nil)
        #expect(try deadline.remaining(at: start + 499_000_000_000) == 1_000_000_000)
        privateRefusal(.timeout) { _ = try deadline.remaining(at: start + 500_000_000_000) }
    }

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
        for raw in 1...24 {
            let status = RootGrantsStatus.helperClosed(Int32(raw))
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
                      Data([1, 0, 0, 0, 4, 0, 0, 0, 25]), Data([1, 0, 0, 0, 4, 255, 255, 255, 255])] {
            privateRefusal(.privateProtocolError) { _ = try RootGrantsPrivateFrame.decodeResponse(frame) }
        }
        privateRefusal(.limitExceeded) { _ = try RootGrantsPrivateFrame.response(.sealed(Data())) }
        privateRefusal(.limitExceeded) { _ = try RootGrantsPrivateFrame.response(.sealed(Data(repeating: 65, count: 131073))) }
    }

    // Only Return confirms; other keys are ignored, Ctrl-C cancels, and EOF is closed.
    @Test func terminalConfirmationKeysAndCancellation() throws {
        for raw in [privateRequestV1, privateRequestV2] {
            let (initial, derived) = try privateReviews(raw)
            let attach = try initial.confirm(currentRequest: raw)
            #expect(attach.stage == .attachReviewed)
            let store = try derived.confirm(currentRequest: raw, currentPreparation: derived.preparation.originalBytes)
            #expect(store.stage == .storeReviewed)
            #expect(derived.text.contains("Nostr pin: MATCH"))
            #expect(derived.text.contains("Namecoin account+origin: MATCH"))
            #expect(derived.text.contains(derived.preparation.publicKey))
            let displayed = RootGrantsTerminalReview.promptText(initial.text)
            #expect(displayed.contains(String(decoding: initial.request.originalBytes, as: UTF8.self)))
            for identity in initial.identities { #expect(displayed.contains(identity)) }
            #expect(displayed.contains("Press Return to continue; Ctrl-C cancels."))
        }
        var keys: [UInt8] = [120, 121, 13]
        var proceeded = 0
        try RootGrantsTerminalReview.checkpoint(confirm: {
            try RootGrantsTerminalConfirmationKey.awaitReturn {
                keys.isEmpty ? nil : keys.removeFirst()
            }
        }) { proceeded += 1 }
        #expect(proceeded == 1)
        for checkpoint in [[UInt8(120), 3], [UInt8(120)]] {
            var keys = checkpoint
            let expected: RootGrantsStatus = checkpoint.last == 3 ? .canceled : .inputCanceled
            privateRefusal(expected) {
                try RootGrantsTerminalConfirmationKey.awaitReturn {
                    keys.isEmpty ? nil : keys.removeFirst()
                }
            }
        }
        var prepares = 0
        var prepareKeys: [UInt8] = [3]
        privateRefusal(.canceled) {
            try RootGrantsTerminalReview.checkpoint(confirm: {
                try RootGrantsTerminalConfirmationKey.awaitReturn {
                    prepareKeys.isEmpty ? nil : prepareKeys.removeFirst()
                }
            }) { prepares += 1 }
        }
        #expect(prepares == 0)
        var stores = 0
        var storeKeys: [UInt8] = [3]
        privateRefusal(.canceled) {
            try RootGrantsTerminalReview.checkpoint(confirm: {
                try RootGrantsTerminalConfirmationKey.awaitReturn {
                    storeKeys.isEmpty ? nil : storeKeys.removeFirst()
                }
            }) { stores += 1 }
        }
        #expect(stores == 0)
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
            _ = try review.confirm(currentRequest: privateRequestV2 + Data([32]),
                                   currentPreparation: review.preparation.originalBytes)
        }
        privateRefusal(.bindingMismatch) {
            _ = try review.confirm(currentRequest: privateRequestV2,
                                   currentPreparation: review.preparation.originalBytes + Data([32]))
        }
        let session = try NativeRootGrantsArchiveSession(publicRequest: privateRequestV2)
        defer { _ = session.close() }
        let store = try review.confirm(currentRequest: privateRequestV2,
                                       currentPreparation: review.preparation.originalBytes)
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

@Suite
struct RootGrantsPrivateFlowTests {
    // This is the exact staged flow called by rootGrantsPrivate. Refusals at
    // either production confirmation must prevent every later store/wrap/seal
    // effect; two generic checkpoint fixtures alone do not prove this wiring.
    @Test func productionFlowRequiresBothDistinctConfirmations() throws {
        struct PreparedReview { let text: String }
        let initialText = "FIRST: stored pair and identities"
        let preparedText = "SECOND: MATCH lines and preparation key"

        for refusedConfirmation in 1...2 {
            var confirmations: [String] = []
            var attachCount = 0, prepareCount = 0, storeCount = 0, wrapCount = 0, sealCount = 0
            privateRefusal(.canceled) {
                _ = try RootGrantsPrivateFlow.perform(
                    initialText: initialText,
                    reviewText: { $0.text },
                    confirm: { text in
                        confirmations.append(text)
                        if confirmations.count == refusedConfirmation {
                            throw RootGrantsReviewError(status: .canceled)
                        }
                    },
                    attach: { attachCount += 1; return "attach-confirmation" },
                    prepare: { _ in prepareCount += 1; return PreparedReview(text: preparedText) },
                    store: { _ in storeCount += 1; return "store-confirmation" },
                    wrap: { _, _ in wrapCount += 1; return "qualified-wrap" },
                    seal: { _, _, _ in sealCount += 1; return "sealed" }
                )
            }
            #expect(confirmations == Array([initialText, preparedText].prefix(refusedConfirmation)))
            #expect(attachCount == (refusedConfirmation == 1 ? 0 : 1))
            #expect(prepareCount == (refusedConfirmation == 1 ? 0 : 1))
            #expect(storeCount == 0 && wrapCount == 0 && sealCount == 0)
        }

        var events: [String] = []
        let sealed = try RootGrantsPrivateFlow.perform(
            initialText: initialText,
            reviewText: { $0.text },
            confirm: { events.append("confirm:" + $0) },
            attach: { events.append("attach"); return "attach-confirmation" },
            prepare: { _ in events.append("prepare"); return PreparedReview(text: preparedText) },
            store: { _ in events.append("store"); return "store-confirmation" },
            wrap: { _, _ in events.append("wrap"); return "qualified-wrap" },
            seal: { _, _, _ in events.append("seal"); return "sealed" }
        )
        #expect(sealed == "sealed")
        #expect(events == ["confirm:" + initialText, "attach", "prepare", "confirm:" + preparedText,
                           "store", "wrap", "seal"])
    }
}

private enum RootGrantsPTYOutcomeValue {
    case accepted
    case refused(RootGrantsStatus)
}

private final class RootGrantsPTYOutcome {
    private let lock = NSLock()
    private var value: RootGrantsPTYOutcomeValue?
    let finished = DispatchGroup()

    init() { finished.enter() }

    func finish(_ value: RootGrantsPTYOutcomeValue) {
        lock.lock(); self.value = value; lock.unlock()
        finished.leave()
    }
    func snapshot() -> RootGrantsPTYOutcomeValue? {
        lock.lock(); defer { lock.unlock() }
        return value
    }
}

private final class RootGrantsPTYFlowEffects {
    private let lock = NSLock()
    private var values: [String] = []

    func append(_ value: String) {
        lock.lock(); values.append(value); lock.unlock()
    }

    func snapshot() -> [String] {
        lock.lock(); defer { lock.unlock() }
        return values
    }
}

// Disposable PTY controls enter the same production reader core used after
// /dev/tty admission. They do not exercise the helper, vault, Keychain or UI.
@Suite(.serialized)
struct RootGrantsTerminalPTYTests {
    private let promptSuffix = Data("Press Return to continue; Ctrl-C cancels.".utf8)

    @Test func catchableSignalSetIncludesTerminalAndJobControlSignals() {
        #expect(Set(RootGrantsPrivateSignals.handledSignals) ==
                Set([SIGINT, SIGHUP, SIGQUIT, SIGTERM, SIGTSTP, SIGTTIN, SIGTTOU]))
    }

    @Test func productionReaderUsesSelectAndAcceptsFreshReturn() throws {
        let (master, slave, original) = try makePTY()
        let cancellation = RootGrantsPrivateCancellation()
        let armed = DispatchSemaphore(value: 0)
        let outcome = startReader(slave: slave, text: "PTY production reader",
                                  cancellation: cancellation, afterArming: { armed.signal() })
        defer {
            cancellation.cancel()
            _ = outcome.finished.wait(timeout: .now() + .seconds(3))
            _ = Darwin.close(master); _ = Darwin.close(slave)
        }
        guard outcome.finished.wait(timeout: .now() + .milliseconds(250)) == .timedOut else {
            Issue.record("Reader exited before rendering its prompt: \(String(describing: outcome.snapshot()))")
            return
        }
        let output = try readUntil(master, suffix: promptSuffix)
        #expect(output.range(of: promptSuffix) != nil)
        #expect(armed.wait(timeout: .now() + .seconds(3)) == .success)
        try writePTY(master, Data([13]))
        #expect(outcome.finished.wait(timeout: .now() + .seconds(3)) == .success)
        guard case .accepted? = outcome.snapshot() else {
            Issue.record("The production terminal reader did not accept the fresh Return: \(String(describing: outcome.snapshot()))")
            return
        }
        #expect(sameTermios(original, try currentTermios(slave)))
    }

    @Test func darwinSelectControlSeesDisposablePTYReadiness() throws {
        let (master, slave, _) = try makePTY()
        defer { _ = Darwin.close(master); _ = Darwin.close(slave) }
        var writable = emptyFDSet()
        __darwin_fd_set(slave, &writable)
        var timeout = timeval(tv_sec: 1, tv_usec: 0)
        let canWrite = Darwin.select(slave + 1, nil, &writable, nil, &timeout)
        #expect(canWrite > 0 && __darwin_fd_isset(slave, &writable) != 0)
        let sent: UInt8 = 0x5a
        let wrote = withUnsafeBytes(of: sent) { Darwin.write(slave, $0.baseAddress!, 1) }
        #expect(wrote == 1)
        var readable = emptyFDSet()
        __darwin_fd_set(master, &readable)
        timeout = timeval(tv_sec: 1, tv_usec: 0)
        let canRead = Darwin.select(master + 1, &readable, nil, nil, &timeout)
        #expect(canRead > 0 && __darwin_fd_isset(master, &readable) != 0)
        var received: UInt8 = 0
        #expect(Darwin.read(master, &received, 1) == 1)
        #expect(received == sent)
    }

    @Test func typeaheadBeforeAndDuringRenderingNeedsFreshReturn() throws {
        for duringRendering in [false, true] {
            let (master, slave, original) = try makePTY()
            let cancellation = RootGrantsPrivateCancellation()
            let armed = DispatchSemaphore(value: 0)
            let text = duringRendering ? String(repeating: "R", count: 64 * 1024) : "short review"
            if !duringRendering { try writePTY(master, Data([13])) }
            let outcome = startReader(slave: slave, text: text,
                                      cancellation: cancellation, afterArming: { armed.signal() })
            defer {
                cancellation.cancel()
                _ = outcome.finished.wait(timeout: .now() + .seconds(3))
                _ = Darwin.close(master); _ = Darwin.close(slave)
            }
            var output = Data()
            if duringRendering {
                let first = try readSome(master, maximum: 2048)
                #expect(!first.isEmpty)
                #expect(first.count < RootGrantsTerminalReview.promptText(text).utf8.count)
                output.append(first)
                try writePTY(master, Data([13])) // Arrives while a long review is still rendering.
            }
            output = try readUntil(master, suffix: promptSuffix, startingWith: output)
            #expect(output.range(of: promptSuffix) != nil)
            #expect(armed.wait(timeout: .now() + .seconds(3)) == .success)
            #expect(outcome.finished.wait(timeout: .now() + .milliseconds(250)) == .timedOut,
                    "Queued Return must be discarded before the reader is armed")
            try writePTY(master, Data([13]))
            #expect(outcome.finished.wait(timeout: .now() + .seconds(3)) == .success)
            guard case .accepted? = outcome.snapshot() else {
                Issue.record("A fresh Return should confirm after queued input is discarded: \(String(describing: outcome.snapshot()))")
                return
            }
            #expect(sameTermios(original, try currentTermios(slave)))
        }
    }

    @Test func cancellationDeadlineAndIOErrorFlushQueuedTailBeforeRestore() throws {
        try assertQueuedTailIsGone(cause: .ctrlC)
        try assertQueuedTailIsGone(cause: .deadline)
        try assertQueuedTailIsGone(cause: .ioError)
    }

    @Test func processSignalCancelsReaderAndRestoresPTY() throws {
        for signalNumber in RootGrantsPrivateSignals.handledSignals {
            // Keep even job-control and core-dump signals ignored at the test
            // process boundary. The production DispatchSource must still
            // observe each one and cancel the active reader.
            let previousDisposition = Darwin.signal(signalNumber, SIG_IGN)
            defer { _ = Darwin.signal(signalNumber, previousDisposition) }
            let (master, slave, original) = try makePTY()
            let cancellation = RootGrantsPrivateCancellation()
            let queue = DispatchQueue(label: "root-grants-pty-signal-control")
            let signals = RootGrantsPrivateSignals(cancellation: cancellation, queue: queue)
            let outcome = startReader(slave: slave, text: "signal cleanup",
                                      cancellation: cancellation, afterArming: {
                // No Return here: the signal, not a queued key, must cancel.
                try writePTY(master, Data("PRIVATE-TAIL".utf8))
                guard Darwin.kill(getpid(), signalNumber) == 0 else {
                    throw RootGrantsReviewError(status: .privateProtocolError)
                }
            })
            defer {
                cancellation.cancel()
                _ = outcome.finished.wait(timeout: .now() + .seconds(3))
                signals.stop()
                _ = Darwin.close(master); _ = Darwin.close(slave)
            }
            _ = try readUntil(master, suffix: promptSuffix)
            #expect(outcome.finished.wait(timeout: .now() + .seconds(3)) == .success)
            guard case .refused(.canceled)? = outcome.snapshot() else {
                Issue.record("Catchable signal \(signalNumber) must safely cancel the raw-mode reader; observed \(String(describing: outcome.snapshot()))")
                return
            }
            #expect(sameTermios(original, try currentTermios(slave)))
            assertNoQueuedBytes(slave)
        }
    }

    @Test func productionFlowCancelsAtFirstRawOutputCheckBeforeAnyEffect() throws {
        let (initial, _) = try privateReviews(privateRequestV2)
        let (master, slave, original) = try makePTY()
        let cancellation = RootGrantsPrivateCancellation()
        let armed = DispatchSemaphore(value: 0)
        let effects = RootGrantsPTYFlowEffects()
        var injectCancel = true
        let outcome = startFlow(slave: slave, initialText: initial.text,
                                cancellation: cancellation, effects: effects,
                                checkOutput: {
            if injectCancel {
                injectCancel = false
                try writePTY(master, Data([3]))
            }
        }, afterArming: { armed.signal() })
        defer {
            cancellation.cancel()
            _ = outcome.finished.wait(timeout: .now() + .seconds(3))
            _ = Darwin.close(master); _ = Darwin.close(slave)
        }
        let finishedAfterCancel = outcome.finished.wait(timeout: .now() + .milliseconds(500))
        #expect(finishedAfterCancel == .success, "Ctrl-C at the first raw-mode output check must cancel")
        if finishedAfterCancel == .timedOut {
            _ = try readUntil(master, suffix: promptSuffix)
            #expect(armed.wait(timeout: .now() + .seconds(3)) == .success)
            try writePTY(master, Data([13]))
            #expect(outcome.finished.wait(timeout: .now() + .seconds(3)) == .success)
        }
        guard case .refused(.canceled)? = outcome.snapshot() else {
            Issue.record("First-output Ctrl-C was discarded; later Return accepted: \(String(describing: outcome.snapshot()))")
            return
        }
        #expect(effects.snapshot().isEmpty)
        #expect(sameTermios(original, try currentTermios(slave)))
        assertNoQueuedBytes(slave)
    }

    @Test func productionFlowCancelsDuringReviewRenderingBeforeAnyEffect() throws {
        let (initial, _) = try privateReviews(privateRequestV2)
        let (master, slave, original) = try makePTY()
        let cancellation = RootGrantsPrivateCancellation()
        let armed = DispatchSemaphore(value: 0)
        let effects = RootGrantsPTYFlowEffects()
        let longReview = initial.text + "\n" + String(repeating: "R", count: 64 * 1024)
        let outcome = startFlow(slave: slave, initialText: longReview,
                                cancellation: cancellation, effects: effects,
                                afterArming: { armed.signal() })
        defer {
            cancellation.cancel()
            _ = outcome.finished.wait(timeout: .now() + .seconds(3))
            _ = Darwin.close(master); _ = Darwin.close(slave)
        }
        let first = try readSome(master, maximum: 2048)
        #expect(!first.isEmpty && first.count < RootGrantsTerminalReview.promptText(longReview).utf8.count)
        try writePTY(master, Data([3]))
        let finishedAfterCancel = outcome.finished.wait(timeout: .now() + .milliseconds(500))
        #expect(finishedAfterCancel == .success, "Ctrl-C while rendering must cancel without a later key")
        if finishedAfterCancel == .timedOut {
            _ = try readUntil(master, suffix: promptSuffix, startingWith: first)
            #expect(armed.wait(timeout: .now() + .seconds(3)) == .success)
            try writePTY(master, Data([13]))
            #expect(outcome.finished.wait(timeout: .now() + .seconds(3)) == .success)
        }
        guard case .refused(.canceled)? = outcome.snapshot() else {
            Issue.record("Rendering-time Ctrl-C was discarded; later Return accepted: \(String(describing: outcome.snapshot()))")
            return
        }
        #expect(effects.snapshot().isEmpty)
        #expect(sameTermios(original, try currentTermios(slave)))
        assertNoQueuedBytes(slave)
    }

    private enum ExitCause: Equatable { case ctrlC, deadline, ioError }

    private func assertQueuedTailIsGone(cause: ExitCause) throws {
        let (master, slave, original) = try makePTY()
        let cancellation = RootGrantsPrivateCancellation()
        var failOutput = false
        let tail = cause == .ctrlC ? Data([3, 84, 65, 73, 76, 10]) : Data("PRIVATE-TAIL\n".utf8)
        let outcome = startReader(slave: slave, text: "cleanup",
            cancellation: cancellation,
            checkOutput: {
                if failOutput { throw RootGrantsReviewError(status: .terminalRequired) }
            },
            afterArming: {
                try writePTY(master, tail)
                if cause == .deadline { cancellation.cancel(.timeout) }
                if cause == .ioError { failOutput = true }
            })
        defer {
            cancellation.cancel()
            _ = outcome.finished.wait(timeout: .now() + .seconds(3))
            _ = Darwin.close(master); _ = Darwin.close(slave)
        }
        _ = try readUntil(master, suffix: promptSuffix)
        #expect(outcome.finished.wait(timeout: .now() + .seconds(3)) == .success)
        let expected: RootGrantsStatus = cause == .ctrlC ? .canceled :
            (cause == .deadline ? .timeout : .terminalRequired)
        guard case .refused(let actual)? = outcome.snapshot(), actual == expected else {
            Issue.record("Expected terminal refusal \(expected) for cleanup cause \(cause), observed \(String(describing: outcome.snapshot()))")
            return
        }
        #expect(sameTermios(original, try currentTermios(slave)))
        assertNoQueuedBytes(slave)
    }

    private func startReader(slave: Int32, text: String,
                             cancellation: RootGrantsPrivateCancellation,
                             checkOutput: @escaping () throws -> Void = {},
                             afterArming: @escaping () throws -> Void = {}) -> RootGrantsPTYOutcome {
        let outcome = RootGrantsPTYOutcome()
        DispatchQueue.global().async {
            do {
                try RootGrantsTerminalReview.confirm(text: text, cancellation: cancellation,
                    descriptor: slave, checkOutput: checkOutput, afterArming: afterArming)
                outcome.finish(.accepted)
            } catch let error as RootGrantsReviewError {
                outcome.finish(.refused(error.status))
            } catch {
                outcome.finish(.refused(.privateProtocolError))
            }
        }
        return outcome
    }

    private func startFlow(slave: Int32, initialText: String,
                           cancellation: RootGrantsPrivateCancellation,
                           effects: RootGrantsPTYFlowEffects,
                           checkOutput: @escaping () throws -> Void = {},
                           afterArming: @escaping () throws -> Void = {}) -> RootGrantsPTYOutcome {
        struct PreparedReview { let text: String }
        let outcome = RootGrantsPTYOutcome()
        DispatchQueue.global().async {
            do {
                _ = try RootGrantsPrivateFlow.perform(
                    initialText: initialText,
                    reviewText: { $0.text },
                    confirm: { text in
                        try RootGrantsTerminalReview.confirm(text: text, cancellation: cancellation,
                            descriptor: slave, checkOutput: checkOutput, afterArming: afterArming)
                    },
                    attach: { () throws -> String in
                        effects.append("attach")
                        throw RootGrantsReviewError(status: .privateProtocolError)
                    },
                    prepare: { _ in effects.append("prepare"); return PreparedReview(text: "second review") },
                    store: { _ in effects.append("store"); return "store-confirmation" },
                    wrap: { _, _ in effects.append("wrap"); return "qualified-wrap" },
                    seal: { _, _, _ in effects.append("seal"); return "sealed" }
                )
                outcome.finish(.accepted)
            } catch let error as RootGrantsReviewError {
                outcome.finish(.refused(error.status))
            } catch {
                outcome.finish(.refused(.privateProtocolError))
            }
        }
        return outcome
    }

    private func makePTY() throws -> (Int32, Int32, termios) {
        var master: Int32 = -1, slave: Int32 = -1
        guard openpty(&master, &slave, nil, nil, nil) == 0 else {
            throw RootGrantsReviewError(status: .terminalRequired)
        }
        let flags = fcntl(slave, F_GETFL)
        guard flags >= 0, fcntl(slave, F_SETFL, flags | O_NONBLOCK) == 0 else {
            _ = Darwin.close(master); _ = Darwin.close(slave)
            throw RootGrantsReviewError(status: .terminalRequired)
        }
        do { return (master, slave, try currentTermios(slave)) }
        catch { _ = Darwin.close(master); _ = Darwin.close(slave); throw error }
    }

    private func currentTermios(_ fd: Int32) throws -> termios {
        var value = termios()
        guard tcgetattr(fd, &value) == 0 else { throw RootGrantsReviewError(status: .terminalRequired) }
        return value
    }

    private func sameTermios(_ a: termios, _ b: termios) -> Bool {
        a.c_iflag == b.c_iflag && a.c_oflag == b.c_oflag && a.c_cflag == b.c_cflag &&
        a.c_lflag == b.c_lflag && a.c_ispeed == b.c_ispeed && a.c_ospeed == b.c_ospeed &&
        withUnsafeBytes(of: a.c_cc, { Array($0) }) == withUnsafeBytes(of: b.c_cc, { Array($0) })
    }

    private func readSome(_ fd: Int32, maximum: Int) throws -> Data {
        var set = emptyFDSet(); __darwin_fd_set(fd, &set)
        var timeout = timeval(tv_sec: 3, tv_usec: 0)
        let ready = Darwin.select(fd + 1, &set, nil, nil, &timeout)
        guard ready > 0 else { throw RootGrantsReviewError(status: .timeout) }
        var bytes = [UInt8](repeating: 0, count: maximum)
        let count = bytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!, $0.count) }
        guard count > 0 else { throw RootGrantsReviewError(status: .terminalRequired) }
        return Data(bytes.prefix(count))
    }

    private func readUntil(_ fd: Int32, suffix: Data, startingWith initial: Data = Data()) throws -> Data {
        var output = initial
        let deadline = DispatchTime.now().uptimeNanoseconds + 5_000_000_000
        // PTY output applies ONLCR, so a prompt ending in a newline may be
        // observed with CRLF or followed by additional terminal bytes.
        while output.range(of: suffix) == nil {
            guard DispatchTime.now().uptimeNanoseconds < deadline else {
                Issue.record("Disposable PTY read timed out after \(output.count) output bytes")
                throw RootGrantsReviewError(status: .timeout)
            }
            var set = emptyFDSet(); __darwin_fd_set(fd, &set)
            var timeout = timeval(tv_sec: 0, tv_usec: 100_000)
            let ready = Darwin.select(fd + 1, &set, nil, nil, &timeout)
            if ready < 0, errno == EINTR { continue }
            guard ready >= 0 else { throw RootGrantsReviewError(status: .terminalRequired) }
            if ready == 0 { continue }
            var bytes = [UInt8](repeating: 0, count: 8192)
            let count = bytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!, $0.count) }
            if count < 0, errno == EINTR || errno == EAGAIN { continue }
            guard count > 0 else { throw RootGrantsReviewError(status: .terminalRequired) }
            output.append(contentsOf: bytes.prefix(count))
        }
        return output
    }

    private func writePTY(_ fd: Int32, _ data: Data) throws {
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes {
                Darwin.write(fd, $0.baseAddress!.advanced(by: offset), data.count - offset)
            }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw RootGrantsReviewError(status: .terminalRequired) }
            offset += count
        }
    }

    private func assertNoQueuedBytes(_ fd: Int32) {
        var byte: UInt8 = 0
        let count = Darwin.read(fd, &byte, 1)
        #expect(count == -1)
        #expect(errno == EAGAIN || errno == EWOULDBLOCK)
    }

    private func emptyFDSet() -> fd_set {
        var set = fd_set()
        _ = withUnsafeMutableBytes(of: &set) { $0.initializeMemory(as: UInt8.self, repeating: 0) }
        return set
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
        for raw in 1...24 {
            var completion = RootGrantsPrivateCompletion()
            let frame = try completion.frame(request: nil, payload: .refusal(.helperClosed(Int32(raw))))
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
