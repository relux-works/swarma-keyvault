import Foundation
import CryptoKit
import Testing
@testable import KeyvaultNativeCore

struct RootGrantsSignV3Tests {
    // Claim: the full retained recovery record emitted by the real Go operation
    // passes Swift validation, while its shorter pair summary is rejected. The
    // exact printable contract bytes remain visible and bound to the grant hash.
    @Test func productionRequestAcceptsFullRetainedRecordAndExactContractBytes() throws {
        let fixture = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("testdata/root-grants-sign-request-v2.json")
        let bytes = try Data(contentsOf: fixture)
        let request = try RootGrantsSignV3Request(ownedBytes: bytes)
        let expectedContract = try #require(String(data: request.contract, encoding: .utf8))
        #expect(expectedContract.contains("example<&>"))
        #expect(expectedContract.contains("<") && expectedContract.contains(">") && expectedContract.contains("&"))
        #expect(request.display.contains(expectedContract))

        let contractHash = SHA256.hash(data: request.contract).map { String(format: "%02x", $0) }.joined()
        let reviewNode = try NativeArchiveJSON.decode(request.reviewBytes, maximum: 1 << 20, canonical: true)
        #expect(try reviewNode.field("contract_sha256").text() == contractHash)
        let grantNode = try NativeArchiveJSON.decode(request.grant, maximum: 65536, canonical: true)
        #expect(try grantNode.field("contract_sha256").text() == contractHash)

        var signingMessage = Data("swarma-grant-v3".utf8)
        signingMessage.append(request.grant)
        let messageHash = SHA256.hash(data: signingMessage).map { String(format: "%02x", $0) }.joined()
        #expect(request.messageSHA256 == messageHash)

        let outer = try NativeArchiveJSON.decode(bytes, maximum: 262144, canonical: true)
        let fields = try outer.fields(["schema", "operation", "review", "envelope", "pair_metadata"])
        let fullHex = try fields[4].text()
        let review = fields[2]
        let record = try NativeArchiveJSON.decode(try review.field("record").canonical(), maximum: 32768, canonical: true)
        let summary = try record.field("pair").canonical()
        #expect(fullHex.utf8.count > summary.count * 2)
        let summaryHex = summary.map { String(format: "%02x", $0) }.joined()
        let source = try #require(String(data: bytes, encoding: .utf8))
        let changed = source.replacingOccurrences(of: "\"pair_metadata\":\"\(fullHex)\"",
                                                   with: "\"pair_metadata\":\"\(summaryHex)\"")
        #expect(changed != source)
        #expect(throws: RootGrantsReviewError.self) {
            _ = try RootGrantsSignV3Request(ownedBytes: Data(changed.utf8))
        }
    }

    // Claim: one reviewed attempt advances through one Touch ID phase and is
    // consumed before private signing; a second use cannot replay it.
    @Test func oneFreshPresenceConsumesOneAttempt() throws {
        var attempt = RootGrantsSignV3Attempt()
        try attempt.confirmReview("SIGN GRANT V3")
        #expect(attempt.phase == .reviewed)
        try attempt.beginPresence()
        #expect(attempt.phase == .presencePending)
        try attempt.acceptFreshTouchID(true)
        #expect(attempt.phase == .presenceFresh)
        try attempt.consumeForSigning()
        #expect(attempt.phase == .consumed)
        #expect(throws: RootGrantsReviewError.self) { try attempt.beginPresence() }
        #expect(attempt.phase == .closed)
    }

    // Claim: an incorrect native review confirmation refuses before presence,
    // and a denied biometric result closes the attempt without signing.
    @Test func reviewAndPresenceRefusalsConsumeAttempt() throws {
        var review = RootGrantsSignV3Attempt()
        #expect(throws: RootGrantsReviewError.self) { try review.confirmReview("APPROVE") }
        #expect(review.phase == .closed)

        var presence = RootGrantsSignV3Attempt()
        try presence.confirmReview("SIGN GRANT V3")
        try presence.beginPresence()
        #expect(throws: RootGrantsReviewError.self) { try presence.acceptFreshTouchID(false) }
        #expect(presence.phase == .closed)
        #expect(throws: RootGrantsReviewError.self) { try presence.consumeForSigning() }
    }

    // Claim: no caller can skip native review or the fresh Touch ID stage and
    // invoke the helper-local signing transition.
    @Test func signingCannotSkipReviewOrTouchID() {
        var attempt = RootGrantsSignV3Attempt()
        #expect(throws: RootGrantsReviewError.self) { try attempt.consumeForSigning() }
        #expect(attempt.phase == .closed)
    }

    // Claim: grant signing has a separate absolute 120-second budget while the
    // existing attach helper keeps its original 900-second default.
    @Test func signingDeadlineDoesNotRenewAttachBudget() throws {
        let signing = RootGrantsPrivateDeadline(startedAt: 100, budget: 120)
        #expect(signing.expiresAt == 220)
        try signing.check(at: 219)
        #expect(throws: RootGrantsReviewError.self) { try signing.check(at: 220) }
        #expect(try RootGrantsPrivateDeadline.boundedGrantSigningBudget(remaining: 900_000_000_000) == 120_000_000_000)
        #expect(try RootGrantsPrivateDeadline.boundedGrantSigningBudget(remaining: 40) == 40)
        #expect(throws: RootGrantsReviewError.self) { try RootGrantsPrivateDeadline.boundedGrantSigningBudget(remaining: 0) }
        #expect(RootGrantsPrivateDeadline(startedAt: 100).expiresAt == 900_000_000_100)
    }

    // Claim: the raw 64-byte signature uses the one-response completion frame,
    // and the existing exact-byte ACK plus EOF consumes it once.
    @Test func signatureFrameRequiresExactAcknowledgementAndEOF() throws {
        let request = Data("review-sign-grant-v3".utf8)
        let signature = Data(repeating: 0xa5, count: 64)
        var completion = RootGrantsPrivateCompletion()
        let frame = try completion.frame(request: request, payload: .signature(signature))
        #expect(frame.count == 69)
        #expect((frame.first ?? 0xff) == 0)
        #expect(try RootGrantsPrivateFrame.number(Data(frame.dropFirst().prefix(4))) == 64)
        #expect(Data(frame.dropFirst(5)) == signature)
        let acknowledgement = try RootGrantsPrivateAcknowledgement.bytes(request: request, sealed: signature)
        try completion.acknowledge(acknowledgement)
        try completion.endOfInput(trailing: Data())
        #expect(completion.phase == .complete)
        #expect(throws: RootGrantsReviewError.self) {
            _ = try RootGrantsPrivateFrame.response(.signature(Data(repeating: 0, count: 63)))
        }
    }
}
