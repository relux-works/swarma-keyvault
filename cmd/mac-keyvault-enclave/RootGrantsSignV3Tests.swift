import Foundation
import Testing
@testable import KeyvaultNativeCore

struct RootGrantsSignV3Tests {
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
