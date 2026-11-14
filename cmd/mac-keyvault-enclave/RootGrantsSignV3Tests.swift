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
        let display = "REVIEW SIGN GRANT V3\nComplete request"
        var confirmedDisplays: [String] = []
        try RootGrantsSignV3ReviewFlow.confirm(display: display, attempt: &attempt) { text in
            confirmedDisplays.append(text)
        }
        #expect(confirmedDisplays == [display, display])
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

    // Claim: refusal at either fresh review closes before presence, and a denied biometric result closes without signing.
    @Test func reviewAndPresenceRefusalsConsumeAttempt() throws {
        let display = "REVIEW SIGN GRANT V3\nComplete request"
        let refusalStatuses: [RootGrantsStatus] = [.canceled, .timeout, .inputCanceled, .terminalRequired]
        for refusedConfirmation in 1...2 {
            for status in refusalStatuses {
                var review = RootGrantsSignV3Attempt()
                var confirmations: [String] = []
                var downstream: [String] = []
                var observed: RootGrantsStatus?
                do {
                    try RootGrantsSignV3ReviewFlow.confirm(display: display, attempt: &review) { text in
                        confirmations.append(text)
                        if confirmations.count == refusedConfirmation {
                            throw RootGrantsReviewError(status: status)
                        }
                    }
                    try review.beginPresence()
                    downstream.append("presence")
                } catch let error as RootGrantsReviewError {
                    observed = error.status
                }
                #expect(observed == status)
                #expect(confirmations == Array(repeating: display, count: refusedConfirmation))
                #expect(review.phase == .closed)
                #expect(downstream.isEmpty)
            }
        }

        var presence = RootGrantsSignV3Attempt()
        try RootGrantsSignV3ReviewFlow.confirm(display: display, attempt: &presence) { _ in }
        try presence.beginPresence()
        #expect(throws: RootGrantsReviewError.self) { try presence.acceptFreshTouchID(false) }
        #expect(presence.phase == .closed)
        #expect(throws: RootGrantsReviewError.self) { try presence.consumeForSigning() }
    }

    // Claim: the production sign body wires request.display to the terminal flow and contains no direct AppKit window review.
    @Test func productionSignPathUsesTerminalReview() throws {
        let sourceURL = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("RootGrantsSignV3.swift")
        let source = try String(contentsOf: sourceURL, encoding: .utf8)
        let start = try #require(source.range(of: "private func signV3Perform("))
        let end = try #require(source.range(of: "\nfunc rootGrantsSignGrantV3()",
                                             range: start.lowerBound..<source.endIndex))
        let productionPath = String(source[start.lowerBound..<end.lowerBound])
        #expect(productionPath.contains("RootGrantsSignV3ReviewFlow.confirm"))
        #expect(productionPath.contains("display: request.display"))
        #expect(productionPath.contains("RootGrantsTerminalReview.confirm"))
        #expect(!productionPath.contains("RootGrantsNativeReview"))
        #expect(!productionPath.contains("SIGN GRANT V3"))
        #expect(!source.contains("RootGrantsNativeReview"))
        #expect(!source.contains("Type SIGN GRANT V3"))
    }

    // Claim: both Returns consume one review transition; replay cannot invoke another confirmation.
    @Test func reviewTransitionCannotReplay() throws {
        var attempt = RootGrantsSignV3Attempt()
        var confirmations = 0
        try RootGrantsSignV3ReviewFlow.confirm(display: "complete request", attempt: &attempt) { _ in
            confirmations += 1
        }
        #expect(confirmations == 2)
        #expect(attempt.phase == .reviewed)
        #expect(throws: RootGrantsReviewError.self) {
            try RootGrantsSignV3ReviewFlow.confirm(display: "complete request", attempt: &attempt) { _ in
                confirmations += 1
            }
        }
        #expect(confirmations == 2)
        #expect(attempt.phase == .closed)
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
