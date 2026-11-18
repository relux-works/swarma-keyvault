import CryptoKit
import Foundation
import Testing
@testable import KeyvaultNativeCore

struct RootGrantsTrustContractV2Tests {
    private static let xOnlyKey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

    // Claim: the exact root baseline and a valid delegated contract parse, while this root-only instance refuses delegation as status 13.
    @Test func parsesRootAndDelegatedProfileWithoutRejectingAllDelegation() throws {
        let root = try RootGrantsTrustContractV2(ownedBytes: Self.contract())
        #expect(root.profile == "swarma-trust-contract/2")
        #expect(root.parentGrantID.isEmpty)
        #expect(root.ordinal == 0)
        #expect(root.delegate.depth == 0)
        #expect(root.derivedV3Scope.isEmpty)
        #expect(root.instanceRefusal() == nil)

        let delegated = try RootGrantsTrustContractV2(ownedBytes: Self.contract(delegate: Self.validDelegate))
        #expect(delegated.delegate.depth == 1)
        #expect(delegated.delegate.notaries.count == 1)
        let refusal = try #require(delegated.instanceRefusal())
        #expect(refusal.code == .delegationNotAuthorized)
        #expect(refusal.nativeStatus == .bindingMismatch)

        let child = try RootGrantsTrustContractV2(ownedBytes: Self.contract(
            parent: String(repeating: "a", count: 64), ordinal: "1"))
        let childRefusal = try #require(child.instanceRefusal())
        #expect(childRefusal.code == .delegationNotAuthorized)
        #expect(childRefusal.nativeStatus == .bindingMismatch)

        let landing = try RootGrantsTrustContractV2(ownedBytes: Self.contract(
            actions: "[\"land\"]", repos: "[\"https://git.example/project\"]"))
        #expect(landing.repos == ["https://git.example/project"])
        #expect(landing.derivedV3Scope == ["repository.push"])
    }

    // Claim: each ordered LIP rule owns its first semantic failure and all LIP findings coarsen to native status 13.
    @Test func reportsFirstFailureInPinnedRuleOrder() throws {
        let base = Self.contract()
        let source = String(decoding: base, as: UTF8.self)
        let cases: [(Data, RootGrantsTrustContractV2FailureCode)] = [
            (Self.replace(base, "swarma-trust-contract/2", "swarma-trust-contract/1"), .contractProfile),
            (Self.contract(network: "test"), .contractField),
            (Self.contract(actions: "[\"unknown\"]"), .contractActions),
            (Self.contract(actions: "[\"land\"]", repos: "[\"https://one/path\"]"), .contractRepos),
            (Self.contract(actions: "[\"spend\"]", spendBudget: "0"), .contractBudget),
            (Self.contract(note: String(repeating: "n", count: 281)), .contractNote),
            (Self.contract(parent: "not-a-hash", ordinal: "1"), .contractParent),
            (Self.contract(delegate: "{\"depth\":0,\"actions\":[],\"budget\":0,\"slots\":[],\"notaries\":[],\"checkpoint\":\"bad\"}"), .contractDelegate),
            (Self.contract(delegate: Self.noNotaryDelegate), .delegateNoNotary),
            (Self.contract(delegate: Self.validDelegate.replacingOccurrences(of: "\"budget\":0", with: "\"budget\":01")), .contractEncoding),
            (Self.contract(delegate: Self.validDelegate.replacingOccurrences(of: "\"checkpoint\":\"\(String(repeating: "a", count: 64))\"", with: "\"checkpoint\":null")), .contractDelegate),
            (Self.contract(delegate: Self.validDelegate.replacingOccurrences(of: "\"checkpoint\":\"\(String(repeating: "a", count: 64))\"", with: "\"checkpoint\":true")), .contractDelegate),
        ]
        for (bytes, expected) in cases {
            let failure = try #require(Self.failure(bytes))
            #expect(failure.code == expected)
            #expect(failure.nativeStatus == .bindingMismatch)
        }

        let reordered = Self.replace(base,
            "\"profile\":\"swarma-trust-contract/2\",\"network\":\"main\"",
            "\"network\":\"main\",\"profile\":\"swarma-trust-contract/2\"")
        #expect(Self.failure(reordered)?.code == .contractEncoding)
        #expect(Self.failure(Data((source + "\n").utf8))?.code == .contractEncoding)
        let escapedNote = Self.replace(base, "\"note\":\"\"", "\"note\":\"\\u0061\"")
        #expect(escapedNote != base)
        #expect(Self.failure(escapedNote)?.code == .contractEncoding)
    }

    // Claim: a parent with nonzero delegate depth fails rule 8 before rule 9's no-notary precedence.
    @Test func parentDepthPrecedesDelegateValueRefusals() throws {
        let parent = String(repeating: "a", count: 64)
        let failure = try #require(Self.failure(Self.contract(parent: parent, ordinal: "1", delegate: Self.noNotaryDelegate)))
        #expect(failure.code == .contractParent)
        #expect(failure.nativeStatus == .bindingMismatch)
    }

    // Claim: a valid spend form passes the public parser but the configured no-spend instance refuses it as status 13.
    @Test func spendIsAnInstanceRefusalAfterSuccessfulParsing() throws {
        let request = try RootGrantsTrustContractV2(ownedBytes: Self.contract(actions: "[\"spend\"]", spendBudget: "1"))
        let refusal = try #require(request.instanceRefusal())
        #expect(refusal.code == .spendNotAuthorized)
        #expect(refusal.nativeStatus == .bindingMismatch)
    }

    // Claim: a well-formed x-only curve point is accepted and an in-range off-curve x value is rule-3 CONTRACT_FIELD.
    @Test func granteeMustBeAnActualSecp256k1Point() throws {
        let valid = try RootGrantsTrustContractV2(ownedBytes: Self.contract(granteeKey: Self.xOnlyKey))
        #expect(valid.granteeKey == Self.xOnlyKey)

        let offCurve = "800000000000000000000000000000000000000000000000ffffffffffffffff"
        #expect(Self.failure(Self.contract(granteeKey: offCurve))?.code == .contractField)

        let badSlot = Self.validDelegate.replacingOccurrences(of: "\"grantee\":\"\(Self.xOnlyKey)\"",
                                                               with: "\"grantee\":\"\(offCurve)\"")
        #expect(Self.failure(Self.contract(delegate: badSlot))?.code == .contractDelegate)

        let badNotaryOwner = Self.validDelegate.replacingOccurrences(of: "\"owner\":\"02\(Self.xOnlyKey)\"",
                                                                      with: "\"owner\":\"02\(offCurve)\"")
        #expect(Self.failure(Self.contract(delegate: badNotaryOwner))?.code == .contractDelegate)
    }

    @Test func elevenMemberTrustOneProfileHasItsOwnFailureCode() throws {
        let trustOne = Data("{\"profile\":\"swarma-trust-contract/1\",\"network\":\"main\",\"landlord_name\":\"id/example-owner\",\"agent_name\":\"id/example-agent\",\"grantee_key\":\"\(Self.xOnlyKey)\",\"actions\":[\"instruct\"],\"repos\":[],\"spend_budget\":0,\"not_before\":1,\"not_after\":2,\"note\":\"\"}".utf8)
        #expect(Self.failure(trustOne)?.code == .contractProfile)
        #expect(Self.failure(Self.contract()) == nil)
    }

    // Claim: the contract purpose signs SHA-256 of exact contract bytes and uses the accepted per-owner Touch ID reason.
    @Test func purposeDigestAndTouchIDReasonAreFixed() throws {
        let contract = Self.contract()
        let expected = Data(SHA256.hash(data: contract))
        #expect(RootGrantsTrustContractV2.countersignDigest(contract) == expected)

        var grantV3Message = Data("swarma-grant-v3".utf8)
        grantV3Message.append(contract)
        #expect(RootGrantsTrustContractV2.countersignDigest(contract) != Data(SHA256.hash(data: grantV3Message)))
        #expect(RootGrantsTrustContractCountersignRequest.localizedReason(ownerPrincipal: "owner:id/fixture-owner") ==
                "Touch ID confirms one root trust contract countersignature for owner:id/fixture-owner.")
    }

    // Claim: empty and exact scope-text byte/hash pairs pass, while missing, unexpected, changed, or differently paired bytes coarsen to 13.
    @Test func scopeTextUsesOnlyItsOwnExactHash() throws {
        let text = Data("first line\nsecond line".utf8)
        let digest = SHA256.hash(data: text).map { String(format: "%02x", $0) }.joined()
        #expect(RootGrantsTrustContractV2.validateScopeText(Data(), reviewedHash: "", contractHash: "") == nil)
        #expect(RootGrantsTrustContractV2.validateScopeText(text, reviewedHash: digest, contractHash: digest) == nil)

        let cases: [(Data, String, String, RootGrantsTrustContractV2FailureCode)] = [
            (text, "", "", .scopeTextUnexpected),
            (Data(), digest, digest, .scopeTextUnavailable),
            (Data("changed line ending\r\n".utf8), digest, digest, .scopeTextHashMismatch),
            (text, "", digest, .scopeTextHashMismatch),
        ]
        for (bytes, reviewedHash, contractHash, expected) in cases {
            let refusal = try #require(RootGrantsTrustContractV2.validateScopeText(
                bytes, reviewedHash: reviewedHash, contractHash: contractHash))
            #expect(refusal.code == expected)
            #expect(refusal.nativeStatus == .bindingMismatch)
        }
    }

    // Claim: the 8192-byte inner contract reaches LIP rule 7, while byte 8193 is the rule-1 CONTRACT_ENCODING refusal.
    @Test func contractByteLimitIsOwnedByLipRuleOne() throws {
        let emptyNote = Self.contract(note: "")
        let noteBytesAtLimit = 8192 - emptyNote.count
        let atLimit = Self.contract(note: String(repeating: "x", count: noteBytesAtLimit))
        let overLimit = Self.contract(note: String(repeating: "x", count: noteBytesAtLimit + 1))
        #expect(atLimit.count == 8192)
        #expect(overLimit.count == 8193)
        #expect(Self.failure(atLimit)?.code == .contractNote)
        #expect(Self.failure(overLimit)?.code == .contractEncoding)
    }

    // Claim: rule-1 literal and duplicate refusals stay outside delegate rule 9; parser resource caps do not steal later LIP ownership.
    @Test func literalsDuplicatesAndLargeInvalidValuesKeepLIPOwnership() throws {
        let valid = Self.contract()
        #expect(Self.failure(valid) == nil)
        #expect(Self.failure(Self.contract(actions: "[true]"))?.code == .contractEncoding)
        #expect(Self.failure(Self.contract(repos: "[null]"))?.code == .contractEncoding)
        #expect(Self.failure(Self.contract(actions: "[{\"x\":1,\"x\":1}]"))?.code == .contractEncoding)

        let manyNumbers = "[" + Array(repeating: "0", count: 2049).joined(separator: ",") + "]"
        #expect(Self.contract(actions: manyNumbers).count < RootGrantsTrustContractV2.maximumBytes)
        #expect(Self.failure(Self.contract(actions: manyNumbers))?.code == .contractActions)

        let delegateMembers = (0..<59).map { "\"extra_\($0)\":0" }
        let oversizedDelegate = "{\"depth\":0,\"actions\":[],\"budget\":0,\"slots\":[],\"notaries\":[],\"checkpoint\":\"\"," +
            delegateMembers.joined(separator: ",") + "}"
        #expect(Self.failure(Self.contract(delegate: oversizedDelegate))?.code == .contractDelegate)

        let deepValue = String(repeating: "[", count: 17) + "0" + String(repeating: "]", count: 17)
        let deepDelegate = "{\"depth\":0,\"actions\":[],\"budget\":0,\"slots\":[],\"notaries\":[],\"checkpoint\":\(deepValue)}"
        #expect(Self.failure(Self.contract(delegate: deepDelegate))?.code == .contractDelegate)

        let duplicateSlot = Self.validDelegate.replacingOccurrences(of: "\"cap\":0", with: "\"cap\":0,\"cap\":0")
        #expect(Self.failure(Self.contract(delegate: duplicateSlot))?.code == .contractDelegate)
        #expect(try RootGrantsTrustContractV2(ownedBytes: Self.contract(delegate: Self.validDelegate)).delegate.depth == 1)
    }

    private static var validDelegate: String {
        "{\"depth\":1,\"actions\":[\"instruct\"],\"budget\":0," +
            "\"slots\":[{\"executor\":\"id/example-worker\",\"grantee\":\"\(xOnlyKey)\",\"cap\":0,\"notary\":\"id/example-notary\"}]," +
            "\"notaries\":[{\"name\":\"id/example-notary\",\"registration\":{\"txid\":\"\(String(repeating: "a", count: 64))\",\"vout\":0},\"owner\":\"02\(xOnlyKey)\"}]," +
            "\"checkpoint\":\"\(String(repeating: "a", count: 64))\"}"
    }

    private static var noNotaryDelegate: String {
        "{\"depth\":1,\"actions\":[\"unknown\"],\"budget\":9,\"slots\":[],\"notaries\":[],\"checkpoint\":\"bad\"}"
    }

    private static func contract(profile: String = "swarma-trust-contract/2", network: String = "main",
                                 actions: String = "[\"instruct\",\"review\"]", repos: String = "[]",
                                 spendBudget: String = "0", scopeHash: String = "", granteeKey: String = xOnlyKey,
                                 parent: String = "",
                                 ordinal: String = "0", delegate: String = "{\"depth\":0,\"actions\":[],\"budget\":0,\"slots\":[],\"notaries\":[],\"checkpoint\":\"\"}",
                                 note: String = "") -> Data {
        let source = "{\"profile\":\"\(profile)\",\"network\":\"\(network)\",\"landlord_name\":\"id/example-owner\",\"agent_name\":\"id/example-agent\",\"grantee_key\":\"\(granteeKey)\",\"actions\":\(actions),\"repos\":\(repos),\"spend_budget\":\(spendBudget),\"not_before\":1,\"not_after\":2,\"scope_text_sha256\":\"\(scopeHash)\",\"parent_grant_id\":\"\(parent)\",\"ordinal\":\(ordinal),\"delegate\":\(delegate),\"note\":\"\(note)\"}"
        return Data(source.utf8)
    }

    private static func replace(_ bytes: Data, _ old: String, _ new: String) -> Data {
        let source = String(decoding: bytes, as: UTF8.self).replacingOccurrences(of: old, with: new)
        return Data(source.utf8)
    }

    private static func failure(_ bytes: Data) -> RootGrantsTrustContractV2Failure? {
        do {
            _ = try RootGrantsTrustContractV2(ownedBytes: bytes)
            return nil
        } catch let failure as RootGrantsTrustContractV2Failure {
            return failure
        } catch {
            return nil
        }
    }
}
