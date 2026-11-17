import Darwin
import CryptoKit
import Foundation
import Testing
@testable import KeyvaultNativeCore

private enum AgentNostrTestFailure: Error { case fixture }

private func agentNostrFixture(_ name: String) throws -> [String: Any] {
    let root = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    let url = root.appendingPathComponent("internal/keyvault/testdata/agent-nostr/\(name).json")
    guard let value = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any] else {
        throw AgentNostrTestFailure.fixture
    }
    return value
}

private func agentNostrHex(_ text: String) throws -> Data {
    let bytes = Array(text.utf8)
    guard bytes.count.isMultiple(of: 2) else { throw AgentNostrTestFailure.fixture }
    var result = Data()
    for index in stride(from: 0, to: bytes.count, by: 2) {
        guard let high = UInt8(String(decoding: bytes[index..<(index + 1)], as: UTF8.self), radix: 16),
              let low = UInt8(String(decoding: bytes[(index + 1)..<(index + 2)], as: UTF8.self), radix: 16) else {
            throw AgentNostrTestFailure.fixture
        }
        result.append(high << 4 | low)
    }
    return result
}

private func agentNostrRefused(_ body: () throws -> Void) -> Bool {
    do { try body(); return false }
    catch AgentNostrPrivateRuntimeError.parentNotAdmitted { return true }
    catch { return false }
}

private func agentNostrTransportRefused(_ body: () throws -> Void) -> Bool {
    do { try body(); return false }
    catch AgentNostrPrivateRuntimeError.transport { return true }
    catch { return false }
}

private func agentNostrDeadlineRefused(_ body: () throws -> Void) -> Bool {
    do { try body(); return false }
    catch AgentNostrPrivateRuntimeError.deadlineExpired { return true }
    catch { return false }
}

private func agentNostrValidEndpoint() -> AgentNostrPrivateEndpointFacts {
    AgentNostrPrivateEndpointFacts(descriptor: 3, device: 1, inode: 2, fileType: UInt16(S_IFSOCK),
        socketType: SOCK_STREAM, localFamily: AF_UNIX, peerFamily: AF_UNIX,
        localUnnamed: true, peerUnnamed: true, localAddress: Data(), peerAddress: Data())
}

private func agentNostrValidCode() -> AgentNostrParentCodeFacts {
    let requirement = Data(AgentNostrParentIdentity.requirement.utf8)
    return AgentNostrParentCodeFacts(identifier: AgentNostrParentIdentity.identifier,
        team: AgentNostrParentIdentity.team, flags: 0x10000, dynamic: 0x10001,
        codeHash: Data(repeating: 7, count: 20), expectedRequirement: requirement,
        actualRequirement: requirement, leafSHA1: AgentNostrParentIdentity.leafSHA1,
        leafSHA256: AgentNostrParentIdentity.leafSHA256, hasEntitlements: false, entitlementsEmpty: false)
}

private func agentNostrPeerFacts(
    code: AgentNostrParentCodeFacts? = nil,
    endpoint: AgentNostrPrivateEndpointFacts? = nil,
    auditToken: Data? = nil,
    parentPID: Int32 = 100,
    parentPIDVersion: Int32 = 5,
    observedParentPID: Int32 = 100,
    helperRealUID: uid_t = 501,
    helperEffectiveUID: uid_t = 501,
    parentRealUID: uid_t = 501,
    parentEffectiveUID: uid_t = 501
) -> AgentNostrPeerFacts {
    AgentNostrPeerFacts(auditToken: auditToken ?? Data(repeating: 9, count: 32),
        parentPID: parentPID, parentPIDVersion: parentPIDVersion, observedParentPID: observedParentPID,
        helperRealUID: helperRealUID, helperEffectiveUID: helperEffectiveUID,
        parentRealUID: parentRealUID, parentEffectiveUID: parentEffectiveUID,
        endpoint: endpoint ?? agentNostrValidEndpoint(), code: code ?? agentNostrValidCode())
}

private struct AgentNostrFlowValue: AgentNostrPrivateOperating {
    let operation = AgentNostrPrivateRequest.Operation.createWrap
    var bytes = Data([1, 2, 3])
    mutating func eraseOwnedBuffers() { if !bytes.isEmpty { bytes.resetBytes(in: 0..<bytes.count) } }
}

private final class AgentNostrFlowChecker: AgentNostrPeerChecking {
    var revalidations = 0
    var failAtRevalidation: Int?
    private let facts = agentNostrPeerFacts()

    func admit() throws -> AgentNostrPeerFacts {
        try AgentNostrParentPolicy.require(facts)
        return facts
    }

    func revalidate(_ expected: AgentNostrPeerFacts) throws {
        revalidations += 1
        if revalidations == failAtRevalidation { throw AgentNostrPrivateRuntimeError.parentNotAdmitted }
        try AgentNostrParentPolicy.requireSame(expected, facts)
    }
}

struct AgentNostrPrivateTests {
    // Entry dispatch consumes one exact argument shape; it grants no identity or authorization by itself.
    @Test func privateEntryIsOneExactCommand() {
        #expect(AgentNostrPrivateEntry.argument == "--agent-nostr-private-v1")
        #expect(AgentNostrPrivateEntry.matches(["helper", AgentNostrPrivateEntry.argument]))
        #expect(!AgentNostrPrivateEntry.matches(["helper"]))
        #expect(!AgentNostrPrivateEntry.matches(["helper", AgentNostrPrivateEntry.argument, "extra"]))
        #expect(!AgentNostrPrivateEntry.matches(["helper", "--recovery-private"]))
    }

    // The checked identity policy admits one complete same-UID vault/socket/code tuple.
    // Synthetic signing facts test predicates only; they prove no live code or kernel association.
    @Test func parentAdmissionIsAClosedPositivePolicy() throws {
        #expect(AgentNostrParentIdentity.identifier == "works.relux.keyvault")
        #expect(AgentNostrParentIdentity.team == "262RZ595FP")
        #expect(AgentNostrParentIdentity.leafSHA1 == "d71190abe54185f908169ee9ca538d4066942c0f")
        #expect(AgentNostrParentIdentity.leafSHA256 == "b315ed0ac55f58d4dbcfc3ce4f7937f6ed058277feba7e4aa3e64bd10b17d3a1")
        #expect(AgentNostrParentIdentity.requirement == #"identifier "works.relux.keyvault" and anchor apple generic and certificate leaf = H"d71190abe54185f908169ee9ca538d4066942c0f" and certificate 1[field.1.2.840.113635.100.6.2.1]"#)
        try AgentNostrParentPolicy.require(agentNostrPeerFacts())
        // PID version is an opaque audit-token process-incarnation value; signed representation is not a policy.
        try AgentNostrParentPolicy.require(agentNostrPeerFacts(parentPIDVersion: -1))
        let sameIdentity = agentNostrPeerFacts()
        try AgentNostrParentPolicy.requireSame(sameIdentity, sameIdentity)
        var emptyEntitlements = agentNostrValidCode()
        emptyEntitlements = AgentNostrParentCodeFacts(identifier: emptyEntitlements.identifier,
            team: emptyEntitlements.team, flags: emptyEntitlements.flags, dynamic: emptyEntitlements.dynamic,
            codeHash: emptyEntitlements.codeHash, expectedRequirement: emptyEntitlements.expectedRequirement,
            actualRequirement: emptyEntitlements.actualRequirement, leafSHA1: emptyEntitlements.leafSHA1,
            leafSHA256: emptyEntitlements.leafSHA256, hasEntitlements: true, entitlementsEmpty: true)
        try AgentNostrParentPolicy.require(agentNostrPeerFacts(code: emptyEntitlements))

        let valid = agentNostrValidCode()
        func positiveRefusalPositive(_ refusal: () throws -> Void) throws {
            try AgentNostrParentPolicy.require(sameIdentity)
            let wasRefused = agentNostrRefused(refusal)
            #expect(wasRefused)
            try AgentNostrParentPolicy.requireSame(sameIdentity, sameIdentity)
        }
        let codeMutations = [
            AgentNostrParentCodeFacts(identifier: "works.relux.other", team: valid.team, flags: valid.flags, dynamic: valid.dynamic, codeHash: valid.codeHash, expectedRequirement: valid.expectedRequirement, actualRequirement: valid.actualRequirement, leafSHA1: valid.leafSHA1, leafSHA256: valid.leafSHA256, hasEntitlements: false, entitlementsEmpty: false),
            AgentNostrParentCodeFacts(identifier: valid.identifier, team: "OTHERTEAM", flags: valid.flags, dynamic: valid.dynamic, codeHash: valid.codeHash, expectedRequirement: valid.expectedRequirement, actualRequirement: valid.actualRequirement, leafSHA1: valid.leafSHA1, leafSHA256: valid.leafSHA256, hasEntitlements: false, entitlementsEmpty: false),
            AgentNostrParentCodeFacts(identifier: valid.identifier, team: valid.team, flags: 0, dynamic: valid.dynamic, codeHash: valid.codeHash, expectedRequirement: valid.expectedRequirement, actualRequirement: valid.actualRequirement, leafSHA1: valid.leafSHA1, leafSHA256: valid.leafSHA256, hasEntitlements: false, entitlementsEmpty: false),
            AgentNostrParentCodeFacts(identifier: valid.identifier, team: valid.team, flags: valid.flags, dynamic: valid.dynamic & ~UInt32(1 << 16), codeHash: valid.codeHash, expectedRequirement: valid.expectedRequirement, actualRequirement: valid.actualRequirement, leafSHA1: valid.leafSHA1, leafSHA256: valid.leafSHA256, hasEntitlements: false, entitlementsEmpty: false),
            AgentNostrParentCodeFacts(identifier: valid.identifier, team: valid.team, flags: valid.flags, dynamic: valid.dynamic | 0x10000000, codeHash: valid.codeHash, expectedRequirement: valid.expectedRequirement, actualRequirement: valid.actualRequirement, leafSHA1: valid.leafSHA1, leafSHA256: valid.leafSHA256, hasEntitlements: false, entitlementsEmpty: false),
            AgentNostrParentCodeFacts(identifier: valid.identifier, team: valid.team, flags: valid.flags, dynamic: valid.dynamic, codeHash: valid.codeHash, expectedRequirement: Data([1, 2, 3]), actualRequirement: Data([1, 2, 4]), leafSHA1: valid.leafSHA1, leafSHA256: valid.leafSHA256, hasEntitlements: false, entitlementsEmpty: false),
            AgentNostrParentCodeFacts(identifier: valid.identifier, team: valid.team, flags: valid.flags, dynamic: valid.dynamic, codeHash: valid.codeHash, expectedRequirement: valid.expectedRequirement, actualRequirement: valid.actualRequirement, leafSHA1: "wrong", leafSHA256: valid.leafSHA256, hasEntitlements: false, entitlementsEmpty: false),
            AgentNostrParentCodeFacts(identifier: valid.identifier, team: valid.team, flags: valid.flags, dynamic: valid.dynamic, codeHash: Data([1]), expectedRequirement: valid.expectedRequirement, actualRequirement: valid.actualRequirement, leafSHA1: valid.leafSHA1, leafSHA256: valid.leafSHA256, hasEntitlements: false, entitlementsEmpty: false),
            AgentNostrParentCodeFacts(identifier: valid.identifier, team: valid.team, flags: valid.flags, dynamic: valid.dynamic, codeHash: valid.codeHash, expectedRequirement: valid.expectedRequirement, actualRequirement: valid.actualRequirement, leafSHA1: valid.leafSHA1, leafSHA256: valid.leafSHA256, hasEntitlements: true, entitlementsEmpty: false),
        ]
        for mutation in codeMutations {
            try positiveRefusalPositive { try AgentNostrParentPolicy.require(agentNostrPeerFacts(code: mutation)) }
        }

        for rejected in [
            agentNostrPeerFacts(auditToken: Data([1])),
            agentNostrPeerFacts(parentPID: 1, observedParentPID: 1),
            agentNostrPeerFacts(parentPID: 100, observedParentPID: 101),
            agentNostrPeerFacts(helperRealUID: 501, helperEffectiveUID: 502),
            agentNostrPeerFacts(parentRealUID: 502),
            agentNostrPeerFacts(parentEffectiveUID: 502),
        ] {
            try positiveRefusalPositive { try AgentNostrParentPolicy.require(rejected) }
        }
        var changedCode = agentNostrValidCode()
        changedCode = AgentNostrParentCodeFacts(identifier: changedCode.identifier, team: changedCode.team,
            flags: changedCode.flags, dynamic: changedCode.dynamic, codeHash: Data(repeating: 8, count: 20),
            expectedRequirement: changedCode.expectedRequirement, actualRequirement: changedCode.actualRequirement,
            leafSHA1: changedCode.leafSHA1, leafSHA256: changedCode.leafSHA256,
            hasEntitlements: changedCode.hasEntitlements, entitlementsEmpty: changedCode.entitlementsEmpty)
        var changedEndpoint = agentNostrValidEndpoint()
        changedEndpoint = AgentNostrPrivateEndpointFacts(descriptor: changedEndpoint.descriptor,
            device: changedEndpoint.device, inode: changedEndpoint.inode + 1, fileType: changedEndpoint.fileType,
            socketType: changedEndpoint.socketType, localFamily: changedEndpoint.localFamily,
            peerFamily: changedEndpoint.peerFamily, localUnnamed: changedEndpoint.localUnnamed,
            peerUnnamed: changedEndpoint.peerUnnamed, localAddress: changedEndpoint.localAddress,
            peerAddress: changedEndpoint.peerAddress)
        for changed in [
            agentNostrPeerFacts(auditToken: Data(repeating: 8, count: 32)),
            agentNostrPeerFacts(parentPID: 101, observedParentPID: 101),
            agentNostrPeerFacts(parentPIDVersion: 6),
            agentNostrPeerFacts(code: changedCode),
            agentNostrPeerFacts(endpoint: changedEndpoint),
        ] {
            try positiveRefusalPositive { try AgentNostrParentPolicy.requireSame(sameIdentity, changed) }
        }
        let unnamedAddresses = [Data([0, UInt8(AF_UNIX)]), Data([0, UInt8(AF_UNIX), 0, 0, 0, 0])]
        let namedAddresses = [Data([0, UInt8(AF_UNIX), 47, 116, 109, 112]),
                              Data([0, UInt8(AF_UNIX), 0, 0, 0, 0, 0, 0, 47])]
        for address in unnamedAddresses {
            #expect(AgentNostrPrivateAddressPolicy.isUnnamedUnixAddress(address))
        }
        for address in namedAddresses {
            #expect(AgentNostrPrivateAddressPolicy.isUnnamedUnixAddress(unnamedAddresses[0]))
            #expect(!AgentNostrPrivateAddressPolicy.isUnnamedUnixAddress(address))
            #expect(AgentNostrPrivateAddressPolicy.isUnnamedUnixAddress(unnamedAddresses[0]))
        }
        var wrongEndpoint = agentNostrValidEndpoint()
        wrongEndpoint = AgentNostrPrivateEndpointFacts(descriptor: 4, device: wrongEndpoint.device,
            inode: wrongEndpoint.inode, fileType: wrongEndpoint.fileType, socketType: wrongEndpoint.socketType,
            localFamily: wrongEndpoint.localFamily, peerFamily: wrongEndpoint.peerFamily,
            localUnnamed: wrongEndpoint.localUnnamed, peerUnnamed: wrongEndpoint.peerUnnamed,
            localAddress: wrongEndpoint.localAddress, peerAddress: wrongEndpoint.peerAddress)
        try positiveRefusalPositive { try AgentNostrParentPolicy.require(agentNostrPeerFacts(endpoint: wrongEndpoint)) }
    }

    // The framing word is exactly four big-endian bytes and bounded before body reads.
    // These pure helpers do not test socket EOF, process lifecycle, deadlines or parent credentials.
    @Test func boundedFrameWordsAndFixedResponseHeader() throws {
        #expect(try AgentNostrPrivateWire.requestLength(Data([0, 0, 0, 1])) == 1)
        #expect(try AgentNostrPrivateWire.requestLength(Data([0, 0, 128, 0])) == 32768)
        #expect(AgentNostrPrivateWire.responseHeader(status: 1, count: 0x010203) == Data([1, 0, 1, 2, 3]))
        for bytes in [Data(), Data([0, 0, 0]), Data([0, 0, 0, 0]), Data([0, 0, 128, 1]), Data([0, 0, 0, 1, 2])] {
            #expect(try AgentNostrPrivateWire.requestLength(Data([0, 0, 0, 1])) == 1)
            do { _ = try AgentNostrPrivateWire.requestLength(bytes); Issue.record("Expected invalid frame length refusal") }
            catch let failure as HelperError { #expect(failure.code == "bad_request") }
            catch { Issue.record("Unexpected frame-length error") }
            #expect(try AgentNostrPrivateWire.requestLength(Data([0, 0, 0, 1])) == 1)
        }
    }

    // Poll timeout arithmetic saturates at the fixed 120-second deadline without unsigned underflow.
    // Injected monotonic timestamps test arithmetic only, not scheduler timing or process termination.
    @Test func deadlinePollBoundsAtExpiry() throws {
        let start: UInt64 = 100
        #expect(try AgentNostrPrivateDeadline.pollMilliseconds(startedAt: start, now: start) == 100)
        #expect(try AgentNostrPrivateDeadline.pollMilliseconds(startedAt: start, now: start + 60_000_000_000) == 100)
        #expect(try AgentNostrPrivateDeadline.pollMilliseconds(startedAt: start, now: start + AgentNostrPrivateDeadline.budget - 1) == 1)
        #expect(agentNostrDeadlineRefused {
            _ = try AgentNostrPrivateDeadline.pollMilliseconds(startedAt: start, now: start + AgentNostrPrivateDeadline.budget)
        })
        #expect(agentNostrDeadlineRefused { _ = try AgentNostrPrivateDeadline.pollMilliseconds(startedAt: 2, now: 1) })
    }

    // Response sizes are operation-specific and refusals carry at most one fixed code.
    // These bound checks do not exercise caller EOF/exit acceptance or socket delivery.
    @Test func responseBoundsRejectOversizedOperationPayloads() throws {
        try AgentNostrPrivateWire.requireResponseBound(status: 0, operation: .createWrap, count: 1)
        try AgentNostrPrivateWire.requireResponseBound(status: 0, operation: .createWrap, count: 24576)
        try AgentNostrPrivateWire.requireResponseBound(status: 0, operation: .unwrapAgentNostr, count: 69)
        try AgentNostrPrivateWire.requireResponseBound(status: 1, operation: nil, count: 1)
        try AgentNostrPrivateWire.requireResponseBound(status: 1, operation: nil, count: 64)
        let invalidBounds: [(UInt8, AgentNostrPrivateRequest.Operation?, Int)] = [
            (0, .unwrapAgentNostr, 68),
            (0, .unwrapAgentNostr, 70),
            (0, .createWrap, 0),
            (0, .createWrap, 24577),
            (1, nil, 65),
            (2, nil, 1),
            (0, nil, 1),
        ]
        for (status, operation, count) in invalidBounds {
            let sibling: (UInt8, AgentNostrPrivateRequest.Operation?, Int)
            if status == 1 { sibling = (1, nil, 1) }
            else if status == 0 { sibling = (0, operation ?? .createWrap, operation == .unwrapAgentNostr ? 69 : 1) }
            else { sibling = (0, .createWrap, 1) }
            try AgentNostrPrivateWire.requireResponseBound(status: sibling.0, operation: sibling.1, count: sibling.2)
            #expect(agentNostrTransportRefused {
                try AgentNostrPrivateWire.requireResponseBound(status: status, operation: operation, count: count)
            })
            try AgentNostrPrivateWire.requireResponseBound(status: sibling.0, operation: sibling.1, count: sibling.2)
        }
    }

    // Only the seven contract statuses survive complete helper framing; raw errors never become status text.
    // This tests the closed mapping only, not parent-side EOF/exit authentication.
    @Test func helperErrorsMapToTheSevenFixedStatuses() {
        func map(_ code: String) -> String? {
            agentNostrPrivateStatus(HelperError(code: code, status: -25293, message: "synthetic"))?.rawValue
        }
        #expect(map("bad_request") == "bad_request")
        #expect(map("invalid_blob") == "invalid_blob")
        #expect(map("policy_refused") == "policy_refused")
        #expect(map("presence_required") == "presence_required")
        for code in ["auth_refused", "auth_failed", "user_canceled", "presence_unavailable", "presence_failed"] {
            #expect(map(code) == "auth_refused")
        }
        #expect(map("enclave_unavailable") == "enclave_unavailable")
        #expect(map("unexpected") == "enclave_unavailable")
        #expect(agentNostrPrivateStatus(AgentNostrPrivateRuntimeError.parentNotAdmitted)?.rawValue == "parent_not_admitted")
        #expect(agentNostrPrivateStatus(AgentNostrPrivateRuntimeError.deadlineExpired)?.rawValue == nil)
        #expect(agentNostrPrivateStatus(AgentNostrPrivateRuntimeError.transport)?.rawValue == nil)
        #expect(Set(AgentNostrPrivateStatus.allCases.map(\.rawValue)) == Set([
            "bad_request", "invalid_blob", "policy_refused", "presence_required",
            "auth_refused", "enclave_unavailable", "parent_not_admitted",
        ]))
    }

    // The route validates identity before the private operation and again before release.
    // This fake models the seam only; it performs no socket, SecCode or Secure Enclave action.
    @Test func flowRequiresAdmissionBeforeOperationAndRelease() throws {
        let checker = AgentNostrFlowChecker()
        var performed = 0
        var released = 0
        try AgentNostrPrivateFlow.run(checker: checker,
            parse: { AgentNostrFlowValue() },
            prepare: { _ in AgentNostrFlowValue() },
            perform: { _ in performed += 1; return Data([42]) },
            release: { operation, payload in
                released += 1
                #expect(operation == .createWrap)
                #expect(payload == Data([42]))
            })
        #expect(checker.revalidations == 2)
        #expect(performed == 1)
        #expect(released == 1)

        let rejectedBeforePrivateUse = AgentNostrFlowChecker()
        rejectedBeforePrivateUse.failAtRevalidation = 1
        performed = 0
        released = 0
        #expect(agentNostrRefused {
            try AgentNostrPrivateFlow.run(checker: rejectedBeforePrivateUse,
                parse: { AgentNostrFlowValue() },
                prepare: { _ in AgentNostrFlowValue() },
                perform: { _ in performed += 1; return Data([42]) },
                release: { _, _ in released += 1 })
        })
        #expect(performed == 0)
        #expect(released == 0)

        let lostAfterPrivateUse = AgentNostrFlowChecker()
        performed = 0
        released = 0
        #expect(agentNostrRefused {
            try AgentNostrPrivateFlow.run(checker: lostAfterPrivateUse,
                parse: { AgentNostrFlowValue() },
                prepare: { _ in AgentNostrFlowValue() },
                perform: { _ in
                    performed += 1
                    lostAfterPrivateUse.failAtRevalidation = lostAfterPrivateUse.revalidations + 1
                    return Data([42])
                },
                release: { _, _ in released += 1 })
        })
        #expect(performed == 1)
        #expect(released == 0)
    }

    // Parse or validation refusals are rechecked against the same admitted process before a status is formed.
    // The injected checker observes ordering only; actual refusal delivery is a native-only check.
    @Test func parseFailureRevalidatesBeforeStatusSelection() throws {
        let stable = AgentNostrFlowChecker()
        do {
            try AgentNostrPrivateFlow.run(checker: stable,
                parse: { () throws -> AgentNostrFlowValue in throw HelperError(code: "bad_request", status: -50, message: "invalid private request") },
                prepare: { _ in AgentNostrFlowValue() },
                perform: { _ in Data([42]) },
                release: { _, _ in Issue.record("A parse refusal must not release a success frame") })
            Issue.record("Expected malformed input refusal")
        } catch let failure as HelperError { #expect(failure.code == "bad_request") }
        #expect(stable.revalidations == 1)

        let changed = AgentNostrFlowChecker()
        changed.failAtRevalidation = 1
        #expect(agentNostrRefused {
            try AgentNostrPrivateFlow.run(checker: changed,
                parse: { () throws -> AgentNostrFlowValue in throw HelperError(code: "bad_request", status: -50, message: "invalid private request") },
                prepare: { _ in AgentNostrFlowValue() },
                perform: { _ in Data([42]) },
                release: { _, _ in Issue.record("A lost parent identity must not release a response") })
        })
    }

    // Canonical request positives come from Go fixture A; malformed requests are paired with A before and after.
    // The injected private operation proves dispatch ordering only, not AEAD opening or a hardware key.
    @Test func fixedPrivateRequestFormsAndRefusals() throws {
        var create = Data(#"{"op":"create-wrap","purpose":"nostr"}"#.utf8)
        let createRequest = try AgentNostrPrivateRequest.decode(&create)
        #expect(createRequest.operation == .createWrap)

        let fixture = try agentNostrFixture("fixture-a")
        let envelopeText = try #require(fixture["envelope_json"] as? String)
        let envelopeData = Data(envelopeText.utf8)
        let envelope = try #require(JSONSerialization.jsonObject(with: envelopeData) as? [String: String])
        let requestText = #"{"op":"unwrap-agent-nostr","blob":"\#(try #require(envelope["enclave_blob"]))","point":"\#(try #require(envelope["point"]))","ciphertext":"\#(try #require(envelope["ciphertext"]))"}"#
        var requestBytes = Data(requestText.utf8)
        let request = try AgentNostrPrivateRequest.decode(&requestBytes)
        #expect(request.operation == .unwrapAgentNostr)
        #expect(request.ciphertext.count == 150)
        #expect(request.point.count == 65)
        var prepared = try AgentNostrPrivateOperation.prepare(request)
        #expect(prepared.operation == .unwrapAgentNostr)
        #expect(prepared.ephemeral.map { _ in true } == true)
        prepared.eraseOwnedBuffers()

        let maxBlobText = Data(repeating: 2, count: 16384).base64EncodedString()
        let maxBlobRequest = #"{"op":"unwrap-agent-nostr","blob":"\#(maxBlobText)","point":"\#(envelope["point"]!)","ciphertext":"\#(envelope["ciphertext"]!)"}"#
        let reorderedRequest = #"{"blob":"\#(envelope["enclave_blob"]!)","op":"unwrap-agent-nostr","point":"\#(envelope["point"]!)","ciphertext":"\#(envelope["ciphertext"]!)"}"#
        var maxBlobBytes = Data(maxBlobRequest.utf8)
        #expect(try AgentNostrPrivateRequest.decode(&maxBlobBytes).blob.count == 16384)

        let malformedRequests = [
            #"{"purpose":"nostr","op":"create-wrap"}"#,
            #"{"op":"create-wrap","purpose":"nostr","extra":"x"}"#,
            maxBlobRequest.replacingOccurrences(of: maxBlobText, with: Data(repeating: 2, count: 16385).base64EncodedString()),
            reorderedRequest,
            requestText + " ",
        ]
        var privateUses = 0
        var releases = 0
        let checker = AgentNostrFlowChecker()
        let createText = #"{"op":"create-wrap","purpose":"nostr"}"#
        func runValid(_ text: String) throws {
            var bytes = Data(text.utf8)
            try AgentNostrPrivateFlow.run(checker: checker,
                parse: { try AgentNostrPrivateRequest.decode(&bytes) },
                prepare: { try AgentNostrPrivateOperation.prepare($0) },
                perform: { prepared in
                    privateUses += 1
                    #expect(prepared.operation == (text == createText ? .createWrap : .unwrapAgentNostr))
                    return Data([0x41])
                },
                release: { _, payload in releases += 1; #expect(payload == Data([0x41])) })
        }
        for malformed in malformedRequests {
            let validSibling = malformed.contains("create-wrap") ? createText : requestText
            try runValid(validSibling)
            let priorPrivateUses = privateUses
            let priorReleases = releases
            var bytes = Data(malformed.utf8)
            do {
                try AgentNostrPrivateFlow.run(checker: checker,
                    parse: { try AgentNostrPrivateRequest.decode(&bytes) },
                    prepare: { try AgentNostrPrivateOperation.prepare($0) },
                    perform: { _ in privateUses += 1; return Data([0x42]) },
                    release: { _, _ in releases += 1 })
                Issue.record("Expected malformed private request refusal")
            } catch let failure as HelperError { #expect(failure.code == "bad_request") }
            catch { Issue.record("Unexpected malformed-request result") }
            #expect(privateUses == priorPrivateUses)
            #expect(releases == priorReleases)
            try runValid(validSibling)
        }
    }

    // A canonical-length but invalid wrapping point is paired with fixture A before and after the guard.
    // The injected operation proves no dispatch; it does not open fixture AEAD or touch hardware.
    @Test func invalidPublicPointStopsBeforePrivateUse() throws {
        let fixture = try agentNostrFixture("fixture-a")
        let envelopeText = try #require(fixture["envelope_json"] as? String)
        let envelope = try #require(JSONSerialization.jsonObject(with: Data(envelopeText.utf8)) as? [String: String])
        let pointText = Data([5] + [UInt8](repeating: 0, count: 64)).base64EncodedString()
        let requestText = #"{"op":"unwrap-agent-nostr","blob":"\#(envelope["enclave_blob"]!)","point":"\#(pointText)","ciphertext":"\#(envelope["ciphertext"]!)"}"#
        var privateUse = 0
        var release = 0
        let checker = AgentNostrFlowChecker()
        func runValidFixtureA() throws {
            var bytes = Data(#"{"op":"unwrap-agent-nostr","blob":"\#(envelope["enclave_blob"]!)","point":"\#(envelope["point"]!)","ciphertext":"\#(envelope["ciphertext"]!)"}"#.utf8)
            try AgentNostrPrivateFlow.run(checker: checker,
                parse: { try AgentNostrPrivateRequest.decode(&bytes) },
                prepare: { try AgentNostrPrivateOperation.prepare($0) },
                perform: { _ in privateUse += 1; return Data(repeating: 0x41, count: 69) },
                release: { _, payload in release += 1; #expect(payload.count == 69) })
        }
        try runValidFixtureA()
        let priorPrivateUse = privateUse
        let priorRelease = release
        do {
            try AgentNostrPrivateFlow.run(checker: checker,
                parse: {
                    var bytes = Data(requestText.utf8)
                    return try AgentNostrPrivateRequest.decode(&bytes)
                },
                prepare: { try AgentNostrPrivateOperation.prepare($0) },
                perform: { _ in privateUse += 1; return Data(repeating: 0x42, count: 69) },
                release: { _, _ in release += 1 })
            Issue.record("Invalid P-256 point must refuse before private use")
        } catch let failure as HelperError { #expect(failure.code == "bad_request") }
        #expect(checker.revalidations == 3)
        #expect(privateUse == priorPrivateUse)
        #expect(release == priorRelease)
        try runValidFixtureA()
    }

    // The Go public fixture checks the canonical five-field create-wrap payload and its point fingerprint.
    // Its marker blob is only a serializer input; no Secure Enclave item is created or read.
    @Test func createWrapResponseIsCanonicalAndBounded() throws {
        let fixture = try agentNostrFixture("fixture-a")
        let envelopeText = try #require(fixture["envelope_json"] as? String)
        let envelope = try #require(JSONSerialization.jsonObject(with: Data(envelopeText.utf8)) as? [String: String])
        let fingerprint = try #require(envelope["fingerprint"])
        let blobText = try #require(envelope["enclave_blob"])
        let pointText = try #require(envelope["point"])
        let blob = try #require(Data(base64Encoded: blobText))
        let point = try #require(Data(base64Encoded: pointText))
        let response = try AgentNostrPrivateWrapResult.encode(blob: blob, point: point)
        let result = try #require(JSONSerialization.jsonObject(with: response) as? [String: Any])
        #expect(Set(result.keys) == Set(["blob", "fingerprint", "point", "policy", "silent_refused"]))
        #expect(result["blob"] as? String == blobText)
        #expect(result["point"] as? String == pointText)
        #expect((result["fingerprint"] as? String) == fingerprint)
        #expect(result["policy"] as? String == "none")
        #expect(result["silent_refused"] as? Bool == false)
        let expected = #"{"blob":"\#(blobText)","fingerprint":"\#(fingerprint)","point":"\#(pointText)","policy":"none","silent_refused":false}"#
        #expect(response == Data(expected.utf8))
        let maxBlobResult = try AgentNostrPrivateWrapResult.encode(blob: Data(repeating: 1, count: 16384), point: point)
        #expect(maxBlobResult.count <= AgentNostrPrivateWire.maximumWrapResponse)

        let invalidCurvePoint = Data([4] + [UInt8](repeating: 0, count: 64))
        for bad in [(Data(), point), (Data(repeating: 1, count: 16385), point),
                    (blob, Data(point.dropLast())), (blob, invalidCurvePoint)] {
            #expect(try AgentNostrPrivateWrapResult.encode(blob: blob, point: point) == response)
            do { _ = try AgentNostrPrivateWrapResult.encode(blob: bad.0, point: bad.1); Issue.record("Expected invalid wrap result refusal") }
            catch let failure as HelperError { #expect(failure.code == "invalid_blob") }
            #expect(try AgentNostrPrivateWrapResult.encode(blob: blob, point: point) == response)
        }
    }

    // Fixture A and its independently sealed KVAX1 mutant exercise CryptoKit ECDH/KDF/AES-GCM and the domain guard.
    // The scalar-1 software wrapper key exists only in this test; Secure Enclave loading and ACLs remain untested.
    @Test func fixtureDomainAndExactLengthAreEnforced() throws {
        let valid = try agentNostrFixture("fixture-a")
        let invalid = try agentNostrFixture("mutant-domain-kvax1")
        let validPlaintext = try agentNostrHex(try #require(valid["plaintext_hex"] as? String))
        let mutantPlaintext = try agentNostrHex(try #require(invalid["plaintext_hex"] as? String))
        #expect(mutantPlaintext.count == 69)
        #expect(mutantPlaintext.prefix(5) == Data("KVAX1".utf8))
        var wrongLength = validPlaintext
        wrongLength.append(0)
        let validEnvelopeText = try #require(valid["envelope_json"] as? String)
        let validEnvelope = try #require(JSONSerialization.jsonObject(with: Data(validEnvelopeText.utf8)) as? [String: String])
        let validPoint = try #require(Data(base64Encoded: validEnvelope["point"]!))
        var scalar = Data(repeating: 0, count: 32)
        scalar[31] = 1 // The Go fixture oracle's public test-only wrapping scalar for fixture A.
        defer { scalar.resetBytes(in: 0..<scalar.count) }
        let wrappingKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: scalar)
        #expect(wrappingKey.publicKey.x963Representation == validPoint)

        func requestText(_ fixture: [String: Any]) throws -> String {
            let envelopeText = try #require(fixture["envelope_json"] as? String)
            let envelope = try #require(JSONSerialization.jsonObject(with: Data(envelopeText.utf8)) as? [String: String])
            return #"{"op":"unwrap-agent-nostr","blob":"\#(try #require(envelope["enclave_blob"]))","point":"\#(try #require(envelope["point"]))","ciphertext":"\#(try #require(envelope["ciphertext"]))"}"#
        }
        let validRequest = try requestText(valid)
        let mutantRequest = try requestText(invalid)
        let checker = AgentNostrFlowChecker()
        var privateUses = 0
        var plaintextReleases = 0
        func run(_ rawRequest: String) throws {
            var bytes = Data(rawRequest.utf8)
            try AgentNostrPrivateFlow.run(checker: checker,
                parse: { try AgentNostrPrivateRequest.decode(&bytes) },
                prepare: { try AgentNostrPrivateOperation.prepare($0) },
                perform: { prepared in
                    privateUses += 1
                    guard let ephemeral = prepared.ephemeral else { throw AgentNostrTestFailure.fixture }
                    let secret = try wrappingKey.sharedSecretFromKeyAgreement(with: ephemeral)
                    return try AgentNostrPrivateOperation.open(ciphertext: prepared.ciphertext, sharedSecret: secret)
                },
                release: { _, payload in
                    plaintextReleases += 1
                    #expect(payload == validPlaintext)
                })
        }
        try run(validRequest)
        #expect(plaintextReleases == 1)
        let usesBeforeDomainRefusal = privateUses
        let releasesBeforeDomainRefusal = plaintextReleases
        do {
            try run(mutantRequest)
            Issue.record("Valid-AEAD KVAX1 plaintext must refuse before response release")
        } catch let failure as HelperError {
            #expect(failure.code == "invalid_blob")
            #expect(failure.message == "invalid agent Nostr plaintext")
        }
        #expect(privateUses == usesBeforeDomainRefusal + 1)
        #expect(plaintextReleases == releasesBeforeDomainRefusal)
        try run(validRequest)
        #expect(plaintextReleases == releasesBeforeDomainRefusal + 1)

        var validCiphertext = try #require(Data(base64Encoded: validEnvelope["ciphertext"]!))
        validCiphertext[validCiphertext.count - 1] ^= 1
        let tamperedRequest = #"{"op":"unwrap-agent-nostr","blob":"\#(validEnvelope["enclave_blob"]!)","point":"\#(validEnvelope["point"]!)","ciphertext":"\#(validCiphertext.base64EncodedString())"}"#
        let usesBeforeTagRefusal = privateUses
        let releasesBeforeTagRefusal = plaintextReleases
        do {
            try run(tamperedRequest)
            Issue.record("Modified GCM tag must refuse before response release")
        } catch let failure as HelperError {
            #expect(failure.code == "invalid_blob")
            #expect(failure.message == "ciphertext authentication failed")
        }
        #expect(privateUses == usesBeforeTagRefusal + 1)
        #expect(plaintextReleases == releasesBeforeTagRefusal)
        try run(validRequest)
        #expect(plaintextReleases == releasesBeforeTagRefusal + 1)

        let releasesBeforeLengthControl = plaintextReleases
        try run(validRequest)
        try AgentNostrPrivatePlaintext.require(validPlaintext)
        do {
            try AgentNostrPrivatePlaintext.require(wrongLength)
            Issue.record("The 70-byte plaintext must refuse")
        } catch let failure as HelperError { #expect(failure.code == "invalid_blob") }
        try AgentNostrPrivatePlaintext.require(validPlaintext)
        try run(validRequest)
        #expect(plaintextReleases == releasesBeforeLengthControl + 2)
    }
}
