// Swift Testing SOURCE only. Build a test target with NamecoinJournalStorage.swift
// and this file, excluding main.swift/operations and their UI/dispatch. No test
// constructs NativeNamecoinJournalStorage or calls Keychain/code-identity/LA APIs.
import CryptoKit
import Foundation
import Security
import Testing
@testable import KeyvaultNativeCore

private let fixtureSidecarBase64 = "S1ZOUzEAAAAAEmZpeHR1cmUvcmVjb3ZlcnlAMQAAABF3YWxsZXQvbmFtZWNvaW5AMQMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAAAAEGZpeHR1cmUtcG9saWN5LTEAAAAPZml4dHVyZS9ub3N0ckAyAQAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQ=="

private func fixtureSelection(sidecar: Data? = nil, helperHash: Data? = nil) throws -> NativeJournalSelection {
    guard let publicSidecar = sidecar ?? Data(base64Encoded: fixtureSidecarBase64) else { throw NativeJournalRefusal.mismatch }
    return try NativeJournalSelection(group: "fixture/recovery@1", account: "wallet/namecoin@1",
                                      publicPin: Data(repeating: 3, count: 32), policy: "fixture-policy-1",
                                      helperCDHash: helperHash ?? Data(repeating: 9, count: 20), sidecar: publicSidecar)
}

private func expectNativeRefusal(_ expected: NativeJournalRefusal, _ operation: () throws -> Void) {
    do { try operation(); Issue.record("Expected a fixed native refusal") }
    catch let actual as NativeJournalRefusal { #expect(actual == expected) }
    catch { Issue.record("Unexpected error type; raw diagnostic intentionally withheld") }
}
private func fixtureHex(_ value: Data) -> String { value.map { String(format: "%02x", $0) }.joined() }

// Independent literal vectors use only public synthetic facts and were computed
// with a one-off stdlib SHA256/length-frame calculation from the written contract.
// They test representation/binding, not Go archive ABI, native custody or Touch ID.
@Test func nativePublicSelectionAndReviewVectors() throws {
    let selection = try fixtureSelection()
    #expect(selection.locator == "e5c1360201e9ed838c085610fce78de3ed75b4d81170bf49e4d2f1f18797b73c")
    #expect(selection.nostrAccount == "fixture/nostr@2")
    #expect(fixtureHex(Data(SHA256.hash(data: selection.metadata))) == "3a1ed5574a6e6f7fbe6ae858ac524dfdea46544c3ff883d645e1e6ffe4d7dcf9")
    let initialize = try NativeJournalOperationPlan(kind: .initialize, selection: selection, adoptionPlanDigest: Data(repeating: 10, count: 32))
    let reconcile = try NativeJournalOperationPlan(kind: .reconcile, selection: selection, adoptionPlanDigest: Data(repeating: 10, count: 32))
    #expect(fixtureHex(Data(SHA256.hash(data: initialize.reviewFrame))) == "bac17db74ac1b46ea5c6b3e5ee065535647feb82feacc4a02ea5482a6cfa1ea8")
    #expect(fixtureHex(Data(SHA256.hash(data: reconcile.reviewFrame))) == "7e7f9256fb842e3da78f835bf45865147c9ddbafdd73633d7bf7c61c1f65b5c9")
    #expect(initialize.reviewFrame != reconcile.reviewFrame)
    let otherPlan = try NativeJournalOperationPlan(kind: .initialize, selection: selection, adoptionPlanDigest: Data(repeating: 11, count: 32))
    #expect(initialize.reviewFrame != otherPlan.reviewFrame)
    expectNativeRefusal(.mismatch) { _ = try NativeJournalOperationPlan(kind: .initialize, selection: selection, adoptionPlanDigest: Data()) }
}

// Valid retained identity forms are paired with invalid encodings/path plants.
// These predicates are not authorization to select or enumerate any live item.
@Test func nativeIdentityCompatibility() {
    for value in ["a/recovery@1", "a-0/recovery@2", String(repeating: "a", count: 40) + "/recovery@2147483647"] {
        #expect(nativeJournalIdentity(value, purpose: "recovery"))
    }
    for value in ["", "a/recovery@0", "a/recovery@01", "a/recovery@+1", "A/recovery@1", "a/../recovery@1", "a/recovery@1/x", "a/nostr@1", "a/recovery@2147483648", "a/recovery@9223372036854775807", "a/recovery@9223372036854775808", String(repeating: "a", count: 41) + "/recovery@1"] {
        #expect(!nativeJournalIdentity(value, purpose: "recovery"))
    }
}

// Sidecar binding/length compatibility is checked before any native adapter is
// created. Arbitrary tail pin/hash changes are bound by metadata, not treated as
// independently authentic: those facts still need the trusted engine/rollout.
@Test func nativeSidecarBoundsAndOwnedSnapshot() throws {
    let selection = try fixtureSelection()
    for length in 0..<selection.sidecar.count {
        expectNativeRefusal(.mismatch) { _ = try fixtureSelection(sidecar: selection.sidecar.prefix(length)) }
    }
    var trailing = selection.sidecar
    trailing.append(0)
    expectNativeRefusal(.mismatch) { _ = try fixtureSelection(sidecar: trailing) }
    var changedBinding = selection.sidecar
    changedBinding[12] ^= 1
    expectNativeRefusal(.mismatch) { _ = try fixtureSelection(sidecar: changedBinding) }
    expectNativeRefusal(.mismatch) { _ = try fixtureSelection(helperHash: Data(repeating: 9, count: 21)) }
    let alternateCodeHash = try fixtureSelection(helperHash: Data(repeating: 8, count: 32))
    #expect(alternateCodeHash.metadata != selection.metadata)
    var changedPublicTail = selection.sidecar
    changedPublicTail[changedPublicTail.count - 1] ^= 1
    let changed = try fixtureSelection(sidecar: changedPublicTail)
    #expect(changed.metadata != selection.metadata)
    // Original immutable selected bytes remain unchanged after caller mutation.
    #expect(selection.sidecar != changedPublicTail)
}

// Public fixture memory only. This checks owned-copy behavior, fixed diagnostics
// and invalidation, not owner data, hardware custody or post-free memory contents.
// Compiler-resistant clearing is a source/SDK obligation, not a fake UI witness.
@Test func nativeOwnedBufferLifetime() throws {
    var publicBytes = [UInt8](repeating: 17, count: 64)
    let owned = try publicBytes.withUnsafeBufferPointer {
        try NativeSecretBytes(copying: UnsafeRawBufferPointer($0), maximum: 64)
    }
    defer { owned.clear() }
    publicBytes[0] = 18
    try owned.withBytes { #expect($0.count == 64 && $0[0] == 17) }
    #expect(owned.description == "<confined native bytes>")
    #expect(owned.debugDescription == "<confined native bytes>")
    owned.clear()
    owned.clear()
    expectNativeRefusal(.operational) { try owned.withBytes { _ in } }
    expectNativeRefusal(.mismatch) {
        _ = try publicBytes.withUnsafeBufferPointer {
            try NativeSecretBytes(copying: UnsafeRawBufferPointer($0), maximum: 63)
        }
    }
}

// Closed refusal classification only; no OS call is made and no successful
// native read/mutation is fabricated by a mock or a callback returning true.
@Test func nativeReadRefusalsStayClosed() {
    #expect(nativeJournalReadFailure(errSecItemNotFound) == .missing)
    for status in [KeyvaultNativeCore.errSecAuthFailed, KeyvaultNativeCore.errSecInteractionNotAllowed, KeyvaultNativeCore.errSecUserCanceled] {
        #expect(nativeJournalReadFailure(status) == .authenticationRefused)
    }
    #expect(nativeJournalReadFailure(KeyvaultNativeCore.errSecNotAvailable) == .operational)
    #expect(nativeJournalReadFailure(OSStatus(-987654)) == .operational)
}

// A synthetic physical anchor contains only public fixture bytes, NOT a valid
// authenticated token/owner key. Positive syntax cannot stand in for engine MAC,
// account rederivation, native protected read or successful initialization.
@Test func nativeProtectedAnchorShapeRefusals() throws {
    let selection = try fixtureSelection()
    var fixture = selection.anchorPrefix
    fixture.append(Data(repeating: 0, count: 8))
    fixture.append(selection.genesisHead)
    fixture.append(Data(repeating: 21, count: 64))
    try fixture.withUnsafeBytes {
        #expect(try nativeJournalAnchorSequence($0, selection: selection, initializing: true) == 0)
    }
    for length in 0..<fixture.count {
        expectNativeRefusal(.mismatch) {
            _ = try fixture.prefix(length).withUnsafeBytes { try nativeJournalAnchorSequence($0, selection: selection) }
        }
    }
    var wrongBinding = fixture
    wrongBinding[10] ^= 1
    expectNativeRefusal(.mismatch) {
        _ = try wrongBinding.withUnsafeBytes { try nativeJournalAnchorSequence($0, selection: selection) }
    }
    var nonGenesis = fixture
    nonGenesis[selection.anchorPrefix.count + 8] ^= 1
    expectNativeRefusal(.mismatch) {
        _ = try nonGenesis.withUnsafeBytes { try nativeJournalAnchorSequence($0, selection: selection, initializing: true) }
    }
    var notInitialization = fixture
    notInitialization[selection.anchorPrefix.count + 7] = 1
    expectNativeRefusal(.mismatch) {
        _ = try notInitialization.withUnsafeBytes { try nativeJournalAnchorSequence($0, selection: selection, initializing: true) }
    }
    try notInitialization.withUnsafeBytes {
        #expect(try nativeJournalAnchorSequence($0, selection: selection) == 1)
    }
}

// Pure transition compatibility, not successful Keychain update/authentication.
// Every key/token byte is synthetic public fixture material.
@Test func nativeReplacementCannotResetOrRekey() throws {
    let selection = try fixtureSelection()
    var previous = selection.anchorPrefix
    previous.append(Data(repeating: 0, count: 8))
    previous.append(selection.genesisHead)
    previous.append(Data(repeating: 21, count: 64))
    var next = previous
    next[selection.anchorPrefix.count + 7] = 1
    next[selection.anchorPrefix.count + 8] ^= 1
    try previous.withUnsafeBytes { oldBytes in
        try next.withUnsafeBytes { newBytes in
            try nativeJournalRequireReplacement(previous: oldBytes, next: newBytes, selection: selection)
        }
    }
    for kind in 0..<3 {
        var forbidden = next
        if kind == 0 { forbidden[selection.anchorPrefix.count + 7] = 0 }
        if kind == 1 { forbidden[selection.anchorPrefix.count + 7] = 2 }
        if kind == 2 { forbidden[selection.anchorPrefix.count + 40] ^= 1 }
        expectNativeRefusal(.mismatch) {
            try previous.withUnsafeBytes { oldBytes in
                try forbidden.withUnsafeBytes { newBytes in
                    try nativeJournalRequireReplacement(previous: oldBytes, next: newBytes, selection: selection)
                }
            }
        }
    }
}

// Pure compatibility controls for the two permitted static flag representations.
// NOT_RUN: these tests perform no signature, CDHash, entitlement, Keychain or
// native qualification checks; admission still requires the actual helper path.
@Test(arguments: [UInt32(0x10002), UInt32(0x10000)])
func nativeHelperRuntimeFlagsAdmitBothSupportedForms(_ flags: UInt32) {
    #expect(nativeJournalAdmitsHelperCodeFlags(flags))
}

// Each forbidden representation must refuse rather than merely contain runtime.
// Neighbor/extra-bit controls include ad-hoc without runtime, missing runtime,
// unrelated status/debug bits and unknown bits. No native authority is simulated;
// executable tests and actual code-signature qualification remain NOT_RUN.
@Test(arguments: [UInt32(0), UInt32(1), UInt32(2), UInt32(3),
                  UInt32(0x10001), UInt32(0x10003), UInt32(0x10004),
                  UInt32(0x10006), UInt32(0x10010), UInt32(0x10012),
                  UInt32(0x20000), UInt32(0x30000), UInt32(0x30002),
                  UInt32(0x10010000), UInt32(0x10010002), UInt32.max])
func nativeHelperRuntimeFlagsRefuseEveryListedOtherForm(_ flags: UInt32) {
    #expect(!nativeJournalAdmitsHelperCodeFlags(flags))
}
