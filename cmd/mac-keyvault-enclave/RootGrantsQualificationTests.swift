// Swift Testing SOURCE for PUBLIC representation/selection/status controls.
// No test invokes a signature, Keychain, SPI, helper, private ABI, LAContext,
// Enclave or owner operation. Actual code/ACL/timeout qualification is NOT_RUN.
import CoreFoundation
import Foundation
import Security
import Testing
@testable import KeyvaultNativeCore

private let qualificationDigest = String(repeating: "a", count: 64)
private func qualificationJSON(reference: Data = Data([1, 2, 3]), digest: String = qualificationDigest) -> Data {
    Data(#"{"schema":"keyvault-root-acl-qualification/1","namespace":"works.relux.mac-keyvault.root-acl-qualification.v1","account":"public-marker@1","item_class":"generic-password","persistent_reference":"\#(reference.base64EncodedString())","receipt_sha256":"\#(digest)"}"#.utf8)
}
private func qualificationRefused(_ operation: () throws -> Void) {
    do { try operation(); Issue.record("Expected fixed qualification refusal") }
    catch RootGrantsQualificationError.refused { }
    catch { Issue.record("Unexpected error class; details withheld") }
}
private func qualificationFacts() -> RootGrantsQualificationCodeFacts {
    // Synthetic PUBLIC identity fields, NOT native code/requirement evidence.
    RootGrantsQualificationCodeFacts(identifier: RootGrantsQualificationIdentity.identifier,
        team: RootGrantsQualificationIdentity.team, flags: 0x10000, dynamic: 0x10001,
        codeHash: Data(repeating: 1, count: 20), expectedRequirement: Data([1, 2, 3]),
        actualRequirement: Data([1, 2, 3]), leafSHA1: RootGrantsQualificationIdentity.leafSHA1,
        leafSHA256: RootGrantsQualificationIdentity.leafSHA256)
}

struct RootGrantsQualificationTests {
    // Exact byte encoding agrees with the published six-field form; maximum
    // reference and owned copies are exercised. No reference grants authority.
    @Test func canonicalPublicRequestAndOwnership() throws {
        let expected = Data((#"{"schema":"keyvault-root-acl-qualification/1","namespace":"works.relux.mac-keyvault.root-acl-qualification.v1","account":"public-marker@1","item_class":"generic-password","persistent_reference":"AQID","receipt_sha256":""# + qualificationDigest + #""}"#).utf8)
        #expect(qualificationJSON() == expected)
        for reference in [Data([0]), Data([1, 2, 3]), Data(repeating: 255, count: 16384)] {
            var original = qualificationJSON(reference: reference)
            let frozen = original
            let request = try RootGrantsQualificationRequest(ownedJSON: original)
            #expect(request.originalBytes == frozen)
            #expect(request.reference == reference)
            #expect(request.receiptSHA256 == qualificationDigest)
            original[original.startIndex] = 32
            #expect(request.originalBytes == frozen)
            var returned = request.reference
            returned[returned.startIndex] ^= 255
            #expect(request.reference == reference)
            let framed = RootGrantsQualificationWire.word(UInt32(frozen.count)) + frozen
            #expect(try RootGrantsQualificationWire.body(framed) == frozen)
        }
        let mutable = NSMutableData(data: qualificationJSON())
        let request = try RootGrantsQualificationRequest(ownedJSON: Data(referencing: mutable))
        mutable.resetBytes(in: NSRange(location: 0, length: mutable.length))
        #expect(request.originalBytes == expected)
        #expect(request.reference == Data([1, 2, 3]))
    }

    // Positive frame limits are framing ONLY, not valid JSON/OS admission.
    // Truncation/trailing/second-frame bytes refuse before any native probe.
    @Test func exactFramingBoundsAndEOFRepresentation() throws {
        for count in [1, 32768] {
            let payload = Data(repeating: 65, count: count)
            let frame = RootGrantsQualificationWire.word(UInt32(count)) + payload
            #expect(try RootGrantsQualificationWire.body(frame) == payload)
            qualificationRefused { _ = try RootGrantsQualificationWire.body(Data(frame.dropLast())) }
            qualificationRefused { _ = try RootGrantsQualificationWire.body(frame + Data([0])) }
            qualificationRefused { _ = try RootGrantsQualificationWire.body(frame + frame) }
        }
        for bytes in [Data(), Data([0, 0, 0]), Data([0, 0, 0, 0]),
                      RootGrantsQualificationWire.word(32769), Data([255, 255, 255, 255])] {
            qualificationRefused { _ = try RootGrantsQualificationWire.body(bytes) }
        }
        #expect(try RootGrantsQualificationWire.length(Data([0, 0, 128, 0])) == 32768)
        qualificationRefused { _ = try RootGrantsQualificationWire.length(Data([0, 0, 0, 1, 0])) }
        qualificationRefused { _ = try RootGrantsQualificationRequest(ownedJSON: Data(repeating: 65, count: 32769)) }
    }

    // Fixed namespace/account/class and exact canonical syntax are positive
    // admission forms. These are parser controls, not actual ACL denials.
    @Test func canonicalClosedFieldsAndBindings() throws {
        let valid = qualificationJSON()
        let text = String(decoding: valid, as: UTF8.self)
        #expect(try RootGrantsQualificationRequest(ownedJSON: valid).reference == Data([1, 2, 3]))
        let mutations = [
            text.replacingOccurrences(of: "keyvault-root-acl-qualification/1", with: "keyvault-root-acl-qualification/2"),
            text.replacingOccurrences(of: "works.relux.mac-keyvault.root-acl-qualification.v1", with: "works.relux.mac-keyvault.root.v1"),
            text.replacingOccurrences(of: "public-marker@1", with: "public-marker@2"),
            text.replacingOccurrences(of: "public-marker@1", with: "PUBLIC-MARKER@1"),
            text.replacingOccurrences(of: "generic-password", with: "internet-password"),
            text.replacingOccurrences(of: "persistent_reference", with: "persistent_ref"),
            text.replacingOccurrences(of: "receipt_sha256", with: "receipt_hash"),
            text.replacingOccurrences(of: #""account":"public-marker@1",""#, with: ""),
            text.replacingOccurrences(of: #""item_class":"generic-password""#, with: #""item_class":null"#),
            text.replacingOccurrences(of: #""persistent_reference":"AQID""#, with: #""persistent_reference":12"#),
            text.replacingOccurrences(of: #""account":"public-marker@1""#, with: #""account":"public-marker@1","account":"public-marker@1""#),
            text.replacingOccurrences(of: #""schema":"keyvault-root-acl-qualification/1","namespace":"works.relux.mac-keyvault.root-acl-qualification.v1""#,
                with: #""namespace":"works.relux.mac-keyvault.root-acl-qualification.v1","schema":"keyvault-root-acl-qualification/1""#),
            text.replacingOccurrences(of: "public-marker@1", with: #"public\u002dmarker@1"#),
            text.replacingOccurrences(of: "public-marker@1", with: "public-marker@1\n"),
            text.replacingOccurrences(of: "public-marker@1", with: "public-marker@1\u{202e}"),
            " " + text, text + "\n", text + "{}", "[" + text + "]",
            text.replacingOccurrences(of: "\":\"", with: "\": \"")
        ]
        for candidate in mutations {
            qualificationRefused { _ = try RootGrantsQualificationRequest(ownedJSON: Data(candidate.utf8)) }
        }
    }

    // Reference bytes are public selection, never receipt/path authority.
    // Canonical pad bits, byte limits and lowercase receipt hash are enforced.
    @Test func referenceAndHashClosedForms() throws {
        for digest in [qualificationDigest, String(repeating: "0", count: 64), String(repeating: "f", count: 64)] {
            #expect(try RootGrantsQualificationRequest(ownedJSON: qualificationJSON(digest: digest)).receiptSHA256 == digest)
        }
        for digest in ["", String(repeating: "a", count: 63), String(repeating: "a", count: 65),
                       String(repeating: "A", count: 64), String(repeating: "g", count: 64), "\n" + String(repeating: "a", count: 63)] {
            qualificationRefused { _ = try RootGrantsQualificationRequest(ownedJSON: qualificationJSON(digest: digest)) }
        }
        for reference in [Data(), Data(repeating: 1, count: 16385)] {
            qualificationRefused { _ = try RootGrantsQualificationRequest(ownedJSON: qualificationJSON(reference: reference)) }
        }
        let one = String(decoding: qualificationJSON(reference: Data([1])), as: UTF8.self)
        #expect(try RootGrantsQualificationRequest(ownedJSON: Data(one.utf8)).reference == Data([1]))
        for encoded in ["", "AQ", "AR==", "AQ===", "AQ==\r\n", "_Q==", "-Q==", " AQ=="] {
            let bad = one.replacingOccurrences(of: "AQ==", with: encoded)
            qualificationRefused { _ = try RootGrantsQualificationRequest(ownedJSON: Data(bad.utf8)) }
        }
    }

    // A foreign reference is not trusted metadata: the actual query retains
    // ALL fixed filters plus sole persistent-ref matchItemList. Actual wrong-
    // namespace/account/reference-source OS fixtures remain separately NOT_RUN.
    @Test func filteredReferenceSourceAndNoPathAuthority() throws {
        for reference in [Data([1]), Data([2, 3, 4])] {
            let request = try RootGrantsQualificationRequest(ownedJSON: qualificationJSON(reference: reference))
            let query = request.metadataFilters()
            #expect(query.count == 6)
            #expect(query[kSecClass as String] as? String == kSecClassGenericPassword as String)
            #expect(query[kSecAttrService as String] as? String == RootGrantsQualificationWire.namespace)
            #expect(query[kSecAttrAccount as String] as? String == RootGrantsQualificationWire.account)
            #expect(query[kSecMatchLimit as String] as? String == kSecMatchLimitOne as String)
            #expect(query[kSecReturnRef as String] as? Bool == true)
            let items = try #require(query[kSecMatchItemList as String] as? [Data])
            #expect(items == [reference])
            #expect(query[kSecValuePersistentRef as String] == nil)
            #expect(query[kSecUseItemList as String] == nil)
            #expect(query[kSecMatchSearchList as String] == nil) // Added ONLY by actual OS-account selection.
            #expect(query[kSecReturnData as String] == nil)
        }
        let text = String(decoding: qualificationJSON(), as: UTF8.self)
        for key in ["reference_source", "receipt_path", "path", "service", "kSecValuePersistentRef", "kSecUseItemList"] {
            let bad = String(text.dropLast()) + ",\"" + key + "\":\"public-fixture\"}"
            qualificationRefused { _ = try RootGrantsQualificationRequest(ownedJSON: Data(bad.utf8)) }
        }
    }

    // Only the exact sole route argument is admitted. No actual dispatcher,
    // process, pipe descriptor or Keychain API is executed by this control.
    @Test func exactArgumentsAndNoReferenceParameters() throws {
        for executable in ["helper", "/public-fixture/mac-keyvault-enclave"] {
            try RootGrantsQualificationWire.requireArguments([executable, "--root-grants-qualification-read"])
        }
        for arguments in [[], ["helper"], ["helper", "--root-grants-qualification-read", "AQID"],
                          ["helper", "--root-grants-qualification-read", "--service", "public-fixture"],
                          ["helper", "--root-grants-qualification-read "], ["helper", "--ROOT-GRANTS-QUALIFICATION-READ"],
                          ["helper", "--root-grants-private-v2"], ["helper", "--root-grants-qualification-read", "--root-grants-qualification-read"]] {
            qualificationRefused { try RootGrantsQualificationWire.requireArguments(arguments) }
        }
    }

    // Fixed output/status mapping only. A startup/selection/metadata denial is
    // never an ACL PASS; successful marker access always fails qualification.
    @Test func finiteResponsesAndOnlyActualDataCallDenials() {
        let outputs: [RootGrantsQualificationResult: String] = [
            .accessRefused: "{\"schema\":\"keyvault-root-acl-qualification/1\",\"result\":\"access-refused\"}\n",
            .unexpectedAccess: "{\"schema\":\"keyvault-root-acl-qualification/1\",\"result\":\"unexpected-access\"}\n",
            .unqualified: "{\"schema\":\"keyvault-root-acl-qualification/1\",\"result\":\"unqualified\"}\n"
        ]
        #expect(RootGrantsQualificationResult.allCases.count == 3)
        for (result, expected) in outputs { #expect(result.response == Data(expected.utf8)) }
        for stage in RootGrantsQualificationResult.Stage.allCases {
            for status in [KeyvaultNativeCore.errSecAuthFailed, KeyvaultNativeCore.errSecInteractionNotAllowed] {
                #expect(RootGrantsQualificationResult.classify(status, at: stage) == (stage == .markerData ? .accessRefused : .unqualified))
            }
        }
        #expect(RootGrantsQualificationResult.classify(errSecSuccess, at: .markerData) == .unexpectedAccess)
        for stage in [RootGrantsQualificationResult.Stage.startup, .selection, .metadata] {
            #expect(RootGrantsQualificationResult.classify(errSecSuccess, at: stage) == .unqualified)
        }
        for status in [errSecItemNotFound, KeyvaultNativeCore.errSecNotAvailable, KeyvaultNativeCore.errSecUserCanceled, KeyvaultNativeCore.errSecDecode, OSStatus(-1), OSStatus(123)] {
            #expect(RootGrantsQualificationResult.classify(status, at: .markerData) == .unqualified)
        }
    }

    // Synthetic public representation controls, NOT native signature/trust or
    // compiled designated-requirement proof. Actual native checks are mandatory.
    @Test func exactHelperIdentityFlagsPinsAndRequirementBinding() throws {
        for length in [20, 32] {
            var facts = qualificationFacts()
            facts.codeHash = Data(repeating: 1, count: length)
            try RootGrantsQualificationIdentity.require(facts)
        }
        for flags in [UInt32(0), 2, 0x10001, 0x10002, 0x10003, 0x20000, UInt32.max] {
            var facts = qualificationFacts(); facts.flags = flags
            qualificationRefused { try RootGrantsQualificationIdentity.require(facts) }
        }
        for dynamic in [UInt32(0), 1, 0x10000, 0x10010001] {
            var facts = qualificationFacts(); facts.dynamic = dynamic
            qualificationRefused { try RootGrantsQualificationIdentity.require(facts) }
        }
        var controls: [RootGrantsQualificationCodeFacts] = []
        var facts = qualificationFacts(); facts.identifier = "works.relux.mac-keyvault"; controls.append(facts)
        facts = qualificationFacts(); facts.identifier += ".other"; controls.append(facts)
        facts = qualificationFacts(); facts.team = "OTHERTEAM0"; controls.append(facts)
        facts = qualificationFacts(); facts.leafSHA1 = String(repeating: "0", count: 40); controls.append(facts)
        facts = qualificationFacts(); facts.leafSHA256 = String(repeating: "0", count: 64); controls.append(facts)
        facts = qualificationFacts(); facts.actualRequirement = Data([1, 2, 4]); controls.append(facts)
        facts = qualificationFacts(); facts.expectedRequirement = Data(); facts.actualRequirement = Data(); controls.append(facts)
        facts = qualificationFacts(); facts.expectedRequirement = Data(repeating: 1, count: 32769); facts.actualRequirement = facts.expectedRequirement; controls.append(facts)
        for count in [0, 19, 21, 31, 33] {
            facts = qualificationFacts(); facts.codeHash = Data(repeating: 1, count: count); controls.append(facts)
        }
        for facts in controls { qualificationRefused { try RootGrantsQualificationIdentity.require(facts) } }
        #expect(RootGrantsQualificationIdentity.requirement == #"identifier "works.relux.keyvault.enclave" and anchor apple generic and certificate leaf = H"d71190abe54185f908169ee9ca538d4066942c0f" and certificate 1[field.1.2.840.113635.100.6.2.1]"#)
    }

    // Positive integer/empty-entitlement forms beside coercion controls. These
    // checks do not replace actual SecCodeCopySigningInformation/validity calls.
    @Test func strictCodeInformationTypesAndEntitlements() throws {
        for number in [NSNumber(value: UInt32(0)), NSNumber(value: UInt32(0x10000)), NSNumber(value: UInt32.max)] {
            #expect(try RootGrantsQualificationIdentity.exactUInt32(number) == number.uint32Value)
        }
        let invalid: [Any?] = [nil, NSNull(), true, NSNumber(value: true), "65536", NSNumber(value: -1),
                              NSNumber(value: UInt64(UInt32.max) + 1), NSNumber(value: UInt64.max),
                              NSNumber(value: 65536.0), NSNumber(value: 65536.5)]
        for value in invalid { qualificationRefused { _ = try RootGrantsQualificationIdentity.exactUInt32(value) } }
        try RootGrantsQualificationIdentity.requireEmptyEntitlements(nil)
        try RootGrantsQualificationIdentity.requireEmptyEntitlements([String: Any]())
        let invalidEntitlements: [Any] = [NSNull(), [Any](), "", ["com.apple.security.get-task-allow": true], ["unexpected": false]]
        for value in invalidEntitlements {
            qualificationRefused { try RootGrantsQualificationIdentity.requireEmptyEntitlements(value) }
        }
    }

    // Synthetic symbol-presence and admission-order model ONLY. No dlsym/SPI
    // invocation or real Keychain query occurs; native call order is separately
    // checked in the source witness. An arbitrary pointer is never called.
    @Test func missingSymbolsAndBadAdmissionCannotReachModeledQuery() throws {
        var byte: UInt8 = 0
        try withUnsafeMutablePointer(to: &byte) { pointer in
            let present = UnsafeMutableRawPointer(pointer)
            try RootGrantsQualificationIdentity.requireSymbols(copy: present, create: present)
            let pairs: [(UnsafeMutableRawPointer?, UnsafeMutableRawPointer?)] = [(nil, nil), (present, nil), (nil, present)]
            for pair in pairs {
                var queries = 0
                qualificationRefused {
                    try RootGrantsQualificationIdentity.requireSymbols(copy: pair.0, create: pair.1)
                    try RootGrantsQualificationIdentity.require(qualificationFacts())
                    queries += 1 // Model counter, never native authority.
                }
                #expect(queries == 0)
            }
            var facts = qualificationFacts(); facts.flags = 0x10002
            var queries = 0
            qualificationRefused {
                try RootGrantsQualificationIdentity.requireSymbols(copy: present, create: present)
                try RootGrantsQualificationIdentity.require(facts)
                queries += 1
            }
            #expect(queries == 0)
        }
    }

    // One immutable monotonic 30s deadline across public phases; no real timing,
    // stuck Security call, Dispatch watchdog or TERM behavior is proven here.
    @Test func originalAbsoluteDeadlineNeverRenews() throws {
        let deadline = RootGrantsQualificationDeadline(startedAt: 1234)
        #expect(deadline.expiresAt == 30_000_001_234)
        for now in [UInt64(1234), 1235, 30_000_001_233] { try deadline.check(at: now) }
        qualificationRefused { try deadline.check(at: 1233) }
        qualificationRefused { try deadline.check(at: 30_000_001_234) }
        qualificationRefused { try deadline.check(at: UInt64.max) }
        #expect(deadline.expiresAt == 30_000_001_234)
        let overflow = RootGrantsQualificationDeadline(startedAt: UInt64.max - 10)
        #expect(overflow.expiresAt == UInt64.max)
        try overflow.check(at: UInt64.max - 1)
    }
}
