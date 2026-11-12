// Swift Testing SOURCE only. Requires a target exposing the exact production
// review model and HelperError without executing main.swift's top-level dispatch.
// No copied model, fake native approval or success stub is a test integration.
// No test calls NamecoinReviewWindow, LAContext, Keychain, a helper or private use.
// All fixtures are public synthetic bytes. Compilation/execution and actual UI,
// layout, owner understanding, Touch ID and archive-to-facts binding are NOT_RUN.
import CryptoKit
import Foundation
import Testing
@testable import KeyvaultNativeCore

private let reviewPublicFrame = Data([0, 1, 2, 255])
private let reviewPublicDigest = "3d1f57c984978ef98a18378c8166c1cb8ede02c03eeb6aee7e2f121dfeee3e56"
private let reviewEndMarker = "END OF COMPLETE INTERNAL REVIEW"

private func expectReviewDisplayRefusal(_ message: String, _ body: () throws -> Void) {
    do { try body(); Issue.record("Expected the specific display refusal") }
    catch let error as HelperError {
        #expect(error.code == "document_display")
        #expect(error.status == KeyvaultNativeCore.errSecParam)
        #expect(error.message == message)
    } catch { Issue.record("Unexpected error type; raw diagnostic intentionally withheld") }
}

private func reviewBinaryFact(_ label: String = "Public script", _ bytes: Data = Data([0])) throws -> NamecoinReviewFact {
    try NamecoinReviewFact(label: label, bytes: bytes)
}
private func reviewPublicSnapshot(_ facts: [NamecoinReviewFact], frame: Data = reviewPublicFrame,
                                  account: String = "wallet/namecoin@1", fee: UInt64 = 42,
                                  operation: NamecoinReviewOperation = .nameFirstupdate) throws -> NamecoinReviewSnapshot {
    try NamecoinReviewSnapshot(operation: operation, account: account, feeAtoms: fee,
                               frozenReviewFrame: frame, facts: facts)
}
private func reviewHex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

// Serialize these potentially large public-buffer constructor checks. This is
// resource discipline, not a native lane lease or proof of display performance.
@Suite(.serialized)
struct NamecoinReviewSnapshotTests {
    // Regression: >1MiB and exactly5MiB hash frames must reach construction with
    // small complete facts; empty/max+1 frames must refuse with the fixed code.
    // Arbitrary buffers are NOT valid PSBTs and no actual display is exercised.
    @Test func reviewHashFrameSizeIsIndependentOfRenderedFacts() throws {
        let fact = try reviewBinaryFact()
        for count in [1048577, 4 * 1024 * 1024, 5 * 1024 * 1024] {
            let frame = Data(repeating: 0x61, count: count)
            let snapshot = try reviewPublicSnapshot([fact], frame: frame)
            #expect(snapshot.digest.count == 32)
            #expect(snapshot.digest == Data(SHA256.hash(data: frame)))
            #expect(snapshot.text.hasSuffix(reviewEndMarker))
            #expect(snapshot.text.contains("Public script [1 bytes]"))
        }
        for frame in [Data(), Data(repeating: 0x61, count: 5 * 1024 * 1024 + 1)] {
            expectReviewDisplayRefusal("invalid internal review snapshot") {
                _ = try reviewPublicSnapshot([fact], frame: frame)
            }
        }
    }

    // Positive exact qualified byte set and empty VALUE; no Unicode repair or
    // normalization. This tests renderability only, not valid Namecoin semantics,
    // complete transaction intent or actual native text/font/layout qualification.
    @Test func semanticPrintableASCIIAndExplicitEmptyValue() throws {
        let printable = Data((32...126).map { UInt8($0) })
        for kind in [NamecoinReviewFactKind.semanticName, .semanticValue] {
            let fact = try NamecoinReviewFact(label: "Printable text", bytes: printable, kind: kind)
            #expect(fact.bytes == printable)
            #expect(fact.kind == kind)
            let snapshot = try reviewPublicSnapshot([fact])
            #expect(snapshot.text.contains("  Kind: " + kind.rawValue))
            #expect(snapshot.text.contains("  Text: " + String(decoding: printable, as: UTF8.self)))
        }
        let value = try NamecoinReviewFact(label: "VALUE", bytes: Data(), kind: .semanticValue)
        let empty = try reviewPublicSnapshot([value])
        #expect(empty.text.contains("VALUE [0 bytes]\n  Kind: Semantic VALUE (printable ASCII)\n(empty)\n  Text: (empty)\n  Escaped ASCII: \n  Hexadecimal:\n"))
        #expect(empty.text.hasSuffix(reviewEndMarker))
    }

    // Pair every semantic refusal with the SAME bytes admitted as binary. Binary
    // retains escaped/full hex but explicitly grants no semantic NAME/VALUE claim.
    // No test asks the OS or a human to accept opaque bytes as meaningful consent.
    @Test func unrenderableSemanticTextAndBinaryCompatibility() throws {
        let refused = [Data([0]), Data([9]), Data([10]), Data([13]), Data([31]), Data([127]),
                       Data([128]), Data([255]), Data("a\nb".utf8), Data("a\r\nb".utf8),
                       Data("a\u{202e}b".utf8), Data("\u{00e9}".utf8), Data("e\u{0301}".utf8),
                       Data("a\u{200d}b".utf8)]
        for bytes in refused {
            for kind in [NamecoinReviewFactKind.semanticName, .semanticValue] {
                expectReviewDisplayRefusal("unrenderable semantic review text") {
                    _ = try NamecoinReviewFact(label: "Semantic text", bytes: bytes, kind: kind)
                }
            }
            let binary = try NamecoinReviewFact(label: "Opaque script", bytes: bytes)
            #expect(binary.kind == .binary)
            #expect(binary.bytes == bytes)
            let snapshot = try reviewPublicSnapshot([binary])
            #expect(snapshot.text.contains("  Kind: Binary bytes (not semantic NAME/VALUE consent)"))
            #expect(snapshot.text.contains("  Hexadecimal:\n" + reviewHex(bytes)))
            #expect(!snapshot.text.contains("\n  Text: "))
            #expect(snapshot.text.utf8.allSatisfy { $0 == 10 || (32...126).contains($0) })
        }
    }

    // Foreign mutable backing and ordinary Data copies cannot change already
    // admitted semantic bytes. No concurrent mutation/data race or private-memory
    // erasure/UI guarantee is claimed. The allocated bytes are public ASCII only.
    @Test func semanticFactOwnsForeignMutableBacking() throws {
        let memory = UnsafeMutableRawPointer.allocate(byteCount: 64, alignment: 1)
        defer { memory.deallocate() }
        memory.initializeMemory(as: UInt8.self, repeating: 65, count: 64)
        let foreign = Data(bytesNoCopy: memory, count: 64, deallocator: .none)
        let fact = try NamecoinReviewFact(label: "NAME", bytes: foreign, kind: .semanticName)
        memory.storeBytes(of: UInt8(27), as: UInt8.self)
        #expect(fact.bytes == Data(repeating: 65, count: 64))
        var callerCopy = fact.bytes
        callerCopy[0] = 0
        #expect(fact.bytes.first == 65)
        let snapshot = try reviewPublicSnapshot([fact])
        #expect(snapshot.text.contains("  Text: " + String(repeating: "A", count: 64)))
        #expect(!snapshot.text.contains("\\x1b"))
    }

    // Snapshot strings/digest are immutable after input mutation; the changed
    // public frame changes its commitment. This does NOT bind arbitrary supplied
    // facts to PSBT intent; that exact archive/parser docking is still required.
    @Test func snapshotCopiesFactsAndBindsChangedFrameDigest() throws {
        var bytes = Data("d/example".utf8)
        let fact = try NamecoinReviewFact(label: "NAME", bytes: bytes, kind: .semanticName)
        var facts = [fact]
        var frame = reviewPublicFrame
        var account = "wallet/namecoin@1"
        let snapshot = try reviewPublicSnapshot(facts, frame: frame, account: account)
        let text = snapshot.text
        let reason = snapshot.reason
        bytes[0] = 0
        facts.removeAll()
        frame[0] = 3
        account = "other/namecoin@2"
        #expect(snapshot.text == text)
        #expect(snapshot.reason == reason)
        #expect(snapshot.account == "wallet/namecoin@1")
        #expect(reviewHex(snapshot.digest) == reviewPublicDigest)
        #expect(snapshot.text.contains("  Text: d/example"))
        let changed = try reviewPublicSnapshot([fact], frame: frame, account: account)
        #expect(changed.digest != snapshot.digest)
        #expect(changed.reason != snapshot.reason)
        var callerDigest = snapshot.digest
        callerDigest[0] ^= 1
        #expect(reviewHex(snapshot.digest) == reviewPublicDigest)
    }

    // Independent literal public SHA256 plus the ENTIRE small expected render:
    // all fields, raw semantic text, empty marker, escaped/hex bytes and final
    // marker. This proves prepared string expectations, not an on-screen view.
    @Test func completeLiteralRenderAndReason() throws {
        let facts = [try NamecoinReviewFact(label: "NAME", bytes: Data("d/example".utf8), kind: .semanticName),
                     try NamecoinReviewFact(label: "VALUE", bytes: Data(), kind: .semanticValue),
                     try reviewBinaryFact("Script", Data([0, 10, 27, 92, 255, 32, 126]))]
        let snapshot = try reviewPublicSnapshot(facts)
        let escaped = "\\x00" + "\\x0a" + "\\x1b" + "\\\\" + "\\xff" + " ~"
        let expected = [
            "NAMECOIN NATIVE REVIEW", "Operation: name_firstupdate", "Account: wallet/namecoin@1",
            "Fee atoms: 42", "Review SHA256: " + reviewPublicDigest,
            "I authorize this transaction. Exported signatures can be submitted by their holder.",
            "Semantic NAME/VALUE text is printable ASCII only; binary bytes are not semantic consent.",
            "Fact values show escaped ASCII and all hexadecimal bytes; empty values are explicit.",
            "NAME [9 bytes]", "  Kind: Semantic NAME (printable ASCII)", "  Text: d/example",
            "  Escaped ASCII: d/example", "  Hexadecimal:", "642f6578616d706c65",
            "VALUE [0 bytes]", "  Kind: Semantic VALUE (printable ASCII)", "(empty)", "  Text: (empty)",
            "  Escaped ASCII: ", "  Hexadecimal:", "Script [7 bytes]",
            "  Kind: Binary bytes (not semantic NAME/VALUE consent)", "  Escaped ASCII: " + escaped,
            "  Hexadecimal:", "000a1b5cff207e", reviewEndMarker
        ].joined(separator: "\n")
        #expect(snapshot.text == expected)
        #expect(snapshot.reason == "Namecoin name_firstupdate; account wallet/namecoin@1; fee 42 atoms; review SHA256 " + reviewPublicDigest)
        #expect(reviewHex(snapshot.digest) == reviewPublicDigest)
        #expect(snapshot.text.components(separatedBy: reviewEndMarker).count == 2)
    }

    // Exact32-byte wrapping retains every byte, including the final partial row;
    // escaped data is inert text. This is not CoreText/AppKit glyph/layout proof.
    @Test func binaryHexRowsRetainEveryByte() throws {
        let bytes = Data((0...64).map { UInt8($0) })
        let snapshot = try reviewPublicSnapshot([try reviewBinaryFact("Script", bytes)])
        let rows = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n" +
                   "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\n40"
        #expect(snapshot.text.contains("Script [65 bytes]"))
        #expect(snapshot.text.hasSuffix("  Hexadecimal:\n" + rows + "\n" + reviewEndMarker))
    }

    // Exhaust the finite binary-byte alphabet and compare all literal hex rows.
    // This establishes prepared byte/render compatibility, not script validity,
    // semantic NAME/VALUE readability or real native glyph/layout success.
    @Test func binaryAlphabetRetainsFullHex() throws {
        let fact = try reviewBinaryFact("All byte values", Data((0...255).map { UInt8($0) }))
        let snapshot = try reviewPublicSnapshot([fact])
        let rows = [
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
            "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
            "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ].joined(separator: "\n")
        #expect(snapshot.text.hasSuffix("  Hexadecimal:\n" + rows + "\n" + reviewEndMarker))
        #expect(fact.kind == .binary)
        #expect(snapshot.text.utf8.allSatisfy { $0 == 10 || (32...126).contains($0) })
    }

    // Label shape/size and unique labels are independent from byte renderability.
    // Source constructor controls only; no test of real UI visibility or consent.
    @Test func labelsMustBeBoundedPrintableAndUnique() throws {
        let boundary = String(repeating: "a", count: 72)
        let fact = try reviewBinaryFact(boundary)
        #expect(fact.label == boundary)
        for label in ["", " leading", "trailing ", String(repeating: "a", count: 73),
                      "a\nb", "a\tb", "a\u{007f}", "a\u{202e}b", "\u{00e9}"] {
            expectReviewDisplayRefusal("invalid internal review fact") {
                _ = try reviewBinaryFact(label)
            }
        }
        let a = try reviewBinaryFact("Same label", Data([1]))
        let b = try NamecoinReviewFact(label: "Same label", bytes: Data("a".utf8), kind: .semanticValue)
        expectReviewDisplayRefusal("invalid internal review snapshot") {
            _ = try reviewPublicSnapshot([a, b])
        }
        let unique = try reviewPublicSnapshot([a, reviewBinaryFact("Different label", Data([1]))])
        #expect(unique.text.contains("Different label [1 bytes]"))
    }

    // Exactly2048 facts versus2049 and empty; byte totals remain independent.
    // No actual native layout/performance claim accompanies these large strings.
    @Test func factCountLimitRetainsAllAdmittedFields() throws {
        var facts = try (0..<2048).map { try reviewBinaryFact("Field \($0)", Data()) }
        let snapshot = try reviewPublicSnapshot(facts)
        let renderedHeaders = snapshot.text.components(separatedBy: "\n").filter { $0.hasPrefix("Field ") }
        #expect(renderedHeaders == (0..<2048).map { "Field \($0) [0 bytes]" })
        #expect(snapshot.text.hasSuffix(reviewEndMarker))
        #expect(snapshot.text.components(separatedBy: "  Kind: Binary bytes (not semantic NAME/VALUE consent)").count == 2049)
        facts.append(try reviewBinaryFact("Field 2048", Data()))
        expectReviewDisplayRefusal("invalid internal review snapshot") {
            _ = try reviewPublicSnapshot(facts)
        }
        expectReviewDisplayRefusal("invalid internal review snapshot") {
            _ = try reviewPublicSnapshot([])
        }
    }

    // Exactly262144 fact bytes render every hex row; max+1 refuses. Hash-frame
    // size does not raise this limit. No native view is allocated or qualified.
    @Test func perFactByteBoundIsIndependent() throws {
        let fact = try reviewBinaryFact("Boundary script", Data(repeating: 0, count: 262144))
        let snapshot = try reviewPublicSnapshot([fact])
        #expect(snapshot.text.contains("Boundary script [262144 bytes]"))
        #expect(snapshot.text.components(separatedBy: "\n").filter { $0 == String(repeating: "00", count: 32) }.count == 8192)
        #expect(snapshot.text.hasSuffix(reviewEndMarker))
        expectReviewDisplayRefusal("invalid internal review fact") {
            _ = try reviewBinaryFact("Too large", Data(repeating: 0, count: 262145))
        }
    }

    // Exactly1MiB fact bytes versus1MiB+1, independently of the5MiB frame cap.
    // Complete string/source boundary only; actual finite native layout may refuse.
    @Test func aggregateFactBytesRemainBounded() throws {
        var facts = try (0..<4).map { try reviewBinaryFact("Part \($0)", Data(repeating: 65, count: 262144)) }
        let snapshot = try reviewPublicSnapshot(facts)
        #expect(snapshot.text.contains("Part 3 [262144 bytes]"))
        #expect(snapshot.text.hasSuffix(reviewEndMarker))
        facts.append(try reviewBinaryFact("One extra byte", Data([65])))
        expectReviewDisplayRefusal("review exceeds display bound") {
            _ = try reviewPublicSnapshot(facts)
        }
    }

    // No narrowing/sign conversion in fee text: test the full UInt64 maximum
    // literal. Journal operations retain fee0 only. This is neither fee-policy
    // admission nor a real biometric-reason/on-screen native witness.
    @Test func fullDecimalUInt64FeeAndOperationRules() throws {
        let fact = try reviewBinaryFact()
        for operation in [NamecoinReviewOperation.nameNew, .nameFirstupdate] {
            let snapshot = try reviewPublicSnapshot([fact], fee: UInt64.max, operation: operation)
            #expect(snapshot.feeAtoms == UInt64.max)
            #expect(snapshot.text.contains("Fee atoms: 18446744073709551615\n"))
            #expect(snapshot.reason.contains("; fee 18446744073709551615 atoms; review SHA256 " + reviewPublicDigest))
        }
        for operation in [NamecoinReviewOperation.journalInitialize, .reconcile] {
            let snapshot = try reviewPublicSnapshot([fact], fee: 0, operation: operation)
            #expect(snapshot.text.contains(operation.consent))
            #expect(snapshot.reason.contains("; fee 0 atoms; review SHA256 " + reviewPublicDigest))
            expectReviewDisplayRefusal("invalid internal review snapshot") {
                _ = try reviewPublicSnapshot([fact], fee: 1, operation: operation)
            }
        }
    }

    // Account display shape is unchanged; canonical identity/generation admission
    // remains the engine/storage contract, NOT a predicate added by this unit.
    // The canonical31-bit maximum is a display positive, not an identity witness.
    @Test func accountDisplayBoundsAndCanonicalPositive() throws {
        let fact = try reviewBinaryFact()
        let canonical = try reviewPublicSnapshot([fact], account: "wallet/namecoin@2147483647")
        #expect(canonical.account == "wallet/namecoin@2147483647")
        let boundary = try reviewPublicSnapshot([fact], account: String(repeating: "a", count: 96))
        #expect(boundary.account.utf8.count == 96)
        for account in ["", String(repeating: "a", count: 97), "wallet/namecoin@1\n", "a b", "a\u{007f}", "a\u{202e}b", "\u{00e9}"] {
            expectReviewDisplayRefusal("invalid internal review snapshot") {
                _ = try reviewPublicSnapshot([fact], account: account)
            }
        }
    }
}
