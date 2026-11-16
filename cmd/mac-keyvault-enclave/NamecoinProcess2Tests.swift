import CryptoKit
import Darwin
import Foundation
import Testing
@testable import KeyvaultNativeCore

// Frozen repository software fixtures only. No key creation, native store,
// presence, account unseal or cryptographic signing runs in these tests.
private func p2Replace(_ object: NativeArchiveJSON, _ name: String, _ value: NativeArchiveJSON) throws -> NativeArchiveJSON {
    guard case .object(let pairs) = object else { throw NativeNamecoinProcessFailure("invalid_request") }
    return .object(pairs.map { $0.0 == name ? (name, value) : $0 })
}
private func p2Octets(_ value: Data) -> NativeArchiveJSON { .array(value.map { .number(UInt64($0)) }) }
private func p2Length(_ value: Int, width: Int = 4) -> Data {
    Data((0..<width).reversed().map { UInt8((UInt64(value) >> ($0 * 8)) & 255) })
}
private func p2Field(_ value: Data, width: Int = 4) -> Data { p2Length(value.count, width: width) + value }
private func p2File(_ name: String) throws -> Data {
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    return try Data(contentsOf: root.appendingPathComponent("internal/keyvault/testdata/recovery/" + name))
}

private struct P2Fixture {
    let inputs: NativeNamecoinProcessInputs
    let frame: Data

    init(_ name: String) throws {
        let v1 = name == "v1"
        let record = try p2File(v1 ? "v1-public-record.json" : "process2/" + name + "-record.json")
        let pair = try p2File(v1 ? "v1-public-ciphertext.json" : "process2/" + name + "-pair.json")
        let r = try NativeArchiveJSON.decode(record, maximum: 32768, canonical: true)
        let n = try r.field("namecoin"), nostr = try r.field("nostr")
        let service = try r.field("service").text()
        let group = try service + "/recovery@" + String(r.field("version").uint())
        let namecoinService = v1 ? service : try n.field("service").text()
        let account = try namecoinService + "/namecoin@" + String(n.field("version").uint())
        let nostrAccount = try service + "/nostr@" + String(nostr.field("version").uint())
        let origin = try n.field("origin").text()
        let pin = try NativeArchiveJSON.object([
            ("schema", .string("keyvault-namecoin-account-pin/1")), ("group", .string(group)),
            ("account", .string(account)), ("account_xpub", n.field("xpub")),
            ("master_fingerprint", .string(String(origin.dropFirst().prefix(8)))),
            ("account_path", .string("m/84h/7h/0h")),
        ]).canonical()
        let pinHash = Data(SHA256.hash(data: pin))
        let revision = "process2-public-fixture-policy/1"
        let groupID = try nativeArchiveUnhex(r.field("group_id").text(), count: 16)
        let nostrPin = try nativeArchiveUnhex(nostr.field("public_key").text(), count: 32)
        let metadataHash = Data(SHA256.hash(data: record)), pairHash = Data(SHA256.hash(data: pair))
        var sidecar = Data("KVNS1\0".utf8)
        sidecar.append(p2Field(Data(group.utf8))); sidecar.append(p2Field(Data(account.utf8)))
        sidecar.append(pinHash); sidecar.append(p2Field(Data(revision.utf8)))
        sidecar.append(p2Field(Data(nostrAccount.utf8))); sidecar.append(groupID)
        sidecar.append(nostrPin); sidecar.append(metadataHash); sidecar.append(pairHash)
        let base = try NativeArchiveJSON.decode(p2File("process2/v2-distinct-service-selection.json"), maximum: 4 << 20, canonical: true)
        var selected = try base.field("selection")
        for (key, value) in [("Group", group), ("Account", account), ("AccountPinSHA256", nativeArchiveHex(pinHash))] {
            selected = try p2Replace(selected, key, .string(value))
        }
        let linked: NativeArchiveJSON = .object([
            ("Binding", .object([("Group", .string(group)), ("Account", .string(account)),
                                  ("PublicPin", p2Octets(pinHash)), ("Policy", .string(revision))])),
            ("NostrAccount", .string(nostrAccount)), ("GroupID", p2Octets(groupID)),
            ("NostrPublicPin", p2Octets(nostrPin)), ("MetadataHash", p2Octets(metadataHash)), ("PairedValueHash", p2Octets(pairHash)),
        ])
        let profile = try NativeArchiveJSON.object([("schema", .string("keyvault-namecoin-native-selection/1")),
                                                    ("selection", selected), ("sidecar", linked)]).canonical()
        let journal = try NativeJournalSelection(group: group, account: account, publicPin: pinHash, policy: revision,
                                                 helperCDHash: Data(repeating: 0xab, count: 20), sidecar: sidecar)
        let argv = ["namecoin", "sign-psbt", "--process-contract", "2", "--group", group, "--account", account,
                    "--profile", "/public/profile.json", "--profile-sha256", nativeArchiveHex(Data(SHA256.hash(data: profile))),
                    "--account-pin", "/public/pin.json", "--request", "/public/request.json", "--request-sha256", String(repeating: "b", count: 64),
                    "--output", "/public/result.json", "--timeout-seconds", "30"]
        inputs = try NativeNamecoinProcessInputs(arguments: .parse2(argv), canonicalSelection: profile, accountPin: pin,
            operationInput: Data(), selection: NativeArchiveSelection(canonicalJSON: profile, journal: journal), journal: journal)
        let envelope = try NativeArchiveJSON.decode(pair, maximum: 65536, canonical: true).field("namecoin")
        let point = try envelope.field("point").base64(maximum: 65)
        var bindingMaterial = Data()
        let domain = v1 ? "works.relux.mac-keyvault.recovery-envelope.v1" : "works.relux.mac-keyvault.recovery-envelope.v2"
        for part in [domain, "works.relux.mac-keyvault.namecoin-wrap.v1", group, "namecoin", account] {
            bindingMaterial.append(Data(part.utf8)); bindingMaterial.append(0)
        }
        bindingMaterial.append(record); bindingMaterial.append(0); bindingMaterial.append(point)
        let opaque = try Data("KVNE1\0".utf8) + p2Field(envelope.field("enclave_blob").base64(maximum: 16384)) + point
            + envelope.field("ciphertext").base64(maximum: 181) + Data(SHA256.hash(data: bindingMaterial))
        let metadata = Data("KVMD1\0".utf8) + p2Field(Data("works.relux.mac-keyvault.nostr.v1".utf8), width: 2)
            + p2Field(Data(group.utf8), width: 2) + pinHash + p2Field(sidecar) + p2Field(record)
        frame = Data("KVCY1\0".utf8) + p2Length(metadata.count) + p2Length(opaque.count) + metadata + opaque
    }
}

@Test func process2FrozenV1AndV2ProjectionCompatibility() throws {
    for name in ["v1", "v2-equal-service", "v2-distinct-service"] {
        let fixture = try P2Fixture(name)
        let parsed = try NativeNamecoinProcess2Frame(fixture.frame)
        _ = try parsed.selectedAccount(fixture.inputs)
        #expect(parsed.physicalAccount == Data(fixture.inputs.journal.group.utf8))
    }
}

@Test func process2CustodyBoundsAndExactLengths() throws {
    let fixture = try P2Fixture("v2-distinct-service")
    var variants = [Data(), Data(fixture.frame.dropLast()), fixture.frame + Data([0]), Data(repeating: 0, count: NativeNamecoinProcess2Frame.maximum + 1)]
    for range in [0..<6, 6..<10, 10..<14] {
        var changed = fixture.frame; changed.replaceSubrange(range, with: Data(repeating: 0xff, count: range.count)); variants.append(changed)
    }
    for raw in variants {
        #expect(throws: NativeNamecoinProcessFailure("invalid_request")) { _ = try NativeNamecoinProcess2Frame(raw) }
    }
}

@Test func process2MetadataAndEnvelopeMismatchesRefuse() throws {
    let fixture = try P2Fixture("v2-distinct-service")
    // Metadata/service, selected physical identity, public pin, sidecar, record,
    // point and binding mutations must refuse before a protected-run boundary.
    let parsed = try NativeNamecoinProcess2Frame(fixture.frame)
    let serviceOffset = 14 + 6 + 2
    let groupOffset = serviceOffset + parsed.service.count + 2
    let pinOffset = groupOffset + parsed.physicalAccount.count
    let sidecarOffset = pinOffset + 32 + 4
    let recordOffset = sidecarOffset + parsed.sidecar.count + 4
    for index in [serviceOffset, groupOffset, pinOffset, sidecarOffset, recordOffset, fixture.frame.count - 33, fixture.frame.count - 1] {
        var changed = fixture.frame; changed[index] ^= 1
        #expect(throws: NativeNamecoinProcessFailure("account_mismatch")) {
            _ = try NativeNamecoinProcess2Frame(changed).selectedAccount(fixture.inputs)
        }
    }
}

@Test func process2ParserHasNoFallback() throws {
    let fixture = try P2Fixture("v2-equal-service")
    let a = fixture.inputs.arguments
    let argv = ["namecoin", "sign-psbt", "--process-contract", "2", "--group", a.group, "--account", a.account,
                "--profile", a.profilePath, "--profile-sha256", a.profileSHA256, "--account-pin", a.accountPinPath,
                "--request", a.requestPath, "--request-sha256", a.requestSHA256, "--output", a.outputPath, "--timeout-seconds", "30"]
    _ = try NativeNamecoinProcessArguments.parse2(argv)
    for tail in [["--process-contract", "2"], ["--unknown", "x"], ["--timeout-seconds", "30"]] {
        #expect(throws: NativeNamecoinProcessFailure("invalid_request")) { _ = try NativeNamecoinProcessArguments.parse2(argv + tail) }
    }
    var wrong = argv; wrong[3] = "02"
    #expect(throws: NativeNamecoinProcessFailure("invalid_request")) { _ = try NativeNamecoinProcessArguments.parse2(wrong) }
    #expect(throws: NativeNamecoinProcessFailure("invalid_request")) { _ = try NativeNamecoinProcessArguments.parse(argv) }
}

@Test func process2CustodyRequiresEOFAndDeadline() throws {
    var descriptors = [Int32](repeating: -1, count: 2)
    #expect(pipe(&descriptors) == 0)
    defer { _ = Darwin.close(descriptors[0]); _ = Darwin.close(descriptors[1]) }
    let bytes = Data([1, 2, 3])
    #expect(bytes.withUnsafeBytes { Darwin.write(descriptors[1], $0.baseAddress!, $0.count) } == bytes.count)
    let deadline = DispatchTime.now().uptimeNanoseconds + 10_000_000
    #expect(throws: (any Error).self) { _ = try nativeNamecoinReadCustody(descriptors[0], deadline: deadline) }
    _ = Darwin.close(descriptors[1]); descriptors[1] = -1
    #expect(try nativeNamecoinReadCustody(descriptors[0], deadline: DispatchTime.now().uptimeNanoseconds + 1_000_000_000).isEmpty)
}
