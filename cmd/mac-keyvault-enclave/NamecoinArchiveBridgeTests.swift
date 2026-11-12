import Foundation
import Darwin
import CryptoKit
import NamecoinArchiveABI
import Testing
@testable import KeyvaultNativeCore

// SOURCE ONLY / NOT_RUN. Public format, correlation, closed-error and software
// lifetime controls only. No test calls C-open/run/close, actual native storage,
// Keychain, account unseal, owner UI, signatures, or an actual acknowledgement
// release. Minimal PSBT/frame fixtures are NOT valid engine signing candidates.
private func expectBridgeRefusal(_ code: String, _ operation: () throws -> Void) {
    do { try operation(); Issue.record("Expected fixed bridge refusal") }
    catch let failure as NativeNamecoinArchiveFailure { #expect(failure.code == code) }
    catch { Issue.record("Unexpected error type; raw diagnostics omitted") }
}
private func bridgeString(_ value: String) -> NativeArchiveJSON { .string(value) }
private func bridgeBytes(_ value: Data) -> NativeArchiveJSON { .array(value.map { .number(UInt64($0)) }) }
private func bridgeFieldReplacing(_ object: NativeArchiveJSON, _ key: String, _ value: NativeArchiveJSON?) throws -> NativeArchiveJSON {
    guard case .object(let pairs) = object else { throw NativeNamecoinArchiveFailure("invalid_request") }
    var replaced = pairs.compactMap { pair -> (String, NativeArchiveJSON)? in
        pair.0 == key ? value.map { (key, $0) } : pair
    }
    if !pairs.contains(where: { $0.0 == key }), let value { replaced.append((key, value)) }
    return .object(replaced)
}

// Only a UUID-named disposable PUBLIC file. Setup cannot repair closed standard
// handles, manipulate another process, or touch a retained fixture/owner value.
private final class BridgePublicFixture {
    let directory: URL
    let descriptor: Int32
    let output: NativeNamecoinPrivateOutput
    let pin: Data
    let journal: NativeJournalSelection
    let config: NativeArchiveJSON
    let request: NativeArchiveJSON
    let frame: Data
    let facts: [NativeArchiveJSON]

    init(psbtCount: Int = 6) throws {
        guard [Int32(0), 1, 2].allSatisfy({ fcntl($0, F_GETFD) >= 0 }) else { throw NativeNamecoinArchiveFailure("output_unavailable") }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("namecoin-bridge-public-" + UUID().uuidString, isDirectory: true)
        do { try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]) }
        catch { throw NativeNamecoinArchiveFailure("output_unavailable") }
        let descriptor = Darwin.open(directory.appendingPathComponent("result").path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, mode_t(0o600))
        guard descriptor >= 3 else { try? FileManager.default.removeItem(at: directory); throw NativeNamecoinArchiveFailure("output_unavailable") }
        let output: NativeNamecoinPrivateOutput
        do { output = try NativeNamecoinPrivateOutput(selectedDescriptor: descriptor) }
        catch { _ = Darwin.close(descriptor); try? FileManager.default.removeItem(at: directory); throw NativeNamecoinArchiveFailure("output_unavailable") }
        var transferred = false
        defer {
            if !transferred {
                try? output.close(); _ = Darwin.close(descriptor)
                try? FileManager.default.removeItem(at: directory)
            }
        }
        // Public syntax fixture, never an actually admitted extended account.
        let pin = Data("public account pin syntax fixture".utf8)
        let hash = Data(SHA256.hash(data: pin))
        let group = "fixture/recovery@1", account = "fixture/namecoin@1", revision = "fixture-policy"
        let genesis = Data(repeating: 0x11, count: 32)
        let policy: NativeArchiveJSON = .object([
            ("revision", .string(revision)), ("per_tx_fee_cap_atoms", .string("1000")),
            ("total_fee_cap_atoms", .string("4000")), ("min_fee_rate_atoms_per_kvb", .string("1")),
            ("max_fee_rate_atoms_per_kvb", .string("1000")), ("dust_relay_fee_atoms_per_kvb", .string("1")),
            ("created_at", .number(10)), ("release_not_after", .number(100)),
            ("final_confirmations", .number(1)), ("release_mode", .string("two-stage"))])
        let binding: NativeArchiveJSON = .object([("Group", .string(group)), ("Account", .string(account)),
                                                 ("PublicPin", bridgeBytes(hash)), ("Policy", .string(revision))])
        let groupID = Data(repeating: 0x22, count: 16), publicHash = Data(repeating: 0x33, count: 32)
        let sidecarJSON: NativeArchiveJSON = .object([("Binding", binding), ("NostrAccount", .string("fixture/nostr@1")),
                                                     ("GroupID", bridgeBytes(groupID)), ("NostrPublicPin", bridgeBytes(publicHash)),
                                                     ("MetadataHash", bridgeBytes(publicHash)), ("PairedValueHash", bridgeBytes(publicHash))])
        var sidecar = Data("KVNS1\0".utf8)
        for value in [group, account] { sidecar.append(nativeJournalLP(Data(value.utf8))) }
        sidecar.append(hash); sidecar.append(nativeJournalLP(Data(revision.utf8)))
        sidecar.append(nativeJournalLP(Data("fixture/nostr@1".utf8))); sidecar.append(groupID)
        for _ in 0..<3 { sidecar.append(publicHash) }
        let journal = try NativeJournalSelection(group: group, account: account, publicPin: hash, policy: revision,
                                             helperCDHash: Data(repeating: 0x44, count: 20), sidecar: sidecar)
        let selection: NativeArchiveJSON = .object([("Network", .string("namecoin-regtest")), ("Genesis", .string(nativeArchiveHex(genesis))),
                                                    ("Group", .string(group)), ("Account", .string(account)),
                                                    ("AccountPinSHA256", .string(nativeArchiveHex(hash))), ("Policy", policy), ("RevealValuesPin", .null)])
        let config: NativeArchiveJSON = .object([("schema", .string("keyvault-namecoin-native-selection/1")), ("selection", selection), ("sidecar", sidecarJSON)])
        let manifest: NativeArchiveJSON = .object([
            ("network", .string("namecoin-regtest")), ("genesis", .string(nativeArchiveHex(genesis))), ("group", .string(group)),
            ("account", .string(account)), ("account_pin_sha256", .string(nativeArchiveHex(hash))), ("policy", policy),
            ("transactions", .array([.object([("slot", .string("A")), ("fee_atoms", .string("900"))])]))])
        let manifestBytes = try manifest.canonical()
        var planFrame = Data("swarma-identity/namecoin-registration-plan/2\0".utf8)
        planFrame.append(nativeJournalLP(manifestBytes))
        let planHash = Data(SHA256.hash(data: planFrame)), requestID = Data(repeating: 0x55, count: 32), sittingID = Data(repeating: 0x66, count: 32)
        var psbt = Data([0x70, 0x73, 0x62, 0x74, 0xff])
        psbt.append(Data(repeating: 0, count: max(1, psbtCount - 5)))
        let name = Data("d/fixture".utf8), randomness = Data(repeating: 0x77, count: 20)
        let intent: NativeArchiveJSON = .object([("operation", .string("name_new")), ("name_hex", .string(nativeArchiveHex(name))), ("rand_hex", .string(nativeArchiveHex(randomness)))])
        let request: NativeArchiveJSON = .object([("schema", .string("keyvault-namecoin-psbt/2")), ("request_id", .string(nativeArchiveHex(requestID))),
                           ("sitting_id", .string(nativeArchiveHex(sittingID))), ("slot", .string("A")), ("network", .string("namecoin-regtest")),
                           ("expires_at", .number(80)), ("psbt", .string(psbt.base64EncodedString())),
                           ("plan_manifest_utf8", .string(String(decoding: manifestBytes, as: UTF8.self))),
                           ("plan_sha256", .string(nativeArchiveHex(planHash))), ("reservation_plan_sha256", .string(nativeArchiveHex(planHash))), ("intent", intent)])
        var frame = Data("keyvault/namecoin-psbt-review/2\0".utf8)
        for data in [psbt, Data("name_new".utf8), name, Data(), randomness] { frame.append(nativeJournalLP(data)) }
        frame.append(contentsOf: [0, 0]); frame.append(planHash); frame.append(planHash); frame.append(sittingID); frame.append(0x41)
        frame.append(nativeJournalLP(Data(group.utf8))); frame.append(nativeJournalLP(Data(account.utf8))); frame.append(hash)
        frame.append(nativeJournalLP(Data("namecoin-regtest".utf8))); frame.append(Data(genesis.reversed()))
        frame.append(nativeJournalLP(Data(revision.utf8)))
        var cap = UInt64(1000).bigEndian; withUnsafeBytes(of: &cap) { frame.append(contentsOf: $0) }
        frame.append(requestID)
        var expires = UInt64(80).bigEndian; withUnsafeBytes(of: &expires) { frame.append(contentsOf: $0) }
        func fact(_ label: String, _ value: Data, _ kind: String = "binary") -> NativeArchiveJSON {
            .object([("label", .string(label)), ("kind", .string(kind)), ("bytes", .string(value.base64EncodedString()))])
        }
        var facts: [NativeArchiveJSON] = []
        for (label, text) in [
            ("Network / genesis", "namecoin-regtest / " + nativeArchiveHex(genesis)), ("Existing recovery group", group),
            ("Account public pin SHA256", nativeArchiveHex(hash)), ("Policy revision", revision), ("Release mode", "two-stage"),
            ("Release deadline UTC seconds", "100"), ("Final confirmations required", "1"),
            ("Request / sitting", nativeArchiveHex(requestID) + " / " + nativeArchiveHex(sittingID)),
            ("Plan SHA256", nativeArchiveHex(planHash)), ("Reservation plan SHA256", nativeArchiveHex(planHash)),
            ("Request expires UTC seconds", "80"), ("Fee caps per transaction / total atoms", "1000 / 4000"),
            ("Fee rates min / max atoms per kvB", "1 / 1000"), ("Dust relay atoms per kvB", "1"),
            ("Transaction A input / output / fee atoms", "1000 / 100 / 900")] {
            facts.append(fact(label, Data(text.utf8)))
        }
        facts.append(fact("A/C NAME", name, "semanticName"))
        facts.append(fact("A/C commitment randomness", randomness))
        facts.append(fact("A/C VALUE", Data(), "semanticValue"))
        facts.append(fact("Opaque fixture script", Data([0, 10, 0xff])))
        self.directory = directory; self.descriptor = descriptor; self.output = output
        self.pin = pin; self.journal = journal; self.config = config; self.request = request
        self.frame = frame; self.facts = facts
        transferred = true
    }
    deinit { try? output.close(); _ = Darwin.close(descriptor); try? FileManager.default.removeItem(at: directory) }
    func operation(mode: NativeNamecoinArchiveMode = .sign, config: NativeArchiveJSON? = nil,
                   input: Data? = nil) throws -> NativeNamecoinArchiveOperation {
        let config = config ?? self.config
        let raw: Data
        if let input { raw = input }
        else if mode == .reconcile {
            var descriptor = Data("KVND1\0".utf8)
            for data in [try request.canonical(), pin, try config.field("selection").canonical()] { descriptor.append(nativeJournalLP(data)) }
            raw = descriptor
        } else { raw = try request.canonical() }
        return try NativeNamecoinArchiveOperation(mode: mode, requestOrDescriptor: raw, selectedAccountPin: pin,
                                                  trustedCanonicalSelection: config.canonical(), journal: journal, output: output)
    }
    func document(mode: NativeNamecoinArchiveMode = .sign, frame: Data? = nil,
                  facts: [NativeArchiveJSON]? = nil) -> NativeArchiveJSON {
        .object([("operation", .string(mode == .reconcile ? "reconcile journal" : "name_new")),
                 ("account", .string(journal.account)), ("fee_atoms", .number(mode == .reconcile ? 0 : 900)),
                 ("review_frame", .string((frame ?? self.frame).base64EncodedString())), ("facts", .array(facts ?? self.facts))])
    }
    func requireEmptyOutput() throws {
        var status = stat()
        guard fstat(descriptor, &status) == 0 else { throw NativeNamecoinArchiveFailure("output_unavailable") }
        #expect(status.st_size == 0)
    }
}

@Suite(.serialized)
struct NamecoinArchiveBridgeTests {
    // Claim: hand-written canonical literal preserves full UInt64 and escaped
    // bytes; rejects duplicate/extra/missing/type/trailing forms. NOT_RUN; this
    // software decoder is not Go PSBT verification or native authority.
    @Test func closedPublicJSONAndUInt64() throws {
        let literal = Data("{\"fee\":18446744073709551615,\"value\":\"\\u003c\\u0026\\u003e\"}".utf8)
        let values = try NativeArchiveJSON.decode(literal, maximum: 256, canonical: true).fields(["fee", "value"])
        #expect(try values[0].uint() == UInt64.max)
        #expect(try values[1].text() == "<&>")
        for bad in ["{\"fee\":1,\"fee\":2}", "{\"fee\":01}", "{\"fee\":1.0}", "{\"fee\":-1}", "{\"fee\":18446744073709551616}", "{\"fee\":1}x"] {
            expectBridgeRefusal("display_refused") { _ = try NativeArchiveJSON.decode(Data(bad.utf8), maximum: 256, canonical: true) }
        }
        for bad in ["{}", "{\"fee\":1,\"extra\":0}"] {
            expectBridgeRefusal("display_refused") {
                _ = try NativeArchiveJSON.decode(Data(bad.utf8), maximum: 256, canonical: true).fields(["fee"])
            }
        }
    }

    // Claim: actual Go config/sidecar representation maps to exact local encoded
    // selection; mutations to sidecar hashes or account refuse. NOT_RUN; supplied
    // fixture pins/code are public syntax only, not qualified identity/admission.
    @Test func exactSelectionAndSidecar() throws {
        let fixture = try BridgePublicFixture()
        let selected = try NativeArchiveSelection(canonicalJSON: fixture.config.canonical(), journal: fixture.journal)
        #expect(selected.account == fixture.journal.account)
        #expect(selected.publicPin == fixture.journal.publicPin)
        let sidecar = try fixture.config.field("sidecar")
        for (field, count) in [("GroupID", 16), ("NostrPublicPin", 32), ("MetadataHash", 32), ("PairedValueHash", 32)] {
            let changedSidecar = try bridgeFieldReplacing(sidecar, field, bridgeBytes(Data(repeating: 0x99, count: count)))
            let changed = try bridgeFieldReplacing(fixture.config, "sidecar", changedSidecar)
            expectBridgeRefusal("account_mismatch") { _ = try NativeArchiveSelection(canonicalJSON: changed.canonical(), journal: fixture.journal) }
        }
        let selection = try fixture.config.field("selection")
        let changedSelection = try bridgeFieldReplacing(selection, "Account", .string("fixture/namecoin@2"))
        let mismatch = try bridgeFieldReplacing(fixture.config, "selection", changedSelection)
        expectBridgeRefusal("account_mismatch") { _ = try NativeArchiveSelection(canonicalJSON: mismatch.canonical(), journal: fixture.journal) }
        for changed in [try bridgeFieldReplacing(fixture.config, "schema", nil), try bridgeFieldReplacing(fixture.config, "extra", .number(1))] {
            expectBridgeRefusal("display_refused") { _ = try NativeArchiveSelection(canonicalJSON: changed.canonical(), journal: fixture.journal) }
        }
        try fixture.requireEmptyOutput()
    }

    // Claim: both actual Go network names and nil/empty byte-slice canonical
    // representations are admitted for public config decoding. NOT_RUN; this
    // does not admit a network transaction, extended key, or native authority.
    @Test func emittedConfigurationForms() throws {
        let fixture = try BridgePublicFixture()
        let original = try fixture.config.field("selection")
        for network in ["namecoin-mainnet", "namecoin-regtest"] {
            for reveal in [NativeArchiveJSON.null, .string("")] {
                var selection = try bridgeFieldReplacing(original, "Network", .string(network))
                selection = try bridgeFieldReplacing(selection, "RevealValuesPin", reveal)
                let config = try bridgeFieldReplacing(fixture.config, "selection", selection)
                let decoded = try NativeArchiveSelection(canonicalJSON: config.canonical(), journal: fixture.journal)
                #expect(decoded.network == network)
            }
        }
        let policy = try original.field("Policy")
        let changedPolicy = try bridgeFieldReplacing(policy, "per_tx_fee_cap_atoms", .string("500"))
        let selection = try bridgeFieldReplacing(original, "Policy", changedPolicy)
        let changed = try bridgeFieldReplacing(fixture.config, "selection", selection)
        expectBridgeRefusal("policy_refused") { _ = try fixture.operation(config: changed) }
        try fixture.requireEmptyOutput()
    }

    // Claim: every admitted fact is rendered, explicit semantic kinds survive,
    // binary controls remain binary, full digest/end marker are present. NOT_RUN;
    // no UI/layout/biometry, valid PSBT, archive run or private proof.
    @Test func completeReviewCorrelationAndOwnedCopy() throws {
        let fixture = try BridgePublicFixture()
        let operation = try fixture.operation()
        var source = try fixture.document().canonical()
        let document = try NativeArchiveReviewDocument(ownedJSON: source, operation: operation)
        source.resetBytes(in: 0..<source.count)
        #expect(document.facts.count == fixture.facts.count)
        #expect(document.snapshot.operation == .nameNew)
        #expect(document.snapshot.feeAtoms == 900)
        #expect(document.snapshot.digest == Data(SHA256.hash(data: fixture.frame)))
        #expect(document.snapshot.text.hasSuffix("END OF COMPLETE INTERNAL REVIEW"))
        #expect(document.snapshot.text.contains("Semantic NAME (printable ASCII)"))
        #expect(document.snapshot.text.contains("Binary bytes (not semantic NAME/VALUE consent)"))
        #expect(document.snapshot.text.contains("(empty)"))
        for fact in document.facts { #expect(document.snapshot.text.contains(fact.label)) }
        try fixture.requireEmptyOutput()
    }

    // Claim: foreign mutable PUBLIC input backing cannot replace owned request
    // or config bytes after construction. NOT_RUN; no native/private buffers,
    // C-run success, UI, or protected-state lifetime proof is asserted.
    @Test func foreignPublicInputOwnership() throws {
        let fixture = try BridgePublicFixture()
        let requestBytes = try fixture.request.canonical()
        let foreignRequest = NSMutableData(data: requestBytes)
        let operation = try fixture.operation(input: Data(referencing: foreignRequest))
        foreignRequest.mutableBytes.initializeMemory(as: UInt8.self, repeating: 0, count: foreignRequest.length)
        #expect(operation.input == requestBytes)
        let configBytes = try fixture.config.canonical()
        let foreignConfig = NSMutableData(data: configBytes)
        let selected = try NativeArchiveSelection(canonicalJSON: Data(referencing: foreignConfig), journal: fixture.journal)
        foreignConfig.mutableBytes.initializeMemory(as: UInt8.self, repeating: 0, count: foreignConfig.length)
        #expect(selected.raw == configBytes)
        let document = try NativeArchiveReviewDocument(ownedJSON: fixture.document().canonical(), operation: operation)
        #expect(document.snapshot.digest == Data(SHA256.hash(data: fixture.frame)))
        try fixture.requireEmptyOutput()
    }

    // Claim: mode2 uses exact historical descriptor tuple, fee0 review retains
    // original fee facts; changed/trailing selection or descriptor refuses.
    // NOT_RUN; authentic completed history/no-ECDSA proof stays actual Go/native.
    @Test func historicalDescriptorAndReconcileReview() throws {
        let fixture = try BridgePublicFixture()
        let operation = try fixture.operation(mode: .reconcile)
        let document = try NativeArchiveReviewDocument(ownedJSON: fixture.document(mode: .reconcile).canonical(), operation: operation)
        #expect(document.snapshot.operation == .reconcile)
        #expect(document.snapshot.feeAtoms == 0)
        #expect(document.snapshot.text.contains("1000 / 100 / 900"))
        var extra = operation.input; extra.append(0)
        expectBridgeRefusal("display_refused") { _ = try fixture.operation(mode: .reconcile, input: extra) }
        var changed = operation.input; changed[changed.count - 1] ^= 1
        expectBridgeRefusal("policy_refused") { _ = try fixture.operation(mode: .reconcile, input: changed) }
        try fixture.requireEmptyOutput()
    }

    // Claim: no digest-only substitute; every domain2 byte is consumed, frame
    // corruption/trailing bytes/oversize/empty and selected fee mismatch refuse.
    // NOT_RUN; large positive is only frame correlation, not valid PSBT/display.
    @Test func fullFrameBoundsAndChangedDigest() throws {
        let fixture = try BridgePublicFixture(psbtCount: 4 << 20)
        let operation = try fixture.operation()
        let good = try NativeArchiveReviewDocument(ownedJSON: fixture.document().canonical(), operation: operation)
        #expect(good.frame.count > 4 << 20)
        for bad in [Data(), Data(repeating: 0, count: (5 << 20) + 1), fixture.frame + Data([0])] {
            expectBridgeRefusal("display_refused") { _ = try NativeArchiveReviewDocument(ownedJSON: fixture.document(frame: bad).canonical(), operation: operation) }
        }
        var changed = fixture.frame; changed[0] ^= 1
        expectBridgeRefusal("display_refused") { _ = try NativeArchiveReviewDocument(ownedJSON: fixture.document(frame: changed).canonical(), operation: operation) }
        #expect(Data(SHA256.hash(data: changed)) != good.snapshot.digest)
        let fee = try bridgeFieldReplacing(fixture.document(), "fee_atoms", .number(901))
        expectBridgeRefusal("display_refused") { _ = try NativeArchiveReviewDocument(ownedJSON: fee.canonical(), operation: operation) }
        try fixture.requireEmptyOutput()
    }

    // Claim: missing/extra/duplicate fields and unknown semantic kinds refuse;
    // unrenderable semantic bytes cannot be downgraded to consent by opaque hex.
    // NOT_RUN; unchanged fixture output is a software pre-use control only.
    @Test func closedReviewFieldsKindsAndSemantics() throws {
        let fixture = try BridgePublicFixture(), operation = try fixture.operation()
        for changed in [try bridgeFieldReplacing(fixture.document(), "facts", nil), try bridgeFieldReplacing(fixture.document(), "extra", .number(1))] {
            expectBridgeRefusal("display_refused") { _ = try NativeArchiveReviewDocument(ownedJSON: changed.canonical(), operation: operation) }
        }
        for kind in ["unknown", "semanticName", "semanticValue"] {
            let fact: NativeArchiveJSON = .object([("label", .string("Additional semantic control")), ("kind", .string(kind)), ("bytes", .string(Data([10]).base64EncodedString()))])
            expectBridgeRefusal("display_refused") { _ = try NativeArchiveReviewDocument(ownedJSON: fixture.document(facts: fixture.facts + [fact]).canonical(), operation: operation) }
        }
        let duplicate = fixture.facts + [fixture.facts[0]]
        expectBridgeRefusal("display_refused") { _ = try NativeArchiveReviewDocument(ownedJSON: fixture.document(facts: duplicate).canonical(), operation: operation) }
        let missingName = try fixture.facts.filter { try $0.field("label").text() != "A/C NAME" }
        expectBridgeRefusal("display_refused") { _ = try NativeArchiveReviewDocument(ownedJSON: fixture.document(facts: missingName).canonical(), operation: operation) }
        try fixture.requireEmptyOutput()
    }

    // Claim: binary cannot replace the selected semantic NAME, changed semantic
    // bytes cannot match the frame, malformed base64/count/per-fact/aggregate
    // bounds refuse without output. NOT_RUN; no engine/native authority proof.
    @Test func semanticBindingAndFactBounds() throws {
        let fixture = try BridgePublicFixture(), operation = try fixture.operation()
        let selected = try fixture.facts.first { try $0.field("label").text() == "A/C NAME" }
        guard let selected else { throw NativeNamecoinArchiveFailure("invalid_request") }
        for replacement in [try bridgeFieldReplacing(selected, "kind", .string("binary")),
                            try bridgeFieldReplacing(selected, "bytes", .string(Data("d/changed".utf8).base64EncodedString())),
                            try bridgeFieldReplacing(selected, "bytes", .string("not base64"))] {
            let facts = try fixture.facts.map { fact in try fact.field("label").text() == "A/C NAME" ? replacement : fact }
            expectBridgeRefusal("display_refused") { _ = try NativeArchiveReviewDocument(ownedJSON: fixture.document(facts: facts).canonical(), operation: operation) }
        }
        func extra(_ label: String, count: Int) -> NativeArchiveJSON {
            .object([("label", .string(label)), ("kind", .string("binary")),
                     ("bytes", .string(Data(repeating: 0x50, count: count).base64EncodedString()))])
        }
        let tooMany = (0..<2049).map { extra("Fact \($0)", count: 0) }
        let tooLarge = fixture.facts + [extra("Oversize fact", count: 262145)]
        let tooMuch = fixture.facts + (0..<5).map { extra("Aggregate \($0)", count: 262144) }
        for facts in [tooMany, tooLarge, tooMuch] {
            expectBridgeRefusal("display_refused") { _ = try NativeArchiveReviewDocument(ownedJSON: fixture.document(facts: facts).canonical(), operation: operation) }
        }
        try fixture.requireEmptyOutput()
    }

    // Claim: nil process context and invalid callback buffers refuse before any
    // Unmanaged dereference/storage call; no actual native success is mocked.
    // NOT_RUN; forged nonnil pointers are outside trusted in-process provenance.
    @Test func invalidCallbacksNeverTouchStorage() {
        var written: size_t = 123
        #expect(nativeArchiveLoadCallback(nil, nil, 0, &written) == -1)
        #expect(written == 0)
        #expect(nativeArchiveReplaceCallback(nil, nil, 0) == -1)
        #expect(nativeArchiveOutputCallback(nil, nil, 0, nil) == -1)
    }

    // Claim: real public stack-buffer pointer shapes admit only bounded valid
    // forms and reject nil/oversize/reconcile-update before storage. NOT_RUN;
    // this is not a callback effect, protected data, or native success mock.
    @Test func finiteCallbackShapes() throws {
        var bytes = [UInt8](repeating: 0x50, count: 512)
        var hash = [UInt8](repeating: 0x51, count: 32)
        var written: size_t = 0
        try bytes.withUnsafeMutableBufferPointer { buffer in
            try hash.withUnsafeMutableBufferPointer { digest in
                try NativeArchiveCallbackShape.load(buffer.baseAddress, capacity: 512, written: &written)
                try NativeArchiveCallbackShape.replace(buffer.baseAddress, count: 512, mode: .sign)
                try NativeArchiveCallbackShape.output(buffer.baseAddress, count: 512, hash: digest.baseAddress)
                for capacity in [0, 513] {
                    expectBridgeRefusal("journal_unavailable") { try NativeArchiveCallbackShape.load(buffer.baseAddress, capacity: size_t(capacity), written: &written) }
                }
                expectBridgeRefusal("journal_unavailable") { try NativeArchiveCallbackShape.load(nil, capacity: 512, written: &written) }
                expectBridgeRefusal("journal_unavailable") { try NativeArchiveCallbackShape.load(buffer.baseAddress, capacity: 512, written: nil) }
                for count in [0, 513] {
                    expectBridgeRefusal("outcome_unknown") { try NativeArchiveCallbackShape.replace(buffer.baseAddress, count: size_t(count), mode: .sign) }
                }
                expectBridgeRefusal("outcome_unknown") { try NativeArchiveCallbackShape.replace(buffer.baseAddress, count: 512, mode: .reconcile) }
                expectBridgeRefusal("outcome_unknown") { try NativeArchiveCallbackShape.replace(nil, count: 512, mode: .sign) }
                expectBridgeRefusal("output_unavailable") { try NativeArchiveCallbackShape.output(buffer.baseAddress, count: (8 << 20) + 1, hash: digest.baseAddress) }
                expectBridgeRefusal("output_unavailable") { try NativeArchiveCallbackShape.output(buffer.baseAddress, count: 512, hash: nil) }
            }
        }
        #expect(bytes.allSatisfy { $0 == 0x50 })
        #expect(written == 0)
    }

    // Claim: exact21 closed codes and unknown numeric codes map conservatively;
    // no raw OS text leaks through mapping. NOT_RUN; no native verdict asserted.
    @Test func closedABICodes() {
        #expect(NativeNamecoinArchiveFailure.abi(Int32(KV_NMC_OK)) == nil)
        let expected: [(Int32, String)] = [
            (Int32(KV_NMC_INVALID_REQUEST), "invalid_request"),
            (Int32(KV_NMC_UNSUPPORTED_PSBT), "unsupported_psbt"),
            (Int32(KV_NMC_UNSUPPORTED_SCRIPT), "unsupported_script"),
            (Int32(KV_NMC_DISPLAY_REFUSED), "display_refused"),
            (Int32(KV_NMC_ACCOUNT_MISMATCH), "account_mismatch"),
            (Int32(KV_NMC_PATH_REFUSED), "path_refused"),
            (Int32(KV_NMC_PREVOUT_MISMATCH), "prevout_mismatch"),
            (Int32(KV_NMC_INTENT_MISMATCH), "intent_mismatch"),
            (Int32(KV_NMC_SIGHASH_REFUSED), "sighash_refused"),
            (Int32(KV_NMC_FEE_REFUSED), "fee_refused"),
            (Int32(KV_NMC_REQUEST_EXPIRED), "request_expired"),
            (Int32(KV_NMC_REPLAY_REFUSED), "replay_refused"),
            (Int32(KV_NMC_ACCOUNT_BUSY), "account_busy"),
            (Int32(KV_NMC_AUTH_REFUSED), "auth_refused"),
            (Int32(KV_NMC_PRESENCE_UNAVAILABLE), "presence_unavailable"),
            (Int32(KV_NMC_ADOPTION_REQUIRED), "adoption_required"),
            (Int32(KV_NMC_HELPER_NOT_ADMITTED), "helper_not_admitted"),
            (Int32(KV_NMC_POLICY_REFUSED), "policy_refused"),
            (Int32(KV_NMC_OUTCOME_UNKNOWN), "outcome_unknown"),
            (Int32(KV_NMC_JOURNAL_UNAVAILABLE), "journal_unavailable"),
            (Int32(KV_NMC_OUTPUT_UNAVAILABLE), "output_unavailable")]
        for (number, code) in expected { #expect(NativeNamecoinArchiveFailure.abi(number)?.code == code) }
        for code in [Int32(-1), 22, Int32.max] { #expect(NativeNamecoinArchiveFailure.abi(code)?.code == "outcome_unknown") }
        #expect(NativeNamecoinArchiveFailure("arbitrary").code == "outcome_unknown")
        #expect(NativeNamecoinArchiveFailure.map(NativeNamecoinOutputRefusal.unknown).code == "outcome_unknown")
    }

    // Claim: UNKNOWN/unknown native codes and inconsistent OK+callback failure
    // cannot downgrade to REFUSED or release ACK. Synthetic numeric inputs test
    // failure precedence only, NOT_RUN; no native-success/private proof.
    @Test func nativeUnknownCannotBeDowngraded() {
        let auth = NativeNamecoinArchiveFailure("auth_refused")
        for code in [Int32(KV_NMC_OUTCOME_UNKNOWN), Int32(-1)] {
            #expect(nativeArchiveRunFailure(code, callbackFailure: auth)?.code == "outcome_unknown")
        }
        #expect(nativeArchiveRunFailure(Int32(KV_NMC_OK), callbackFailure: auth)?.code == "outcome_unknown")
        #expect(nativeArchiveRunFailure(Int32(KV_NMC_OUTPUT_UNAVAILABLE), callbackFailure: NativeNamecoinArchiveFailure("outcome_unknown"))?.code == "outcome_unknown")
        #expect(nativeArchiveRunFailure(Int32(KV_NMC_JOURNAL_UNAVAILABLE), callbackFailure: auth)?.code == "auth_refused")
        #expect(nativeArchiveRunFailure(Int32(KV_NMC_JOURNAL_UNAVAILABLE), callbackFailure: nil)?.code == "journal_unavailable")
    }

    // Claim: software ordering forbids ACK before successful run return and
    // closes ownership once; no C calls, fake run success or native proof here.
    // NOT_RUN; actual handle close and secret clearing need qualified execution.
    @Test func noAckBeforeRunAndCloseOwnershipOnce() throws {
        var lifecycle = NativeArchiveLifecycle()
        expectBridgeRefusal("outcome_unknown") { try lifecycle.requireAckPhase() }
        try lifecycle.beginRun()
        expectBridgeRefusal("outcome_unknown") { try lifecycle.requireAckPhase() }
        expectBridgeRefusal("replay_refused") { try lifecycle.beginRun() }
        expectBridgeRefusal("outcome_unknown") { try lifecycle.returned(Int32(KV_NMC_OUTCOME_UNKNOWN)) }
        expectBridgeRefusal("outcome_unknown") { try lifecycle.requireAckPhase() }
        lifecycle.close()
        expectBridgeRefusal("outcome_unknown") { try lifecycle.requireAckPhase() }
        var owner = try NativeArchiveHandleOwnership(7)
        #expect(owner.takeForClose() == 7)
        #expect(owner.takeForClose() == nil)
        #expect(owner.takeForClose() == nil)
        expectBridgeRefusal("outcome_unknown") { _ = try NativeArchiveHandleOwnership(0) }
    }

    // Claim: exact frozen public ACK syntax and independent hash correlate; no
    // early ACK/whitespace/extra/mismatched hash passes. NOT_RUN; decoding this
    // literal is NOT an ACK release, actual SIGNED result, or native completion.
    @Test func exactAcknowledgementCorrelation() throws {
        let hash = Data(repeating: 0x12, count: 32)
        let literal = Data(("{\"schema\":\"keyvault-namecoin-psbt-ack/2\",\"status\":\"SIGNED\",\"result_sha256\":\"" + String(repeating: "12", count: 32) + "\"}\n").utf8)
        #expect(try nativeArchiveValidateAcknowledgement(literal, resultHash: hash) == literal)
        for bad in [Data(literal.dropLast()), literal + Data([10]), Data("{}\n".utf8)] {
            expectBridgeRefusal("outcome_unknown") { _ = try nativeArchiveValidateAcknowledgement(bad, resultHash: hash) }
        }
        expectBridgeRefusal("outcome_unknown") { _ = try nativeArchiveValidateAcknowledgement(literal, resultHash: Data(repeating: 0, count: 32)) }
    }
}
