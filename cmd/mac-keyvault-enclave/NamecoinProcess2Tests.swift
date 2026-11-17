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
    for index in [serviceOffset, groupOffset, pinOffset, sidecarOffset, recordOffset, fixture.frame.count - 32 - 181 - 65, fixture.frame.count - 1] {
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
    #expect(throws: NativeNamecoinProcessFailure("request_expired")) { _ = try nativeNamecoinReadCustody(descriptors[0], deadline: deadline) }
    _ = Darwin.close(descriptors[1]); descriptors[1] = -1
    #expect(try nativeNamecoinReadCustody(descriptors[0], deadline: DispatchTime.now().uptimeNanoseconds + 1_000_000_000).isEmpty)
}

private func p2Pipe(_ raw: Data = Data()) throws -> (Int32, Int32) {
    var fds = [Int32](repeating: -1, count: 2)
    guard pipe(&fds) == 0 else { throw NativeNamecoinProcessFailure("output_unavailable") }
    guard raw.count < 8192 else { _ = Darwin.close(fds[0]); _ = Darwin.close(fds[1]); throw NativeNamecoinProcessFailure("invalid_request") }
    if !raw.isEmpty {
        let written = raw.withUnsafeBytes { Darwin.write(fds[1], $0.baseAddress!, $0.count) }
        guard written == raw.count else { _ = Darwin.close(fds[0]); _ = Darwin.close(fds[1]); throw NativeNamecoinProcessFailure("output_unavailable") }
    }
    return (fds[0], fds[1])
}

private func p2Request(_ fixture: P2Fixture, syntax: BridgePublicFixture) throws -> Data {
    var request = syntax.request
    var manifest = try NativeArchiveJSON.decode(Data(request.field("plan_manifest_utf8").text().utf8), maximum: 1 << 20, canonical: false)
    let selected = fixture.inputs.selection
    for (key, value) in [("group", selected.group), ("account", selected.account), ("network", selected.network),
                          ("genesis", nativeArchiveHex(selected.genesis)), ("account_pin_sha256", nativeArchiveHex(selected.publicPin))] {
        manifest = try p2Replace(manifest, key, .string(value))
    }
    manifest = try p2Replace(manifest, "policy", selected.policy)
    let bytes = try manifest.canonical()
    request = try p2Replace(request, "plan_manifest_utf8", .string(String(decoding: bytes, as: UTF8.self)))
    request = try p2Replace(request, "plan_sha256", .string(nativeArchiveHex(Data(SHA256.hash(data: Data("swarma-identity/namecoin-registration-plan/2\0".utf8) + p2Field(bytes))))))
    request = try p2Replace(request, "network", .string(selected.network))
    return try request.canonical()
}

private struct P2OutputSnapshot: Equatable {
    let device: dev_t, inode: ino_t, owner: uid_t, mode: mode_t, links: nlink_t
    let size: off_t, offset: off_t
    let flags: Int32, descriptorFlags: Int32

    init(_ descriptor: Int32) throws {
        var value = stat()
        guard fstat(descriptor, &value) == 0 else { throw NativeNamecoinProcessFailure("output_unavailable") }
        device = value.st_dev; inode = value.st_ino; owner = value.st_uid
        mode = value.st_mode; links = value.st_nlink; size = value.st_size
        offset = lseek(descriptor, 0, SEEK_CUR)
        flags = fcntl(descriptor, F_GETFL); descriptorFlags = fcntl(descriptor, F_GETFD)
        guard offset >= 0, flags >= 0, descriptorFlags >= 0 else { throw NativeNamecoinProcessFailure("output_unavailable") }
    }
}

// The protected-run closure is explicitly simulated; this checks real pipes,
// fd3/status/ACK ordering and refusal boundaries, never native signing success.
@MainActor @Test func process2DispatcherBridgesOnlyValidatedCustody() async throws {
    let fixture = try P2Fixture("v2-distinct-service")
    for mode in ["complete", "malformed", "metadata", "oversized-psbt", "oversized-request", "before-effect", "after-effect"] {
        let syntax = try BridgePublicFixture(psbtCount: mode == "oversized-psbt" ? (1 << 20) + 1 : 6)
        let outputBefore = try P2OutputSnapshot(syntax.descriptor)
        var request = try p2Request(fixture, syntax: syntax)
        if mode == "oversized-request" {
            request.append(Data(repeating: 0x20, count: (2 << 20) + 1 - request.count))
            // A valid over-limit request reaches custody if the loader's own
            // post-read ceiling is removed; malformed JSON cannot mask that bug.
            #expect(try NativeArchiveRequest(request, selected: fixture.inputs.selection).psbt.count == 6)
        }
        var argv = ["namecoin", "sign-psbt", "--process-contract", "2", "--group", fixture.inputs.journal.group,
                    "--account", fixture.inputs.journal.account, "--profile", "/public/profile.json",
                    "--profile-sha256", nativeArchiveHex(Data(SHA256.hash(data: fixture.inputs.canonicalSelection))),
                    "--account-pin", "/public/pin.json", "--request", "/public/request.json",
                    "--request-sha256", nativeArchiveHex(Data(SHA256.hash(data: request))), "--output", "/public/result.json",
                    "--timeout-seconds", "30"]
        #expect(argv.count > 2)
        let stdin = try p2Pipe(); _ = Darwin.close(stdin.1)
        defer { _ = Darwin.close(stdin.0) }
        var raw = fixture.frame
        if mode == "malformed" { raw.append(0) }
        if mode == "metadata" { raw[14 + 6 + 2] ^= 1 }
        let custody = try p2Pipe(raw); _ = Darwin.close(custody.1)
        // runNamecoinProcess2 owns custody.0 and the status writer after creation.
        let status = try p2Pipe()
        defer { _ = Darwin.close(status.0) }
        var protectedCalls = 0, sinkCreated = false
        let resultBytes = Data("public simulated result".utf8)
        let digest = Data(SHA256.hash(data: resultBytes))
        var ack = try NativeArchiveJSON.object([("schema", .string("keyvault-namecoin-psbt-ack/2")),
            ("status", .string("SIGNED")), ("result_sha256", .string(nativeArchiveHex(digest)))]).canonical()
        ack.append(10)
        let dependencies = NativeNamecoinProcessDependencies(readPublicFile: { path, maximum in
            let bytes: Data
            switch path {
            case "/public/profile.json": bytes = fixture.inputs.canonicalSelection
            case "/public/pin.json": bytes = fixture.inputs.accountPin
            case "/public/request.json":
                #expect(maximum == 2 << 20)
                bytes = request
            default: throw NativeNamecoinProcessFailure("invalid_request")
            }
            // Deliberately violate the reader's limit for this control: only
            // the production loader may enforce the post-read request ceiling.
            if mode != "oversized-request" || path != "/public/request.json" {
                guard bytes.count <= maximum else { throw NativeNamecoinProcessFailure("invalid_request") }
            }
            return bytes
        }, currentHelperCDHash: { fixture.inputs.journal.helperCDHash }, sealedAccountSource: nil,
        makeStatusSink: { descriptor, binding in
            sinkCreated = true
            return try NativeNamecoinStatusWriter(descriptor: descriptor, binding: binding)
        }, runArchive: { operation, _, before in
            protectedCalls += 1
            if mode == "before-effect" { throw NativeNamecoinProcessFailure("journal_unavailable") }
            try before()
            if mode == "after-effect" { throw NativeNamecoinProcessFailure("auth_refused") }
            try operation.output.writePublicResult(resultBytes, expectedSHA256: digest)
            try operation.output.close()
            return ack
        })
        let result = await runNamecoinProcess2(arguments: argv, stdinDescriptor: stdin.0, resultDescriptor: syntax.descriptor,
            statusDescriptor: status.1, custodyDescriptor: custody.0, dependencies: dependencies)
        if !sinkCreated { _ = Darwin.close(status.1) }
        var frames = Data()
        var buffer = [UInt8](repeating: 0, count: 256)
        while true {
            let count = buffer.withUnsafeMutableBytes { Darwin.read(status.0, $0.baseAddress!, $0.count) }
            guard count >= 0 else { throw NativeNamecoinProcessFailure("outcome_unknown") }
            if count == 0 { break }
            frames.append(contentsOf: buffer.prefix(count))
        }
        switch mode {
        case "complete":
            #expect(protectedCalls == 1 && result.exitCode == 0 && result.stdout == ack && frames.count == 160)
            #expect(try Data(contentsOf: syntax.directory.appendingPathComponent("result")) == resultBytes)
            if frames.count == 160 {
                let binding = try nativeNamecoinStatusBinding(.parse2(argv))
                #expect(frames[6] == 1 && frames[86] == 2)
                #expect(Data(frames[8..<40]) == binding && Data(frames[88..<120]) == binding)
                #expect(Data(frames[120..<152]) == digest)
            }
        case "malformed", "metadata", "oversized-psbt", "oversized-request":
            #expect(protectedCalls == 0 && !sinkCreated && frames.isEmpty && result.exitCode != 0)
            if mode == "oversized-request" {
                #expect(result.exitCode == 2)
                #expect(result.stdout == Data("{\"schema\":\"keyvault-namecoin-psbt-error/2\",\"code\":\"invalid_request\",\"status\":\"REFUSED\",\"message\":\"Namecoin signing invalid_request.\"}\n".utf8))
            }
        case "before-effect":
            #expect(protectedCalls == 1 && frames.isEmpty && result.exitCode != 0)
        default:
            #expect(protectedCalls == 1 && frames.count == 80 && result.exitCode != 0)
            #expect(String(decoding: result.stdout, as: UTF8.self).contains("UNKNOWN"))
        }
        if mode != "complete" {
            // Refusals, including the simulated post-effect UNKNOWN, preserve
            // the caller's exact empty descriptor and its identity/flags/offset.
            #expect(try P2OutputSnapshot(syntax.descriptor) == outputBefore)
            try syntax.requireEmptyOutput()
        }
        // Every invocation is distinct. No failed/unknown case invokes a retry.
        argv.removeAll()
    }
}

// The production router owns fixed fd5. Run each route probe in a fresh exec
// with fd5 reserved as /dev/null before Swift Testing starts, so no descriptor
// belonging to this test runner or a parallel test can be replaced or closed.
private final class P2RouterBundleMarker: NSObject {}

@Test func processRouterSelectsClosedContracts() throws {
    for mode in ["v2", "v1", "zero-padded", "unknown", "missing-value", "duplicate-v2", "duplicate-v1", "unknown-flag"] {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("namecoin-router-public-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let logURL = directory.appendingPathComponent("child.log")
        let log = Darwin.open(logURL.path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, mode_t(0o600))
        guard log >= 0 else { throw NativeNamecoinProcessFailure("output_unavailable") }
        defer { _ = Darwin.close(log) }
        let null = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
        guard null >= 0 else { throw NativeNamecoinProcessFailure("output_unavailable") }
        let source = fcntl(null, F_DUPFD_CLOEXEC, 64)
        _ = Darwin.close(null)
        guard source >= 64 else { throw NativeNamecoinProcessFailure("output_unavailable") }
        defer { _ = Darwin.close(source) }
        // Keep both action sources above the fixed destination descriptors.
        let logSource = fcntl(log, F_DUPFD_CLOEXEC, 64)
        guard logSource >= 64 else { throw NativeNamecoinProcessFailure("output_unavailable") }
        defer { _ = Darwin.close(logSource) }
        var actions: posix_spawn_file_actions_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw NativeNamecoinProcessFailure("output_unavailable") }
        defer { posix_spawn_file_actions_destroy(&actions) }
        for (from, to) in [(source, Int32(0)), (source, Int32(5)), (logSource, Int32(1)), (logSource, Int32(2))] {
            guard posix_spawn_file_actions_adddup2(&actions, from, to) == 0 else { throw NativeNamecoinProcessFailure("output_unavailable") }
        }
        guard posix_spawn_file_actions_addclose(&actions, source) == 0,
              posix_spawn_file_actions_addclose(&actions, logSource) == 0 else { throw NativeNamecoinProcessFailure("output_unavailable") }
        let executable = URL(fileURLWithPath: CommandLine.arguments[0]).path
        // Darwin's SwiftPM helper requires the current bundle as an explicit
        // input; execing the helper alone can exit zero without running tests.
        guard let bundleExecutable = Bundle(for: P2RouterBundleMarker.self).executableURL else {
            throw NativeNamecoinProcessFailure("output_unavailable")
        }
        let arguments = [executable, "--test-bundle-path", bundleExecutable.path,
                         "--testing-library", "swift-testing", "--filter", "processRouterChildProbe"]
        var environment = ["PATH=/usr/bin:/bin", "HOME=" + NSHomeDirectory(),
                           "TMPDIR=" + FileManager.default.temporaryDirectory.path,
                           "MAC_KEYVAULT_SKIP_KEYCHAIN=1", "KEYVAULT_ROUTER_PUBLIC_TEST_CASE=" + mode]
        // Preserve public toolchain lookup paths without forwarding unrelated
        // runtime settings or credentials.
        for name in ["DYLD_FRAMEWORK_PATH", "DYLD_LIBRARY_PATH"] {
            if let value = ProcessInfo.processInfo.environment[name] { environment.append(name + "=" + value) }
        }
        var argv = arguments.map { strdup($0) } + [nil]
        var envp = environment.map { strdup($0) } + [nil]
        defer { for value in argv + envp { free(value) } }
        var pid: pid_t = 0
        let started = argv.withUnsafeMutableBufferPointer { a in
            envp.withUnsafeMutableBufferPointer { e in
                posix_spawn(&pid, executable, &actions, nil, a.baseAddress!, e.baseAddress!)
            }
        }
        guard started == 0, pid > 1 else { throw NativeNamecoinProcessFailure("output_unavailable") }
        print("Router public probe: case=\(mode) pid=\(pid)")
        let deadline = DispatchTime.now().uptimeNanoseconds + 20_000_000_000
        var status: Int32 = 0, timedOut = false
        while true {
            let waited = waitpid(pid, &status, WNOHANG)
            if waited == pid { break }
            if waited == -1 {
                if errno == EINTR { continue }
                throw NativeNamecoinProcessFailure("outcome_unknown")
            }
            if !timedOut && DispatchTime.now().uptimeNanoseconds >= deadline {
                timedOut = true
                _ = Darwin.kill(pid, SIGKILL)
            }
            usleep(5_000)
        }
        let output = try Data(contentsOf: logURL)
        #expect(!timedOut && status == 0, "Router child \(mode): \(String(decoding: output.prefix(4096), as: UTF8.self))")
        // An empty filter selection or skipped child must not count as proof.
        #expect(String(decoding: output, as: UTF8.self).contains("ROUTER_PUBLIC_CASE_OK:" + mode))
    }
}

// This probe is selected only by the parent test above. The two canonical
// selectors must reach their distinct public-input ceilings; malformed/duplicate
// selectors must reach neither path. All cases refuse before status/bridge and
// preserve the caller's empty output. This is no custody or signing success.
@MainActor @Test(.enabled(if: ProcessInfo.processInfo.environment["KEYVAULT_ROUTER_PUBLIC_TEST_CASE"] != nil))
func processRouterChildProbe() async throws {
    let mode = try #require(ProcessInfo.processInfo.environment["KEYVAULT_ROUTER_PUBLIC_TEST_CASE"])
    let cases = ["v2", "v1", "zero-padded", "unknown", "missing-value", "duplicate-v2", "duplicate-v1", "unknown-flag"]
    #expect(cases.contains(mode))
    var inherited = stat()
    guard fstat(5, &inherited) == 0, inherited.st_mode & mode_t(S_IFMT) == mode_t(S_IFCHR) else {
        throw NativeNamecoinProcessFailure("invalid_request")
    }
    let fixture = try P2Fixture("v2-distinct-service")
    let syntax = try BridgePublicFixture(psbtCount: (1 << 20) + 1)
    let before = try P2OutputSnapshot(syntax.descriptor)
    let request = try p2Request(fixture, syntax: syntax)
    var argv = ["namecoin", "sign-psbt", "--process-contract", "2", "--group", fixture.inputs.journal.group,
                "--account", fixture.inputs.journal.account, "--profile", "/public/profile.json",
                "--profile-sha256", nativeArchiveHex(Data(SHA256.hash(data: fixture.inputs.canonicalSelection))),
                "--account-pin", "/public/pin.json", "--request", "/public/request.json",
                "--request-sha256", nativeArchiveHex(Data(SHA256.hash(data: request))), "--output", "/public/result.json",
                "--timeout-seconds", "30"]
    switch mode {
    case "v1": argv[3] = "1"
    case "zero-padded": argv[3] = "02"
    case "unknown": argv[3] = "9"
    case "missing-value": argv.remove(at: 3)
    case "duplicate-v2": argv += ["--process-contract", "2"]
    case "duplicate-v1": argv[3] = "1"; argv += ["--process-contract", "1"]
    case "unknown-flag": argv += ["--unknown", "x"]
    default: break
    }
    let stdin = try p2Pipe(); _ = Darwin.close(stdin.1)
    defer { _ = Darwin.close(stdin.0) }
    let status = try p2Pipe()
    defer { _ = Darwin.close(status.0) }
    var statusWriter = status.1
    defer { if statusWriter >= 0 { _ = Darwin.close(statusWriter) } }
    var reads: [String] = [], requestMaximum: Int?, helperChecks = 0, sinks = 0, bridges = 0
    let dependencies = NativeNamecoinProcessDependencies(readPublicFile: { path, maximum in
        reads.append(path)
        switch path {
        case "/public/profile.json": return fixture.inputs.canonicalSelection
        case "/public/pin.json": return fixture.inputs.accountPin
        case "/public/request.json": requestMaximum = maximum; return request
        default: throw NativeNamecoinProcessFailure("invalid_request")
        }
    }, currentHelperCDHash: { helperChecks += 1; return fixture.inputs.journal.helperCDHash }, sealedAccountSource: nil,
    makeStatusSink: { _, _ in sinks += 1; throw NativeNamecoinProcessFailure("output_unavailable") },
    runArchive: { _, _, _ in bridges += 1; throw NativeNamecoinProcessFailure("journal_unavailable") })
    let result = await runNamecoinProcess(arguments: argv, stdinDescriptor: stdin.0, resultDescriptor: syntax.descriptor,
                                          statusDescriptor: statusWriter, dependencies: dependencies)
    _ = Darwin.close(statusWriter); statusWriter = -1
    var byte: UInt8 = 0
    #expect(Darwin.read(status.0, &byte, 1) == 0)
    #expect(sinks == 0 && bridges == 0)
    #expect(try P2OutputSnapshot(syntax.descriptor) == before)
    try syntax.requireEmptyOutput()
    if mode == "v1" || mode == "v2" {
        #expect(reads == ["/public/profile.json", "/public/pin.json", "/public/request.json"] && helperChecks == 1)
        #expect(requestMaximum == (mode == "v2" ? 2 << 20 : 8 << 20))
    } else {
        #expect(reads.isEmpty && requestMaximum == nil && helperChecks == 0)
    }
    let code = mode == "v1" ? "journal_unavailable" : "invalid_request"
    let refusal = try #require(JSONSerialization.jsonObject(with: result.stdout) as? [String: String])
    #expect(refusal == ["schema": "keyvault-namecoin-psbt-error/2", "code": code,
                        "status": "REFUSED", "message": "Namecoin signing " + code + "."])
    #expect(result.exitCode == (mode == "v1" ? 1 : 2))
    FileHandle.standardOutput.write(Data(("ROUTER_PUBLIC_CASE_OK:" + mode + "\n").utf8))
}
