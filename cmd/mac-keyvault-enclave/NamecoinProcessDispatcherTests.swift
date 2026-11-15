import CryptoKit
import Darwin
import Foundation
import Testing
@testable import KeyvaultNativeCore

// Public syntax fixtures and injected boundaries only. These tests never open
// Keychain, invoke Touch ID, decrypt an envelope, or run the native Namecoin ABI.
private final class ProcessEventLog {
    var values: [String] = []
    var statusBinding: Data?
    var statusResultDigest: Data?
}

private final class ProcessRecordingStatusSink: NativeNamecoinStatusSink {
    private let log: ProcessEventLog
    private let failCompletion: Bool
    private var closed = false

    init(log: ProcessEventLog, failCompletion: Bool = false) {
        self.log = log
        self.failCompletion = failCompletion
    }

    func effectStarted() throws { log.values.append("effect-started") }

    func nativeCompleted(resultSHA256: Data) throws {
        log.statusResultDigest = resultSHA256
        log.values.append("native-completed-attempt")
        guard !failCompletion else { throw NativeNamecoinProcessFailure("outcome_unknown") }
        log.values.append("native-completed")
    }

    func close() throws {
        guard !closed else { return }
        closed = true
        log.values.append("status-close")
    }
}

private final class ProcessObservedStatusSink: NativeNamecoinStatusSink {
    private let writer: NativeNamecoinStatusWriter
    private let log: ProcessEventLog
    private var closed = false

    init(writer: NativeNamecoinStatusWriter, log: ProcessEventLog) {
        self.writer = writer
        self.log = log
    }

    func effectStarted() throws {
        try writer.effectStarted()
        log.values.append("effect-started")
    }

    func nativeCompleted(resultSHA256: Data) throws {
        log.statusResultDigest = resultSHA256
        log.values.append("native-completed-attempt")
        try writer.nativeCompleted(resultSHA256: resultSHA256)
        log.values.append("native-completed")
    }

    func close() throws {
        guard !closed else { return }
        closed = true
        try writer.close()
        log.values.append("status-close")
    }
}

private final class ProcessSealedAccountSource: NativeNamecoinSealedAccountSource {
    private let account: NativeJournalSealedAccount
    private let log: ProcessEventLog
    private(set) var loads = 0
    private(set) var selectedGroup = ""
    private(set) var selectedAccount = ""

    init(account: NativeJournalSealedAccount, log: ProcessEventLog) {
        self.account = account
        self.log = log
    }

    func loadSelectedAccount(selection: NativeArchiveSelection,
                             journal: NativeJournalSelection) throws -> NativeJournalSealedAccount {
        loads += 1
        selectedGroup = selection.group
        selectedAccount = journal.account
        log.values.append("source-load")
        return account
    }
}

private final class ProcessSafeInputFixture {
    let directory: URL

    init() throws {
        let temporaryDirectory = FileManager.default.temporaryDirectory
        var resolvedPath = [CChar](repeating: 0, count: Int(PATH_MAX))
        let resolved = temporaryDirectory.path.withCString { source in
            resolvedPath.withUnsafeMutableBufferPointer { target in
                Darwin.realpath(source, target.baseAddress)
            }
        }
        guard resolved != nil else { throw NativeNamecoinProcessFailure("output_unavailable") }
        directory = URL(fileURLWithPath: String(cString: resolvedPath), isDirectory: true)
            .appendingPathComponent("namecoin-process-public-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
    }

    deinit { try? FileManager.default.removeItem(at: directory) }

    func file(_ name: String, bytes: Data, mode: mode_t = 0o600) throws -> URL {
        let url = directory.appendingPathComponent(name)
        let descriptor = Darwin.open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)
        guard descriptor >= 0 else { throw NativeNamecoinProcessFailure("output_unavailable") }
        var closed = false
        defer { if !closed { _ = Darwin.close(descriptor) } }
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeBytes {
                Darwin.write(descriptor, $0.baseAddress!.advanced(by: offset), bytes.count - offset)
            }
            guard count > 0 else { throw NativeNamecoinProcessFailure("output_unavailable") }
            offset += count
        }
        let closeResult = Darwin.close(descriptor)
        closed = true
        guard closeResult == 0 else { throw NativeNamecoinProcessFailure("output_unavailable") }
        return url
    }
}

private func processHex(_ bytes: Data) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

private func processBytes(_ value: String) -> Data {
    let encoded = Array(value.utf8)
    var result = Data(capacity: encoded.count / 2)
    var index = 0
    while index + 1 < encoded.count {
        result.append(UInt8(String(decoding: encoded[index..<(index + 2)], as: UTF8.self), radix: 16)!)
        index += 2
    }
    return result
}

private func processPipe() throws -> (read: Int32, write: Int32) {
    var descriptors = [Int32](repeating: -1, count: 2)
    let result = descriptors.withUnsafeMutableBufferPointer { Darwin.pipe($0.baseAddress!) }
    guard result == 0 else { throw NativeNamecoinProcessFailure("output_unavailable") }
    return (descriptors[0], descriptors[1])
}

private func processEOFStdin() throws -> Int32 {
    let descriptors = try processPipe()
    _ = Darwin.close(descriptors.write)
    return descriptors.read
}

private func processReadToEOF(_ descriptor: Int32) throws -> Data {
    var result = Data()
    while true {
        var chunk = Data(count: 256)
        let count = chunk.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress!, $0.count) }
        if count == 0 { return result }
        if count < 0 {
            if errno == EINTR { continue }
            throw NativeNamecoinProcessFailure("outcome_unknown")
        }
        result.append(chunk.prefix(count))
    }
}

private func processArgv(mode: NativeNamecoinProcessMode, fixture: BridgePublicFixture,
                         profile: Data, request: Data,
                         revealPinPath: String? = nil) -> [String] {
    var argv = ["namecoin", mode.rawValue,
                "--process-contract", "1",
                "--group", fixture.journal.group,
                "--account", fixture.journal.account,
                "--profile", "/public/profile.json",
                "--profile-sha256", processHex(Data(SHA256.hash(data: profile))),
                "--account-pin", "/public/account-pin.json"]
    switch mode {
    case .sign:
        argv += ["--request", "/public/request.json",
                 "--request-sha256", processHex(Data(SHA256.hash(data: request))),
                 "--output", "/public/result.json"]
        if let revealPinPath { argv += ["--reveal-values-pin", revealPinPath] }
    case .reconcile:
        argv += ["--query", "/public/query.json", "--output", "/public/result.json"]
    case .initialize:
        argv += ["--adoption-plan-sha256", String(repeating: "a", count: 64)]
    }
    argv += ["--timeout-seconds", "60"]
    return argv
}

private func processQuery() throws -> Data {
    try NativeArchiveJSON.object([
        ("schema", .string("keyvault-namecoin-reconcile/2")),
        ("request_id", .string(String(repeating: "1", count: 64))),
        ("plan_sha256", .string(String(repeating: "2", count: 64))),
        ("slot", .string("A")),
    ]).canonical()
}

private func processAcknowledgement(_ resultDigest: Data) throws -> Data {
    var raw = try NativeArchiveJSON.object([
        ("schema", .string("keyvault-namecoin-psbt-ack/2")),
        ("status", .string("SIGNED")),
        ("result_sha256", .string(processHex(resultDigest))),
    ]).canonical()
    raw.append(10)
    return raw
}

private func expectProcessEventOrder(_ log: ProcessEventLog, _ expected: [String]) {
    let indexes = expected.map { log.values.firstIndex(of: $0) }
    guard indexes.allSatisfy({ $0 != nil }) else {
        Issue.record("Missing expected process events: \(expected.filter { !log.values.contains($0) })")
        return
    }
    let positions = indexes.compactMap { $0 }
    #expect(zip(positions, positions.dropFirst()).allSatisfy { $0 < $1 })
}

private typealias ProcessPublicReader = (String, Int) throws -> Data

private func processPublicReader(fixture: BridgePublicFixture, request: Data,
                                 profile: Data? = nil,
                                 query: Data? = nil, pin: Data? = nil,
                                 revealPin: Data? = nil,
                                 log: ProcessEventLog? = nil,
                                 enforceMaximum: Bool = true) throws -> ProcessPublicReader {
    let limits = [
        "/public/profile.json": 4 << 20,
        "/public/account-pin.json": 32768,
        "/public/request.json": 8 << 20,
        "/public/query.json": 4096,
    ]
    let selectedProfile: Data
    if let profile { selectedProfile = profile } else { selectedProfile = try fixture.config.canonical() }
    var files: [String: Data] = [
        "/public/profile.json": selectedProfile,
        "/public/account-pin.json": pin ?? fixture.pin,
        "/public/request.json": request,
    ]
    if let query { files["/public/query.json"] = query }
    if let revealPin { files["/public/reveal-values-pin.json"] = revealPin }
    return { path, maximum in
        log?.values.append("read:" + path)
        let expectedMaximum: Int?
        if path == "/public/reveal-values-pin.json" { expectedMaximum = 1 << 20 }
        else { expectedMaximum = limits[path] }
        guard let bytes = files[path], expectedMaximum == maximum,
              !enforceMaximum || bytes.count <= maximum else {
            throw NativeNamecoinProcessFailure("invalid_request")
        }
        return bytes
    }
}

@MainActor
private func processDependencies(fixture: BridgePublicFixture, request: Data,
                                 profile: Data? = nil,
                                 query: Data? = nil, pin: Data? = nil,
                                 revealPin: Data? = nil,
                                 source: (any NativeNamecoinSealedAccountSource)? = nil,
                                 log: ProcessEventLog,
                                 status: any NativeNamecoinStatusSink,
                                 runArchive: @escaping NativeNamecoinArchiveRunner,
                                 enforceMaximum: Bool = true) throws -> NativeNamecoinProcessDependencies {
    let reader = try processPublicReader(fixture: fixture, request: request, profile: profile,
                                         query: query, pin: pin, revealPin: revealPin,
                                         log: log, enforceMaximum: enforceMaximum)
    return NativeNamecoinProcessDependencies(
        readPublicFile: reader,
        currentHelperCDHash: { log.values.append("helper-cdhash"); return fixture.journal.helperCDHash },
        sealedAccountSource: source,
        makeStatusSink: { descriptor, binding in
            #expect(descriptor >= 3)
            #expect(binding.count == 32)
            log.statusBinding = binding
            log.values.append("status-create")
            return status
        },
        runArchive: runArchive
    )
}

private func processFailureCode(_ result: NativeNamecoinProcessResult) throws -> String {
    let raw = result.stdout.last == 10 ? Data(result.stdout.dropLast()) : result.stdout
    let body = try NativeArchiveJSON.decode(raw, maximum: 4096, canonical: true)
    return try body.field("code").text()
}

private func processResultFailureCode(_ result: NativeNamecoinProcessResult) -> String {
    (try? processFailureCode(result)) ?? "unparseable"
}

private func expectProcessParseRefusal(_ argv: [String]) {
    do {
        _ = try NativeNamecoinProcessArguments.parse(argv)
        Issue.record("Expected closed process argv refusal")
    } catch let failure as NativeNamecoinProcessFailure {
        #expect(failure.code == "invalid_request")
    } catch {
        Issue.record("Unexpected process argv error")
    }
}

private func processFixtureSealedAccount() throws -> NativeJournalSealedAccount {
    let p256Generator = processBytes("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
    return try NativeJournalSealedAccount(enclaveBlob: Data("opaque public envelope fixture".utf8),
                                          wrappingPoint: p256Generator,
                                          ciphertext: p256Generator + Data(repeating: 0x5a, count: 116),
                                          expectedBinding: Data(repeating: 0x99, count: 32))
}

private func processRevealProfileAndRequest(fixture: BridgePublicFixture, slot: String,
                                            revealPin: Data) throws -> (profile: Data, request: Data) {
    guard ["C", "D"].contains(slot) else { throw NativeNamecoinProcessFailure("invalid_request") }
    let selection = try processReplace(fixture.config.field("selection"), key: "RevealValuesPin",
                                       value: .string(revealPin.base64EncodedString()))
    let config = try processReplace(fixture.config, key: "selection", value: selection)
    let profile = try config.canonical()

    let manifestText = try fixture.request.field("plan_manifest_utf8").text()
    let manifest = try NativeArchiveJSON.decode(Data(manifestText.utf8), maximum: 1 << 20, canonical: true)
    let transactions = try manifest.field("transactions").list()
    guard transactions.count == 1 else { throw NativeNamecoinProcessFailure("invalid_request") }
    let transaction = try processReplace(transactions[0], key: "slot", value: .string(slot))
    let changedManifest = try processReplace(manifest, key: "transactions", value: .array([transaction]))
    let manifestBytes = try changedManifest.canonical()
    var planFrame = Data("swarma-identity/namecoin-registration-plan/2\0".utf8)
    planFrame.append(nativeJournalLP(manifestBytes))
    let planDigest = Data(SHA256.hash(data: planFrame))

    var intent = try processReplace(fixture.request.field("intent"), key: "operation",
                                    value: .string("name_firstupdate"))
    intent = try processReplace(intent, key: "value_hex", value: .string("00"))
    intent = try processReplace(intent, key: "reservation_outpoint", value: .object([
        ("txid", .string(String(repeating: "3", count: 64))), ("vout", .number(0)),
    ]))
    var request = try processReplace(fixture.request, key: "slot", value: .string(slot))
    request = try processReplace(request, key: "plan_manifest_utf8",
                                 value: .string(String(decoding: manifestBytes, as: UTF8.self)))
    request = try processReplace(request, key: "plan_sha256", value: .string(processHex(planDigest)))
    request = try processReplace(request, key: "reservation_plan_sha256", value: .string(processHex(planDigest)))
    request = try processReplace(request, key: "intent", value: intent)
    return (profile, try request.canonical())
}

@Suite(.serialized)
struct NamecoinProcessDispatcherTests {
    @Test func processArgumentsRejectClosedFormBypass() throws {
        let fixture = try BridgePublicFixture()
        let profile = try fixture.config.canonical()
        let request = try fixture.request.canonical()
        let valid = processArgv(mode: .sign, fixture: fixture, profile: profile, request: request)
        #expect(try NativeNamecoinProcessArguments.parse(valid).mode.rawValue == "sign-psbt")
        #expect(try NativeNamecoinProcessArguments.parse(processArgv(mode: .reconcile, fixture: fixture,
                                                                       profile: profile, request: request)).mode.rawValue == "reconcile")

        func replacing(_ flag: String, with value: String) -> [String] {
            var copy = valid
            if let index = copy.firstIndex(of: flag), index + 1 < copy.count { copy[index + 1] = value }
            return copy
        }
        expectProcessParseRefusal(replacing("--process-contract", with: "2"))
        var duplicate = valid
        duplicate += ["--group", fixture.journal.group]
        expectProcessParseRefusal(duplicate)
        var unknown = valid
        unknown += ["--trace", "1"]
        expectProcessParseRefusal(unknown)
        expectProcessParseRefusal(replacing("--profile-sha256", with: String(repeating: "A", count: 64)))
        expectProcessParseRefusal(replacing("--profile", with: "/public/../profile.json"))
        expectProcessParseRefusal(replacing("--timeout-seconds", with: "01"))
        var modeOnly = valid
        modeOnly += ["--query", "/public/query.json"]
        expectProcessParseRefusal(modeOnly)
    }

    @Test func statusBindingMatchesProcess1VectorAndBindsPublicInputs() throws {
        let profileDigest = Data(SHA256.hash(data: Data("profile digest".utf8)))
        let requestDigest = Data(SHA256.hash(data: Data("operation digest".utf8)))
        let argv = ["namecoin", "sign-psbt",
                    "--process-contract", "1",
                    "--group", "fixture/recovery@1",
                    "--account", "fixture/namecoin@1",
                    "--profile", "/public/profile.json",
                    "--profile-sha256", processHex(profileDigest),
                    "--account-pin", "/public/account-pin.json",
                    "--request", "/public/request.json",
                    "--request-sha256", processHex(requestDigest),
                    "--output", "/public/result.json",
                    "--timeout-seconds", "60"]
        let arguments = try NativeNamecoinProcessArguments.parse(argv)
        let binding = try nativeNamecoinStatusBinding(arguments)
        #expect(processHex(binding) == "ef3083cd1e1b9442fcf90c31789b8bf36bf8a4ff9e2420cd7f07d5e8297e7bf8")
        var changed = argv
        if let index = changed.firstIndex(of: "--request-sha256") { changed[index + 1] = String(repeating: "3", count: 64) }
        #expect(try nativeNamecoinStatusBinding(NativeNamecoinProcessArguments.parse(changed)) != binding)
    }

    @Test func safePublicInputAdmitsOnlyPrivateStableRegularFiles() throws {
        let fixture = try ProcessSafeInputFixture()
        let bytes = Data("public fixture bytes".utf8)
        let regular = try fixture.file("regular", bytes: bytes)
        #expect(try NativeNamecoinSafeInput.read(regular.path, 1024) == bytes)

        let tooLarge = try fixture.file("too-large", bytes: Data(repeating: 0x41, count: 5))
        expectSafeInputRefusal(tooLarge.path, maximum: 4)
        let broadMode = try fixture.file("broad-mode", bytes: bytes, mode: 0o644)
        expectSafeInputRefusal(broadMode.path, maximum: 1024)

        let hardLink = fixture.directory.appendingPathComponent("hard-link")
        let linkResult = regular.path.withCString { source in
            hardLink.path.withCString { Darwin.link(source, $0) }
        }
        #expect(linkResult == 0)
        if linkResult == 0 { expectSafeInputRefusal(regular.path, maximum: 1024) }

        let symbolicLink = fixture.directory.appendingPathComponent("symbolic-link")
        let symlinkResult = regular.path.withCString { source in
            symbolicLink.path.withCString { Darwin.symlink(source, $0) }
        }
        #expect(symlinkResult == 0)
        if symlinkResult == 0 { expectSafeInputRefusal(symbolicLink.path, maximum: 1024) }
    }

    @Test @MainActor func initializeJournalRefusesBeforeAnyInputOrEffect() async throws {
        let fixture = try BridgePublicFixture()
        let profile = try fixture.config.canonical()
        let request = try fixture.request.canonical()
        let argv = processArgv(mode: .initialize, fixture: fixture, profile: profile, request: request)
        let log = ProcessEventLog()
        let status = ProcessRecordingStatusSink(log: log)
        let dependencies = NativeNamecoinProcessDependencies(
            readPublicFile: { _, _ in Issue.record("Initialization must refuse before reading files"); throw NativeNamecoinProcessFailure("invalid_request") },
            currentHelperCDHash: { Issue.record("Initialization must refuse before helper lookup"); return Data() },
            sealedAccountSource: nil,
            makeStatusSink: { _, _ in Issue.record("Initialization must not create fd-4 status"); return status },
            runArchive: { _, _, _ in Issue.record("Initialization must not reach archive"); throw NativeNamecoinProcessFailure("invalid_request") }
        )
        let result = await runNamecoinProcess1(arguments: argv, stdinDescriptor: -1,
                                               resultDescriptor: fixture.descriptor, statusDescriptor: -1,
                                               dependencies: dependencies)
        #expect(try processFailureCode(result) == "invalid_request")
        #expect(result.exitCode == 2)
        #expect(log.values.isEmpty)
        try fixture.requireEmptyOutput()
    }

    @Test @MainActor func signWithoutSealedAccountSourceRefusesBeforeEffects() async throws {
        let fixture = try BridgePublicFixture()
        let profile = try fixture.config.canonical()
        let request = try fixture.request.canonical()
        let stdin = try processEOFStdin()
        defer { _ = Darwin.close(stdin) }
        let statusPipe = try processPipe()
        defer { _ = Darwin.close(statusPipe.read); _ = Darwin.close(statusPipe.write) }
        let oldFlags = fcntl(statusPipe.read, F_GETFL)
        #expect(oldFlags >= 0 && fcntl(statusPipe.read, F_SETFL, oldFlags | O_NONBLOCK) == 0)
        let log = ProcessEventLog()
        let status = ProcessRecordingStatusSink(log: log)
        var archiveCalls = 0
        let dependencies = try processDependencies(fixture: fixture, request: request, log: log, status: status,
                                                   runArchive: { _, _, _ in
            archiveCalls += 1
            throw NativeNamecoinProcessFailure("outcome_unknown")
        })
        let result = await runNamecoinProcess1(arguments: processArgv(mode: .sign, fixture: fixture,
                                                                      profile: profile, request: request),
                                               stdinDescriptor: stdin, resultDescriptor: fixture.descriptor,
                                               statusDescriptor: statusPipe.write, dependencies: dependencies)
        #expect(try processFailureCode(result) == "journal_unavailable")
        #expect(result.exitCode == 1)
        #expect(archiveCalls == 0)
        #expect(!log.values.contains("status-create"))
        #expect(!log.values.contains("effect-started"))
        try fixture.requireEmptyOutput()
        var byte: UInt8 = 0
        #expect(Darwin.read(statusPipe.read, &byte, 1) == -1)
        #expect(errno == EAGAIN || errno == EWOULDBLOCK)
    }

    @Test @MainActor func processInputValidationRejectsHashesPinsAndQueryBounds() async throws {
        let fixture = try BridgePublicFixture()
        let profile = try fixture.config.canonical()
        let request = try fixture.request.canonical()
        let validQuery = try processQuery()
        let log = ProcessEventLog()
        let status = ProcessRecordingStatusSink(log: log)
        let source = ProcessSealedAccountSource(account: try processFixtureSealedAccount(), log: log)
        let noRun: NativeNamecoinArchiveRunner = { _, _, _ in
            Issue.record("Input refusal must happen before archive dispatch")
            throw NativeNamecoinProcessFailure("outcome_unknown")
        }

        @MainActor func run(_ argv: [String], requestBytes: Data, query: Data? = nil,
                 pin: Data? = nil, enforceMaximum: Bool = true) async throws -> NativeNamecoinProcessResult {
            let stdin = try processEOFStdin()
            defer { _ = Darwin.close(stdin) }
            let dependencies = try processDependencies(fixture: fixture, request: requestBytes, query: query,
                                                       pin: pin, source: source, log: log, status: status,
                                                       runArchive: noRun, enforceMaximum: enforceMaximum)
            return await runNamecoinProcess1(arguments: argv, stdinDescriptor: stdin,
                                             resultDescriptor: fixture.descriptor, statusDescriptor: -1,
                                             dependencies: dependencies)
        }

        var badProfile = processArgv(mode: .sign, fixture: fixture, profile: profile, request: request)
        if let hash = badProfile.firstIndex(of: "--profile-sha256") { badProfile[hash + 1] = String(repeating: "0", count: 64) }
        let badProfileResult = try await run(badProfile, requestBytes: request)
        #expect(try processFailureCode(badProfileResult) == "policy_refused")

        var badRequestDigest = processArgv(mode: .sign, fixture: fixture, profile: profile, request: request)
        if let hash = badRequestDigest.firstIndex(of: "--request-sha256") { badRequestDigest[hash + 1] = String(repeating: "0", count: 64) }
        let badRequestDigestResult = try await run(badRequestDigest, requestBytes: request)
        #expect(try processFailureCode(badRequestDigestResult) == "invalid_request")

        let badPinResult = try await run(processArgv(mode: .sign, fixture: fixture, profile: profile, request: request),
                                         requestBytes: request, pin: Data("wrong public pin".utf8))
        #expect(try processFailureCode(badPinResult) == "account_mismatch")

        let reconcileArgv = processArgv(mode: .reconcile, fixture: fixture, profile: profile, request: request)
        let oversizedQuery = Data(repeating: 0x20, count: 4097)
        let oversizedQueryResult = try await run(reconcileArgv, requestBytes: request,
                                                 query: oversizedQuery, enforceMaximum: false)
        #expect(try processFailureCode(oversizedQueryResult) == "invalid_request")
        let malformedQueryResult = try await run(reconcileArgv, requestBytes: request,
                                                 query: Data("{}".utf8))
        #expect(try processFailureCode(malformedQueryResult) == "invalid_request")
        #expect(!log.values.contains("status-create"))
        #expect(!log.values.contains("effect-started"))
        #expect(source.loads == 0)
        try fixture.requireEmptyOutput()
    }

    @Test @MainActor func nameUpdateRefusesBeforeSourceOrBridge() async throws {
        let fixture = try BridgePublicFixture()
        let profile = try fixture.config.canonical()
        let requestJSON = try fixture.request.field("intent")
        let changedIntent = try processReplace(requestJSON, key: "operation", value: .string("name_update"))
        let changedRequestJSON = try processReplace(fixture.request, key: "intent", value: changedIntent)
        let changedRequest = try changedRequestJSON.canonical()
        let stdin = try processEOFStdin()
        defer { _ = Darwin.close(stdin) }
        let log = ProcessEventLog()
        let source = ProcessSealedAccountSource(account: try processFixtureSealedAccount(), log: log)
        let status = ProcessRecordingStatusSink(log: log)
        var archiveCalls = 0
        let dependencies = try processDependencies(fixture: fixture, request: changedRequest,
                                                   source: source, log: log, status: status,
                                                   runArchive: { _, _, _ in
            archiveCalls += 1
            throw NativeNamecoinProcessFailure("outcome_unknown")
        })
        let result = await runNamecoinProcess1(arguments: processArgv(mode: .sign, fixture: fixture,
                                                                      profile: profile, request: changedRequest),
                                               stdinDescriptor: stdin, resultDescriptor: fixture.descriptor,
                                               statusDescriptor: -1, dependencies: dependencies)
        #expect(try processFailureCode(result) == "intent_mismatch")
        #expect(source.loads == 0 && archiveCalls == 0)
        #expect(!log.values.contains("status-create"))
        try fixture.requireEmptyOutput()
    }

    @Test @MainActor func nameFirstupdateSlotsAcceptMatchingRevealPin() async throws {
        for slot in ["C", "D"] {
            let fixture = try BridgePublicFixture()
            let revealPin = Data("public reveal-values pin fixture".utf8)
            let inputs = try processRevealProfileAndRequest(fixture: fixture, slot: slot, revealPin: revealPin)
            let stdin = try processEOFStdin()
            defer { _ = Darwin.close(stdin) }
            let statusPipe = try processPipe()
            defer { _ = Darwin.close(statusPipe.read); _ = Darwin.close(statusPipe.write) }
            let log = ProcessEventLog()
            let source = ProcessSealedAccountSource(account: try processFixtureSealedAccount(), log: log)
            let status = ProcessRecordingStatusSink(log: log)
            let publicResult = Data(("public " + slot + " result fixture").utf8)
            let digest = Data(SHA256.hash(data: publicResult))
            let acknowledgement = try processAcknowledgement(digest)
            let argv = processArgv(mode: .sign, fixture: fixture, profile: inputs.profile,
                                   request: inputs.request, revealPinPath: "/public/reveal-values-pin.json")
            let dependencies = try processDependencies(fixture: fixture, request: inputs.request,
                                                       profile: inputs.profile, revealPin: revealPin,
                                                       source: source, log: log, status: status,
                                                       runArchive: { operation, _, beforeNativeRun in
                #expect(operation.request.slot == slot)
                #expect(operation.request.operation.rawValue == "name_firstupdate")
                try beforeNativeRun()
                do { try operation.output.writePublicResult(publicResult, expectedSHA256: digest) }
                catch { Issue.record("Injected public output write failed: \(error)"); throw error }
                return acknowledgement
            })
            let result = await runNamecoinProcess1(arguments: argv, stdinDescriptor: stdin,
                                                   resultDescriptor: fixture.descriptor,
                                                   statusDescriptor: statusPipe.write,
                                                   dependencies: dependencies)
            #expect(result.exitCode == 0 && result.stdout == acknowledgement,
                    "failure code: \(processResultFailureCode(result))")
            #expect(source.loads == 1)
            #expect(log.values.contains("native-completed"))
        }
    }

    @Test @MainActor func nameFirstupdateRejectsMismatchedRevealPinBeforeEffects() async throws {
        let fixture = try BridgePublicFixture()
        let selectedPin = Data("selected public reveal pin".utf8)
        let suppliedPin = Data("different public reveal pin".utf8)
        let inputs = try processRevealProfileAndRequest(fixture: fixture, slot: "C", revealPin: selectedPin)
        let stdin = try processEOFStdin()
        defer { _ = Darwin.close(stdin) }
        let log = ProcessEventLog()
        let source = ProcessSealedAccountSource(account: try processFixtureSealedAccount(), log: log)
        let status = ProcessRecordingStatusSink(log: log)
        let dependencies = try processDependencies(fixture: fixture, request: inputs.request,
                                                   profile: inputs.profile, revealPin: suppliedPin,
                                                   source: source, log: log, status: status,
                                                   runArchive: { _, _, _ in
            Issue.record("Reveal pin mismatch must refuse before archive dispatch")
            throw NativeNamecoinProcessFailure("outcome_unknown")
        })
        let result = await runNamecoinProcess1(arguments: processArgv(mode: .sign, fixture: fixture,
                                                                      profile: inputs.profile,
                                                                      request: inputs.request,
                                                                      revealPinPath: "/public/reveal-values-pin.json"),
                                               stdinDescriptor: stdin, resultDescriptor: fixture.descriptor,
                                               statusDescriptor: -1, dependencies: dependencies)
        #expect(try processFailureCode(result) == "intent_mismatch")
        #expect(source.loads == 0)
        #expect(!log.values.contains("status-create"))
        try fixture.requireEmptyOutput()
    }

    @Test @MainActor func reconcileValidatesThenReturnsUnknownWithoutEffects() async throws {
        let fixture = try BridgePublicFixture()
        let profile = try fixture.config.canonical()
        let request = try fixture.request.canonical()
        let query = try processQuery()
        let argv = processArgv(mode: .reconcile, fixture: fixture, profile: profile, request: request)
        let stdin = try processEOFStdin()
        defer { _ = Darwin.close(stdin) }
        let statusPipe = try processPipe()
        defer { _ = Darwin.close(statusPipe.read); _ = Darwin.close(statusPipe.write) }
        let oldFlags = fcntl(statusPipe.read, F_GETFL)
        #expect(oldFlags >= 0 && fcntl(statusPipe.read, F_SETFL, oldFlags | O_NONBLOCK) == 0)
        let log = ProcessEventLog()
        let status = ProcessRecordingStatusSink(log: log)
        var archiveCalls = 0
        let dependencies = try processDependencies(fixture: fixture, request: request, query: query,
                                                   log: log, status: status, runArchive: { _, _, _ in
            archiveCalls += 1
            throw NativeNamecoinProcessFailure("outcome_unknown")
        })
        let result = await runNamecoinProcess1(arguments: argv, stdinDescriptor: stdin,
                                               resultDescriptor: fixture.descriptor, statusDescriptor: statusPipe.write,
                                               dependencies: dependencies)
        #expect(try processFailureCode(result) == "outcome_unknown")
        #expect(result.exitCode == 1)
        #expect(archiveCalls == 0)
        #expect(!log.values.contains("status-create"))
        try fixture.requireEmptyOutput()
        var byte: UInt8 = 0
        #expect(Darwin.read(statusPipe.read, &byte, 1) == -1)
        #expect(errno == EAGAIN || errno == EWOULDBLOCK)
    }

    @Test @MainActor func statusWriterFramesAndOwnsStatusDescriptor() throws {
        let pipe = try processPipe()
        defer { _ = Darwin.close(pipe.read) }
        let binding = Data(repeating: 0x31, count: 32)
        let digest = Data(repeating: 0x72, count: 32)
        let writer = try NativeNamecoinStatusWriter(descriptor: pipe.write, binding: binding)
        #expect(fcntl(pipe.write, F_GETFD) == FD_CLOEXEC)
        try writer.effectStarted()
        try writer.nativeCompleted(resultSHA256: digest)
        try writer.close()
        let bytes = try processReadToEOF(pipe.read)
        #expect(bytes.count == 160)
        guard bytes.count == 160 else { return }
        #expect(bytes.prefix(4) == Data("KVNS".utf8))
        #expect(bytes[4] == 0 && bytes[5] == 1 && bytes[6] == 1 && bytes[7] == 0)
        #expect(bytes[8..<40] == binding)
        #expect(bytes[40..<72] == Data(repeating: 0, count: 32))
        #expect(bytes[72..<80] == Data(repeating: 0, count: 8))
        #expect(bytes[80..<84] == Data("KVNS".utf8))
        #expect(bytes[84] == 0 && bytes[85] == 1 && bytes[86] == 2 && bytes[87] == 0)
        #expect(bytes[88..<120] == binding)
        #expect(bytes[120..<152] == digest)
        #expect(bytes[152..<160] == Data(repeating: 0, count: 8))

        let badPipe = try processPipe()
        let badWriter = try NativeNamecoinStatusWriter(descriptor: badPipe.write, binding: binding)
        expectProcessSinkRefusal { try badWriter.nativeCompleted(resultSHA256: digest) }
        try badWriter.effectStarted()
        expectProcessSinkRefusal { try badWriter.effectStarted() }
        try badWriter.close()
        #expect(try processReadToEOF(badPipe.read).count == 80)
        _ = Darwin.close(badPipe.read)
    }

    @Test @MainActor func fakeSealedSourceDispatchesBeforeProtectedCallAndCompletion() async throws {
        let fixture = try BridgePublicFixture()
        let profile = try fixture.config.canonical()
        let request = try fixture.request.canonical()
        let stdin = try processEOFStdin()
        defer { _ = Darwin.close(stdin) }
        let statusPipe = try processPipe()
        var statusDescriptorTransferred = false
        defer {
            _ = Darwin.close(statusPipe.read)
            if !statusDescriptorTransferred { _ = Darwin.close(statusPipe.write) }
        }
        let log = ProcessEventLog()
        let source = ProcessSealedAccountSource(account: try processFixtureSealedAccount(), log: log)
        let publicResult = Data("public test result only".utf8)
        let resultDigest = Data(SHA256.hash(data: publicResult))
        let acknowledgement = try processAcknowledgement(resultDigest)
        let argv = processArgv(mode: .sign, fixture: fixture, profile: profile, request: request)
        let expectedBinding = try nativeNamecoinStatusBinding(NativeNamecoinProcessArguments.parse(argv))
        let reader = try processPublicReader(fixture: fixture, request: request, log: log)
        let dependencies = NativeNamecoinProcessDependencies(
            readPublicFile: reader,
            currentHelperCDHash: { log.values.append("helper-cdhash"); return fixture.journal.helperCDHash },
            sealedAccountSource: source,
            makeStatusSink: { descriptor, binding in
                log.statusBinding = binding
                let writer = try NativeNamecoinStatusWriter(descriptor: descriptor, binding: binding)
                statusDescriptorTransferred = true
                log.values.append("status-create")
                return ProcessObservedStatusSink(writer: writer, log: log)
            },
            runArchive: { operation, _, beforeNativeRun in
            log.values.append("archive-enter")
            try beforeNativeRun()
            log.values.append("protected-call")
            do { try operation.output.writePublicResult(publicResult, expectedSHA256: resultDigest) }
            catch { Issue.record("Injected public output write failed: \(error)"); throw error }
            log.values.append("output-closed")
            try operation.output.close()
            log.values.append("archive-return")
            return acknowledgement
        })
        let result = await runNamecoinProcess1(arguments: argv,
                                               stdinDescriptor: stdin, resultDescriptor: fixture.descriptor,
                                               statusDescriptor: statusPipe.write, dependencies: dependencies)
        #expect(result.exitCode == 0 && result.stdout == acknowledgement,
                "failure code: \(processResultFailureCode(result))")
        #expect(source.loads == 1)
        #expect(source.selectedGroup == fixture.journal.group && source.selectedAccount == fixture.journal.account)
        #expect(log.statusBinding == expectedBinding)
        expectProcessEventOrder(log, ["source-load", "status-create", "effect-started", "protected-call",
                                      "output-closed", "archive-return", "native-completed"])
        #expect(log.statusResultDigest == resultDigest)
        #expect(log.values.last == "status-close")
        let frames = try processReadToEOF(statusPipe.read)
        #expect(frames.count == 160)
        if frames.count == 160 {
            #expect(frames[6] == 1 && frames[86] == 2)
            #expect(frames[8..<40] == expectedBinding && frames[88..<120] == expectedBinding)
            #expect(frames[40..<72] == Data(repeating: 0, count: 32))
            #expect(frames[120..<152] == resultDigest)
            #expect(frames[7] == 0 && frames[87] == 0)
            #expect(frames[72..<80] == Data(repeating: 0, count: 8))
            #expect(frames[152..<160] == Data(repeating: 0, count: 8))
        }
        var output = Data(count: publicResult.count)
        let copied = output.withUnsafeMutableBytes { Darwin.pread(fixture.descriptor, $0.baseAddress!, $0.count, 0) }
        #expect(copied == publicResult.count && output == publicResult)
    }

    @Test @MainActor func postEffectFailureNeverAcknowledges() async throws {
        let fixture = try BridgePublicFixture()
        let profile = try fixture.config.canonical()
        let request = try fixture.request.canonical()
        let stdin = try processEOFStdin()
        defer { _ = Darwin.close(stdin) }
        let statusPipe = try processPipe()
        defer { _ = Darwin.close(statusPipe.read); _ = Darwin.close(statusPipe.write) }
        let log = ProcessEventLog()
        let source = ProcessSealedAccountSource(account: try processFixtureSealedAccount(), log: log)
        let status = ProcessRecordingStatusSink(log: log)
        let dependencies = try processDependencies(fixture: fixture, request: request, source: source,
                                                   log: log, status: status, runArchive: { _, _, beforeNativeRun in
            try beforeNativeRun()
            throw NativeNamecoinProcessFailure("journal_unavailable")
        })
        let result = await runNamecoinProcess1(arguments: processArgv(mode: .sign, fixture: fixture,
                                                                      profile: profile, request: request),
                                               stdinDescriptor: stdin, resultDescriptor: fixture.descriptor,
                                               statusDescriptor: statusPipe.write, dependencies: dependencies)
        #expect(try processFailureCode(result) == "outcome_unknown")
        #expect(result.exitCode == 1)
        #expect(!log.values.contains("native-completed"))
        #expect(!String(decoding: result.stdout, as: UTF8.self).contains("keyvault-namecoin-psbt-ack/2"))
        try fixture.requireEmptyOutput()
    }

    @Test @MainActor func failedCompletionFrameCannotReturnAcknowledgement() async throws {
        let fixture = try BridgePublicFixture()
        let profile = try fixture.config.canonical()
        let request = try fixture.request.canonical()
        let stdin = try processEOFStdin()
        defer { _ = Darwin.close(stdin) }
        let statusPipe = try processPipe()
        defer { _ = Darwin.close(statusPipe.read); _ = Darwin.close(statusPipe.write) }
        let log = ProcessEventLog()
        let source = ProcessSealedAccountSource(account: try processFixtureSealedAccount(), log: log)
        let status = ProcessRecordingStatusSink(log: log, failCompletion: true)
        let publicResult = Data("public test result before lost status".utf8)
        let digest = Data(SHA256.hash(data: publicResult))
        let acknowledgement = try processAcknowledgement(digest)
        let dependencies = try processDependencies(fixture: fixture, request: request, source: source,
                                                   log: log, status: status, runArchive: { operation, _, beforeNativeRun in
            try beforeNativeRun()
            do { try operation.output.writePublicResult(publicResult, expectedSHA256: digest) }
            catch { Issue.record("Injected public output write failed: \(error)"); throw error }
            return acknowledgement
        })
        let result = await runNamecoinProcess1(arguments: processArgv(mode: .sign, fixture: fixture,
                                                                      profile: profile, request: request),
                                               stdinDescriptor: stdin, resultDescriptor: fixture.descriptor,
                                               statusDescriptor: statusPipe.write, dependencies: dependencies)
        #expect(try processFailureCode(result) == "outcome_unknown")
        #expect(result.exitCode == 1 && result.stdout != acknowledgement)
        #expect(log.values.contains("native-completed-attempt"))
        #expect(!log.values.contains("native-completed"))
        var output = Data(count: publicResult.count)
        let copied = output.withUnsafeMutableBytes { Darwin.pread(fixture.descriptor, $0.baseAddress!, $0.count, 0) }
        #expect(copied == publicResult.count && output == publicResult)
    }

    @Test @MainActor func malformedAcknowledgementNeverCompletesStatus() async throws {
        let fixture = try BridgePublicFixture()
        let profile = try fixture.config.canonical()
        let request = try fixture.request.canonical()
        let stdin = try processEOFStdin()
        defer { _ = Darwin.close(stdin) }
        let statusPipe = try processPipe()
        defer { _ = Darwin.close(statusPipe.read); _ = Darwin.close(statusPipe.write) }
        let log = ProcessEventLog()
        let source = ProcessSealedAccountSource(account: try processFixtureSealedAccount(), log: log)
        let status = ProcessRecordingStatusSink(log: log)
        let publicResult = Data("public fixture result with malformed acknowledgement".utf8)
        let digest = Data(SHA256.hash(data: publicResult))
        let malformedAcknowledgement = Data("{\"schema\":\"wrong-schema\"}\n".utf8)
        let dependencies = try processDependencies(fixture: fixture, request: request, source: source,
                                                   log: log, status: status, runArchive: { operation, _, beforeNativeRun in
            try beforeNativeRun()
            try operation.output.writePublicResult(publicResult, expectedSHA256: digest)
            return malformedAcknowledgement
        })
        let result = await runNamecoinProcess1(arguments: processArgv(mode: .sign, fixture: fixture,
                                                                      profile: profile, request: request),
                                               stdinDescriptor: stdin, resultDescriptor: fixture.descriptor,
                                               statusDescriptor: statusPipe.write, dependencies: dependencies)
        #expect(try processFailureCode(result) == "outcome_unknown")
        #expect(result.stdout != malformedAcknowledgement)
        #expect(!log.values.contains("native-completed-attempt"))
        #expect(log.statusResultDigest == nil)
    }
}

private func processReplace(_ object: NativeArchiveJSON, key: String,
                            value: NativeArchiveJSON?) throws -> NativeArchiveJSON {
    guard case .object(let pairs) = object else { throw NativeNamecoinProcessFailure("invalid_request") }
    var replaced = pairs.compactMap { pair -> (String, NativeArchiveJSON)? in
        pair.0 == key ? value.map { (key, $0) } : pair
    }
    if !pairs.contains(where: { $0.0 == key }), let value { replaced.append((key, value)) }
    return .object(replaced)
}

private func expectProcessSinkRefusal(_ operation: () throws -> Void) {
    do { try operation(); Issue.record("Expected fixed status sink refusal") }
    catch let failure as NativeNamecoinProcessFailure { #expect(failure.code == "outcome_unknown") }
    catch { Issue.record("Unexpected status sink error") }
}

private func expectSafeInputRefusal(_ path: String, maximum: Int) {
    do { _ = try NativeNamecoinSafeInput.read(path, maximum); Issue.record("Expected safe-input refusal") }
    catch let failure as NativeNamecoinProcessFailure { #expect(failure.code == "invalid_request") }
    catch { Issue.record("Unexpected safe-input error") }
}
