import CryptoKit
import Darwin
import Foundation
import Security

enum NativeNamecoinProcessMode: String {
    case sign = "sign-psbt"
    case reconcile
    case initialize = "initialize-journal"
}

struct NativeNamecoinProcessFailure: Error, Equatable {
    static let codes = NativeNamecoinArchiveFailure.codes
    let code: String

    init(_ code: String) {
        self.code = Self.codes.contains(code) ? code : "outcome_unknown"
    }
}

struct NativeNamecoinProcessArguments {
    let mode: NativeNamecoinProcessMode
    let group: String
    let account: String
    let profilePath: String
    let profileSHA256: String
    let profileDigest: Data
    let accountPinPath: String
    let requestPath: String
    let requestSHA256: String
    let requestDigest: Data
    let queryPath: String
    let outputPath: String
    let revealValuesPinPath: String
    let adoptionPlanSHA256: String
    let timeoutSeconds: Int

    static func parse(_ argv: [String]) throws -> Self {
        guard argv.count >= 2, argv[0] == "namecoin", (argv.count - 2).isMultiple(of: 2),
              let mode = NativeNamecoinProcessMode(rawValue: argv[1]) else {
            throw NativeNamecoinProcessFailure("invalid_request")
        }
        var values: [String: String] = [:]
        var index = 2
        while index < argv.count {
            let flag = argv[index], value = argv[index + 1]
            guard flag.hasPrefix("--"), !value.isEmpty, values[flag] == nil else {
                throw NativeNamecoinProcessFailure("invalid_request")
            }
            values[flag] = value
            index += 2
        }

        var expected: Set<String> = ["--process-contract", "--group", "--account", "--profile",
                                     "--profile-sha256", "--account-pin", "--timeout-seconds"]
        switch mode {
        case .sign:
            expected.formUnion(["--request", "--request-sha256", "--output"])
            if values["--reveal-values-pin"] != nil { expected.insert("--reveal-values-pin") }
        case .reconcile:
            expected.formUnion(["--query", "--output"])
        case .initialize:
            expected.insert("--adoption-plan-sha256")
        }
        guard Set(values.keys) == expected, values["--process-contract"] == "1",
              let group = values["--group"], nativeNamecoinIdentity(group, purpose: "recovery"),
              let account = values["--account"], nativeNamecoinIdentity(account, purpose: "namecoin"),
              let profilePath = values["--profile"], nativeNamecoinAbsolutePath(profilePath),
              let profileSHA256 = values["--profile-sha256"], let profileDigest = nativeNamecoinDecodeHash(profileSHA256),
              let accountPinPath = values["--account-pin"], nativeNamecoinAbsolutePath(accountPinPath),
              let timeoutText = values["--timeout-seconds"],
              let timeout = Int(timeoutText), (1...3600).contains(timeout), String(timeout) == timeoutText else {
            throw NativeNamecoinProcessFailure("invalid_request")
        }

        var requestPath = "", requestSHA256 = "", requestDigest = Data()
        var queryPath = "", outputPath = "", revealPath = "", adoptionSHA256 = ""
        switch mode {
        case .sign:
            guard let path = values["--request"], nativeNamecoinAbsolutePath(path),
                  let hash = values["--request-sha256"], let digest = nativeNamecoinDecodeHash(hash),
                  let output = values["--output"], nativeNamecoinAbsolutePath(output) else {
                throw NativeNamecoinProcessFailure("invalid_request")
            }
            requestPath = path; requestSHA256 = hash; requestDigest = digest; outputPath = output
            if let reveal = values["--reveal-values-pin"] {
                guard nativeNamecoinAbsolutePath(reveal) else { throw NativeNamecoinProcessFailure("invalid_request") }
                revealPath = reveal
            }
        case .reconcile:
            guard let query = values["--query"], nativeNamecoinAbsolutePath(query),
                  let output = values["--output"], nativeNamecoinAbsolutePath(output) else {
                throw NativeNamecoinProcessFailure("invalid_request")
            }
            queryPath = query; outputPath = output
        case .initialize:
            guard let digest = values["--adoption-plan-sha256"], nativeNamecoinDecodeHash(digest) != nil else {
                throw NativeNamecoinProcessFailure("invalid_request")
            }
            adoptionSHA256 = digest
        }
        return Self(mode: mode, group: group, account: account, profilePath: profilePath,
                    profileSHA256: profileSHA256, profileDigest: profileDigest, accountPinPath: accountPinPath,
                    requestPath: requestPath, requestSHA256: requestSHA256, requestDigest: requestDigest,
                    queryPath: queryPath, outputPath: outputPath, revealValuesPinPath: revealPath,
                    adoptionPlanSHA256: adoptionSHA256, timeoutSeconds: timeout)
    }
}

struct NativeNamecoinProcessInputs {
    let arguments: NativeNamecoinProcessArguments
    let canonicalSelection: Data
    let accountPin: Data
    let operationInput: Data
    let selection: NativeArchiveSelection
    let journal: NativeJournalSelection
}

struct NativeNamecoinProcessResult {
    let stdout: Data
    let exitCode: Int32

    static func success(_ acknowledgement: Data) -> Self {
        Self(stdout: acknowledgement, exitCode: 0)
    }

    static func failure(_ code: String) -> Self {
        let failure = NativeNamecoinProcessFailure(code)
        let status = failure.code == "outcome_unknown" ? "UNKNOWN" : "REFUSED"
        let body = "{\"schema\":\"keyvault-namecoin-psbt-error/2\",\"code\":\"\(failure.code)\",\"status\":\"\(status)\",\"message\":\"Namecoin signing \(failure.code).\"}\n"
        let exit: Int32
        switch failure.code {
        case "invalid_request", "unsupported_psbt", "unsupported_script": exit = 2
        case "account_busy", "presence_unavailable", "outcome_unknown", "journal_unavailable", "output_unavailable": exit = 1
        default: exit = 3
        }
        return Self(stdout: Data(body.utf8), exitCode: exit)
    }
}

protocol NativeNamecoinStatusSink: AnyObject {
    func effectStarted() throws
    func nativeCompleted(resultSHA256: Data) throws
    func close() throws
}

// The current helper has no admitted source for the selected encrypted
// Namecoin recovery envelope. This boundary accepts only the already selected
// public profile and journal binding; it does not accept account-pin bytes.
protocol NativeNamecoinSealedAccountSource {
    func loadSelectedAccount(selection: NativeArchiveSelection,
                             journal: NativeJournalSelection) throws -> NativeJournalSealedAccount
}

typealias NativeNamecoinBeforeProtectedRun = () throws -> Void
typealias NativeNamecoinArchiveRunner = @MainActor (NativeNamecoinArchiveOperation, NativeJournalSealedAccount,
                                                     NativeNamecoinBeforeProtectedRun) async throws -> Data

@MainActor
struct NativeNamecoinProcessDependencies {
    let readPublicFile: (String, Int) throws -> Data
    let currentHelperCDHash: () throws -> Data
    let sealedAccountSource: (any NativeNamecoinSealedAccountSource)?
    let makeStatusSink: (Int32, Data) throws -> any NativeNamecoinStatusSink
    let runArchive: NativeNamecoinArchiveRunner

    static func live() -> Self {
        Self(readPublicFile: NativeNamecoinSafeInput.read,
             currentHelperCDHash: nativeNamecoinCurrentHelperCDHash,
             sealedAccountSource: nil,
             makeStatusSink: { descriptor, binding in try NativeNamecoinStatusWriter(descriptor: descriptor, binding: binding) },
             runArchive: { operation, sealedAccount, beforeNativeRun in
                 try await performNamecoinArchiveOperation(operation, sealedAccount: sealedAccount,
                                                           beforeNativeRun: beforeNativeRun)
             })
    }
}

@MainActor
func runNamecoinProcess1(arguments argv: [String], stdinDescriptor: Int32, resultDescriptor: Int32,
                         statusDescriptor: Int32, dependencies: NativeNamecoinProcessDependencies) async -> NativeNamecoinProcessResult {
    var effectStarted = false
    var output: NativeNamecoinPrivateOutput?
    var status: (any NativeNamecoinStatusSink)?
    defer {
        try? status?.close()
        try? output?.close()
    }

    do {
        let arguments = try NativeNamecoinProcessArguments.parse(argv)
        guard arguments.mode != .initialize else { return .failure("invalid_request") }
        try nativeNamecoinRequireEmptyStdin(stdinDescriptor)
        let inputs = try nativeNamecoinLoadInputs(arguments, dependencies: dependencies)
        if arguments.mode == .reconcile {
            // ANSWER-13 keeps reconciliation at this boundary until the exact
            // descriptor receipt and retention contract is agreed.
            return .failure("outcome_unknown")
        }

        guard let source = dependencies.sealedAccountSource else {
            throw NativeNamecoinProcessFailure("journal_unavailable")
        }
        let sealedAccount = try source.loadSelectedAccount(selection: inputs.selection, journal: inputs.journal)
        let createdOutput = try NativeNamecoinPrivateOutput(selectedDescriptor: resultDescriptor)
        output = createdOutput
        let operation = try NativeNamecoinArchiveOperation(mode: .sign,
                                                           requestOrDescriptor: inputs.operationInput,
                                                           selectedAccountPin: inputs.accountPin,
                                                           trustedCanonicalSelection: inputs.canonicalSelection,
                                                           journal: inputs.journal,
                                                           output: createdOutput)
        let binding = try nativeNamecoinStatusBinding(arguments)
        status = try dependencies.makeStatusSink(statusDescriptor, binding)
        let acknowledgement = try await dependencies.runArchive(operation, sealedAccount) {
            guard !effectStarted, let status else { throw NativeNamecoinProcessFailure("outcome_unknown") }
            try status.effectStarted()
            effectStarted = true
        }
        guard effectStarted, let status, let output else { throw NativeNamecoinProcessFailure("outcome_unknown") }
        // The bridge already closes both resources after clearing borrowed
        // account bytes. These idempotent owner closes also fail closed for an
        // injected/test runner that returns before cleanup.
        try output.close()
        let digest = try nativeNamecoinAcknowledgementDigest(acknowledgement)
        try status.nativeCompleted(resultSHA256: digest)
        try status.close()
        return .success(acknowledgement)
    } catch {
        return .failure(nativeNamecoinFailureCode(error, effectStarted: effectStarted))
    }
}

func nativeNamecoinLoadInputs(_ arguments: NativeNamecoinProcessArguments,
                                      dependencies: NativeNamecoinProcessDependencies,
                                      requestMaximum: Int = 8 << 20, psbtMaximum: Int = 4 << 20) throws -> NativeNamecoinProcessInputs {
    let profile = try dependencies.readPublicFile(arguments.profilePath, 4 << 20)
    guard Data(SHA256.hash(data: profile)) == arguments.profileDigest else {
        throw NativeNamecoinProcessFailure("policy_refused")
    }
    let helperCDHash = try dependencies.currentHelperCDHash()
    let root = try NativeArchiveJSON.decode(profile, maximum: 4 << 20, canonical: true)
    let top = try root.fields(["schema", "selection", "sidecar"])
    guard try top[0].text() == "keyvault-namecoin-native-selection/1" else {
        throw NativeNamecoinProcessFailure("policy_refused")
    }
    let selectionJSON = top[1]
    let group = try selectionJSON.field("Group").text()
    let account = try selectionJSON.field("Account").text()
    guard let publicPin = nativeNamecoinDecodeHash(try selectionJSON.field("AccountPinSHA256").text()) else {
        throw NativeNamecoinProcessFailure("account_mismatch")
    }
    let revision = try selectionJSON.field("Policy").field("revision").text()
    guard group == arguments.group, account == arguments.account else {
        throw NativeNamecoinProcessFailure("account_mismatch")
    }
    let sidecar = try nativeNamecoinEncodeSidecar(top[2], group: group, account: account,
                                                 publicPin: publicPin, revision: revision)
    let journal: NativeJournalSelection
    do {
        journal = try NativeJournalSelection(group: group, account: account, publicPin: publicPin,
                                             policy: revision, helperCDHash: helperCDHash, sidecar: sidecar)
    } catch let refusal as NativeJournalRefusal {
        throw NativeNamecoinProcessFailure(nativeNamecoinFailureCode(refusal, effectStarted: false))
    }
    let selected = try NativeArchiveSelection(canonicalJSON: profile, journal: journal)
    let pin = try dependencies.readPublicFile(arguments.accountPinPath, 32768)
    guard !pin.isEmpty, Data(SHA256.hash(data: pin)) == selected.publicPin else {
        throw NativeNamecoinProcessFailure("account_mismatch")
    }

    let operationInput: Data
    switch arguments.mode {
    case .sign:
        operationInput = try dependencies.readPublicFile(arguments.requestPath, requestMaximum)
        guard operationInput.count <= requestMaximum, Data(SHA256.hash(data: operationInput)) == arguments.requestDigest else {
            throw NativeNamecoinProcessFailure("invalid_request")
        }
        let request = try NativeArchiveRequest(operationInput, selected: selected)
        guard request.psbt.count <= psbtMaximum else { throw NativeNamecoinProcessFailure("invalid_request") }
        try nativeNamecoinValidateRevealPin(request, selection: selected, path: arguments.revealValuesPinPath,
                                            readPublicFile: dependencies.readPublicFile)
    case .reconcile:
        operationInput = try dependencies.readPublicFile(arguments.queryPath, 4096)
        try nativeNamecoinValidateReconcileQuery(operationInput)
    case .initialize:
        throw NativeNamecoinProcessFailure("invalid_request")
    }
    return NativeNamecoinProcessInputs(arguments: arguments, canonicalSelection: profile, accountPin: pin,
                                       operationInput: operationInput, selection: selected, journal: journal)
}

private func nativeNamecoinValidateRevealPin(_ request: NativeArchiveRequest, selection: NativeArchiveSelection,
                                             path: String, readPublicFile: (String, Int) throws -> Data) throws {
    let selectedPin = try selection.selection.field("RevealValuesPin")
    switch request.slot {
    case "A", "B":
        guard path.isEmpty else { throw NativeNamecoinProcessFailure("intent_mismatch") }
        if case .null = selectedPin { return }
        guard try selectedPin.base64(maximum: 1 << 20, empty: true).isEmpty else {
            throw NativeNamecoinProcessFailure("intent_mismatch")
        }
    case "C", "D":
        guard !path.isEmpty else { throw NativeNamecoinProcessFailure("intent_mismatch") }
        let supplied = try readPublicFile(path, 1 << 20)
        guard !supplied.isEmpty, try selectedPin.base64(maximum: 1 << 20) == supplied else {
            throw NativeNamecoinProcessFailure("intent_mismatch")
        }
    default:
        throw NativeNamecoinProcessFailure("invalid_request")
    }
}

private func nativeNamecoinValidateReconcileQuery(_ raw: Data) throws {
    do {
        let query = try NativeArchiveJSON.decode(raw, maximum: 4096, canonical: true)
        let fields = try query.fields(["schema", "request_id", "plan_sha256", "slot"])
        guard try fields[0].text() == "keyvault-namecoin-reconcile/2",
              let requestID = nativeNamecoinDecodeHash(try fields[1].text()), requestID.count == 32,
              let planSHA256 = nativeNamecoinDecodeHash(try fields[2].text()), planSHA256.count == 32,
              ["A", "B", "C", "D"].contains(try fields[3].text()) else {
            throw NativeNamecoinProcessFailure("invalid_request")
        }
    } catch let failure as NativeNamecoinProcessFailure {
        throw failure
    } catch {
        throw NativeNamecoinProcessFailure("invalid_request")
    }
}

private func nativeNamecoinEncodeSidecar(_ json: NativeArchiveJSON, group: String, account: String,
                                         publicPin: Data, revision: String) throws -> Data {
    let fields = try json.fields(["Binding", "NostrAccount", "GroupID", "NostrPublicPin", "MetadataHash", "PairedValueHash"])
    let binding = try fields[0].fields(["Group", "Account", "PublicPin", "Policy"])
    guard try binding[0].text() == group, try binding[1].text() == account,
          try binding[2].octets(32) == publicPin, try binding[3].text() == revision else {
        throw NativeNamecoinProcessFailure("account_mismatch")
    }
    var result = Data("KVNS1\0".utf8)
    result.append(nativeJournalLP(Data(group.utf8)))
    result.append(nativeJournalLP(Data(account.utf8)))
    result.append(publicPin)
    result.append(nativeJournalLP(Data(revision.utf8)))
    result.append(nativeJournalLP(Data(try fields[1].text().utf8)))
    result.append(try fields[2].octets(16))
    result.append(try fields[3].octets(32))
    result.append(try fields[4].octets(32))
    result.append(try fields[5].octets(32))
    return result
}

func nativeNamecoinStatusBinding(_ arguments: NativeNamecoinProcessArguments) throws -> Data {
    guard arguments.mode == .sign, arguments.profileDigest.count == 32, arguments.requestDigest.count == 32 else {
        throw NativeNamecoinProcessFailure("invalid_request")
    }
    var material = Data("keyvault-namecoin-process-observation/1\0".utf8)
    for field in [Data("sign-psbt".utf8), Data(arguments.group.utf8), Data(arguments.account.utf8),
                  arguments.profileDigest, arguments.requestDigest] {
        guard field.count <= Int(UInt32.max) else { throw NativeNamecoinProcessFailure("invalid_request") }
        var length = UInt32(field.count).bigEndian
        material.append(withUnsafeBytes(of: &length) { Data($0) })
        material.append(field)
    }
    return Data(SHA256.hash(data: material))
}

func nativeNamecoinAcknowledgementDigest(_ raw: Data) throws -> Data {
    guard !raw.isEmpty, raw.count <= 256, raw.last == 10 else {
        throw NativeNamecoinProcessFailure("outcome_unknown")
    }
    do {
        let body = try NativeArchiveJSON.decode(Data(raw.dropLast()), maximum: 255, canonical: true)
        let fields = try body.fields(["schema", "status", "result_sha256"])
        guard try fields[0].text() == "keyvault-namecoin-psbt-ack/2", try fields[1].text() == "SIGNED",
              let digest = nativeNamecoinDecodeHash(try fields[2].text()) else {
            throw NativeNamecoinProcessFailure("outcome_unknown")
        }
        return digest
    } catch {
        throw NativeNamecoinProcessFailure("outcome_unknown")
    }
}

func nativeNamecoinFailureCode(_ error: Error, effectStarted: Bool) -> String {
    if effectStarted { return "outcome_unknown" }
    if let failure = error as? NativeNamecoinProcessFailure { return failure.code }
    if let failure = error as? NativeNamecoinArchiveFailure { return failure.code }
    if let failure = error as? NativeNamecoinOutputRefusal {
        return failure == .unknown ? "outcome_unknown" : "output_unavailable"
    }
    if let failure = error as? NativeJournalRefusal {
        switch failure {
        case .missing: return "journal_unavailable"
        case .authenticationRefused: return "auth_refused"
        case .mismatch: return "account_mismatch"
        case .operational: return "journal_unavailable"
        case .unknown: return "outcome_unknown"
        }
    }
    return "invalid_request"
}

func nativeNamecoinRequireEmptyStdin(_ descriptor: Int32) throws {
    var byte: UInt8 = 0
    let count = Darwin.read(descriptor, &byte, 1)
    guard count == 0 else { throw NativeNamecoinProcessFailure("invalid_request") }
}

private func nativeNamecoinAbsolutePath(_ path: String) -> Bool {
    guard path.first == "/", path != "/", !path.utf8.contains(0) else { return false }
    let components = path.split(separator: "/", omittingEmptySubsequences: false)
    guard components.first == "", components.count > 1 else { return false }
    return components.dropFirst().allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." }
}

private func nativeNamecoinIdentity(_ value: String, purpose: String) -> Bool {
    let components = value.split(separator: "/", omittingEmptySubsequences: false)
    guard components.count == 2, (1...40).contains(components[0].utf8.count),
          components[0].utf8.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }),
          components[1].hasPrefix(purpose + "@") else { return false }
    let version = components[1].dropFirst(purpose.utf8.count + 1)
    guard let number = UInt64(version), number > 0, number <= UInt64(Int32.max), String(number) == String(version) else { return false }
    return true
}

private func nativeNamecoinDecodeHash(_ value: String) -> Data? {
    let bytes = Array(value.utf8)
    guard bytes.count == 64 else { return nil }
    var digest = Data(capacity: 32)
    for index in stride(from: 0, to: bytes.count, by: 2) {
        guard let high = nativeNamecoinHexDigit(bytes[index]), let low = nativeNamecoinHexDigit(bytes[index + 1]) else { return nil }
        digest.append((high << 4) | low)
    }
    return digest
}

private func nativeNamecoinHexDigit(_ byte: UInt8) -> UInt8? {
    switch byte {
    case 48...57: return byte - 48
    case 97...102: return byte - 87
    default: return nil
    }
}

private struct NativeNamecoinDirectory {
    let descriptor: Int32
    let parent: Int32
    let name: String
    let device: dev_t
    let inode: ino_t
}

private final class NativeNamecoinHeldPath {
    private(set) var directories: [NativeNamecoinDirectory] = []
    private(set) var closed = false
    let uid: uid_t
    let name: String

    init(path: String) throws {
        guard getuid() == geteuid(), nativeNamecoinAbsolutePath(path) else {
            throw NativeNamecoinProcessFailure("invalid_request")
        }
        uid = getuid()
        guard let last = path.split(separator: "/", omittingEmptySubsequences: false).last, !last.isEmpty else {
            throw NativeNamecoinProcessFailure("invalid_request")
        }
        name = String(last)
        var opened: [Int32] = []
        var transferred = false
        defer { if !transferred { for descriptor in opened.reversed() { _ = Darwin.close(descriptor) } } }
        let root = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { throw NativeNamecoinProcessFailure("invalid_request") }
        opened.append(root)
        try Self.requireSafeDirectory(root, uid: uid)
        var current = root
        let components = path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        let rootInfo = try Self.directoryInfo(root)
        var heldDirectories = [NativeNamecoinDirectory(descriptor: root, parent: -1, name: "",
                                                       device: rootInfo.st_dev, inode: rootInfo.st_ino)]
        for component in components.dropLast() {
            let next = component.withCString { Darwin.openat(current, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0) }
            guard next >= 0 else { throw NativeNamecoinProcessFailure("invalid_request") }
            opened.append(next)
            try Self.requireSafeDirectory(next, uid: uid)
            var held = stat(), selected = stat()
            guard fstat(next, &held) == 0,
                  component.withCString({ Darwin.fstatat(current, $0, &selected, AT_SYMLINK_NOFOLLOW) }) == 0,
                  held.st_dev == selected.st_dev, held.st_ino == selected.st_ino,
                  selected.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR) else {
                throw NativeNamecoinProcessFailure("invalid_request")
            }
            heldDirectories.append(NativeNamecoinDirectory(descriptor: next, parent: current, name: component,
                                                           device: held.st_dev, inode: held.st_ino))
            current = next
        }
        self.directories = heldDirectories
        transferred = true
    }

    deinit { close() }

    private static func directoryInfo(_ descriptor: Int32) throws -> stat {
        var value = stat()
        guard fstat(descriptor, &value) == 0 else { throw NativeNamecoinProcessFailure("invalid_request") }
        return value
    }

    private static func requireSafeDirectory(_ descriptor: Int32, uid: uid_t) throws {
        let value = try directoryInfo(descriptor)
        guard value.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              (value.st_uid == 0 || value.st_uid == uid), value.st_mode & mode_t(0o7022) == 0 else {
            throw NativeNamecoinProcessFailure("invalid_request")
        }
    }

    func parentDescriptor() throws -> Int32 {
        guard !closed, let parent = directories.last else { throw NativeNamecoinProcessFailure("invalid_request") }
        try validate()
        return parent.descriptor
    }

    func validate() throws {
        guard !closed else { throw NativeNamecoinProcessFailure("invalid_request") }
        for item in directories {
            try Self.requireSafeDirectory(item.descriptor, uid: uid)
            guard item.parent >= 0 else { continue }
            var current = stat(), path = stat()
            guard fstat(item.descriptor, &current) == 0,
                  item.name.withCString({ Darwin.fstatat(item.parent, $0, &path, AT_SYMLINK_NOFOLLOW) }) == 0,
                  current.st_dev == path.st_dev, current.st_ino == path.st_ino,
                  current.st_dev == item.device, current.st_ino == item.inode,
                  path.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR) else {
                throw NativeNamecoinProcessFailure("invalid_request")
            }
        }
    }

    func close() {
        guard !closed else { return }
        closed = true
        for item in directories.reversed() { _ = Darwin.close(item.descriptor) }
        directories.removeAll()
    }
}

enum NativeNamecoinSafeInput {
    static func read(_ path: String, _ maximum: Int) throws -> Data {
        guard maximum > 0 else { throw NativeNamecoinProcessFailure("invalid_request") }
        let held = try NativeNamecoinHeldPath(path: path)
        defer { held.close() }
        let parent = try held.parentDescriptor()
        let descriptor = held.name.withCString { Darwin.openat(parent, $0, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0) }
        guard descriptor >= 0 else { throw NativeNamecoinProcessFailure("invalid_request") }
        defer { _ = Darwin.close(descriptor) }
        var before = stat(), namedBefore = stat()
        guard fstat(descriptor, &before) == 0,
              held.name.withCString({ Darwin.fstatat(parent, $0, &namedBefore, AT_SYMLINK_NOFOLLOW) }) == 0,
              before.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG), before.st_uid == getuid(),
              before.st_mode & mode_t(0o7777) == mode_t(0o600), before.st_nlink == 1,
              before.st_size > 0, before.st_size <= off_t(maximum),
              before.st_dev == namedBefore.st_dev, before.st_ino == namedBefore.st_ino,
              namedBefore.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              fcntl(descriptor, F_GETFD) == FD_CLOEXEC else {
            throw NativeNamecoinProcessFailure("invalid_request")
        }
        var result = Data(count: Int(before.st_size))
        let total = result.count
        var offset = 0
        while offset < total {
            let count = result.withUnsafeMutableBytes { buffer in
                Darwin.pread(descriptor, buffer.baseAddress!.advanced(by: offset), total - offset, off_t(offset))
            }
            guard count > 0 else { throw NativeNamecoinProcessFailure("invalid_request") }
            offset += count
        }
        var extra: UInt8 = 0
        guard Darwin.pread(descriptor, &extra, 1, before.st_size) == 0 else {
            throw NativeNamecoinProcessFailure("invalid_request")
        }
        try held.validate()
        var after = stat(), namedAfter = stat()
        guard fstat(descriptor, &after) == 0,
              held.name.withCString({ Darwin.fstatat(parent, $0, &namedAfter, AT_SYMLINK_NOFOLLOW) }) == 0,
              after.st_dev == before.st_dev, after.st_ino == before.st_ino, after.st_size == before.st_size,
              after.st_mtimespec.tv_sec == before.st_mtimespec.tv_sec,
              after.st_mtimespec.tv_nsec == before.st_mtimespec.tv_nsec,
              after.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG), after.st_uid == getuid(),
              after.st_mode & mode_t(0o7777) == mode_t(0o600), after.st_nlink == 1,
              fcntl(descriptor, F_GETFD) == FD_CLOEXEC,
              after.st_dev == namedAfter.st_dev, after.st_ino == namedAfter.st_ino,
              namedAfter.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG) else {
            throw NativeNamecoinProcessFailure("invalid_request")
        }
        return result
    }
}

private func nativeNamecoinCurrentHelperCDHash() throws -> Data {
    var code: SecCode?
    guard SecCodeCopySelf(SecCSFlags(rawValue: 0), &code) == errSecSuccess, let running = code,
          SecCodeCheckValidity(running, SecCSFlags(rawValue: kSecCSStrictValidate), nil) == errSecSuccess else {
        throw NativeNamecoinProcessFailure("helper_not_admitted")
    }
    var information: CFDictionary?
    guard copyRunningCodeSigningInformation(running,
                                            SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSDynamicInformation),
                                            &information) == errSecSuccess,
          let facts = information as? [String: Any], let hash = facts[kSecCodeInfoUnique as String] as? Data,
          hash.count == 20 || hash.count == 32 else {
        throw NativeNamecoinProcessFailure("helper_not_admitted")
    }
    return hash
}

final class NativeNamecoinStatusWriter: NativeNamecoinStatusSink {
    private enum Phase: Equatable { case ready, started, completed, failed, closed }
    private let binding: Data
    private var descriptor: Int32?
    private var phase = Phase.ready

    init(descriptor: Int32, binding: Data) throws {
        var status = stat()
        let flags = fcntl(descriptor, F_GETFD)
        guard binding.count == 32, descriptor >= 3, flags >= 0, flags & ~FD_CLOEXEC == 0,
              fstat(descriptor, &status) == 0, status.st_mode & mode_t(S_IFMT) == mode_t(S_IFIFO),
              fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) == 0, fcntl(descriptor, F_GETFD) == FD_CLOEXEC else {
            throw NativeNamecoinProcessFailure("helper_not_admitted")
        }
        self.descriptor = descriptor
        self.binding = binding
    }

    func effectStarted() throws {
        guard phase == .ready else { throw NativeNamecoinProcessFailure("outcome_unknown") }
        try write(event: 1, digest: Data(repeating: 0, count: 32))
        phase = .started
    }

    func nativeCompleted(resultSHA256: Data) throws {
        guard phase == .started, resultSHA256.count == 32 else {
            throw NativeNamecoinProcessFailure("outcome_unknown")
        }
        try write(event: 2, digest: resultSHA256)
        phase = .completed
    }

    private func write(event: UInt8, digest: Data) throws {
        guard let descriptor, digest.count == 32 else { throw NativeNamecoinProcessFailure("outcome_unknown") }
        var frame = Data(repeating: 0, count: 80)
        frame.replaceSubrange(0..<4, with: Data("KVNS".utf8))
        frame[4] = 0; frame[5] = 1; frame[6] = event
        frame.replaceSubrange(8..<40, with: binding)
        frame.replaceSubrange(40..<72, with: digest)
        let count = frame.withUnsafeBytes { Darwin.write(descriptor, $0.baseAddress!, 80) }
        guard count == 80 else { phase = .failed; throw NativeNamecoinProcessFailure("outcome_unknown") }
    }

    func close() throws {
        guard let descriptor else { return }
        self.descriptor = nil
        phase = .closed
        guard Darwin.close(descriptor) == 0 else { throw NativeNamecoinProcessFailure("outcome_unknown") }
    }
}
