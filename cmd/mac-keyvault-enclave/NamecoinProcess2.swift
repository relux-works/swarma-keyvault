import CryptoKit
import Darwin
import Foundation

extension NativeNamecoinProcessArguments {
    // Process/1 parsing remains closed and unchanged. Version2 admits sign only,
    // with exactly one canonical selector and the existing flag grammar.
    static func parse2(_ argv: [String]) throws -> Self {
        guard argv.count >= 2, argv[1] == "sign-psbt", (argv.count - 2).isMultiple(of: 2) else {
            throw NativeNamecoinProcessFailure("invalid_request")
        }
        var canonical = argv
        var selectors = 0
        for index in stride(from: 2, to: argv.count, by: 2) where argv[index] == "--process-contract" {
            selectors += 1
            guard argv[index + 1] == "2" else { throw NativeNamecoinProcessFailure("invalid_request") }
            canonical[index + 1] = "1"
        }
        guard selectors == 1 else { throw NativeNamecoinProcessFailure("invalid_request") }
        return try parse(canonical)
    }
}

@MainActor
func runNamecoinProcess(arguments argv: [String], stdinDescriptor: Int32, resultDescriptor: Int32,
                        statusDescriptor: Int32, dependencies: NativeNamecoinProcessDependencies) async -> NativeNamecoinProcessResult {
    // A selector value is inspected only for routing. Each destination performs
    // its own closed parse; a malformed version2 never falls back to version1.
    let selects2 = argv.indices.contains { index in
        argv[index] == "--process-contract" && index + 1 < argv.count && argv[index + 1] == "2"
    }
    if selects2 {
        return await runNamecoinProcess2(arguments: argv, stdinDescriptor: stdinDescriptor,
                                         resultDescriptor: resultDescriptor, statusDescriptor: statusDescriptor,
                                         custodyDescriptor: 5, dependencies: dependencies)
    }
    return await runNamecoinProcess1(arguments: argv, stdinDescriptor: stdinDescriptor,
                                     resultDescriptor: resultDescriptor, statusDescriptor: statusDescriptor,
                                     dependencies: dependencies)
}

struct NativeNamecoinProcess2Frame {
    static let maximumMetadata = 34816
    static let envelopeFixed = 288
    static let maximumEnvelope = envelopeFixed + 16384
    static let maximum = 14 + maximumMetadata + maximumEnvelope
    let service: Data
    let physicalAccount: Data
    let publicPin: Data
    let sidecar: Data
    let record: Data
    let blob: Data
    let point: Data
    let ciphertext: Data
    let binding: Data

    init(_ raw: Data) throws {
        do {
            guard raw.count <= Self.maximum else { throw NativeNamecoinProcessFailure("invalid_request") }
            var outer = NativeArchiveCursor(bytes: raw)
            try outer.require(Data("KVCY1\0".utf8))
            let metadataLength = try outer.uint(4), envelopeLength = try outer.uint(4)
            guard (54...UInt64(Self.maximumMetadata)).contains(metadataLength),
                  (UInt64(Self.envelopeFixed + 1)...UInt64(Self.maximumEnvelope)).contains(envelopeLength),
                  UInt64(raw.count) == 14 + metadataLength + envelopeLength else {
                throw NativeNamecoinProcessFailure("invalid_request")
            }
            var metadata = NativeArchiveCursor(bytes: try outer.take(Int(metadataLength)))
            var envelope = NativeArchiveCursor(bytes: try outer.take(Int(envelopeLength)))
            try outer.requireEnd()
            try metadata.require(Data("KVMD1\0".utf8))
            func shortField(_ cursor: inout NativeArchiveCursor, maximum: Int) throws -> Data {
                let length = try cursor.uint(2)
                guard (1...UInt64(maximum)).contains(length) else { throw NativeNamecoinProcessFailure("invalid_request") }
                return try cursor.take(Int(length))
            }
            service = try shortField(&metadata, maximum: 128)
            physicalAccount = try shortField(&metadata, maximum: 256)
            publicPin = try metadata.take(32)
            sidecar = try metadata.blob(640)
            record = try metadata.blob(32768)
            guard !sidecar.isEmpty, !record.isEmpty else { throw NativeNamecoinProcessFailure("invalid_request") }
            try metadata.requireEnd()
            try envelope.require(Data("KVNE1\0".utf8))
            blob = try envelope.blob(16384)
            guard !blob.isEmpty else { throw NativeNamecoinProcessFailure("invalid_request") }
            point = try envelope.take(65)
            ciphertext = try envelope.take(181)
            binding = try envelope.take(32)
            try envelope.requireEnd()
        } catch { throw NativeNamecoinProcessFailure("invalid_request") }
    }

    // The vault validates the complete pair and its hash before projection. The
    // helper checks the retained public profile/record and projected envelope;
    // it has neither a paired-item source nor the Nostr envelope.
    func selectedAccount(_ inputs: NativeNamecoinProcessInputs) throws -> NativeJournalSealedAccount {
        do {
            guard service == Data("works.relux.mac-keyvault.nostr.v1".utf8),
                  physicalAccount == Data(inputs.journal.group.utf8), publicPin == inputs.journal.publicPin,
                  sidecar == inputs.journal.sidecar else { throw NativeJournalRefusal.mismatch }
            let profile = try NativeArchiveJSON.decode(inputs.canonicalSelection, maximum: 4 << 20, canonical: true)
            let linked = try profile.field("sidecar")
            guard try linked.field("MetadataHash").octets(32) == Data(SHA256.hash(data: record)) else {
                throw NativeJournalRefusal.mismatch
            }
            let root = try NativeArchiveJSON.decode(record, maximum: 32768, canonical: true)
            let fields = try root.fields(["schema", "group_id", "service", "version", "created", "nostr", "namecoin"])
            let schema = try fields[0].text(), groupService = try fields[2].text(), groupVersion = try fields[3].uint()
            guard ["keyvault-recovery/1", "keyvault-recovery/2"].contains(schema),
                  groupVersion > 0, groupVersion <= UInt64(Int32.max),
                  "\(groupService)/recovery@\(groupVersion)" == inputs.journal.group,
                  try nativeArchiveUnhex(fields[1].text(), count: 16) == linked.field("GroupID").octets(16) else {
                throw NativeJournalRefusal.mismatch
            }
            let purposeFields = ["purpose", "version", "path", "algorithm", "presence", "public_key", "npub", "xpub", "origin", "wrapping_point", "wrapping_fingerprint"]
            let names = schema == "keyvault-recovery/2" ? ["service"] + purposeFields : purposeFields
            let nostr = try fields[5].fields(names), namecoin = try fields[6].fields(names)
            let offset = schema == "keyvault-recovery/2" ? 1 : 0
            let namecoinService = offset == 1 ? try namecoin[0].text() : groupService
            let nostrService = offset == 1 ? try nostr[0].text() : groupService
            let namecoinVersion = try namecoin[offset + 1].uint(), nostrVersion = try nostr[offset + 1].uint()
            guard namecoinVersion > 0, namecoinVersion <= UInt64(Int32.max), nostrVersion > 0, nostrVersion <= UInt64(Int32.max),
                  nostrService == groupService,
                  "\(namecoinService)/namecoin@\(namecoinVersion)" == inputs.journal.account,
                  "\(nostrService)/nostr@\(nostrVersion)" == inputs.journal.nostrAccount,
                  try namecoin[offset].text() == "namecoin", try namecoin[offset + 2].text() == "m/84'/7'/0'",
                  try namecoin[offset + 3].text() == "bip32-secp256k1", try namecoin[offset + 4].text() == "biometry-any",
                  try namecoin[offset + 5].text().isEmpty, try namecoin[offset + 6].text().isEmpty,
                  try nostr[offset].text() == "nostr", try nostr[offset + 2].text() == "m/44'/1237'/0'/0/0",
                  try nostr[offset + 3].text() == "secp256k1-bip340", try nostr[offset + 4].text() == "none",
                  try nostr[offset + 7].text().isEmpty, try nostr[offset + 8].text().isEmpty,
                  try nativeArchiveUnhex(nostr[offset + 5].text(), count: 32) == linked.field("NostrPublicPin").octets(32) else {
                throw NativeJournalRefusal.mismatch
            }
            let pin = try NativeArchiveJSON.decode(inputs.accountPin, maximum: 32768, canonical: true)
            _ = try pin.fields(["schema", "group", "account", "account_xpub", "master_fingerprint", "account_path"])
            guard try pin.field("schema").text() == "keyvault-namecoin-account-pin/1",
                  try pin.field("group").text() == inputs.journal.group,
                  try pin.field("account").text() == inputs.journal.account else { throw NativeJournalRefusal.mismatch }
            guard try pin.field("account_xpub").text() == namecoin[offset + 7].text(),
                  try namecoin[offset + 8].text() == "[" + pin.field("master_fingerprint").text() + "/84h/7h/0h]",
                  try pin.field("account_path").text() == "m/84h/7h/0h" else { throw NativeJournalRefusal.mismatch }
            for purpose in [nostr, namecoin] {
                let wrappingPoint = try purpose[offset + 9].base64(maximum: 65)
                _ = try P256.KeyAgreement.PublicKey(x963Representation: wrappingPoint)
                guard wrappingPoint.count == 65,
                      try nativeArchiveUnhex(purpose[offset + 10].text(), count: 32) == Data(SHA256.hash(data: wrappingPoint)) else {
                    throw NativeJournalRefusal.mismatch
                }
            }
            guard try namecoin[offset + 9].base64(maximum: 65) == point,
                  try nostr[offset + 9].base64(maximum: 65) != point else { throw NativeJournalRefusal.mismatch }
            let domain = schema == "keyvault-recovery/2" ? "works.relux.mac-keyvault.recovery-envelope.v2" : "works.relux.mac-keyvault.recovery-envelope.v1"
            var preimage = Data()
            for part in [domain, "works.relux.mac-keyvault.namecoin-wrap.v1", inputs.journal.group, "namecoin", inputs.journal.account] {
                preimage.append(Data(part.utf8)); preimage.append(0)
            }
            preimage.append(record); preimage.append(0); preimage.append(point)
            guard Data(SHA256.hash(data: preimage)) == binding else { throw NativeJournalRefusal.mismatch }
            return try NativeJournalSealedAccount(enclaveBlob: blob, wrappingPoint: point, ciphertext: ciphertext, expectedBinding: binding)
        } catch { throw NativeNamecoinProcessFailure("account_mismatch") }
    }
}

// Bounded bytes and a monotonic deadline, including the final EOF. No allocation
// uses an unvalidated wire length. Parent death closes the sole pipe writer.
func nativeNamecoinReadCustody(_ descriptor: Int32, deadline: UInt64) throws -> Data {
    var info = stat()
    let flags = fcntl(descriptor, F_GETFL)
    guard descriptor >= 3, fstat(descriptor, &info) == 0, info.st_mode & mode_t(S_IFMT) == mode_t(S_IFIFO),
          flags >= 0, flags & O_ACCMODE == O_RDONLY, fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0 else {
        throw NativeNamecoinProcessFailure("invalid_request")
    }
    var result = Data()
    while true {
        let now = DispatchTime.now().uptimeNanoseconds
        guard now < deadline else { throw NativeNamecoinProcessFailure("request_expired") }
        let milliseconds = min(UInt64(Int32.max), max(1, (deadline - now) / 1_000_000))
        var watched = pollfd(fd: descriptor, events: Int16(POLLIN | POLLHUP), revents: 0)
        let ready = Darwin.poll(&watched, 1, Int32(milliseconds))
        if ready < 0 && errno == EINTR { continue }
        if ready == 0 { throw NativeNamecoinProcessFailure("request_expired") }
        guard ready > 0, watched.revents & Int16(POLLERR | POLLNVAL) == 0 else {
            throw NativeNamecoinProcessFailure("invalid_request")
        }
        var buffer = [UInt8](repeating: 0, count: min(4096, NativeNamecoinProcess2Frame.maximum + 1 - result.count))
        let count = buffer.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress!, $0.count) }
        if count < 0 && errno == EINTR { continue }
        guard count >= 0 else { throw NativeNamecoinProcessFailure("invalid_request") }
        if count == 0 { return result }
        result.append(contentsOf: buffer.prefix(count))
        guard result.count <= NativeNamecoinProcess2Frame.maximum else { throw NativeNamecoinProcessFailure("invalid_request") }
    }
}

@MainActor
func runNamecoinProcess2(arguments argv: [String], stdinDescriptor: Int32, resultDescriptor: Int32,
                         statusDescriptor: Int32, custodyDescriptor: Int32,
                         dependencies: NativeNamecoinProcessDependencies) async -> NativeNamecoinProcessResult {
    var effectStarted = false
    var output: NativeNamecoinPrivateOutput?
    var status: (any NativeNamecoinStatusSink)?
    var custodyClosed = false
    defer {
        if !custodyClosed { _ = Darwin.close(custodyDescriptor) }
        try? status?.close(); try? output?.close()
    }
    do {
        let arguments = try NativeNamecoinProcessArguments.parse2(argv)
        let deadline = DispatchTime.now().uptimeNanoseconds + UInt64(arguments.timeoutSeconds) * 1_000_000_000
        try nativeNamecoinRequireEmptyStdin(stdinDescriptor)
        let inputs = try nativeNamecoinLoadInputs(arguments, dependencies: dependencies, requestMaximum: 2 << 20, psbtMaximum: 1 << 20)
        let raw = try nativeNamecoinReadCustody(custodyDescriptor, deadline: deadline)
        let closeResult = Darwin.close(custodyDescriptor)
        custodyClosed = true
        guard closeResult == 0 else { throw NativeNamecoinProcessFailure("invalid_request") }
        let account = try NativeNamecoinProcess2Frame(raw).selectedAccount(inputs)
        let createdOutput = try NativeNamecoinPrivateOutput(selectedDescriptor: resultDescriptor)
        output = createdOutput
        let operation = try NativeNamecoinArchiveOperation(mode: .sign, requestOrDescriptor: inputs.operationInput,
            selectedAccountPin: inputs.accountPin, trustedCanonicalSelection: inputs.canonicalSelection,
            journal: inputs.journal, output: createdOutput)
        status = try dependencies.makeStatusSink(statusDescriptor, nativeNamecoinStatusBinding(arguments))
        let acknowledgement = try await dependencies.runArchive(operation, account) {
            guard !effectStarted, let status else { throw NativeNamecoinProcessFailure("outcome_unknown") }
            guard DispatchTime.now().uptimeNanoseconds < deadline else { throw NativeNamecoinProcessFailure("request_expired") }
            try status.effectStarted()
            effectStarted = true
        }
        guard effectStarted, let status, let output else { throw NativeNamecoinProcessFailure("outcome_unknown") }
        try output.close()
        try status.nativeCompleted(resultSHA256: nativeNamecoinAcknowledgementDigest(acknowledgement))
        try status.close()
        return .success(acknowledgement)
    } catch {
        return .failure(nativeNamecoinFailureCode(error, effectStarted: effectStarted))
    }
}
