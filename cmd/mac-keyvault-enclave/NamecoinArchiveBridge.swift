import Foundation
import Darwin
import CryptoKit
import NamecoinArchiveABI

// Internal consumer of the generated libkeyvault_namecoin.h. The build owner
// must import that actual header and link its matching archive. No C declarations,
// public dispatcher, caller approval flag, private return, or fallback lives here.
struct NativeNamecoinArchiveFailure: Error, Equatable {
    let code: String
    static let codes = ["invalid_request", "unsupported_psbt", "unsupported_script", "display_refused",
                        "account_mismatch", "path_refused", "prevout_mismatch", "intent_mismatch",
                        "sighash_refused", "fee_refused", "request_expired", "replay_refused",
                        "account_busy", "auth_refused", "presence_unavailable", "adoption_required",
                        "helper_not_admitted", "policy_refused", "outcome_unknown",
                        "journal_unavailable", "output_unavailable"]
    init(_ code: String) { self.code = Self.codes.contains(code) ? code : "outcome_unknown" }
    static func abi(_ code: Int32) -> Self? {
        if code == Int32(KV_NMC_OK) { return nil }
        switch code {
        case Int32(KV_NMC_INVALID_REQUEST): return Self("invalid_request")
        case Int32(KV_NMC_UNSUPPORTED_PSBT): return Self("unsupported_psbt")
        case Int32(KV_NMC_UNSUPPORTED_SCRIPT): return Self("unsupported_script")
        case Int32(KV_NMC_DISPLAY_REFUSED): return Self("display_refused")
        case Int32(KV_NMC_ACCOUNT_MISMATCH): return Self("account_mismatch")
        case Int32(KV_NMC_PATH_REFUSED): return Self("path_refused")
        case Int32(KV_NMC_PREVOUT_MISMATCH): return Self("prevout_mismatch")
        case Int32(KV_NMC_INTENT_MISMATCH): return Self("intent_mismatch")
        case Int32(KV_NMC_SIGHASH_REFUSED): return Self("sighash_refused")
        case Int32(KV_NMC_FEE_REFUSED): return Self("fee_refused")
        case Int32(KV_NMC_REQUEST_EXPIRED): return Self("request_expired")
        case Int32(KV_NMC_REPLAY_REFUSED): return Self("replay_refused")
        case Int32(KV_NMC_ACCOUNT_BUSY): return Self("account_busy")
        case Int32(KV_NMC_AUTH_REFUSED): return Self("auth_refused")
        case Int32(KV_NMC_PRESENCE_UNAVAILABLE): return Self("presence_unavailable")
        case Int32(KV_NMC_ADOPTION_REQUIRED): return Self("adoption_required")
        case Int32(KV_NMC_HELPER_NOT_ADMITTED): return Self("helper_not_admitted")
        case Int32(KV_NMC_POLICY_REFUSED): return Self("policy_refused")
        case Int32(KV_NMC_OUTCOME_UNKNOWN): return Self("outcome_unknown")
        case Int32(KV_NMC_JOURNAL_UNAVAILABLE): return Self("journal_unavailable")
        case Int32(KV_NMC_OUTPUT_UNAVAILABLE): return Self("output_unavailable")
        default: return Self("outcome_unknown")
        }
    }
    static func map(_ error: Error) -> Self {
        if let error = error as? Self { return error }
        if let error = error as? NativeNamecoinOutputRefusal {
            return Self(error == .unknown ? "outcome_unknown" : "output_unavailable")
        }
        if let error = error as? NativeJournalRefusal {
            switch error {
            case .authenticationRefused: return Self("auth_refused")
            case .mismatch: return Self("account_mismatch")
            case .missing, .operational: return Self("journal_unavailable")
            case .unknown: return Self("outcome_unknown")
            }
        }
        if let error = error as? HelperError {
            switch error.code {
            case "document_display": return Self("display_refused")
            case "auth_refused", "user_canceled", "auth_failed", "presence_failed": return Self("auth_refused")
            case "presence_required", "presence_unavailable", "enclave_unavailable": return Self("presence_unavailable")
            default: return Self("outcome_unknown")
            }
        }
        return Self("outcome_unknown")
    }
}

// Finite public-format decoder only, not a PSBT parser or an authority source.
// Preserve order for the generated Go documents, reject duplicate keys, and
// require unsigned integer syntax without floating-point loss of UInt64 fees.
indirect enum NativeArchiveJSON {
    case object([(String, NativeArchiveJSON)])
    case array([NativeArchiveJSON])
    case string(String)
    case number(UInt64)
    case null

    func fields(_ names: [String], ordered: Bool = true) throws -> [NativeArchiveJSON] {
        guard case .object(let pairs) = self, pairs.count == names.count,
              Set(pairs.map { $0.0 }) == Set(names),
              !ordered || pairs.map({ $0.0 }) == names else { throw NativeNamecoinArchiveFailure("display_refused") }
        return try names.map { name in
            guard let value = pairs.first(where: { $0.0 == name })?.1 else { throw NativeNamecoinArchiveFailure("display_refused") }
            return value
        }
    }
    func field(_ name: String) throws -> NativeArchiveJSON {
        guard case .object(let pairs) = self, let value = pairs.first(where: { $0.0 == name })?.1 else {
            throw NativeNamecoinArchiveFailure("display_refused")
        }
        return value
    }
    func text() throws -> String {
        guard case .string(let value) = self else { throw NativeNamecoinArchiveFailure("display_refused") }
        return value
    }
    func uint() throws -> UInt64 {
        guard case .number(let value) = self else { throw NativeNamecoinArchiveFailure("display_refused") }
        return value
    }
    func list() throws -> [NativeArchiveJSON] {
        guard case .array(let value) = self else { throw NativeNamecoinArchiveFailure("display_refused") }
        return value
    }
    func base64(maximum: Int, empty: Bool = false) throws -> Data {
        let encoded = try text()
        guard let bytes = Data(base64Encoded: encoded), bytes.count <= maximum,
              empty || !bytes.isEmpty, bytes.base64EncodedString() == encoded else {
            throw NativeNamecoinArchiveFailure("display_refused")
        }
        return bytes
    }
    func octets(_ count: Int) throws -> Data {
        let values = try list()
        guard values.count == count else { throw NativeNamecoinArchiveFailure("account_mismatch") }
        return try Data(values.map { value in
            let byte = try value.uint()
            guard byte <= 255 else { throw NativeNamecoinArchiveFailure("account_mismatch") }
            return UInt8(byte)
        })
    }
    func canonical() throws -> Data {
        func quote(_ text: String) throws -> String {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.withoutEscapingSlashes]
            var value = String(decoding: try encoder.encode(text), as: UTF8.self)
            for (source, target) in [("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"),
                                     ("\u{2028}", "\\u2028"), ("\u{2029}", "\\u2029")] {
                value = value.replacingOccurrences(of: source, with: target)
            }
            return value
        }
        let value: String
        switch self {
        case .null: value = "null"
        case .number(let number): value = String(number)
        case .string(let text): value = try quote(text)
        case .array(let values):
            value = "[" + (try values.map { String(decoding: try $0.canonical(), as: UTF8.self) }).joined(separator: ",") + "]"
        case .object(let values):
            value = "{" + (try values.map { try quote($0.0) + ":" + String(decoding: $0.1.canonical(), as: UTF8.self) }).joined(separator: ",") + "}"
        }
        return Data(value.utf8)
    }

    static func decode(_ raw: Data, maximum: Int, canonical: Bool) throws -> Self {
        guard !raw.isEmpty, raw.count <= maximum else { throw NativeNamecoinArchiveFailure("display_refused") }
        var parser = NativeArchiveJSONReader(bytes: Array(raw))
        let value = try parser.value(depth: 0)
        parser.space()
        guard parser.offset == parser.bytes.count else { throw NativeNamecoinArchiveFailure("display_refused") }
        if canonical, try value.canonical() != raw { throw NativeNamecoinArchiveFailure("display_refused") }
        return value
    }
}

private struct NativeArchiveJSONReader {
    let bytes: [UInt8]
    var offset = 0
    mutating func space() { while offset < bytes.count && [UInt8(9), 10, 13, 32].contains(bytes[offset]) { offset += 1 } }
    mutating func take(_ byte: UInt8) throws {
        space()
        guard offset < bytes.count, bytes[offset] == byte else { throw NativeNamecoinArchiveFailure("display_refused") }
        offset += 1
    }
    mutating func string() throws -> String {
        space()
        let start = offset
        try take(34)
        while offset < bytes.count {
            let byte = bytes[offset]
            offset += 1
            if byte == 34 {
                do { return try JSONDecoder().decode(String.self, from: Data(bytes[start..<offset])) }
                catch { throw NativeNamecoinArchiveFailure("display_refused") }
            }
            guard byte >= 32 else { throw NativeNamecoinArchiveFailure("display_refused") }
            if byte == 92 { offset += 1 }
        }
        throw NativeNamecoinArchiveFailure("display_refused")
    }
    mutating func value(depth: Int) throws -> NativeArchiveJSON {
        space()
        guard depth < 16, offset < bytes.count else { throw NativeNamecoinArchiveFailure("display_refused") }
        switch bytes[offset] {
        case 34: return .string(try string())
        case 123:
            offset += 1; space()
            var pairs: [(String, NativeArchiveJSON)] = []
            var keys = Set<String>()
            if offset < bytes.count && bytes[offset] == 125 { offset += 1; return .object(pairs) }
            while true {
                guard pairs.count < 64 else { throw NativeNamecoinArchiveFailure("display_refused") }
                let key = try string()
                guard keys.insert(key).inserted else { throw NativeNamecoinArchiveFailure("display_refused") }
                try take(58)
                pairs.append((key, try value(depth: depth + 1)))
                space()
                guard offset < bytes.count else { throw NativeNamecoinArchiveFailure("display_refused") }
                if bytes[offset] == 125 { offset += 1; return .object(pairs) }
                try take(44)
            }
        case 91:
            offset += 1; space()
            var values: [NativeArchiveJSON] = []
            if offset < bytes.count && bytes[offset] == 93 { offset += 1; return .array(values) }
            while true {
                guard values.count < 2048 else { throw NativeNamecoinArchiveFailure("display_refused") }
                values.append(try value(depth: depth + 1)); space()
                guard offset < bytes.count else { throw NativeNamecoinArchiveFailure("display_refused") }
                if bytes[offset] == 93 { offset += 1; return .array(values) }
                try take(44)
            }
        case 110:
            guard bytes.count - offset >= 4, Array(bytes[offset..<offset + 4]) == Array("null".utf8) else { throw NativeNamecoinArchiveFailure("display_refused") }
            offset += 4; return .null
        case 48...57:
            let start = offset
            while offset < bytes.count && (48...57).contains(bytes[offset]) { offset += 1 }
            let digits = String(decoding: bytes[start..<offset], as: UTF8.self)
            guard let number = UInt64(digits), String(number) == digits else { throw NativeNamecoinArchiveFailure("display_refused") }
            return .number(number)
        default: throw NativeNamecoinArchiveFailure("display_refused")
        }
    }
}

func nativeArchiveHex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
func nativeArchiveUnhex(_ text: String, count: Int? = nil) throws -> Data {
    let bytes = Array(text.utf8)
    guard bytes.count % 2 == 0, count == nil || bytes.count == count! * 2,
          bytes.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
        throw NativeNamecoinArchiveFailure("display_refused")
    }
    var result = Data()
    for index in stride(from: 0, to: bytes.count, by: 2) {
        func digit(_ byte: UInt8) -> UInt8 { byte <= 57 ? byte - 48 : byte - 87 }
        result.append((digit(bytes[index]) << 4) | digit(bytes[index + 1]))
    }
    return result
}

struct NativeArchiveSelection {
    let raw: Data
    let selection: NativeArchiveJSON
    let policy: NativeArchiveJSON
    let group: String
    let account: String
    let network: String
    let genesis: Data
    let publicPin: Data
    let revision: String
    let feeCap: UInt64

    // Provenance is the trusted local caller's obligation. Parsing this public
    // Go canonicalJSON is not setup authority, owner consent, or a presence token.
    init(canonicalJSON: Data, journal: NativeJournalSelection) throws {
        do {
            let owned = nativeJournalOwnedPublicData(canonicalJSON)
            let config = try NativeArchiveJSON.decode(owned, maximum: 4 << 20, canonical: true)
            let top = try config.fields(["schema", "selection", "sidecar"])
            guard try top[0].text() == "keyvault-namecoin-native-selection/1" else { throw NativeNamecoinArchiveFailure("policy_refused") }
            let values = try top[1].fields(["Network", "Genesis", "Group", "Account", "AccountPinSHA256", "Policy", "RevealValuesPin"])
            let policyValues = try values[5].fields(["revision", "per_tx_fee_cap_atoms", "total_fee_cap_atoms", "min_fee_rate_atoms_per_kvb", "max_fee_rate_atoms_per_kvb", "dust_relay_fee_atoms_per_kvb", "created_at", "release_not_after", "final_confirmations", "release_mode"])
            let selectedGroup = try values[2].text(), selectedAccount = try values[3].text()
            let pin = try nativeArchiveUnhex(values[4].text(), count: 32)
            let policyRevision = try policyValues[0].text()
            guard selectedGroup == journal.group, selectedAccount == journal.account,
                  pin == journal.publicPin, policyRevision == journal.policy else { throw NativeNamecoinArchiveFailure("account_mismatch") }
            let sidecar = try top[2].fields(["Binding", "NostrAccount", "GroupID", "NostrPublicPin", "MetadataHash", "PairedValueHash"])
            let binding = try sidecar[0].fields(["Group", "Account", "PublicPin", "Policy"])
            guard try binding[0].text() == selectedGroup, try binding[1].text() == selectedAccount,
                  try binding[2].octets(32) == pin, try binding[3].text() == policyRevision else { throw NativeNamecoinArchiveFailure("account_mismatch") }
            var encoded = Data("KVNS1\0".utf8)
            encoded.append(nativeJournalLP(Data(selectedGroup.utf8)))
            encoded.append(nativeJournalLP(Data(selectedAccount.utf8)))
            encoded.append(pin)
            encoded.append(nativeJournalLP(Data(policyRevision.utf8)))
            encoded.append(nativeJournalLP(Data(try sidecar[1].text().utf8)))
            for (index, size) in [(2, 16), (3, 32), (4, 32), (5, 32)] { encoded.append(try sidecar[index].octets(size)) }
            guard encoded == journal.sidecar else { throw NativeNamecoinArchiveFailure("account_mismatch") }
            let network = try values[0].text()
            guard ["namecoin-mainnet", "namecoin-regtest"].contains(network),
                  let cap = UInt64(try policyValues[1].text()), String(cap) == (try policyValues[1].text()) else { throw NativeNamecoinArchiveFailure("policy_refused") }
            // Validate every policy field's wire type; Go owns its actual policy
            // admission, time, amount, PSBT and account-public derivation checks.
            for index in 1...5 {
                let text = try policyValues[index].text()
                guard let value = UInt64(text), String(value) == text else { throw NativeNamecoinArchiveFailure("policy_refused") }
            }
            _ = try policyValues[6].uint(); _ = try policyValues[7].uint()
            guard try policyValues[8].uint() <= UInt64(UInt32.max) else { throw NativeNamecoinArchiveFailure("policy_refused") }
            _ = try policyValues[9].text()
            if case .null = values[6] {} else { _ = try values[6].base64(maximum: 2 << 20, empty: true) }
            raw = owned
            selection = top[1]; policy = values[5]
            group = selectedGroup; account = selectedAccount; self.network = network
            genesis = try nativeArchiveUnhex(values[1].text(), count: 32)
            publicPin = pin; revision = policyRevision; feeCap = cap
        } catch let failure as NativeNamecoinArchiveFailure { throw failure }
        catch { throw NativeNamecoinArchiveFailure("policy_refused") }
    }
}

struct NativeArchiveCursor {
    let bytes: Data
    var offset = 0
    mutating func take(_ count: Int) throws -> Data {
        guard count >= 0, offset <= bytes.count, count <= bytes.count - offset else { throw NativeNamecoinArchiveFailure("display_refused") }
        let result = bytes.subdata(in: offset..<offset + count)
        offset += count
        return result
    }
    mutating func uint(_ count: Int) throws -> UInt64 { try take(count).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) } }
    mutating func blob(_ maximum: Int) throws -> Data {
        let length = try uint(4)
        guard length <= UInt64(maximum) else { throw NativeNamecoinArchiveFailure("display_refused") }
        return try take(Int(length))
    }
    mutating func require(_ expected: Data) throws {
        guard try take(expected.count) == expected else { throw NativeNamecoinArchiveFailure("display_refused") }
    }
    func requireEnd() throws {
        guard offset == bytes.count else { throw NativeNamecoinArchiveFailure("display_refused") }
    }
}

enum NativeNamecoinArchiveMode: Int32 { case sign = 1, reconcile = 2 }

struct NativeArchiveRequest {
    let value: NativeArchiveJSON
    let intent: NativeArchiveJSON
    let manifest: NativeArchiveJSON
    let psbt: Data
    let slot: String
    let operation: NamecoinReviewOperation
    let name: Data
    let finalValue: Data
    let randomness: Data
    let selectedFee: UInt64

    init(_ raw: Data, selected: NativeArchiveSelection) throws {
        let value = try NativeArchiveJSON.decode(raw, maximum: 8 << 20, canonical: false)
        let fields = try value.fields(["schema", "request_id", "sitting_id", "slot", "network", "expires_at", "psbt", "plan_manifest_utf8", "plan_sha256", "reservation_plan_sha256", "intent"], ordered: false)
        guard try fields[0].text() == "keyvault-namecoin-psbt/2", try fields[4].text() == selected.network else { throw NativeNamecoinArchiveFailure("intent_mismatch") }
        let slot = try fields[3].text()
        guard ["A", "B", "C", "D"].contains(slot) else { throw NativeNamecoinArchiveFailure("invalid_request") }
        for index in [1, 2, 8, 9] { _ = try nativeArchiveUnhex(fields[index].text(), count: 32) }
        _ = try fields[5].uint()
        let psbt = try fields[6].base64(maximum: 4 << 20)
        guard psbt.starts(with: Data([0x70, 0x73, 0x62, 0x74, 0xff])) else { throw NativeNamecoinArchiveFailure("unsupported_psbt") }
        let manifestBytes = Data(try fields[7].text().utf8)
        var commitment = Data("swarma-identity/namecoin-registration-plan/2\0".utf8)
        commitment.append(nativeJournalLP(manifestBytes))
        guard nativeArchiveHex(Data(SHA256.hash(data: commitment))) == (try fields[8].text()) else { throw NativeNamecoinArchiveFailure("intent_mismatch") }
        let manifest = try NativeArchiveJSON.decode(manifestBytes, maximum: 1 << 20, canonical: false)
        for (key, expected) in [("network", selected.network), ("group", selected.group), ("account", selected.account),
                                ("genesis", nativeArchiveHex(selected.genesis)), ("account_pin_sha256", nativeArchiveHex(selected.publicPin))] {
            guard try manifest.field(key).text() == expected else { throw NativeNamecoinArchiveFailure("account_mismatch") }
        }
        let policyNames = ["revision", "per_tx_fee_cap_atoms", "total_fee_cap_atoms", "min_fee_rate_atoms_per_kvb", "max_fee_rate_atoms_per_kvb", "dust_relay_fee_atoms_per_kvb", "created_at", "release_not_after", "final_confirmations", "release_mode"]
        let actualPolicy = try manifest.field("policy").fields(policyNames, ordered: false)
        let expectedPolicy = try selected.policy.fields(policyNames)
        for index in actualPolicy.indices {
            guard try actualPolicy[index].canonical() == expectedPolicy[index].canonical() else { throw NativeNamecoinArchiveFailure("policy_refused") }
        }
        let intent = fields[10]
        let reveal = slot == "C" || slot == "D"
        let intended = try intent.fields(reveal ? ["operation", "name_hex", "value_hex", "rand_hex", "reservation_outpoint"] : ["operation", "name_hex", "rand_hex"], ordered: false)
        let operation: NamecoinReviewOperation = reveal ? .nameFirstupdate : .nameNew
        guard try intended[0].text() == operation.rawValue else { throw NativeNamecoinArchiveFailure("intent_mismatch") }
        let name = try nativeArchiveUnhex(intended[1].text())
        let finalValue = reveal ? try nativeArchiveUnhex(intended[2].text()) : Data()
        let randomness = try nativeArchiveUnhex(intended[reveal ? 3 : 2].text(), count: 20)
        guard !name.isEmpty, name.count <= 255, finalValue.count <= 520 else { throw NativeNamecoinArchiveFailure("display_refused") }
        let transactions = try manifest.field("transactions").list()
        let matches = try transactions.filter { try $0.field("slot").text() == slot }
        guard matches.count == 1, let fee = UInt64(try matches[0].field("fee_atoms").text()),
              String(fee) == (try matches[0].field("fee_atoms").text()) else { throw NativeNamecoinArchiveFailure("fee_refused") }
        self.value = value; self.intent = intent; self.manifest = manifest
        self.psbt = psbt; self.slot = slot; self.operation = operation
        self.name = name; self.finalValue = finalValue; self.randomness = randomness
        selectedFee = fee
    }

    // Decode every field in immutable frame domain2. This is correlation, not a
    // second PSBT engine: actual script/sighash/account/fee verification stays Go.
    func correlate(frame: Data, selected: NativeArchiveSelection) throws {
        guard !frame.isEmpty, frame.count <= 5 << 20 else { throw NativeNamecoinArchiveFailure("display_refused") }
        var cursor = NativeArchiveCursor(bytes: frame)
        try cursor.require(Data("keyvault/namecoin-psbt-review/2\0".utf8))
        guard try cursor.blob(4 << 20) == psbt,
              try cursor.blob(32) == Data(operation.rawValue.utf8), try cursor.blob(255) == name,
              try cursor.blob(520) == finalValue, try cursor.blob(20) == randomness else { throw NativeNamecoinArchiveFailure("display_refused") }
        let reveal = operation == .nameFirstupdate
        try cursor.require(Data([reveal ? 1 : 0]))
        if reveal {
            let outpoint = try intent.field("reservation_outpoint").fields(["txid", "vout"], ordered: false)
            try cursor.require(Data(try nativeArchiveUnhex(outpoint[0].text(), count: 32).reversed()))
            let vout = try outpoint[1].uint()
            guard vout <= UInt64(UInt32.max), try cursor.uint(4) == vout else { throw NativeNamecoinArchiveFailure("display_refused") }
        }
        try cursor.require(Data([reveal ? 1 : 0]))
        for field in ["reservation_plan_sha256", "plan_sha256", "sitting_id"] {
            try cursor.require(nativeArchiveUnhex(value.field(field).text(), count: 32))
        }
        try cursor.require(Data(slot.utf8))
        guard try cursor.blob(80) == Data(selected.group.utf8),
              try cursor.blob(80) == Data(selected.account.utf8) else { throw NativeNamecoinArchiveFailure("account_mismatch") }
        try cursor.require(selected.publicPin)
        guard try cursor.blob(64) == Data(selected.network.utf8) else { throw NativeNamecoinArchiveFailure("account_mismatch") }
        try cursor.require(Data(selected.genesis.reversed()))
        guard try cursor.blob(128) == Data(selected.revision.utf8), try cursor.uint(8) == selected.feeCap else { throw NativeNamecoinArchiveFailure("policy_refused") }
        try cursor.require(nativeArchiveUnhex(value.field("request_id").text(), count: 32))
        guard try cursor.uint(8) == value.field("expires_at").uint() else { throw NativeNamecoinArchiveFailure("display_refused") }
        try cursor.requireEnd()
    }
}

struct NativeNamecoinArchiveOperation {
    let mode: NativeNamecoinArchiveMode
    let input: Data
    let pin: Data
    let selected: NativeArchiveSelection
    let journal: NativeJournalSelection
    let output: NativeNamecoinPrivateOutput
    let request: NativeArchiveRequest

    init(mode: NativeNamecoinArchiveMode, requestOrDescriptor: Data, selectedAccountPin: Data,
         trustedCanonicalSelection: Data, journal: NativeJournalSelection,
         output: NativeNamecoinPrivateOutput) throws {
        let ownedInput = nativeJournalOwnedPublicData(requestOrDescriptor)
        let ownedPin = nativeJournalOwnedPublicData(selectedAccountPin)
        let selected = try NativeArchiveSelection(canonicalJSON: trustedCanonicalSelection, journal: journal)
        guard !ownedPin.isEmpty, ownedPin.count <= 32768,
              Data(SHA256.hash(data: ownedPin)) == selected.publicPin,
              !ownedInput.isEmpty, ownedInput.count <= 12 << 20 else { throw NativeNamecoinArchiveFailure("account_mismatch") }
        let requestBytes: Data
        if mode == .reconcile {
            var cursor = NativeArchiveCursor(bytes: ownedInput)
            try cursor.require(Data("KVND1\0".utf8))
            requestBytes = try cursor.blob(8 << 20)
            guard try cursor.blob(32768) == ownedPin,
                  try cursor.blob(2 << 20) == selected.selection.canonical() else { throw NativeNamecoinArchiveFailure("policy_refused") }
            try cursor.requireEnd()
        } else { requestBytes = ownedInput }
        self.request = try NativeArchiveRequest(requestBytes, selected: selected)
        self.mode = mode
        input = ownedInput
        pin = ownedPin
        self.selected = selected; self.journal = journal; self.output = output
    }
}

struct NativeArchiveReviewDocument {
    let snapshot: NamecoinReviewSnapshot
    let facts: [NamecoinReviewFact]
    let frame: Data

    init(ownedJSON: Data, operation: NativeNamecoinArchiveOperation) throws {
        let document = try NativeArchiveJSON.decode(ownedJSON, maximum: 9 << 20, canonical: true)
        let values = try document.fields(["operation", "account", "fee_atoms", "review_frame", "facts"])
        let expectedOperation: NamecoinReviewOperation = operation.mode == .reconcile ? .reconcile : operation.request.operation
        guard try values[0].text() == expectedOperation.rawValue, try values[1].text() == operation.selected.account,
              try values[2].uint() == (operation.mode == .reconcile ? 0 : operation.request.selectedFee) else { throw NativeNamecoinArchiveFailure("display_refused") }
        let frame = try values[3].base64(maximum: 5 << 20)
        try operation.request.correlate(frame: frame, selected: operation.selected)
        let list = try values[4].list()
        guard !list.isEmpty, list.count <= 2048 else { throw NativeNamecoinArchiveFailure("display_refused") }
        var admitted: [NamecoinReviewFact] = []
        var total = 0
        for entry in list {
            let fact = try entry.fields(["label", "kind", "bytes"])
            let kind: NamecoinReviewFactKind
            switch try fact[1].text() {
            case "binary": kind = .binary
            case "semanticName": kind = .semanticName
            case "semanticValue": kind = .semanticValue
            default: throw NativeNamecoinArchiveFailure("display_refused")
            }
            let bytes = try fact[2].base64(maximum: 262144, empty: true)
            total += bytes.count
            guard total <= 1 << 20 else { throw NativeNamecoinArchiveFailure("display_refused") }
            do { admitted.append(try NamecoinReviewFact(label: fact[0].text(), bytes: bytes, kind: kind)) }
            catch { throw NativeNamecoinArchiveFailure("display_refused") }
        }
        guard Set(admitted.map { $0.label }).count == admitted.count else { throw NativeNamecoinArchiveFailure("display_refused") }
        func require(_ label: String, _ bytes: Data, _ kind: NamecoinReviewFactKind = .binary) throws {
            guard let fact = admitted.first(where: { $0.label == label }), fact.kind == kind, fact.bytes == bytes else {
                throw NativeNamecoinArchiveFailure("display_refused")
            }
        }
        let selected = operation.selected, request = operation.request
        try require("Network / genesis", Data((selected.network + " / " + nativeArchiveHex(selected.genesis)).utf8))
        try require("Existing recovery group", Data(selected.group.utf8))
        try require("Account public pin SHA256", Data(nativeArchiveHex(selected.publicPin).utf8))
        try require("Policy revision", Data(selected.revision.utf8))
        for (label, key) in [("Release mode", "release_mode"), ("Release deadline UTC seconds", "release_not_after"), ("Final confirmations required", "final_confirmations")] {
            let value = try selected.policy.field(key)
            let text: String
            if case .string(let string) = value { text = string } else { text = String(try value.uint()) }
            try require(label, Data(text.utf8))
        }
        try require("Request / sitting", Data(try (request.value.field("request_id").text() + " / " + request.value.field("sitting_id").text()).utf8))
        for (label, key) in [("Plan SHA256", "plan_sha256"), ("Reservation plan SHA256", "reservation_plan_sha256")] {
            try require(label, Data(try request.value.field(key).text().utf8))
        }
        try require("Request expires UTC seconds", Data(String(try request.value.field("expires_at").uint()).utf8))
        for (label, left, right) in [("Fee caps per transaction / total atoms", "per_tx_fee_cap_atoms", "total_fee_cap_atoms"), ("Fee rates min / max atoms per kvB", "min_fee_rate_atoms_per_kvb", "max_fee_rate_atoms_per_kvb")] {
            try require(label, Data(try (selected.policy.field(left).text() + " / " + selected.policy.field(right).text()).utf8))
        }
        try require("Dust relay atoms per kvB", Data(try selected.policy.field("dust_relay_fee_atoms_per_kvb").text().utf8))
        let prefix = request.slot == "A" || request.slot == "C" ? "A/C" : "B/D"
        try require(prefix + " NAME", request.name, .semanticName)
        try require(prefix + " commitment randomness", request.randomness)
        if request.operation == .nameFirstupdate { try require(prefix + " VALUE", request.finalValue, .semanticValue) }
        // Every returned fact survives; no digest-only review or selective render.
        // All original transaction fee/facts remain even for reconcile fee0.
        self.frame = frame
        facts = admitted
        do {
            snapshot = try NamecoinReviewSnapshot(operation: expectedOperation, account: selected.account,
                                                  feeAtoms: values[2].uint(), frozenReviewFrame: frame, facts: admitted)
        } catch { throw NativeNamecoinArchiveFailure("display_refused") }
    }
}

// An authoritative native UNKNOWN must never be downgraded by a narrower
// callback refusal. An OK return alongside any callback failure is inconsistent
// and cannot release an ACK. This helper reports only closed failure precedence.
func nativeArchiveRunFailure(_ code: Int32,
                             callbackFailure: NativeNamecoinArchiveFailure?) -> NativeNamecoinArchiveFailure? {
    let native = NativeNamecoinArchiveFailure.abi(code)
    if native?.code == "outcome_unknown" { return native }
    if let callbackFailure {
        if code == Int32(KV_NMC_OK) || callbackFailure.code == "outcome_unknown" {
            return NativeNamecoinArchiveFailure("outcome_unknown")
        }
        return callbackFailure
    }
    return native
}

// Software ordering/ownership only. These states are never accepted from IPC and
// do not certify review, biometry, native success, or journal provenance.
struct NativeArchiveLifecycle {
    enum Phase: Equatable { case opened, running, ran, closed }
    private(set) var phase: Phase = .opened
    mutating func beginRun() throws {
        guard phase == .opened else { throw NativeNamecoinArchiveFailure("replay_refused") }
        phase = .running
    }
    mutating func returned(_ code: Int32) throws {
        guard phase == .running else { throw NativeNamecoinArchiveFailure("outcome_unknown") }
        if let failure = NativeNamecoinArchiveFailure.abi(code) { throw failure }
        phase = .ran
    }
    func requireAckPhase() throws {
        guard phase == .ran else { throw NativeNamecoinArchiveFailure("outcome_unknown") }
    }
    mutating func close() { phase = .closed }
}

struct NativeArchiveHandleOwnership {
    private var value: UInt64?
    init(_ value: UInt64) throws {
        guard value != 0 else { throw NativeNamecoinArchiveFailure("outcome_unknown") }
        self.value = value
    }
    mutating func takeForClose() -> UInt64? {
        let result = value
        value = nil
        return result
    }
}

private final class NativeArchiveHandle {
    let value: UInt64
    private var ownership: NativeArchiveHandleOwnership
    init(_ value: UInt64) throws { self.value = value; ownership = try NativeArchiveHandleOwnership(value) }
    func close() throws {
        guard let value = ownership.takeForClose() else { return }
        // Clear ownership BEFORE this call; failure is UNKNOWN, never a retry.
        guard kv_nmc_close_v1(value) == Int32(KV_NMC_OK) else { throw NativeNamecoinArchiveFailure("outcome_unknown") }
    }
    deinit { try? close() }
    func copyReview() throws -> Data { try copy(acknowledgement: false, maximum: 9 << 20) }
    func copyAck() throws -> Data { try copy(acknowledgement: true, maximum: 256) }
    private func copy(acknowledgement: Bool, maximum: Int) throws -> Data {
        var count: size_t = 0
        let query = acknowledgement ? kv_nmc_copy_ack_v1(value, nil, 0, &count) : kv_nmc_copy_review_v1(value, nil, 0, &count)
        if let failure = NativeNamecoinArchiveFailure.abi(query) { throw failure }
        guard count > 0, count <= size_t(maximum) else { throw NativeNamecoinArchiveFailure(acknowledgement ? "outcome_unknown" : "display_refused") }
        var bytes = [UInt8](repeating: 0, count: Int(count))
        var written: size_t = 0
        let result = bytes.withUnsafeMutableBufferPointer { buffer in
            acknowledgement ? kv_nmc_copy_ack_v1(value, buffer.baseAddress, size_t(buffer.count), &written)
                : kv_nmc_copy_review_v1(value, buffer.baseAddress, size_t(buffer.count), &written)
        }
        if let failure = NativeNamecoinArchiveFailure.abi(result) { throw failure }
        guard written == count else { throw NativeNamecoinArchiveFailure(acknowledgement ? "outcome_unknown" : "display_refused") }
        return Data(bytes)
    }
}

func nativeArchiveValidateAcknowledgement(_ raw: Data, resultHash: Data) throws -> Data {
    guard resultHash.count == 32, !raw.isEmpty, raw.count <= 256,
          raw.last == 10 else { throw NativeNamecoinArchiveFailure("outcome_unknown") }
    do {
        let body = try NativeArchiveJSON.decode(Data(raw.dropLast()), maximum: 255, canonical: true)
        let fields = try body.fields(["schema", "status", "result_sha256"])
        guard try fields[0].text() == "keyvault-namecoin-psbt-ack/2",
              try fields[1].text() == "SIGNED", try fields[2].text() == nativeArchiveHex(resultHash) else {
            throw NativeNamecoinArchiveFailure("outcome_unknown")
        }
        return nativeJournalOwnedPublicData(raw)
    } catch { throw NativeNamecoinArchiveFailure("outcome_unknown") }
}

// Pure pointer/size admission can be tested with public stack fixtures without
// constructing native storage or inventing a successful native callback.
enum NativeArchiveCallbackShape {
    static func load(_ buffer: UnsafeMutablePointer<UInt8>?, capacity: size_t,
                     written: UnsafeMutablePointer<size_t>?) throws {
        guard buffer != nil, written != nil, capacity > 0, capacity <= 512 else {
            throw NativeNamecoinArchiveFailure("journal_unavailable")
        }
    }
    static func replace(_ bytes: UnsafePointer<UInt8>?, count: size_t,
                        mode: NativeNamecoinArchiveMode) throws {
        guard bytes != nil, count > 0, count <= 512, mode == .sign else {
            throw NativeNamecoinArchiveFailure("outcome_unknown")
        }
    }
    static func output(_ bytes: UnsafePointer<UInt8>?, count: size_t,
                       hash: UnsafePointer<UInt8>?) throws {
        guard bytes != nil, hash != nil, count > 0,
              count <= size_t(NativeNamecoinPrivateOutput.maximumResultBytes) else {
            throw NativeNamecoinArchiveFailure("output_unavailable")
        }
    }
}

// Callbacks are synchronous and process-local. The only nonnil context pointer
// ever supplied is passUnretained(self) within withExtendedLifetime during run.
// Arbitrary forged native pointers are outside this trusted in-process ABI; no
// parent IPC can supply one. A pointer is never retained by the Go adapter.
final class NativeArchiveCallbackContext {
    private let storage: NativeNamecoinJournalStorage
    private let output: NativeNamecoinPrivateOutput
    private let mode: NativeNamecoinArchiveMode
    private var prior: NativeSecretBytes?
    private(set) var active = false
    private(set) var effectPossible = false
    private(set) var failure: NativeNamecoinArchiveFailure?
    private(set) var resultHash: Data?

    init(storage: NativeNamecoinJournalStorage, output: NativeNamecoinPrivateOutput,
         mode: NativeNamecoinArchiveMode, frozen: NativeFrozenJournalAnchor) throws {
        self.storage = storage; self.output = output; self.mode = mode
        try frozen.withBytes { prior = try NativeSecretBytes(copying: $0, maximum: 512) }
    }
    func begin() throws {
        guard !active, failure == nil, prior != nil, resultHash == nil else { throw NativeNamecoinArchiveFailure("replay_refused") }
        active = true
    }
    func end() { active = false }
    func clear() { active = false; prior?.clear(); prior = nil }
    deinit { clear() }
    private func record(_ error: Error) -> Int32 {
        let mapped = NativeNamecoinArchiveFailure.map(error)
        if effectPossible || mapped.code == "outcome_unknown" { failure = NativeNamecoinArchiveFailure("outcome_unknown") }
        else if failure == nil { failure = mapped }
        return -1
    }
    func load(_ buffer: UnsafeMutablePointer<UInt8>?, capacity: size_t, written: UnsafeMutablePointer<size_t>?) -> Int32 {
        if let written { written.pointee = 0 }
        do { try NativeArchiveCallbackShape.load(buffer, capacity: capacity, written: written) }
        catch { return record(error) }
        guard active, failure == nil, capacity > 0, capacity <= 512,
              let buffer, let written, let prior else { return record(NativeNamecoinArchiveFailure("journal_unavailable")) }
        do {
            try storage.withExistingAnchor { actual in
                try prior.withBytes { expected in
                    guard actual.count <= Int(capacity), actual.count == expected.count,
                          let source = actual.baseAddress, let frozen = expected.baseAddress,
                          timingsafe_bcmp(source, frozen, actual.count) == 0 else { throw NativeJournalRefusal.unknown }
                    buffer.update(from: source.assumingMemoryBound(to: UInt8.self), count: actual.count)
                    written.pointee = size_t(actual.count)
                }
            }
            return 0
        } catch { return record(error) }
    }
    func replace(_ bytes: UnsafePointer<UInt8>?, count: size_t) -> Int32 {
        do { try NativeArchiveCallbackShape.replace(bytes, count: count, mode: mode) }
        catch { return record(error) }
        guard active, failure == nil, mode == .sign, let prior,
              let bytes, count > 0, count <= 512 else { return record(NativeNamecoinArchiveFailure("outcome_unknown")) }
        // The engine has already attempted DISPATCHED persistence before this
        // callback; even a failed native update cannot claim no private effect.
        effectPossible = true
        do {
            let next = try NativeSecretBytes(copying: UnsafeRawBufferPointer(start: bytes, count: Int(count)), maximum: 512)
            var transferred = false
            defer { if !transferred { next.clear() } }
            try storage.replaceExistingAnchor(expected: prior, replacement: next)
            // replaceExistingAnchor includes exact selected-item readback. Go
            // then independently calls load again; rollover keeps that exact
            // next buffer, never a mutable re-read or secret Data/JSON copy.
            prior.clear()
            self.prior = next
            transferred = true
            return 0
        } catch { return record(error) }
    }
    func writeResult(_ bytes: UnsafePointer<UInt8>?, count: size_t, hash: UnsafePointer<UInt8>?) -> Int32 {
        do { try NativeArchiveCallbackShape.output(bytes, count: count, hash: hash) }
        catch { return record(error) }
        guard active, failure == nil, resultHash == nil, let bytes, let hash,
              count > 0, count <= size_t(NativeNamecoinPrivateOutput.maximumResultBytes) else {
            return record(NativeNamecoinArchiveFailure("output_unavailable"))
        }
        do {
            // ONLY the actual verified Go Result constructor calls this ABI. Its
            // SHA256 is supplied independently of this copy. These are PUBLIC
            // result bytes; matching hashes alone cannot certify secret-free data.
            let publicBytes = Data(bytes: bytes, count: Int(count))
            let expected = Data(bytes: hash, count: 32)
            try output.writePublicResult(publicBytes, expectedSHA256: expected)
            effectPossible = true
            resultHash = expected
            return 0
        } catch {
            // In reconcile mode the Go error can be output_unavailable even
            // after a partial native write. Preserve its actual UNKNOWN here.
            if (error as? NativeNamecoinOutputRefusal) == .unknown { effectPossible = true }
            return record(error)
        }
    }
}

// Exact typedefs from the generated header; no guessed signatures or C exports.
let nativeArchiveLoadCallback: kv_nmc_load_fn = { context, buffer, capacity, written in
    if let written { written.pointee = 0 }
    guard let context else { return -1 }
    return Unmanaged<NativeArchiveCallbackContext>.fromOpaque(context).takeUnretainedValue()
        .load(buffer, capacity: capacity, written: written)
}
let nativeArchiveReplaceCallback: kv_nmc_replace_fn = { context, bytes, count in
    guard let context else { return -1 }
    return Unmanaged<NativeArchiveCallbackContext>.fromOpaque(context).takeUnretainedValue().replace(bytes, count: count)
}
let nativeArchiveOutputCallback: kv_nmc_output_fn = { context, bytes, count, hash in
    guard let context else { return -1 }
    return Unmanaged<NativeArchiveCallbackContext>.fromOpaque(context).takeUnretainedValue().writeResult(bytes, count: count, hash: hash)
}

final class NativeNamecoinArchiveBridge {
    let snapshot: NamecoinReviewSnapshot
    private let handle: NativeArchiveHandle
    private let storage: NativeNamecoinJournalStorage
    private let frozen: NativeFrozenJournalAnchor
    private let callbacks: NativeArchiveCallbackContext
    private let output: NativeNamecoinPrivateOutput
    private var lifecycle = NativeArchiveLifecycle()

    private init(handle: NativeArchiveHandle, storage: NativeNamecoinJournalStorage,
                 frozen: NativeFrozenJournalAnchor, callbacks: NativeArchiveCallbackContext,
                 output: NativeNamecoinPrivateOutput, snapshot: NamecoinReviewSnapshot) {
        self.handle = handle; self.storage = storage; self.frozen = frozen
        self.callbacks = callbacks; self.output = output; self.snapshot = snapshot
    }

    static func open(_ operation: NativeNamecoinArchiveOperation) throws -> NativeNamecoinArchiveBridge {
        var request = Array(operation.input), pin = Array(operation.pin), config = Array(operation.selected.raw)
        var identifier: UInt64 = 0
        let code = request.withUnsafeMutableBufferPointer { request in
            pin.withUnsafeMutableBufferPointer { pin in
                config.withUnsafeMutableBufferPointer { config in
                    kv_nmc_open_v1(operation.mode.rawValue, request.baseAddress, size_t(request.count),
                                   pin.baseAddress, size_t(pin.count), config.baseAddress, size_t(config.count), &identifier)
                }
            }
        }
        if let failure = NativeNamecoinArchiveFailure.abi(code) {
            var refusal = failure
            do { try operation.output.close() } catch { refusal = NativeNamecoinArchiveFailure("outcome_unknown") }
            if identifier != 0 {
                let retained = try NativeArchiveHandle(identifier)
                do { try retained.close() } catch { refusal = NativeNamecoinArchiveFailure("outcome_unknown") }
            }
            throw refusal
        }
        let handle: NativeArchiveHandle
        do { handle = try NativeArchiveHandle(identifier) }
        catch {
            try? operation.output.close()
            throw NativeNamecoinArchiveFailure("outcome_unknown")
        }
        var frozen: NativeFrozenJournalAnchor?
        var context: NativeArchiveCallbackContext?
        do {
            let review = try NativeArchiveReviewDocument(ownedJSON: handle.copyReview(), operation: operation)
            // The C handle now retains the real kernel gate. Only from this
            // point may code identity, selected native item or value be read.
            let storage: NativeNamecoinJournalStorage
            do { storage = try NativeNamecoinJournalStorage(selection: operation.journal) }
            catch NativeJournalRefusal.mismatch { throw NativeNamecoinArchiveFailure("helper_not_admitted") }
            let anchor = try storage.freezeExistingAnchorForReconciliation()
            frozen = anchor
            let callbacks = try NativeArchiveCallbackContext(storage: storage, output: operation.output,
                                                            mode: operation.mode, frozen: anchor)
            context = callbacks
            return NativeNamecoinArchiveBridge(handle: handle, storage: storage, frozen: anchor,
                                                callbacks: callbacks, output: operation.output, snapshot: review.snapshot)
        } catch {
            context?.clear(); frozen?.clear()
            var failure = NativeNamecoinArchiveFailure.map(error)
            do { try operation.output.close() } catch { failure = NativeNamecoinArchiveFailure("outcome_unknown") }
            do { try handle.close() } catch { failure = NativeNamecoinArchiveFailure("outcome_unknown") }
            throw failure
        }
    }

    deinit {
        // Fallback resource destruction preserves the same secret-before-gate
        // order; ownership guards prevent retrying any prior close attempt.
        callbacks.clear(); frozen.clear()
        try? output.close()
        try? handle.close()
    }

    func verifyFrozenAfterReview() throws {
        guard lifecycle.phase == .opened else { throw NativeNamecoinArchiveFailure("replay_refused") }
        do { try storage.verifyFrozenAnchorUnchanged(frozen) }
        catch { throw NativeNamecoinArchiveFailure("outcome_unknown") }
    }

    // Called only by the narrow appended entry within sealedAccount.withAccount.
    // No pointer, account bytes or CryptoKit key escapes this lexical C-run call.
    func runBorrowing(_ account: UnsafeRawBufferPointer) throws {
        guard account.count == 64, let base = account.baseAddress else { throw NativeNamecoinArchiveFailure("account_mismatch") }
        try lifecycle.beginRun()
        try callbacks.begin()
        defer { callbacks.end() }
        let code = withExtendedLifetime(callbacks) {
            var table = kv_nmc_callbacks_v1()
            table.context = Unmanaged.passUnretained(callbacks).toOpaque()
            table.load_protected = nativeArchiveLoadCallback
            table.replace_protected = nativeArchiveReplaceCallback
            table.write_public_result = nativeArchiveOutputCallback
            return kv_nmc_run_v1(handle.value, UnsafeMutablePointer(mutating: base.assumingMemoryBound(to: UInt8.self)), size_t(account.count), &table)
        }
        if let failure = nativeArchiveRunFailure(code, callbackFailure: callbacks.failure) {
            throw callbacks.effectPossible ? NativeNamecoinArchiveFailure("outcome_unknown") : failure
        }
        do { try lifecycle.returned(code) }
        catch { throw callbacks.effectPossible ? NativeNamecoinArchiveFailure("outcome_unknown") : NativeNamecoinArchiveFailure.map(error) }
    }

    // Called AFTER withAccount returned and cleared its owned source material.
    // Copy/parse the exact ACK only after real run and successful public output
    // cleanup; return it only after native buffers clear and the single C-close.
    func finishAndClose() throws -> Data {
        try lifecycle.requireAckPhase()
        guard let hash = callbacks.resultHash, callbacks.failure == nil else { throw NativeNamecoinArchiveFailure("outcome_unknown") }
        let acknowledgement = try nativeArchiveValidateAcknowledgement(handle.copyAck(), resultHash: hash)
        callbacks.clear(); frozen.clear()
        do { try output.close() } catch { throw NativeNamecoinArchiveFailure("outcome_unknown") }
        lifecycle.close()
        try handle.close()
        return acknowledgement
    }

    func refuseAndClose(_ error: Error) -> NativeNamecoinArchiveFailure {
        var refusal = callbacks.effectPossible ? NativeNamecoinArchiveFailure("outcome_unknown") : NativeNamecoinArchiveFailure.map(error)
        callbacks.clear(); frozen.clear()
        do { try output.close() } catch { refusal = NativeNamecoinArchiveFailure("outcome_unknown") }
        lifecycle.close()
        do { try handle.close() } catch { refusal = NativeNamecoinArchiveFailure("outcome_unknown") }
        return refusal
    }
}
