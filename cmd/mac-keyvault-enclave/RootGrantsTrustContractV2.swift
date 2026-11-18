import CryptoKit
import Foundation

enum RootGrantsTrustContractV2FailureCode: String, Equatable {
    case contractEncoding = "CONTRACT_ENCODING"
    case contractProfile = "CONTRACT_PROFILE"
    case contractField = "CONTRACT_FIELD"
    case contractActions = "CONTRACT_ACTIONS"
    case contractRepos = "CONTRACT_REPOS"
    case contractBudget = "CONTRACT_BUDGET"
    case contractNote = "CONTRACT_NOTE"
    case contractParent = "CONTRACT_PARENT"
    case contractDelegate = "CONTRACT_DELEGATE"
    case delegateNoNotary = "DELEGATE_NO_NOTARY"
    case delegationNotAuthorized = "delegation_not_authorized"
    case spendNotAuthorized = "spend_not_authorized"
    case scopeTextUnavailable = "scope_text_unavailable"
    case scopeTextUnexpected = "scope_text_unexpected"
    case scopeTextHashMismatch = "scope_text_hash_mismatch"
}

struct RootGrantsTrustContractV2Failure: Error, Equatable {
    let code: RootGrantsTrustContractV2FailureCode

    // Every known trust/2 semantic refusal uses the agreed native coarsening.
    var nativeStatus: RootGrantsStatus { .bindingMismatch }
}

struct RootGrantsTrustContractV2 {
    static let maximumBytes = 8192
    static let maximumAtoms: UInt64 = 2_100_000_000_000_000
    static let maximumUnixTime: UInt64 = 253_402_300_799
    static let actions = ["instruct", "land", "review", "spend"]

    struct Slot {
        let executor: String
        let grantee: String
        let cap: UInt64
        let notary: String
    }

    struct Notary {
        let name: String
        let txid: String
        let vout: UInt64
        let owner: String
    }

    struct Delegate {
        let depth: UInt64
        let actions: [String]
        let budget: UInt64
        let slots: [Slot]
        let notaries: [Notary]
        let checkpoint: String
    }

    let bytes: Data
    let profile: String
    let network: String
    let landlordName: String
    let agentName: String
    let granteeKey: String
    let actions: [String]
    let repos: [String]
    let spendBudget: UInt64
    let notBefore: UInt64
    let notAfter: UInt64
    let scopeTextSHA256: String
    let parentGrantID: String
    let ordinal: UInt64
    let delegate: Delegate
    let note: String

    var derivedV3Scope: [String] {
        var scope: [String] = []
        if actions.contains("land") { scope.append("repository.push") }
        if actions.contains("spend") { scope.append("pay") }
        return scope.sorted()
    }

    static func countersignDigest(_ exactContractBytes: Data) -> Data {
        Data(SHA256.hash(data: exactContractBytes))
    }

    init(ownedBytes input: Data) throws {
        func fail(_ code: RootGrantsTrustContractV2FailureCode) -> RootGrantsTrustContractV2Failure {
            RootGrantsTrustContractV2Failure(code: code)
        }

        guard (1...Self.maximumBytes).contains(input.count) else { throw fail(.contractEncoding) }
        let owned = input.withUnsafeBytes { Data($0) }
        let root: NativeArchiveJSON
        do {
            // The whole LIP contract is capped at 8192 bytes. Keep lower
            // generic decoder caps from stealing rule-4 or rule-9 findings.
            root = try NativeArchiveJSON.decode(owned, maximum: Self.maximumBytes, canonical: true, escapeHTML: false,
                                               maximumArrayMembers: Self.maximumBytes,
                                               maximumObjectMembers: Self.maximumBytes, maximumDepth: owned.count,
                                               allowDuplicateObjectKeys: true, allowBooleanLiterals: true,
                                               retainInvalidNumberTokens: true)
        } catch {
            throw fail(.contractEncoding)
        }
        guard Self.objectKeysAreUniqueOutsideDelegate(root, rootObject: true),
              Self.lexicalValuesAreAllowed(root, rootObject: true) else {
            throw fail(.contractEncoding)
        }

        let profileV1Members = ["profile", "network", "landlord_name", "agent_name", "grantee_key", "actions",
                                "repos", "spend_budget", "not_before", "not_after", "note"]
        if case .object(let pairs) = root, pairs.map({ $0.0 }) == profileV1Members {
            let legacyFields: [NativeArchiveJSON]
            do { legacyFields = try root.fields(profileV1Members) }
            catch { throw fail(.contractEncoding) }
            guard Self.string(legacyFields[0]) != nil, Self.string(legacyFields[1]) != nil,
                  Self.string(legacyFields[2]) != nil, Self.string(legacyFields[3]) != nil,
                  Self.string(legacyFields[4]) != nil, Self.array(legacyFields[5]) != nil,
                  Self.array(legacyFields[6]) != nil, Self.number(legacyFields[7]) != nil,
                  Self.number(legacyFields[8]) != nil, Self.number(legacyFields[9]) != nil,
                  Self.string(legacyFields[10]) != nil else { throw fail(.contractEncoding) }
            throw fail(.contractProfile)
        }

        let memberNames = [
            "profile", "network", "landlord_name", "agent_name", "grantee_key", "actions", "repos",
            "spend_budget", "not_before", "not_after", "scope_text_sha256", "parent_grant_id", "ordinal",
            "delegate", "note",
        ]
        let fields: [NativeArchiveJSON]
        do { fields = try root.fields(memberNames) }
        catch { throw fail(.contractEncoding) }

        // Rule 1 owns the member types, except that delegate is classified by rule 9.
        guard Self.string(fields[0]) != nil, Self.string(fields[1]) != nil,
              Self.string(fields[2]) != nil, Self.string(fields[3]) != nil,
              Self.string(fields[4]) != nil, Self.array(fields[5]) != nil,
              Self.array(fields[6]) != nil, Self.number(fields[7]) != nil,
              Self.number(fields[8]) != nil, Self.number(fields[9]) != nil,
              Self.string(fields[10]) != nil, Self.string(fields[11]) != nil,
              Self.number(fields[12]) != nil, Self.string(fields[14]) != nil else {
            throw fail(.contractEncoding)
        }

        let profile = Self.string(fields[0])!
        let network = Self.string(fields[1])!
        let landlordName = Self.string(fields[2])!
        let agentName = Self.string(fields[3])!
        let granteeKey = Self.string(fields[4])!
        let spendBudget = Self.number(fields[7])!
        let notBefore = Self.number(fields[8])!
        let notAfter = Self.number(fields[9])!
        let scopeTextSHA256 = Self.string(fields[10])!
        let parentGrantID = Self.string(fields[11])!
        let ordinal = Self.number(fields[12])!
        let note = Self.string(fields[14])!

        // Rule 2 owns the profile literal after rule 1 has selected the member set.
        guard profile == "swarma-trust-contract/2" else { throw fail(.contractProfile) }

        // Rule 3 owns inherited field values, the trust key spelling, window and text hash grammar.
        guard network == "main" || network == "regtest",
              Self.validIDName(landlordName), Self.validIDName(agentName), landlordName != agentName,
              TrustSecp256k1Key.isValidXOnly(granteeKey),
              notAfter > notBefore, notAfter <= Self.maximumUnixTime,
              scopeTextSHA256.isEmpty || Self.isLowerHex(scopeTextSHA256, count: 64) else {
            throw fail(.contractField)
        }

        // Rule 4 owns the action members and their strict byte ordering.
        guard let actions = Self.stringArray(Self.array(fields[5])), !actions.isEmpty,
              Self.isStrictlySorted(actions), actions.allSatisfy(Self.actions.contains) else {
            throw fail(.contractActions)
        }

        // Rule 5 owns repository values and the exact land/repository relationship.
        guard let repos = Self.stringArray(Self.array(fields[6])), repos.count <= 16,
              (actions.contains("land") == !repos.isEmpty), Self.isStrictlySorted(repos),
              repos.allSatisfy(Self.validRepository) else {
            throw fail(.contractRepos)
        }

        // Rule 6 owns the spend action and budget relationship.
        guard spendBudget <= Self.maximumAtoms,
              (actions.contains("spend") == (spendBudget > 0)) else {
            throw fail(.contractBudget)
        }

        // Rule 7 owns only the printable note length; the note never grants authority.
        guard note.utf8.count <= 280 else { throw fail(.contractNote) }

        // Rule 8 runs before any value-level rule-9 finding.
        guard parentGrantID.isEmpty || Self.isLowerHex(parentGrantID, count: 64),
              ordinal <= 16, (parentGrantID.isEmpty == (ordinal == 0)) else {
            throw fail(.contractParent)
        }
        if !parentGrantID.isEmpty, case .object(let pairs) = fields[13],
           let first = pairs.first, first.0 == "depth",
           case .number(let depth) = first.1, depth != 0 {
            throw fail(.contractParent)
        }

        // Rule 9a owns the closed delegate, row, registration and notary shapes.
        guard let delegate = try Self.parseDelegate(fields[13], landlordName: landlordName,
                                                     contractActions: actions,
                                                     fail: fail) else {
            throw fail(.contractDelegate)
        }

        bytes = owned
        self.profile = profile
        self.network = network
        self.landlordName = landlordName
        self.agentName = agentName
        self.granteeKey = granteeKey
        self.actions = actions
        self.repos = repos
        self.spendBudget = spendBudget
        self.notBefore = notBefore
        self.notAfter = notAfter
        self.scopeTextSHA256 = scopeTextSHA256
        self.parentGrantID = parentGrantID
        self.ordinal = ordinal
        self.delegate = delegate
        self.note = note
    }

    func instanceRefusal() -> RootGrantsTrustContractV2Failure? {
        if !parentGrantID.isEmpty || ordinal != 0 || delegate.depth != 0 {
            return RootGrantsTrustContractV2Failure(code: .delegationNotAuthorized)
        }
        if actions.contains("spend") {
            return RootGrantsTrustContractV2Failure(code: .spendNotAuthorized)
        }
        return nil
    }

    static func validateScopeText(_ bytes: Data, reviewedHash: String,
                                  contractHash: String) -> RootGrantsTrustContractV2Failure? {
        guard reviewedHash == contractHash else {
            return RootGrantsTrustContractV2Failure(code: .scopeTextHashMismatch)
        }
        if contractHash.isEmpty {
            return bytes.isEmpty ? nil : RootGrantsTrustContractV2Failure(code: .scopeTextUnexpected)
        }
        guard !bytes.isEmpty else { return RootGrantsTrustContractV2Failure(code: .scopeTextUnavailable) }
        let digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        guard digest == contractHash else { return RootGrantsTrustContractV2Failure(code: .scopeTextHashMismatch) }
        return nil
    }

    private static func parseDelegate(_ value: NativeArchiveJSON, landlordName: String,
                                      contractActions: [String],
                                      fail: (RootGrantsTrustContractV2FailureCode) -> RootGrantsTrustContractV2Failure) throws
        -> Delegate? {
        let names = ["depth", "actions", "budget", "slots", "notaries", "checkpoint"]
        let fields: [NativeArchiveJSON]
        do { fields = try value.fields(names) }
        catch { return nil }
        guard let depth = number(fields[0]), let actionValues = array(fields[1]),
              let budget = number(fields[2]), let slotValues = array(fields[3]),
              let notaryValues = array(fields[4]), let checkpoint = string(fields[5]) else {
            return nil
        }

        // Rule 9b precedes every value-level rule-9 failure once the outer shape is valid.
        if depth == 1 && notaryValues.isEmpty { throw fail(.delegateNoNotary) }

        guard depth <= 1, budget <= maximumAtoms,
              let delegateActions = stringArray(actionValues),
              Self.isStrictlySorted(delegateActions),
              delegateActions.allSatisfy({ contractActions.contains($0) && $0 != "spend" }) else {
            throw fail(.contractDelegate)
        }

        if depth == 0 {
            guard delegateActions.isEmpty, budget == 0, slotValues.isEmpty,
                  notaryValues.isEmpty, checkpoint.isEmpty else { throw fail(.contractDelegate) }
            return Delegate(depth: depth, actions: delegateActions, budget: budget,
                            slots: [], notaries: [], checkpoint: checkpoint)
        }

        guard !delegateActions.isEmpty, budget == 0,
              (1...16).contains(slotValues.count), (1...4).contains(notaryValues.count),
              Self.isLowerHex(checkpoint, count: 64) else { throw fail(.contractDelegate) }

        var notaries: [Notary] = []
        notaries.reserveCapacity(notaryValues.count)
        for value in notaryValues {
            guard let fields = try? value.fields(["name", "registration", "owner"]),
                  let name = string(fields[0]), validIDName(name),
                  let registration = try? fields[1].fields(["txid", "vout"]),
                  let txid = string(registration[0]), isLowerHex(txid, count: 64),
                  let vout = number(registration[1]), vout <= UInt64(UInt32.max),
                  let owner = string(fields[2]), validCompressedSecp256k1KeySpelling(owner) else {
                throw fail(.contractDelegate)
            }
            notaries.append(Notary(name: name, txid: txid, vout: vout, owner: owner))
        }
        let notaryNames = notaries.map(\.name)
        guard isStrictlySorted(notaryNames) else { throw fail(.contractDelegate) }

        var slots: [Slot] = []
        slots.reserveCapacity(slotValues.count)
        for value in slotValues {
            guard let fields = try? value.fields(["executor", "grantee", "cap", "notary"]),
                  let executor = string(fields[0]), validIDName(executor), executor != landlordName,
                  let grantee = string(fields[1]), TrustSecp256k1Key.isValidXOnly(grantee),
                  let cap = number(fields[2]), cap == 0,
                  let notary = string(fields[3]), notaryNames.contains(notary) else {
                throw fail(.contractDelegate)
            }
            slots.append(Slot(executor: executor, grantee: grantee, cap: cap, notary: notary))
        }
        return Delegate(depth: depth, actions: delegateActions, budget: budget,
                        slots: slots, notaries: notaries, checkpoint: checkpoint)
    }

    private static func lexicalValuesAreAllowed(_ value: NativeArchiveJSON, inDelegate: Bool = false,
                                                rootObject: Bool = false) -> Bool {
        switch value {
        case .null, .boolean:
            return inDelegate
        case .number(let number):
            return number <= UInt64(Int64.max)
        case .invalidNumber:
            return false
        case .string(let text):
            return text.utf8.allSatisfy { (0x20...0x7e).contains($0) }
        case .array(let values):
            return values.allSatisfy { lexicalValuesAreAllowed($0, inDelegate: inDelegate) }
        case .object(let pairs):
            return pairs.allSatisfy { pair in
                let name = pair.0
                let child = pair.1
                return name.utf8.allSatisfy { (0x20...0x7e).contains($0) } &&
                    lexicalValuesAreAllowed(child, inDelegate: inDelegate || (rootObject && name == "delegate"))
            }
        }
    }

    private static func objectKeysAreUniqueOutsideDelegate(_ value: NativeArchiveJSON,
                                                              inDelegate: Bool = false,
                                                              rootObject: Bool = false) -> Bool {
        switch value {
        case .object(let pairs):
            if !inDelegate {
                let names = pairs.map(\.0)
                guard Set(names).count == names.count else { return false }
            }
            return pairs.allSatisfy { pair in
                let name = pair.0
                let child = pair.1
                return objectKeysAreUniqueOutsideDelegate(child,
                                                          inDelegate: inDelegate || (rootObject && name == "delegate"))
            }
        case .array(let values):
            return values.allSatisfy { objectKeysAreUniqueOutsideDelegate($0, inDelegate: inDelegate) }
        case .string, .number, .invalidNumber, .boolean, .null:
            return true
        }
    }

    private static func string(_ value: NativeArchiveJSON) -> String? {
        guard case .string(let text) = value else { return nil }
        return text
    }

    private static func number(_ value: NativeArchiveJSON) -> UInt64? {
        guard case .number(let number) = value else { return nil }
        return number
    }

    private static func array(_ value: NativeArchiveJSON) -> [NativeArchiveJSON]? {
        guard case .array(let values) = value else { return nil }
        return values
    }

    private static func stringArray(_ values: [NativeArchiveJSON]) -> [String]? {
        var result: [String] = []
        result.reserveCapacity(values.count)
        for value in values {
            guard let text = string(value) else { return nil }
            result.append(text)
        }
        return result
    }

    private static func stringArray(_ values: [NativeArchiveJSON]?) -> [String]? {
        guard let values else { return nil }
        return stringArray(values)
    }

    private static func isStrictlySorted(_ values: [String]) -> Bool {
        guard values.count > 1 else { return true }
        for index in 1..<values.count where !values[index - 1].utf8.lexicographicallyPrecedes(values[index].utf8) {
            return false
        }
        return true
    }

    private static func isLowerHex(_ value: String, count: Int) -> Bool {
        value.utf8.count == count && value.utf8.allSatisfy {
            (48...57).contains($0) || (97...102).contains($0)
        }
    }

    private static func validIDName(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard bytes.count >= 4, bytes.count <= 255,
              bytes[0...2].elementsEqual(Array("id/".utf8)) else { return false }
        return bytes.dropFirst(3).allSatisfy {
            (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95 || $0 == 46
        }
    }

    private static func validRepository(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard bytes.count <= 200, value.hasPrefix("https://"),
              let slash = value.dropFirst(8).firstIndex(of: "/") else { return false }
        let host = String(value[value.index(value.startIndex, offsetBy: 8)..<slash])
        let path = value[value.index(after: slash)...]
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2, labels.allSatisfy({ label in
            let value = Array(label.utf8)
            guard !value.isEmpty, value.count <= 63,
                  value.first != 45, value.last != 45 else { return false }
            return value.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
        }) else { return false }

        let segments = path.split(separator: "/", omittingEmptySubsequences: false)
        guard !segments.isEmpty else { return false }
        return segments.allSatisfy { segment in
            let value = Array(segment.utf8)
            guard !value.isEmpty, segment != ".", segment != ".." else { return false }
            return value.allSatisfy {
                (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) ||
                    $0 == 46 || $0 == 95 || $0 == 45
            }
        }
    }

    private static func validCompressedSecp256k1KeySpelling(_ value: String) -> Bool {
        TrustSecp256k1Key.isValidCompressed(value)
    }
}

// Public input must be an actual secp256k1 point, not merely a 32-byte hex string.
// The field is small enough for this bounded, fixed-iteration modular check.
enum TrustSecp256k1Key {
    private typealias Words = [UInt64] // Little-endian 4-limb field element.
    private static let modulus: Words = [0xFFFFFFFEFFFFFC2F, .max, .max, .max]
    private static let sqrtExponent: Words = words(hex: "3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c")
    private static let zero: Words = [0, 0, 0, 0]
    private static let one: Words = [1, 0, 0, 0]

    static func isValidXOnly(_ value: String) -> Bool {
        guard value.utf8.count == 64, value.utf8.allSatisfy(isLowerHex),
              let x = parseHex(value), lessThan(x, modulus) else { return false }
        return hasSquareRoot(of: addMod(multiplyMod(multiplyMod(x, x), x), [7, 0, 0, 0]))
    }

    static func isValidCompressed(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard bytes.count == 66,
              bytes[0] == 48, bytes[1] == 50 || bytes[1] == 51,
              bytes.dropFirst(2).allSatisfy(isLowerHex),
              let x = parseHex(String(decoding: bytes.dropFirst(2), as: UTF8.self)), lessThan(x, modulus) else {
            return false
        }
        return hasSquareRoot(of: addMod(multiplyMod(multiplyMod(x, x), x), [7, 0, 0, 0]))
    }

    private static func hasSquareRoot(of value: Words) -> Bool {
        var result = one
        for bit in stride(from: 255, through: 0, by: -1) {
            result = multiplyMod(result, result)
            if bitIsSet(sqrtExponent, bit) { result = multiplyMod(result, value) }
        }
        return multiplyMod(result, result) == value
    }

    private static func multiplyMod(_ lhs: Words, _ rhs: Words) -> Words {
        var result = zero
        var addend = lhs
        for word in rhs {
            var bits = word
            for _ in 0..<64 {
                if bits & 1 == 1 { result = addMod(result, addend) }
                bits >>= 1
                addend = addMod(addend, addend)
            }
        }
        return result
    }

    private static func addMod(_ lhs: Words, _ rhs: Words) -> Words {
        // If lhs + rhs would reach p, subtracting p first avoids every
        // 257-bit carry case. Otherwise the limb sum is strictly below p.
        let distanceToModulus = subtract(modulus, rhs)
        if !lessThan(lhs, distanceToModulus) {
            return subtract(lhs, distanceToModulus)
        }

        var result = [UInt64](repeating: 0, count: 4)
        var carry = false
        for index in 0..<4 {
            let (partial, firstCarry) = lhs[index].addingReportingOverflow(rhs[index])
            let (sum, secondCarry) = partial.addingReportingOverflow(carry ? 1 : 0)
            result[index] = sum
            carry = firstCarry || secondCarry
        }
        return result
    }

    private static func subtract(_ lhs: Words, _ rhs: Words) -> Words {
        var result = [UInt64](repeating: 0, count: 4)
        var borrow = false
        for index in 0..<4 {
            let (partial, firstBorrow) = lhs[index].subtractingReportingOverflow(rhs[index])
            let (difference, secondBorrow) = partial.subtractingReportingOverflow(borrow ? 1 : 0)
            result[index] = difference
            borrow = firstBorrow || secondBorrow
        }
        return result
    }

    private static func lessThan(_ lhs: Words, _ rhs: Words) -> Bool {
        for index in stride(from: 3, through: 0, by: -1) {
            if lhs[index] != rhs[index] { return lhs[index] < rhs[index] }
        }
        return false
    }

    private static func bitIsSet(_ value: Words, _ bit: Int) -> Bool {
        (value[bit / 64] & (UInt64(1) << (bit % 64))) != 0
    }

    private static func isLowerHex(_ byte: UInt8) -> Bool {
        (48...57).contains(byte) || (97...102).contains(byte)
    }

    private static func parseHex(_ value: String) -> Words? {
        let bytes = Array(value.utf8)
        guard bytes.count == 64, bytes.allSatisfy(isLowerHex) else { return nil }
        var result = [UInt64](repeating: 0, count: 4)
        for index in 0..<32 {
            let high = nibble(bytes[index * 2])
            let low = nibble(bytes[index * 2 + 1])
            let destination = 31 - index
            result[destination / 8] |= UInt64((high << 4) | low) << ((destination % 8) * 8)
        }
        return result
    }

    private static func nibble(_ byte: UInt8) -> UInt8 {
        byte <= 57 ? byte - 48 : byte - 87
    }

    private static func words(hex: String) -> Words {
        // This constant is internal and fixed; malformed source is a programmer error.
        guard let result = parseHex(hex) else { preconditionFailure("invalid fixed secp256k1 exponent") }
        return result
    }
}
