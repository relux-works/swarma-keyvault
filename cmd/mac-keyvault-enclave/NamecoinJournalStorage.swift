// Internal macOS journal storage. No facade operation or exported C ABI.
// The linked engine must own its kernel gate before constructing/using this
// finite adapter and hold it through durable completion and secret cleanup.
import CryptoKit
import Darwin
import Foundation
import Security

// Closed internal outcomes; never attach localized OS/exception descriptions.
enum NativeJournalRefusal: Error, Equatable {
    case missing
    case authenticationRefused
    case mismatch
    case operational
    case unknown
}

func nativeJournalReadFailure(_ status: OSStatus) -> NativeJournalRefusal {
    switch status {
    case errSecItemNotFound: return .missing
    case errSecAuthFailed, errSecInteractionNotAllowed, errSecUserCanceled: return .authenticationRefused
    default: return .operational
    }
}

// Exact legacy ad-hoc and certificate runtime representations. This predicate
// alone proves neither code identity nor signature validity or root ACL authority.
// The actual helper check must also enforce its pinned hash and all other checks.
func nativeJournalAdmitsHelperCodeFlags(_ flags: UInt32) -> Bool {
    flags == 0x10002 || flags == 0x10000
}

// C-compatible owned memory. Raw account, child and intermediate secrets never
// become String, diagnostic, argv or serialized private-key representations.
// Borrowed pointers cannot outlive the synchronous closure. Not Sendable.
final class NativeSecretBytes: CustomStringConvertible, CustomDebugStringConvertible {
    private var allocation: UnsafeMutableRawPointer?
    let count: Int
    var description: String { "<confined native bytes>" }
    var debugDescription: String { description }

    init(copying source: UnsafeRawBufferPointer, maximum: Int) throws {
        guard source.count > 0, maximum > 0, maximum <= 65536,
              source.count <= maximum, let base = source.baseAddress else { throw NativeJournalRefusal.mismatch }
        guard let memory = malloc(source.count) else { throw NativeJournalRefusal.operational }
        count = source.count
        allocation = memory
        memory.copyMemory(from: base, byteCount: source.count)
    }

    func withBytes(_ consume: (UnsafeRawBufferPointer) throws -> Void) throws {
        guard let memory = allocation else { throw NativeJournalRefusal.operational }
        try consume(UnsafeRawBufferPointer(start: memory, count: count))
    }

    func clear() {
        if let memory = allocation {
            // Annex K memset_s is specified not to be removed as a dead store.
            // Failure is not ignored by substituting an optimizable Swift loop.
            if memset_s(memory, count, 0, count) != 0 { fatalError("native clear failed") }
            free(memory)
            allocation = nil
        }
    }
    deinit { clear() }
}

// Materialize public foreign-backed bytes too; Data(value) may otherwise keep
// a shared backing store. This helper is never used to copy private material.
func nativeJournalOwnedPublicData(_ value: Data) -> Data {
    if value.isEmpty { return Data() }
    return value.withUnsafeBytes { Data(bytes: $0.baseAddress!, count: $0.count) }
}

func nativeJournalLP(_ value: Data) -> Data {
    var length = UInt32(value.count).bigEndian
    var result = withUnsafeBytes(of: &length) { Data($0) }
    result.append(value)
    return result
}

func nativeJournalIdentity(_ value: String, purpose: String) -> Bool {
    let parts = value.split(separator: "/", omittingEmptySubsequences: false)
    guard parts.count == 2, (1...40).contains(parts[0].utf8.count),
          parts[0].utf8.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }),
          parts[1].hasPrefix(purpose + "@") else { return false }
    let version = parts[1].dropFirst(purpose.utf8.count + 1)
    guard let number = Int64(version), number > 0, number <= 2147483647,
          String(number) == version else { return false }
    return true
}

// Public facts frozen by the qualified local invocation, not parsed from a
// caller's approval bit, arbitrary item selector or mutable filesystem lookup.
// Sidecar bytes are the exact admitted local KVNS1 encoding supplied by the
// linked engine. This adapter validates their binding prefix before storing.
struct NativeJournalSelection {
    static let service = "works.relux.mac-keyvault.namecoin-journal.v1"
    static let schema = "keyvault-namecoin-journal/1"
    let group: String
    let account: String
    let publicPin: Data
    let policy: String
    let helperCDHash: Data
    let sidecar: Data
    let nostrAccount: String
    let locator: String
    let metadata: Data
    let anchorPrefix: Data
    let genesisHead: Data

    init(group: String, account: String, publicPin: Data, policy: String,
         helperCDHash: Data, sidecar: Data) throws {
        guard nativeJournalIdentity(group, purpose: "recovery"),
              nativeJournalIdentity(account, purpose: "namecoin"), publicPin.count == 32,
              (1...128).contains(policy.utf8.count), policy.utf8.allSatisfy({ (33...126).contains($0) }),
              helperCDHash.count == 20 || helperCDHash.count == 32,
              sidecar.count <= 640 else { throw NativeJournalRefusal.mismatch }
        var binding = nativeJournalLP(Data(group.utf8))
        binding.append(nativeJournalLP(Data(account.utf8)))
        let locatorBytes = Data(SHA256.hash(data: binding))
        locator = locatorBytes.map { String(format: "%02x", $0) }.joined()
        binding.append(publicPin)
        binding.append(nativeJournalLP(Data(policy.utf8)))
        var anchor = Data("KVNA1\0".utf8)
        anchor.append(binding)
        anchorPrefix = anchor
        var genesis = Data("keyvault/namecoin-journal-genesis/1\0".utf8)
        genesis.append(binding)
        genesisHead = Data(SHA256.hash(data: genesis))
        var prefix = Data("KVNS1\0".utf8)
        prefix.append(binding)
        guard sidecar.starts(with: prefix), sidecar.count >= prefix.count + 4 + 1 + 16 + 96 else {
            throw NativeJournalRefusal.mismatch
        }
        // Exact remainder: LP(existing Nostr identity), group16, three hashes32.
        let tail = Array(sidecar.dropFirst(prefix.count))
        let length = tail.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length <= 80, tail.count == 4 + Int(length) + 16 + 96,
              let nostr = String(bytes: tail[4..<4 + Int(length)], encoding: .utf8),
              nativeJournalIdentity(nostr, purpose: "nostr"),
              nostr.split(separator: "/")[0] == group.split(separator: "/")[0] else {
            throw NativeJournalRefusal.mismatch
        }
        self.group = group
        self.account = account
        self.publicPin = nativeJournalOwnedPublicData(publicPin)
        self.policy = policy
        self.helperCDHash = nativeJournalOwnedPublicData(helperCDHash)
        self.sidecar = nativeJournalOwnedPublicData(sidecar)
        self.nostrAccount = nostr
        // Public native metadata, never the anchor value/key/token. The sidecar
        // occupies only this NEW item's generic attribute; the pair is untouched.
        var attributes = Data((Self.schema + "\0").utf8)
        attributes.append(binding)
        attributes.append(nativeJournalLP(helperCDHash))
        attributes.append(nativeJournalLP(sidecar))
        metadata = attributes
    }
}

// Physical format/binding only. Neither this check nor public metadata can
// authenticate the confined key/token: the linked engine MUST verify its MAC and
// independently rederive account integrity before private use/reconciliation.
func nativeJournalAnchorSequence(_ bytes: UnsafeRawBufferPointer,
                                 selection: NativeJournalSelection,
                                 initializing: Bool = false) throws -> UInt64 {
    let prefix = selection.anchorPrefix
    guard bytes.count == prefix.count + 104, let base = bytes.baseAddress else { throw NativeJournalRefusal.mismatch }
    let matches = prefix.withUnsafeBytes { expected in
        timingsafe_bcmp(base, expected.baseAddress!, expected.count) == 0
    }
    guard matches else { throw NativeJournalRefusal.mismatch }
    var sequence: UInt64 = 0
    for index in prefix.count..<prefix.count + 8 { sequence = (sequence << 8) | UInt64(bytes[index]) }
    if initializing && sequence != 0 { throw NativeJournalRefusal.mismatch }
    if sequence == 0 {
        let correctGenesis = selection.genesisHead.withUnsafeBytes { expected in
            timingsafe_bcmp(base.advanced(by: prefix.count + 8), expected.baseAddress!, 32) == 0
        }
        guard correctGenesis else { throw NativeJournalRefusal.mismatch }
    }
    return sequence
}

// Same binding and integrity authority, exactly one monotonic journal step.
// This is still a shape check, not token/KDF authentication or native durability.
func nativeJournalRequireReplacement(previous: UnsafeRawBufferPointer,
                                     next: UnsafeRawBufferPointer,
                                     selection: NativeJournalSelection) throws {
    let oldSequence = try nativeJournalAnchorSequence(previous, selection: selection)
    let newSequence = try nativeJournalAnchorSequence(next, selection: selection)
    guard oldSequence < UInt64.max, newSequence == oldSequence + 1,
          let oldBase = previous.baseAddress, let newBase = next.baseAddress,
          timingsafe_bcmp(oldBase.advanced(by: selection.anchorPrefix.count + 40),
                          newBase.advanced(by: selection.anchorPrefix.count + 40), 32) == 0 else { throw NativeJournalRefusal.mismatch }
}

// One same-process reconciliation read. The item reference and raw protected
// bytes are frozen before review; a later check may refuse change but never
// replaces these bytes with a newly selected state after owner confirmation.
final class NativeFrozenJournalAnchor {
    fileprivate let reference: Data
    fileprivate let metadata: Data
    fileprivate let value: NativeSecretBytes
    fileprivate init(reference: Data, metadata: Data, value: NativeSecretBytes) {
        self.reference = reference
        self.metadata = metadata
        self.value = value
    }
    func withBytes(_ consume: (UnsafeRawBufferPointer) throws -> Void) throws { try value.withBytes(consume) }
    func clear() { value.clear() }
    deinit { clear() }
}

// Exactly one fixed service/account selection in the OS account's login
// Keychain. There is no list/delete/reset/adopt/arbitrary-query interface.
final class NativeNamecoinJournalStorage {
    let selection: NativeJournalSelection
    private let keychain: SecKeychain
    private let selfApplication: SecTrustedApplication
    private let selfApplicationData: Data

    init(selection: NativeJournalSelection) throws {
        self.selection = selection
        try Self.verifyRunningHelper(selection.helperCDHash)
        var app: SecTrustedApplication?
        var status = SecTrustedApplicationCreateFromPath(nil, &app)
        guard status == errSecSuccess, let actual = app else { throw NativeJournalRefusal.operational }
        var applicationData: CFData?
        status = SecTrustedApplicationCopyData(actual, &applicationData)
        guard status == errSecSuccess, let encoded = applicationData else { throw NativeJournalRefusal.operational }
        selfApplication = actual
        selfApplicationData = encoded as Data
        // This finite helper never changes the process setting back to enable a
        // Keychain prompt. Biometric review uses its own fresh LAContext instead.
        guard SecKeychainSetUserInteractionAllowed(false) == errSecSuccess else { throw NativeJournalRefusal.operational }
        keychain = try Self.openAccountLoginKeychain()
    }

    private static func openAccountLoginKeychain() throws -> SecKeychain {
        var entry = passwd()
        var found: UnsafeMutablePointer<passwd>?
        var buffer = [CChar](repeating: 0, count: 16384)
        let status = buffer.withUnsafeMutableBufferPointer {
            getpwuid_r(getuid(), &entry, $0.baseAddress, $0.count, &found)
        }
        guard status == 0, found != nil, let home = entry.pw_dir else { throw NativeJournalRefusal.operational }
        // Public OS account path, never environment HOME or changed default.
        let path = String(cString: home) + "/Library/Keychains/login.keychain-db"
        var reference: SecKeychain?
        let opened = path.withCString { SecKeychainOpen($0, &reference) }
        guard opened == errSecSuccess, let login = reference else { throw nativeJournalReadFailure(opened) }
        var state: SecKeychainStatus = 0
        let checked = SecKeychainGetStatus(login, &state)
        guard checked == errSecSuccess, state & SecKeychainStatus(kSecUnlockStateStatus) != 0 else {
            throw NativeJournalRefusal.authenticationRefused
        }
        return login
    }

    private static func verifyRunningHelper(_ expectedHash: Data) throws {
        var code: SecCode?
        guard SecCodeCopySelf(SecCSFlags(rawValue: 0), &code) == errSecSuccess, let running = code,
              SecCodeCheckValidity(running, SecCSFlags(rawValue: kSecCSStrictValidate), nil) == errSecSuccess else {
            throw NativeJournalRefusal.mismatch
        }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(running, SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSDynamicInformation), &information) == errSecSuccess,
              let facts = information as? [String: Any],
              let flags = facts[kSecCodeInfoFlags as String] as? NSNumber,
              let dynamic = facts[kSecCodeInfoStatus as String] as? NSNumber,
              let hash = facts[kSecCodeInfoUnique as String] as? Data,
              nativeJournalAdmitsHelperCodeFlags(flags.uint32Value), dynamic.uint32Value & 0x10000 != 0,
              dynamic.uint32Value & 1 != 0, dynamic.uint32Value & 0x10000000 == 0,
              hash == expectedHash else { throw NativeJournalRefusal.mismatch }
        if let entitlements = facts[kSecCodeInfoEntitlementsDict as String] {
            guard let dictionary = entitlements as? [String: Any], dictionary.isEmpty else { throw NativeJournalRefusal.mismatch }
        }
    }

    private func query() -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: NativeJournalSelection.service,
         kSecAttrAccount as String: selection.locator,
         kSecMatchSearchList as String: [keychain]]
    }

    private func selectedItem() throws -> SecKeychainItem {
        var request = query()
        request[kSecMatchLimit as String] = kSecMatchLimitAll
        request[kSecReturnRef as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        guard status == errSecSuccess else { throw nativeJournalReadFailure(status) }
        guard let rows = result as? [SecKeychainItem], rows.count == 1 else { throw NativeJournalRefusal.mismatch }
        let item = rows[0]
        var actualKeychain: SecKeychain?
        guard SecKeychainItemCopyKeychain(item, &actualKeychain) == errSecSuccess,
              let actual = actualKeychain, CFEqual(actual, keychain) else { throw NativeJournalRefusal.mismatch }
        try validatePublicAttributes(item)
        try validateSoleHelperDecrypt(item)
        return item
    }

    private func validatePublicAttributes(_ item: SecKeychainItem) throws {
        let request: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                     kSecMatchItemList as String: [item],
                                     kSecMatchSearchList as String: [keychain],
                                     kSecReturnAttributes as String: true]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        guard status == errSecSuccess else { throw nativeJournalReadFailure(status) }
        guard let attributes = result as? [String: Any],
              attributes[kSecAttrService as String] as? String == NativeJournalSelection.service,
              attributes[kSecAttrAccount as String] as? String == selection.locator,
              attributes[kSecAttrLabel as String] as? String == selection.locator,
              attributes[kSecAttrComment as String] as? String == NativeJournalSelection.schema,
              attributes[kSecAttrGeneric as String] as? Data == selection.metadata else { throw NativeJournalRefusal.mismatch }
    }

    private func validateSoleHelperDecrypt(_ item: SecKeychainItem) throws {
        var access: SecAccess?
        guard SecKeychainItemCopyAccess(item, &access) == errSecSuccess, let access = access,
              let acls = SecAccessCopyMatchingACLList(access, kSecACLAuthorizationDecrypt) as? [SecACL],
              !acls.isEmpty else { throw NativeJournalRefusal.mismatch }
        for acl in acls {
            var apps: CFArray?
            var description: CFString?
            var prompt: SecKeychainPromptSelector = 0
            guard SecACLCopyContents(acl, &apps, &description, &prompt) == errSecSuccess,
                  let applications = apps as? [SecTrustedApplication], applications.count == 1 else { throw NativeJournalRefusal.mismatch }
            var data: CFData?
            guard SecTrustedApplicationCopyData(applications[0], &data) == errSecSuccess,
                  let actual = data, (actual as Data) == selfApplicationData else { throw NativeJournalRefusal.mismatch }
        }
    }

    private func persistentReference(_ item: SecKeychainItem) throws -> Data {
        var result: CFData?
        guard SecKeychainItemCreatePersistentReference(item, &result) == errSecSuccess,
              let reference = result else { throw NativeJournalRefusal.operational }
        return reference as Data
    }

    private func withValue(_ item: SecKeychainItem, consume: (UnsafeRawBufferPointer) throws -> Void) throws {
        // Recheck finite public binding and sole-helper policy before secret read.
        try validatePublicAttributes(item)
        try validateSoleHelperDecrypt(item)
        var length: UInt32 = 0
        var raw: UnsafeMutableRawPointer?
        let status = SecKeychainItemCopyAttributesAndData(item, nil, nil, nil, &length, &raw)
        defer {
            if let raw = raw {
                if memset_s(raw, Int(length), 0, Int(length)) != 0 { fatalError("native clear failed") }
                SecKeychainItemFreeAttributesAndData(nil, raw)
            }
        }
        guard status == errSecSuccess else { throw nativeJournalReadFailure(status) }
        guard length > 0, length <= 512, let bytes = raw else { throw NativeJournalRefusal.mismatch }
        let borrowed = UnsafeRawBufferPointer(start: bytes, count: Int(length))
        _ = try nativeJournalAnchorSequence(borrowed, selection: selection)
        try consume(borrowed)
    }

    // Read existing state only. Missing/deleted state is a fixed refusal, never
    // initialization, reset, empty history or proof that nothing was signed.
    func withExistingAnchor(_ consume: (UnsafeRawBufferPointer) throws -> Void) throws {
        try withValue(selectedItem(), consume: consume)
    }

    func freezeExistingAnchorForReconciliation() throws -> NativeFrozenJournalAnchor {
        let item = try selectedItem()
        let reference = try persistentReference(item)
        var owned: NativeSecretBytes?
        try withValue(item) { owned = try NativeSecretBytes(copying: $0, maximum: 512) }
        guard let frozen = owned else { throw NativeJournalRefusal.operational }
        return NativeFrozenJournalAnchor(reference: reference, metadata: selection.metadata, value: frozen)
    }

    func verifyFrozenAnchorUnchanged(_ frozen: NativeFrozenJournalAnchor) throws {
        guard frozen.metadata == selection.metadata else { throw NativeJournalRefusal.mismatch }
        let item = try selectedItem()
        guard try persistentReference(item) == frozen.reference else { throw NativeJournalRefusal.mismatch }
        try compareValue(item, frozen.value)
    }

    func requireAbsentForExplicitInitialization() throws {
        do { _ = try selectedItem() }
        catch NativeJournalRefusal.missing { return }
        throw NativeJournalRefusal.mismatch
    }

    // Separate initialize plumbing calls this after its own complete review and
    // fresh biometric unseal/KDF. There is no ECDSA or paired-item write here.
    // Sidecar/public metadata and secret anchor are created together in ONE new
    // item. Existing/conflicting state is never updated, deleted or recreated.
    func createInitializedAnchor(_ value: NativeSecretBytes) throws {
        guard value.count <= 512 else { throw NativeJournalRefusal.mismatch }
        try value.withBytes { _ = try nativeJournalAnchorSequence($0, selection: selection, initializing: true) }
        try requireAbsentForExplicitInitialization()
        var access: SecAccess?
        guard SecAccessCreate("Namecoin journal anchor" as CFString, [selfApplication] as CFArray, &access) == errSecSuccess,
              let policy = access else { throw NativeJournalRefusal.operational }
        var request: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                     kSecUseKeychain as String: keychain,
                                     kSecAttrService as String: NativeJournalSelection.service,
                                     kSecAttrAccount as String: selection.locator,
                                     kSecAttrLabel as String: selection.locator,
                                     kSecAttrComment as String: NativeJournalSelection.schema,
                                     kSecAttrGeneric as String: selection.metadata,
                                     kSecAttrAccess as String: policy,
                                     kSecReturnRef as String: true]
        var created: CFTypeRef?
        var mutationStatus: OSStatus = errSecParam
        try value.withBytes { bytes in
            // Non-owning view, synchronous call; no Swift secret Data copy.
            guard let base = bytes.baseAddress,
                  let view = CFDataCreateWithBytesNoCopy(nil, base.assumingMemoryBound(to: UInt8.self), bytes.count, kCFAllocatorNull) else { throw NativeJournalRefusal.operational }
            request[kSecValueData as String] = view
            mutationStatus = SecItemAdd(request as CFDictionary, &created)
            request.removeValue(forKey: kSecValueData as String)
        }
        if mutationStatus == errSecDuplicateItem { throw NativeJournalRefusal.mismatch }
        guard mutationStatus == errSecSuccess else { throw NativeJournalRefusal.unknown }
        do {
            guard let created = created, CFGetTypeID(created) == SecKeychainItemGetTypeID() else { throw NativeJournalRefusal.unknown }
            let item = unsafeBitCast(created, to: SecKeychainItem.self)
            try verifyExactStoredValue(value, expectedReference: persistentReference(item))
        } catch { throw NativeJournalRefusal.unknown }
    }

    // Expected bytes and persistent reference detect replacement under the gate;
    // they are NOT a Keychain compare-and-swap. No attribute/ACL write is made.
    // Any attempted mutation/readback uncertainty is preserved as UNKNOWN.
    func replaceExistingAnchor(expected: NativeSecretBytes, replacement: NativeSecretBytes) throws {
        guard expected.count <= 512, replacement.count <= 512 else { throw NativeJournalRefusal.mismatch }
        try expected.withBytes { previous in
            try replacement.withBytes { next in
                try nativeJournalRequireReplacement(previous: previous, next: next, selection: selection)
            }
        }
        let item = try selectedItem()
        let reference = try persistentReference(item)
        try compareValue(item, expected)
        var mutationStatus: OSStatus = errSecParam
        try replacement.withBytes { bytes in
            mutationStatus = SecKeychainItemModifyAttributesAndData(item, nil, UInt32(bytes.count), bytes.baseAddress)
        }
        guard mutationStatus == errSecSuccess else { throw NativeJournalRefusal.unknown }
        do { try verifyExactStoredValue(replacement, expectedReference: reference) }
        catch { throw NativeJournalRefusal.unknown }
    }

    private func compareValue(_ item: SecKeychainItem, _ expected: NativeSecretBytes) throws {
        try withValue(item) { actual in
            try expected.withBytes { wanted in
                guard actual.count == wanted.count else { throw NativeJournalRefusal.mismatch }
                guard let actualBase = actual.baseAddress, let wantedBase = wanted.baseAddress,
                      timingsafe_bcmp(actualBase, wantedBase, actual.count) == 0 else { throw NativeJournalRefusal.mismatch }
            }
        }
    }

    private func verifyExactStoredValue(_ expected: NativeSecretBytes, expectedReference: Data?) throws {
        let item = try selectedItem()
        if let reference = expectedReference, try persistentReference(item) != reference { throw NativeJournalRefusal.mismatch }
        try compareValue(item, expected)
    }
}

// This is an internal initialization/reconciliation document, not a PSBT review
// frame or facade schema. Every byte of the immutable public selected plan is
// bound here; the actual transaction review frame remains the engine's contract.
struct NativeJournalOperationPlan {
    enum Kind: String { case initialize, reconcile }
    let kind: Kind
    let selection: NativeJournalSelection
    let adoptionPlanDigest: Data
    let reviewFrame: Data

    init(kind: Kind, selection: NativeJournalSelection, adoptionPlanDigest: Data) throws {
        guard adoptionPlanDigest.count == 32 else { throw NativeJournalRefusal.mismatch }
        self.kind = kind
        self.selection = selection
        self.adoptionPlanDigest = nativeJournalOwnedPublicData(adoptionPlanDigest)
        var frame = Data("keyvault/namecoin-journal-native-review/1\0".utf8)
        frame.append(nativeJournalLP(Data(kind.rawValue.utf8)))
        frame.append(nativeJournalLP(selection.metadata))
        frame.append(adoptionPlanDigest)
        reviewFrame = frame
    }

}
