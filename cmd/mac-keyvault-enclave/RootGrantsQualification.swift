import CoreFoundation
import CryptoKit
import Darwin
import Dispatch
import Foundation
import Security

// Permanent finite PUBLIC-marker negative control, never a root/pair browser,
// private-account operation, presence service or receipt filesystem reader.
enum RootGrantsQualificationError: Error { case refused }

enum RootGrantsQualificationWire {
    static let entry = "--root-grants-qualification-read"
    static let schema = "keyvault-root-acl-qualification/1"
    static let namespace = "works.relux.mac-keyvault.root-acl-qualification.v1"
    static let account = "public-marker@1"
    static let itemClass = "generic-password"
    static let maximumRequest = 32768
    static let maximumReference = 16384

    static func requireArguments(_ arguments: [String]) throws {
        guard arguments.count == 2, arguments[1] == entry else { throw RootGrantsQualificationError.refused }
    }
    static func length(_ bytes: Data) throws -> Int {
        guard bytes.count == 4 else { throw RootGrantsQualificationError.refused }
        let count = bytes.reduce(0) { ($0 << 8) | Int($1) }
        guard (1...maximumRequest).contains(count) else { throw RootGrantsQualificationError.refused }
        return count
    }
    static func word(_ count: UInt32) -> Data {
        var value = count.bigEndian
        return withUnsafeBytes(of: &value) { Data($0) }
    }
    // Exact slice framing only; this does not establish a canonical request.
    static func body(_ frame: Data) throws -> Data {
        guard frame.count >= 4 else { throw RootGrantsQualificationError.refused }
        let count = try length(Data(frame.prefix(4)))
        guard frame.count == count + 4 else { throw RootGrantsQualificationError.refused }
        return frame.dropFirst(4).withUnsafeBytes { Data($0) }
    }
}

struct RootGrantsQualificationRequest {
    let originalBytes: Data
    let reference: Data
    let receiptSHA256: String

    init(ownedJSON: Data) throws {
        guard (1...RootGrantsQualificationWire.maximumRequest).contains(ownedJSON.count) else {
            throw RootGrantsQualificationError.refused
        }
        let raw = ownedJSON.withUnsafeBytes { Data($0) }
        guard (1...RootGrantsQualificationWire.maximumRequest).contains(raw.count),
              let object = try? JSONSerialization.jsonObject(with: raw),
              let fields = object as? [String: String], fields.count == 6,
              fields["schema"] == RootGrantsQualificationWire.schema,
              fields["namespace"] == RootGrantsQualificationWire.namespace,
              fields["account"] == RootGrantsQualificationWire.account,
              fields["item_class"] == RootGrantsQualificationWire.itemClass,
              let encoded = fields["persistent_reference"], let digest = fields["receipt_sha256"],
              let decoded = Data(base64Encoded: encoded),
              (1...RootGrantsQualificationWire.maximumReference).contains(decoded.count),
              decoded.base64EncodedString() == encoded,
              digest.utf8.count == 64,
              digest.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw RootGrantsQualificationError.refused
        }
        // Only fixed ASCII fields, canonical base64 and lowerhex reach this
        // encoding. Exact equality rejects duplicate/reordered/escaped/extra
        // fields and whitespace instead of normalizing them into admission.
        let canonical = Data(#"{"schema":"\#(RootGrantsQualificationWire.schema)","namespace":"\#(RootGrantsQualificationWire.namespace)","account":"\#(RootGrantsQualificationWire.account)","item_class":"\#(RootGrantsQualificationWire.itemClass)","persistent_reference":"\#(decoded.base64EncodedString())","receipt_sha256":"\#(digest)"}"#.utf8)
        guard canonical == raw else { throw RootGrantsQualificationError.refused }
        originalBytes = raw
        reference = decoded.withUnsafeBytes { Data($0) }
        receiptSHA256 = digest // Public binding only; never file/consent authority.
    }

    // The actual probe adds ONLY its OS-selected login Keychain search list.
    // No direct-reference useItems path, supplied namespace or return-data query.
    func metadataFilters() -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: RootGrantsQualificationWire.namespace,
         kSecAttrAccount as String: RootGrantsQualificationWire.account,
         kSecMatchItemList as String: [reference as CFData],
         kSecMatchLimit as String: kSecMatchLimitOne,
         kSecReturnRef as String: true]
    }
}

enum RootGrantsQualificationResult: String, CaseIterable {
    case accessRefused = "access-refused"
    case unexpectedAccess = "unexpected-access"
    case unqualified = "unqualified"
    var response: Data {
        Data((#"{"schema":"keyvault-root-acl-qualification/1","result":"\#(rawValue)"}"# + "\n").utf8)
    }
    enum Stage: Equatable, CaseIterable { case startup, selection, metadata, markerData }
    // Only the actual marker-data API status may classify an intended denial.
    // ANY successful data access fails qualification, regardless of value bytes.
    static func classify(_ status: OSStatus, at stage: Stage) -> Self {
        guard stage == .markerData else { return .unqualified }
        if status == errSecSuccess { return .unexpectedAccess }
        if status == errSecAuthFailed || status == errSecInteractionNotAllowed { return .accessRefused }
        return .unqualified
    }
}

// Pure public representation checks. Facts constructed in software are NOT
// code admission; the actual probe always executes native signature checks.
struct RootGrantsQualificationCodeFacts {
    var identifier: String
    var team: String
    var flags: UInt32
    var dynamic: UInt32
    var codeHash: Data
    var expectedRequirement: Data
    var actualRequirement: Data
    var leafSHA1: String
    var leafSHA256: String
}
enum RootGrantsQualificationIdentity {
    static let runningValidationFlags = SecCSFlags(rawValue: kSecCSStrictValidate).union(.noNetworkAccess)
    static let staticValidationFlags = runningValidationFlags.union(SecCSFlags(rawValue: kSecCSCheckAllArchitectures))
    static let identifier = "works.relux.keyvault.enclave"
    static let team = "262RZ595FP"
    static let leafSHA1 = "d71190abe54185f908169ee9ca538d4066942c0f"
    static let leafSHA256 = "b315ed0ac55f58d4dbcfc3ce4f7937f6ed058277feba7e4aa3e64bd10b17d3a1"
    static let requirement = #"identifier "works.relux.keyvault.enclave" and anchor apple generic and certificate leaf = H"d71190abe54185f908169ee9ca538d4066942c0f" and certificate 1[field.1.2.840.113635.100.6.2.1]"#

    static func requireSymbols(copy: UnsafeMutableRawPointer?, create: UnsafeMutableRawPointer?) throws {
        guard copy != nil, create != nil else { throw RootGrantsQualificationError.refused }
    }
    static func exactUInt32(_ value: Any?) throws -> UInt32 {
        guard let value, CFGetTypeID(value as CFTypeRef) == CFNumberGetTypeID() else {
            throw RootGrantsQualificationError.refused
        }
        let number = value as! CFNumber // Type ID checked; never a function pointer.
        var integer: Int64 = 0
        guard !CFNumberIsFloatType(number), CFNumberGetValue(number, .sInt64Type, &integer),
              integer >= 0, integer <= Int64(UInt32.max) else { throw RootGrantsQualificationError.refused }
        return UInt32(integer)
    }
    static func requireEmptyEntitlements(_ value: Any?) throws {
        guard let value else { return } // Absent and a real empty dictionary are valid.
        guard let dictionary = value as? [String: Any], dictionary.isEmpty else { throw RootGrantsQualificationError.refused }
    }
    static func require(_ facts: RootGrantsQualificationCodeFacts) throws {
        guard facts.identifier == identifier, facts.team == team, facts.flags == 0x10000,
              facts.dynamic & 0x10001 == 0x10001, facts.dynamic & 0x10000000 == 0,
              [20, 32].contains(facts.codeHash.count),
              (1...32768).contains(facts.expectedRequirement.count),
              facts.actualRequirement == facts.expectedRequirement,
              facts.leafSHA1 == leafSHA1, facts.leafSHA256 == leafSHA256 else {
            throw RootGrantsQualificationError.refused
        }
    }
}

struct RootGrantsQualificationDeadline {
    static let budget: UInt64 = 30_000_000_000
    let startedAt: UInt64
    var expiresAt: UInt64 {
        let (value, overflow) = startedAt.addingReportingOverflow(Self.budget)
        return overflow ? UInt64.max : value
    }
    func check(at now: UInt64 = DispatchTime.now().uptimeNanoseconds) throws {
        guard now >= startedAt, now - startedAt < Self.budget else { throw RootGrantsQualificationError.refused }
    }
}

private enum RootGrantsQualificationNative {
    // Both system SPI addresses are checked only for presence, before ANY
    // Keychain API. No SPI prototype is guessed or invoked by this read path.
    static func read(_ request: RootGrantsQualificationRequest,
                     deadline: RootGrantsQualificationDeadline) -> RootGrantsQualificationResult {
        guard let security = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW | RTLD_LOCAL) else {
            return .unqualified
        }
        defer { _ = dlclose(security) }
        do {
            try deadline.check()
            try RootGrantsQualificationIdentity.requireSymbols(
                copy: dlsym(security, "SecTrustedApplicationCopyRequirement"),
                create: dlsym(security, "SecTrustedApplicationCreateFromRequirement"))
            try verifyRunningHelper()
            try deadline.check()
            let login = try loginKeychain()
            try deadline.check()
            var query = request.metadataFilters()
            query[kSecMatchSearchList as String] = [login]
            var result: CFTypeRef?
            guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
                  let actual = result, CFGetTypeID(actual) == SecKeychainItemGetTypeID() else {
                throw RootGrantsQualificationError.refused
            }
            let item = actual as! SecKeychainItem // Exact returned native type checked.
            try deadline.check()
            try verifyMetadata(item)
            try deadline.check()
            return readMarker(item) // The ONLY data read and denial classifier.
        } catch { return .unqualified } // No raw OS/caller text or value escapes.
    }

    private static func verifyRunningHelper() throws {
        guard getuid() == geteuid() else { throw RootGrantsQualificationError.refused }
        let zero = SecCSFlags(rawValue: 0)
        var expected: SecRequirement?, actual: SecRequirement?
        var running: SecCode?, code: SecStaticCode?
        var expectedData: CFData?, actualData: CFData?, information: CFDictionary?
        guard SecRequirementCreateWithString(RootGrantsQualificationIdentity.requirement as CFString, zero, &expected) == errSecSuccess,
              let expected,
              SecCodeCopySelf(zero, &running) == errSecSuccess, let running,
              SecCodeCheckValidity(running, RootGrantsQualificationIdentity.runningValidationFlags, expected) == errSecSuccess,
              SecCodeCopyStaticCode(running, zero, &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, RootGrantsQualificationIdentity.staticValidationFlags, expected) == errSecSuccess,
              SecCodeCopyDesignatedRequirement(code, zero, &actual) == errSecSuccess, let actual,
              SecRequirementCopyData(expected, zero, &expectedData) == errSecSuccess, let expectedData,
              SecRequirementCopyData(actual, zero, &actualData) == errSecSuccess, let actualData,
              copyRunningCodeSigningInformation(running, SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSDynamicInformation), &information) == errSecSuccess,
              let dictionary = information as? [String: Any],
              let identifier = dictionary[kSecCodeInfoIdentifier as String] as? String,
              let team = dictionary[kSecCodeInfoTeamIdentifier as String] as? String,
              let codeHash = dictionary[kSecCodeInfoUnique as String] as? Data,
              let certificates = dictionary[kSecCodeInfoCertificates as String] as? [AnyObject],
              let certificate = certificates.first, CFGetTypeID(certificate) == SecCertificateGetTypeID() else {
            throw RootGrantsQualificationError.refused
        }
        try RootGrantsQualificationIdentity.requireEmptyEntitlements(dictionary[kSecCodeInfoEntitlementsDict as String])
        let leaf = SecCertificateCopyData(certificate as! SecCertificate) as Data
        guard (1...32768).contains(leaf.count) else { throw RootGrantsQualificationError.refused }
        let facts = RootGrantsQualificationCodeFacts(identifier: identifier, team: team,
            flags: try RootGrantsQualificationIdentity.exactUInt32(dictionary[kSecCodeInfoFlags as String]),
            dynamic: try RootGrantsQualificationIdentity.exactUInt32(dictionary[kSecCodeInfoStatus as String]),
            codeHash: codeHash, expectedRequirement: expectedData as Data, actualRequirement: actualData as Data,
            leafSHA1: Insecure.SHA1.hash(data: leaf).map { String(format: "%02x", $0) }.joined(),
            leafSHA256: SHA256.hash(data: leaf).map { String(format: "%02x", $0) }.joined())
        try RootGrantsQualificationIdentity.require(facts)
    }

    private static func loginKeychain() throws -> SecKeychain {
        guard SecKeychainSetUserInteractionAllowed(false) == errSecSuccess else { throw RootGrantsQualificationError.refused }
        var buffer = [CChar](repeating: 0, count: 16384)
        let name: String = try buffer.withUnsafeMutableBufferPointer { bytes in
            var entry = passwd()
            var found: UnsafeMutablePointer<passwd>?
            guard getpwuid_r(getuid(), &entry, bytes.baseAddress, bytes.count, &found) == 0,
                  found != nil, entry.pw_uid == getuid(), let home = entry.pw_dir,
                  let name = String(validatingUTF8: home), name.hasPrefix("/") else {
                throw RootGrantsQualificationError.refused
            }
            return name // Copy while the passwd buffer is still borrowed.
        }
        let path = name + "/Library/Keychains/login.keychain-db"
        guard path.utf8.count < Int(PATH_MAX) else { throw RootGrantsQualificationError.refused }
        var opened: SecKeychain?
        guard path.withCString({ SecKeychainOpen($0, &opened) }) == errSecSuccess, let login = opened else {
            throw RootGrantsQualificationError.refused
        }
        var actual = [CChar](repeating: 0, count: Int(PATH_MAX))
        var length = UInt32(actual.count), state: SecKeychainStatus = 0
        let copied = actual.withUnsafeMutableBufferPointer { SecKeychainGetPath(login, &length, $0.baseAddress!) }
        guard copied == errSecSuccess, length == UInt32(path.utf8.count), Int(length) < actual.count,
              actual.prefix(Int(length)).map({ UInt8(bitPattern: $0) }) == Array(path.utf8),
              SecKeychainGetStatus(login, &state) == errSecSuccess,
              state & SecKeychainStatus(kSecUnlockStateStatus) != 0 else { throw RootGrantsQualificationError.refused }
        return login
    }

    private static func verifyMetadata(_ item: SecKeychainItem) throws {
        var tags = [SecItemAttr.serviceItemAttr.rawValue, SecItemAttr.accountItemAttr.rawValue]
        var formats = [UInt32(CSSM_DB_ATTRIBUTE_FORMAT_STRING), UInt32(CSSM_DB_ATTRIBUTE_FORMAT_STRING)]
        var itemClass: SecItemClass = .internetPasswordItemClass // Must be overwritten with the exact generic class.
        var attributes: UnsafeMutablePointer<SecKeychainAttributeList>?
        defer { if let attributes { _ = SecKeychainItemFreeAttributesAndData(attributes, nil) } }
        let status = tags.withUnsafeMutableBufferPointer { tags in
            formats.withUnsafeMutableBufferPointer { formats in
                var info = SecKeychainAttributeInfo(count: 2, tag: tags.baseAddress!, format: formats.baseAddress)
                return SecKeychainItemCopyAttributesAndData(item, &info, &itemClass, &attributes, nil, nil)
            }
        }
        guard status == errSecSuccess, itemClass == .genericPasswordItemClass,
              let list = attributes?.pointee, list.count == 2, let values = list.attr else {
            throw RootGrantsQualificationError.refused
        }
        for (offset, expected) in [RootGrantsQualificationWire.namespace, RootGrantsQualificationWire.account].enumerated() {
            let attribute = values[offset]
            let tag = offset == 0 ? SecItemAttr.serviceItemAttr.rawValue : SecItemAttr.accountItemAttr.rawValue
            guard attribute.tag == tag, attribute.length == UInt32(expected.utf8.count), let data = attribute.data,
                  UnsafeRawBufferPointer(start: data, count: Int(attribute.length)).elementsEqual(expected.utf8) else {
                throw RootGrantsQualificationError.refused
            }
        }
    }

    private static func readMarker(_ item: SecKeychainItem) -> RootGrantsQualificationResult {
        var count: UInt32 = 0
        var bytes: UnsafeMutableRawPointer?
        let status = SecKeychainItemCopyAttributesAndData(item, nil, nil, nil, &count, &bytes)
        // Never make Data/String/log/output from this OS-owned value, including
        // an unexpected success with different/empty bytes. Clear then OS-free.
        if let bytes {
            if memset_s(bytes, Int(count), 0, Int(count)) != 0 { _exit(1) }
            _ = SecKeychainItemFreeAttributesAndData(nil, bytes)
        }
        return RootGrantsQualificationResult.classify(status, at: .markerData)
    }
}

private final class RootGrantsQualificationTransport {
    private let input: RootGrantsPrivatePipeIdentity
    private let output: RootGrantsPrivatePipeIdentity
    private let deadline: RootGrantsQualificationDeadline
    init(deadline: RootGrantsQualificationDeadline) throws {
        self.deadline = deadline
        // Reuse only the existing actual kernel anonymous-pipe classifier. It
        // performs no private/C-session/TTY/native-account operation.
        input = try RootGrantsPrivatePipes.identity(STDIN_FILENO, writing: false)
        output = try RootGrantsPrivatePipes.identity(STDOUT_FILENO, writing: true)
        guard input.handle != output.handle else { throw RootGrantsQualificationError.refused }
    }
    private func ready(_ fd: Int32, writing: Bool) throws {
        let expected = writing ? output : input
        guard try RootGrantsPrivatePipes.identity(fd, writing: writing) == expected else { throw RootGrantsQualificationError.refused }
        while true {
            try deadline.check()
            var state = pollfd(fd: fd, events: Int16(writing ? POLLOUT : POLLIN), revents: 0)
            let result = poll(&state, 1, 100)
            if result < 0, errno == EINTR { continue }
            guard result >= 0 else { throw RootGrantsQualificationError.refused }
            if result == 0 { continue }
            guard state.revents & Int16(POLLERR | POLLNVAL) == 0 else { throw RootGrantsQualificationError.refused }
            return
        }
    }
    private func readBytes(_ count: Int) throws -> Data {
        var bytes = Data()
        while bytes.count < count {
            try ready(STDIN_FILENO, writing: false)
            var part = [UInt8](repeating: 0, count: min(4096, count - bytes.count))
            let capacity = part.count
            let received = part.withUnsafeMutableBytes { Darwin.read(STDIN_FILENO, $0.baseAddress, capacity) }
            if received < 0, errno == EINTR { continue }
            guard received > 0 else { throw RootGrantsQualificationError.refused }
            bytes.append(contentsOf: part.prefix(received))
        }
        return bytes
    }
    func request() throws -> RootGrantsQualificationRequest {
        let count = try RootGrantsQualificationWire.length(readBytes(4))
        let bytes = try readBytes(count)
        while true {
            try ready(STDIN_FILENO, writing: false)
            var trailing: UInt8 = 0
            let count = Darwin.read(STDIN_FILENO, &trailing, 1)
            if count < 0, errno == EINTR { continue }
            guard count == 0 else { throw RootGrantsQualificationError.refused }
            break
        }
        return try RootGrantsQualificationRequest(ownedJSON: bytes)
    }
    func respond(_ result: RootGrantsQualificationResult) throws {
        let bytes = result.response
        try ready(STDOUT_FILENO, writing: true)
        let count = bytes.withUnsafeBytes { Darwin.write(STDOUT_FILENO, $0.baseAddress, bytes.count) }
        guard count == bytes.count else { throw RootGrantsQualificationError.refused }
        try deadline.check()
    }
}

// One request, one silent read attempt, only fixed status bytes. There is no
// receipt file, private ABI, native prompt, Enclave, retry or cleanup mutation.
func rootGrantsQualificationRead() -> Int32 {
    let deadline = RootGrantsQualificationDeadline(startedAt: DispatchTime.now().uptimeNanoseconds)
    do { try RootGrantsQualificationWire.requireArguments(CommandLine.arguments) }
    catch { return 1 }
    let queue = DispatchQueue(label: "keyvault.root-marker-deadline")
    signal(SIGTERM, SIG_IGN); signal(SIGPIPE, SIG_IGN)
    let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: queue)
    termination.setEventHandler { _exit(1) } // Safe queue, never an async handler.
    termination.resume()
    let timeout = DispatchSource.makeTimerSource(queue: queue)
    timeout.schedule(deadline: DispatchTime(uptimeNanoseconds: deadline.expiresAt))
    // Synchronous Security APIs have no finite cancellation primitive. This
    // public-only child ends nonzero even if an OS call is stuck. No private
    // C session/TTY state exists; parent still owns its exact-PID TERM grace.
    timeout.setEventHandler { _exit(1) }
    timeout.resume()
    defer { timeout.cancel(); termination.cancel() }
    do {
        let transport = try RootGrantsQualificationTransport(deadline: deadline)
        let request = try transport.request()
        try deadline.check()
        let result = RootGrantsQualificationNative.read(request, deadline: deadline)
        try deadline.check()
        try transport.respond(result)
        try deadline.check()
        return 0
    } catch { return 1 } // Malformed/fatal protocol: no raw text or second output.
}
