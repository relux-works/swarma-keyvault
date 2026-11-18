import CoreFoundation
import CryptoKit
import Darwin
import Dispatch
import Foundation
import Security

enum AgentNostrPrivateRuntimeError: Error {
    case parentNotAdmitted
    case deadlineExpired
    case transport
}

enum AgentNostrPrivateStatus: String, CaseIterable {
    case badRequest = "bad_request"
    case invalidBlob = "invalid_blob"
    case policyRefused = "policy_refused"
    case presenceRequired = "presence_required"
    case authRefused = "auth_refused"
    case enclaveUnavailable = "enclave_unavailable"
    case parentNotAdmitted = "parent_not_admitted"
}

enum AgentNostrPrivateEntry {
    static let argument = "--agent-nostr-private-v1"
    static let descriptor: Int32 = 3

    static func matches(_ arguments: [String]) -> Bool {
        arguments.count == 2 && arguments[1] == argument
    }
}

struct AgentNostrPrivateRequest: AgentNostrPrivateErasable {
    enum Operation: Equatable {
        case createWrap
        case unwrapAgentNostr
    }

    let operation: Operation
    var blob = Data()
    var point = Data()
    var ciphertext = Data()

    mutating func eraseOwnedBuffers() {
        if !blob.isEmpty { blob.resetBytes(in: 0..<blob.count) }
        if !point.isEmpty { point.resetBytes(in: 0..<point.count) }
        if !ciphertext.isEmpty { ciphertext.resetBytes(in: 0..<ciphertext.count) }
    }

    static func decode(_ raw: inout Data) throws -> Self {
        defer { if !raw.isEmpty { raw.resetBytes(in: 0..<raw.count) } }
        var blob = Data(), point = Data(), ciphertext = Data()
        defer {
            if !blob.isEmpty { blob.resetBytes(in: 0..<blob.count) }
            if !point.isEmpty { point.resetBytes(in: 0..<point.count) }
            if !ciphertext.isEmpty { ciphertext.resetBytes(in: 0..<ciphertext.count) }
        }
        guard (1...AgentNostrPrivateWire.maximumRequest).contains(raw.count),
              let object = try? JSONSerialization.jsonObject(with: raw),
              let fields = object as? [String: String] else {
            throw HelperError(code: "bad_request", status: errSecParam, message: "invalid private request")
        }

        if fields.count == 2, fields["op"] == "create-wrap", fields["purpose"] == "nostr" {
            let canonical = Data(#"{"op":"create-wrap","purpose":"nostr"}"#.utf8)
            guard raw == canonical else {
                throw HelperError(code: "bad_request", status: errSecParam, message: "noncanonical private request")
            }
            return Self(operation: .createWrap)
        }

        guard fields.count == 4, fields["op"] == "unwrap-agent-nostr",
              let blobText = fields["blob"], let pointText = fields["point"],
              let ciphertextText = fields["ciphertext"] else {
            throw HelperError(code: "bad_request", status: errSecParam, message: "invalid private request")
        }
        guard let decodedBlob = canonicalBase64(blobText, maximum: 16384) else {
            throw HelperError(code: "bad_request", status: errSecParam, message: "invalid private request")
        }
        blob = decodedBlob
        guard let decodedPoint = canonicalBase64(pointText, exact: 65) else {
            throw HelperError(code: "bad_request", status: errSecParam, message: "invalid private request")
        }
        point = decodedPoint
        guard let decodedCiphertext = canonicalBase64(ciphertextText, exact: 150) else {
            throw HelperError(code: "bad_request", status: errSecParam, message: "invalid private request")
        }
        ciphertext = decodedCiphertext
        let canonical = Data(("{\"op\":\"unwrap-agent-nostr\",\"blob\":\"\(blobText)\",\"point\":\"\(pointText)\",\"ciphertext\":\"\(ciphertextText)\"}").utf8)
        guard raw == canonical else {
            throw HelperError(code: "bad_request", status: errSecParam, message: "noncanonical private request")
        }
        return Self(operation: .unwrapAgentNostr, blob: blob, point: point, ciphertext: ciphertext)
    }

    private static func canonicalBase64(_ text: String, maximum: Int = Int.max, exact: Int? = nil) -> Data? {
        guard text.utf8.allSatisfy({ byte in
            (65...90).contains(byte) || (97...122).contains(byte) || (48...57).contains(byte) || byte == 43 || byte == 47 || byte == 61
        }), var bytes = Data(base64Encoded: text) else { return nil }
        guard !bytes.isEmpty, bytes.count <= maximum,
              exact == nil || bytes.count == exact, bytes.base64EncodedString() == text else {
            if !bytes.isEmpty { bytes.resetBytes(in: 0..<bytes.count) }
            return nil
        }
        return bytes
    }
}

protocol AgentNostrPrivateErasable {
    mutating func eraseOwnedBuffers()
}

protocol AgentNostrPrivateOperating: AgentNostrPrivateErasable {
    var operation: AgentNostrPrivateRequest.Operation { get }
}

struct AgentNostrPrivatePrepared: AgentNostrPrivateOperating {
    let operation: AgentNostrPrivateRequest.Operation
    var blob: Data
    var point: Data
    var ciphertext: Data
    let ephemeral: P256.KeyAgreement.PublicKey?

    mutating func eraseOwnedBuffers() {
        if !blob.isEmpty { blob.resetBytes(in: 0..<blob.count) }
        if !point.isEmpty { point.resetBytes(in: 0..<point.count) }
        if !ciphertext.isEmpty { ciphertext.resetBytes(in: 0..<ciphertext.count) }
    }
}

enum AgentNostrPrivatePlaintext {
    static let count = 69
    static let domain = Data("KVAN1".utf8)

    static func require(_ bytes: Data) throws {
        guard bytes.count == count, bytes.prefix(domain.count) == domain else {
            throw HelperError(code: "invalid_blob", status: errSecDecode, message: "invalid agent Nostr plaintext")
        }
    }
}

enum AgentNostrPrivateWrapResult {
    static func encode(blob: Data, point: Data) throws -> Data {
        guard !blob.isEmpty, blob.count <= 16384,
              let parsedPoint = try? P256.KeyAgreement.PublicKey(x963Representation: point),
              parsedPoint.x963Representation == point else {
            throw HelperError(code: "invalid_blob", status: errSecDecode, message: "invalid hardware representation")
        }
        let fingerprint = SHA256.hash(data: point).map { String(format: "%02x", $0) }.joined()
        let result: [String: Any] = [
            "blob": blob.base64EncodedString(),
            "fingerprint": fingerprint,
            "point": point.base64EncodedString(),
            "policy": "none",
            "silent_refused": false,
        ]
        do {
            let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys, .withoutEscapingSlashes])
            guard (1...AgentNostrPrivateWire.maximumWrapResponse).contains(data.count) else {
                throw HelperError(code: "invalid_blob", status: errSecDecode, message: "wrap result exceeded limit")
            }
            return data
        } catch let error as HelperError { throw error }
        catch { throw HelperError(code: "invalid_blob", status: errSecDecode, message: "wrap result encoding failed") }
    }
}

struct AgentNostrParentCodeFacts: Equatable {
    let identifier: String
    let team: String
    let flags: UInt32
    let dynamic: UInt32
    let codeHash: Data
    let expectedRequirement: Data
    let actualRequirement: Data
    let leafSHA1: String
    let leafSHA256: String
    let hasEntitlements: Bool
    let entitlementsEmpty: Bool
}

struct AgentNostrPrivateEndpointFacts: Equatable {
    let descriptor: Int32
    let device: UInt64
    let inode: UInt64
    let fileType: UInt16
    let socketType: Int32
    let localFamily: Int32
    let peerFamily: Int32
    let localUnnamed: Bool
    let peerUnnamed: Bool
    let localAddress: Data
    let peerAddress: Data

    var admissible: Bool {
        descriptor == AgentNostrPrivateEntry.descriptor &&
        fileType == UInt16(S_IFSOCK) && socketType == SOCK_STREAM &&
        localFamily == AF_UNIX && peerFamily == AF_UNIX && localUnnamed && peerUnnamed
    }
}

enum AgentNostrPrivateAddressPolicy {
    // Darwin sockaddr_un begins with sun_len and sun_family; every sun_path
    // byte must remain zero for a socketpair endpoint with no pathname.
    static func isUnnamedUnixAddress(_ bytes: Data) -> Bool {
        bytes.count >= 2 && bytes.dropFirst(2).allSatisfy { $0 == 0 }
    }
}

struct AgentNostrPeerFacts: Equatable {
    let auditToken: Data
    let parentPID: Int32
    let parentPIDVersion: Int32
    let observedParentPID: Int32
    let helperRealUID: uid_t
    let helperEffectiveUID: uid_t
    let parentRealUID: uid_t
    let parentEffectiveUID: uid_t
    let endpoint: AgentNostrPrivateEndpointFacts
    let code: AgentNostrParentCodeFacts
}

enum AgentNostrParentIdentity {
    static let identifier = "works.relux.keyvault"
    static let team = "262RZ595FP"
    static let leafSHA1 = "d71190abe54185f908169ee9ca538d4066942c0f"
    static let leafSHA256 = "b315ed0ac55f58d4dbcfc3ce4f7937f6ed058277feba7e4aa3e64bd10b17d3a1"
    static let requirement = #"identifier "works.relux.keyvault" and anchor apple generic and certificate leaf = H"d71190abe54185f908169ee9ca538d4066942c0f" and certificate 1[field.1.2.840.113635.100.6.2.1]"#
    static let auditTokenBytes = 32
}

enum AgentNostrParentPolicy {
    static func require(_ facts: AgentNostrPeerFacts) throws {
        guard facts.auditToken.count == AgentNostrParentIdentity.auditTokenBytes,
              facts.parentPID > 1,
              facts.observedParentPID == facts.parentPID,
              facts.helperRealUID == facts.helperEffectiveUID,
              facts.parentRealUID == facts.helperRealUID,
              facts.parentEffectiveUID == facts.helperEffectiveUID,
              facts.endpoint.admissible else {
            throw AgentNostrPrivateRuntimeError.parentNotAdmitted
        }
        try require(facts.code)
    }

    static func require(_ facts: AgentNostrParentCodeFacts) throws {
        guard facts.identifier == AgentNostrParentIdentity.identifier,
              facts.team == AgentNostrParentIdentity.team,
              facts.flags == 0x10000,
              facts.dynamic & 0x10001 == 0x10001,
              facts.dynamic & 0x10000000 == 0,
              [20, 32].contains(facts.codeHash.count),
              (1...32768).contains(facts.expectedRequirement.count),
              facts.expectedRequirement == facts.actualRequirement,
              facts.leafSHA1 == AgentNostrParentIdentity.leafSHA1,
              facts.leafSHA256 == AgentNostrParentIdentity.leafSHA256,
              !facts.hasEntitlements || facts.entitlementsEmpty else {
            throw AgentNostrPrivateRuntimeError.parentNotAdmitted
        }
    }

    static func requireSame(_ expected: AgentNostrPeerFacts, _ current: AgentNostrPeerFacts) throws {
        try require(current)
        guard expected.auditToken == current.auditToken,
              expected.parentPID == current.parentPID,
              expected.parentPIDVersion == current.parentPIDVersion,
              expected.observedParentPID == current.observedParentPID,
              expected.helperRealUID == current.helperRealUID,
              expected.helperEffectiveUID == current.helperEffectiveUID,
              expected.parentRealUID == current.parentRealUID,
              expected.parentEffectiveUID == current.parentEffectiveUID,
              expected.endpoint == current.endpoint,
              expected.code == current.code else {
            throw AgentNostrPrivateRuntimeError.parentNotAdmitted
        }
    }
}

protocol AgentNostrPeerChecking: AnyObject {
    func admit() throws -> AgentNostrPeerFacts
    func revalidate(_ expected: AgentNostrPeerFacts) throws
}

enum AgentNostrPrivateFlow {
    static func run<Request: AgentNostrPrivateErasable, Prepared: AgentNostrPrivateOperating>(
        checker: AgentNostrPeerChecking,
        parse: () throws -> Request,
        prepare: (Request) throws -> Prepared,
        perform: (inout Prepared) throws -> Data,
        release: (AgentNostrPrivateRequest.Operation, inout Data) throws -> Void
    ) throws {
        let original = try checker.admit()
        var request: Request
        do { request = try parse() }
        catch {
            try checker.revalidate(original)
            throw error
        }
        defer { request.eraseOwnedBuffers() }
        var prepared: Prepared
        do { prepared = try prepare(request) }
        catch {
            try checker.revalidate(original)
            throw error
        }
        defer { prepared.eraseOwnedBuffers() }
        try checker.revalidate(original)
        var response: Data
        do { response = try perform(&prepared) }
        catch {
            try checker.revalidate(original)
            throw error
        }
        defer { if !response.isEmpty { response.resetBytes(in: 0..<response.count) } }
        try checker.revalidate(original)
        try release(prepared.operation, &response)
    }
}

struct AgentNostrPrivateDeadline {
    static let budget: UInt64 = 120_000_000_000
    let startedAt = DispatchTime.now().uptimeNanoseconds

    func check() throws {
        let now = DispatchTime.now().uptimeNanoseconds
        guard now >= startedAt, now - startedAt < Self.budget else {
            throw AgentNostrPrivateRuntimeError.deadlineExpired
        }
    }

    func pollMilliseconds() throws -> Int32 {
        try check()
        return try Self.pollMilliseconds(startedAt: startedAt, now: DispatchTime.now().uptimeNanoseconds)
    }

    static func pollMilliseconds(startedAt: UInt64, now: UInt64) throws -> Int32 {
        guard now >= startedAt, now - startedAt < budget else {
            throw AgentNostrPrivateRuntimeError.deadlineExpired
        }
        let remaining = budget - (now - startedAt)
        let millis = max(UInt64(1), (remaining + 999_999) / 1_000_000)
        return Int32(min(UInt64(100), millis))
    }
}

enum AgentNostrPrivateWire {
    static let maximumRequest = 32768
    static let maximumWrapResponse = 24576
    static let maximumUnwrapResponse = 69
    static let maximumRefusal = 64

    static func requestLength(_ bytes: Data) throws -> Int {
        guard bytes.count == 4 else {
            throw HelperError(code: "bad_request", status: errSecParam, message: "invalid private frame length")
        }
        let length = bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length > 0, length <= maximumRequest else {
            throw HelperError(code: "bad_request", status: errSecParam, message: "invalid private frame length")
        }
        return Int(length)
    }

    static func responseHeader(status: UInt8, count: Int) -> Data {
        var length = UInt32(count).bigEndian
        var data = Data([status])
        withUnsafeBytes(of: &length) { data.append(contentsOf: $0) }
        return data
    }

    static func requireResponseBound(status: UInt8, operation: AgentNostrPrivateRequest.Operation?, count: Int) throws {
        if status == 1 {
            guard (1...maximumRefusal).contains(count) else { throw AgentNostrPrivateRuntimeError.transport }
            return
        }
        guard status == 0, let operation else { throw AgentNostrPrivateRuntimeError.transport }
        switch operation {
        case .createWrap:
            guard (1...maximumWrapResponse).contains(count) else { throw AgentNostrPrivateRuntimeError.transport }
        case .unwrapAgentNostr:
            guard count == maximumUnwrapResponse else { throw AgentNostrPrivateRuntimeError.transport }
        }
    }
}

private struct AgentNostrPrivateAddress {
    let family: Int32
    let bytes: Data
    let unnamed: Bool
}

private enum AgentNostrPrivateSocket {
    static func prepare(_ descriptor: Int32) throws -> AgentNostrPrivateEndpointFacts {
        guard descriptor == AgentNostrPrivateEntry.descriptor else {
            throw AgentNostrPrivateRuntimeError.parentNotAdmitted
        }
        try requireNoUnexpectedDescriptors()

        var file = stat()
        guard fstat(descriptor, &file) == 0,
              file.st_mode & mode_t(S_IFMT) == mode_t(S_IFSOCK) else {
            throw AgentNostrPrivateRuntimeError.parentNotAdmitted
        }
        let identity = (UInt64(truncatingIfNeeded: file.st_dev), UInt64(truncatingIfNeeded: file.st_ino))
        try requireStandardStreamsDoNotAlias(identity, descriptor)

        let descriptorFlags = fcntl(descriptor, F_GETFD)
        guard descriptorFlags >= 0, descriptorFlags & FD_CLOEXEC == 0,
              fcntl(descriptor, F_SETFD, descriptorFlags | FD_CLOEXEC) == 0 else {
            throw AgentNostrPrivateRuntimeError.parentNotAdmitted
        }
        var noSignalPipe: Int32 = 1
        guard setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSignalPipe,
                         socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            throw AgentNostrPrivateRuntimeError.parentNotAdmitted
        }

        var socketType: Int32 = 0
        var socketTypeLength = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &socketType, &socketTypeLength) == 0,
              socketTypeLength == socklen_t(MemoryLayout<Int32>.size), socketType == SOCK_STREAM else {
            throw AgentNostrPrivateRuntimeError.parentNotAdmitted
        }
        let local = try address(descriptor, peer: false)
        let peer = try address(descriptor, peer: true)
        let facts = AgentNostrPrivateEndpointFacts(
            descriptor: descriptor, device: identity.0, inode: identity.1,
            fileType: UInt16(file.st_mode & mode_t(S_IFMT)), socketType: socketType,
            localFamily: local.family, peerFamily: peer.family,
            localUnnamed: local.unnamed, peerUnnamed: peer.unnamed,
            localAddress: local.bytes, peerAddress: peer.bytes)
        guard facts.admissible else { throw AgentNostrPrivateRuntimeError.parentNotAdmitted }
        return facts
    }

    private static func address(_ descriptor: Int32, peer: Bool) throws -> AgentNostrPrivateAddress {
        var storage = sockaddr_storage()
        var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let result = withUnsafeMutablePointer(to: &storage) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { address in
                peer ? getpeername(descriptor, address, &length) : getsockname(descriptor, address, &length)
            }
        }
        guard result == 0,
              length >= socklen_t(MemoryLayout<sockaddr>.size),
              length <= socklen_t(MemoryLayout<sockaddr_storage>.size) else {
            throw AgentNostrPrivateRuntimeError.parentNotAdmitted
        }
        let bytes = withUnsafeBytes(of: storage) { Data($0.prefix(Int(length))) }
        let family = Int32(storage.ss_family)
        let unnamed = AgentNostrPrivateAddressPolicy.isUnnamedUnixAddress(bytes)
        return AgentNostrPrivateAddress(family: family, bytes: bytes, unnamed: unnamed)
    }

    private static func requireNoUnexpectedDescriptors() throws {
        var limits = rlimit()
        guard getrlimit(RLIMIT_NOFILE, &limits) == 0, limits.rlim_cur <= 65536 else {
            throw AgentNostrPrivateRuntimeError.parentNotAdmitted
        }
        let upperBound = Int32(limits.rlim_cur)
        if upperBound <= 4 { return }
        for fd in Int32(4)..<upperBound {
            if fcntl(fd, F_GETFD) >= 0 || errno != EBADF {
                throw AgentNostrPrivateRuntimeError.parentNotAdmitted
            }
        }
    }

    private static func requireStandardStreamsDoNotAlias(_ expected: (UInt64, UInt64), _ privateFD: Int32) throws {
        for fd in Int32(0)..<privateFD {
            var file = stat()
            if fstat(fd, &file) == 0 {
                let actual = (UInt64(truncatingIfNeeded: file.st_dev), UInt64(truncatingIfNeeded: file.st_ino))
                guard actual.0 != expected.0 || actual.1 != expected.1 else {
                    throw AgentNostrPrivateRuntimeError.parentNotAdmitted
                }
            } else if errno != EBADF {
                throw AgentNostrPrivateRuntimeError.parentNotAdmitted
            }
        }
    }
}

private struct AgentNostrNativePeerCapture {
    let facts: AgentNostrPeerFacts
    let code: SecCode
}

private enum AgentNostrNativePeer {
    private static let zero = SecCSFlags(rawValue: 0)
    private static let runningFlags = SecCSFlags(rawValue: kSecCSStrictValidate).union(.noNetworkAccess)
    private static let staticFlags = runningFlags.union(SecCSFlags(rawValue: kSecCSCheckAllArchitectures))

    static func capture(_ descriptor: Int32, expectedEndpoint: AgentNostrPrivateEndpointFacts,
                        deadline: AgentNostrPrivateDeadline) throws -> AgentNostrNativePeerCapture {
        try deadline.check()
        let endpoint = try AgentNostrPrivateSocketSnapshot.capture(descriptor)
        guard endpoint == expectedEndpoint else { throw AgentNostrPrivateRuntimeError.parentNotAdmitted }

        var token = audit_token_t()
        var tokenLength = socklen_t(MemoryLayout<audit_token_t>.size)
        let tokenStatus = withUnsafeMutablePointer(to: &token) { pointer in
            pointer.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout<audit_token_t>.size) { bytes in
                getsockopt(descriptor, SOL_LOCAL, LOCAL_PEERTOKEN, bytes, &tokenLength)
            }
        }
        guard tokenStatus == 0, tokenLength == socklen_t(MemoryLayout<audit_token_t>.size) else {
            throw AgentNostrPrivateRuntimeError.parentNotAdmitted
        }
        let tokenBytes = withUnsafeBytes(of: token) { Data($0) }
        let parentPID = audit_token_to_pid(token)
        let parentVersion = audit_token_to_pidversion(token)
        let helperUID = getuid(), helperEUID = geteuid()
        let observedParentPID = getppid()
        guard parentPID > 1, observedParentPID == parentPID,
              helperUID == helperEUID,
              audit_token_to_ruid(token) == helperUID,
              audit_token_to_euid(token) == helperEUID else {
            throw AgentNostrPrivateRuntimeError.parentNotAdmitted
        }

        let attributes: [String: Any] = [kSecGuestAttributeAudit as String: tokenBytes]
        var running: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes as CFDictionary, zero, &running) == errSecSuccess,
              let running else {
            throw AgentNostrPrivateRuntimeError.parentNotAdmitted
        }
        var expected: SecRequirement?
        var actual: SecRequirement?
        var staticCode: SecStaticCode?
        var expectedData: CFData?
        var actualData: CFData?
        var information: CFDictionary?
        guard SecRequirementCreateWithString(AgentNostrParentIdentity.requirement as CFString, zero, &expected) == errSecSuccess,
              let expected,
              SecCodeCheckValidity(running, runningFlags, expected) == errSecSuccess,
              SecCodeCopyStaticCode(running, zero, &staticCode) == errSecSuccess, let staticCode,
              SecStaticCodeCheckValidity(staticCode, staticFlags, expected) == errSecSuccess,
              SecCodeCopyDesignatedRequirement(staticCode, zero, &actual) == errSecSuccess, let actual,
              SecRequirementCopyData(expected, zero, &expectedData) == errSecSuccess, let expectedData,
              SecRequirementCopyData(actual, zero, &actualData) == errSecSuccess, let actualData,
              copyRunningCodeSigningInformation(running,
                  SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSDynamicInformation), &information) == errSecSuccess,
              let facts = try codeFacts(information, expectedRequirement: expectedData as Data,
                                        actualRequirement: actualData as Data) else {
            throw AgentNostrPrivateRuntimeError.parentNotAdmitted
        }

        let peerFacts = AgentNostrPeerFacts(
            auditToken: tokenBytes, parentPID: parentPID, parentPIDVersion: parentVersion,
            observedParentPID: observedParentPID, helperRealUID: helperUID, helperEffectiveUID: helperEUID,
            parentRealUID: audit_token_to_ruid(token), parentEffectiveUID: audit_token_to_euid(token),
            endpoint: endpoint, code: facts)
        try AgentNostrParentPolicy.require(peerFacts)
        try deadline.check()
        return AgentNostrNativePeerCapture(facts: peerFacts, code: running)
    }

    private static func codeFacts(_ information: CFDictionary?, expectedRequirement: Data,
                                  actualRequirement: Data) throws -> AgentNostrParentCodeFacts? {
        guard let information, CFGetTypeID(information) == CFDictionaryGetTypeID(),
              let dictionary = information as? [String: Any],
              let identifier = dictionary[kSecCodeInfoIdentifier as String] as? String,
              let team = dictionary[kSecCodeInfoTeamIdentifier as String] as? String,
              let codeHash = dictionary[kSecCodeInfoUnique as String] as? Data,
              let certificates = dictionary[kSecCodeInfoCertificates as String] as? [AnyObject],
              let certificate = certificates.first,
              CFGetTypeID(certificate) == SecCertificateGetTypeID() else {
            throw AgentNostrPrivateRuntimeError.parentNotAdmitted
        }
        let hasEntitlements = dictionary[kSecCodeInfoEntitlementsDict as String] != nil
        let entitlementsEmpty: Bool
        do {
            if hasEntitlements {
                try RootGrantsQualificationIdentity.requireEmptyEntitlements(dictionary[kSecCodeInfoEntitlementsDict as String])
            }
            entitlementsEmpty = hasEntitlements
        } catch { throw AgentNostrPrivateRuntimeError.parentNotAdmitted }
        let leaf = SecCertificateCopyData(certificate as! SecCertificate) as Data
        guard (1...32768).contains(leaf.count) else { throw AgentNostrPrivateRuntimeError.parentNotAdmitted }
        do {
            return AgentNostrParentCodeFacts(
                identifier: identifier, team: team,
                flags: try RootGrantsQualificationIdentity.exactUInt32(dictionary[kSecCodeInfoFlags as String]),
                dynamic: try RootGrantsQualificationIdentity.exactUInt32(dictionary[kSecCodeInfoStatus as String]),
                codeHash: codeHash, expectedRequirement: expectedRequirement, actualRequirement: actualRequirement,
                leafSHA1: Insecure.SHA1.hash(data: leaf).map { String(format: "%02x", $0) }.joined(),
                leafSHA256: SHA256.hash(data: leaf).map { String(format: "%02x", $0) }.joined(),
                hasEntitlements: hasEntitlements, entitlementsEmpty: entitlementsEmpty)
        } catch { throw AgentNostrPrivateRuntimeError.parentNotAdmitted }
    }
}

private enum AgentNostrPrivateSocketSnapshot {
    static func capture(_ descriptor: Int32) throws -> AgentNostrPrivateEndpointFacts {
        var file = stat()
        guard fstat(descriptor, &file) == 0,
              file.st_mode & mode_t(S_IFMT) == mode_t(S_IFSOCK) else {
            throw AgentNostrPrivateRuntimeError.parentNotAdmitted
        }
        var socketType: Int32 = 0
        var socketTypeLength = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &socketType, &socketTypeLength) == 0,
              socketTypeLength == socklen_t(MemoryLayout<Int32>.size) else {
            throw AgentNostrPrivateRuntimeError.parentNotAdmitted
        }
        let local = try address(descriptor, peer: false)
        let peer = try address(descriptor, peer: true)
        return AgentNostrPrivateEndpointFacts(
            descriptor: descriptor,
            device: UInt64(truncatingIfNeeded: file.st_dev), inode: UInt64(truncatingIfNeeded: file.st_ino),
            fileType: UInt16(file.st_mode & mode_t(S_IFMT)), socketType: socketType,
            localFamily: local.family, peerFamily: peer.family,
            localUnnamed: local.unnamed, peerUnnamed: peer.unnamed,
            localAddress: local.bytes, peerAddress: peer.bytes)
    }

    private static func address(_ descriptor: Int32, peer: Bool) throws -> AgentNostrPrivateAddress {
        var storage = sockaddr_storage()
        var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let result = withUnsafeMutablePointer(to: &storage) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { address in
                peer ? getpeername(descriptor, address, &length) : getsockname(descriptor, address, &length)
            }
        }
        guard result == 0,
              length >= socklen_t(MemoryLayout<sockaddr>.size),
              length <= socklen_t(MemoryLayout<sockaddr_storage>.size) else {
            throw AgentNostrPrivateRuntimeError.parentNotAdmitted
        }
        let bytes = withUnsafeBytes(of: storage) { Data($0.prefix(Int(length))) }
        return AgentNostrPrivateAddress(
            family: Int32(storage.ss_family), bytes: bytes,
            unnamed: AgentNostrPrivateAddressPolicy.isUnnamedUnixAddress(bytes))
    }
}

private final class AgentNostrLivePeerChecker: AgentNostrPeerChecking {
    private let descriptor: Int32
    private let endpoint: AgentNostrPrivateEndpointFacts
    private let deadline: AgentNostrPrivateDeadline
    private var initialFacts: AgentNostrPeerFacts?
    private var retainedCode: SecCode?

    init(descriptor: Int32, endpoint: AgentNostrPrivateEndpointFacts, deadline: AgentNostrPrivateDeadline) {
        self.descriptor = descriptor
        self.endpoint = endpoint
        self.deadline = deadline
    }

    func admit() throws -> AgentNostrPeerFacts {
        guard initialFacts == nil, retainedCode == nil else { throw AgentNostrPrivateRuntimeError.parentNotAdmitted }
        let capture = try AgentNostrNativePeer.capture(descriptor, expectedEndpoint: endpoint, deadline: deadline)
        initialFacts = capture.facts
        retainedCode = capture.code
        return capture.facts
    }

    func revalidate(_ expected: AgentNostrPeerFacts) throws {
        guard let initialFacts, initialFacts == expected, let retainedCode else {
            throw AgentNostrPrivateRuntimeError.parentNotAdmitted
        }
        let capture = try AgentNostrNativePeer.capture(descriptor, expectedEndpoint: endpoint, deadline: deadline)
        try AgentNostrParentPolicy.requireSame(expected, capture.facts)
        // Keep the original dynamic code object live for the full transaction.
        withExtendedLifetime(retainedCode) {}
        withExtendedLifetime(capture.code) {}
    }
}

private struct AgentNostrPrivateTransport {
    let descriptor: Int32
    let endpoint: AgentNostrPrivateEndpointFacts
    let deadline: AgentNostrPrivateDeadline

    func readRequest() throws -> AgentNostrPrivateRequest {
        let lengthBytes = try readExact(4)
        let length = try AgentNostrPrivateWire.requestLength(lengthBytes)
        var raw = try readExact(length)
        defer { if !raw.isEmpty { raw.resetBytes(in: 0..<raw.count) } }
        try requireEOF()
        return try AgentNostrPrivateRequest.decode(&raw)
    }

    func release(_ operation: AgentNostrPrivateRequest.Operation, payload: inout Data,
                 writer: AgentNostrPrivateWriter) throws {
        try writer.write(status: 0, operation: operation, payload: &payload)
    }

    func refuse(_ status: AgentNostrPrivateStatus, writer: AgentNostrPrivateWriter) throws {
        var payload = Data(status.rawValue.utf8)
        defer { if !payload.isEmpty { payload.resetBytes(in: 0..<payload.count) } }
        guard (1...AgentNostrPrivateWire.maximumRefusal).contains(payload.count) else {
            throw AgentNostrPrivateRuntimeError.transport
        }
        try writer.write(status: 1, operation: nil, payload: &payload)
    }

    private func readExact(_ count: Int) throws -> Data {
        var output = Data()
        while output.count < count {
            try wait(events: Int16(POLLIN | POLLHUP))
            var chunk = [UInt8](repeating: 0, count: min(4096, count - output.count))
            defer { for index in chunk.indices { chunk[index] = 0 } }
            let amount = chunk.withUnsafeMutableBytes { bytes in
                Darwin.read(descriptor, bytes.baseAddress, bytes.count)
            }
            if amount < 0, errno == EINTR { continue }
            guard amount > 0 else { throw HelperError(code: "bad_request", status: errSecParam, message: "incomplete private frame") }
            output.append(contentsOf: chunk.prefix(amount))
        }
        return output
    }

    private func requireEOF() throws {
        while true {
            try wait(events: Int16(POLLIN | POLLHUP))
            var byte: UInt8 = 0
            let amount = Darwin.read(descriptor, &byte, 1)
            if amount < 0, errno == EINTR { continue }
            guard amount == 0 else { throw HelperError(code: "bad_request", status: errSecParam, message: "trailing private request bytes") }
            return
        }
    }

    private func wait(events: Int16) throws {
        while true {
            try deadline.check()
            try requireSameEndpoint()
            var state = pollfd(fd: descriptor, events: events, revents: 0)
            let result = poll(&state, 1, try deadline.pollMilliseconds())
            if result < 0, errno == EINTR { continue }
            guard result >= 0 else { throw AgentNostrPrivateRuntimeError.transport }
            if result == 0 { continue }
            guard state.revents & Int16(POLLNVAL) == 0 else { throw AgentNostrPrivateRuntimeError.transport }
            if state.revents & events != 0 || state.revents & Int16(POLLERR) != 0 { return }
        }
    }

    private func requireSameEndpoint() throws {
        guard try AgentNostrPrivateSocketSnapshot.capture(descriptor) == endpoint else {
            throw AgentNostrPrivateRuntimeError.parentNotAdmitted
        }
    }
}

private final class AgentNostrPrivateWriter {
    let descriptor: Int32
    let endpoint: AgentNostrPrivateEndpointFacts
    let deadline: AgentNostrPrivateDeadline
    var started = false

    init(descriptor: Int32, endpoint: AgentNostrPrivateEndpointFacts, deadline: AgentNostrPrivateDeadline) {
        self.descriptor = descriptor
        self.endpoint = endpoint
        self.deadline = deadline
    }

    func write(status: UInt8, operation: AgentNostrPrivateRequest.Operation?, payload: inout Data) throws {
        try AgentNostrPrivateWire.requireResponseBound(status: status, operation: operation, count: payload.count)
        let header = AgentNostrPrivateWire.responseHeader(status: status, count: payload.count)
        started = true
        try writeAll(header)
        try writeAll(payload)
    }

    private func writeAll(_ bytes: Data) throws {
        var offset = 0
        while offset < bytes.count {
            try deadline.check()
            guard try AgentNostrPrivateSocketSnapshot.capture(descriptor) == endpoint else {
                throw AgentNostrPrivateRuntimeError.parentNotAdmitted
            }
            var state = pollfd(fd: descriptor, events: Int16(POLLOUT), revents: 0)
            let ready = poll(&state, 1, try deadline.pollMilliseconds())
            if ready < 0, errno == EINTR { continue }
            guard ready > 0, state.revents & Int16(POLLNVAL | POLLERR) == 0,
                  state.revents & Int16(POLLOUT) != 0 else {
                if ready == 0 { continue }
                throw AgentNostrPrivateRuntimeError.transport
            }
            let amount = bytes.withUnsafeBytes { raw in
                Darwin.write(descriptor, raw.baseAddress!.advanced(by: offset), raw.count - offset)
            }
            if amount < 0, errno == EINTR { continue }
            guard amount > 0 else { throw AgentNostrPrivateRuntimeError.transport }
            offset += amount
        }
    }
}

enum AgentNostrPrivateOperation {
    static func prepare(_ request: AgentNostrPrivateRequest) throws -> AgentNostrPrivatePrepared {
        switch request.operation {
        case .createWrap:
            return AgentNostrPrivatePrepared(operation: .createWrap, blob: Data(), point: Data(), ciphertext: Data(), ephemeral: nil)
        case .unwrapAgentNostr:
            do {
                let wrapping = try P256.KeyAgreement.PublicKey(x963Representation: request.point)
                guard wrapping.x963Representation == request.point,
                      request.ciphertext.count == 150 else {
                    throw HelperError(code: "bad_request", status: errSecParam, message: "invalid private request")
                }
                let ephemeralBytes = Data(request.ciphertext.prefix(65))
                let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralBytes)
                return AgentNostrPrivatePrepared(operation: .unwrapAgentNostr, blob: request.blob,
                    point: request.point, ciphertext: request.ciphertext, ephemeral: ephemeral)
            } catch let error as HelperError { throw error }
            catch { throw HelperError(code: "bad_request", status: errSecParam, message: "invalid private point") }
        }
    }

    static func perform(_ prepared: inout AgentNostrPrivatePrepared) throws -> Data {
        switch prepared.operation {
        case .createWrap:
            return try createWrap()
        case .unwrapAgentNostr:
            return try unwrap(prepared)
        }
    }

    private static func createWrap() throws -> Data {
        guard SecureEnclave.isAvailable else {
            throw HelperError(code: "enclave_unavailable", status: errSecNotAvailable, message: "hardware unavailable")
        }
        let context = silentContext()
        defer { context.invalidate() }
        let access = try recoveryAccessControl("nostr")
        let key: SecureEnclave.P256.KeyAgreement.PrivateKey
        do {
            key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access, authenticationContext: context)
        } catch {
            throw translate(error, "agent Nostr create-wrap")
        }
        var blob = key.dataRepresentation
        defer { if !blob.isEmpty { blob.resetBytes(in: 0..<blob.count) } }
        let point = key.publicKey.x963Representation
        return try AgentNostrPrivateWrapResult.encode(blob: blob, point: point)
    }

    private static func unwrap(_ prepared: AgentNostrPrivatePrepared) throws -> Data {
        guard SecureEnclave.isAvailable, let ephemeral = prepared.ephemeral else {
            throw HelperError(code: "enclave_unavailable", status: errSecNotAvailable, message: "hardware unavailable")
        }
        var blob = prepared.blob
        defer { if !blob.isEmpty { blob.resetBytes(in: 0..<blob.count) } }
        let context = silentContext()
        defer { context.invalidate() }
        let key: SecureEnclave.P256.KeyAgreement.PrivateKey
        do { key = try recoveryLoad(blob, context) }
        catch { throw translate(error, "agent Nostr unwrap") }
        guard key.publicKey.x963Representation == prepared.point else {
            throw HelperError(code: "invalid_blob", status: errSecDecode, message: "wrapping point mismatch")
        }
        let secret: SharedSecret
        do { secret = try key.sharedSecretFromKeyAgreement(with: ephemeral) }
        catch { throw translate(error, "agent Nostr unwrap") }
        return try open(ciphertext: prepared.ciphertext, sharedSecret: secret)
    }

    static func open(ciphertext: Data, sharedSecret: SharedSecret) throws -> Data {
        guard ciphertext.count == 150 else {
            throw HelperError(code: "invalid_blob", status: errSecDecode, message: "invalid ciphertext length")
        }
        var material = sharedSecret.x963DerivedSymmetricKey(using: SHA256.self,
            sharedInfo: ciphertext.prefix(65), outputByteCount: 32).withUnsafeBytes { Data($0) }
        defer { if !material.isEmpty { material.resetBytes(in: 0..<material.count) } }
        let keyMaterial = SymmetricKey(data: material.prefix(16))
        let nonce: AES.GCM.Nonce
        do { nonce = try AES.GCM.Nonce(data: material.suffix(16)) }
        catch { throw HelperError(code: "invalid_blob", status: errSecDecode, message: "invalid ciphertext nonce") }
        let box: AES.GCM.SealedBox
        do {
            box = try AES.GCM.SealedBox(nonce: nonce,
                ciphertext: ciphertext.dropFirst(65).dropLast(16),
                tag: ciphertext.suffix(16))
        } catch {
            throw HelperError(code: "invalid_blob", status: errSecDecode, message: "invalid ciphertext frame")
        }
        var plaintext: Data
        do { plaintext = try AES.GCM.open(box, using: keyMaterial) }
        catch { throw HelperError(code: "invalid_blob", status: errSecDecode, message: "ciphertext authentication failed") }
        defer { if !plaintext.isEmpty { plaintext.resetBytes(in: 0..<plaintext.count) } }
        try AgentNostrPrivatePlaintext.require(plaintext)
        return plaintext
    }
}

func agentNostrPrivate() -> Int32 {
    let deadline = AgentNostrPrivateDeadline()
    let endpoint: AgentNostrPrivateEndpointFacts
    do { endpoint = try AgentNostrPrivateSocket.prepare(AgentNostrPrivateEntry.descriptor) }
    catch { return 1 }

    let checker = AgentNostrLivePeerChecker(descriptor: AgentNostrPrivateEntry.descriptor,
                                            endpoint: endpoint, deadline: deadline)
    let transport = AgentNostrPrivateTransport(descriptor: AgentNostrPrivateEntry.descriptor,
                                               endpoint: endpoint, deadline: deadline)
    let writer = AgentNostrPrivateWriter(descriptor: AgentNostrPrivateEntry.descriptor,
                                         endpoint: endpoint, deadline: deadline)
    do {
        try AgentNostrPrivateFlow.run(checker: checker,
            parse: { try transport.readRequest() },
            prepare: { try AgentNostrPrivateOperation.prepare($0) },
            perform: { (prepared: inout AgentNostrPrivatePrepared) in try AgentNostrPrivateOperation.perform(&prepared) },
            release: { (operation: AgentNostrPrivateRequest.Operation, payload: inout Data) in
                try transport.release(operation, payload: &payload, writer: writer)
            })
        return 0
    } catch {
        guard !writer.started, let status = agentNostrPrivateStatus(error) else { return 1 }
        do { try transport.refuse(status, writer: writer) }
        catch { return 1 }
        return 1
    }
}

func agentNostrPrivateStatus(_ error: Error) -> AgentNostrPrivateStatus? {
    if let runtime = error as? AgentNostrPrivateRuntimeError {
        if case .parentNotAdmitted = runtime { return .parentNotAdmitted }
        return nil
    }
    guard let failure = error as? HelperError else { return .enclaveUnavailable }
    switch failure.code {
    case "bad_request": return .badRequest
    case "invalid_blob": return .invalidBlob
    case "policy_refused": return .policyRefused
    case "presence_required": return .presenceRequired
    case "auth_refused", "auth_failed", "user_canceled", "presence_unavailable", "presence_failed": return .authRefused
    case "enclave_unavailable": return .enclaveUnavailable
    default: return .enclaveUnavailable
    }
}
