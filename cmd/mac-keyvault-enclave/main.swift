// mac-keyvault-enclave is the Secure Enclave half of mac-keyvault. It holds no
// state: a key is a CryptoKit SecureEnclave.P256.Signing.PrivateKey whose
// dataRepresentation (a blob only this device's Secure Enclave can unwrap) the
// Go side stores. That route needs no keychain entitlement, so an ad-hoc
// signed binary can use it (probe 2026-10-19, owner-presence-key-261019).
//
// Protocol: one JSON request on stdin, one JSON response on stdout, exit 0 on
// success and 1 with {"error":{...}} otherwise. Nothing travels in argv.
//
//   {"op":"create","presence":"none"|"user-presence"}
//       -> {"blob":B64,"point":B64,"presence_enforced":BOOL}
//   {"op":"public","blob":B64}
//       -> {"point":B64}
//   {"op":"sign","blob":B64,"digest":B64,"presence":"none"|"required","reason":S,
//    "interaction":"none"?}
//       -> {"der":B64,"point":B64}
//
// "interaction":"none" never shows a prompt: a presence key then refuses with
// errSecInteractionNotAllowed. Tests use it to prove that refusal on real
// hardware without asking anyone for a finger.
//
// Every LAContext is fresh and never given a reuse duration, so a presence key
// asks for Touch ID or the login password on every signature. Errors carry the Security.framework
// OSStatus the Go side already names (errSecInteractionNotAllowed and so on).
// There is no software fallback anywhere: without the Secure Enclave every
// operation fails.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

let errSecUserCanceled: Int32 = -128
let errSecAuthFailed: Int32 = -25293
let errSecNotAvailable: Int32 = -25291
let errSecInteractionNotAllowed: Int32 = -25308
let errSecDecode: Int32 = -26275
let errSecParam: Int32 = -50

struct HelperError: Error {
    let code: String
    let status: Int32
    let message: String
}

let maxRequestBytes = 64 * 1024
let maxReasonLength = 200

func emit(_ object: [String: Any], exitCode: Int32) -> Never {
    let data = (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data("{}".utf8)
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data("\n".utf8))
    exit(exitCode)
}

func fail(_ error: HelperError) -> Never {
    emit(["error": ["code": error.code, "status": Int(error.status), "message": error.message]], exitCode: 1)
}

// A context that never shows UI: signing with a presence key through it fails
// with LAError.notInteractive instead of prompting.
func silentContext() -> LAContext {
    let context = LAContext()
    context.interactionNotAllowed = true
    return context
}

// translate maps what CryptoKit and LocalAuthentication throw to an OSStatus
// the Go side translates; anything unknown keeps its domain in the message.
func translate(_ error: Error, _ op: String) -> HelperError {
    let ns = error as NSError
    if ns.domain == LAError.errorDomain {
        switch LAError.Code(rawValue: ns.code) {
        case .notInteractive:
            return HelperError(code: "presence_required", status: errSecInteractionNotAllowed, message: "\(op): user presence is required and interaction is not allowed")
        case .userCancel, .systemCancel, .appCancel:
            return HelperError(code: "user_canceled", status: errSecUserCanceled, message: "\(op): the presence prompt was canceled")
        case .authenticationFailed:
            return HelperError(code: "auth_failed", status: errSecAuthFailed, message: "\(op): presence was not confirmed")
        case .biometryLockout, .biometryNotEnrolled, .biometryNotAvailable, .passcodeNotSet:
            return HelperError(code: "presence_unavailable", status: errSecNotAvailable, message: "\(op): biometry is locked out, not enrolled or unavailable (LAError \(ns.code))")
        default:
            return HelperError(code: "presence_failed", status: errSecAuthFailed, message: "\(op): LocalAuthentication error \(ns.code)")
        }
    }
    if ns.domain == "CryptoTokenKit" {
        // A blob loads even when its wrapped private part is damaged (the
        // public half travels in clear); the token refuses it at first use.
        return HelperError(code: "invalid_blob", status: errSecDecode, message: "\(op): the Secure Enclave refused the key blob (CryptoTokenKit \(ns.code))")
    }
    if ns.domain == NSOSStatusErrorDomain {
        return HelperError(code: "security", status: Int32(truncatingIfNeeded: ns.code), message: "\(op): OSStatus \(ns.code)")
    }
    return HelperError(code: "security", status: errSecDecode, message: "\(op): \(ns.domain) \(ns.code)")
}

func accessControl(presence: Bool) throws -> SecAccessControl {
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    if presence {
        // Touch ID or the login password for every signature (owner
        // decision 2026-10-19): the key survives fingerprint changes.
        flags.insert(.userPresence)
    }
    var error: Unmanaged<CFError>?
    guard let control = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error) else {
        let status = error.map { Int32(truncatingIfNeeded: CFErrorGetCode($0.takeRetainedValue())) } ?? errSecParam
        throw HelperError(code: "security", status: status, message: "create: access control refused")
    }
    return control
}

func decodeBase64(_ value: Any?, _ field: String) throws -> Data {
    guard let text = value as? String, let data = Data(base64Encoded: text) else {
        throw HelperError(code: "bad_request", status: errSecParam, message: "\(field) is not base64")
    }
    return data
}

func loadKey(_ blob: Data, context: LAContext) throws -> SecureEnclave.P256.Signing.PrivateKey {
    do {
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: context)
    } catch {
        // A blob from another device, a tampered blob or a blob this user's
        // Secure Enclave cannot unwrap all end here.
        throw HelperError(code: "invalid_blob", status: errSecDecode, message: "the Secure Enclave refused the key blob")
    }
}

// sha256Digest turns 32 raw bytes into a SHA256Digest. CryptoKit has no public
// initializer, so the bytes are loaded into its 32-byte layout and the result
// is read back and compared: any layout change refuses instead of signing
// something else.
func sha256Digest(_ bytes: Data) throws -> SHA256Digest {
    guard bytes.count == SHA256Digest.byteCount, MemoryLayout<SHA256Digest>.size == SHA256Digest.byteCount else {
        throw HelperError(code: "bad_request", status: errSecParam, message: "digest must be \(SHA256Digest.byteCount) bytes")
    }
    let digest = bytes.withUnsafeBytes { $0.loadUnaligned(as: SHA256Digest.self) }
    guard Data(digest) == bytes else {
        throw HelperError(code: "security", status: errSecParam, message: "digest layout check failed; nothing was signed")
    }
    return digest
}

// presenceEnforced signs a random digest through a silent context: a presence
// key must refuse with notInteractive, a plain key must sign. Any other answer
// is an error, never a verdict.
func presenceEnforced(_ blob: Data) throws -> Bool {
    let key = try loadKey(blob, context: silentContext())
    let probe = try sha256Digest(Data(SHA256.hash(data: Data(UUID().uuidString.utf8))))
    do {
        _ = try key.signature(for: probe)
        return false
    } catch {
        let translated = translate(error, "presence probe")
        if translated.code == "presence_required" {
            return true
        }
        throw translated
    }
}

func create(_ request: [String: Any]) throws -> [String: Any] {
    guard SecureEnclave.isAvailable else {
        throw HelperError(code: "enclave_unavailable", status: errSecNotAvailable, message: "the Secure Enclave is not available")
    }
    let presence: Bool
    switch request["presence"] as? String {
    case "none": presence = false
    case "user-presence": presence = true
    default: throw HelperError(code: "bad_request", status: errSecParam, message: "presence must be none or user-presence")
    }
    let key: SecureEnclave.P256.Signing.PrivateKey
    do {
        key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl(presence: presence), authenticationContext: silentContext())
    } catch let error as HelperError {
        throw error
    } catch {
        throw translate(error, "create")
    }
    let blob = key.dataRepresentation
    return [
        "blob": blob.base64EncodedString(),
        "point": key.publicKey.x963Representation.base64EncodedString(),
        "presence_enforced": try presenceEnforced(blob),
    ]
}

func publicKey(_ request: [String: Any]) throws -> [String: Any] {
    let key = try loadKey(try decodeBase64(request["blob"], "blob"), context: silentContext())
    return ["point": key.publicKey.x963Representation.base64EncodedString()]
}

func sign(_ request: [String: Any]) throws -> [String: Any] {
    let blob = try decodeBase64(request["blob"], "blob")
    let digest = try sha256Digest(try decodeBase64(request["digest"], "digest"))
    let required: Bool
    switch request["presence"] as? String {
    case "none": required = false
    case "required": required = true
    default: throw HelperError(code: "bad_request", status: errSecParam, message: "presence must be none or required")
    }
    let context: LAContext
    if required {
        // A record that says presence must hold a key that enforces it: a
        // blob that signs silently was swapped or created without the ACL.
        guard try presenceEnforced(blob) else {
            throw HelperError(code: "presence_not_enforced", status: errSecAuthFailed, message: "the key signs without user presence although its record requires it; nothing was signed")
        }
        context = request["interaction"] as? String == "none" ? silentContext() : LAContext()
        var reason = (request["reason"] as? String) ?? "mac-keyvault signature"
        reason = String(reason.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }.prefix(maxReasonLength))
        context.localizedReason = reason.isEmpty ? "mac-keyvault signature" : reason
    } else {
        context = silentContext()
    }
    let key = try loadKey(blob, context: context)
    let signature: P256.Signing.ECDSASignature
    do {
        signature = try key.signature(for: digest)
    } catch {
        throw translate(error, "sign")
    }
    return [
        "der": signature.derRepresentation.base64EncodedString(),
        "point": key.publicKey.x963Representation.base64EncodedString(),
    ]
}

let input = FileHandle.standardInput.readData(ofLength: maxRequestBytes + 1)
guard input.count <= maxRequestBytes,
      let parsed = try? JSONSerialization.jsonObject(with: input),
      let request = parsed as? [String: Any],
      let op = request["op"] as? String
else {
    fail(HelperError(code: "bad_request", status: errSecParam, message: "stdin must be one JSON object with op, at most \(maxRequestBytes) bytes"))
}
do {
    switch op {
    case "create": emit(try create(request), exitCode: 0)
    case "public": emit(try publicKey(request), exitCode: 0)
    case "sign": emit(try sign(request), exitCode: 0)
    default: throw HelperError(code: "bad_request", status: errSecParam, message: "unknown op \(op)")
    }
} catch let error as HelperError {
    fail(error)
} catch {
    fail(translate(error, op))
}
