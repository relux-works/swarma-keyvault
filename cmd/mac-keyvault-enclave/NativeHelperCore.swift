// mac-keyvault-enclave is the Secure Enclave half of mac-keyvault. It holds no
// state: a key is a CryptoKit SecureEnclave.P256.Signing.PrivateKey whose
// dataRepresentation (a blob only this device's Secure Enclave can unwrap) the
// Go side stores. That route needs no keychain entitlement, so an ad-hoc
// signed binary can use it (probe 2026-10-19, owner-presence-key-261019).
//
// Protocol: bounded JSON on private stdin/stdout; exit 0 on success and 1
// with {"error":{...}} otherwise. Nothing travels in argv. Generic operations
// use one request/response. review-document uses confirmed/dispatch handoffs
// in the same process before presence authentication and signature output.
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

import AppKit
import CoreText
import CryptoKit
import Foundation
import LocalAuthentication
import Security

// SecCode.h permits this API's SecStaticCodeRef argument to carry a running
// SecCodeRef. Keep that SAME object: converting it to disk-only static code
// loses kSecCSDynamicInformation. This view bridges the Swift CF types only;
// the original strong reference remains alive throughout the native call.
func copyRunningCodeSigningInformation(_ running: SecCode, _ flags: SecCSFlags,
                                      _ information: UnsafeMutablePointer<CFDictionary?>) -> OSStatus {
    return withExtendedLifetime(running) {
        SecCodeCopySigningInformation(unsafeBitCast(running, to: SecStaticCode.self), flags, information)
    }
}

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

// Frames are bounded and newline delimited for the attended two-stage route.
// Legacy one-shot operations may terminate their one frame with EOF.
func readFrame() throws -> [String: Any] {
    var input = Data()
    while true {
        let next = FileHandle.standardInput.readData(ofLength: 1)
        if next.isEmpty || next[0] == 10 { break }
        input.append(next)
        guard input.count <= maxRequestBytes else {
            throw HelperError(code: "bad_request", status: errSecParam, message: "request frame exceeds limit")
        }
    }
    guard let parsed = try? JSONSerialization.jsonObject(with: input), let object = parsed as? [String: Any] else {
        throw HelperError(code: "bad_request", status: errSecParam, message: "expected one bounded JSON object")
    }
    return object
}

func writeFrame(_ object: [String: Any]) throws {
    let raw = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    guard raw.count < maxRequestBytes else {
        throw HelperError(code: "bad_request", status: errSecParam, message: "response frame exceeds limit")
    }
    FileHandle.standardOutput.write(raw)
    FileHandle.standardOutput.write(Data([10]))
}

// Parse the canonical label for one exact supported owner key. The display
// uses that same service and generation; the reason cannot supply its own label.
func documentKeyDisplay(_ label: String) -> String? {
    let prefix = "works.relux.mac-keyvault.key."
    guard label.hasPrefix(prefix) else { return nil }
    let parts = label.dropFirst(prefix.count).split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 3, parts[1] == "grants-owner-v1", parts[2].first == "v",
          let generation = Int32(parts[2].dropFirst()), generation > 0,
          parts[2] == "v" + String(generation) else { return nil }
    let service = parts[0].utf8
    guard (1...40).contains(service.count), service.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }) else { return nil }
    return "\(parts[0])/\(parts[1]) v\(generation)"
}

// Immutable owned bytes and a closed identity. No generic reason filtering,
// digest-prefix UI, external callback or separate-process consent token.
struct DocumentPlan {
    let bytes: Data
    let text: String
    let digest: Data
    let point: Data
    let spki: Data
    let label: String
    let reason: String
    let keyDisplay: String

    init(_ object: [String: Any]) throws {
        guard Set(object.keys) == Set(["document", "digest", "point", "spki", "label", "reason"]) else {
            throw HelperError(code: "bad_request", status: errSecParam, message: "document binding fields differ")
        }
        bytes = try decodeBase64(object["document"], "document")
        digest = try decodeBase64(object["digest"], "digest")
        point = try decodeBase64(object["point"], "point")
        spki = try decodeBase64(object["spki"], "spki")
        label = (object["label"] as? String) ?? ""
        reason = (object["reason"] as? String) ?? ""
        guard let decoded = String(data: bytes, encoding: .utf8), Data(decoded.utf8) == bytes,
              !bytes.isEmpty, bytes.count <= 16384,
              digest == Data(SHA256.hash(data: bytes)),
              let display = documentKeyDisplay(label),
              point.count == 65, spki.count <= 1024,
              reason == "mac-keyvault: sign exact UTF-8 document SHA256 \(digest.map { String(format: "%02x", $0) }.joined()) with \(display)",
              reason.unicodeScalars.count <= maxReasonLength,
              !reason.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) || CharacterSet.illegalCharacters.contains($0) }) else {
            throw HelperError(code: "bad_request", status: errSecParam, message: "document bytes/digest/key/reason mismatch")
        }
        let publicKey = try P256.Signing.PublicKey(x963Representation: point)
        guard publicKey.derRepresentation == spki else {
            throw HelperError(code: "bad_request", status: errSecParam, message: "native public point differs from exact SPKI pin")
        }
        // Duplicate the conservative admission at the final native boundary.
        guard !decoded.contains("BEGIN DOCUMENT"), !decoded.contains("END DOCUMENT"), !decoded.contains("UNSIGNED exact UTF-8 document;") else {
            throw HelperError(code: "document_display", status: errSecParam, message: "document impersonates review framing")
        }
        let lines = decoded.components(separatedBy: "\n")
        guard lines.count <= 256, decoded.unicodeScalars.contains(where: { $0.value != 32 && $0.value != 10 }) else {
            throw HelperError(code: "document_display", status: errSecParam, message: "document line/visibility bound")
        }
        for line in lines {
            guard line.unicodeScalars.count <= 160, !line.hasPrefix(" "), !line.hasSuffix(" "), !line.contains("  ") else {
                throw HelperError(code: "document_display", status: errSecParam, message: "document spacing/line bound")
            }
            for scalar in line.unicodeScalars {
                let n = scalar.value
                guard (32...126).contains(n) || (0x410...0x44f).contains(n) || n == 0x401 || n == 0x451 || "«»–—‘’“”…№".unicodeScalars.contains(scalar) else {
                    throw HelperError(code: "document_display", status: errSecParam, message: "unsupported document scalar")
                }
            }
        }
        text = decoded
        keyDisplay = display
    }

    var binding: [String: Any] {
        return ["document": bytes.base64EncodedString(), "digest": digest.base64EncodedString(),
                "point": point.base64EncodedString(), "spki": spki.base64EncodedString(), "label": label, "reason": reason]
    }

    func matches(_ other: DocumentPlan) -> Bool {
        return bytes == other.bytes && digest == other.digest && point == other.point && spki == other.spki && label == other.label && reason == other.reason
    }
}

// AppKit plain text is data inside a separate bordered view. Trusted controls
// identify the key, public SPKI hash, all digest bytes, byte count and final LF.
// Scrolling makes every admitted line available; reaching the end does not prove
// reading. Explicit consent remains a separate unchecked control and button.
final class DocumentReviewWindow: NSObject, NSWindowDelegate {
    let plan: DocumentPlan
    let window: NSWindow
    let textView: NSTextView
    let scroll: NSScrollView
    let consent: NSButton
    let confirm: NSButton
    var bottomSeen = false
    var observer: NSObjectProtocol?

    init(_ plan: DocumentPlan) throws {
        self.plan = plan
        guard Thread.isMainThread, let screen = NSScreen.main else {
            throw HelperError(code: "document_display", status: errSecNotAvailable, message: "no native display")
        }
        let font = NSFont.monospacedSystemFont(ofSize: 13, weight: .regular)
        let ctFont = CTFontCreateWithName(font.fontName as CFString, font.pointSize, nil)
        let units = Array(plan.text.replacingOccurrences(of: "\n", with: "").utf16)
        var glyphs = [CGGlyph](repeating: 0, count: units.count)
        guard !units.isEmpty, CTFontGetGlyphsForCharacters(ctFont, units, &glyphs, units.count), !glyphs.contains(0) else {
            throw HelperError(code: "document_display", status: errSecParam, message: "native font has a missing glyph")
        }
        let paragraph = NSMutableParagraphStyle()
        paragraph.lineBreakMode = .byClipping
        paragraph.baseWritingDirection = .leftToRight
        let attributes: [NSAttributedString.Key: Any] = [.font: font, .paragraphStyle: paragraph, .ligature: 0, .kern: 0, .foregroundColor: NSColor.textColor]
        let longest = plan.text.components(separatedBy: "\n").map { ($0 as NSString).size(withAttributes: attributes).width }.max() ?? 0
        let width = max(880, ceil(longest) + 100)
        let height = min(780, screen.visibleFrame.height - 100)
        guard width <= screen.visibleFrame.width - 80, height >= 540 else {
            throw HelperError(code: "document_display", status: errSecNotAvailable, message: "display cannot fit complete unwrapped document lines")
        }
        let reviewWindow = NSWindow(contentRect: NSRect(x: 0, y: 0, width: width, height: height), styleMask: [.titled, .closable], backing: .buffered, defer: false)
        reviewWindow.title = "Review exact owner document"
        reviewWindow.isReleasedWhenClosed = false
        let scrollView = NSScrollView(frame: NSRect(x: 20, y: 112, width: width - 40, height: height - 290))
        scrollView.hasVerticalScroller = true
        scrollView.hasHorizontalScroller = false
        scrollView.borderType = .bezelBorder
        scrollView.autohidesScrollers = false
        let containerWidth = scrollView.contentSize.width - 24
        let storage = NSTextStorage(string: plan.text, attributes: attributes)
        let layout = NSLayoutManager()
        let container = NSTextContainer(containerSize: NSSize(width: containerWidth, height: 100000))
        container.lineFragmentPadding = 0
        container.widthTracksTextView = false
        container.heightTracksTextView = false
        container.maximumNumberOfLines = 0
        layout.addTextContainer(container)
        storage.addLayoutManager(layout)
        layout.ensureLayout(for: container)
        let range = layout.glyphRange(for: container)
        let chars = layout.characterRange(forGlyphRange: range, actualGlyphRange: nil)
        let used = layout.usedRect(for: container)
        var overflow = false
        layout.enumerateLineFragments(forGlyphRange: range) { _, rect, _, _, _ in
            if rect.minX < 0 || rect.maxX > containerWidth { overflow = true }
        }
        guard range.location == 0, range.length == layout.numberOfGlyphs,
              chars.location == 0, chars.length == (plan.text as NSString).length,
              !overflow, used.maxX <= containerWidth, used.maxY < 99900 else {
            throw HelperError(code: "document_display", status: errSecParam, message: "native document layout is incomplete or overflows")
        }
        let documentView = NSTextView(frame: NSRect(x: 0, y: 0, width: scrollView.contentSize.width, height: max(scrollView.contentSize.height, ceil(used.maxY) + 48)), textContainer: container)
        documentView.textContainerInset = NSSize(width: 12, height: 12)
        documentView.isEditable = false
        documentView.isSelectable = true
        documentView.isRichText = false
        documentView.usesFontPanel = false
        documentView.menu = nil
        documentView.isHorizontallyResizable = false
        documentView.isVerticallyResizable = false
        let consentButton = NSButton(checkboxWithTitle: "I reviewed the complete exact text and authorize this one signature.", target: nil, action: nil)
        consentButton.frame = NSRect(x: 20, y: 70, width: width - 40, height: 26)
        consentButton.state = .off
        let confirmButton = NSButton(title: "Confirm text, then authenticate", target: nil, action: nil)
        confirmButton.frame = NSRect(x: width - 330, y: 20, width: 310, height: 34)
        confirmButton.isEnabled = false
        self.window = reviewWindow
        self.scroll = scrollView
        self.textView = documentView
        self.consent = consentButton
        self.confirm = confirmButton
        super.init()
        window.delegate = self
        window.center()
        guard let content = window.contentView else { throw HelperError(code: "document_display", status: errSecParam, message: "no review content view") }
        let digestHex = plan.digest.map { String(format: "%02x", $0) }.joined()
        let spkiHash = Data(SHA256.hash(data: plan.spki)).map { String(format: "%02x", $0) }.joined()
        let terminalLF = plan.bytes.last == 10 ? "present" : "absent"
        let header = NSTextField(wrappingLabelWithString: "SIGNATURE REVIEW — document below is plain data\nKey: \(plan.keyDisplay) (Secure Enclave; presence required)\nPublic SPKI SHA256: \(spkiHash)\nDocument SHA256: \(digestHex)\nExact UTF-8: \(plan.bytes.count) bytes; terminal LF \(terminalLF). Scroll to the end, then confirm. No grant authority is asserted.")
        header.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
        header.frame = NSRect(x: 20, y: height - 162, width: width - 40, height: 142)
        content.addSubview(header)
        scroll.documentView = textView
        content.addSubview(scroll)
        consent.target = self
        consent.action = #selector(updateConsent)
        content.addSubview(consent)
        confirm.target = self
        confirm.action = #selector(accept)
        content.addSubview(confirm)
        let cancel = NSButton(title: "Cancel", target: self, action: #selector(cancelReview))
        cancel.frame = NSRect(x: 20, y: 20, width: 120, height: 34)
        cancel.keyEquivalent = "\u{1b}"
        content.addSubview(cancel)
        scroll.contentView.postsBoundsChangedNotifications = true
        observer = NotificationCenter.default.addObserver(forName: NSView.boundsDidChangeNotification, object: scroll.contentView, queue: .main) { [weak self] _ in self?.updateConsent() }
        textView.scroll(NSPoint.zero)
    }

    deinit { if let observer = observer { NotificationCenter.default.removeObserver(observer) } }

    @objc func updateConsent() {
        if scroll.contentView.bounds.maxY >= textView.bounds.maxY - 1 { bottomSeen = true }
        let onScreen = window.screen.map { $0.visibleFrame.contains(window.frame) } ?? false
        confirm.isEnabled = bottomSeen && consent.state == .on && onScreen && completeLayout()
    }

    func completeLayout() -> Bool {
        guard Data(textView.string.utf8) == plan.bytes, let layout = textView.layoutManager, let container = textView.textContainer else { return false }
        layout.ensureLayout(for: container)
        let glyphs = layout.glyphRange(for: container)
        let characters = layout.characterRange(forGlyphRange: glyphs, actualGlyphRange: nil)
        let used = layout.usedRect(for: container)
        let bounds = layout.boundingRect(forGlyphRange: glyphs, in: container)
        return glyphs.location == 0 && glyphs.length == layout.numberOfGlyphs && characters.location == 0 && characters.length == (plan.text as NSString).length && used.maxX <= container.containerSize.width && bounds.minX >= 0 && bounds.maxX <= container.containerSize.width && used.maxY + 24 <= textView.bounds.height && container.containerSize.width <= scroll.contentSize.width - 24
    }

    @objc func accept() {
        updateConsent()
        guard confirm.isEnabled, window.isVisible, Data(textView.string.utf8) == plan.bytes else { return }
        NSApplication.shared.stopModal(withCode: .OK)
    }

    @objc func cancelReview() { NSApplication.shared.stopModal(withCode: .cancel) }
    func windowShouldClose(_ sender: NSWindow) -> Bool { cancelReview(); return false }

    func run() throws {
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        window.makeKeyAndOrderFront(nil)
        app.activate(ignoringOtherApps: true)
        window.displayIfNeeded()
        updateConsent()
        let answer = app.runModal(for: window)
        window.orderOut(nil)
        guard answer == .OK, bottomSeen, consent.state == .on, Data(textView.string.utf8) == plan.bytes else {
            throw HelperError(code: "user_canceled", status: errSecUserCanceled, message: "complete document consent canceled; nothing signed")
        }
    }
}

func reviewDocument(_ request: [String: Any]) throws -> [String: Any] {
    guard Set(request.keys) == Set(["op", "blob", "presence", "review"]), request["presence"] as? String == "required",
          let review = request["review"] as? [String: Any] else {
        throw HelperError(code: "bad_request", status: errSecParam, message: "full review requires the closed presence-bound request")
    }
    let plan = try DocumentPlan(review)
    let blob = try decodeBase64(request["blob"], "blob")
    // Public inspection only, before review; no silent signing probe here.
    let publicKey = try loadKey(blob, context: silentContext()).publicKey
    guard publicKey.x963Representation == plan.point, publicKey.derRepresentation == plan.spki else {
        throw HelperError(code: "invalid_blob", status: errSecDecode, message: "native key differs from displayed public identity")
    }
    let app = NSApplication.shared
    app.setActivationPolicy(.regular)
    app.finishLaunching()
    try DocumentReviewWindow(plan).run()
    var confirmed = plan.binding
    confirmed["phase"] = "confirmed"
    try writeFrame(confirmed)
    // Same process and immutable plan; the Go parent now rechecks source,
    // custody and cancellation. A boolean/digest alone cannot dispatch.
    var dispatch = try readFrame()
    guard dispatch.removeValue(forKey: "phase") as? String == "dispatch", plan.matches(try DocumentPlan(dispatch)) else {
        throw HelperError(code: "bad_request", status: errSecParam, message: "final document dispatch differs from consent")
    }
    guard try presenceEnforced(blob) else {
        throw HelperError(code: "presence_not_enforced", status: errSecAuthFailed, message: "owner key does not enforce presence")
    }
    let context = LAContext()
    // Exact validated reason; no filtering, prefix digest or clipping.
    context.localizedReason = plan.reason
    let key = try loadKey(blob, context: context)
    guard key.publicKey.x963Representation == plan.point, key.publicKey.derRepresentation == plan.spki, Data(SHA256.hash(data: plan.bytes)) == plan.digest else {
        throw HelperError(code: "bad_request", status: errSecParam, message: "final native key/digest mismatch")
    }
    let digest = try sha256Digest(plan.digest)
    let signature: P256.Signing.ECDSASignature
    do { signature = try key.signature(for: digest) }
    catch { throw translate(error, "owner document sign") }
    guard publicKey.isValidSignature(signature, for: digest) else {
        throw HelperError(code: "security", status: errSecAuthFailed, message: "native exact-byte verification failed")
    }
    return ["der": signature.derRepresentation.base64EncodedString(), "point": plan.point.base64EncodedString()]
}


// Internal presentation only. No JSON/private-protocol operation dispatches here.
// The future transaction engine must construct this snapshot from its one owned
// parsed plan and frozen review frame, not caller prose or a display-authority bit.
// This type neither parses PSBT nor defines a new review/wire frame.
enum NamecoinReviewOperation: String {
    case nameNew = "name_new"
    case nameFirstupdate = "name_firstupdate"
    case journalInitialize = "initialize journal"
    case reconcile = "reconcile journal"

    var consent: String {
        switch self {
        case .nameNew, .nameFirstupdate:
            return "I authorize this transaction. Exported signatures can be submitted by their holder."
        case .journalInitialize:
            return "I authorize first journal initialization in this adoption sitting. No transaction is signed."
        case .reconcile:
            return "I authorize inspection of the existing journal. No new signature or initialization."
        }
    }
}

// The engine must choose semantic kinds for parsed NAME/VALUE facts. Default
// binary facts preserve existing journal callers; opaque escaped/hex bytes do
// not establish meaningful consent to a name or value. This is display policy,
// not a PSBT/name/value parser or proof that facts belong to a review frame.
enum NamecoinReviewFactKind: String {
    case binary = "Binary bytes (not semantic NAME/VALUE consent)"
    case semanticName = "Semantic NAME (printable ASCII)"
    case semanticValue = "Semantic VALUE (printable ASCII)"
}

struct NamecoinReviewFact {
    let label: String
    let bytes: Data
    let kind: NamecoinReviewFactKind

    init(label: String, bytes: Data, kind: NamecoinReviewFactKind = .binary) throws {
        guard !label.isEmpty, label.utf8.count <= 72,
              label.utf8.allSatisfy({ (32...126).contains($0) }),
              label.first != " ", label.last != " ", bytes.count <= 262144 else {
            throw HelperError(code: "document_display", status: errSecParam, message: "invalid internal review fact")
        }
        // Copy even foreign mutable backing before validation/rendering. No
        // later external mutation can replace the admitted semantic bytes.
        let owned = bytes.isEmpty ? Data() : bytes.withUnsafeBytes { Data(bytes: $0.baseAddress!, count: $0.count) }
        switch kind {
        case .binary: break
        case .semanticName, .semanticValue:
            // Qualified text is exactly bytes32...126. Reject control, newline,
            // bidi and all other non-ASCII encodings; do not replace or normalize.
            // This predicate admits empty bytes, rendered explicitly below.
            guard owned.allSatisfy({ (32...126).contains($0) }) else {
                throw HelperError(code: "document_display", status: errSecParam, message: "unrenderable semantic review text")
            }
        }
        self.label = label
        self.bytes = owned
        self.kind = kind
    }
}

struct NamecoinReviewSnapshot {
    let operation: NamecoinReviewOperation
    let account: String
    let feeAtoms: UInt64
    let digest: Data
    let text: String
    let reason: String

    init(operation: NamecoinReviewOperation, account: String, feeAtoms: UInt64,
         frozenReviewFrame: Data, facts: [NamecoinReviewFact]) throws {
        // Account is display-shaped here; the trusted engine/storage must admit
        // its exact retained identity/generation. This is no new account policy.
        guard !account.isEmpty, account.utf8.count <= 96,
              account.utf8.allSatisfy({ (33...126).contains($0) }),
              !frozenReviewFrame.isEmpty, frozenReviewFrame.count <= 5 * 1024 * 1024,
              !facts.isEmpty, facts.count <= 2048,
              Set(facts.map { $0.label }).count == facts.count,
              (operation == .nameNew || operation == .nameFirstupdate) || feeAtoms == 0 else {
            throw HelperError(code: "document_display", status: errSecParam, message: "invalid internal review snapshot")
        }
        self.operation = operation
        self.account = account
        self.feeAtoms = feeAtoms
        let ownedFrame = frozenReviewFrame.withUnsafeBytes { Data(bytes: $0.baseAddress!, count: $0.count) }
        digest = Data(SHA256.hash(data: ownedFrame))
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        reason = "Namecoin \(operation.rawValue); account \(account); fee \(feeAtoms) atoms; review SHA256 \(hex)"
        var lines = ["NAMECOIN NATIVE REVIEW", "Operation: \(operation.rawValue)", "Account: \(account)",
                     "Fee atoms: \(feeAtoms)", "Review SHA256: \(hex)", operation.consent,
                     "Semantic NAME/VALUE text is printable ASCII only; binary bytes are not semantic consent.",
                     "Fact values show escaped ASCII and all hexadecimal bytes; empty values are explicit."]
        var total = 0
        for fact in facts {
            total += fact.bytes.count
            guard total <= 1048576 else {
                throw HelperError(code: "document_display", status: errSecParam, message: "review exceeds display bound")
            }
            lines.append("\(fact.label) [\(fact.bytes.count) bytes]")
            lines.append("  Kind: " + fact.kind.rawValue)
            if fact.bytes.isEmpty { lines.append("(empty)") }
            switch fact.kind {
            case .binary: break
            case .semanticName, .semanticValue:
                // Construction admitted exact ASCII; decoding cannot repair or
                // substitute a byte. Empty VALUE remains visibly distinct.
                lines.append("  Text: " + (fact.bytes.isEmpty ? "(empty)" : String(decoding: fact.bytes, as: UTF8.self)))
            }
            let value = Array(fact.bytes)
            let escaped = value.map { byte -> String in
                if byte == 92 { return "\\\\" }
                if (32...126).contains(byte) { return String(UnicodeScalar(byte)) }
                return String(format: "\\x%02x", byte)
            }.joined()
            lines.append("  Escaped ASCII: " + escaped)
            lines.append("  Hexadecimal:")
            for offset in stride(from: 0, to: value.count, by: 32) {
                lines.append(value[offset..<min(offset + 32, value.count)].map { String(format: "%02x", $0) }.joined())
            }
        }
        lines.append("END OF COMPLETE INTERNAL REVIEW")
        text = lines.joined(separator: "\n")
    }
}

// All admitted bytes are laid out in one immutable plain-text view. Long lines
// wrap, never elide; range checks refuse missing glyphs or incomplete layout.
// Scrolling and checking consent are UI controls, not proof that someone read.
final class NamecoinReviewWindow: NSObject, NSWindowDelegate {
    let snapshot: NamecoinReviewSnapshot
    let window: NSWindow
    let scroll: NSScrollView
    let textView: NSTextView
    let consent: NSButton
    let confirm: NSButton
    var observer: NSObjectProtocol?
    var bottomSeen = false

    init(_ snapshot: NamecoinReviewSnapshot) throws {
        guard Thread.isMainThread, let screen = NSScreen.main,
              screen.visibleFrame.width >= 850, screen.visibleFrame.height >= 650 else {
            throw HelperError(code: "document_display", status: errSecNotAvailable, message: "native display unavailable")
        }
        self.snapshot = snapshot
        let width: CGFloat = min(1000, screen.visibleFrame.width - 80)
        let height: CGFloat = min(800, screen.visibleFrame.height - 100)
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: width, height: height),
                          styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "Namecoin: review exact internal operation"
        window.isReleasedWhenClosed = false
        scroll = NSScrollView(frame: NSRect(x: 20, y: 140, width: width - 40, height: height - 200))
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = false
        scroll.autohidesScrollers = false
        scroll.borderType = .bezelBorder
        let font = NSFont.monospacedSystemFont(ofSize: 13, weight: .regular)
        let ctFont = CTFontCreateWithName(font.fontName as CFString, font.pointSize, nil)
        let units = Array(snapshot.text.replacingOccurrences(of: "\n", with: "").utf16)
        var glyphs = [CGGlyph](repeating: 0, count: units.count)
        guard CTFontGetGlyphsForCharacters(ctFont, units, &glyphs, units.count), !glyphs.contains(0) else {
            throw HelperError(code: "document_display", status: errSecParam, message: "native review glyph missing")
        }
        let paragraph = NSMutableParagraphStyle()
        paragraph.lineBreakMode = .byCharWrapping
        paragraph.baseWritingDirection = .leftToRight
        let storage = NSTextStorage(string: snapshot.text, attributes: [.font: font, .paragraphStyle: paragraph, .ligature: 0, .kern: 0])
        let layout = NSLayoutManager()
        let container = NSTextContainer(containerSize: NSSize(width: scroll.contentSize.width - 24, height: 10000000))
        container.lineFragmentPadding = 0
        container.widthTracksTextView = false
        container.heightTracksTextView = false
        container.maximumNumberOfLines = 0
        layout.addTextContainer(container)
        storage.addLayoutManager(layout)
        layout.ensureLayout(for: container)
        let used = layout.usedRect(for: container)
        textView = NSTextView(frame: NSRect(x: 0, y: 0, width: scroll.contentSize.width,
                              height: max(scroll.contentSize.height, ceil(used.maxY) + 48)), textContainer: container)
        textView.textContainerInset = NSSize(width: 12, height: 12)
        textView.isEditable = false
        textView.isSelectable = true
        textView.isRichText = false
        textView.usesFontPanel = false
        textView.menu = nil
        textView.isHorizontallyResizable = false
        textView.isVerticallyResizable = false
        consent = NSButton(checkboxWithTitle: "I reviewed all facts and authorize the exact operation above.", target: nil, action: nil)
        consent.frame = NSRect(x: 20, y: 90, width: width - 40, height: 28)
        consent.state = .off
        confirm = NSButton(title: "Confirm review, then use Touch ID", target: nil, action: nil)
        confirm.frame = NSRect(x: width - 350, y: 25, width: 330, height: 36)
        confirm.isEnabled = false
        super.init()
        guard completeLayout(), let content = window.contentView else {
            throw HelperError(code: "document_display", status: errSecParam, message: "native review layout incomplete")
        }
        window.delegate = self
        window.center()
        scroll.documentView = textView
        content.addSubview(scroll)
        content.addSubview(consent)
        content.addSubview(confirm)
        consent.target = self
        consent.action = #selector(updateConsent)
        confirm.target = self
        confirm.action = #selector(accept)
        let cancel = NSButton(title: "Cancel", target: self, action: #selector(cancelReview))
        cancel.frame = NSRect(x: 20, y: 25, width: 120, height: 36)
        cancel.keyEquivalent = "\u{1b}"
        content.addSubview(cancel)
        scroll.contentView.postsBoundsChangedNotifications = true
        observer = NotificationCenter.default.addObserver(forName: NSView.boundsDidChangeNotification, object: scroll.contentView, queue: .main) { [weak self] _ in self?.updateConsent() }
        textView.scroll(NSPoint.zero)
    }

    deinit { if let observer = observer { NotificationCenter.default.removeObserver(observer) } }

    func completeLayout() -> Bool {
        guard textView.string == snapshot.text, let layout = textView.layoutManager,
              let container = textView.textContainer else { return false }
        layout.ensureLayout(for: container)
        let glyphs = layout.glyphRange(for: container)
        let chars = layout.characterRange(forGlyphRange: glyphs, actualGlyphRange: nil)
        let used = layout.usedRect(for: container)
        let bounds = layout.boundingRect(forGlyphRange: glyphs, in: container)
        return glyphs.location == 0 && glyphs.length == layout.numberOfGlyphs && chars.location == 0 &&
               chars.length == (snapshot.text as NSString).length && bounds.minX >= 0 &&
               bounds.maxX <= container.containerSize.width && used.maxY + 24 <= textView.bounds.height &&
               container.containerSize.width <= scroll.contentSize.width - 24
    }

    @objc func updateConsent() {
        if scroll.contentView.bounds.maxY >= textView.bounds.maxY - 1 { bottomSeen = true }
        let onScreen = window.screen.map { $0.visibleFrame.contains(window.frame) } ?? false
        confirm.isEnabled = bottomSeen && consent.state == .on && onScreen && completeLayout()
    }
    @objc func accept() {
        updateConsent()
        guard confirm.isEnabled, window.isVisible else { return }
        NSApplication.shared.stopModal(withCode: .OK)
    }
    @objc func cancelReview() { NSApplication.shared.stopModal(withCode: .cancel) }
    func windowShouldClose(_ sender: NSWindow) -> Bool { cancelReview(); return false }

    func run() throws {
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        app.finishLaunching()
        window.makeKeyAndOrderFront(nil)
        app.activate(ignoringOtherApps: true)
        window.displayIfNeeded()
        updateConsent()
        let answer = app.runModal(for: window)
        window.orderOut(nil)
        guard answer == .OK, bottomSeen, consent.state == .on, completeLayout() else {
            throw HelperError(code: "user_canceled", status: errSecUserCanceled, message: "Namecoin review refused")
        }
    }
}

// A context never escapes this operation and is invalidated on every exit. The
// internal engine must use this same immutable snapshot/account and recheck its
// review-frame binding before private use. There is no caller consent boolean,
// cross-process consent token, context cache, password fallback or public route.
@MainActor
func withNamecoinReviewedBiometrics<T>(_ snapshot: NamecoinReviewSnapshot,
                                      operation: (LAContext) throws -> T) async throws -> T {
    try NamecoinReviewWindow(snapshot).run()
    let context = LAContext()
    context.localizedFallbackTitle = ""
    context.localizedReason = snapshot.reason
    context.touchIDAuthenticationAllowableReuseDuration = 0
    defer { context.invalidate() }
    try NativeNamecoinBiometryPolicy.requireTouchID(on: context)
    do {
        guard try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: snapshot.reason) else {
            throw HelperError(code: "auth_refused", status: errSecAuthFailed, message: "Namecoin biometry refused")
        }
    } catch let error as HelperError { throw error }
    catch { throw translate(error, "Namecoin reviewed biometry") }
    // Operation/storage refusals keep their closed type, especially UNKNOWN
    // after a possible mutation. Only biometric failures are translated above.
    return try operation(context)
}


// Recovery mode has a separate bounded binary protocol. It is never dispatched
// from the existing public JSON operations and waits for the verified parent.
func recoveryWrite(_ status: UInt8, _ payload: Data) {
    var length = UInt32(payload.count).bigEndian
    var frame = Data([status])
    withUnsafeBytes(of: &length) { frame.append(contentsOf: $0) }
    frame.append(payload)
    FileHandle.standardOutput.write(frame)
    frame.resetBytes(in: 0..<frame.count)
}

func recoveryRead(_ count: Int) throws -> Data {
    var output = Data()
    while output.count < count {
        let part = FileHandle.standardInput.readData(ofLength: count - output.count)
        guard !part.isEmpty else { throw HelperError(code: "bad_request", status: errSecParam, message: "incomplete private frame") }
        output.append(part)
    }
    return output
}

func recoveryRequest() throws -> [String: String] {
    let sizeBytes = try recoveryRead(4)
    let count = sizeBytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    guard count > 0 && count <= 32768 else { throw HelperError(code: "bad_request", status: errSecParam, message: "private frame too large") }
    let raw = try recoveryRead(Int(count))
    guard FileHandle.standardInput.readData(ofLength: 1).isEmpty,
          let values = try JSONSerialization.jsonObject(with: raw) as? [String: String],
          let op = values["op"] else { throw HelperError(code: "bad_request", status: errSecParam, message: "invalid private request") }
    let fields: [String]
    switch op {
    case "create-wrap": fields = ["op", "purpose"]
    case "unwrap-nostr": fields = ["op", "blob", "point", "ciphertext"]
    case "qualify-wrap": fields = ["op", "purpose", "blob", "point"]
    default: throw HelperError(code: "bad_request", status: errSecParam, message: "unknown private operation")
    }
    guard Set(values.keys) == Set(fields) else { throw HelperError(code: "bad_request", status: errSecParam, message: "private request fields") }
    // Exact parent encoding rejects duplicate/escaped keys, trailing data and
    // alternate encodings before any hardware operation. Values are ASCII
    // operation/purpose identifiers or canonical standard base64.
    var parts = [String]()
    for field in fields {
        guard let value = values[field], value.utf8.allSatisfy({ byte in
            (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122) || (byte >= 48 && byte <= 57) || [43,47,61,45].contains(byte)
        }) else { throw HelperError(code: "bad_request", status: errSecParam, message: "private request encoding") }
        parts.append("\"" + field + "\":\"" + value + "\"")
    }
    guard raw == Data(("{" + parts.joined(separator: ",") + "}").utf8) else { throw HelperError(code: "bad_request", status: errSecParam, message: "noncanonical private request") }
    return values
}

func recoveryData(_ text: String?, _ maximum: Int, _ exact: Int? = nil) throws -> Data {
    guard let text = text, text.count <= ((maximum + 2) / 3) * 4,
          let data = Data(base64Encoded: text), data.count > 0, data.count <= maximum,
          data.base64EncodedString() == text, exact == nil || data.count == exact else {
        throw HelperError(code: "bad_request", status: errSecParam, message: "invalid private field")
    }
    return data
}

func recoveryAccessControl(_ purpose: String) throws -> SecAccessControl {
    let flags: SecAccessControlCreateFlags
    switch purpose {
    case "nostr": flags = [.privateKeyUsage]
    case "namecoin": flags = [.privateKeyUsage, .biometryAny]
    default: throw HelperError(code: "bad_request", status: errSecParam, message: "invalid purpose")
    }
    // Positive policy allowlist: userPresence would admit password fallback;
    // biometryCurrentSet would invalidate backup access after enrollment changes.
    let expected: SecAccessControlCreateFlags = purpose == "namecoin" ? [.privateKeyUsage, .biometryAny] : [.privateKeyUsage]
    guard flags == expected else { throw HelperError(code: "policy_refused", status: errSecAuthFailed, message: "wrapping policy") }
    var error: Unmanaged<CFError>?
    guard let control = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error) else {
        throw HelperError(code: "policy_refused", status: errSecAuthFailed, message: "wrapping access control")
    }
    return control
}

func recoveryLoad(_ blob: Data, _ context: LAContext) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
    guard SecureEnclave.isAvailable else { throw HelperError(code: "enclave_unavailable", status: errSecNotAvailable, message: "hardware unavailable") }
    return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob, authenticationContext: context)
}

func recoveryFixtureKey() throws -> P256.KeyAgreement.PrivateKey {
    // Public disposable fixture scalar 1. This is not owner key material.
    var bytes = Data(repeating: 0, count: 32); bytes[31] = 1
    defer { bytes.resetBytes(in: 0..<bytes.count) }
    return try P256.KeyAgreement.PrivateKey(rawRepresentation: bytes)
}

func recoverySilentPolicy(_ blob: Data, _ purpose: String) throws -> Bool {
    let context = silentContext()
    defer { context.invalidate() }
    let key = try recoveryLoad(blob, context)
    let peer = try recoveryFixtureKey()
    do {
        _ = try key.sharedSecretFromKeyAgreement(with: peer.publicKey)
        guard purpose == "nostr" else { throw HelperError(code: "policy_refused", status: errSecAuthFailed, message: "presence key used silently") }
        return false
    } catch let error as HelperError { throw error }
    catch {
        let mapped = translate(error, "recovery presence probe")
        guard purpose == "namecoin" && (mapped.code == "presence_required" || mapped.status == errSecInteractionNotAllowed) else { throw mapped }
        return true
    }
}

func recoveryFixtureQualification(_ blob: Data, _ point: Data, _ purpose: String) throws {
    _ = try recoverySilentPolicy(blob, purpose)
    let context = LAContext()
    context.localizedFallbackTitle = ""
    context.localizedReason = "Qualify the Namecoin account wrapping key with a public fixture; no transaction is signed"
    defer { context.invalidate() }
    let key = try recoveryLoad(blob, context)
    guard key.publicKey.x963Representation == point else { throw HelperError(code: "invalid_blob", status: errSecDecode, message: "wrapping point mismatch") }
    let peer = try recoveryFixtureKey()
    let shared = try key.sharedSecretFromKeyAgreement(with: peer.publicKey)
    let expected = try peer.sharedSecretFromKeyAgreement(with: key.publicKey)
    // Compare derived public-fixture check values; never export hardware private
    // keys or introduce a general Namecoin plaintext-returning endpoint.
    let a = shared.x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: Data("recovery-qualification/1".utf8), outputByteCount: 32)
    let b = expected.x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: Data("recovery-qualification/1".utf8), outputByteCount: 32)
    guard a == b else { throw HelperError(code: "invalid_blob", status: errSecDecode, message: "fixture ECDH mismatch") }
}

func recoveryPrivate() -> Int32 {
    do {
        var inputInfo = stat(), outputInfo = stat()
        guard fstat(STDIN_FILENO, &inputInfo) == 0, fstat(STDOUT_FILENO, &outputInfo) == 0,
              inputInfo.st_mode & mode_t(S_IFMT) == mode_t(S_IFIFO),
              outputInfo.st_mode & mode_t(S_IFMT) == mode_t(S_IFIFO) else {
            throw HelperError(code: "bad_request", status: errSecParam, message: "private anonymous pipes required")
        }
        let request = try recoveryRequest()
        switch request["op"] {
        case "create-wrap":
            guard let purpose = request["purpose"], SecureEnclave.isAvailable else { throw HelperError(code: "enclave_unavailable", status: errSecNotAvailable, message: "hardware unavailable") }
            let context = silentContext()
            defer { context.invalidate() }
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: recoveryAccessControl(purpose), authenticationContext: context)
            let blob = key.dataRepresentation, point = key.publicKey.x963Representation
            guard !blob.isEmpty && blob.count <= 16384 && point.count == 65 else { throw HelperError(code: "invalid_blob", status: errSecDecode, message: "invalid hardware representation") }
            let refused = try recoverySilentPolicy(blob, purpose)
            if purpose == "namecoin" { try recoveryFixtureQualification(blob, point, purpose) }
            let fingerprint = SHA256.hash(data: point).map { String(format: "%02x", $0) }.joined()
            let result: [String: Any] = ["blob": blob.base64EncodedString(), "point": point.base64EncodedString(), "fingerprint": fingerprint, "policy": purpose == "namecoin" ? "biometry-any" : "none", "silent_refused": refused]
            recoveryWrite(0, try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys, .withoutEscapingSlashes]))
            return 0
        case "unwrap-nostr":
            let blob = try recoveryData(request["blob"], 16384)
            let point = try recoveryData(request["point"], 65, 65)
            let ciphertext = try recoveryData(request["ciphertext"], 149, 149)
            let context = silentContext()
            defer { context.invalidate() }
            let key = try recoveryLoad(blob, context)
            guard key.publicKey.x963Representation == point else { throw HelperError(code: "invalid_blob", status: errSecDecode, message: "wrapping point mismatch") }
            let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: ciphertext.prefix(65))
            let secret = try key.sharedSecretFromKeyAgreement(with: ephemeral)
            let derived = secret.x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: ciphertext.prefix(65), outputByteCount: 32)
            var material = derived.withUnsafeBytes { Data($0) }
            defer { material.resetBytes(in: 0..<material.count) }
            let aes = SymmetricKey(data: material.prefix(16))
            let nonce = try AES.GCM.Nonce(data: material.suffix(16))
            let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext.dropFirst(65).dropLast(16), tag: ciphertext.suffix(16))
            var plain = try AES.GCM.open(box, using: aes)
            defer { plain.resetBytes(in: 0..<plain.count) }
            guard plain.count == 68 && plain.prefix(4) == Data("KVN1".utf8) else { throw HelperError(code: "invalid_blob", status: errSecDecode, message: "invalid plaintext frame") }
            recoveryWrite(0, plain)
            return 0
        case "qualify-wrap":
            guard let purpose = request["purpose"], ["nostr", "namecoin"].contains(purpose) else { throw HelperError(code: "bad_request", status: errSecParam, message: "invalid purpose") }
            try recoveryFixtureQualification(recoveryData(request["blob"], 16384), recoveryData(request["point"], 65, 65), purpose)
            recoveryWrite(0, Data("qualified".utf8))
            return 0
        default: throw HelperError(code: "bad_request", status: errSecParam, message: "private operation refused")
        }
    } catch {
        // Closed fixed error vocabulary. No raw exception/input/OS text crosses
        // this seam or reaches stderr, including authentication failures.
        let mapped = (error as? HelperError) ?? translate(error, "recovery")
        let code: String
        switch mapped.code {
        case "presence_required": code = "presence_required"
        case "user_canceled", "auth_failed", "presence_unavailable", "presence_failed": code = "auth_refused"
        case "enclave_unavailable": code = "enclave_unavailable"
        case "bad_request": code = "bad_request"
        case "policy_refused": code = "policy_refused"
        default: code = "invalid_blob"
        }
        recoveryWrite(1, Data(code.utf8))
        return 1
    }
}

public func runKeyvaultHelper() -> Never {
if CommandLine.arguments.dropFirst().first == "--root-grants-qualification-read" {
    exit(rootGrantsQualificationRead())
}
if CommandLine.arguments == [CommandLine.arguments[0], "--root-grants-private-v2"] {
    exit(rootGrantsPrivate())
}
if CommandLine.arguments == [CommandLine.arguments[0], "--root-grants-sign-grant-v3"] {
    exit(rootGrantsSignGrantV3())
}
if CommandLine.arguments == [CommandLine.arguments[0], "--recovery-private"] {
    exit(recoveryPrivate())
}

do {
    let request = try readFrame()
    guard let op = request["op"] as? String else {
        throw HelperError(code: "bad_request", status: errSecParam, message: "missing operation")
    }
    switch op {
    case "create": emit(try create(request), exitCode: 0)
    case "public": emit(try publicKey(request), exitCode: 0)
    case "sign": emit(try sign(request), exitCode: 0)
    case "review-document": emit(try reviewDocument(request), exitCode: 0)
    default: throw HelperError(code: "bad_request", status: errSecParam, message: "unknown operation")
    }
} catch let error as HelperError {
    fail(error)
} catch {
    fail(translate(error, "helper"))
}
}
