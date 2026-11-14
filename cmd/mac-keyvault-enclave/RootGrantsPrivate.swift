import AppKit
import CoreText
import CryptoKit
import Darwin
import Dispatch
import Foundation
import LocalAuthentication
import Security

// Finite PUBLIC/SEALED transport only. Decoding a frame never proves an
// authenticated helper, native review, wrap qualification or parent custody.
enum RootGrantsPrivateFrame {
    enum Payload { case sealed(Data), signature(Data), refusal(RootGrantsStatus) }
    static func number(_ bytes: Data) throws -> Int {
        guard bytes.count == 4 else { throw RootGrantsReviewError(status: .invalidArguments) }
        return bytes.reduce(0) { ($0 << 8) | Int($1) }
    }
    static func word(_ value: UInt32) -> Data {
        var value = value.bigEndian
        return withUnsafeBytes(of: &value) { Data($0) }
    }
    static func request(_ frame: Data) throws -> Data {
        guard frame.count >= 4 else { throw RootGrantsReviewError(status: .invalidArguments) }
        let length = try number(Data(frame.prefix(4)))
        guard (1...262144).contains(length), frame.count == length + 4 else {
            throw RootGrantsReviewError(status: .invalidArguments)
        }
        return frame.dropFirst(4).withUnsafeBytes { Data($0) }
    }
    static func response(_ payload: Payload) throws -> Data {
        switch payload {
        case .sealed(let bytes):
            guard (1...131072).contains(bytes.count) else { throw RootGrantsReviewError(status: .limitExceeded) }
            return Data([0]) + word(UInt32(bytes.count)) + bytes
        case .signature(let bytes):
            guard bytes.count == 64 else { throw RootGrantsReviewError(status: .privateProtocolError) }
            return Data([0]) + word(64) + bytes
        case .refusal(let status):
            let fixed = status == .success ? RootGrantsStatus.privateProtocolError : status
            return Data([1]) + word(4) + word(UInt32(fixed.rawValue))
        }
    }
    static func decodeResponse(_ frame: Data) throws -> Payload {
        guard frame.count >= 5 else { throw RootGrantsReviewError(status: .privateProtocolError) }
        let length = try number(Data(frame.dropFirst().prefix(4)))
        guard frame.count == length + 5 else { throw RootGrantsReviewError(status: .privateProtocolError) }
        let bytes = Data(frame.dropFirst(5))
        switch frame.first {
        case 0 where (1...131072).contains(length): return .sealed(bytes)
        case 1 where length == 4:
            let raw = try number(bytes)
            guard (1...24).contains(raw) else {
                throw RootGrantsReviewError(status: .privateProtocolError)
            }
            let status = RootGrantsStatus.helperClosed(Int32(raw))
            return .refusal(status)
        default: throw RootGrantsReviewError(status: .privateProtocolError)
        }
    }
}

enum RootGrantsPrivateControl {
    static func recheck(stage: UInt8, remainingNanoseconds: UInt64) throws -> Data {
        guard (1...2).contains(stage), remainingNanoseconds > 0, remainingNanoseconds <= 120_000_000_000 else {
            throw RootGrantsReviewError(status: .privateProtocolError)
        }
        let marker: UInt8 = stage == 1 ? 51 : 52
        var frame = Data([2]) + RootGrantsPrivateFrame.word(12)
        var remaining = remainingNanoseconds.bigEndian
        frame.append(withUnsafeBytes(of: &remaining) { Data($0) })
        frame.append(contentsOf: [75, 86, 82, marker]) // KVR3 / KVR4, in order.
        return frame
    }
    static func response(status: UInt8, length: Int, payload: Data) throws {
        guard payload.count == length else { throw RootGrantsReviewError(status: .privateProtocolError) }
        if status == 0 && length == 0 { return }
        guard status == 1 && length == 4 else { throw RootGrantsReviewError(status: .privateProtocolError) }
        let raw = try RootGrantsPrivateFrame.number(payload)
        guard (1...24).contains(raw) else { throw RootGrantsReviewError(status: .privateProtocolError) }
        throw RootGrantsReviewError(status: RootGrantsStatus.helperClosed(Int32(raw)))
    }
}

// PUBLIC byte binding only: not review, presence, storage or completion authority.
// Original exchanged bytes, including lengths, are hashed without reserialization.
enum RootGrantsPrivateAcknowledgement {
    static func bytes(request: Data, sealed: Data) throws -> Data {
        guard (1...262144).contains(request.count), (1...131072).contains(sealed.count) else {
            throw RootGrantsReviewError(status: .privateProtocolError)
        }
        var frame = Data("keyvault-root-grants-completion/2".utf8)
        frame.append(0)
        frame.append(RootGrantsPrivateFrame.word(UInt32(request.count)))
        frame.append(request)
        frame.append(0)
        frame.append(RootGrantsPrivateFrame.word(UInt32(sealed.count)))
        frame.append(sealed)
        return Data("KVG2".utf8) + Data(SHA256.hash(data: frame))
    }
}

// One frame and one public completion exchange. A refusal/failure consumes the
// state; it never permits a second frame or another private attempt.
struct RootGrantsPrivateCompletion {
    enum Phase: Equatable { case ready, awaitingAcknowledgement, awaitingEOF, complete, failed }
    private(set) var phase = Phase.ready
    private var expected: Data?

    mutating func frame(request: Data?, payload: RootGrantsPrivateFrame.Payload) throws -> Data {
        guard phase == .ready else { try fail() }
        phase = .failed // Consume before frame construction or any possible write.
        let bytes = try RootGrantsPrivateFrame.response(payload)
        switch payload {
        case .sealed(let sealed), .signature(let sealed):
            guard let request else { throw RootGrantsReviewError(status: .privateProtocolError) }
            expected = try RootGrantsPrivateAcknowledgement.bytes(request: request, sealed: sealed)
            phase = .awaitingAcknowledgement
        case .refusal:
            phase = .awaitingEOF
        }
        return bytes
    }
    mutating func acknowledge(_ bytes: Data) throws {
        guard phase == .awaitingAcknowledgement, let expected, bytes == expected else { try fail() }
        self.expected = nil
        phase = .awaitingEOF
    }
    mutating func endOfInput(trailing: Data) throws {
        guard phase == .awaitingEOF, trailing.isEmpty else { try fail() }
        phase = .complete
    }
    private mutating func fail() throws -> Never {
        expected = nil; phase = .failed
        throw RootGrantsReviewError(status: .privateProtocolError)
    }
}

// Fixed entry-to-exit budget, independent of any C handle or later phase.
// Supplied instants are process-local monotonic values, never parent authority.
struct RootGrantsPrivateDeadline {
    static let budget: UInt64 = 900_000_000_000
    static let grantSigningBudget: UInt64 = 120_000_000_000
    let startedAt: UInt64
	let duration: UInt64
	init(startedAt: UInt64, budget: UInt64 = RootGrantsPrivateDeadline.budget) {
        self.startedAt = startedAt
		self.duration = budget
    }
    var expiresAt: UInt64 {
		let (value, overflow) = startedAt.addingReportingOverflow(duration)
        return overflow ? UInt64.max : value
    }
    func check(at now: UInt64) throws {
		guard now >= startedAt, now - startedAt < duration else {
            throw RootGrantsReviewError(status: .timeout)
        }
    }
    func remaining(at now: UInt64) throws -> UInt64 {
        try check(at: now)
        return duration - (now - startedAt)
    }
    static func boundedGrantSigningBudget(remaining: UInt64) throws -> UInt64 {
        guard remaining > 0 else { throw RootGrantsReviewError(status: .timeout) }
        return min(grantSigningBudget, remaining)
    }
}

enum RootGrantsTerminalConfirmationKey {
    // A key other than Return is consumed without confirming. Ctrl-C is an
    // explicit cancellation byte while ISIG is disabled for this one-key read.
    static func consume(_ byte: UInt8) throws -> Bool? {
        if byte == 3 { throw RootGrantsReviewError(status: .canceled) }
        if byte == 10 || byte == 13 { return true }
        return nil
    }

    static func awaitReturn(next: () throws -> UInt8?) throws {
        while true {
            guard let byte = try next() else { throw RootGrantsReviewError(status: .inputCanceled) }
            if try consume(byte) == true { return }
        }
    }
}

enum RootGrantsTerminalReview {
    // A small unit-test utility only. Production confirmation ordering is
    // owned by RootGrantsPrivateFlow below, and its tests exercise that flow.
    static func checkpoint<T>(confirm: () throws -> Void, proceed: () throws -> T) throws -> T {
        try confirm()
        return try proceed()
    }

    static func promptText(_ text: String) -> String {
        text + "\nPress Return to continue; Ctrl-C cancels.\n"
    }

    static func confirm(text: String, cancellation: RootGrantsPrivateCancellation,
                        transport: RootGrantsPrivateTransport) throws {
        guard text.utf8.count <= 1 << 20 else { throw RootGrantsReviewError(status: .limitExceeded) }
        let fd = "/dev/tty".withCString { Darwin.open($0, O_RDWR | O_NOCTTY | O_CLOEXEC | O_NONBLOCK) }
        guard fd >= 0 else { throw RootGrantsReviewError(status: .terminalRequired) }
        defer { _ = Darwin.close(fd) }
        try requireForegroundTTY(fd)
        try confirm(text: text, cancellation: cancellation, descriptor: fd,
                    checkOutput: { try transport.checkOutput() })
    }

    // The production wrapper above opens only /dev/tty and checks its
    // foreground process group. PTY tests pass a disposable descriptor into
    // this same reader/termios implementation; it is never a runtime input
    // source or a way to bypass production descriptor admission.
    static func confirm(text: String, cancellation: RootGrantsPrivateCancellation,
                        descriptor fd: Int32, checkOutput: () throws -> Void,
                        afterArming: () throws -> Void = {}) throws {
        guard text.utf8.count <= 1 << 20 else { throw RootGrantsReviewError(status: .limitExceeded) }
        var info = stat()
        guard fd >= 0, fd < FD_SETSIZE, isatty(fd) == 1, fstat(fd, &info) == 0,
              info.st_mode & mode_t(S_IFMT) == mode_t(S_IFCHR) else {
            throw RootGrantsReviewError(status: .terminalRequired)
        }
        var original = termios()
        guard tcgetattr(fd, &original) == 0 else {
            throw RootGrantsReviewError(status: .terminalRequired)
        }
        func flushPendingInput() -> Bool {
            for _ in 0..<4 {
                if tcflush(fd, TCIFLUSH) == 0 { return true }
                if errno != EINTR { return false }
            }
            return false
        }
        // Discard input sent before the first review began, before raw mode.
        guard flushPendingInput() else {
            throw RootGrantsReviewError(status: .terminalRequired)
        }
        var hidden = original
        hidden.c_lflag &= ~tcflag_t(ICANON | ECHO | ECHONL | IEXTEN | ISIG)
        hidden.c_iflag &= ~tcflag_t(ICRNL | INLCR | IGNCR | IXON | IXOFF | ISTRIP | PARMRK)
        withUnsafeMutableBytes(of: &hidden.c_cc) { controlCharacters in
            controlCharacters[Int(VMIN)] = cc_t(1)
            controlCharacters[Int(VTIME)] = cc_t(0)
        }
        // Conservatively assume a failed raw-mode transition may have changed
        // some flags. Install cleanup before calling tcsetattr so even EINTR
        // or another partial failure attempts to restore the saved state.
        var changed = false
        func restore() -> Bool {
            guard changed else { return true }
            for attempt in 0..<4 {
                var saved = original
                var installed = false
                for _ in 0..<4 {
                    if tcsetattr(fd, TCSANOW, &saved) == 0 { installed = true; break }
                    if errno != EINTR { return false }
                }
                guard installed else { return false }
                var observed = termios()
                var readBack = false
                for _ in 0..<4 {
                    if tcgetattr(fd, &observed) == 0 { readBack = true; break }
                    if errno != EINTR { return false }
                }
                guard readBack else { return false }
                let ccEqual = withUnsafeBytes(of: observed.c_cc, { Array($0) }) ==
                    withUnsafeBytes(of: original.c_cc, { Array($0) })
                if observed.c_iflag == original.c_iflag && observed.c_oflag == original.c_oflag &&
                   observed.c_cflag == original.c_cflag && observed.c_lflag == original.c_lflag &&
                   observed.c_ispeed == original.c_ispeed && observed.c_ospeed == original.c_ospeed && ccEqual {
                    changed = false
                    return true
                }
                if attempt == 3 {
                    return false
                }
                // Applying canonical mode can mark input for reprocessing on
                // Darwin. The queue must be empty before retrying restoration.
                guard flushPendingInput() else { return false }
            }
            return false
        }
        // Every exit after raw mode first removes queued input while echo is
        // still disabled. If flushing fails, keep echo disabled and refuse;
        // restoring it would expose an unread private tail to the next reader.
        defer {
            if changed, flushPendingInput() { _ = restore() }
        }
        changed = true
        guard tcsetattr(fd, TCSANOW, &hidden) == 0 else {
            let flushed = flushPendingInput()
            guard flushed, restore() else {
                throw RootGrantsReviewError(status: .operationUnavailable)
            }
            throw RootGrantsReviewError(status: .terminalRequired)
        }

        func write(_ raw: Data) throws {
            var offset = 0
            while offset < raw.count {
                try cancellation.check()
                try checkOutput()
                try wait(fd, writing: true)
                let count = raw.withUnsafeBytes {
                    Darwin.write(fd, $0.baseAddress!.advanced(by: offset), raw.count - offset)
                }
                if count < 0, errno == EINTR || errno == EAGAIN { continue }
                guard count > 0 else { throw RootGrantsReviewError(status: .terminalRequired) }
                offset += count
            }
        }
        func nextByte() throws -> UInt8? {
            while true {
                try cancellation.reviewDeadline()
                try checkOutput()
                try wait(fd, writing: false)
                var byte: UInt8 = 0
                let count = Darwin.read(fd, &byte, 1)
                if count < 0, errno == EINTR || errno == EAGAIN { continue }
                guard count >= 0 else { throw RootGrantsReviewError(status: .terminalRequired) }
                return count == 0 ? nil : byte
            }
        }
        func wait(_ descriptor: Int32, writing: Bool) throws {
            while true {
                try cancellation.reviewDeadline()
                try checkOutput()
                var readable = fd_set()
                var writable = fd_set()
                withUnsafeMutableBytes(of: &readable) { $0.initializeMemory(as: UInt8.self, repeating: 0) }
                withUnsafeMutableBytes(of: &writable) { $0.initializeMemory(as: UInt8.self, repeating: 0) }
                if writing { __darwin_fd_set(descriptor, &writable) }
                else { __darwin_fd_set(descriptor, &readable) }
                var timeout = timeval(tv_sec: 0, tv_usec: 100_000)
                let ready = writing
                    ? Darwin.select(descriptor + 1, nil, &writable, nil, &timeout)
                    : Darwin.select(descriptor + 1, &readable, nil, nil, &timeout)
                if ready < 0, errno == EINTR { continue }
                guard ready >= 0 else { throw RootGrantsReviewError(status: .terminalRequired) }
                if ready == 0 { continue }
                if writing ? __darwin_fd_isset(descriptor, &writable) != 0 :
                             __darwin_fd_isset(descriptor, &readable) != 0 { return }
            }
        }

        var failure: Error?
        do {
            let prompt = promptText(text)
            try write(Data(prompt.utf8))
            // Input arriving while the complete review is rendered is
            // type-ahead, not consent. Arm only after display output finishes.
            guard flushPendingInput() else { throw RootGrantsReviewError(status: .terminalRequired) }
            try afterArming()
            try RootGrantsTerminalConfirmationKey.awaitReturn(next: nextByte)
        } catch { failure = error }
        let flushed = flushPendingInput()
        guard flushed else { throw RootGrantsReviewError(status: .operationUnavailable) }
        guard restore() else { throw RootGrantsReviewError(status: .operationUnavailable) }
        if let failure { throw failure }
    }

    private static func requireForegroundTTY(_ fd: Int32) throws {
        var info = stat()
        let foreground = tcgetpgrp(fd)
        guard fd < FD_SETSIZE, isatty(fd) == 1, fstat(fd, &info) == 0,
              info.st_mode & mode_t(S_IFMT) == mode_t(S_IFCHR),
              foreground > 0, foreground == getpgrp() else {
            throw RootGrantsReviewError(status: .terminalRequired)
        }
    }
}

// One production operation skeleton owns both confirmation call sites. The
// private helper wires real review/prepare/wrap/seal closures below; tests use
// inert closures to prove either refusal stops before later effects.
enum RootGrantsPrivateFlow {
    static func perform<Attach, Review, Store, Wrap, Result>(
        initialText: String,
        reviewText: (Review) -> String,
        confirm: (String) throws -> Void,
        attach: () throws -> Attach,
        prepare: (Attach) throws -> Review,
        store: (Review) throws -> Store,
        wrap: (Review, Store) throws -> Wrap,
        seal: (Review, Store, Wrap) throws -> Result
    ) throws -> Result {
        try confirm(initialText)
        let attachConfirmation = try attach()
        let review = try prepare(attachConfirmation)
        try confirm(reviewText(review))
        let storeConfirmation = try store(review)
        let qualifiedWrap = try wrap(review, storeConfirmation)
        return try seal(review, storeConfirmation, qualifiedWrap)
    }
}

// Software cancellation state only; no flag is review/presence/wrap authority.
// Never call cancel from an asynchronous signal handler.
final class RootGrantsPrivateCancellation {
    private let lock = NSLock()
    private let deadline: RootGrantsPrivateDeadline
    init(deadline: RootGrantsPrivateDeadline = RootGrantsPrivateDeadline(startedAt: DispatchTime.now().uptimeNanoseconds)) {
        self.deadline = deadline
    }
    func checkDeadline() throws { try deadline.check(at: DispatchTime.now().uptimeNanoseconds) }
    private var failure: RootGrantsStatus?
    private var session: NativeRootGrantsArchiveSession?
    private var context: LAContext?
    private var signingCancellation: (() -> Void)?
    func remainingNanoseconds() throws -> UInt64 {
        try deadline.remaining(at: DispatchTime.now().uptimeNanoseconds)
    }
    func setSigningCancellation(_ value: (() -> Void)?) throws {
        lock.lock()
        let refusal = failure
        let occupied = value != nil && signingCancellation != nil
        if value == nil || refusal == nil && !occupied { signingCancellation = value }
        lock.unlock()
        // Removing a completed helper handle is cleanup, so cancellation must
        // not turn that cleanup into a new failure.
        if value == nil { return }
        if let refusal { value?(); throw RootGrantsReviewError(status: refusal) }
        if occupied { value?(); throw RootGrantsReviewError(status: .operationUnavailable) }
    }
    func check() throws {
        try checkDeadline()
        lock.lock(); let value = failure; lock.unlock()
        if let value { throw RootGrantsReviewError(status: value) }
    }
    func publish(_ value: NativeRootGrantsArchiveSession) throws {
        lock.lock()
        if let failure {
            lock.unlock()
            _ = value.close()
            throw RootGrantsReviewError(status: failure)
        }
        guard session == nil else {
            lock.unlock()
            _ = value.close()
            cancel(.operationUnavailable)
            throw RootGrantsReviewError(status: .operationUnavailable)
        }
        session = value
        lock.unlock()
    }
    func setAuthenticationContext(_ value: LAContext?) throws {
        lock.lock()
        let refusal = failure
        if refusal == nil { context = value }
        lock.unlock()
        if let refusal { value?.invalidate(); throw RootGrantsReviewError(status: refusal) }
    }
    func cancel(_ status: RootGrantsStatus = .canceled) {
        lock.lock()
        if failure == nil { failure = status == .success ? .privateProtocolError : status }
        let active = session, authentication = context, signing = signingCancellation
        lock.unlock()
        authentication?.invalidate()
        signing?()
        _ = active?.close() // No state lock held while Go restores its reader.
    }
    func reviewDeadline() throws {
        try check()
        lock.lock(); let active = session; lock.unlock()
        try active?.checkReviewDeadline()
    }
    @discardableResult
    func finish() -> RootGrantsStatus {
        lock.lock()
        let active = session, authentication = context, signing = signingCancellation
        session = nil; context = nil; signingCancellation = nil
        lock.unlock()
        authentication?.invalidate()
        signing?()
        return active?.close() ?? .success
    }
}

// Catchable process signals are ignored at the process disposition layer and
// observed by DispatchSource before the terminal enters raw mode. Dispatch
// handlers cancel on a queue; no asynchronous signal handler calls Swift code.
final class RootGrantsPrivateSignals {
    static let handledSignals = [SIGINT, SIGHUP, SIGQUIT, SIGTERM, SIGTSTP, SIGTTIN, SIGTTOU]
    private let sources: [DispatchSourceSignal]
    private let restoreHandlers: [() -> Void]
    private let lock = NSLock()
    private var stopped = false

    init(cancellation: RootGrantsPrivateCancellation, queue: DispatchQueue) {
        var sources: [DispatchSourceSignal] = []
        var restoreHandlers: [() -> Void] = []
        for number in Self.handledSignals {
            let previous = Darwin.signal(number, SIG_IGN)
            restoreHandlers.append { _ = Darwin.signal(number, previous) }
            let source = DispatchSource.makeSignalSource(signal: number, queue: queue)
            source.setEventHandler { cancellation.cancel(.canceled) }
            source.resume()
            sources.append(source)
        }
        self.sources = sources
        self.restoreHandlers = restoreHandlers
    }

    func stop() {
        lock.lock()
        guard !stopped else { lock.unlock(); return }
        stopped = true
        lock.unlock()

        let cancelled = DispatchGroup()
        for source in sources {
            cancelled.enter()
            source.setCancelHandler { cancelled.leave() }
            source.cancel()
        }
        cancelled.wait()
        for restore in restoreHandlers.reversed() { restore() }
    }

    deinit { stop() }
}

// Only known noninteractive denials qualify the silent-use negative control.
// A generic CryptoKit/OS failure never stands in for a required-presence result.
enum RootGrantsSilentProbe {
    static func refused(_ error: NSError) -> Bool {
        var current: NSError? = error
        for _ in 0..<4 {
            guard let value = current else { return false }
            if value.domain == NSOSStatusErrorDomain && value.code == Int(errSecInteractionNotAllowed) { return true }
            if value.domain == LAError.errorDomain && value.code == LAError.Code.notInteractive.rawValue { return true }
            current = value.userInfo[NSUnderlyingErrorKey] as? NSError
        }
        return false
    }
}

// Opaque native origin: the sole constructor executes real hardware operations.
// No public struct, caller approval bit, injected provider or raw private key
// can construct this value. Blob/point are PUBLIC/SEALED, never key plaintext.
private final class RootGrantsQualifiedWrap {
    private let key: SecureEnclave.P256.KeyAgreement.PrivateKey
    let point: Data
    let blob: Data
    private init(_ key: SecureEnclave.P256.KeyAgreement.PrivateKey, point: Data, blob: Data) {
        self.key = key; self.point = point; self.blob = blob
    }
    static func create(review: RootGrantsDerivedReview, store: RootGrantsPublicConfirmation,
                       session: NativeRootGrantsArchiveSession,
                       cancellation: RootGrantsPrivateCancellation,
                       transport: RootGrantsPrivateTransport) throws -> RootGrantsQualifiedWrap {
        try cancellation.check()
        try transport.checkOutput()
        try session.recheckBeforeWrap(store, currentRequest: review.initial.request.originalBytes,
                                      currentPreparation: review.preparation.originalBytes)
        guard SecureEnclave.isAvailable else { throw RootGrantsReviewError(status: .wrappingPolicyRefused) }
        let context = LAContext()
        context.localizedFallbackTitle = ""
        context.touchIDAuthenticationAllowableReuseDuration = 0
        let reason = "Attach root grants \(review.initial.request.rootAddress). Request SHA256 \(review.initial.request.requestHash). Review SHA256 \(review.snapshotHash). Root K \(review.preparation.publicKey)."
        context.localizedReason = reason
        defer { context.invalidate(); try? cancellation.setAuthenticationContext(nil) }
        do { try NativeNamecoinBiometryPolicy.requireTouchID(on: context) }
        catch { throw RootGrantsReviewError(status: .wrappingPolicyRefused) }
        try cancellation.setAuthenticationContext(context)
        try cancellation.check()
        let flags: SecAccessControlCreateFlags = [.biometryAny, .privateKeyUsage]
        var accessError: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                           flags, &accessError) else {
            _ = accessError?.takeRetainedValue()
            throw RootGrantsReviewError(status: .wrappingPolicyRefused)
        }
        // Create once after the exact STORE; never persist a helper key item.
        let key: SecureEnclave.P256.KeyAgreement.PrivateKey
        // Creation cannot silently authenticate/warm the later review context.
        let creation = LAContext()
        creation.interactionNotAllowed = true
        creation.localizedFallbackTitle = ""
        creation.touchIDAuthenticationAllowableReuseDuration = 0
        defer { creation.invalidate() }
        do { key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: control, authenticationContext: creation) }
        catch { throw RootGrantsReviewError(status: .wrappingPolicyRefused) }
        let point = key.publicKey.x963Representation, blob = key.dataRepresentation
        guard point.count == 65, (1...16384).contains(blob.count),
              !review.initial.request.retainedWrappingPoints.contains(point) else {
            throw RootGrantsReviewError(status: .wrappingPolicyRefused)
        }
        // Published disposable scalar1 ONLY. No owner scalar is read/serialized.
        var scalar = Data(repeating: 0, count: 32); scalar[31] = 1
        defer { scalar.resetBytes(in: 0..<scalar.count) }
        let fixture = try P256.KeyAgreement.PrivateKey(rawRepresentation: scalar)
        let silent = LAContext()
        silent.interactionNotAllowed = true
        silent.localizedFallbackTitle = ""
        silent.touchIDAuthenticationAllowableReuseDuration = 0
        defer { silent.invalidate() }
        do {
            let probe = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob, authenticationContext: silent)
            guard probe.publicKey.x963Representation == point else { throw RootGrantsReviewError(status: .wrappingPolicyRefused) }
            _ = try probe.sharedSecretFromKeyAgreement(with: fixture.publicKey)
            throw RootGrantsReviewError(status: .wrappingPolicyRefused)
        } catch let refusal as RootGrantsReviewError { throw refusal }
        catch {
            guard RootGrantsSilentProbe.refused(error as NSError) else {
                throw RootGrantsReviewError(status: .wrappingPolicyRefused)
            }
        }
        try cancellation.check()
        try session.recheckBeforeWrap(store, currentRequest: review.initial.request.originalBytes,
                                      currentPreparation: review.preparation.originalBytes)
        // Evaluate on the SAME fresh capability-qualified context. Polling the
        // real C session checks its original deadline; it never creates a cap
        // or renews900s. Cancellation invalidates this context on a safe queue.
        let done = DispatchSemaphore(value: 0), answerLock = NSLock()
        var accepted = false
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, _ in
            answerLock.lock(); accepted = success; answerLock.unlock(); done.signal()
        }
        while done.wait(timeout: .now() + .milliseconds(100)) != .success {
            try cancellation.check()
            try transport.checkOutput()
            try session.recheckBeforeWrap(store, currentRequest: review.initial.request.originalBytes,
                                          currentPreparation: review.preparation.originalBytes)
        }
        answerLock.lock(); let authenticated = accepted; answerLock.unlock()
        try cancellation.check()
        try transport.checkOutput()
        guard authenticated else { throw RootGrantsReviewError(status: .wrappingPolicyRefused) }
        try session.recheckBeforeWrap(store, currentRequest: review.initial.request.originalBytes,
                                      currentPreparation: review.preparation.originalBytes)
        do {
            let loaded = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob, authenticationContext: context)
            guard loaded.publicKey.x963Representation == point else { throw RootGrantsReviewError(status: .wrappingPolicyRefused) }
            let actual = try loaded.sharedSecretFromKeyAgreement(with: fixture.publicKey)
            let expected = try fixture.sharedSecretFromKeyAgreement(with: loaded.publicKey)
            let info = Data("root-grants-wrap-public-qualification/1".utf8)
            let a = actual.x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: info, outputByteCount: 32)
            let b = expected.x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: info, outputByteCount: 32)
            guard a == b else { throw RootGrantsReviewError(status: .wrappingPolicyRefused) }
        } catch let refusal as RootGrantsReviewError { throw refusal }
        catch { throw RootGrantsReviewError(status: .wrappingPolicyRefused) }
        try cancellation.check()
        return RootGrantsQualifiedWrap(key, point: point, blob: blob)
    }
}

// This route owns exactly one process-local C lifecycle and writes one public
// response at most. Never append a refusal after a partial/lost output frame.
func rootGrantsPrivate() -> Int32 {
    let deadline = RootGrantsPrivateDeadline(startedAt: DispatchTime.now().uptimeNanoseconds)
    let cancellation = RootGrantsPrivateCancellation(deadline: deadline)
    let queue = DispatchQueue(label: "keyvault.root-attachment-cancellation")
    signal(SIGPIPE, SIG_IGN)
    let signals = RootGrantsPrivateSignals(cancellation: cancellation, queue: queue)
    defer { signals.stop() } // All relevant signals precede any tty mutation.
    let timeout = DispatchSource.makeTimerSource(queue: queue)
    timeout.schedule(deadline: DispatchTime(uptimeNanoseconds: deadline.expiresAt))
    timeout.setEventHandler { cancellation.cancel(.timeout) }
    timeout.resume() // The original deadline also closes a blocked real Prepare.
    defer { timeout.cancel() }
    let parent = getppid()
    guard parent > 1 else { return 1 }
    let parentExit = DispatchSource.makeProcessSource(identifier: parent, eventMask: .exit, queue: queue)
    parentExit.setEventHandler { cancellation.cancel(.privateProtocolError) }
    parentExit.resume()
    defer { parentExit.cancel(); _ = cancellation.finish() }
    guard getppid() == parent else { return 1 }
    let transport: RootGrantsPrivateTransport
    do { transport = try RootGrantsPrivateTransport(cancellation) }
    catch { return 1 } // No fallback to an unadmitted stdout descriptor.
    var payload: RootGrantsPrivateFrame.Payload
    var exchangedRequest: Data?
    do {
        let bytes = try transport.request()
        exchangedRequest = bytes
        payload = try autoreleasepool { () throws -> RootGrantsPrivateFrame.Payload in
            try cancellation.check()
            let session = try NativeRootGrantsArchiveSession(publicRequest: bytes)
            try cancellation.publish(session) // A racing signal closes before Prepare.
            let initial = session.initialReview
            let result = try RootGrantsPrivateFlow.perform(
                initialText: initial.text,
                reviewText: { $0.text },
                confirm: { text in
                    try RootGrantsTerminalReview.confirm(text: text, cancellation: cancellation, transport: transport)
                },
                attach: {
                    try initial.confirm(currentRequest: initial.request.originalBytes)
                },
                prepare: { attach in
                    try cancellation.check()
                    return try session.prepare(after: attach, currentRequest: initial.request.originalBytes)
                },
                store: { review in
                    let store = try review.confirm(currentRequest: initial.request.originalBytes,
                                                   currentPreparation: review.preparation.originalBytes)
                    try cancellation.check()
                    return store
                },
                wrap: { review, store in
                    try cancellation.check()
                    return try RootGrantsQualifiedWrap.create(review: review, store: store, session: session,
                        cancellation: cancellation, transport: transport)
                },
                seal: { review, store, wrap in
                    try cancellation.check()
                    try transport.checkOutput()
                    let sealed = try session.sealAfterReviewedStore(store, currentRequest: initial.request.originalBytes,
                        currentPreparation: review.preparation.originalBytes, publicPoint: wrap.point, sealedDeviceBlob: wrap.blob)
                    try cancellation.check()
                    return sealed
                }
            )
            return .sealed(result.originalBytes)
        }
    } catch {
        payload = .refusal((error as? RootGrantsReviewError)?.status ?? .privateProtocolError)
    }
    let cleanup = cancellation.finish()
    if cleanup != .success { payload = .refusal(cleanup) }
    // Private attempt locals have left scope; finish closed the actual C session
    // and invalidated native context before the first public response byte.
    do {
        try transport.write(payload, request: exchangedRequest)
        try transport.complete()
        return 0 // Both success and well-formed refusal require EOF/exit0.
    } catch { return 1 } // No second frame, private retry or completion fallback.
}

struct RootGrantsPrivatePipeIdentity: Equatable {
    let handle: UInt64
    let device: dev_t
    let inode: ino_t
}
enum RootGrantsPrivatePipes {
    static func identity(_ fd: Int32, writing: Bool) throws -> RootGrantsPrivatePipeIdentity {
        var info = stat(), pipe = pipe_fdinfo()
        let size = MemoryLayout<pipe_fdinfo>.size
        let flags = fcntl(fd, F_GETFL)
        guard fd >= 0, fstat(fd, &info) == 0, info.st_mode & mode_t(S_IFMT) == mode_t(S_IFIFO),
              flags >= 0, flags & O_ACCMODE == (writing ? O_WRONLY : O_RDONLY),
              flags & (O_NONBLOCK | O_ASYNC) == 0,
              proc_pidfdinfo(getpid(), fd, PROC_PIDFDPIPEINFO, &pipe, Int32(size)) == Int32(size) else {
            throw RootGrantsReviewError(status: .invalidArguments)
        }
        // A named (even unlinked) FIFO is a vnode descriptor, not this kernel
        // PIPEINFO type. No pathname, parent claim or fstat-only alias suffices.
        return RootGrantsPrivatePipeIdentity(handle: pipe.pipeinfo.pipe_handle, device: info.st_dev, inode: info.st_ino)
    }
}
final class RootGrantsPrivateTransport {
    let input: RootGrantsPrivatePipeIdentity
    let output: RootGrantsPrivatePipeIdentity
    let cancellation: RootGrantsPrivateCancellation
    private var completion = RootGrantsPrivateCompletion()
    private var outputClosed = false
    init(_ cancellation: RootGrantsPrivateCancellation) throws {
        self.cancellation = cancellation
        input = try RootGrantsPrivatePipes.identity(STDIN_FILENO, writing: false)
        output = try RootGrantsPrivatePipes.identity(STDOUT_FILENO, writing: true)
        guard input.handle != output.handle else { throw RootGrantsReviewError(status: .invalidArguments) }
    }
    private func ready(_ fd: Int32, writing: Bool) throws {
        try cancellation.check()
        let frozen = writing ? output : input
        guard try RootGrantsPrivatePipes.identity(fd, writing: writing) == frozen else {
            throw RootGrantsReviewError(status: .privateProtocolError)
        }
        while true {
            try cancellation.check()
            var p = pollfd(fd: fd, events: Int16(writing ? POLLOUT : POLLIN), revents: 0)
            let result = poll(&p, 1, 100)
            if result < 0, errno == EINTR { continue }
            guard result >= 0 else { throw RootGrantsReviewError(status: .privateProtocolError) }
            if result == 0 { continue }
            guard p.revents & Int16(POLLNVAL | POLLERR) == 0 else {
                throw RootGrantsReviewError(status: .privateProtocolError)
            }
            return
        }
    }
    private func readBytes(_ count: Int) throws -> Data {
        var result = Data()
        while result.count < count {
            try ready(STDIN_FILENO, writing: false)
            var bytes = [UInt8](repeating: 0, count: min(4096, count - result.count))
            let capacity = bytes.count
            let readCount = bytes.withUnsafeMutableBytes { Darwin.read(STDIN_FILENO, $0.baseAddress, capacity) }
            if readCount < 0, errno == EINTR { continue }
            guard readCount > 0 else { throw RootGrantsReviewError(status: .invalidArguments) }
            result.append(contentsOf: bytes.prefix(readCount))
        }
        return result
    }
    func request() throws -> Data {
        let prefix = try readBytes(4), count = try RootGrantsPrivateFrame.number(prefix)
        guard (1...262144).contains(count) else { throw RootGrantsReviewError(status: .invalidArguments) }
        // stdin intentionally remains open for the one completion message.
        return try readBytes(count)
    }
    func recheck(stage: UInt8, remainingNanoseconds: UInt64) throws {
        let frame = try RootGrantsPrivateControl.recheck(stage: stage,
            remainingNanoseconds: remainingNanoseconds)
        try writeControl(frame)
        let header = try readBytes(5)
        let status = header[0]
        let length = try RootGrantsPrivateFrame.number(Data(header.dropFirst()))
        guard (0...4).contains(length) else { throw RootGrantsReviewError(status: .privateProtocolError) }
        let payload = try readBytes(length)
        try RootGrantsPrivateControl.response(status: status, length: length, payload: payload)
    }
    private func writeControl(_ frame: Data) throws {
        var offset = 0
        while offset < frame.count {
            try ready(STDOUT_FILENO, writing: true)
            let count = frame.count - offset
            let written = frame.withUnsafeBytes { Darwin.write(STDOUT_FILENO, $0.baseAddress!.advanced(by: offset), count) }
            if written < 0, errno == EINTR { continue }
            guard written > 0 else { throw RootGrantsReviewError(status: .privateProtocolError) }
            offset += written
        }
    }
    func checkOutput() throws {
        try cancellation.check()
        guard try RootGrantsPrivatePipes.identity(STDOUT_FILENO, writing: true) == output else {
            throw RootGrantsReviewError(status: .privateProtocolError)
        }
        var p = pollfd(fd: STDOUT_FILENO, events: Int16(POLLOUT), revents: 0)
        guard poll(&p, 1, 0) == 1, p.revents & Int16(POLLERR | POLLHUP | POLLNVAL) == 0,
              p.revents & Int16(POLLOUT) != 0 else {
            throw RootGrantsReviewError(status: .privateProtocolError)
        }
    }
    func write(_ payload: RootGrantsPrivateFrame.Payload, request: Data?) throws {
        let frame = try completion.frame(request: request, payload: payload)
        var offset = 0
        while offset < frame.count {
            try cancellation.checkDeadline()
            switch payload {
            case .sealed, .signature:
                try ready(STDOUT_FILENO, writing: true)
            case .refusal:
                // Cleanup is complete. A canceled session may emit its single
                // fixed nine-byte refusal, but never wait indefinitely for it.
                guard try RootGrantsPrivatePipes.identity(STDOUT_FILENO, writing: true) == output else {
                    throw RootGrantsReviewError(status: .privateProtocolError)
                }
                var p = pollfd(fd: STDOUT_FILENO, events: Int16(POLLOUT), revents: 0)
                guard poll(&p, 1, 100) == 1, p.revents & Int16(POLLERR | POLLHUP | POLLNVAL) == 0,
                      p.revents & Int16(POLLOUT) != 0 else {
                    throw RootGrantsReviewError(status: .privateProtocolError)
                }
            }
            // <=PIPE_BUF after POLLOUT: do not issue a larger blocking write.
            let count = min(Int(PIPE_BUF), frame.count - offset)
            let n = frame.withUnsafeBytes { Darwin.write(STDOUT_FILENO, $0.baseAddress!.advanced(by: offset), count) }
            if n < 0, errno == EINTR { continue }
            guard n > 0 else { throw RootGrantsReviewError(status: .privateProtocolError) }
            offset += n
        }
    }
    func complete() throws {
        // C is already closed. Only the original outer clock/cancellation state
        // governs this bounded public wait; no query of a closed C handle.
        if completion.phase == .awaitingAcknowledgement {
            let ack: Data
            do { ack = try readBytes(36) }
            catch let refusal as RootGrantsReviewError where refusal.status == .timeout || refusal.status == .canceled {
                throw refusal
            } catch { throw RootGrantsReviewError(status: .privateProtocolError) }
            try completion.acknowledge(ack)
        }
        var extra: UInt8 = 0
        while true {
            try ready(STDIN_FILENO, writing: false)
            let count = Darwin.read(STDIN_FILENO, &extra, 1)
            if count < 0, errno == EINTR { continue }
            guard count >= 0 else { throw RootGrantsReviewError(status: .privateProtocolError) }
            try completion.endOfInput(trailing: count == 0 ? Data() : Data([extra]))
            break
        }
        try cancellation.check()
        guard try RootGrantsPrivatePipes.identity(STDOUT_FILENO, writing: true) == output,
              !outputClosed else { throw RootGrantsReviewError(status: .privateProtocolError) }
        outputClosed = true // Never retry an uncertain close or replace stdout.
        guard Darwin.close(STDOUT_FILENO) == 0 else { throw RootGrantsReviewError(status: .privateProtocolError) }
        try cancellation.check()
    }
}

// Reject oversized/control text before committing an edit; preserve AppKit's
// field-editor delegate and ordinary text-field value synchronization.
private final class RootGrantsConfirmationFormatter: Formatter {
    private func admitted(_ value: String) -> Bool {
        value.utf8.count <= 128 && value.utf8.allSatisfy { (32...126).contains($0) }
    }
    override func string(for obj: Any?) -> String? { obj as? String }
    override func getObjectValue(_ obj: AutoreleasingUnsafeMutablePointer<AnyObject?>?, for string: String,
                                 errorDescription error: AutoreleasingUnsafeMutablePointer<NSString?>?) -> Bool {
        guard admitted(string) else { return false }
        obj?.pointee = string as NSString
        return true
    }
    override func isPartialStringValid(_ partialString: String,
        newEditingString newString: AutoreleasingUnsafeMutablePointer<NSString?>?,
        errorDescription error: AutoreleasingUnsafeMutablePointer<NSString?>?) -> Bool { admitted(partialString) }
}

final class RootGrantsNativeReview: NSObject, NSWindowDelegate, NSTextFieldDelegate {
    let text: String
    let cancellation: RootGrantsPrivateCancellation
    let transport: RootGrantsPrivateTransport
    let window: NSWindow
    let scroll: NSScrollView
    let view: NSTextView
    let fields: [NSTextField]
    let confirm: NSButton
    var observer: NSObjectProtocol?
    var bottomSeen = false
    var refusal: RootGrantsStatus?

    init(text: String, labels: [String], cancellation: RootGrantsPrivateCancellation,
         transport: RootGrantsPrivateTransport, title: String = "Root grants: complete attachment review") throws {
        guard Thread.isMainThread, text.utf8.count <= 1 << 20, [1, 4].contains(labels.count),
              let screen = NSScreen.main, screen.visibleFrame.width >= 850, screen.visibleFrame.height >= 700 else {
            throw RootGrantsReviewError(status: .operationUnavailable)
        }
        self.text = text; self.cancellation = cancellation; self.transport = transport
        let width = min(CGFloat(1000), screen.visibleFrame.width - 80)
        let height = min(CGFloat(900), screen.visibleFrame.height - 80)
        let footer = CGFloat(labels.count * 44 + 70)
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: width, height: height),
                          styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = title
        window.isReleasedWhenClosed = false
        scroll = NSScrollView(frame: NSRect(x: 20, y: footer, width: width - 40, height: height - footer - 30))
        scroll.hasVerticalScroller = true; scroll.hasHorizontalScroller = false
        let font = NSFont.monospacedSystemFont(ofSize: 13, weight: .regular)
        let units = Array(text.replacingOccurrences(of: "\n", with: "").utf16)
        var glyphs = [CGGlyph](repeating: 0, count: units.count)
        let ct = CTFontCreateWithName(font.fontName as CFString, font.pointSize, nil)
        guard CTFontGetGlyphsForCharacters(ct, units, &glyphs, units.count), !glyphs.contains(0) else {
            throw RootGrantsReviewError(status: .operationUnavailable)
        }
        let paragraph = NSMutableParagraphStyle()
        paragraph.lineBreakMode = .byCharWrapping; paragraph.baseWritingDirection = .leftToRight
        let storage = NSTextStorage(string: text, attributes: [.font: font, .paragraphStyle: paragraph, .ligature: 0, .kern: 0])
        let layout = NSLayoutManager()
        let container = NSTextContainer(containerSize: NSSize(width: scroll.contentSize.width - 24, height: 10000000))
        container.lineFragmentPadding = 0; container.widthTracksTextView = false
        container.heightTracksTextView = false; container.maximumNumberOfLines = 0
        layout.addTextContainer(container); storage.addLayoutManager(layout); layout.ensureLayout(for: container)
        view = NSTextView(frame: NSRect(x: 0, y: 0, width: scroll.contentSize.width,
                          height: max(scroll.contentSize.height, ceil(layout.usedRect(for: container).maxY) + 48)), textContainer: container)
        view.textContainerInset = NSSize(width: 12, height: 12)
        view.isEditable = false; view.isSelectable = true; view.isRichText = false
        view.usesFontPanel = false; view.menu = nil
        view.isHorizontallyResizable = false; view.isVerticallyResizable = false
        fields = labels.map { _ in NSTextField(string: "") }
        confirm = NSButton(title: "Confirm exact text", target: nil, action: nil)
        super.init()
        guard complete(), let content = window.contentView else { throw RootGrantsReviewError(status: .operationUnavailable) }
        scroll.documentView = view; content.addSubview(scroll)
        for (i, label) in labels.enumerated() {
            let y = footer - CGFloat((i + 1) * 44)
            let caption = NSTextField(labelWithString: label)
            caption.frame = NSRect(x: 20, y: y + 22, width: width - 40, height: 20)
            fields[i].frame = NSRect(x: 20, y: y, width: width - 40, height: 24)
            fields[i].formatter = RootGrantsConfirmationFormatter()
            fields[i].delegate = self
            content.addSubview(caption); content.addSubview(fields[i])
        }
        confirm.frame = NSRect(x: width - 250, y: 15, width: 230, height: 36)
        confirm.target = self; confirm.action = #selector(accept); confirm.isEnabled = false
        content.addSubview(confirm)
        let cancel = NSButton(title: "Cancel", target: self, action: #selector(cancelReview))
        cancel.frame = NSRect(x: 20, y: 15, width: 120, height: 36); cancel.keyEquivalent = "\u{1b}"
        content.addSubview(cancel)
        window.delegate = self; window.center()
        scroll.contentView.postsBoundsChangedNotifications = true
        observer = NotificationCenter.default.addObserver(forName: NSView.boundsDidChangeNotification, object: scroll.contentView,
                   queue: .main) { [weak self] _ in self?.update() }
        view.scroll(NSPoint.zero)
    }
    deinit { if let observer { NotificationCenter.default.removeObserver(observer) } }
    func complete() -> Bool {
        guard view.string == text, let layout = view.layoutManager, let container = view.textContainer else { return false }
        layout.ensureLayout(for: container)
        let glyphs = layout.glyphRange(for: container)
        let chars = layout.characterRange(forGlyphRange: glyphs, actualGlyphRange: nil)
        let bounds = layout.boundingRect(forGlyphRange: glyphs, in: container)
        return glyphs.location == 0 && glyphs.length == layout.numberOfGlyphs &&
            chars.location == 0 && chars.length == (text as NSString).length && bounds.minX >= 0 &&
            bounds.maxX <= container.containerSize.width && container.containerSize.width <= scroll.contentSize.width - 24 && layout.usedRect(for: container).maxY + 24 <= view.bounds.height
    }
    func update() {
        if scroll.contentView.bounds.maxY >= view.bounds.maxY - 1 { bottomSeen = true }
        let onScreen = window.screen.map { $0.visibleFrame.contains(window.frame) } ?? false
        confirm.isEnabled = bottomSeen && onScreen && complete() &&
            fields.allSatisfy { !$0.stringValue.isEmpty && $0.stringValue.utf8.count <= 128 &&
                $0.stringValue.utf8.allSatisfy { (32...126).contains($0) } }
    }
    func controlTextDidChange(_ notification: Notification) { update() }
    @objc func accept() { update(); if confirm.isEnabled, window.isVisible { NSApplication.shared.stopModal(withCode: .OK) } }
    @objc func cancelReview() { NSApplication.shared.stopModal(withCode: .cancel) }
    func windowShouldClose(_ sender: NSWindow) -> Bool { cancelReview(); return false }
    func run() throws -> [String] {
        let app = NSApplication.shared
        app.setActivationPolicy(.regular); app.finishLaunching()
        window.makeKeyAndOrderFront(nil); app.activate(ignoringOtherApps: true); window.displayIfNeeded(); update()
        let timer = Timer(timeInterval: 0.1, repeats: true) { [weak self] _ in
            guard let self else { return }
            do { try self.cancellation.reviewDeadline(); try self.transport.checkOutput(); self.update() }
            catch { self.refusal = (error as? RootGrantsReviewError)?.status ?? .privateProtocolError; self.cancelReview() }
        }
        RunLoop.main.add(timer, forMode: .modalPanel)
        defer { timer.invalidate(); window.orderOut(nil) }
        try cancellation.reviewDeadline()
        try transport.checkOutput()
        let result = app.runModal(for: window)
        if let refusal { throw RootGrantsReviewError(status: refusal) }
        try cancellation.check()
        guard result == .OK, bottomSeen, complete() else { throw RootGrantsReviewError(status: .canceled) }
        return fields.map(\.stringValue)
    }
}
