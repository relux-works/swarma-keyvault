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
    enum Payload { case sealed(Data), refusal(RootGrantsStatus) }
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
            guard (1...20).contains(raw), let status = RootGrantsStatus(rawValue: Int32(raw)) else {
                throw RootGrantsReviewError(status: .privateProtocolError)
            }
            return .refusal(status)
        default: throw RootGrantsReviewError(status: .privateProtocolError)
        }
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
        case .sealed(let sealed):
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
    let startedAt: UInt64
    var expiresAt: UInt64 {
        let (value, overflow) = startedAt.addingReportingOverflow(Self.budget)
        return overflow ? UInt64.max : value
    }
    func check(at now: UInt64) throws {
        guard now >= startedAt, now - startedAt < Self.budget else {
            throw RootGrantsReviewError(status: .timeout)
        }
    }
}

enum RootGrantsPrivateConfirmation {
    static func attach(_ review: RootGrantsInitialReview, lines: [String]?) throws -> RootGrantsPublicConfirmation {
        guard let lines else { throw RootGrantsReviewError(status: .inputCanceled) }
        guard lines.count == 4, lines.allSatisfy({ $0.utf8.count <= 128 }) else {
            throw RootGrantsReviewError(status: .canceled)
        }
        return try review.confirmRetypes(Array(lines.prefix(3)), attach: lines[3],
                                         currentRequest: review.request.originalBytes)
    }
    static func store(_ review: RootGrantsDerivedReview, line: String?) throws -> RootGrantsPublicConfirmation {
        guard let line else { throw RootGrantsReviewError(status: .inputCanceled) }
        guard line.utf8.count <= 128 else { throw RootGrantsReviewError(status: .canceled) }
        return try review.confirmStore(line, currentRequest: review.initial.request.originalBytes,
                                       currentPreparation: review.preparation.originalBytes)
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
    fileprivate func setAuthenticationContext(_ value: LAContext?) throws {
        lock.lock()
        let refusal = failure
        if refusal == nil { context = value }
        lock.unlock()
        if let refusal { value?.invalidate(); throw RootGrantsReviewError(status: refusal) }
    }
    func cancel(_ status: RootGrantsStatus = .canceled) {
        lock.lock()
        if failure == nil { failure = status == .success ? .privateProtocolError : status }
        let active = session, authentication = context
        lock.unlock()
        authentication?.invalidate()
        _ = active?.close() // No state lock held while Go restores its reader.
    }
    fileprivate func reviewDeadline() throws {
        try check()
        lock.lock(); let active = session; lock.unlock()
        try active?.checkReviewDeadline()
    }
    @discardableResult
    func finish() -> RootGrantsStatus {
        lock.lock()
        let active = session, authentication = context
        session = nil; context = nil
        lock.unlock()
        authentication?.invalidate()
        return active?.close() ?? .success
    }
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
    signal(SIGTERM, SIG_IGN)
    signal(SIGPIPE, SIG_IGN)
    let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: queue)
    termination.setEventHandler { cancellation.cancel() }
    termination.resume() // Registered before Open/private work/publication.
    let timeout = DispatchSource.makeTimerSource(queue: queue)
    timeout.schedule(deadline: DispatchTime(uptimeNanoseconds: deadline.expiresAt))
    timeout.setEventHandler { cancellation.cancel(.timeout) }
    timeout.resume() // The original deadline also closes a blocked real Prepare.
    defer { timeout.cancel() }
    let parent = getppid()
    guard parent > 1 else { termination.cancel(); return 1 }
    let parentExit = DispatchSource.makeProcessSource(identifier: parent, eventMask: .exit, queue: queue)
    parentExit.setEventHandler { cancellation.cancel(.privateProtocolError) }
    parentExit.resume()
    defer { termination.cancel(); parentExit.cancel(); _ = cancellation.finish() }
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
            let entries = try RootGrantsNativeReview(text: initial.text,
                labels: ["Retype the full existing Nostr identity", "Retype the full existing Namecoin identity",
                         "Retype the full new root grants identity", "Type ATTACH ROOT GRANTS"], cancellation: cancellation, transport: transport).run()
            let attach = try RootGrantsPrivateConfirmation.attach(initial, lines: entries)
            try cancellation.check()
            let review = try session.prepare(after: attach, currentRequest: initial.request.originalBytes)
            let final = try RootGrantsNativeReview(text: review.text, labels: ["Type STORE ROOT GRANTS"],
                                                   cancellation: cancellation, transport: transport).run()
            let store = try RootGrantsPrivateConfirmation.store(review, line: final.first)
            try cancellation.check()
            let wrap = try RootGrantsQualifiedWrap.create(review: review, store: store, session: session, cancellation: cancellation, transport: transport)
            try cancellation.check()
            try transport.checkOutput()
            let result = try session.sealAfterReviewedStore(store, currentRequest: initial.request.originalBytes,
                currentPreparation: review.preparation.originalBytes, publicPoint: wrap.point, sealedDeviceBlob: wrap.blob)
            try cancellation.check()
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
private final class RootGrantsPrivateTransport {
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
            case .sealed:
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

private final class RootGrantsNativeReview: NSObject, NSWindowDelegate, NSTextFieldDelegate {
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
         transport: RootGrantsPrivateTransport) throws {
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
        window.title = "Root grants: complete attachment review"
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
