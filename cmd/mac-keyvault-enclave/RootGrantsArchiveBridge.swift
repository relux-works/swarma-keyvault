import Darwin
import Foundation
import NamecoinArchiveABI

// Same-process PUBLIC/SEALED plumbing only. This does not implement owner UI,
// terminal input, wrap creation/qualification, presence, parent IPC or storage.
// The internal sealing caller must perform actual native wrap qualification.
// Public confirmations and public point/blob bytes do not certify that runtime.
enum RootGrantsArchiveBindings {
    static let responseLimit = 131072
    static let handleBit: UInt64 = 1 << 63

    static func rootHandle(_ handle: UInt64) -> Bool {
        handle & handleBit != 0 && handle & ~handleBit != 0
    }
    static func status(_ raw: Int32) throws {
        if let refusal = RootGrantsReviewError.fromStatus(raw) { throw refusal }
    }
    static func opened(status raw: Int32, handle: UInt64) throws {
        guard raw == 0 || handle == 0 else { throw RootGrantsReviewError(status: .privateProtocolError) }
        try status(raw)
        guard rootHandle(handle) else { throw RootGrantsReviewError(status: .privateProtocolError) }
    }
    static func length(_ count: size_t) throws -> Int {
        guard count > 0, count <= size_t(responseLimit) else {
            throw RootGrantsReviewError(status: .privateProtocolError)
        }
        return Int(count)
    }
    // These checks compare public values, never attest an actual presentation.
    static func initial(_ confirmation: RootGrantsPublicConfirmation,
                        review: RootGrantsInitialReview, currentRequest: Data) throws {
        guard currentRequest == review.request.originalBytes else {
            throw RootGrantsReviewError(status: .bindingMismatch)
        }
        guard confirmation.stage == .attachReviewed,
              confirmation.requestHash == review.request.requestHash,
              confirmation.snapshotHash == review.snapshotHash else {
            throw RootGrantsReviewError(status: .operationUnavailable)
        }
    }
    static func store(_ confirmation: RootGrantsPublicConfirmation,
                      review: RootGrantsDerivedReview, currentRequest: Data, currentPreparation: Data) throws {
        guard currentRequest == review.initial.request.originalBytes,
              currentPreparation == review.preparation.originalBytes else {
            throw RootGrantsReviewError(status: .bindingMismatch)
        }
        guard confirmation.stage == .storeReviewed,
              confirmation.requestHash == review.initial.request.requestHash,
              confirmation.snapshotHash == review.snapshotHash else {
            throw RootGrantsReviewError(status: .operationUnavailable)
        }
    }
    static func sealedInputs(_ sealed: RootGrantsSealedPublicView, point: Data, blob: Data) throws {
        do {
            let record = try NativeArchiveJSON.decode(sealed.recordBytes, maximum: responseLimit, canonical: true)
            let envelope = try NativeArchiveJSON.decode(sealed.envelopeBytes, maximum: responseLimit, canonical: true)
            guard try record.field("wrapping_point").base64(maximum: 65) == point,
                  try envelope.field("point").base64(maximum: 65) == point,
                  try envelope.field("enclave_blob").base64(maximum: 16384) == blob else {
                throw RootGrantsReviewError(status: .bindingMismatch)
            }
        } catch let refusal as RootGrantsReviewError { throw refusal }
        catch { throw RootGrantsReviewError(status: .privateProtocolError) }
    }
}

final class NativeRootGrantsArchiveSession {
    let initialReview: RootGrantsInitialReview
    private enum Phase: Equatable { case opened, preparing, reviewReady, sealing, closed }
    private let condition = NSCondition()
    private var handle: UInt64 = 0
    private var phase = Phase.closed
    private var derivedReview: RootGrantsDerivedReview?
    private var closing = false
    private var closeStatus = RootGrantsStatus.success

    init(publicRequest: Data) throws {
        let request = try RootGrantsPublicRequest(ownedBytes: publicRequest)
        initialReview = try RootGrantsInitialReview(request: request)
        // Actual cgo input is mutable at the imported source boundary. Go owns
        // copies and never writes/retains this borrowed PUBLIC array.
        var raw = Array(request.originalBytes)
        let count = raw.count
        var opened: UInt64 = 0
        let code = raw.withUnsafeMutableBufferPointer {
            kv_rg_open_v1($0.baseAddress, size_t(count), &opened)
        }
        do {
            try RootGrantsArchiveBindings.opened(status: code, handle: opened)
            guard Data(raw) == request.originalBytes else {
                throw RootGrantsReviewError(status: .privateProtocolError)
            }
        } catch {
            // Never reinterpret a low-bit/Namecoin value as a Root handle.
            if RootGrantsArchiveBindings.rootHandle(opened) {
                let cleanup = RootGrantsStatus.closed(kv_rg_close_v1(opened))
                if cleanup != .success { throw RootGrantsReviewError(status: cleanup) }
            }
            throw error
        }
        handle = opened
        phase = .opened
    }

    deinit { _ = close() }

    // Call on an ordinary thread/DispatchSource cancellation path, NEVER inside
    // an asynchronous signal handler. No Swift lock is held across Go Close:
    // Go cancels first, allowing its blocked reader to restore terminal state.
    // The original C-open900s deadline is never renewed by this object.
    @discardableResult
    func close() -> RootGrantsStatus {
        close(expected: nil)
    }

    private func close(expected: UInt64?) -> RootGrantsStatus {
        condition.lock()
        while closing { condition.wait() }
        if let expected, (handle != expected || phase != .sealing) {
            let result: RootGrantsStatus = closeStatus == .success ? .canceled : closeStatus
            condition.unlock()
            return result
        }
        guard handle != 0 else {
            let result = closeStatus
            condition.unlock()
            return result
        }
        let owned = handle
        handle = 0
        phase = .closed
        derivedReview = nil
        closing = true
        condition.unlock()
        let result = RootGrantsStatus.closed(kv_rg_close_v1(owned))
        condition.lock()
        closeStatus = result
        closing = false
        condition.broadcast()
        condition.unlock()
        return result
    }

    private func refused(_ error: Error) -> RootGrantsReviewError {
        let primary = (error as? RootGrantsReviewError)?.status ?? .privateProtocolError
        let cleanup = close()
        return RootGrantsReviewError(status: cleanup == .success ? primary : cleanup)
    }

    private func begin(_ expected: Phase, _ next: Phase) throws -> UInt64 {
        condition.lock()
        defer { condition.unlock() }
        guard handle != 0, phase == expected else {
            throw RootGrantsReviewError(status: .operationUnavailable)
        }
        phase = next
        return handle
    }
    private func live(_ owned: UInt64, _ expected: Phase) throws {
        condition.lock()
        defer { condition.unlock() }
        guard handle == owned, phase == expected else {
            throw RootGrantsReviewError(status: .canceled)
        }
    }
    private func publish(_ review: RootGrantsDerivedReview, owned: UInt64) throws {
        condition.lock()
        defer { condition.unlock() }
        guard handle == owned, phase == .preparing else {
            throw RootGrantsReviewError(status: .canceled)
        }
        derivedReview = review
        phase = .reviewReady
    }

    private func copy(_ owned: UInt64, sealed: Bool) throws -> Data {
        var needed: size_t = 0
        let query = sealed ? kv_rg_copy_sealed_v1(owned, nil, 0, &needed)
                           : kv_rg_copy_public_v1(owned, nil, 0, &needed)
        try RootGrantsArchiveBindings.status(query)
        let count = try RootGrantsArchiveBindings.length(needed)
        var bytes = [UInt8](repeating: 0, count: count)
        var written: size_t = 0
        let result = bytes.withUnsafeMutableBufferPointer {
            sealed ? kv_rg_copy_sealed_v1(owned, $0.baseAddress, size_t(count), &written)
                   : kv_rg_copy_public_v1(owned, $0.baseAddress, size_t(count), &written)
        }
        // A short-capacity refusal is final; never resize/retry or accept a
        // partial buffer. Real prepared copy-size controls require a later lane.
        try RootGrantsArchiveBindings.status(result)
        guard written == needed else { throw RootGrantsReviewError(status: .privateProtocolError) }
        return Data(bytes)
    }

    // This invokes the REAL engine-owned tty reader. Automated public plumbing
    // tests must never call it with a valid initial confirmation.
    func prepare(after confirmation: RootGrantsPublicConfirmation, currentRequest: Data) throws -> RootGrantsDerivedReview {
        do {
            try RootGrantsArchiveBindings.initial(confirmation, review: initialReview, currentRequest: currentRequest)
            let owned = try begin(.opened, .preparing)
            try RootGrantsArchiveBindings.status(kv_rg_prepare_v1(owned))
            try live(owned, .preparing)
            let bytes = try copy(owned, sealed: false)
            let preparation = try RootGrantsPreparationPublicView(ownedBytes: bytes, request: initialReview.request)
            let review = try RootGrantsDerivedReview(initial: initialReview, attach: confirmation, preparation: preparation)
            try publish(review, owned: owned)
            return review
        } catch { throw refused(error) }
    }

    // Pure C status query during native review: Go checks its ORIGINAL deadline
    // before checking phase. New-phase10/zero length is the specified empty
    // pre-Prepare response, not permission to prepare or a renewed budget.
    func checkReviewDeadline() throws {
        do {
            condition.lock()
            let owned = handle, expected = phase
            condition.unlock()
            guard owned != 0, expected == .opened || expected == .reviewReady else {
                throw RootGrantsReviewError(status: .operationUnavailable)
            }
            var count: size_t = 0
            let status = kv_rg_copy_public_v1(owned, nil, 0, &count)
            if expected == .opened {
                guard status == 10, count == 0 else {
                    try RootGrantsArchiveBindings.status(status)
                    throw RootGrantsReviewError(status: .privateProtocolError)
                }
            } else {
                try RootGrantsArchiveBindings.status(status)
                _ = try RootGrantsArchiveBindings.length(count)
            }
            try live(owned, expected)
        } catch { throw refused(error) }
    }

    // Recheck the actual live C preparation before any native wrap work.
    // Public confirmations establish byte binding only, never hardware policy,
    // native display or presence. This does not renew the C deadline.
    func recheckBeforeWrap(_ confirmation: RootGrantsPublicConfirmation,
                           currentRequest: Data, currentPreparation: Data) throws {
        do {
            condition.lock()
            let review = derivedReview
            condition.unlock()
            guard let review else { throw RootGrantsReviewError(status: .operationUnavailable) }
            try RootGrantsArchiveBindings.store(confirmation, review: review, currentRequest: currentRequest,
                                               currentPreparation: currentPreparation)
            condition.lock()
            let owned = handle
            let ready = phase == .reviewReady
            condition.unlock()
            guard owned != 0, ready else { throw RootGrantsReviewError(status: .operationUnavailable) }
            // A real pure copy checks the original Go deadline without renewing
            // it. Never create a wrap from a stale public snapshot alone.
            guard try copy(owned, sealed: false) == currentPreparation else {
                throw RootGrantsReviewError(status: .bindingMismatch)
            }
            try live(owned, .reviewReady)
        } catch { throw refused(error) }
    }

    // INTERNAL caller must originate the distinct wrap from actual native
    // qualification after the full unchanged review and fresh TouchID. Public
    // point/blob/confirmation values alone do not establish that provenance.
    func sealAfterReviewedStore(_ confirmation: RootGrantsPublicConfirmation,
                                currentRequest: Data, currentPreparation: Data,
                                publicPoint: Data, sealedDeviceBlob: Data) throws -> RootGrantsSealedPublicView {
        do {
            condition.lock()
            let review = derivedReview
            condition.unlock()
            guard let review else { throw RootGrantsReviewError(status: .operationUnavailable) }
            try RootGrantsArchiveBindings.store(confirmation, review: review, currentRequest: currentRequest,
                                               currentPreparation: currentPreparation)
            guard publicPoint.count == 65, (1...16384).contains(sealedDeviceBlob.count) else {
                throw RootGrantsReviewError(status: .invalidArguments)
            }
            let point = publicPoint.withUnsafeBytes { Data($0) }
            let blob = sealedDeviceBlob.withUnsafeBytes { Data($0) }
            guard !initialReview.request.retainedWrappingPoints.contains(point) else {
                throw RootGrantsReviewError(status: .wrappingPolicyRefused)
            }
            var pointInput = Array(point), blobInput = Array(blob)
            let pointCount = pointInput.count, blobCount = blobInput.count
            let owned = try begin(.reviewReady, .sealing)
            let code = pointInput.withUnsafeMutableBufferPointer { p in
                blobInput.withUnsafeMutableBufferPointer { b in
                    kv_rg_seal_v1(owned, p.baseAddress, size_t(pointCount), b.baseAddress, size_t(blobCount))
                }
            }
            try RootGrantsArchiveBindings.status(code)
            guard Data(pointInput) == point, Data(blobInput) == blob else {
                throw RootGrantsReviewError(status: .privateProtocolError)
            }
            try live(owned, .sealing)
            let result = try RootGrantsSealedPublicView(ownedBytes: copy(owned, sealed: true),
                                                       request: initialReview.request, preparation: review.preparation)
            try RootGrantsArchiveBindings.sealedInputs(result, point: point, blob: blob)
            try live(owned, .sealing)
            let cleanup = close(expected: owned)
            guard cleanup == .success else { throw RootGrantsReviewError(status: cleanup) }
            // This is not a presence/store receipt. A later caller must retain
            // effect-aware UNKNOWN handling after wrap/add/output uncertainty.
            return result
        } catch { throw refused(error) }
    }
}
