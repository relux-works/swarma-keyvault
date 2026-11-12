import Foundation
import Darwin
import CryptoKit

// This is an internal I/O phase, with no production dispatcher or archive binding.
// The trusted Go caller must first strictly validate and construct the complete
// PUBLIC result and independently provide its SHA256. Data is not an authority:
// this primitive cannot prevent a programming error from passing secret bytes.
// No private inputs or private buffers belong in this API.
enum NativeNamecoinOutputRefusal: String, Error, Equatable {
    case unavailable = "output_unavailable"
    case unknown = "outcome_unknown"
}

// A bounded, fail-only seam for source tests. Every admission check and every
// successful I/O operation still uses the real descriptor. No case certifies
// native authority, fabricates bytes/readback, or turns a failed operation green.
enum NativeNamecoinOutputTestFault: Equatable {
    case none
    case partialWriteFailure
    case synchronizeFailure
    case readbackFailure
    case closeReplyLost
}

// Single-owner, synchronous, non-Sendable adapter. Its trusted lifecycle caller
// must serialize calls and retain the actual Go gate through cleanup. There is
// no lock, exclusion substitute, child process, or listener inside this adapter.
final class NativeNamecoinPrivateOutput {
    static let maximumResultBytes = 8 * 1024 * 1024
    private static let chunkBytes = 64 * 1024

    private struct Identity {
        let device: dev_t
        let inode: ino_t
        let owner: uid_t
        let mode: mode_t
        let links: nlink_t

        init(_ value: stat) {
            device = value.st_dev
            inode = value.st_ino
            owner = value.st_uid
            mode = value.st_mode
            links = value.st_nlink
        }

        func matches(_ value: stat) -> Bool {
            device == value.st_dev && inode == value.st_ino &&
                owner == value.st_uid && mode == value.st_mode && links == value.st_nlink
        }

        // Cleanup may close our still-owned inode after its permissions or link
        // count changed. A reused descriptor for another inode is never closed.
        func sameObject(_ value: stat) -> Bool {
            device == value.st_dev && inode == value.st_ino
        }
    }

    private let callerDescriptor: Int32
    private let identity: Identity
    private let statusFlags: Int32
    private let fault: NativeNamecoinOutputTestFault
    private var ownedDescriptor: Int32?
    private var consumed = false
    private var writeWasPossible = false

    convenience init(selectedDescriptor: Int32) throws {
        try self.init(selectedDescriptor: selectedDescriptor, testFault: .none)
    }

    // Process-local selection only. This is not a path/descriptor parser, an
    // authorization boolean, a public RPC, or an engine result certification.
    init(selectedDescriptor: Int32, testFault: NativeNamecoinOutputTestFault) throws {
        guard selectedDescriptor >= 3 else { throw NativeNamecoinOutputRefusal.unavailable }
        let initial = try Self.readStatus(selectedDescriptor)
        guard initial.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              initial.st_uid == getuid(),
              initial.st_mode & mode_t(0o7777) == mode_t(0o600),
              initial.st_nlink == 1, initial.st_size == 0,
              lseek(selectedDescriptor, 0, SEEK_CUR) == 0 else {
            throw NativeNamecoinOutputRefusal.unavailable
        }
        let flags = fcntl(selectedDescriptor, F_GETFL)
        // The parent's exact creation contract is O_RDWR|O_CREAT|O_EXCL|
        // O_NOFOLLOW, mode 0600. Creation-only bits may disappear from F_GETFL.
        // Only these forms (plus an already-set CLOEXEC bit) are admitted.
        let allowed = O_ACCMODE | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC
        guard flags >= 0, flags & O_ACCMODE == O_RDWR,
              flags & ~allowed == 0 else {
            throw NativeNamecoinOutputRefusal.unavailable
        }
        let descriptorFlags = fcntl(selectedDescriptor, F_GETFD)
        guard descriptorFlags >= 0, descriptorFlags & ~FD_CLOEXEC == 0,
              fcntl(selectedDescriptor, F_SETFD, descriptorFlags | FD_CLOEXEC) == 0,
              fcntl(selectedDescriptor, F_GETFD) == FD_CLOEXEC else {
            throw NativeNamecoinOutputRefusal.unavailable
        }
        let frozen = Identity(initial)
        let duplicate = fcntl(selectedDescriptor, F_DUPFD_CLOEXEC, Int32(3))
        guard duplicate >= 3 else { throw NativeNamecoinOutputRefusal.unavailable }
        do {
            try Self.check(selectedDescriptor, identity: frozen, flags: flags, size: 0, offset: 0)
            try Self.check(duplicate, identity: frozen, flags: flags, size: 0, offset: 0)
        } catch {
            // No close retry, including EINTR. Never close the caller's handle.
            var current = stat()
            if fstat(duplicate, &current) == 0 && frozen.sameObject(current) {
                _ = Darwin.close(duplicate)
            }
            throw NativeNamecoinOutputRefusal.unavailable
        }
        callerDescriptor = selectedDescriptor
        identity = frozen
        statusFlags = flags
        fault = testFault
        ownedDescriptor = duplicate
    }

    deinit { try? close() }

    private static func readStatus(_ descriptor: Int32) throws -> stat {
        var value = stat()
        guard fstat(descriptor, &value) == 0 else { throw NativeNamecoinOutputRefusal.unavailable }
        return value
    }

    private static func check(_ descriptor: Int32, identity: Identity, flags: Int32,
                              size: Int, offset: Int) throws {
        let value = try readStatus(descriptor)
        guard identity.matches(value), value.st_size == off_t(size),
              fcntl(descriptor, F_GETFL) == flags,
              fcntl(descriptor, F_GETFD) == FD_CLOEXEC,
              lseek(descriptor, 0, SEEK_CUR) == off_t(offset) else {
            throw NativeNamecoinOutputRefusal.unavailable
        }
    }

    private func checkBoth(size: Int, offset: Int) throws -> Int32 {
        guard let descriptor = ownedDescriptor else { throw NativeNamecoinOutputRefusal.unavailable }
        try Self.check(callerDescriptor, identity: identity, flags: statusFlags, size: size, offset: offset)
        try Self.check(descriptor, identity: identity, flags: statusFlags, size: size, offset: offset)
        return descriptor
    }

    private func refusalForPhase() -> NativeNamecoinOutputRefusal {
        writeWasPossible ? .unknown : .unavailable
    }

    // Removes ownership before the single close attempt. A failed close is never
    // retried, since a reused numeric descriptor could now belong to other code.
    private func closeOwned() throws {
        guard let descriptor = ownedDescriptor else { return }
        ownedDescriptor = nil
        var current = stat()
        guard fstat(descriptor, &current) == 0, identity.sameObject(current) else {
            throw refusalForPhase()
        }
        let result = Darwin.close(descriptor)
        guard result == 0, fault != .closeReplyLost else { throw refusalForPhase() }
    }

    func close() throws {
        consumed = true
        try closeOwned()
    }

    // Success means only exact, synchronized public-byte I/O and checked cleanup.
    // It does NOT establish a public receipt, SIGNED, a protected anchor, final
    // completion, or acknowledgement. The real lifecycle must retain its fixed Go
    // gate through all output cleanup and the remaining protected completion.
    func writePublicResult(_ publicResult: Data, expectedSHA256: Data) throws {
        guard !consumed, ownedDescriptor != nil else { throw NativeNamecoinOutputRefusal.unavailable }
        consumed = true
        do {
            guard !publicResult.isEmpty, publicResult.count <= Self.maximumResultBytes,
                  expectedSHA256.count == 32 else {
                throw NativeNamecoinOutputRefusal.unavailable
            }
            // Freeze caller storage before hashing/writing. No mutable re-read.
            let bytes = publicResult.withUnsafeBytes { Data(bytes: $0.baseAddress!, count: $0.count) }
            let expected = expectedSHA256.withUnsafeBytes { Data(bytes: $0.baseAddress!, count: $0.count) }
            guard Data(SHA256.hash(data: bytes)) == expected else {
                throw NativeNamecoinOutputRefusal.unavailable
            }
            _ = try checkBoth(size: 0, offset: 0)
            var written = 0
            while written < bytes.count {
                let descriptor = try checkBoth(size: written, offset: written)
                var count = min(Self.chunkBytes, bytes.count - written)
                if fault == .partialWriteFailure { count = min(count, 17) }
                // Even a negative write result may leave effects uncertain.
                writeWasPossible = true
                let amount = bytes.withUnsafeBytes {
                    Darwin.write(descriptor, $0.baseAddress!.advanced(by: written), count)
                }
                guard amount > 0, amount <= count else { throw NativeNamecoinOutputRefusal.unknown }
                written += amount
                _ = try checkBoth(size: written, offset: written)
                if fault == .partialWriteFailure { throw NativeNamecoinOutputRefusal.unknown }
                // Positive short writes advance normally; a failed syscall is
                // never retried. Nothing truncates, repairs, or overwrites data.
            }
            let descriptor = try checkBoth(size: bytes.count, offset: bytes.count)
            if fault == .synchronizeFailure { throw NativeNamecoinOutputRefusal.unknown }
            guard fsync(descriptor) == 0 else { throw NativeNamecoinOutputRefusal.unknown }
            _ = try checkBoth(size: bytes.count, offset: bytes.count)
            if fault == .readbackFailure { throw NativeNamecoinOutputRefusal.unknown }
            var hasher = SHA256()
            var position = 0
            var buffer = [UInt8](repeating: 0, count: Self.chunkBytes)
            while position < bytes.count {
                let readDescriptor = try checkBoth(size: bytes.count, offset: bytes.count)
                let requested = min(buffer.count, bytes.count - position)
                let amount = buffer.withUnsafeMutableBytes {
                    pread(readDescriptor, $0.baseAddress!, requested, off_t(position))
                }
                guard amount == requested else { throw NativeNamecoinOutputRefusal.unknown }
                _ = try checkBoth(size: bytes.count, offset: bytes.count)
                let part = Data(buffer.prefix(amount))
                guard part == bytes.subdata(in: position..<(position + amount)) else {
                    throw NativeNamecoinOutputRefusal.unknown
                }
                hasher.update(data: part)
                position += amount
            }
            guard Data(hasher.finalize()) == expected else { throw NativeNamecoinOutputRefusal.unknown }
            let eofDescriptor = try checkBoth(size: bytes.count, offset: bytes.count)
            var extra: UInt8 = 0
            guard pread(eofDescriptor, &extra, 1, off_t(bytes.count)) == 0 else {
                throw NativeNamecoinOutputRefusal.unknown
            }
            _ = try checkBoth(size: bytes.count, offset: bytes.count)
            try closeOwned()
            try Self.check(callerDescriptor, identity: identity, flags: statusFlags,
                           size: bytes.count, offset: bytes.count)
        } catch {
            let refusal = refusalForPhase()
            try? closeOwned()
            throw refusal
        }
    }
}

// Descriptor checks do not prove the parent's O_EXCL/O_NOFOLLOW creation or the
// current pathname: this child has no pathname and cannot detect every directory
// entry replacement. Other aliases can race between checks; this is not a lock or
// an atomic filesystem transaction. The lifecycle owns parent-path validation,
// process discipline, and the actual Go gate. No fallback or listener is supplied.
