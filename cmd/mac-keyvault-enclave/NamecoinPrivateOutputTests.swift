import Foundation
import Darwin
import CryptoKit
import Testing
@testable import KeyvaultNativeCore

// SOURCE ONLY / NOT_RUN. These tests exercise disposable PUBLIC fixture files,
// actual Darwin descriptors, and the bounded fail-only I/O seam. They do not
// invoke owner UI, Keychain, private operations, the Go engine, or native consent.
// A successful I/O phase is not a receipt, SIGNED, anchor, or completion proof.
private enum OutputFixtureError: Error { case setup }

private func expectOutputRefusal(_ expected: NativeNamecoinOutputRefusal,
                                 _ body: () throws -> Void) {
    do {
        try body()
        Issue.record("Expected fixed output refusal")
    } catch let refusal as NativeNamecoinOutputRefusal {
        #expect(refusal == expected)
    } catch {
        Issue.record("Unexpected error type; raw diagnostics intentionally omitted")
    }
}

private func outputDigest(_ bytes: Data) -> Data { Data(SHA256.hash(data: bytes)) }

private func requireFixtureStandardDescriptors() throws {
    // Refuse setup if an open could occupy a standard descriptor. The test
    // process must keep these handles stable; there is no global repair/locking.
    guard [Int32(0), 1, 2].allSatisfy({ fcntl($0, F_GETFD) >= 0 }) else {
        throw OutputFixtureError.setup
    }
}

// This fixture owns only its fresh directory and recorded descriptors. It never
// uses dup2, changes standard descriptors, or closes a descriptor owned by peers.
private final class PublicOutputFixture {
    let root: URL
    let path: String
    private(set) var descriptor: Int32?
    private var additionalDescriptors: [Int32] = []

    init() throws {
        try requireFixtureStandardDescriptors()
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("namecoin-public-output-" + UUID().uuidString, isDirectory: true)
        root = directory
        path = directory.appendingPathComponent("result").path
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                    attributes: [.posixPermissions: 0o700])
        } catch { throw OutputFixtureError.setup }
        let opened = Darwin.open(path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, mode_t(0o600))
        guard opened >= 3 else {
            try? FileManager.default.removeItem(at: root)
            throw OutputFixtureError.setup
        }
        descriptor = opened
        // Test-only fixture normalization, never adapter repair or real state.
        guard fchmod(opened, mode_t(0o600)) == 0 else {
            descriptor = nil
            _ = Darwin.close(opened)
            try? FileManager.default.removeItem(at: root)
            throw OutputFixtureError.setup
        }
    }

    deinit {
        if let descriptor { _ = Darwin.close(descriptor) }
        for descriptor in additionalDescriptors { _ = Darwin.close(descriptor) }
        try? FileManager.default.removeItem(at: root)
    }

    func fd() throws -> Int32 {
        guard let descriptor else { throw OutputFixtureError.setup }
        return descriptor
    }

    func openAgain(flags: Int32) throws -> Int32 {
        try requireFixtureStandardDescriptors()
        let opened = Darwin.open(path, flags | O_NOFOLLOW)
        guard opened >= 3 else {
            throw OutputFixtureError.setup
        }
        additionalDescriptors.append(opened)
        return opened
    }

    func openDirectory() throws -> Int32 {
        try requireFixtureStandardDescriptors()
        let opened = Darwin.open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard opened >= 3 else {
            throw OutputFixtureError.setup
        }
        additionalDescriptors.append(opened)
        return opened
    }

    func closeOriginal() throws -> Int32 {
        let original = try fd()
        descriptor = nil
        guard Darwin.close(original) == 0 else { throw OutputFixtureError.setup }
        return original
    }

    func bytes() throws -> Data {
        let descriptor = try fd()
        var status = stat()
        guard fstat(descriptor, &status) == 0, status.st_size >= 0,
              status.st_size <= off_t(NativeNamecoinPrivateOutput.maximumResultBytes + 1) else {
            throw OutputFixtureError.setup
        }
        let count = Int(status.st_size)
        if count == 0 { return Data() }
        var bytes = [UInt8](repeating: 0, count: count)
        let actual = bytes.withUnsafeMutableBytes { pread(descriptor, $0.baseAddress!, count, 0) }
        guard actual == count else { throw OutputFixtureError.setup }
        return Data(bytes)
    }

    func put(_ bytes: Data, at offset: off_t = 0) throws {
        let descriptor = try fd()
        let count = bytes.withUnsafeBytes { pwrite(descriptor, $0.baseAddress!, $0.count, offset) }
        guard count == bytes.count else { throw OutputFixtureError.setup }
    }
}

@Suite(.serialized)
struct NamecoinPrivateOutputTests {
    // Claim: exact bytes (including LF), size/hash, shared offset, caller lifetime,
    // and both CLOEXEC checks use real files. Repeat calls refuse without effect.
    // NOT_RUN; no engine/public-result authority or native/private proof.
    @Test func completeBytesAndOneShot() throws {
        let fixture = try PublicOutputFixture()
        let original = try fixture.fd()
        #expect(fcntl(original, F_GETFD) & FD_CLOEXEC == 0)
        let output = try NativeNamecoinPrivateOutput(selectedDescriptor: original)
        #expect(fcntl(original, F_GETFD) == FD_CLOEXEC)
        let bytes = Data("{\"public_fixture\":\"complete\"}\n".utf8)
        try output.writePublicResult(bytes, expectedSHA256: outputDigest(bytes))
        let actual = try fixture.bytes()
        #expect(actual == bytes)
        #expect(actual.last == 0x0a)
        #expect(actual.count == bytes.count)
        #expect(outputDigest(actual) == outputDigest(bytes))
        #expect(fcntl(original, F_GETFD) == FD_CLOEXEC)
        #expect(lseek(original, 0, SEEK_CUR) == off_t(bytes.count))
        expectOutputRefusal(.unavailable) {
            try output.writePublicResult(Data([0x42]), expectedSHA256: outputDigest(Data([0x42])))
        }
        #expect(try fixture.bytes() == bytes)
        try output.close()
        try output.close()
        #expect(fcntl(original, F_GETFD) == FD_CLOEXEC)
    }

    // Claim: both legitimate initial CLOEXEC forms are accepted, and admission
    // sets the caller flag without closing it. Closing before use writes nothing.
    // NOT_RUN; this does not observe an exec or qualify child-spawn discipline.
    @Test func alreadyCloseOnExecAndExplicitCleanup() throws {
        let fixture = try PublicOutputFixture()
        let original = try fixture.fd()
        #expect(fcntl(original, F_SETFD, FD_CLOEXEC) == 0)
        let output = try NativeNamecoinPrivateOutput(selectedDescriptor: original)
        try output.close()
        try output.close()
        let bytes = Data([0x41])
        expectOutputRefusal(.unavailable) {
            try output.writePublicResult(bytes, expectedSHA256: outputDigest(bytes))
        }
        #expect(try fixture.bytes().isEmpty)
        #expect(fcntl(original, F_GETFD) == FD_CLOEXEC)
    }

    // Claim: the exact 8 MiB limit is usable; empty and max+1 refuse pre-write
    // with unchanged empty fixtures. These are constructor/I/O bounds, not a
    // valid engine result or PSBT proof. NOT_RUN; no native/private operations.
    @Test func resultBounds() throws {
        let allowed = try PublicOutputFixture()
        let bytes = Data(repeating: 0x50, count: NativeNamecoinPrivateOutput.maximumResultBytes)
        let output = try NativeNamecoinPrivateOutput(selectedDescriptor: allowed.fd())
        try output.writePublicResult(bytes, expectedSHA256: outputDigest(bytes))
        #expect(try allowed.bytes() == bytes)
        for rejected in [Data(), Data(repeating: 0x50, count: bytes.count + 1)] {
            let fixture = try PublicOutputFixture()
            let refused = try NativeNamecoinPrivateOutput(selectedDescriptor: fixture.fd())
            expectOutputRefusal(.unavailable) {
                try refused.writePublicResult(rejected, expectedSHA256: outputDigest(rejected))
            }
            #expect(try fixture.bytes().isEmpty)
        }
    }

    // Claim: mismatched or malformed independent hashes refuse BEFORE any write;
    // even a corrected second call stays consumed. NOT_RUN; supplying a matching
    // hash does not certify that bytes were validated by the future Go engine.
    @Test func hashMismatchConsumesWithoutWrite() throws {
        let bytes = Data("public fixture\n".utf8)
        for hash in [Data(repeating: 0, count: 32), Data(repeating: 0, count: 31)] {
            let fixture = try PublicOutputFixture()
            let output = try NativeNamecoinPrivateOutput(selectedDescriptor: fixture.fd())
            expectOutputRefusal(.unavailable) { try output.writePublicResult(bytes, expectedSHA256: hash) }
            #expect(try fixture.bytes().isEmpty)
            expectOutputRefusal(.unavailable) {
                try output.writePublicResult(bytes, expectedSHA256: outputDigest(bytes))
            }
            #expect(try fixture.bytes().isEmpty)
        }
    }

    // Claim: negative, standard, and actually closed descriptors give the exact
    // unavailable code. No standard stream content is read and none is changed
    // or closed. NOT_RUN; setup requires stable, already-open standard handles.
    @Test func invalidAndStandardDescriptors() throws {
        for descriptor in [Int32(-1), 0, 1, 2] {
            expectOutputRefusal(.unavailable) {
                _ = try NativeNamecoinPrivateOutput(selectedDescriptor: descriptor)
            }
        }
        let fixture = try PublicOutputFixture()
        let closed = try fixture.closeOriginal()
        expectOutputRefusal(.unavailable) {
            _ = try NativeNamecoinPrivateOutput(selectedDescriptor: closed)
        }
    }

    // Claim: actual readonly/append/nonblocking/async file forms refuse admission
    // and leave the fixture empty. A fixture-open failure is a setup failure,
    // never a successful negative control. NOT_RUN; real kernel flags required.
    @Test func forbiddenAccessFlags() throws {
        for flags in [O_RDONLY, O_RDWR | O_APPEND, O_RDWR | O_NONBLOCK, O_RDWR | O_ASYNC] {
            let fixture = try PublicOutputFixture()
            let other = try fixture.openAgain(flags: flags)
            guard fcntl(other, F_GETFL) & (O_ACCMODE | O_APPEND | O_NONBLOCK | O_ASYNC) == flags else {
                throw OutputFixtureError.setup
            }
            expectOutputRefusal(.unavailable) {
                _ = try NativeNamecoinPrivateOutput(selectedDescriptor: other)
            }
            #expect(try fixture.bytes().isEmpty)
            #expect(fcntl(other, F_GETFD) >= 0)
        }
    }

    // Claim: real pipe and directory descriptors cannot become output files;
    // cleanup touches only fixture-owned handles. NOT_RUN; not a native proof.
    @Test func nonregularDescriptors() throws {
        try requireFixtureStandardDescriptors()
        var pipeDescriptors: [Int32] = [-1, -1]
        guard pipe(&pipeDescriptors) == 0 else { throw OutputFixtureError.setup }
        guard pipeDescriptors.allSatisfy({ $0 >= 3 }) else {
            for descriptor in pipeDescriptors where descriptor >= 3 { _ = Darwin.close(descriptor) }
            throw OutputFixtureError.setup
        }
        defer { for descriptor in pipeDescriptors { _ = Darwin.close(descriptor) } }
        for descriptor in pipeDescriptors {
            expectOutputRefusal(.unavailable) {
                _ = try NativeNamecoinPrivateOutput(selectedDescriptor: descriptor)
            }
        }
        let fixture = try PublicOutputFixture()
        let directory = try fixture.openDirectory()
        expectOutputRefusal(.unavailable) {
            _ = try NativeNamecoinPrivateOutput(selectedDescriptor: directory)
        }
        #expect(try fixture.bytes().isEmpty)
    }

    // Claim: exact 0600 and one link are required; only disposable fixture state
    // is chmod/linked. Rejections leave fixture bytes untouched. NOT_RUN; no
    // real Keychain/path/owner state or authorization is exercised.
    @Test func permissionsAndHardlink() throws {
        for mode in [mode_t(0o400), 0o640, 0o700, 0o1600] {
            let fixture = try PublicOutputFixture()
            #expect(fchmod(try fixture.fd(), mode) == 0)
            expectOutputRefusal(.unavailable) {
                _ = try NativeNamecoinPrivateOutput(selectedDescriptor: fixture.fd())
            }
            #expect(try fixture.bytes().isEmpty)
        }
        let fixture = try PublicOutputFixture()
        let alias = fixture.root.appendingPathComponent("second-link").path
        guard link(fixture.path, alias) == 0 else { throw OutputFixtureError.setup }
        expectOutputRefusal(.unavailable) {
            _ = try NativeNamecoinPrivateOutput(selectedDescriptor: fixture.fd())
        }
        #expect(try fixture.bytes().isEmpty)
    }

    // Claim: initial bytes and initial nonzero offset are independent refusals;
    // existing content/offset is not truncated, reset, or repaired. NOT_RUN.
    @Test func preexistingBytesAndOffset() throws {
        let preexisting = try PublicOutputFixture()
        let marker = Data([0x50])
        try preexisting.put(marker)
        #expect(lseek(try preexisting.fd(), 0, SEEK_CUR) == 0)
        expectOutputRefusal(.unavailable) {
            _ = try NativeNamecoinPrivateOutput(selectedDescriptor: preexisting.fd())
        }
        #expect(try preexisting.bytes() == marker)
        let shifted = try PublicOutputFixture()
        #expect(lseek(try shifted.fd(), 1, SEEK_SET) == 1)
        expectOutputRefusal(.unavailable) {
            _ = try NativeNamecoinPrivateOutput(selectedDescriptor: shifted.fd())
        }
        #expect(lseek(try shifted.fd(), 0, SEEK_CUR) == 1)
        #expect(try shifted.bytes().isEmpty)
    }

    // Claim: growth or shared status-flag changes after admission refuse BEFORE
    // write, preserving the external bytes. NOT_RUN; observations between checks
    // cannot eliminate races by arbitrary aliases or prove a pathname binding.
    @Test func laterExternalGrowthAndFlagChange() throws {
        let bytes = Data("public fixture\n".utf8)
        let grown = try PublicOutputFixture()
        let output = try NativeNamecoinPrivateOutput(selectedDescriptor: grown.fd())
        let marker = Data([0x50, 0x51])
        try grown.put(marker)
        expectOutputRefusal(.unavailable) {
            try output.writePublicResult(bytes, expectedSHA256: outputDigest(bytes))
        }
        #expect(try grown.bytes() == marker)
        let changed = try PublicOutputFixture()
        let changedFD = try changed.fd()
        let other = try NativeNamecoinPrivateOutput(selectedDescriptor: changedFD)
        guard fcntl(changedFD, F_SETFL, O_RDWR | O_APPEND) == 0,
              fcntl(changedFD, F_GETFL) & O_APPEND != 0 else { throw OutputFixtureError.setup }
        expectOutputRefusal(.unavailable) {
            try other.writePublicResult(bytes, expectedSHA256: outputDigest(bytes))
        }
        #expect(try changed.bytes().isEmpty)
        #expect(fcntl(changedFD, F_GETFL) & O_APPEND != 0)
    }

    // Claim: post-admission permission/link/offset/CLOEXEC changes refuse before
    // write. Fixture changes remain as made; the adapter does not repair them.
    // NOT_RUN; wrong-UID admission is a source guard, not privileged test evidence.
    @Test func laterMetadataOffsetAndDescriptorFlags() throws {
        let bytes = Data("public fixture\n".utf8)
        for change in 0..<4 {
            let fixture = try PublicOutputFixture()
            let original = try fixture.fd()
            let output = try NativeNamecoinPrivateOutput(selectedDescriptor: original)
            switch change {
            case 0:
                guard fchmod(original, mode_t(0o640)) == 0 else { throw OutputFixtureError.setup }
            case 1:
                let alias = fixture.root.appendingPathComponent("later-link").path
                guard link(fixture.path, alias) == 0 else { throw OutputFixtureError.setup }
            case 2:
                guard lseek(original, 1, SEEK_SET) == 1 else { throw OutputFixtureError.setup }
            default:
                guard fcntl(original, F_SETFD, Int32(0)) == 0 else { throw OutputFixtureError.setup }
            }
            expectOutputRefusal(.unavailable) {
                try output.writePublicResult(bytes, expectedSHA256: outputDigest(bytes))
            }
            #expect(try fixture.bytes().isEmpty)
            var status = stat()
            guard fstat(original, &status) == 0 else { throw OutputFixtureError.setup }
            switch change {
            case 0: #expect(status.st_mode & mode_t(0o7777) == mode_t(0o640))
            case 1: #expect(status.st_nlink == 2)
            case 2: #expect(lseek(original, 0, SEEK_CUR) == 1)
            default: #expect(fcntl(original, F_GETFD) == 0)
            }
        }
    }

    // Claim: real numeric-FD reuse for another inode refuses; cleanup retains the
    // replacement caller handle and does not write either object. No dup2/std
    // mutation. NOT_RUN; this is descriptor identity, not directory-entry proof.
    @Test func callerDescriptorIdentityDrift() throws {
        let first = try PublicOutputFixture()
        let selected = try first.fd()
        let output = try NativeNamecoinPrivateOutput(selectedDescriptor: selected)
        _ = try first.closeOriginal()
        let replacement = try PublicOutputFixture()
        let replacementFD = try replacement.fd()
        guard replacementFD == selected else { throw OutputFixtureError.setup }
        let bytes = Data("public fixture\n".utf8)
        expectOutputRefusal(.unavailable) {
            try output.writePublicResult(bytes, expectedSHA256: outputDigest(bytes))
        }
        #expect(fcntl(replacementFD, F_GETFD) >= 0)
        #expect(try replacement.bytes().isEmpty)
        // Reopen the first path solely to check its still-empty fixture inode.
        let firstProbe = try first.openAgain(flags: O_RDONLY)
        var status = stat()
        #expect(fstat(firstProbe, &status) == 0)
        #expect(status.st_size == 0)
    }

    // Claim: real partial writes + synthetic failure, and synthetic fsync/read
    // failure boundaries after real writes, always return UNKNOWN. No retry,
    // truncation, repair, or claim of unchanged output. NOT_RUN; synthetic faults
    // do not prove disk-failure behavior, actual native authority, or completion.
    @Test func partialAndPostWriteFailuresStayUnknown() throws {
        let bytes = Data(repeating: 0x50, count: 100)
        for fault in [NativeNamecoinOutputTestFault.partialWriteFailure, .synchronizeFailure,
                      .readbackFailure, .closeReplyLost] {
            let fixture = try PublicOutputFixture()
            let original = try fixture.fd()
            let output = try NativeNamecoinPrivateOutput(selectedDescriptor: original, testFault: fault)
            expectOutputRefusal(.unknown) {
                try output.writePublicResult(bytes, expectedSHA256: outputDigest(bytes))
            }
            let observed = try fixture.bytes()
            if fault == .partialWriteFailure {
                #expect(observed == Data(bytes.prefix(17)))
            } else {
                #expect(observed == bytes)
            }
            expectOutputRefusal(.unavailable) {
                try output.writePublicResult(bytes, expectedSHA256: outputDigest(bytes))
            }
            try output.close()
            try output.close()
            #expect(try fixture.bytes() == observed)
            #expect(fcntl(original, F_GETFD) == FD_CLOEXEC)
            // A real new handle survives repeated cleanup, including the seam
            // that performs a real close but simulates its lost success reply.
            let probe = try fixture.openAgain(flags: O_RDONLY)
            try output.close()
            #expect(fcntl(probe, F_GETFD) >= 0)
        }
    }
}
