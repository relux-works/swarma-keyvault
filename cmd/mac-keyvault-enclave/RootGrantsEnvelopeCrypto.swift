import CryptoKit
import Foundation

enum RootGrantsEnvelopeGCMError: Error {
    case invalidCiphertext
}

enum RootGrantsEnvelopeGCM {
    static func open(_ ciphertext: Data, material: Data, plaintextMagic: Data) throws -> Data {
        guard material.count == 32, ciphertext.count >= 65 + 16 else {
            throw RootGrantsEnvelopeGCMError.invalidCiphertext
        }
        let symmetric = SymmetricKey(data: material.prefix(16))
        let nonce: AES.GCM.Nonce
        do { nonce = try AES.GCM.Nonce(data: material.suffix(16)) }
        catch { throw RootGrantsEnvelopeGCMError.invalidCiphertext }
        let box: AES.GCM.SealedBox
        do {
            box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext.dropFirst(65).dropLast(16),
                                        tag: ciphertext.suffix(16))
        } catch { throw RootGrantsEnvelopeGCMError.invalidCiphertext }
        var plaintext: Data
        do { plaintext = try AES.GCM.open(box, using: symmetric) }
        catch { throw RootGrantsEnvelopeGCMError.invalidCiphertext }
        guard plaintext.count == 68, plaintext.prefix(4) == plaintextMagic else {
            plaintext.resetBytes(in: 0..<plaintext.count)
            throw RootGrantsEnvelopeGCMError.invalidCiphertext
        }
        return plaintext
    }
}

func rootGrantsCountersignOpenCiphertext(_ ciphertext: Data, material: Data) throws -> Data {
    try RootGrantsEnvelopeGCM.open(ciphertext, material: material, plaintextMagic: Data("KVG1".utf8))
}

func rootGrantsSignV3OpenCiphertext(_ ciphertext: Data, material: Data) throws -> Data {
    try RootGrantsEnvelopeGCM.open(ciphertext, material: material, plaintextMagic: Data("KVG1".utf8))
}

func rootGrantsRecoveryOpenCiphertext(_ ciphertext: Data, material: Data) throws -> Data {
    try RootGrantsEnvelopeGCM.open(ciphertext, material: material, plaintextMagic: Data("KVN1".utf8))
}
