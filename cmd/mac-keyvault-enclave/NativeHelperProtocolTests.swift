import Darwin
import CryptoKit
import Foundation
import Testing
@testable import KeyvaultNativeCore

struct NativeHelperProtocolTests {
    private struct GoSealedNonceFile: Decodable {
        let schema: String
        let vectors: [GoSealedNonceVector]
    }

    private struct GoSealedNonceVector: Decodable {
        let id: String
        let plaintextMagic: String
        let ciphertextBase64: String

        enum CodingKeys: String, CodingKey {
            case id
            case plaintextMagic = "plaintext_magic"
            case ciphertextBase64 = "ciphertext_base64"
        }
    }

    @Test func goSealed16ByteNonceOpensAndTamperedTagRefusesOnAllDecryptPaths() throws {
        let url = try #require(Bundle.module.url(forResource: "RootGrantsF7GoSealedNonce16-19",
                                                 withExtension: "json"))
        let fixture = try JSONDecoder().decode(GoSealedNonceFile.self, from: Data(contentsOf: url))
        #expect(fixture.schema == "keyvault-go-aes-gcm-nonce16-test/1")
        #expect(fixture.vectors.count == 2)

        for (vectorIndex, vector) in fixture.vectors.enumerated() {
            guard let ciphertext = Data(base64Encoded: vector.ciphertextBase64), ciphertext.count == 149 else {
                Issue.record("invalid Go-sealed nonce witness \(vector.id)")
                continue
            }
            let nonceByte: UInt8
            let paths: [(String, (Data, Data) throws -> Data)]
            switch vector.id {
            case "kvg1":
                nonceByte = 0x11
                paths = [
                    ("trust-countersign", { try rootGrantsCountersignOpenCiphertext($0, material: $1) }),
                    ("grant-v3", { try rootGrantsSignV3OpenCiphertext($0, material: $1) }),
                ]
            case "kvn1":
                nonceByte = 0x22
                paths = [("recovery", { try rootGrantsRecoveryOpenCiphertext($0, material: $1) })]
            default:
                Issue.record("unknown Go-sealed nonce witness \(vector.id)")
                continue
            }
            let material = Data(repeating: 0, count: 16) + Data(repeating: nonceByte, count: 16)
            let expected = Data(vector.plaintextMagic.utf8) + Data((4..<68).map { UInt8(($0 * 3) & 0xff) })
            for (pathIndex, (path, open)) in paths.enumerated() {
                var plaintext = try open(ciphertext, material)
                defer { plaintext.resetBytes(in: 0..<plaintext.count) }
                #expect(plaintext == expected, "Go-sealed 16-byte nonce failed on \(path)")

                var tampered = ciphertext
                tampered[tampered.index(before: tampered.endIndex)] ^= 1
                #expect(throws: RootGrantsEnvelopeGCMError.self) { _ = try open(tampered, material) }

                let alternateNonce = Data((0..<16).map { UInt8(0x80 + vectorIndex * 8 + pathIndex + $0) })
                let key = SymmetricKey(data: material.prefix(16))
                let nonce = try AES.GCM.Nonce(data: alternateNonce)
                let resealed = try AES.GCM.seal(expected, using: key, nonce: nonce)
                let alternateCiphertext = Data(ciphertext.prefix(65)) + resealed.ciphertext + resealed.tag
                let alternateMaterial = Data(material.prefix(16)) + alternateNonce
                var wrongNonce = alternateNonce
                wrongNonce[0] ^= 1
                let wrongNonceMaterial = Data(material.prefix(16)) + wrongNonce
                #expect(try open(alternateCiphertext, alternateMaterial) == expected,
                        "same-magic alternate nonce failed on \(path)")
                #expect(throws: RootGrantsEnvelopeGCMError.self) {
                    _ = try open(alternateCiphertext, wrongNonceMaterial)
                }

                var wrongFrame = expected
                wrongFrame.replaceSubrange(0..<4, with: Data("BAD1".utf8))
                let wrongFrameNonce = Data((0..<16).map { UInt8(0xC0 + vectorIndex * 8 + pathIndex + $0) })
                let frameNonce = try AES.GCM.Nonce(data: wrongFrameNonce)
                let wrongFrameBox = try AES.GCM.seal(wrongFrame, using: key, nonce: frameNonce)
                let authenticatedFrame = try AES.GCM.SealedBox(nonce: frameNonce, ciphertext: wrongFrameBox.ciphertext,
                                                                tag: wrongFrameBox.tag)
                #expect(try AES.GCM.open(authenticatedFrame, using: key) == wrongFrame)
                let wrongFrameCiphertext = Data(ciphertext.prefix(65)) + wrongFrameBox.ciphertext + wrongFrameBox.tag
                #expect(throws: RootGrantsEnvelopeGCMError.self) {
                    _ = try open(wrongFrameCiphertext, Data(material.prefix(16)) + wrongFrameNonce)
                }
            }
        }
    }

    @Test func publicOperationChecksClosedFieldsBeforeDecodingBlob() {
        var failure: HelperError?
        do {
            _ = try publicKey(["op": "public", "blob": "%%%", "unexpected": "field"])
        } catch let error as HelperError {
            failure = error
        } catch {
            Issue.record("unexpected public-operation error: \(error)")
        }
        #expect(failure?.code == "bad_request")
        #expect(failure?.status == KeyvaultNativeCore.errSecParam)
        #expect(failure?.message == "request fields differ from the closed operation")

        var admittedFailure: HelperError?
        do {
            _ = try publicKey(["op": "public", "blob": "%%%"])
        } catch let error as HelperError {
            admittedFailure = error
        } catch {
            Issue.record("unexpected admitted-public-operation error: \(error)")
        }
        #expect(admittedFailure?.message == "blob is not base64")
    }

    @Test func writeFrameUsesProductionOutputWriterAndPropagatesEPIPE() throws {
        var captured = Data()
        try writeFrame(["z": 1, "a": "frame"], using: { captured.append($0) })
        #expect(String(decoding: captured, as: UTF8.self) == "{\"a\":\"frame\",\"z\":1}\n")

        var writeAttempts = 0
        do {
            try writeFrame(["result": "fixture"], using: { _ in
                writeAttempts += 1
                throw POSIXError(.EPIPE)
            })
            Issue.record("closed output writer unexpectedly succeeded")
        } catch let error as POSIXError {
            #expect(error.code == .EPIPE)
        }
        #expect(writeAttempts == 1)
    }

    @Test func eachGenericOperationRejectsUnknownRequestFields() throws {
        let cases: [(String, [String])] = [
            ("create", ["presence"]),
            ("public", ["blob"]),
            ("sign", ["blob", "digest", "presence", "reason"]),
            ("review-document", ["blob", "presence", "review"]),
        ]
        for (operation, required) in cases {
            var request = ["op": operation]
            for key in required { request[key] = "fixture" }
            try requireHelperRequestFields(request, operation: operation, required: Set(required),
                                           optional: operation == "sign" ? ["interaction"] : [])
            request["unexpected"] = "fixture"
            #expect(throws: HelperError.self) {
                try requireHelperRequestFields(request, operation: operation, required: Set(required),
                                               optional: operation == "sign" ? ["interaction"] : [])
            }
        }

        try requireHelperRequestFields(["op": "sign", "blob": "fixture", "digest": "fixture",
                                        "presence": "none", "reason": "fixture", "interaction": "none"],
                                       operation: "sign", required: ["blob", "digest", "presence", "reason"],
                                       optional: ["interaction"])
    }

    @Test func genericHelperSIGPIPEInstallerRequestsIgnoreDisposition() {
        var installed = false
        installGenericHelperSIGPIPEIgnore { signalNumber, action in
            installed = signalNumber == SIGPIPE && action == .ignore
        }
        #expect(installed)
    }
}
