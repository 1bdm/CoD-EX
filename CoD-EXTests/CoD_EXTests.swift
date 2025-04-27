//
//  CoD_EXTests.swift
//  CoD-EXTests
//
//  Created by Dakshinamurthy Balusamuy on 17/04/25.
//

import Testing
@testable import CoD_EX
import CryptoKit

struct CoD_EXTests {

    // Helper: AES-GCM Encrypt
    func encrypt(plaintext: Data, key: SymmetricKey) throws -> EncryptedPayload {
        let nonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(plaintext, using: key, nonce: nonce)
        return EncryptedPayload(
            version: EncryptedPayload.currentVersion,
            nonce: sealedBox.nonce.data,
            tag: sealedBox.tag,
            ciphertext: sealedBox.ciphertext
        )
    }

    // Helper: AES-GCM Decrypt
    func decrypt(payload: EncryptedPayload, key: SymmetricKey) throws -> Data {
        let nonce = try AES.GCM.Nonce(data: payload.nonce)
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: payload.ciphertext, tag: payload.tag)
        return try AES.GCM.open(box, using: key)
    }

    @Test func testRoundTripEncryption() async throws {
        let key = SymmetricKey(size: .bits256)
        let original = "SecretMessage123".data(using: .utf8)!
        let payload = try encrypt(plaintext: original, key: key)
        let blob = payload.toData()
        guard let decoded = EncryptedPayload.fromData(blob) else { throw "Failed to decode payload" }
        let decrypted = try decrypt(payload: decoded, key: key)
        #expect(decrypted == original)
    }

    @Test func testTruncatedDataFails() async throws {
        let key = SymmetricKey(size: .bits256)
        let original = "SecretMessage123".data(using: .utf8)!
        let payload = try encrypt(plaintext: original, key: key)
        var blob = payload.toData()
        blob = blob.prefix(blob.count - 5) // Truncate
        let decoded = EncryptedPayload.fromData(blob)
        #expect(decoded == nil)
    }

    @Test func testWrongKeyFails() async throws {
        let key = SymmetricKey(size: .bits256)
        let wrongKey = SymmetricKey(size: .bits256)
        let original = "SecretMessage123".data(using: .utf8)!
        let payload = try encrypt(plaintext: original, key: key)
        let blob = payload.toData()
        guard let decoded = EncryptedPayload.fromData(blob) else { throw "Failed to decode payload" }
        do {
            _ = try decrypt(payload: decoded, key: wrongKey)
            #expect(false) // Should not succeed
        } catch {
            #expect(true)
        }
    }

    @Test func testCorruptedHeaderFails() async throws {
        let key = SymmetricKey(size: .bits256)
        let original = "SecretMessage123".data(using: .utf8)!
        let payload = try encrypt(plaintext: original, key: key)
        var blob = payload.toData()
        blob[0] = 0xFF // Corrupt version byte
        let decoded = EncryptedPayload.fromData(blob)
        // Decoding will succeed, but version will be wrong
        #expect(decoded != nil && decoded!.version == 0xFF)
        // Try to decrypt, should fail
        do {
            _ = try decrypt(payload: decoded!, key: key)
            #expect(false)
        } catch {
            #expect(true)
        }
    }

    @Test func example() async throws {
        // Write your test here and use APIs like `#expect(...)` to check expected conditions.
    }

}
