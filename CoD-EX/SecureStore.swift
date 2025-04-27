import Foundation
import Security

class SecureStore {
    static let shared = SecureStore()
    private init() {}
    
    private let aesKeyKey = "com.codex.aeskey"
    private let pinHashKey = "com.codex.pinhash"
    
    // MARK: - AES Key
    func saveAESKey(_ key: Data) -> Bool {
        return save(key, for: aesKeyKey)
    }
    
    func getAESKey() -> Data? {
        return retrieve(for: aesKeyKey)
    }
    
    // MARK: - PIN Hash
    func savePINHash(_ hash: Data) -> Bool {
        return save(hash, for: pinHashKey)
    }
    
    func getPINHash() -> Data? {
        return retrieve(for: pinHashKey)
    }
    
    // MARK: - Private Keychain Helpers
    private func save(_ data: Data, for key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]
        SecItemDelete(query as CFDictionary) // Remove old item if exists
        let attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data
        ]
        let status = SecItemAdd(attributes as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    private func retrieve(for key: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var dataTypeRef: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
        if status == errSecSuccess {
            return dataTypeRef as? Data
        }
        return nil
    }
}

// MARK: - Encrypted Payload Contract
struct EncryptedPayload {
    static let currentVersion: UInt8 = 1

    let version: UInt8
    let nonce: Data
    let tag: Data
    let ciphertext: Data

    // Serialize to Data
    func toData() -> Data {
        var data = Data()
        data.append(version)
        data.append(UInt8(nonce.count))
        data.append(nonce)
        data.append(UInt8(tag.count))
        data.append(tag)
        data.append(ciphertext)
        return data
    }

    // Deserialize from Data
    static func fromData(_ data: Data) -> EncryptedPayload? {
        var cursor = 0
        guard data.count > 3 else { return nil }
        let version = data[cursor]
        cursor += 1
        let nonceLen = Int(data[cursor])
        cursor += 1
        guard data.count > cursor + nonceLen else { return nil }
        let nonce = data.subdata(in: cursor..<(cursor+nonceLen))
        cursor += nonceLen
        let tagLen = Int(data[cursor])
        cursor += 1
        guard data.count > cursor + tagLen else { return nil }
        let tag = data.subdata(in: cursor..<(cursor+tagLen))
        cursor += tagLen
        let ciphertext = data.subdata(in: cursor..<data.count)
        return EncryptedPayload(version: version, nonce: nonce, tag: tag, ciphertext: ciphertext)
    }
} 