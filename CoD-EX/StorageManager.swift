import Foundation

#if canImport(UIKit)
import UIKit
#endif

class StorageManager {
    static let shared = StorageManager()
    private init() {}

    enum VaultType: String {
        case media = "Media"
        case thumbs = "Thumbs"
    }

    private var vaultRoot: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("Vault")
    }

    func directory(for type: VaultType) -> URL {
        let dir = vaultRoot.appendingPathComponent(type.rawValue)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    func newFileURL(for type: VaultType) -> URL {
        let uuid = UUID().uuidString
        return directory(for: type).appendingPathComponent(uuid).appendingPathExtension("enc")
    }

    func atomicWrite(data: Data, to url: URL) throws {
        let tmpURL = url.appendingPathExtension("tmp")
        try data.write(to: tmpURL, options: .atomic)
        if FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.removeItem(at: url)
        }
        try FileManager.default.moveItem(at: tmpURL, to: url)
    }

    // Additional helpers (read, list, delete) can be added as needed
}

extension StorageManager {
    /// Generates, encrypts, and saves a thumbnail for a given UIImage.
    /// - Parameters:
    ///   - image: The source UIImage.
    ///   - uuid: The UUID string to use for the thumbnail filename.
    ///   - key: The symmetric key for encryption.
    /// - Throws: Any error from image processing, encryption, or file writing.
    /// - Returns: The file URL where the encrypted thumbnail was saved.
    @discardableResult
    func saveEncryptedThumbnail(from image: UIImage, uuid: String, key: SymmetricKey) throws -> URL {
        // 1. Downscale to 120x120 JPEG
        let size = CGSize(width: 120, height: 120)
        UIGraphicsBeginImageContextWithOptions(size, true, 0)
        image.draw(in: CGRect(origin: .zero, size: size))
        let resized = UIGraphicsGetImageFromCurrentImageContext()
        UIGraphicsEndImageContext()
        guard let thumbData = resized?.jpegData(compressionQuality: 0.75) else {
            throw NSError(domain: "ThumbnailError", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to create thumbnail data"])
        }
        // 2. Encrypt
        let payload = try encrypt(plaintext: thumbData, key: key)
        let encryptedData = payload.toData()
        // 3. Save atomically
        let url = directory(for: .thumbs)
            .appendingPathComponent(uuid)
            .appendingPathExtension("thumb.enc")
        try atomicWrite(data: encryptedData, to: url)
        return url
    }

    /// Loads and decrypts a thumbnail image for a given UUID and key.
    /// - Parameters:
    ///   - uuid: The UUID string used for the thumbnail filename.
    ///   - key: The symmetric key for decryption.
    /// - Returns: The decrypted UIImage, or nil if failed.
    func loadDecryptedThumbnail(uuid: String, key: SymmetricKey) -> UIImage? {
        let url = directory(for: .thumbs)
            .appendingPathComponent(uuid)
            .appendingPathExtension("thumb.enc")
        guard let encryptedData = try? Data(contentsOf: url),
              let payload = EncryptedPayload.fromData(encryptedData) else {
            return nil
        }
        do {
            let decryptedData = try decrypt(payload: payload, key: key)
            return UIImage(data: decryptedData)
        } catch {
            return nil
        }
    }

    // Helper: AES-GCM Decrypt (for use in StorageManager)
    func decrypt(payload: EncryptedPayload, key: SymmetricKey) throws -> Data {
        let nonce = try AES.GCM.Nonce(data: payload.nonce)
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: payload.ciphertext, tag: payload.tag)
        return try AES.GCM.open(box, using: key)
    }
}

// Helper: AES-GCM Encrypt (for use in StorageManager)
#if canImport(CryptoKit)
import CryptoKit
#endif

extension StorageManager {
    func encrypt(plaintext: Data, key: SymmetricKey) throws -> EncryptedPayload {
        let nonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(plaintext, using: key, nonce: nonce)
        return EncryptedPayload(
            version: EncryptedPayload.currentVersion,
            nonce: Data(sealedBox.nonce),
            tag: sealedBox.tag,
            ciphertext: sealedBox.ciphertext
        )
    }
} 