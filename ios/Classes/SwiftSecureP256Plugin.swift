import Flutter
import Foundation
import LocalAuthentication
import UIKit

public class SwiftSecureP256Plugin: NSObject, FlutterPlugin {
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(
            name: "insight42_secure_p256_plugin", binaryMessenger: registrar.messenger())
        let instance = SwiftSecureP256Plugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "getPublicKey":
            do {
                let param = call.arguments as? [String: Any]
                let tag = param!["tag"] as! String
                let requireUserPresence = (param!["requireUserPresence"] as? Bool) ?? false
                var password: String? = nil
                if let pwd = param!["password"] as? String {
                    password = pwd
                }

                let key = try getPublicKey(
                    tag: tag, password: password, requireUserPresence: requireUserPresence)
                result(FlutterStandardTypedData(bytes: key))
            } catch {
                result(
                    FlutterError(
                        code: "getPublicKey", message: error.localizedDescription,
                        details: "\(error)"))
            }
        case "sign":
            do {
                let param = call.arguments as? [String: Any]
                let tag = param!["tag"] as! String
                let payload = (param!["payload"] as! FlutterStandardTypedData).data
                var password: String? = nil
                if let pwd = param!["password"] as? String {
                    password = pwd
                }

                let signature = try sign(
                    tag: tag,
                    password: password,
                    payload: payload
                )!
                result(FlutterStandardTypedData(bytes: signature))
            } catch {
                result(
                    FlutterError(
                        code: "sign", message: error.localizedDescription, details: "\(error)"))
            }
        case "verify":
            do {
                let param = call.arguments as? [String: Any]
                let payload = (param!["payload"] as! FlutterStandardTypedData).data
                let publicKey = (param!["publicKey"] as! FlutterStandardTypedData).data
                let signature = (param!["signature"] as! FlutterStandardTypedData).data
                let verified = try verify(
                    payload: payload,
                    publicKey: publicKey,
                    signature: signature
                )

                result(verified)
            } catch {
                result(
                    FlutterError(
                        code: "verify", message: error.localizedDescription, details: "\(error)"))
            }
        case "getSharedSecret":
            do {
                let param = call.arguments as? [String: Any]
                let tag = param!["tag"] as! String
                let publicKeyData = (param!["publicKey"] as! FlutterStandardTypedData).data
                var password: String? = nil
                if let pwd = param!["password"] as? String {
                    password = pwd
                }

                let sharedSecret = try getSharedSecret(
                    tag: tag, password: password, publicKeyData: publicKeyData)!
                result(FlutterStandardTypedData(bytes: sharedSecret))
            } catch {
                result(
                    FlutterError(
                        code: "getSharedSecret", message: error.localizedDescription,
                        details: "\(error)"))
            }
        case "encryptData":
            do {
                let param = call.arguments as? [String: Any]
                let tag = param!["tag"] as! String
                let plaintext = (param!["plaintext"] as! FlutterStandardTypedData).data

                let ciphertext = try encryptDataECIES(tag: tag, plaintext: plaintext)
                result(ciphertext)
            } catch {
                result(
                    FlutterError(
                        code: "encryptData", message: error.localizedDescription,
                        details: "\(error)"))
            }
        case "decryptData":
            do {
                let param = call.arguments as? [String: Any]
                let tag = param!["tag"] as! String
                let ciphertext = (param!["ciphertext"] as! FlutterStandardTypedData).data

                let plaintext = try decryptDataECIES(tag: tag, ciphertext: ciphertext)
                result(plaintext)
            } catch {
                result(
                    FlutterError(
                        code: "decryptData", message: error.localizedDescription,
                        details: "\(error)"))

            }
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    func generateKeyPair(tag: String, password: String?, requireUserPresence: Bool) throws
        -> SecKey
    {
        let tagData = tag.data(using: .utf8)
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        var accessError: Unmanaged<CFError>?
        if requireUserPresence {
            flags.insert(.userPresence)
        }
        let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &accessError
        )
        if let error = accessError {
            throw error.takeRetainedValue() as Error
        }

        let parameter: CFDictionary
        var parameterTemp: [String: Any]

        if let tagData = tagData {
            // PRIVATE-key attrs: persistent, tagged, decrypt-enabled
            let privateAttrs: [String: Any] = [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tagData,
                kSecAttrAccessControl as String: accessControl,
            ]
            // PUBLIC-key attrs: persistent, tagged
            let publicAttrs: [String: Any] = [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tagData,
            ]

            parameterTemp = [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits as String: 256,
                kSecPrivateKeyAttrs as String: privateAttrs,
                kSecPublicKeyAttrs as String: publicAttrs,
            ]
            #if targetEnvironment(simulator)
            #else
                parameterTemp[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
            #endif

            parameter = parameterTemp as CFDictionary
            var secKeyCreateRandomKeyError: Unmanaged<CFError>?
            guard let secKey = SecKeyCreateRandomKey(parameter, &secKeyCreateRandomKeyError)
            else {
                throw secKeyCreateRandomKeyError!.takeRetainedValue() as Error
            }

            return secKey
        } else {
            throw CustomError.runtimeError("Invalid TAG") as Error
        }
    }

    /// Returns the public key bytes for `tag`, creating the key-pair if needed.
    /// - Parameters:
    ///   - tag: your unique key namespace
    ///   - level: "secure" (no user prompt) or "high" (Face/Touch ID or passcode required)
    func getPublicKey(
        tag: String, password: String?, requireUserPresence: Bool = false
    ) throws -> Data {
        let secKey: SecKey

        if let existing = try? getSecKey(tag: tag, password: password, requireUserPresence: requireUserPresence) {
            secKey = existing
        } else {
            secKey = try generateKeyPair(
                tag: tag, password: password, requireUserPresence: requireUserPresence)
        }

        guard let pubKey = SecKeyCopyPublicKey(secKey) else {
            throw NSError(
                domain: NSOSStatusErrorDomain, code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Unable to extract public key"])
        }

        var cfError: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(pubKey, &cfError) as Data? else {
            throw cfError!.takeRetainedValue() as Error
        }
        return data
    }

    func sign(tag: String, password: String?, payload: Data) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: tag,
            kSecReturnRef as String: true,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
            let privKey = item as! SecKey?
        else {
            throw NSError(domain: "KEY_NOT_FOUND", code: -1, userInfo: nil)
        }
        var error: Unmanaged<CFError>?
        guard
            let signData = SecKeyCreateSignature(
                privKey,
                SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256,
                payload as CFData,
                &error
            )
        else {
            if let e = error {
                throw e.takeUnretainedValue() as Error
            }
            throw CustomError.runtimeError("Cannot sign the payload")
        }
        return signData as Data
    }

    func verify(payload: Data, publicKey: Data, signature: Data) throws -> Bool {
        let newPublicParams: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256,
        ]
        guard
            let newPublicKey = SecKeyCreateWithData(
                publicKey as CFData,
                newPublicParams as CFDictionary,
                nil
            )
        else {
            return false
        }

        let verify = SecKeyVerifySignature(
            newPublicKey,
            SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256,
            payload as CFData,
            signature as CFData,
            nil
        )
        return verify
    }

    func getSharedSecret(tag: String, password: String?, publicKeyData: Data) throws -> Data? {
        let secKey: SecKey
        let publicKey: SecKey
        let publicKeyAttributes =
            [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                kSecAttrKeySizeInBits as String: 256,

            ] as CFDictionary

        var error: Unmanaged<CFError>?
        do {
            secKey = try getSecKey(tag: tag, password: password)
            publicKey = SecKeyCreateWithData(publicKeyData as CFData, publicKeyAttributes, &error)!
        } catch {
            throw error
        }

        var canDoCofactor = SecKeyIsAlgorithmSupported(
            privateKey,
            .keyExchange,
            SecKeyAlgorithm.ecdhKeyExchangeCofactorX963SHA256
        )
        print("cofactor-X963-SHA256 supported? \(canDoCofactor)")

        canDoCofactor = SecKeyIsAlgorithmSupported(
            privateKey,
            .keyExchange,
            SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA256
        )
        print("standard-X963-SHA256 supported? \(canDoCofactor)")
        var canDoCofactor = SecKeyIsAlgorithmSupported(
            publicKey,
            .keyExchange,
            SecKeyAlgorithm.ecdhKeyExchangeCofactorX963SHA256
        )
        print("cofactor-X963-SHA256 supported? \(canDoCofactor)")

        canDoCofactor = SecKeyIsAlgorithmSupported(
            publicKey,
            .keyExchange,
            SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA256
        )
        print("standard-X963-SHA256 supported? \(canDoCofactor)")

        let sharedSecretData =
            SecKeyCopyKeyExchangeResult(
                secKey,
                SecKeyAlgorithm.ecdhKeyExchangeStandard,
                publicKey,
                [:] as CFDictionary,
                &error
            ) as Data?
        return sharedSecretData
    }
    // Encrypt using the enclave’s public key (ECIES / you can choose algorithm).
    private func encryptDataECIES(tag: String, plaintext: Data) throws -> FlutterStandardTypedData {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecReturnRef as String: true,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
            let pubKey = item as! SecKey?
        else {
            throw NSError(domain: "KEY_NOT_FOUND", code: -1, userInfo: nil)
        }
        // Encrypt with ECIES (cofactor mode + AES-GCM)
        var error: Unmanaged<CFError>?
        guard
            let cipher = SecKeyCreateEncryptedData(
                pubKey,
                .eciesEncryptionCofactorX963SHA256AESGCM,
                plaintext as CFData,
                &error
            ) as Data?
        else {
            throw error!.takeRetainedValue()
        }
        return FlutterStandardTypedData(bytes: cipher)
    }

    // Decrypt inside the Secure Enclave
    private func decryptDataECIES(tag: String, ciphertext: Data) throws -> FlutterStandardTypedData
    {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: tag,
            kSecReturnRef as String: true,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
            let privKey = item as! SecKey?
        else {
            throw NSError(domain: "KEY_NOT_FOUND", code: -1, userInfo: nil)
        }
        // Perform decryption
        var error: Unmanaged<CFError>?

        guard
            let plain = SecKeyCreateDecryptedData(
                privKey,
                .eciesEncryptionCofactorX963SHA256AESGCM,
                ciphertext as CFData,
                &error
            ) as Data?
        else {
            throw error!.takeRetainedValue()
        }
        return FlutterStandardTypedData(bytes: plain)
    }

    /// Retrieves the enclave private key reference for `tag`, applying user auth if `level == "high"`.
    /// - Parameters:
    ///   - tag: your unique key namespace
    ///   - level: "secure" or "high"
    internal func getSecKey(tag: String, password: String?, requireUserPresence: Bool = false) throws
        -> SecKey
    {
        let tagData = tag.data(using: .utf8)!
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tagData,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            let msg = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error"
            throw NSError(
                domain: NSOSStatusErrorDomain, code: Int(status),
                userInfo: [NSLocalizedDescriptionKey: msg])
        }
        return item as! SecKey
    }

    internal func isKeyCreated(tag: String, password: String?) -> Bool {
        do {
            let result = try getSecKey(tag: tag, password: password)
            return result != nil ? true : false
        } catch {
            return false
        }
    }
}

enum CustomError: Error {

    case runtimeError(String)

    func get() -> String {
        switch self {
        case .runtimeError(let desc):
            return desc
        }
    }
}

extension CustomError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .runtimeError:
            return NSLocalizedString("\(self.get())", comment: "Custom Error")
        }
    }
}
