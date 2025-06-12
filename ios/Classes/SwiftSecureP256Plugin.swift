import Flutter
import Foundation
import LocalAuthentication
import Security
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
                let canDecrypt = (param!["canDecrypt"] as? Bool) ?? false
                let highSecurity = (param!["highSecurity"] as? Bool) ?? false
                var password: String? = nil
                if let pwd = param!["password"] as? String {
                    password = pwd
                }

                let key = try getPublicKey(
                    tag: tag, password: password, highSecurity: highSecurity, canDecrypt: canDecrypt
                )
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
                )
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

    func generateKeyPair(tag: String, password: String?, highSecurity: Bool, canDecrypt: Bool)
        throws -> SecKey
    {
        let tagData = tag.data(using: .utf8)
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        var accessError: Unmanaged<CFError>?
        if highSecurity {
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
                kSecAttrCanDecrypt as String: canDecrypt,
            ]
            // PUBLIC-key attrs: persistent, tagged
            let publicAttrs: [String: Any] = [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tagData,
                kSecAttrCanEncrypt as String: canDecrypt,
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

            if flags.contains(.applicationPassword) {
                let context = LAContext()
                var newPassword: Data?
                if let password = password, !password.isEmpty {
                    newPassword = password.data(using: .utf8)
                }
                context.setCredential(newPassword, type: .applicationPassword)
                parameterTemp[kSecUseAuthenticationContext as String] = context
            }

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
        tag: String, password: String?, highSecurity: Bool = false, canDecrypt: Bool = false
    ) throws -> Data {
        let secKey: SecKey

        if let existing = try? getSecKey(tag: tag, password: password, highSecurity: highSecurity) {
            secKey = existing
        } else {
            secKey = try generateKeyPair(
                tag: tag, password: password, highSecurity: highSecurity, canDecrypt: canDecrypt)
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

    func sign(
        tag: String,
        password: String?,
        payload: Data
    ) throws -> Data {

        let context = LAContext()
        context.localizedReason = "Authenticate to sign/decrypt"
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: tag,
            kSecReturnRef as String: true,
        ]

        if try requiresUserPresence(tag: tag) {
            let context = LAContext()
            context.localizedReason = "Authenticate to sign data"
            query[kSecUseAuthenticationContext as String] = context
        }

        // Fetch the SecKey (this will prompt only if userPresence was set)
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
            let keyToUse = item as? SecKey
        else {
            throw NSError(domain: "KEY_NOT_FOUND", code: -1, userInfo: nil)
        }

        // Create the signature
        var cfErr: Unmanaged<CFError>?
        guard
            let sigData = SecKeyCreateSignature(
                keyToUse,
                .ecdsaSignatureMessageX962SHA256,
                payload as CFData,
                &cfErr
            ) as Data?
        else {
            throw cfErr?.takeRetainedValue()
                ?? NSError(
                    domain: NSOSStatusErrorDomain, code: -1, userInfo: nil
                )
        }

        return sigData
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
            ] as CFDictionary

        var error: Unmanaged<CFError>?
        do {
            secKey = try getSecKey(tag: tag, password: password)
            publicKey = SecKeyCreateWithData(publicKeyData as CFData, publicKeyAttributes, &error)!
        } catch {
            throw error
        }

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
        var cfErr: Unmanaged<CFError>?
        guard
            let cipher = SecKeyCreateEncryptedData(
                pubKey,
                .eciesEncryptionCofactorX963SHA256AESGCM,
                plaintext as CFData,
                &cfErr
            ) as Data?
        else {
            throw cfErr!.takeRetainedValue()
        }
        return FlutterStandardTypedData(bytes: cipher)
    }

    // Decrypt inside the Secure Enclave
    private func decryptDataECIES(
        tag: String,
        ciphertext: Data
    ) throws -> FlutterStandardTypedData {
        let needsAuth = try requiresUserPresence(tag: tag)
        // Prepare context with a reason
        // Query for the private key in Secure Enclave
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: tag as CFString,
            kSecReturnRef as String: true,
        ]

        if needsAuth {
            let authCtx = LAContext()
            authCtx.localizedReason = "Authenticate to decrypt data"
            query[kSecUseAuthenticationContext as String] = authCtx
        }
        // Fetch the key (prompts if needed)
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess,
            let keyToUse = item as? SecKey
        else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: nil)
        }

        // Decrypt inside the enclave
        var error: Unmanaged<CFError>?
        guard
            let plainData = SecKeyCreateDecryptedData(
                keyToUse,
                .eciesEncryptionCofactorX963SHA256AESGCM,
                ciphertext as CFData,
                &error
            ) as Data?
        else {
            throw error?.takeRetainedValue()
                ?? NSError(
                    domain: NSOSStatusErrorDomain, code: -1, userInfo: nil
                )
        }

        return FlutterStandardTypedData(bytes: plainData)
    }

    /// Retrieves the enclave private key reference for `tag`, applying user auth if `level == "high"`.
    /// - Parameters:
    ///   - tag: your unique key namespace
    ///   - level: "secure" or "high"
    internal func getSecKey(tag: String, password: String?, highSecurity: Bool = false) throws
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

        if highSecurity {
            let ctx = LAContext()
            ctx.localizedReason = "Authenticate to use your high-security key"
            query[kSecUseAuthenticationContext as String] = ctx
        }

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

    /// Returns true if this Secure Enclave private key was created
    /// with `.userPresence` (i.e. will prompt Touch/Face ID or passcode).
    internal func requiresUserPresence(tag: String) throws -> Bool {
        let tagData = tag.data(using: .utf8)!
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: tagData,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        // Non-interactive context
        let ctx = LAContext()
        ctx.interactionNotAllowed = true
        query[kSecUseAuthenticationContext as String] = ctx

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        switch status {
        case errSecSuccess:
            // key exists and didn’t need UI
            return false
        case errSecInteractionNotAllowed:
            // key exists but requires user-presence
            return true
        default:
            // something else went wrong
            throw NSError(
                domain: NSOSStatusErrorDomain,
                code: Int(status),
                userInfo: nil
            )
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
