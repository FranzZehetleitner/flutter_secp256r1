import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:secp256r1/src/helpers.dart';

import 'p256_platform_interface.dart';

class SecureP256 {
  const SecureP256._();

  static Future<EcPublicKey> getPublicKey(String tag,
      [bool securityLevelHigh = false]) async {
    assert(tag.isNotEmpty);
    final raw =
        await SecureP256Platform.instance.getPublicKey(tag, securityLevelHigh);

    // ECDSA starts with 0x04 and 65 length.
    return ecPublicKeyFromX963(raw);
  }

  static Future<List<int>> sign(String tag, Uint8List payload) async {
    assert(tag.isNotEmpty);
    assert(payload.isNotEmpty);
    final signature = await SecureP256Platform.instance.sign(tag, payload);
    return signature;
  }

  static Future<bool> verify(
    Uint8List payload,
    EcPublicKey publicKey,
    Uint8List signature,
  ) {
    assert(payload.isNotEmpty);
    assert(signature.isNotEmpty);
    Uint8List rawKey = encodeEcPublicKeyX963(publicKey);

    return SecureP256Platform.instance.verify(
      payload,
      rawKey,
      signature,
    );
  }

  static Future<Uint8List> getSharedSecret(String tag, EcPublicKey publicKey) {
    assert(tag.isNotEmpty);
    Uint8List rawKey = encodeEcPublicKeyX963(publicKey);
    return SecureP256Platform.instance.getSharedSecret(tag, rawKey);
  }

  static Future<Uint8List> encryptData(
      {required String tag, required Uint8List plaintext}) async {
    assert(plaintext.isNotEmpty);
    assert(tag.isNotEmpty);
    return SecureP256Platform.instance.encryptData(
      tag,
      plaintext,
    );
  }

  static Future<Uint8List> decryptData(
      {required String tag, required Uint8List ciphertext}) async {
    assert(ciphertext.isNotEmpty);
    assert(tag.isNotEmpty);
    return SecureP256Platform.instance.decryptData(
      tag,
      ciphertext,
    );
  }

  /// Return [iv, cipher].
/*static Future<Tuple2<Uint8List, Uint8List>> encrypt({
    required Uint8List sharedSecret,
    required Uint8List message,
  }) async {
    assert(sharedSecret.isNotEmpty);
    assert(message.isNotEmpty);
    final sharedX = sharedSecret.sublist(0, 32);
    final iv = Uint8List.fromList(randomAsU8a(12));
    final cipher = await aes256GcmEncrypt(
      req: AesEncryptReq(
        key: sharedX,
        iv: Uint8List.fromList(iv),
        message: message,
      ),
    );
    return Tuple2(iv, cipher);
  }

  static Future<Uint8List> decrypt({
    required Uint8List sharedSecret,
    required Uint8List iv,
    required Uint8List cipher,
  }) async {
    assert(sharedSecret.isNotEmpty);
    assert(iv.lengthInBytes == 12);
    assert(cipher.isNotEmpty);
    final sharedX = sharedSecret.sublist(0, 32);
    final decryptedMessage256 = await aes256GcmDecrypt(
      req: AesDecryptReq(
        key: sharedX,
        iv: iv,
        cipherText: cipher,
      ),
    );
    return decryptedMessage256;
  }

   */
}
