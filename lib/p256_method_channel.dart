import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'p256_platform_interface.dart';
import 'src/constants.dart';

/// An implementation of [SecureP256Platform] that uses method channels.
class SecureP256Channel extends SecureP256Platform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('insight42_secure_p256_plugin');

  @override
  Future<Uint8List> getPublicKey(String tag,
      {bool requireUserPresence = false}) async {
    final keyBytes = await methodChannel.invokeMethod(
      Methods.getPublicKey,
      {
        'tag': tag,
        'requireUserPresence': requireUserPresence ? "high" : "secure",
      },
    );
    return keyBytes;
  }

  @override
  Future<Uint8List> sign(String tag, Uint8List payload) async {
    final signature = await methodChannel.invokeMethod(
      Methods.sign,
      {'tag': tag, 'payload': payload},
    );
    return signature;
  }

  @override
  Future<bool> verify(
    Uint8List payload,
    Uint8List publicKey,
    Uint8List signature,
  ) async {
    final result = await methodChannel.invokeMethod<bool>(
      Methods.verify,
      {
        'payload': payload,
        'publicKey': publicKey,
        'signature': signature,
      },
    );
    return result ?? false;
  }

  @override
  Future<Uint8List> getSharedSecret(String tag, Uint8List publicKey) async {
    final result = await methodChannel.invokeMethod(
      Methods.getSharedSecret,
      {'tag': tag, 'publicKey': publicKey},
    );
    return result;
  }

  @override
  Future<Uint8List> encryptData(String tag, Uint8List plaintext) async {
    final result = await methodChannel.invokeMethod(
      Methods.encryptData,
      {'tag': tag, 'plaintext': plaintext},
    );
    return result;
  }

  @override
  Future<Uint8List> decryptData(String tag, Uint8List ciphertext) async {
    final result = await methodChannel.invokeMethod(
      Methods.decryptData,
      {'tag': tag, 'ciphertext': ciphertext},
    );
    return result;
  }
}
