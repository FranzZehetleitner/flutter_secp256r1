import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// Parses a SecKeyCopyExternalRepresentation-style P-256 public key
/// (ANSI X9.63 uncompressed: 0x04||X||Y) into an `EcPublicKey`.
EcPublicKey ecPublicKeyFromX963(Uint8List rawKey,
    {
    /// By default, uses ECDH-P256; if you need
    /// ECDSA-P256, pass `Ecdsa.p256(Sha256()).keyPairType` here.
    KeyPairType type = KeyPairType.p256}) {
  if (rawKey.isEmpty || rawKey[0] != 0x04) {
    throw FormatException(
      'Invalid EC point format: expected uncompressed form (0x04 prefix).',
    );
  }
  final coordinateLen = (rawKey.length - 1) ~/ 2;
  final x = rawKey.sublist(1, 1 + coordinateLen);
  final y = rawKey.sublist(1 + coordinateLen);
  return EcPublicKey(x: x, y: y, type: type);
}

/// Encode a cryptography.EcPublicKey (P-256) into the
/// uncompressed ANSI X9.63 form (0x04 || X || Y),
/// so that Swift’s SecKeyCreateWithData can import it.
Uint8List encodeEcPublicKeyX963(EcPublicKey publicKey) {
  final x = publicKey.x;
  final y = publicKey.y;
  if (x.length != 32 || y.length != 32) {
    throw ArgumentError('P-256 coordinates must each be 32 bytes');
  }
  return Uint8List.fromList([0x04, ...x, ...y]);
}
