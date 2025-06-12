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
/*
class EcdsaUtil {
  static Uint8List ecPublicKeyToDER(EcPublicKey pub) {
    final rawKey = pub.toDer();
    return rawKey;
  }

  /// Returns true if the signature looks like a DER-encoded ASN.1 SEQUENCE
  static bool isDerSignature(Uint8List sig) {
    return sig.isNotEmpty && sig[0] == 0x30;
  }

  /// Decode a DER‐encoded ECDSA signature (ASN.1 SEQUENCE of two INTEGERS)
  /// into the raw 64-byte [r||s] form, padding each to exactly 32 bytes.
  static EcPublicKey derToRaw(Uint8List der, {int partLength = 32}) {

    return EcPublicKey.parseDer(der, type: KeyPairType.p256);

    }

    return [
      ...normalize(rBytes),
      ...normalize(sBytes),
    ];
  }

  /// Wraps a raw 64-byte [r||s] ECDSA signature into a DER‐encoded ASN.1 SEQUENCE.
  static Uint8List bytesWrapDerSignature(Uint8List rawSig) {
    if (rawSig.length != 64) {
      throw ArgumentError.value(
        rawSig,
        'rawSig',
        'Expected 64 bytes (r||s), got ${rawSig.length}',
      );
    }

    // Split into r and s
    final rBytes = rawSig.sublist(0, 32);
    final sBytes = rawSig.sublist(32);

    // Decode bytes to BigInt
    BigInt bytesToBigInt(Uint8List b) {
      BigInt acc = BigInt.zero;
      for (final byte in b) {
        acc = (acc << 8) | BigInt.from(byte);
      }
      return acc;
    }

    final r = ASN1Integer(bytesToBigInt(rBytes));
    final s = ASN1Integer(bytesToBigInt(sBytes));

    // Sequence of two INTEGERS
    final seq = ASN1Sequence();
    seq.add(r);
    seq.add(s);

    return seq.encodedBytes as Uint8List;
  }
}

 */
