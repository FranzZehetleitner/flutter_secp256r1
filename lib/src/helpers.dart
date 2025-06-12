import 'dart:typed_data';

import 'package:pointycastle/asn1/primitives/asn1_integer.dart';
import 'package:pointycastle/asn1/primitives/asn1_sequence.dart';
import 'package:pointycastle/ecc/api.dart';

ECPublicKey parseP256PublicKey(Uint8List keyBytes) {
  // Expect 0x04 prefix for uncompressed form
  if (keyBytes.length != 65 || keyBytes[0] != 0x04) {
    throw ArgumentError.value(
      keyBytes,
      'keyBytes',
      'Invalid EC public key, expected 65 bytes starting with 0x04',
    );
  }

  // Create the domain parameters for P-256
  final ECDomainParameters params = ECDomainParameters('prime256v1');
  // Decode the point directly:
  final ECPoint p = params.curve.decodePoint(keyBytes)!;
  return ECPublicKey(p, params);
}

class EcdsaUtil {
  static Uint8List ecPublicKeyToRaw(ECPublicKey pub) {
    final rawKey = pub.Q?.getEncoded(false);
    if (rawKey == null) {
      throw FormatException("Could not read publicKey");
    }
    return rawKey;
  }

  /// Returns true if the signature looks like a DER-encoded ASN.1 SEQUENCE
  static bool isDerSignature(Uint8List sig) {
    return sig.isNotEmpty && sig[0] == 0x30;
  }

  /// Decode a DER‐encoded ECDSA signature (ASN.1 SEQUENCE of two INTEGERS)
  /// into the raw 64-byte [r||s] form, padding each to exactly 32 bytes.
  static List<int> derToRaw(Uint8List der, {int partLength = 32}) {
    final seq = ASN1Sequence.fromBytes(der);
    final rBytes = (seq.elements?[0] as ASN1Integer).valueBytes!;
    final sBytes = (seq.elements?[1] as ASN1Integer).valueBytes!;

    List<int> normalize(List<int> bytes) {
      // strip DER sign-byte if present
      if (bytes.length == partLength + 1 && bytes.first == 0) {
        bytes = bytes.sublist(1);
      }
      if (bytes.length > partLength) {
        throw ArgumentError('Integer too large: ${bytes.length} > $partLength');
      }
      return List.filled(partLength - bytes.length, 0) + bytes;
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
