import 'dart:convert';
import 'dart:typed_data';
import 'package:webcrypto/webcrypto.dart';
import '../exceptions.dart';

/// Constants for COSE key labels.
///
/// See RFC 9052.
abstract class Cose {
  static const int kty = 1;
  static const int alg = 3;
  static const int crv = -1;
  static const int x = -2;
  static const int y = -3;
  static const int n = -1;
  static const int e = -2;
}

/// Converts an ASN.1 DER ECDSA signature to the raw R|S format expected by WebCrypto.
Uint8List convertDerToRawEcdsaSignature(
  Uint8List derSignature,
  int curveSizeBytes,
) {
  if (derSignature.isEmpty || derSignature[0] != 0x30) {
    throw WebAuthnException('Invalid signature format: expected SEQUENCE');
  }

  int offset = 1;
  int seqLen = derSignature[offset++];
  if ((seqLen & 0x80) != 0) {
    int numBytes = seqLen & 0x7F;
    seqLen = 0;
    for (int i = 0; i < numBytes; i++) {
      seqLen = (seqLen << 8) | derSignature[offset++];
    }
  }

  if (derSignature[offset++] != 0x02) {
    throw WebAuthnException('Invalid signature format: expected INTEGER for r');
  }
  int rLen = derSignature[offset++];
  if ((rLen & 0x80) != 0) {
    throw WebAuthnException(
      'Invalid signature format: unexpected long form length for r',
    );
  }

  final r = derSignature.sublist(offset, offset + rLen);
  offset += rLen;

  if (derSignature[offset++] != 0x02) {
    throw WebAuthnException('Invalid signature format: expected INTEGER for s');
  }
  int sLen = derSignature[offset++];
  if ((sLen & 0x80) != 0) {
    throw WebAuthnException(
      'Invalid signature format: unexpected long form length for s',
    );
  }

  final s = derSignature.sublist(offset, offset + sLen);

  Uint8List padOrStrip(Uint8List value) {
    if (value.length == curveSizeBytes) return value;
    if (value.length > curveSizeBytes) {
      int stripLen = value.length - curveSizeBytes;
      for (int i = 0; i < stripLen; i++) {
        if (value[i] != 0) {
          throw WebAuthnException('Invalid signature: R or S value too large');
        }
      }
      return value.sublist(stripLen);
    }
    final padded = Uint8List(curveSizeBytes);
    padded.setRange(curveSizeBytes - value.length, curveSizeBytes, value);
    return padded;
  }

  final rFormatted = padOrStrip(r);
  final sFormatted = padOrStrip(s);

  return Uint8List.fromList([...rFormatted, ...sFormatted]);
}

/// Converts a COSE [credentialPublicKey] map to a `webcrypto` public key object.
///
/// Supports ES256, ES384, ES512, RS256, and PS256.
///
/// Returns one of: [EcdsaPublicKey], [RsassaPkcs1V15PublicKey], or [RsaPssPublicKey].
Future<Object?> parseCosePublicKey(
  Map<int, dynamic>? credentialPublicKey,
) async {
  if (credentialPublicKey == null) return null;

  final kty = credentialPublicKey[Cose.kty] as int?;
  final alg = credentialPublicKey[Cose.alg] as int?;

  return switch (kty) {
    2 => _parseEcKey(credentialPublicKey, alg),
    3 => _parseRsaKey(credentialPublicKey, alg),
    _ => throw UnsupportedAlgorithmException('Unsupported key type: $kty'),
  };
}

Future<EcdsaPublicKey> _parseEcKey(Map<int, dynamic> key, int? alg) {
  final crv = key[Cose.crv] as int?;
  final x = (key[Cose.x] as List?)?.cast<int>();
  final y = (key[Cose.y] as List?)?.cast<int>();

  if (x == null || y == null) {
    throw InvalidAuthenticatorDataException('Missing EC coordinates');
  }

  final (curve, crvStr) = switch (crv) {
    1 => (EllipticCurve.p256, 'P-256'),
    2 => (EllipticCurve.p384, 'P-384'),
    3 => (EllipticCurve.p521, 'P-521'),
    _ => throw UnsupportedAlgorithmException('Unsupported curve: $crv'),
  };

  final jwk = {
    'kty': 'EC',
    'crv': crvStr,
    'x': base64Url.encode(x).replaceAll('=', ''),
    'y': base64Url.encode(y).replaceAll('=', ''),
  };

  if (alg != null) {
    final algStr = switch (alg) {
      -7 => 'ES256',
      -35 => 'ES384',
      -36 => 'ES512',
      _ => null,
    };
    if (algStr != null) jwk['alg'] = algStr;
  }

  return EcdsaPublicKey.importJsonWebKey(jwk, curve);
}

Future<Object> _parseRsaKey(Map<int, dynamic> key, int? alg) {
  final n = (key[Cose.n] as List?)?.cast<int>();
  final e = (key[Cose.e] as List?)?.cast<int>();

  if (n == null || e == null) {
    throw InvalidAuthenticatorDataException('Missing RSA parameters');
  }

  final jwk = {
    'kty': 'RSA',
    'n': base64Url.encode(n).replaceAll('=', ''),
    'e': base64Url.encode(e).replaceAll('=', ''),
  };

  return switch (alg) {
    -257 => () {
      jwk['alg'] = 'RS256';
      return RsassaPkcs1V15PublicKey.importJsonWebKey(jwk, Hash.sha256);
    }(),
    -37 => () {
      jwk['alg'] = 'PS256';
      return RsaPssPublicKey.importJsonWebKey(jwk, Hash.sha256);
    }(),
    _ => throw UnsupportedAlgorithmException('Unsupported RSA algorithm: $alg'),
  };
}
