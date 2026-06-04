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

/// A sealed class hierarchy representing a parsed WebAuthn public key.
sealed class WebAuthnPublicKey {
  const WebAuthnPublicKey();
}

/// An ECDSA WebAuthn public key.
final class EcdsaWebAuthnPublicKey extends WebAuthnPublicKey {
  final EcdsaPublicKey key;
  final int alg;
  const EcdsaWebAuthnPublicKey(this.key, this.alg);
}

/// An RSA RsassaPkcs1V15 WebAuthn public key.
final class RsassaPkcs1V15WebAuthnPublicKey extends WebAuthnPublicKey {
  final RsassaPkcs1V15PublicKey key;
  const RsassaPkcs1V15WebAuthnPublicKey(this.key);
}

/// An RSA RsaPss WebAuthn public key.
final class RsaPssWebAuthnPublicKey extends WebAuthnPublicKey {
  final RsaPssPublicKey key;
  const RsaPssWebAuthnPublicKey(this.key);
}

/// Converts a COSE [credentialPublicKey] map to a [WebAuthnPublicKey] object.
///
/// Supports ES256, ES384, ES512, RS256, and PS256.
///
/// Returns one of: [EcdsaWebAuthnPublicKey], [RsassaPkcs1V15WebAuthnPublicKey], or [RsaPssWebAuthnPublicKey].
Future<WebAuthnPublicKey?> parseCosePublicKey(
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

Future<EcdsaWebAuthnPublicKey> _parseEcKey(
  Map<int, dynamic> key,
  int? alg,
) async {
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

  final resolvedAlg = alg ?? -7;

  final importedKey = await EcdsaPublicKey.importJsonWebKey(jwk, curve);
  return EcdsaWebAuthnPublicKey(importedKey, resolvedAlg);
}

Future<WebAuthnPublicKey> _parseRsaKey(Map<int, dynamic> key, int? alg) async {
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
    -257 => () async {
      jwk['alg'] = 'RS256';
      final importedKey = await RsassaPkcs1V15PublicKey.importJsonWebKey(
        jwk,
        Hash.sha256,
      );
      return RsassaPkcs1V15WebAuthnPublicKey(importedKey);
    }(),
    -37 => () async {
      jwk['alg'] = 'PS256';
      final importedKey = await RsaPssPublicKey.importJsonWebKey(
        jwk,
        Hash.sha256,
      );
      return RsaPssWebAuthnPublicKey(importedKey);
    }(),
    _ => throw UnsupportedAlgorithmException('Unsupported RSA algorithm: $alg'),
  };
}
