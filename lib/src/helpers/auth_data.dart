import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';
import 'package:cbor/cbor.dart';
import 'package:webcrypto/webcrypto.dart';
import '../exceptions.dart';
import 'cbor_utils.dart';

/// Constants for COSE key labels.
///
/// See RFC 9052.
abstract class _Cose {
  static const int kty = 1;
  static const int alg = 3;
  static const int crv = -1;
  static const int x = -2;
  static const int y = -3;
  static const int n = -1;
  static const int e = -2;
}

/// Constants for Authenticator Data flags.
///
/// See Section 6.1 of the WebAuthn specification.
abstract class _Flags {
  static const int up = 0x01;
  static const int uv = 0x04;
  static const int be = 0x08;
  static const int bs = 0x10;
  static const int at = 0x40;
  static const int ed = 0x80;
}

/// Represents the parsed `authenticatorData` (authData) structure.
///
/// See Section 6.1 of the WebAuthn specification.
class AuthenticatorData {
  /// SHA-256 hash of the Relying Party ID.
  final Uint8List rpIdHash;

  /// Bitfield indicating various states (UP, UV, AT, ED, etc.).
  final int flags;

  /// 32-bit unsigned big-endian integer for replay protection.
  final int signCount;

  /// The AAGUID of the authenticator (only if AT flag is set).
  final Uint8List? aaguid;

  /// The credential ID (only if AT flag is set).
  final Uint8List? credentialId;

  /// The decoded COSE Public Key (only if AT flag is set).
  ///
  /// In WebAuthn, COSE keys are CBOR maps where keys are integers.
  final Map<int, dynamic>? credentialPublicKey;

  /// Decoded extension data (only if ED flag is set).
  ///
  /// Extension keys are strings (extension identifiers).
  final Map<String, dynamic>? extensions;

  AuthenticatorData({
    required Uint8List rpIdHash,
    required this.flags,
    required this.signCount,
    Uint8List? aaguid,
    Uint8List? credentialId,
    Map<int, dynamic>? credentialPublicKey,
    Map<String, dynamic>? extensions,
  }) : rpIdHash = rpIdHash.asUnmodifiableView(),
       aaguid = aaguid?.asUnmodifiableView(),
       credentialId = credentialId?.asUnmodifiableView(),
       credentialPublicKey = credentialPublicKey != null
           ? UnmodifiableMapView(credentialPublicKey)
           : null,
       extensions = extensions != null ? UnmodifiableMapView(extensions) : null;

  /// User Present (UP) flag.
  bool get isUserPresent => (flags & _Flags.up) != 0;

  /// User Verified (UV) flag.
  bool get isUserVerified => (flags & _Flags.uv) != 0;

  /// Backup Eligibility (BE) flag.
  bool get isBackupEligible => (flags & _Flags.be) != 0;

  /// Backup State (BS) flag.
  bool get isBackedUp => (flags & _Flags.bs) != 0;

  /// Attested Credential Data (AT) flag.
  bool get hasAttestedCredentialData => (flags & _Flags.at) != 0;

  /// Extension Data (ED) flag.
  bool get hasExtensions => (flags & _Flags.ed) != 0;

  /// Converts the [credentialPublicKey] map to a `webcrypto` public key object.
  ///
  /// Supports ES256, ES384, ES512, RS256, and PS256.
  ///
  /// Returns one of: [EcdsaPublicKey], [RsassaPkcs1V15PublicKey], or [RsaPssPublicKey].
  Future<Object?> toPublicKey() async {
    final key = credentialPublicKey;
    if (key == null) return null;

    final kty = key[_Cose.kty] as int?;
    final alg = key[_Cose.alg] as int?;

    return switch (kty) {
      2 => _parseEcKey(key, alg),
      3 => _parseRsaKey(key, alg),
      _ => throw UnsupportedAlgorithmException('Unsupported key type: $kty'),
    };
  }

  Future<EcdsaPublicKey> _parseEcKey(Map<int, dynamic> key, int? alg) {
    final crv = key[_Cose.crv] as int?;
    final x = key[_Cose.x] as List<int>?;
    final y = key[_Cose.y] as List<int>?;

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
    final n = key[_Cose.n] as List<int>?;
    final e = key[_Cose.e] as List<int>?;

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
      _ => throw UnsupportedAlgorithmException(
        'Unsupported RSA algorithm: $alg',
      ),
    };
  }

  /// Parses the raw binary `authenticatorData`.
  static AuthenticatorData parse(Uint8List data) {
    if (data.length < 37) {
      throw InvalidAuthenticatorDataException(
        'Authenticator data too short (${data.length} bytes)',
      );
    }

    final buffer = data.buffer;
    final byteData = ByteData.view(buffer, data.offsetInBytes, data.length);
    int offset = 0;

    // 1. rpIdHash (32 bytes)
    final rpIdHash = data.sublist(0, 32);
    offset += 32;

    // 2. flags (1 byte)
    final flags = byteData.getUint8(offset);
    offset += 1;

    // 3. signCount (4 bytes)
    final signCount = byteData.getUint32(offset);
    offset += 4;

    Uint8List? aaguid;
    Uint8List? credentialId;
    Map<int, dynamic>? credentialPublicKey;

    // 4. attestedCredentialData (if AT flag set)
    if ((flags & _Flags.at) != 0) {
      if (data.length < offset + 18) {
        throw InvalidAuthenticatorDataException(
          'Insufficient data for attestedCredentialData',
        );
      }

      // aaguid (16 bytes)
      aaguid = data.sublist(offset, offset + 16);
      offset += 16;

      // credentialIdLength (2 bytes)
      final credentialIdLength = byteData.getUint16(offset);
      offset += 2;

      if (data.length < offset + credentialIdLength) {
        throw InvalidAuthenticatorDataException('Credential ID out of bounds');
      }

      // credentialId (L bytes)
      credentialId = data.sublist(offset, offset + credentialIdLength);
      offset += credentialIdLength;

      // credentialPublicKey (CBOR variable length)
      final remaining = data.sublist(offset);
      try {
        final (cborValue, consumed) = decodeOne(remaining);

        if (cborValue is CborMap) {
          final mapObj = cborValue.toObject();
          if (mapObj is Map) {
            credentialPublicKey = mapObj.cast<int, dynamic>();
          } else {
            throw InvalidAuthenticatorDataException(
              'Credential public key is not a CBOR map object',
            );
          }
        } else {
          throw InvalidAuthenticatorDataException(
            'Credential public key is not a CBOR map',
          );
        }

        // Advance offset past the public key
        offset += consumed;
      } on WebAuthnException {
        rethrow;
      } catch (e) {
        throw InvalidAuthenticatorDataException(
          'Failed to decode credential public key: $e',
        );
      }
    }

    // 5. extensions (if ED flag set)
    Map<String, dynamic>? extensions;
    if ((flags & _Flags.ed) != 0) {
      final remaining = data.sublist(offset);
      try {
        final (cborValue, consumed) = decodeOne(remaining);

        if (cborValue is CborMap) {
          final mapObj = cborValue.toObject();
          if (mapObj is Map) {
            extensions = mapObj.cast<String, dynamic>();
          }
        }

        offset += consumed;
      } on WebAuthnException {
        rethrow;
      } catch (e) {
        throw InvalidAuthenticatorDataException(
          'Failed to decode extension data: $e',
        );
      }
    }

    // Security check: Verify no trailing garbage bytes.
    if (offset < data.length) {
      throw InvalidAuthenticatorDataException(
        'Trailing bytes found after authenticator data (${data.length - offset} bytes)',
      );
    }

    return AuthenticatorData(
      rpIdHash: rpIdHash,
      flags: flags,
      signCount: signCount,
      aaguid: aaguid,
      credentialId: credentialId,
      credentialPublicKey: credentialPublicKey,
      extensions: extensions,
    );
  }
}
