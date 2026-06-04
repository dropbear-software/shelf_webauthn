import 'dart:collection';
import 'dart:typed_data';
import 'package:cbor/cbor.dart';
import '../exceptions.dart';
import 'cbor_utils.dart';
import 'cose.dart';

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

  /// Converts the [credentialPublicKey] map to a [WebAuthnPublicKey] object.
  ///
  /// Supports ES256, ES384, ES512, RS256, and PS256.
  Future<WebAuthnPublicKey?> toPublicKey() async {
    return parseCosePublicKey(credentialPublicKey);
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
        final decoded = decodeOne(remaining);
        final cborValue = decoded.value;
        final consumed = decoded.consumed;

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
        final decoded = decodeOne(remaining);
        final cborValue = decoded.value;
        final consumed = decoded.consumed;

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
