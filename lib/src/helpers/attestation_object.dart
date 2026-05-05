import 'dart:typed_data';
import 'package:cbor/cbor.dart';
import '../exceptions.dart';
import 'auth_data.dart';
import 'cbor_utils.dart';

/// Represents the decoded `attestationObject` from an [AuthenticatorAttestationResponse].
///
/// The attestation object contains both the authenticator data and the
/// attestation statement that provides cryptographic proof of the credential's provenance.
class AttestationObject {
  /// The attestation statement format identifier (e.g., "none", "packed", "fido-u2f").
  final String fmt;

  /// The parsed authenticator data.
  final AuthenticatorData authData;

  /// The raw, unparsed attestation statement.
  ///
  /// Its structure depends on the value of [fmt].
  final Map<String, dynamic> attStmt;

  AttestationObject({
    required this.fmt,
    required this.authData,
    required this.attStmt,
  });

  /// Decodes and parses a raw `attestationObject` CBOR payload.
  static AttestationObject parse(Uint8List data) {
    CborValue cborValue;
    try {
      final decoded = decodeOne(data);
      cborValue = decoded.value;

      if (decoded.consumed != data.length) {
        throw InvalidAuthenticatorDataException(
          'Trailing bytes after attestationObject',
        );
      }
    } on WebAuthnException {
      rethrow;
    } catch (e) {
      throw InvalidAuthenticatorDataException(
        'Failed to decode attestationObject CBOR: $e',
      );
    }

    if (cborValue is! CborMap) {
      throw InvalidAuthenticatorDataException(
        'attestationObject must be a CBOR map',
      );
    }

    final mapObj = cborValue.toObject();
    if (mapObj is! Map) {
      throw InvalidAuthenticatorDataException(
        'attestationObject must decode to a map',
      );
    }

    final map = mapObj.cast<String, dynamic>();

    // Extract 'fmt'
    final fmtRaw = map['fmt'];
    if (fmtRaw is! String) {
      throw InvalidAuthenticatorDataException(
        'attestationObject missing or invalid "fmt" field',
      );
    }

    // Extract 'authData'
    final authDataRaw = map['authData'];
    if (authDataRaw is! List<int>) {
      throw InvalidAuthenticatorDataException(
        'attestationObject missing or invalid "authData" field',
      );
    }

    AuthenticatorData authData;
    try {
      final authDataBytes = authDataRaw is Uint8List
          ? authDataRaw
          : Uint8List.fromList(authDataRaw);
      authData = AuthenticatorData.parse(authDataBytes);
    } catch (e) {
      throw InvalidAuthenticatorDataException(
        'Failed to parse authData within attestationObject: $e',
      );
    }

    // Extract 'attStmt'
    final attStmtRaw = map['attStmt'];
    if (attStmtRaw is! Map) {
      throw InvalidAuthenticatorDataException(
        'attestationObject missing or invalid "attStmt" field',
      );
    }

    return AttestationObject(
      fmt: fmtRaw,
      authData: authData,
      attStmt: attStmtRaw.cast<String, dynamic>(),
    );
  }
}
