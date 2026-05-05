import 'dart:typed_data';
import '../exceptions.dart';
import 'auth_data.dart';

/// Base class for verifying different attestation statement formats.
///
/// See Section 8 (Defined Attestation Statement Formats) of the WebAuthn specification.
abstract class AttestationStatementVerifier {
  /// Verifies the attestation statement.
  ///
  /// Throws a [WebAuthnException] (such as [InvalidAuthenticatorDataException])
  /// if verification fails. Completes successfully if the attestation is valid.
  ///
  /// - [attStmt]: The decoded CBOR map containing the attestation statement.
  /// - [authData]: The parsed authenticator data.
  /// - [clientDataHash]: The SHA-256 hash of the serialized clientDataJSON.
  Future<void> verify(
    Map<String, dynamic> attStmt,
    AuthenticatorData authData,
    Uint8List clientDataHash,
  );
}

/// Verifier for the "none" attestation statement format.
///
/// See Section 8.7 (None Attestation Statement Format) of the WebAuthn specification.
class NoneAttestationVerifier extends AttestationStatementVerifier {
  @override
  Future<void> verify(
    Map<String, dynamic> attStmt,
    AuthenticatorData authData,
    Uint8List clientDataHash,
  ) async {
    // The "none" format MUST have an empty attStmt.
    if (attStmt.isNotEmpty) {
      throw InvalidAuthenticatorDataException(
        'Attestation statement for "none" format must be empty',
      );
    }
  }
}
