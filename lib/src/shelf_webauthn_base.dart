import 'dart:convert';
import 'dart:typed_data';
import 'package:collection/collection.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:cbor/cbor.dart';
import 'models/models.dart';
import 'helpers/client_data.dart';
import 'helpers/attestation_object.dart';
import 'helpers/attestation_statement.dart';
import 'helpers/cose.dart';
import 'exceptions.dart';

// ---------------------------------------------------------------------------
// Core Server Class
// ---------------------------------------------------------------------------

/// The core entry point for performing WebAuthn Relying Party operations.
class WebAuthnServer {
  /// The Relying Party ID (usually the domain name, e.g., "example.com").
  final String rpId;

  /// The expected origin of the client (e.g., "https://example.com").
  final String expectedOrigin;

  WebAuthnServer({required this.rpId, required this.expectedOrigin});

  // --- Phase 1: Registration ---

  /// Generates the options required by the client to create a new credential.
  PublicKeyCredentialCreationOptions generateRegistrationOptions({
    required String userId,
    required String username,
  }) {
    // TODO: Implement secure random challenge generation and build options
    throw UnimplementedError('Registration generation is not yet implemented.');
  }

  /// Verifies an attestation response received from a client during registration.
  Future<CredentialRecord> verifyRegistrationResponse({
    required AuthenticatorAttestationResponse response,
    required String expectedChallenge,
    bool requireUserVerification = false,
    List<int>? allowedAlgs,
    Future<bool> Function(Uint8List credentialId)? existingCredentialCheck,
  }) async {
    // 5-6: Parse clientDataJSON
    final clientData = CollectedClientData.parse(response.clientDataJSON);

    // 7-11: Verify clientDataJSON
    final expectedChallengeBytes = base64Url.decode(
      base64Url.normalize(expectedChallenge),
    );
    clientData.verify(
      expectedType: ClientDataType.create,
      expectedChallenge: expectedChallengeBytes,
      expectedOrigin: expectedOrigin,
    );

    // 12: Hash clientDataJSON
    final clientDataHash = Uint8List.fromList(
      crypto.sha256.convert(response.clientDataJSON).bytes,
    );

    // 13: Parse attestationObject
    final attObj = AttestationObject.parse(response.attestationObject);
    final authData = attObj.authData;

    // 14: Verify rpIdHash
    final expectedRpIdHash = Uint8List.fromList(
      crypto.sha256.convert(utf8.encode(rpId)).bytes,
    );
    if (!const ListEquality().equals(authData.rpIdHash, expectedRpIdHash)) {
      throw InvalidAuthenticatorDataException('rpIdHash mismatch');
    }

    // 15: Verify UP bit
    if (!authData.isUserPresent) {
      throw InvalidAuthenticatorDataException(
        'User Presence (UP) flag not set',
      );
    }

    // 16: Verify UV bit if required
    if (requireUserVerification && !authData.isUserVerified) {
      throw InvalidAuthenticatorDataException(
        'User Verification (UV) flag not set but required',
      );
    }

    // 17: Backup Eligibility and State logic
    if (!authData.isBackupEligible && authData.isBackedUp) {
      throw InvalidAuthenticatorDataException(
        'Backup State (BS) is set but Backup Eligibility (BE) is not',
      );
    }

    // 20: Verify alg
    final credentialPublicKey = authData.credentialPublicKey;
    if (credentialPublicKey == null) {
      throw InvalidAuthenticatorDataException('Missing credentialPublicKey');
    }

    final alg = credentialPublicKey[Cose.alg] as int?;
    if (alg == null) {
      throw InvalidAuthenticatorDataException(
        'Missing alg in credentialPublicKey',
      );
    }

    if (allowedAlgs != null && !allowedAlgs.contains(alg)) {
      throw InvalidAuthenticatorDataException('Algorithm $alg is not allowed');
    }

    // 21-24: Attestation validation
    if (attObj.fmt == 'none') {
      final verifier = NoneAttestationVerifier();
      await verifier.verify(attObj.attStmt, authData, clientDataHash);
    } else {
      throw WebAuthnException('Unsupported attestation format: ${attObj.fmt}');
    }

    // 25: Verify credentialId length <= 1023
    final credentialId = authData.credentialId;
    if (credentialId == null) {
      throw InvalidAuthenticatorDataException('Missing credentialId');
    }
    if (credentialId.length > 1023) {
      throw InvalidAuthenticatorDataException(
        'credentialId is larger than 1023 bytes',
      );
    }

    // 26: Check if credentialId is already registered
    if (existingCredentialCheck != null) {
      final isRegistered = await existingCredentialCheck(credentialId);
      if (isRegistered) {
        throw WebAuthnException('Credential ID is already registered');
      }
    }

    // 27: Construct CredentialRecord
    final cborMap = CborMap({
      for (final entry in credentialPublicKey.entries)
        CborValue(entry.key): CborValue(entry.value),
    });
    final publicKeyBytes = cbor.encode(cborMap);

    return CredentialRecord(
      credentialType: 'public-key',
      credentialId: base64Url.encode(credentialId).replaceAll('=', ''),
      publicKey: publicKeyBytes,
      signCount: authData.signCount,
      uvInitialized: authData.isUserVerified,
      transports: response.transports,
      backupEligible: authData.isBackupEligible,
      backupState: authData.isBackedUp,
      attestationObject: response.attestationObject,
      attestationClientDataJSON: response.clientDataJSON,
    );
  }

  // --- Phase 2: Authentication ---

  /// Generates the options required by the client to request an assertion.
  PublicKeyCredentialRequestOptions generateAuthenticationOptions({
    String? username,
  }) {
    // TODO: Implement secure random challenge generation and build options
    throw UnimplementedError(
      'Authentication generation is not yet implemented.',
    );
  }

  /// Verifies an assertion response received from a client during authentication.
  Future<VerificationResult> verifyAuthenticationResponse({
    required AuthenticatorAssertionResponse response,
    required String expectedChallenge,
    required CredentialRecord storedCredential,
  }) async {
    // TODO: Implement Section 7.2 of the WebAuthn spec
    throw UnimplementedError(
      'Authentication verification is not yet implemented.',
    );
  }
}
