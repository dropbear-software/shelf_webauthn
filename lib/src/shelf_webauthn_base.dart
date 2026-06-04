import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:collection/collection.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:cbor/cbor.dart';
import 'package:webcrypto/webcrypto.dart';
import 'models/models.dart';
import 'helpers/auth_data.dart';
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

  /// The registry of attestation statement verifiers mapped by their format identifier.
  final Map<String, AttestationStatementVerifier> attestationVerifiers;

  WebAuthnServer({
    required this.rpId,
    required this.expectedOrigin,
    Map<String, AttestationStatementVerifier>? attestationVerifiers,
  }) : attestationVerifiers =
           attestationVerifiers ?? {'none': NoneAttestationVerifier()};

  // --- Phase 1: Registration ---

  /// Generates the options required by the client to create a new credential.
  PublicKeyCredentialCreationOptions generateRegistrationOptions({
    required String userId,
    required String username,
    String? userDisplayName,
    int? timeout,
    List<PubKeyCredParam>? pubKeyCredParams,
    List<String>? excludeCredentials,
    AuthenticatorSelectionCriteria? authenticatorSelection,
    String? attestation,
    Map<String, dynamic>? extensions,
  }) {
    final random = Random.secure();
    final challengeBytes = Uint8List.fromList(
      List<int>.generate(32, (_) => random.nextInt(256)),
    );
    final challenge = base64Url.encode(challengeBytes).replaceAll('=', '');

    return PublicKeyCredentialCreationOptions(
      rp: RelyingPartyEntity(
        id: rpId,
        name: rpId, // Defaulting name to rpId, can be expanded later
      ),
      user: UserEntity(
        id: userId,
        name: username,
        displayName: userDisplayName ?? username,
      ),
      challenge: challenge,
      pubKeyCredParams:
          pubKeyCredParams ??
          const [
            // ES256
            PubKeyCredParam(alg: -7),
            // RS256
            PubKeyCredParam(alg: -257),
          ],
      timeout: timeout,
      excludeCredentials: excludeCredentials,
      authenticatorSelection: authenticatorSelection,
      attestation: attestation,
      extensions: extensions,
    );
  }

  /// Verifies an attestation response received from a client during registration.
  Future<CredentialRecord> verifyRegistrationResponse({
    required AuthenticatorAttestationResponse response,
    required String expectedChallenge,
    required List<int> userHandle,
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
    final verifier = attestationVerifiers[attObj.fmt];
    if (verifier == null) {
      throw UnsupportedAlgorithmException(
        'Unsupported attestation format: ${attObj.fmt}',
      );
    }
    await verifier.verify(attObj.attStmt, authData, clientDataHash);

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
      userHandle: userHandle,
      attestationObject: response.attestationObject,
      attestationClientDataJSON: response.clientDataJSON,
    );
  }

  // --- Phase 2: Authentication ---

  /// Generates the options required by the client to request an assertion.
  PublicKeyCredentialRequestOptions generateAuthenticationOptions({
    int? timeout,
    List<PublicKeyCredentialDescriptor>? allowCredentials,
    String? userVerification,
    Map<String, dynamic>? extensions,
  }) {
    final random = Random.secure();
    final challengeBytes = Uint8List.fromList(
      List<int>.generate(32, (_) => random.nextInt(256)),
    );
    final challenge = base64Url.encode(challengeBytes).replaceAll('=', '');

    return PublicKeyCredentialRequestOptions(
      challenge: challenge,
      timeout: timeout,
      rpId: rpId,
      allowCredentials: allowCredentials,
      userVerification: userVerification,
      extensions: extensions,
    );
  }

  /// Verifies an assertion response received from a client during authentication.
  Future<VerificationResult> verifyAuthenticationResponse({
    required AuthenticatorAssertionResponse response,
    required String expectedChallenge,
    required CredentialRecord storedCredential,
    bool requireUserVerification = false,
  }) async {
    // 6: Verify userHandle matches stored credential userHandle if present in assertion response
    if (response.userHandle != null) {
      if (!const ListEquality().equals(
        response.userHandle,
        storedCredential.userHandle,
      )) {
        throw WebAuthnException(
          'User handle mismatch: owner does not match assertion userHandle',
        );
      }
    }

    // 7-10: Parse and verify clientDataJSON
    final clientData = CollectedClientData.parse(response.clientDataJSON);

    final expectedChallengeBytes = base64Url.decode(
      base64Url.normalize(expectedChallenge),
    );
    clientData.verify(
      expectedType: ClientDataType.get,
      expectedChallenge: expectedChallengeBytes,
      expectedOrigin: expectedOrigin,
    );

    // 14: Parse and verify authenticatorData
    final authData = AuthenticatorData.parse(response.authenticatorData);

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

    // 18: Verify backup state changes against the storedCredential.
    // Spec allows RP policy to reject if BE changes unexpectedly, but we'll
    // simply log or accept the new state for now.
    if (storedCredential.backupEligible && !authData.isBackupEligible) {
      // A previously backup eligible credential is no longer backup eligible.
      // This is unusual but technically possible.
    }

    // 19: Compute clientDataHash
    final clientDataHash = Uint8List.fromList(
      crypto.sha256.convert(response.clientDataJSON).bytes,
    );

    // 20: Signature Verification
    final concatData = Uint8List.fromList([
      ...response.authenticatorData,
      ...clientDataHash,
    ]);

    // Parse the stored CBOR public key map
    final cborValue = cbor.decode(storedCredential.publicKey);
    if (cborValue is! CborMap) {
      throw WebAuthnException('Stored public key is not a valid CBOR map');
    }

    final mapObj = cborValue.toObject();
    if (mapObj is! Map) {
      throw WebAuthnException('Stored public key map is invalid');
    }
    final credentialPublicKeyMap = mapObj.cast<int, dynamic>();

    // Reconstruct the WebCrypto public key object
    final publicKey = await parseCosePublicKey(credentialPublicKeyMap);
    if (publicKey == null) {
      throw WebAuthnException('Failed to parse stored public key');
    }

    bool signatureValid = false;
    try {
      signatureValid = await switch (publicKey) {
        EcdsaWebAuthnPublicKey(key: final ecdsaKey, alg: final alg) =>
          () async {
            final int curveSizeBytes = switch (alg) {
              -7 => 32,
              -35 => 48,
              -36 => 66,
              _ => throw WebAuthnException(
                'Unsupported ECDSA alg for signature conversion: $alg',
              ),
            };

            final rawSignature = convertDerToRawEcdsaSignature(
              response.signature,
              curveSizeBytes,
            );

            return await ecdsaKey.verifyBytes(
              rawSignature,
              concatData,
              Hash.sha256,
            );
          }(),
        RsassaPkcs1V15WebAuthnPublicKey(key: final rsaKey) =>
          rsaKey.verifyBytes(response.signature, concatData),
        RsaPssWebAuthnPublicKey(key: final rsaKey) => rsaKey.verifyBytes(
          response.signature,
          concatData,
          32, // saltLength for PS256 is equal to the hash length (32 bytes)
        ),
      };
    } catch (e) {
      throw WebAuthnException('Signature verification failed: $e');
    }

    if (!signatureValid) {
      throw WebAuthnException('Invalid signature');
    }

    // 21: Verify signCount
    if (authData.signCount != 0 || storedCredential.signCount != 0) {
      if (authData.signCount <= storedCredential.signCount) {
        throw WebAuthnException(
          'Signature counter is not strictly strictly greater than the stored counter. '
          'Potential cloned authenticator detected.',
        );
      }
    }

    // 24: Return successful VerificationResult
    return VerificationResult(
      success: true,
      updatedSignCount: authData.signCount,
    );
  }
}
