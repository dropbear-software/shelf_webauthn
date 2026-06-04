import 'dart:convert';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:shelf_webauthn/shelf_webauthn.dart';
import 'package:shelf_webauthn/src/exceptions.dart';
import 'package:convert/convert.dart';

import 'vectors.dart';

String getChallengeFromVector(Map<String, String> data) {
  final expectedChallengeHex = data['challenge']!;
  final expectedChallengeBytes = hex.decode(expectedChallengeHex);
  return base64Url.encode(expectedChallengeBytes).replaceAll('=', '');
}

AuthenticatorAttestationResponse buildRegistrationResponse(
  Map<String, String> data,
) {
  final clientDataJSONBytes = Uint8List.fromList(
    hex.decode(data['clientDataJSON']!),
  );

  final attestationObjectBytes = Uint8List.fromList(
    hex.decode(data['attestationObject']!),
  );

  return AuthenticatorAttestationResponse(
    clientDataJSON: clientDataJSONBytes,
    attestationObject: attestationObjectBytes,
  );
}

AuthenticatorAssertionResponse buildAuthenticationResponse(
  Map<String, String> data,
) {
  final clientDataJSONBytes = Uint8List.fromList(
    hex.decode(data['clientDataJSON']!),
  );

  final authenticatorDataBytes = Uint8List.fromList(
    hex.decode(data['authenticatorData']!),
  );

  final signatureBytes = Uint8List.fromList(hex.decode(data['signature']!));

  return AuthenticatorAssertionResponse(
    clientDataJSON: clientDataJSONBytes,
    authenticatorData: authenticatorDataBytes,
    signature: signatureBytes,
  );
}

class MockAttestationVerifier extends AttestationStatementVerifier {
  bool verified = false;

  @override
  Future<void> verify(
    Map<String, dynamic> attStmt,
    AuthenticatorData authData,
    Uint8List clientDataHash,
  ) async {
    verified = true;
  }
}

void main() {
  group('WebAuthnServer.generateRegistrationOptions', () {
    test('generates valid options with secure challenge', () {
      final server = WebAuthnServer(
        rpId: 'example.org',
        expectedOrigin: 'https://example.org',
      );

      final options = server.generateRegistrationOptions(
        userId: 'user-123',
        username: 'alice',
        userDisplayName: 'Alice Smith',
      );

      expect(options.rp.id, equals('example.org'));
      expect(options.rp.name, equals('example.org'));

      expect(options.user.id, equals('user-123'));
      expect(options.user.name, equals('alice'));
      expect(options.user.displayName, equals('Alice Smith'));

      // Challenge must be base64url encoded and at least 16 bytes
      expect(options.challenge, isNotEmpty);
      final challengeBytes = base64Url.decode(
        base64Url.normalize(options.challenge),
      );
      expect(challengeBytes.length, greaterThanOrEqualTo(16));
      expect(options.challenge.contains('='), isFalse); // No padding

      // Default pubKeyCredParams
      expect(options.pubKeyCredParams.length, equals(2));
      expect(options.pubKeyCredParams[0].alg, equals(-7)); // ES256
      expect(options.pubKeyCredParams[1].alg, equals(-257)); // RS256
    });
  });

  group('WebAuthnServer.generateAuthenticationOptions', () {
    test('generates valid options with secure challenge', () {
      final server = WebAuthnServer(
        rpId: 'example.org',
        expectedOrigin: 'https://example.org',
      );

      final options = server.generateAuthenticationOptions(
        timeout: 60000,
        userVerification: 'required',
      );

      expect(options.rpId, equals('example.org'));
      expect(options.timeout, equals(60000));
      expect(options.userVerification, equals('required'));

      // Challenge must be base64url encoded and at least 16 bytes
      expect(options.challenge, isNotEmpty);
      final challengeBytes = base64Url.decode(
        base64Url.normalize(options.challenge),
      );
      expect(challengeBytes.length, greaterThanOrEqualTo(16));
      expect(options.challenge.contains('='), isFalse); // No padding
    });
  });

  group('WebAuthnServer.verifyRegistrationResponse', () {
    test('successfully verifies a valid "none" attestation response', () async {
      final server = WebAuthnServer(
        rpId: 'example.org',
        expectedOrigin: 'https://example.org',
      );

      final vector = testVectors.firstWhere(
        (v) => v.name == 'sctn-test-vectors-none-es256',
      );

      final expectedChallengeBase64Url = getChallengeFromVector(
        vector.registration,
      );
      final response = buildRegistrationResponse(vector.registration);

      final credentialRecord = await server.verifyRegistrationResponse(
        response: response,
        expectedChallenge: expectedChallengeBase64Url,
        userHandle: Uint8List.fromList([1, 2, 3, 4]),
      );

      expect(credentialRecord.credentialType, equals('public-key'));

      final expectedCredentialIdHex = vector.registration['credential_id']!;
      final actualCredentialIdHex = hex.encode(
        base64Url.decode(base64Url.normalize(credentialRecord.credentialId)),
      );
      expect(actualCredentialIdHex, equals(expectedCredentialIdHex));

      expect(credentialRecord.signCount, equals(0));
      expect(credentialRecord.backupEligible, isTrue);
      expect(credentialRecord.backupState, isTrue);
    });

    test('throws when origin is invalid', () async {
      final server = WebAuthnServer(
        rpId: 'example.org',
        expectedOrigin: 'https://invalid-origin.com',
      );

      final vector = testVectors.firstWhere(
        (v) => v.name == 'sctn-test-vectors-none-es256',
      );

      final expectedChallengeBase64Url = getChallengeFromVector(
        vector.registration,
      );
      final response = buildRegistrationResponse(vector.registration);

      await expectLater(
        server.verifyRegistrationResponse(
          response: response,
          expectedChallenge: expectedChallengeBase64Url,
          userHandle: Uint8List.fromList([1, 2, 3, 4]),
        ),
        throwsA(isA<InvalidAuthenticatorDataException>()),
      );
    });

    test(
      'uses registered custom attestation verifier for none format',
      () async {
        final mockVerifier = MockAttestationVerifier();
        final server = WebAuthnServer(
          rpId: 'example.org',
          expectedOrigin: 'https://example.org',
          attestationVerifiers: {'none': mockVerifier},
        );

        final vector = testVectors.firstWhere(
          (v) => v.name == 'sctn-test-vectors-none-es256',
        );

        final expectedChallengeBase64Url = getChallengeFromVector(
          vector.registration,
        );
        final response = buildRegistrationResponse(vector.registration);

        await server.verifyRegistrationResponse(
          response: response,
          expectedChallenge: expectedChallengeBase64Url,
          userHandle: Uint8List.fromList([1, 2, 3, 4]),
        );

        expect(mockVerifier.verified, isTrue);
      },
    );

    test(
      'throws UnsupportedAlgorithmException when attestation format has no verifier',
      () async {
        final server = WebAuthnServer(
          rpId: 'example.org',
          expectedOrigin: 'https://example.org',
          attestationVerifiers: {}, // empty registry
        );

        final vector = testVectors.firstWhere(
          (v) => v.name == 'sctn-test-vectors-none-es256',
        );

        final expectedChallengeBase64Url = getChallengeFromVector(
          vector.registration,
        );
        final response = buildRegistrationResponse(vector.registration);

        await expectLater(
          server.verifyRegistrationResponse(
            response: response,
            expectedChallenge: expectedChallengeBase64Url,
            userHandle: Uint8List.fromList([1, 2, 3, 4]),
          ),
          throwsA(isA<UnsupportedAlgorithmException>()),
        );
      },
    );
  });

  group('WebAuthnServer.verifyAuthenticationResponse', () {
    test('successfully verifies a valid assertion response', () async {
      final server = WebAuthnServer(
        rpId: 'example.org',
        expectedOrigin: 'https://example.org',
      );

      final vector = testVectors.firstWhere(
        (v) => v.name == 'sctn-test-vectors-none-es256',
      );

      // First, get the stored credential from the registration phase
      final expectedRegChallengeBase64Url = getChallengeFromVector(
        vector.registration,
      );
      final regResponse = buildRegistrationResponse(vector.registration);
      final storedCredential = await server.verifyRegistrationResponse(
        response: regResponse,
        expectedChallenge: expectedRegChallengeBase64Url,
        userHandle: Uint8List.fromList([1, 2, 3, 4]),
      );

      // Now verify the authentication phase
      final expectedAuthChallengeBase64Url = getChallengeFromVector(
        vector.authentication,
      );
      final authResponse = buildAuthenticationResponse(vector.authentication);

      final result = await server.verifyAuthenticationResponse(
        response: authResponse,
        expectedChallenge: expectedAuthChallengeBase64Url,
        storedCredential: storedCredential,
      );

      expect(result.success, isTrue);
      expect(result.updatedSignCount, equals(0));
    });

    test('throws when signature is invalid', () async {
      final server = WebAuthnServer(
        rpId: 'example.org',
        expectedOrigin: 'https://example.org',
      );

      final vector = testVectors.firstWhere(
        (v) => v.name == 'sctn-test-vectors-none-es256',
      );

      final expectedRegChallengeBase64Url = getChallengeFromVector(
        vector.registration,
      );
      final regResponse = buildRegistrationResponse(vector.registration);
      final storedCredential = await server.verifyRegistrationResponse(
        response: regResponse,
        expectedChallenge: expectedRegChallengeBase64Url,
        userHandle: Uint8List.fromList([1, 2, 3, 4]),
      );

      final expectedAuthChallengeBase64Url = getChallengeFromVector(
        vector.authentication,
      );
      final authResponse = buildAuthenticationResponse(vector.authentication);

      // Tamper with the signature
      final badSignature = Uint8List.fromList(authResponse.signature);
      badSignature[0] ^= 0xFF; // Flip some bits

      final badResponse = AuthenticatorAssertionResponse(
        clientDataJSON: authResponse.clientDataJSON,
        authenticatorData: authResponse.authenticatorData,
        signature: badSignature,
      );

      await expectLater(
        server.verifyAuthenticationResponse(
          response: badResponse,
          expectedChallenge: expectedAuthChallengeBase64Url,
          storedCredential: storedCredential,
        ),
        throwsA(isA<WebAuthnException>()),
      );
    });

    test(
      'throws when userHandle is present but mismatch stored credential userHandle',
      () async {
        final server = WebAuthnServer(
          rpId: 'example.org',
          expectedOrigin: 'https://example.org',
        );

        final vector = testVectors.firstWhere(
          (v) => v.name == 'sctn-test-vectors-none-es256',
        );

        final expectedRegChallengeBase64Url = getChallengeFromVector(
          vector.registration,
        );
        final regResponse = buildRegistrationResponse(vector.registration);
        final storedCredential = await server.verifyRegistrationResponse(
          response: regResponse,
          expectedChallenge: expectedRegChallengeBase64Url,
          userHandle: Uint8List.fromList([1, 2, 3, 4]),
        );

        final authResponse = buildAuthenticationResponse(vector.authentication);
        final badAuthResponse = AuthenticatorAssertionResponse(
          clientDataJSON: authResponse.clientDataJSON,
          authenticatorData: authResponse.authenticatorData,
          signature: authResponse.signature,
          userHandle: Uint8List.fromList([5, 6, 7, 8]),
        );

        await expectLater(
          server.verifyAuthenticationResponse(
            response: badAuthResponse,
            expectedChallenge: getChallengeFromVector(vector.authentication),
            storedCredential: storedCredential,
          ),
          throwsA(
            isA<WebAuthnException>().having(
              (e) => e.message,
              'message',
              contains('User handle mismatch'),
            ),
          ),
        );
      },
    );
  });
}
