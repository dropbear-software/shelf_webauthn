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
        ),
        throwsA(isA<InvalidAuthenticatorDataException>()),
      );
    });
  });
}
