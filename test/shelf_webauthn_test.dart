import 'dart:convert';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:shelf_webauthn/shelf_webauthn.dart';
import 'package:shelf_webauthn/src/exceptions.dart';
import 'package:convert/convert.dart';

import 'vectors.dart';

void main() {
  group('WebAuthnServer.verifyRegistrationResponse', () {
    test('successfully verifies a valid "none" attestation response', () async {
      final server = WebAuthnServer(
        rpId: 'example.org',
        expectedOrigin: 'https://example.org',
      );

      final vector = testVectors.firstWhere(
        (v) => v.name == 'sctn-test-vectors-none-es256',
      );

      // The challenge from the vector
      final expectedChallengeHex = vector.registration['challenge']!;
      final expectedChallengeBytes = hex.decode(expectedChallengeHex);
      final expectedChallengeBase64Url = base64Url
          .encode(expectedChallengeBytes)
          .replaceAll('=', '');

      final clientDataJSONBytes = Uint8List.fromList(
        hex.decode(vector.registration['clientDataJSON']!),
      );

      final attestationObjectBytes = Uint8List.fromList(
        hex.decode(vector.registration['attestationObject']!),
      );

      final response = AuthenticatorAttestationResponse(
        clientDataJSON: clientDataJSONBytes,
        attestationObject: attestationObjectBytes,
      );

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

      final expectedChallengeHex = vector.registration['challenge']!;
      final expectedChallengeBytes = hex.decode(expectedChallengeHex);
      final expectedChallengeBase64Url = base64Url
          .encode(expectedChallengeBytes)
          .replaceAll('=', '');

      final clientDataJSONBytes = Uint8List.fromList(
        hex.decode(vector.registration['clientDataJSON']!),
      );

      final attestationObjectBytes = Uint8List.fromList(
        hex.decode(vector.registration['attestationObject']!),
      );

      final response = AuthenticatorAttestationResponse(
        clientDataJSON: clientDataJSONBytes,
        attestationObject: attestationObjectBytes,
      );

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
