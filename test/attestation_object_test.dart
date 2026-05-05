import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:shelf_webauthn/src/helpers/attestation_object.dart';
import 'package:shelf_webauthn/src/helpers/attestation_statement.dart';
import 'package:shelf_webauthn/src/helpers/auth_data.dart';
import 'package:shelf_webauthn/src/exceptions.dart';
import 'package:convert/convert.dart';

import 'vectors.dart';

void main() {
  group('AttestationObject Parsing', () {
    test('parses test vector with "none" attestation', () {
      final vector = testVectors.firstWhere(
        (v) => v.name == 'sctn-test-vectors-none-es256',
      );
      final attestationObjectHex = vector.registration['attestationObject']!;
      final attestationObjectBytes = Uint8List.fromList(
        hex.decode(attestationObjectHex),
      );

      final attObj = AttestationObject.parse(attestationObjectBytes);

      // Verify the format
      expect(attObj.fmt, equals('none'));

      // Verify the attestation statement is empty for "none"
      expect(attObj.attStmt, isEmpty);

      // Verify nested authenticator data properties match the vector
      final expectedAaguidHex = vector.registration['aaguid']!;
      expect(hex.encode(attObj.authData.aaguid!), equals(expectedAaguidHex));

      final expectedCredentialIdHex = vector.registration['credential_id']!;
      expect(
        hex.encode(attObj.authData.credentialId!),
        equals(expectedCredentialIdHex),
      );
    });

    test('throws on invalid CBOR data', () {
      final invalidData = Uint8List.fromList([
        0x01,
        0x02,
        0x03,
      ]); // Not a valid attestation map
      expect(
        () => AttestationObject.parse(invalidData),
        throwsA(isA<InvalidAuthenticatorDataException>()),
      );
    });
  });

  group('NoneAttestationVerifier', () {
    final verifier = NoneAttestationVerifier();
    // A dummy auth data & client data hash since 'none' format ignores them
    final dummyHash = Uint8List(32);

    test('succeeds when attStmt is empty', () async {
      // Create a dummy AuthenticatorData manually or parse a minimal valid one.
      // Since `NoneAttestationVerifier` doesn't actually use authData, we can
      // pass a minimal constructed one.
      final dummyAuthData = AuthenticatorData.parse(Uint8List(37));

      await expectLater(
        verifier.verify({}, dummyAuthData, dummyHash),
        completes,
      );
    });

    test('throws when attStmt is not empty', () async {
      final dummyAuthData = AuthenticatorData.parse(Uint8List(37));
      final invalidAttStmt = {'foo': 'bar'};

      await expectLater(
        verifier.verify(invalidAttStmt, dummyAuthData, dummyHash),
        throwsA(isA<InvalidAuthenticatorDataException>()),
      );
    });
  });
}
