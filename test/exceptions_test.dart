import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:shelf_webauthn/src/helpers/auth_data.dart';
import 'package:shelf_webauthn/src/exceptions.dart';

void main() {
  group('WebAuthn Exceptions', () {
    test('parse throws InvalidAuthenticatorDataException for short data', () {
      final shortData = Uint8List(36);
      expect(
        () => AuthenticatorData.parse(shortData),
        throwsA(isA<InvalidAuthenticatorDataException>()),
      );
    });

    test(
      'toPublicKey throws UnsupportedAlgorithmException for unknown kty',
      () async {
        final authData = AuthenticatorData(
          rpIdHash: Uint8List(32),
          flags: 0x40, // AT flag set
          signCount: 0,
          credentialPublicKey: {1: 99}, // kty: 99 (unknown)
        );

        expect(
          () => authData.toPublicKey(),
          throwsA(isA<UnsupportedAlgorithmException>()),
        );
      },
    );
  });
}
