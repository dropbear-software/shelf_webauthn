import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:test/test.dart';
import 'package:shelf_webauthn/src/helpers/auth_data.dart';
import 'package:cbor/cbor.dart';
import 'package:webcrypto/webcrypto.dart';
import 'vectors.dart';

void main() {
  group('AuthenticatorData.parse', () {
    test('Parses assertion authenticatorData from test vector', () {
      final vector = testVectors.firstWhere(
        (v) => v.name == 'sctn-test-vectors-none-es256',
      );
      final authDataHex = vector.authentication['authenticatorData']!;
      final authDataBytes = Uint8List.fromList(hex.decode(authDataHex));

      final authData = AuthenticatorData.parse(authDataBytes);

      expect(authData.flags, equals(0x19));
      expect(authData.isUserPresent, isTrue);
      expect(authData.isUserVerified, isFalse);
      expect(authData.isBackupEligible, isTrue);
      expect(authData.isBackedUp, isTrue);
      expect(authData.hasAttestedCredentialData, isFalse);
      expect(authData.hasExtensions, isFalse);
      expect(authData.signCount, equals(0));
    });

    test('Parses attestation authData and imports public key', () async {
      final vector = testVectors.firstWhere(
        (v) => v.name == 'sctn-test-vectors-none-es256',
      );
      final attestationObjectHex = vector.registration['attestationObject']!;
      final attestationObjectBytes = Uint8List.fromList(
        hex.decode(attestationObjectHex),
      );

      final decoded = cbor.decode(attestationObjectBytes) as CborMap;
      final map = decoded.toObject() as Map;
      final authDataBytes = map['authData'] as List<int>;

      final authData = AuthenticatorData.parse(
        Uint8List.fromList(authDataBytes),
      );

      expect(authData.hasAttestedCredentialData, isTrue);

      // Verify Public Key import
      final publicKey = await authData.toPublicKey();
      expect(publicKey, isA<EcdsaPublicKey>());

      final ecdsaKey = publicKey as EcdsaPublicKey;
      final jwk = await ecdsaKey.exportJsonWebKey();
      expect(jwk['kty'], equals('EC'));
      expect(jwk['crv'], equals('P-256'));
      // alg might be null depending on implementation
    });

    test('Parses RSA attestation authData and imports public key', () async {
      final vector = testVectors.firstWhere(
        (v) => v.name == 'sctn-test-vectors-packed-rs256',
      );
      final attestationObjectHex = vector.registration['attestationObject']!;
      final attestationObjectBytes = Uint8List.fromList(
        hex.decode(attestationObjectHex),
      );

      final decoded = cbor.decode(attestationObjectBytes) as CborMap;
      final map = decoded.toObject() as Map;
      final authDataBytes = map['authData'] as List<int>;

      final authData = AuthenticatorData.parse(
        Uint8List.fromList(authDataBytes),
      );

      expect(authData.hasAttestedCredentialData, isTrue);

      // Verify Public Key import
      final publicKey = await authData.toPublicKey();
      expect(publicKey, isA<RsassaPkcs1V15PublicKey>());

      final rsaKey = publicKey as RsassaPkcs1V15PublicKey;
      final jwk = await rsaKey.exportJsonWebKey();
      expect(jwk['kty'], equals('RSA'));
      expect(jwk['alg'], equals('RS256'));
    });
  });
}
