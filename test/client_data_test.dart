import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:test/test.dart';
import 'package:shelf_webauthn/src/helpers/client_data.dart';
import 'package:shelf_webauthn/src/exceptions.dart';
import 'vectors.dart';

void main() {
  group('CollectedClientData', () {
    test('Parses registration clientDataJSON from test vector', () {
      final vector = testVectors.firstWhere(
        (v) => v.name == 'sctn-test-vectors-none-es256',
      );
      final clientDataHex = vector.registration['clientDataJSON']!;
      final clientDataBytes = Uint8List.fromList(hex.decode(clientDataHex));

      final clientData = CollectedClientData.parse(clientDataBytes);

      expect(clientData.type, equals(ClientDataType.create));
      expect(clientData.origin.toString(), equals('https://example.org'));
      expect(clientData.crossOrigin, isFalse);
      expect(clientData.rawData['extraData'], isNotNull);

      // Verify validation logic
      final expectedChallenge = hex.decode(vector.registration['challenge']!);
      clientData.verify(
        expectedType: ClientDataType.create,
        expectedChallenge: expectedChallenge,
        expectedOrigin: 'https://example.org',
      );
    });

    test('Parses authentication clientDataJSON from test vector', () {
      final vector = testVectors.firstWhere(
        (v) => v.name == 'sctn-test-vectors-none-es256',
      );
      final clientDataHex = vector.authentication['clientDataJSON']!;
      final clientDataBytes = Uint8List.fromList(hex.decode(clientDataHex));

      final clientData = CollectedClientData.parse(clientDataBytes);

      expect(clientData.type, equals(ClientDataType.get));
      expect(clientData.origin.toString(), equals('https://example.org'));

      // Verify validation logic
      final expectedChallenge = hex.decode(vector.authentication['challenge']!);
      clientData.verify(
        expectedType: ClientDataType.get,
        expectedChallenge: expectedChallenge,
        expectedOrigin: 'https://example.org',
      );
    });

    test('Throws on missing required fields', () {
      final invalidJson = '{"type":"webauthn.create"}';
      final bytes = Uint8List.fromList(invalidJson.codeUnits);

      expect(
        () => CollectedClientData.parse(bytes),
        throwsA(isA<InvalidAuthenticatorDataException>()),
      );
    });

    test('Throws on challenge mismatch', () {
      final vector = testVectors.firstWhere(
        (v) => v.name == 'sctn-test-vectors-none-es256',
      );
      final clientDataHex = vector.authentication['clientDataJSON']!;
      final clientData = CollectedClientData.parse(
        Uint8List.fromList(hex.decode(clientDataHex)),
      );

      expect(
        () => clientData.verify(
          expectedType: ClientDataType.get,
          expectedChallenge: [0, 0, 0],
          expectedOrigin: 'https://example.org',
        ),
        throwsA(isA<InvalidAuthenticatorDataException>()),
      );
    });
  });
}
