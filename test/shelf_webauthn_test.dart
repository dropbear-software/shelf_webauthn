import 'package:shelf_webauthn/shelf_webauthn.dart';
import 'package:test/test.dart';

void main() {
  group('WebAuthnServer Initialization', () {
    test('Can instantiate WebAuthnServer', () {
      final server = WebAuthnServer(
        rpId: 'localhost',
        expectedOrigin: 'http://localhost:8080',
      );

      expect(server.rpId, equals('localhost'));
      expect(server.expectedOrigin, equals('http://localhost:8080'));
    });

    test('Throws UnimplementedError on method calls', () {
      final server = WebAuthnServer(
        rpId: 'localhost',
        expectedOrigin: 'http://localhost:8080',
      );

      expect(
        () => server.generateRegistrationOptions(userId: '1', username: 'test'),
        throwsUnimplementedError,
      );

      expect(
        () => server.generateAuthenticationOptions(),
        throwsUnimplementedError,
      );
    });
  });
}
