import 'package:shelf_webauthn/shelf_webauthn.dart';

void main() {
  final webAuthn = WebAuthnServer(
    rpId: 'example.com',
    expectedOrigin: 'https://example.com',
  );

  try {
    final options = webAuthn.generateRegistrationOptions(
      userId: 'user-1',
      username: 'test@example.com',
    );
    print('Generated Challenge: ${options.challenge}');
  } on UnimplementedError catch (e) {
    print('Expected error: $e');
  }
}
