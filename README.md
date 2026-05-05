# Shelf WebAuthn

A server-side WebAuthentication (WebAuthn) Relying Party (RP) implementation for the Dart ecosystem.

This package provides the core cryptographic and validation logic required to process WebAuthn registration and authentication ceremonies on a Dart backend. It is designed to work seamlessly with the `shelf` HTTP server framework, allowing you to easily add passkeys, biometrics, and security key authentication to your Dart web applications.

## Features

*   **Standard Compliant**: Implements Relying Party (RP) operations as defined in Section 7 of the W3C Web Authentication specification.
*   **Registration**: Generates creation options and validates `AuthenticatorAttestationResponse` payloads.
*   **Authentication**: Generates request options and validates `AuthenticatorAssertionResponse` payloads.
*   **Security Built-in**: Handles CBOR decoding, COSE key parsing, cryptographic signature verification (ECDSA/RSA), and replay protection.
*   **Framework Agnostic Core**: While tailored for `shelf`, the core validation logic is stateless and can be used in any Dart backend environment.

## Getting started

*Note: This package is currently under active development. The API is subject to change.*

Add the package to your `pubspec.yaml` (once published) or reference it locally.

## Usage

The easiest way to get started is using the high-level `WebAuthnEndpoints` router for the `shelf` framework. You simply need to provide an implementation for storing temporary challenges and user credentials.

```dart
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as shelf_io;
import 'package:shelf_webauthn/shelf_webauthn.dart';
import 'package:shelf_router/shelf_router.dart';

void main() async {
  // 1. Initialize the core WebAuthn Server logic
  final webAuthn = WebAuthnServer(
    rpId: 'example.com',
    expectedOrigin: 'https://example.com',
  );

  // 2. Wire up the Endpoints Router with your database
  final endpoints = WebAuthnEndpoints(
    server: webAuthn,
    challengeStore: MyDatabaseChallengeStore(),
    credentialStore: MyDatabaseCredentialStore(),
    getSessionId: (Request request) => request.headers['x-session-id']!,
    getUserId: (Request request) => request.headers['x-user-id']!,
  );

  // 3. Mount the standard WebAuthn endpoints to your app router
  final appRouter = Router();
  appRouter.mount('/auth/webauthn/', endpoints.router.call);

  // Serve the API
  await shelf_io.serve(appRouter.call, 'localhost', 8080);
}
```

### Low-Level API

If you are not using `shelf_router` or need custom logic, you can interact directly with the stateless `WebAuthnServer` instance to generate options and verify JSON responses.

```dart
// 1. Generate options
final creationOptions = webAuthn.generateRegistrationOptions(
  userId: 'user-123',
  username: 'alice@example.com',
);

// 2. Parse JSON response from the client
final response = parseRegistrationResponseJson(jsonPayload);

// 3. Verify the attestation
final credentialRecord = await webAuthn.verifyRegistrationResponse(
  response: response, 
  expectedChallenge: creationOptions.challenge,
);
```

## Additional information

Please refer to the [W3C Web Authentication Specification](https://w3c.github.io/webauthn/) for more detailed information on the standard.
