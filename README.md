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

Below is a conceptual example of how you will use the `WebAuthnServer` to handle registration and authentication. 

```dart
import 'package:shelf_webauthn/shelf_webauthn.dart';

void main() async {
  // Initialize the WebAuthn server with your domain details
  final webAuthn = WebAuthnServer(
    rpId: 'example.com',
    expectedOrigin: 'https://example.com',
  );

  // --- Registration (MakeCredential) ---
  
  // 1. Generate options to send to the client
  final creationOptions = webAuthn.generateRegistrationOptions(
    userId: 'user-123',
    username: 'alice@example.com',
  );
  
  // (Send options to client, receive response)
  // ...
  
  // 2. Verify the attestation response received from the client
  // final credentialRecord = await webAuthn.verifyRegistrationResponse(
  //   response: attestationResponse, 
  //   expectedChallenge: creationOptions.challenge,
  // );
  // 
  // Save `credentialRecord` to your database!

  // --- Authentication (GetAssertion) ---

  // 1. Generate options to send to the client
  final requestOptions = webAuthn.generateAuthenticationOptions();

  // (Send options to client, receive response)
  // ...

  // 2. Verify the assertion response received from the client
  // final result = await webAuthn.verifyAuthenticationResponse(
  //   response: assertionResponse,
  //   expectedChallenge: requestOptions.challenge,
  //   storedCredential: credentialRecordFromDatabase,
  // );
  //
  // if (result.success) {
  //   // Update sign count in DB and log user in!
  // }
}
```

## Additional information

Please refer to the [W3C Web Authentication Specification](https://w3c.github.io/webauthn/) for more detailed information on the standard.
