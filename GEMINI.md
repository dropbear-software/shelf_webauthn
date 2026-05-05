# Shelf WebAuthn

A server-side WebAuthentication (WebAuthn) Relying Party (RP) implementation for the Dart ecosystem, designed for use with the `shelf` HTTP server framework.

## Project Overview

- **Purpose**: Provides cryptographic and validation logic for WebAuthn registration and authentication ceremonies.
- **Main Technologies**: 
  - **Dart SDK**: ^3.11.5
  - **`cbor`**: For decoding binary structures (`attestationObject`, `authData`).
  - **`webcrypto`**: For asymmetric public keys and signature verification.
  - **`crypto`**: For SHA-256 hashing.
- **Architecture**: 
  - **Stateless Core**: The `WebAuthnServer` class in `lib/src/shelf_webauthn_base.dart` is the main entry point.
  - **Shelf Integration**: The `WebAuthnEndpoints` class in `lib/src/shelf/endpoints.dart` provides a pre-built `shelf_router` for rapid integration.
  - **Data Models**: Strongly-typed, immutable (`final`, `const`) classes for WebAuthn data structures, located in `lib/src/models/`.
  - **Spec Alignment**: Strictly implements Sections 7.1 and 7.2 of the W3C Web Authentication specification.

## Building and Running

- **Fetch Dependencies**: `dart pub get`
- **Run Tests**: `dart test`
- **Run Example**: `dart run example/shelf_webauthn_example.dart` (Serves an HTML frontend demo at http://localhost:8080)
- **Static Analysis**: `dart analyze`
- **Formatting**: `dart format .`

## Project Structure

- `lib/`: Contains the core logic.
  - `shelf_webauthn.dart`: Main library export.
  - `src/shelf_webauthn_base.dart`: Core stateless server logic.
  - `src/models/`: Immutable data models.
  - `src/helpers/`: Parsing utilities for CBOR, COSE keys, and client data.
  - `src/shelf/`: Integration layer containing parsers and the `WebAuthnEndpoints` router.
- `test/`: Comprehensive test suite using official W3C test vectors (`vectors.dart`).
- `example/`: Contains a fully functional, end-to-end `shelf_io` server and an `index.html` frontend demo.

## Development Conventions

- **Spec Compliance**: All implementation steps should strictly follow the W3C WebAuthn specification (Sections 7.1 and 7.2).
- **Testing**: Use the provided `testVectors` in `test/vectors.dart` for rigorous validation of registration and authentication flows.
- **Error Handling**: Throw descriptive exceptions or use `VerificationResult` to return status.
- **Coding Style**: Adhere to [Effective Dart](https://dart.dev/effective-dart) guidelines. Models should be `final` and implement value equality.
- **Formatting**: Run `dart format .` before committing.
- **Analysis**: Ensure `dart analyze` passes with no issues.
