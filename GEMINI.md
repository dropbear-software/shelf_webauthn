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
  - **Data Models**: Strongly-typed classes for WebAuthn data structures (options, responses, records).
  - **Spec Alignment**: Targets Section 7 of the W3C Web Authentication specification.

## Building and Running

- **Fetch Dependencies**: `dart pub get`
- **Run Tests**: `dart test`
- **Run Example**: `dart run example/shelf_webauthn_example.dart`
- **Static Analysis**: `dart analyze`
- **Formatting**: `dart format .`

## Project Structure

- `lib/`: Contains the core logic.
  - `shelf_webauthn.dart`: Main library export.
  - `src/`: Internal implementation details (stubs currently).
- `docs/`: 
  - `PRD.md`: Product Requirements Document.
  - `auth_data_parsing_plan.md`: Detailed plan for parsing `authenticatorData`.
- `test/`: 
  - `shelf_webauthn_test.dart`: Unit tests for the server.
  - `vectors.dart`: Official W3C WebAuthn spec test vectors (Section 16).
- `tool/`: Helper scripts for development (e.g., `extract_vectors.dart`).
- `spec/`: Local copy of the WebAuthn specification.

## Development Conventions

- **Spec Compliance**: All implementation steps should strictly follow the W3C WebAuthn specification (Sections 7.1 and 7.2).
- **Testing**: Use the provided `testVectors` in `test/vectors.dart` for rigorous validation of registration and authentication flows.
- **Error Handling**: Throw descriptive exceptions or use `VerificationResult` to return status.
- **Coding Style**: Adhere to [Effective Dart](https://dart.dev/effective-dart) guidelines.
- **Formatting**: Run `dart format .` before committing.
- **Analysis**: Ensure `dart analyze` passes with no issues.
